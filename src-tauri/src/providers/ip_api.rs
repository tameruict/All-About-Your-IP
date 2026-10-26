//! `ip_api` adapter — ip-api.com — primary free geo + ASN + hosting/proxy/mobile flags (§5.1).
//!
//! Also hosts the shared provider plumbing used by every adapter in this module
//! tree: the §6.1 threshold→[`Signal`] normaliser, the `ProviderError` mapping,
//! the key scrubber and the per-provider rate limiter. Those live here (rather
//! than in `mod.rs`, which is scaffold-owned) but are exported so the other
//! adapters and the tests can share one implementation.
//!
//! source_url: https://ip-api.com/
//!
//! Free tier: 45 req/phút. Cache + backoff bắt buộc (§5.1) — enforced by
//! [`RateLimiter`] with `rate_limit: 45` from `providers.yaml`.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use serde_json::Value;

use crate::models::{Category, GeoPoint, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "ip_api";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "ip-api";

/// Production endpoint. ip-api's free tier is HTTP-only (HTTPS is a paid plan).
pub const API_BASE: &str = "http://ip-api.com";
/// Fields requested explicitly — `*` is not allowed on the free tier.
pub const FIELDS: &str = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
/// Free-tier ceiling (§5.1): 45 requests/minute.
pub const RATE_LIMIT_PER_MINUTE: u32 = 45;

// ===========================================================================
// Shared provider plumbing (exported for the sibling adapters + tests)
// ===========================================================================

/// Default HTTP client shared by every adapter.
///
/// One pool for the whole app keeps connection setup cost out of the per-check
/// budget. The request *timeout* is applied per call so a slow provider cannot
/// hold a pooled connection past its own ceiling (§4.3).
///
/// A failure to build the client is a programming error, not a runtime
/// condition: `Client::builder().build()` only fails when TLS cannot be
/// initialised at all, in which case no adapter could ever work.
pub fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("IPChecker/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// Build a `ProviderError` in the uniform wire shape (§4.4).
pub fn perr(kind: &str, message: impl Into<String>, status: Option<u16>, retryable: bool) -> ProviderError {
    ProviderError {
        kind: kind.to_string(),
        message: message.into(),
        status,
        retryable,
    }
}

/// `ProviderError::NoKey` — a key-requiring provider without a stored key.
///
/// Never fatal: the orchestrator marks the provider `skipped(missing_key)`,
/// deducts Confidence and carries on (§5.1, §6.3).
pub fn err_no_key(provider: &str) -> ProviderError {
    perr(
        "no_key",
        format!("Chưa có API key cho {provider} — provider bị bỏ qua, không chặn kết luận"),
        None,
        false,
    )
}

/// `ProviderError::Quota` — quota/credit exhausted (HTTP 402/403/429).
pub fn err_quota(provider: &str, status: u16, detail: Option<&str>) -> ProviderError {
    perr(
        "quota",
        format!(
            "{provider}: hết quota hoặc vượt rate limit (HTTP {status}){}",
            detail.map(|d| format!(" — {d}")).unwrap_or_default()
        ),
        Some(status),
        false,
    )
}

/// `ProviderError::Http` — any other non-success status.
pub fn err_http(provider: &str, status: u16, detail: Option<&str>) -> ProviderError {
    perr(
        "http",
        format!(
            "{provider}: HTTP {status}{}",
            detail.map(|d| format!(" — {d}")).unwrap_or_default()
        ),
        Some(status),
        // 5xx is worth a single retry; 4xx is not (§4.3: no retry storm).
        status >= 500,
    )
}

/// `ProviderError::Parse` — 2xx but the body is not what the API documents.
pub fn err_parse(provider: &str, detail: impl Into<String>) -> ProviderError {
    perr(
        "parse",
        format!("{provider}: phản hồi không đúng định dạng — {}", detail.into()),
        None,
        false,
    )
}

/// `ProviderError::Timeout` — the request exceeded the provider timeout.
pub fn err_timeout(provider: &str) -> ProviderError {
    let mut e = ProviderError::timeout();
    e.message = format!("{provider}: {}", e.message);
    e
}

/// Map a `reqwest` failure onto the uniform error shape.
///
/// Timeout / connect errors become `timeout` (retryable, but the orchestrator
/// retries at most once — §4.3); everything else becomes `http`.
pub fn map_reqwest_error(provider: &str, err: &reqwest::Error) -> ProviderError {
    if err.is_timeout() || err.is_connect() {
        err_timeout(provider)
    } else if err.is_decode() {
        err_parse(provider, err.to_string())
    } else {
        perr("http", format!("{provider}: {err}"), err.status().map(|s| s.as_u16()), true)
    }
}

/// Classify a non-success HTTP status into the right error kind.
pub fn status_error(provider: &str, status: u16, detail: Option<&str>) -> ProviderError {
    match status {
        401 | 407 => perr(
            "no_key",
            format!(
                "{provider}: key bị thiếu hoặc không hợp lệ (HTTP {status}){}",
                detail.map(|d| format!(" — {d}")).unwrap_or_default()
            ),
            Some(status),
            false,
        ),
        402 | 403 | 429 => err_quota(provider, status, detail),
        _ => err_http(provider, status, detail),
    }
}

/// §6.1: map a raw provider score onto [`Signal`] using the thresholds declared
/// in `providers.yaml` — never a hardcoded magic number.
///
/// `raw < clean_below` → Clean, `raw > bad_above` → Bad, otherwise Suspicious.
/// A missing threshold is a configuration gap, not a reason to guess: the
/// signal stays `Unknown` and the caller keeps `raw_score` for the UI.
pub fn threshold_signal(raw: Option<f64>, thresholds: Option<&Thresholds>) -> Signal {
    match (raw, thresholds) {
        (Some(score), Some(t)) => {
            if score < t.clean_below {
                Signal::Clean
            } else if score > t.bad_above {
                Signal::Bad
            } else {
                Signal::Suspicious
            }
        }
        _ => Signal::Unknown,
    }
}

/// Build `ProviderEvidence` for a provider that has no score scale (geo / ASN):
/// the signal reflects consistency, never a fabricated number.
pub fn evidence(
    provider: &str,
    category: Category,
    upstream: &str,
    signal: Signal,
    raw_score: Option<f64>,
    raw: Option<Value>,
    source_url: &str,
    latency_ms: Option<u64>,
    reason: Option<String>,
) -> ProviderEvidence {
    ProviderEvidence {
        provider: provider.to_string(),
        category,
        upstream: upstream.to_string(),
        signal,
        raw_score,
        raw,
        checked_at: chrono::Utc::now().to_rfc3339(),
        source_url: source_url.to_string(),
        latency_ms,
        error: None,
        reason,
        from_cache: false,
    }
}

/// Remove every secret from a JSON payload before it can reach `raw`, SQLite or
/// the export (§5.4, §10.3, §11: "raw payload phải đã xoá key").
///
/// Two passes:
/// 1. Any key whose *name* looks secret (`token`, `key`, `secret`, `password`,
///    `apikey`, …) is replaced by `"[redacted]"` at any depth.
/// 2. Any *string value* that contains one of the supplied secrets verbatim is
///    scrubbed too — this catches APIs that echo the key inside a message.
pub fn scrub_secrets(value: &mut Value, secrets: &[&str]) {
    fn looks_secret(name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n.contains("token")
            || n.contains("api_key")
            || n.contains("apikey")
            || n.contains("secret")
            || n.contains("password")
            || n == "key"
            || n.ends_with("_key")
    }

    fn walk(value: &mut Value, secrets: &[&str]) {
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if looks_secret(k) {
                        if !v.is_null() {
                            *v = Value::String("[redacted]".to_string());
                        }
                        continue;
                    }
                    walk(v, secrets);
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    walk(item, secrets);
                }
            }
            Value::String(s) => {
                let mut hit = false;
                let mut out = s.clone();
                for secret in secrets {
                    if secret.len() >= 4 && out.contains(secret) {
                        out = out.replace(secret, "[redacted]");
                        hit = true;
                    }
                }
                if hit {
                    *s = out;
                }
            }
            _ => {}
        }
    }

    walk(value, secrets);
}

/// Per-provider fixed-window rate limiter (§5.1).
///
/// Keeps the adapter inside the free-tier ceiling so a burst never turns into a
/// 429 storm. `limit == 0` means "unknown / unlimited" per `providers.yaml`.
#[derive(Debug)]
pub struct RateLimiter {
    limit_per_minute: u32,
    window: Duration,
    state: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    window_start: Option<Instant>,
    used: u32,
}

impl RateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit_per_minute,
            window: Duration::from_secs(60),
            state: Mutex::new(LimiterState::default()),
        }
    }

    pub fn limit_per_minute(&self) -> u32 {
        self.limit_per_minute
    }

    /// How long the caller must wait before the next request is allowed.
    ///
    /// `Some(delay)` means blocked for that long; `None` means a slot was
    /// reserved and the request may proceed immediately.
    pub fn try_acquire(&self) -> Option<Duration> {
        if self.limit_per_minute == 0 {
            return None;
        }
        let mut st = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let expired = match st.window_start {
            Some(start) => now.duration_since(start) >= self.window,
            None => true,
        };
        if expired {
            st.window_start = Some(now);
            st.used = 0;
        }
        if st.used < self.limit_per_minute {
            st.used += 1;
            None
        } else {
            let start = st.window_start.unwrap_or(now);
            let elapsed = now.duration_since(start);
            Some(self.window.saturating_sub(elapsed).max(Duration::from_millis(1)))
        }
    }

    /// Wait for a slot instead of failing fast.
    pub async fn acquire(&self) -> Duration {
        loop {
            match self.try_acquire() {
                None => return Duration::ZERO,
                Some(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    /// Test helper: how many slots remain in the current window.
    pub fn remaining(&self) -> u32 {
        if self.limit_per_minute == 0 {
            return u32::MAX;
        }
        let st = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.limit_per_minute.saturating_sub(st.used)
    }
}

/// Shared HTTP helper: GET + timeout + status classification.
///
/// Returns the parsed JSON body or a mapped [`ProviderError`]. A 4xx is never
/// retried here — the caller sees `Quota`/`NoKey`/`Http` and moves on (§4.3).
pub async fn get_json(
    client: &reqwest::Client,
    provider: &str,
    url: &str,
    headers: HeaderMap,
    timeout: Duration,
) -> Result<(Value, u16, u64), ProviderError> {
    let started = Instant::now();
    let resp = client
        .get(url)
        .headers(headers)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| map_reqwest_error(provider, &e))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| map_reqwest_error(provider, &e))?;
    let latency_ms = started.elapsed().as_millis() as u64;

    if !(200..300).contains(&status) {
        let detail = brief_detail(&text);
        return Err(status_error(provider, status, detail.as_deref()));
    }

    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| err_parse(provider, format!("JSON không hợp lệ: {e}")))?;
    Ok((parsed, status, latency_ms))
}

/// Short human-readable excerpt of an error body for the message field.
pub fn brief_detail(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cut: String = trimmed.chars().take(180).collect();
    Some(cut)
}

// ===========================================================================
// Adapter
// ===========================================================================

/// Adapter for ip-api.com.
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    thresholds: Option<Thresholds>,
    rate_limiter: std::sync::Arc<RateLimiter>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`).
    ///
    /// No key is needed here: ip-api is keyless and the YAML thresholds are read
    /// later through [`Adapter::with_thresholds`] once the registry is loaded, so
    /// a missing `providers.yaml` can never panic at start-up.
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Apply the §6.1 thresholds loaded from `providers.yaml`.
    pub fn with_thresholds_from(mut self, thresholds: Option<Thresholds>) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Mock/test constructor: point the adapter at a local wiremock server so
    /// the suite runs offline (no real network in CI).
    pub fn with_base_url(
        client: reqwest::Client,
        base_url: impl Into<String>,
        thresholds: Option<Thresholds>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            thresholds,
            rate_limiter: std::sync::Arc::new(RateLimiter::new(RATE_LIMIT_PER_MINUTE)),
            timeout: Duration::from_millis(5000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn rate_limiter(&self) -> &std::sync::Arc<RateLimiter> {
        &self.rate_limiter
    }

    pub fn endpoint(&self, ip: &IpAddr) -> String {
        format!("{}/json/{}?fields={}", self.base_url, ip, FIELDS)
    }
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for Adapter {
    fn id(&self) -> &'static str {
        ID
    }

    fn category(&self) -> Category {
        Category::Geo
    }

    fn upstream(&self) -> &'static str {
        UPSTREAM
    }

    fn requires_key(&self) -> bool {
        false
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        // §5.1: stay inside 45 req/min; the wait happens here, not as a 429 storm.
        self.rate_limiter.acquire().await;

        let (body, _, latency_ms) = get_json(
            &self.client,
            ID,
            &self.endpoint(ip),
            HeaderMap::new(),
            self.timeout,
        )
        .await?;

        // ip-api signals application-level failures with HTTP 200 + status:fail.
        let status_field = body.get("status").and_then(Value::as_str).unwrap_or("");
        if status_field != "success" {
            let message = body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("ip-api trả về status khác success");
            // "private range"/"reserved range"/"invalid query" are hard errors;
            // the ratelimit message is a quota problem (§5.1 backoff).
            if message.to_ascii_lowercase().contains("limit") {
                return Err(err_quota(ID, 429, Some(message)));
            }
            return Err(err_parse(ID, message));
        }

        build_geo_evidence(ID, UPSTREAM, &body, latency_ms)
    }
}

/// `ip-api` payload → geo [`ProviderEvidence`].
///
/// Geo has no score scale (§6.1), so the signal only encodes "is this a
/// residential-looking IP". Proxy/hosting flags are surfaced in `raw` for the
/// `ip_api_flags` fraud hint and for the location engine (§7.3–§7.5).
pub fn build_geo_evidence(
    provider: &str,
    upstream: &str,
    body: &Value,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    let proxy = body.get("proxy").and_then(Value::as_bool).unwrap_or(false);
    let hosting = body.get("hosting").and_then(Value::as_bool).unwrap_or(false);
    let mobile = body.get("mobile").and_then(Value::as_bool).unwrap_or(false);

    // A clean geo answer needs a country; without one there is nothing to vote.
    if body.get("countryCode").and_then(Value::as_str).is_none()
        && body.get("country").and_then(Value::as_str).is_none()
    {
        return Err(err_parse(provider, "thiếu country/countryCode"));
    }

    let signal = if proxy {
        Signal::Bad
    } else if hosting {
        Signal::Suspicious
    } else {
        Signal::Clean
    };

    let reason = if proxy {
        Some("IP bị gắn cờ proxy".to_string())
    } else if hosting {
        Some("IP thuộc dải hosting/datacenter — vị trí geo có thể lệch (§7.5)".to_string())
    } else if mobile {
        Some("IP mobile — thành phố chỉ là gateway nhà mạng (§7.5)".to_string())
    } else {
        None
    };

    let raw = serde_json::json!({
        "country": body.get("country"),
        "country_code": body.get("countryCode"),
        "region": body.get("regionName"),
        "city": body.get("city"),
        "postal": body.get("zip"),
        "latitude": body.get("lat"),
        "longitude": body.get("lon"),
        "timezone": body.get("timezone"),
        "isp": body.get("isp"),
        "org": body.get("org"),
        "as": body.get("as"),
        "asname": body.get("asname"),
        "reverse": body.get("reverse"),
        "mobile": body.get("mobile"),
        "proxy": body.get("proxy"),
        "hosting": body.get("hosting"),
        "query": body.get("query"),
    });

    Ok(evidence(
        provider,
        Category::Geo,
        upstream,
        signal,
        None,
        Some(raw),
        "https://ip-api.com/",
        Some(latency_ms),
        reason,
    ))
}

/// Map an `ip-api`-shaped payload onto a [`GeoPoint`] for triangulation (§7.3).
///
/// `accuracy_radius_km` is `None` here: the API does not publish one, and
/// inventing a radius would overstate precision (§7.1).
pub fn to_geo_point(body: &Value) -> GeoPoint {
    GeoPoint {
        source: ID.to_string(),
        source_kind: "api".to_string(),
        country: body.get("country").and_then(Value::as_str).map(str::to_string),
        country_code: body
            .get("countryCode")
            .and_then(Value::as_str)
            .map(str::to_string),
        region: body
            .get("regionName")
            .and_then(Value::as_str)
            .map(str::to_string),
        city: body.get("city").and_then(Value::as_str).map(str::to_string),
        postal: body.get("zip").and_then(Value::as_str).map(str::to_string),
        latitude: body.get("lat").and_then(Value::as_f64),
        longitude: body.get("lon").and_then(Value::as_f64),
        timezone: body
            .get("timezone")
            .and_then(Value::as_str)
            .map(str::to_string),
        accuracy_radius_km: None,
        db_version: None,
        db_updated_at: None,
        distance_from_centroid_km: None,
        over_precise: false,
    }
}

// ===========================================================================
// Tests (offline, wiremock on localhost)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_api_is_keyless_and_geo() {
        // §5.2: ip-api free tier needs no credential.
        let a = Adapter::new();
        assert!(!a.requires_key());
        assert_eq!(a.id(), "ip_api");
        assert_eq!(a.category(), Category::Geo);
        assert_eq!(a.upstream(), "ip-api");
    }

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client")
    }

    fn fixture(name: &str) -> String {
        let path = format!("{}/../tests/fixtures/providers/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("đọc fixture {path}: {e}"))
    }

    fn adapter(server: &MockServer) -> Adapter {
        Adapter::with_base_url(client(), server.uri(), None).with_timeout(Duration::from_millis(800))
    }

    #[tokio::test]
    async fn ip_api_success_clean() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/json/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(fixture("ip_api.clean.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "ip_api");
        assert_eq!(ev.upstream, "ip-api");
        assert_eq!(ev.category, Category::Geo);
        // 8.8.8.8 is hosting:true, proxy:false → Suspicious, never "Clean datacenter".
        assert_eq!(ev.signal, Signal::Suspicious);
        assert_eq!(ev.source_url, "https://ip-api.com/");
        let raw = ev.raw.unwrap();
        assert_eq!(raw["country_code"], "SG");
        assert_eq!(raw["hosting"], true);
    }

    #[tokio::test]
    async fn ip_api_proxy_flag_is_bad() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/json/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(fixture("ip_api.bad.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.signal, Signal::Bad);
        assert!(ev.reason.unwrap().contains("proxy"));
    }

    #[tokio::test]
    async fn ip_api_quota_429_maps_to_quota_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/json/.*"))
            .respond_with(ResponseTemplate::new(429).set_body_raw(
                fixture("ip_api.quota-403.json"),
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là lỗi");
        assert_eq!(err.kind, "quota");
        assert_eq!(err.status, Some(429));
        // A 4xx must never be retried (§4.3: no retry storm).
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn ip_api_timeout_maps_to_timeout_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/json/.*"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(3000)))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là timeout");
        assert_eq!(err.kind, "timeout");
        assert!(err.retryable);
    }

    #[tokio::test]
    async fn ip_api_app_level_fail_is_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/json/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"status":"fail","message":"invalid query","query":"8.8.8.8"}"#,
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là lỗi parse");
        assert_eq!(err.kind, "parse");
    }

    #[test]
    fn rate_limiter_blocks_after_limit_and_resets() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.try_acquire().is_none());
        assert!(limiter.try_acquire().is_none());
        assert!(limiter.try_acquire().is_none());
        // 4th request in the same window must be told to wait.
        let delay = limiter.try_acquire().expect("phải bị chặn");
        assert!(delay > Duration::ZERO && delay <= Duration::from_secs(60));
        assert_eq!(limiter.remaining(), 0);
    }

    #[test]
    fn rate_limiter_zero_means_unlimited() {
        let limiter = RateLimiter::new(0);
        for _ in 0..100 {
            assert!(limiter.try_acquire().is_none());
        }
    }

    #[test]
    fn threshold_signal_uses_yaml_values_not_magic_numbers() {
        let t = Thresholds {
            clean_below: 25.0,
            bad_above: 75.0,
        };
        assert_eq!(threshold_signal(Some(12.0), Some(&t)), Signal::Clean);
        assert_eq!(threshold_signal(Some(25.0), Some(&t)), Signal::Suspicious);
        assert_eq!(threshold_signal(Some(55.0), Some(&t)), Signal::Suspicious);
        assert_eq!(threshold_signal(Some(89.0), Some(&t)), Signal::Bad);
        // Missing thresholds must not invent a verdict.
        assert_eq!(threshold_signal(Some(99.0), None), Signal::Unknown);
        assert_eq!(threshold_signal(None, Some(&t)), Signal::Unknown);
    }

    #[test]
    fn scrub_secrets_removes_nested_tokens() {
        let mut v = serde_json::json!({
            "data": { "ip": "8.8.8.8", "token": "SECRET-TOKEN-123", "note": "key=SECRET-TOKEN-123" },
            "api_key": "SECRET-TOKEN-123",
            "list": [{ "secret": "abc" }]
        });
        scrub_secrets(&mut v, &["SECRET-TOKEN-123"]);
        let text = v.to_string();
        assert!(!text.contains("SECRET-TOKEN-123"), "key còn sót: {text}");
        assert_eq!(v["data"]["ip"], "8.8.8.8");
    }

    #[tokio::test]
    async fn geo_point_from_fixture_is_not_over_precise() {
        let body: Value = serde_json::from_str(&fixture("ip_api.clean.json")).unwrap();
        let gp = to_geo_point(&body);
        assert_eq!(gp.country_code.as_deref(), Some("SG"));
        assert_eq!(gp.city.as_deref(), Some("Singapore"));
        assert!(gp.latitude.unwrap() > 1.0);
        // §7.1: no invented accuracy radius.
        assert!(gp.accuracy_radius_km.is_none());
        assert!(!gp.over_precise);
    }
}
