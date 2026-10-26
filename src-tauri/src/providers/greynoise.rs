//! `greynoise` adapter — GreyNoise — honeypot / mass-scanner detection, community API (§5.3).
//!
//! Tells us whether an IP is "background noise": an internet-wide scanner or
//! brute-forcer, as opposed to an IP that only ever talks to real services.
//! The community endpoint is the cheapest tier; `classification` is its verdict.
//!
//! source_url: https://www.greynoise.io/
//!
//! `requires_key` is `false` in `providers.yaml` (community tier, limited), so a
//! missing key still attempts the request and maps a 401 to `no_key` — the
//! provider never blocks the whole check either way.
//!
//! Classification → signal, per GreyNoise's documented vocabulary:
//! * `malicious`            → Bad
//! * `benign` (or RIOT hit) → Clean
//! * `unknown` with noise   → Suspicious  (scanning, but not attributed)
//! * no noise               → Clean        (never seen scanning)
//!
//! This is a fixed vocabulary, not a numeric score, so no YAML threshold applies
//! (§6.1 "Geo/ASN không có score" logic — same idea for classifications).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{default_client, err_parse, evidence, scrub_secrets, status_error};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "greynoise";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "greynoise";

/// Production endpoint (community API v3).
pub const API_BASE: &str = "https://api.greynoise.io/v3/community";
/// Keyless fallback endpoint (Shodan InternetDB — free, keyless scanner/honeypot/vuln intel)
/// used when GreyNoise Community API's 25 req/week anonymous quota returns HTTP 429.
pub const FALLBACK_API_BASE: &str = "https://internetdb.shodan.io";
/// Where to get a community key, shown in Settings (§11).
pub const KEY_HELP_URL: &str = "https://viz.greynoise.io/account";

/// How long to bypass GreyNoise's keyless endpoint after an HTTP 429 before probing again.
const KEYLESS_COOLDOWN_SECS: u64 = 600;

/// Epoch seconds until which keyless GreyNoise calls go straight to the fallback.
static KEYLESS_QUOTA_COOLDOWN_UNTIL: AtomicU64 = AtomicU64::new(0);

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Adapter for GreyNoise.
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    fallback_url: Option<String>,
    token: Option<String>,
    /// Kept for symmetry with the other adapters / registry plumbing. GreyNoise
    /// answers with a classification, so no threshold is read from it.
    thresholds: Option<Thresholds>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`).
    ///
    /// The community tier works without a key (`requires_key: false` in
    /// `providers.yaml`), so this is usable out of the box. A key is attached
    /// later with [`Adapter::with_token`]. When GreyNoise's 25 req/week
    /// anonymous community limit returns HTTP 429, the adapter falls back to
    /// Shodan InternetDB so Threat Intel keeps voting (§6.3).
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
            .with_fallback_url(FALLBACK_API_BASE)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the optional community key from Credential Manager.
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    /// Configure the keyless fallback base URL (used when GreyNoise returns 429).
    pub fn with_fallback_url(mut self, url: impl Into<String>) -> Self {
        let trimmed = url.into().trim_end_matches('/').to_string();
        self.fallback_url = if trimmed.is_empty() { None } else { Some(trimmed) };
        self
    }

    /// Kept for signature symmetry: GreyNoise answers with a classification, so
    /// no numeric threshold is consumed.
    pub fn with_thresholds_from(mut self, thresholds: Option<Thresholds>) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Mock/test constructor (offline localhost wiremock).
    pub fn with_base_url(
        client: reqwest::Client,
        base_url: impl Into<String>,
        token: Option<String>,
        thresholds: Option<Thresholds>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            fallback_url: None,
            token: token.filter(|t| !t.trim().is_empty()),
            thresholds,
            timeout: Duration::from_millis(7000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// `GET {base}/{ip}`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        format!("{}/{}", self.base_url, ip)
    }

    /// GreyNoise accepts the community key in the `key` header.
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(token) = &self.token {
            if let Ok(value) = HeaderValue::from_str(token) {
                headers.insert(HeaderName::from_static("key"), value);
            }
        }
        headers
    }

    async fn check_primary(&self, ip: &IpAddr, started: std::time::Instant) -> Result<ProviderEvidence, ProviderError> {
        let resp = self
            .client
            .get(&self.endpoint(ip))
            .headers(self.headers())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| super::ip_api::map_reqwest_error(ID, &e))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| super::ip_api::map_reqwest_error(ID, &e))?;
        let latency_ms = started.elapsed().as_millis() as u64;

        // GreyNoise Community API v3 returns HTTP 404 with JSON `{"ip":"...","noise":false,"riot":false,"message":"IP not observed scanning the internet."}`
        // when an IP is not observed scanning. Parse JSON on 2xx or 404.
        if !(200..300).contains(&status) && status != 404 {
            let detail = super::ip_api::brief_detail(&text);
            return Err(status_error(ID, status, detail.as_deref()));
        }

        let mut body: Value = match serde_json::from_str(&text) {
            Ok(val) => val,
            Err(e) => {
                if status == 404 {
                    let detail = super::ip_api::brief_detail(&text);
                    return Err(status_error(ID, status, detail.as_deref()));
                }
                return Err(err_parse(ID, format!("JSON không hợp lệ: {e}")));
            }
        };

        if let Some(token) = self.token.as_deref() {
            scrub_secrets(&mut body, &[token]);
        }

        let _ = &self.thresholds;
        build_evidence(&body, latency_ms)
    }

    async fn check_fallback(
        &self,
        fallback_base: &str,
        ip: &IpAddr,
        started: std::time::Instant,
    ) -> Result<ProviderEvidence, ProviderError> {
        let url = format!("{fallback_base}/{ip}");
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| super::ip_api::map_reqwest_error(ID, &e))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| super::ip_api::map_reqwest_error(ID, &e))?;
        let latency_ms = started.elapsed().as_millis() as u64;

        if status == 404 {
            let raw = serde_json::json!({
                "classification": "unobserved",
                "noise": false,
                "riot": false,
                "ip": ip.to_string(),
                "fallback": "internetdb",
                "message": "IP not observed scanning or exposing services.",
            });
            return Ok(evidence(
                ID,
                Category::ThreatIntel,
                UPSTREAM,
                Signal::Clean,
                None,
                Some(raw),
                "https://viz.greynoise.io/",
                Some(latency_ms),
                Some("Threat Intel: IP không quét diện rộng (noise=false)".to_string()),
            ));
        }

        if !(200..300).contains(&status) {
            let detail = super::ip_api::brief_detail(&text);
            return Err(status_error(ID, status, detail.as_deref()));
        }

        let body: Value = serde_json::from_str(&text)
            .map_err(|e| err_parse(ID, format!("JSON fallback không hợp lệ: {e}")))?;
        build_internetdb_evidence(ip, &body, latency_ms)
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
        Category::ThreatIntel
    }

    fn upstream(&self) -> &'static str {
        UPSTREAM
    }

    fn requires_key(&self) -> bool {
        false
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        let started = std::time::Instant::now();

        // When running keyless against the production GreyNoise Community API and
        // its 25 req/week anonymous bucket is in cooldown, go straight to the
        // fallback so checks stay fast and never trip the circuit breaker.
        if let Some(fallback_base) = self.fallback_url.as_deref() {
            if self.token.is_none()
                && self.base_url == API_BASE
                && now_epoch_secs() < KEYLESS_QUOTA_COOLDOWN_UNTIL.load(Ordering::Relaxed)
            {
                if let Ok(ev) = self.check_fallback(fallback_base, ip, started).await {
                    return Ok(ev);
                }
            }
        }

        match self.check_primary(ip, started).await {
            Ok(ev) => Ok(ev),
            Err(primary_err) => {
                if let Some(fallback_base) = self.fallback_url.as_deref() {
                    if matches!(primary_err.kind.as_str(), "quota" | "no_key" | "timeout") {
                        if self.token.is_none() && self.base_url == API_BASE && primary_err.kind == "quota" {
                            KEYLESS_QUOTA_COOLDOWN_UNTIL.store(
                                now_epoch_secs().saturating_add(KEYLESS_COOLDOWN_SECS),
                                Ordering::Relaxed,
                            );
                        }
                        if let Ok(ev) = self.check_fallback(fallback_base, ip, started).await {
                            return Ok(ev);
                        }
                    }
                }
                Err(primary_err)
            }
        }
    }
}

/// GreyNoise payload → threat-intel [`ProviderEvidence`].
pub fn build_evidence(body: &Value, latency_ms: u64) -> Result<ProviderEvidence, ProviderError> {
    let classification = body
        .get("classification")
        .and_then(Value::as_str)
        .map(|c| c.to_ascii_lowercase());
    let noise = body.get("noise").and_then(Value::as_bool).unwrap_or(false);
    let riot = body.get("riot").and_then(Value::as_bool).unwrap_or(false);
    let has_noise_bool = body.get("noise").and_then(Value::as_bool).is_some();

    // Community API v3 returns `{"ip":"...","noise":false,"riot":false,"message":"IP not observed scanning the internet."}`
    // without a `classification` field when the IP is clean/unobserved (§5.3: "no noise → Clean").
    if classification.is_none() && has_noise_bool && !noise && body.get("error").is_none() {
        let raw = serde_json::json!({
            "classification": "unobserved",
            "noise": false,
            "riot": riot,
            "name": body.get("name"),
            "link": body.get("link"),
            "last_seen": body.get("last_seen"),
            "ip": body.get("ip"),
            "message": body.get("message"),
        });
        return Ok(evidence(
            ID,
            Category::ThreatIntel,
            UPSTREAM,
            Signal::Clean,
            None,
            Some(raw),
            "https://viz.greynoise.io/",
            Some(latency_ms),
            Some("GreyNoise: IP không quét diện rộng (noise=false, riot=false)".to_string()),
        ));
    }

    // Some community responses carry an explicit error object with HTTP 200.
    if let Some(message) = body.get("message").and_then(Value::as_str) {
        let lower = message.to_ascii_lowercase();
        if classification.is_none() {
            if lower.contains("quota") || lower.contains("limit") {
                return Err(super::ip_api::err_quota(ID, 429, Some(message)));
            }
            if lower.contains("auth") || lower.contains("key") {
                return Err(status_error(ID, 401, Some(message)));
            }
            return Err(err_parse(ID, message));
        }
    }

    let Some(classification) = classification else {
        return Err(err_parse(ID, "thiếu classification"));
    };

    let signal = match classification.as_str() {
        "malicious" => Signal::Bad,
        "benign" => Signal::Clean,
        // "unknown": scanning behaviour is still a mild signal.
        _ => {
            if noise {
                Signal::Suspicious
            } else {
                Signal::Clean
            }
        }
    };

    let name = body.get("name").and_then(Value::as_str).unwrap_or("unknown");
    let reason = if classification == "malicious" {
        Some(format!("GreyNoise: {name} (malicious, đang quét diện rộng)"))
    } else if noise {
        Some(format!("GreyNoise: {name} (noise, chưa quy kết được)"))
    } else if riot {
        Some(format!("GreyNoise RIOT: {name} (dịch vụ phổ biến, không phải scanner)"))
    } else {
        Some(format!("GreyNoise: {classification}"))
    };

    let raw = serde_json::json!({
        "classification": classification,
        "noise": noise,
        "riot": riot,
        "name": body.get("name"),
        "link": body.get("link"),
        "last_seen": body.get("last_seen"),
        "ip": body.get("ip"),
    });

    Ok(evidence(
        ID,
        Category::ThreatIntel,
        UPSTREAM,
        signal,
        None,
        Some(raw),
        "https://viz.greynoise.io/",
        Some(latency_ms),
        reason,
    ))
}

/// Map a Shodan InternetDB payload (`https://internetdb.shodan.io/{ip}`) onto
/// GreyNoise's classification vocabulary when GreyNoise's keyless 25/week
/// community quota is exhausted.
pub fn build_internetdb_evidence(
    ip: &IpAddr,
    body: &Value,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    let tags: Vec<String> = body
        .get("tags")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(|s| s.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    let vulns: Vec<String> = body
        .get("vulns")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let hostnames: Vec<String> = body
        .get("hostnames")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let has_tag = |candidates: &[&str]| {
        tags.iter()
            .any(|t| candidates.iter().any(|c| t == c || t.contains(c)))
    };

    let is_malicious = has_tag(&[
        "malware",
        "compromised",
        "c2",
        "botnet",
        "ransomware",
        "exploit",
        "backdoor",
        "trojan",
        "cryptominer",
    ]);
    let is_scanner = has_tag(&["scanner", "honeypot", "tor"]) || !vulns.is_empty();
    let is_riot = has_tag(&["cdn", "cloud", "pqc"]) && !is_malicious && !is_scanner;

    let (classification, noise, signal) = if is_malicious {
        ("malicious", true, Signal::Bad)
    } else if is_scanner {
        ("unknown", true, Signal::Suspicious)
    } else {
        ("benign", false, Signal::Clean)
    };

    let name = hostnames
        .first()
        .map(String::as_str)
        .unwrap_or(if is_riot { "common-service" } else { "internetdb" });

    let reason = if classification == "malicious" {
        Some(format!(
            "Threat Intel: {name} (malicious tags: {})",
            tags.join(", ")
        ))
    } else if noise {
        let detail = if !tags.is_empty() {
            format!("tags: {}", tags.join(", "))
        } else {
            format!("{} CVE", vulns.len())
        };
        Some(format!("Threat Intel: {name} (scanner/exposed — {detail})"))
    } else if is_riot {
        Some(format!("Threat Intel: {name} (dịch vụ phổ biến, không phải scanner)"))
    } else {
        Some(format!("Threat Intel: {name} (không ghi nhận hành vi scanner)"))
    };

    let raw = serde_json::json!({
        "classification": classification,
        "noise": noise,
        "riot": is_riot,
        "name": name,
        "ip": body.get("ip").and_then(Value::as_str).unwrap_or(&ip.to_string()),
        "ports": body.get("ports"),
        "tags": tags,
        "vulns": vulns,
        "hostnames": hostnames,
        "fallback": "internetdb",
    });

    Ok(evidence(
        ID,
        Category::ThreatIntel,
        UPSTREAM,
        signal,
        None,
        Some(raw),
        "https://viz.greynoise.io/",
        Some(latency_ms),
        reason,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_TOKEN: &str = "gn-community-key-5566";

    fn fixture(name: &str) -> String {
        let path = format!("{}/../tests/fixtures/providers/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("đọc fixture {path}: {e}"))
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client")
    }

    fn adapter(server: &MockServer) -> Adapter {
        Adapter::with_base_url(client(), server.uri(), Some(TEST_TOKEN.into()), None)
            .with_timeout(Duration::from_millis(800))
    }

    async fn serve(file: &str, status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(status).set_body_raw(fixture(file), "application/json"))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn greynoise_benign_is_clean() {
        let server = serve("greynoise.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "greynoise");
        assert_eq!(ev.category, Category::ThreatIntel);
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.raw.unwrap()["noise"], false);
    }

    #[tokio::test]
    async fn greynoise_unknown_with_noise_is_suspicious() {
        let server = serve("greynoise.suspicious.json", 200).await;
        let ip: IpAddr = "185.244.1.1".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.signal, Signal::Suspicious);
    }

    #[tokio::test]
    async fn greynoise_malicious_is_bad() {
        let server = serve("greynoise.bad.json", 200).await;
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.signal, Signal::Bad);
        assert_eq!(ev.raw.unwrap()["classification"], "malicious");
    }

    #[tokio::test]
    async fn greynoise_quota_body_maps_to_quota() {
        let server = serve("greynoise.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn greynoise_http_429_maps_to_quota() {
        let server = serve("greynoise.quota-403.json", 429).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn greynoise_401_maps_to_no_key_but_does_not_panic() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(401).set_body_raw(
                r#"{"message":"invalid api key"}"#,
                "application/json",
            ))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là no_key");
        assert_eq!(err.kind, "no_key");
        // Keyless usage is allowed by the registry, so this must not be fatal.
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn greynoise_timeout_maps_to_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(3000)))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là timeout");
        assert_eq!(err.kind, "timeout");
    }

    #[test]
    fn greynoise_requires_key_flag_is_false() {
        let a = Adapter::new();
        assert!(!a.requires_key());
        assert!(!a.has_token());
    }

    #[tokio::test]
    async fn greynoise_raw_never_contains_the_key() {
        let server = MockServer::start().await;
        let body = format!(
            r#"{{"ip":"8.8.8.8","noise":false,"classification":"benign","key":"{TEST_TOKEN}"}}"#
        );
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        let text = ev.raw.unwrap().to_string();
        assert!(!text.contains(TEST_TOKEN), "key lọt vào raw: {text}");
    }

    #[tokio::test]
    async fn greynoise_429_falls_back_to_internetdb_when_configured() {
        let primary = serve("greynoise.quota-403.json", 429).await;
        let fallback = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"ip":"8.8.8.8","ports":[53,443],"tags":["pqc"],"vulns":[],"hostnames":["dns.google"]}"#,
                "application/json",
            ))
            .mount(&fallback)
            .await;

        let a = Adapter::with_base_url(client(), primary.uri(), None, None)
            .with_fallback_url(fallback.uri())
            .with_timeout(Duration::from_millis(800));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = a.check(&ip).await.expect("fallback phải cứu được lỗi 429");
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.raw.unwrap()["fallback"], "internetdb");
    }
}
