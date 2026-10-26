//! `proxycheck` adapter — ProxyCheck.io — risk score, ~1.000/ngày free (§5.2).
//!
//! Works keyless on the free tier, so it is a primary fraud vote even when the
//! user has configured no keys at all (§13.4). A key raises the quota but is
//! optional; the rate limiter keeps us inside 60 req/min from `providers.yaml`.
//!
//! source_url: https://proxycheck.io/

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, GeoPoint, ProviderError, ProviderEvidence};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{default_client, err_parse, evidence, get_json, scrub_secrets, threshold_signal, RateLimiter};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "proxycheck";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "proxycheck";

/// Production endpoint — the IP is a path segment, flags are query params.
pub const API_BASE: &str = "https://proxycheck.io/v2";
/// Free-tier ceiling from `providers.yaml`.
pub const RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Query flags: `vpn` adds the VPN flag, `asn` adds ASN, `risk` adds the 0–100
/// risk score this adapter votes on.
pub const QUERY_FLAGS: &str = "vpn=1&asn=1&risk=1";

/// Adapter for ProxyCheck.io.
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
    thresholds: Option<Thresholds>,
    rate_limiter: Arc<RateLimiter>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`).
    ///
    /// ProxyCheck works keyless on the free tier, so this is fully functional
    /// with no configuration at all (§13.4). A key is optional and attached
    /// later with [`Adapter::with_token`].
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the optional key resolved from `config::get_api_key("proxycheck")`.
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    /// Apply the §6.1 thresholds from `providers.yaml`
    /// (`clean_below: 20`, `bad_above: 70`).
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
            token: token.filter(|t| !t.trim().is_empty()),
            thresholds,
            rate_limiter: Arc::new(RateLimiter::new(RATE_LIMIT_PER_MINUTE)),
            timeout: Duration::from_millis(7000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// `GET {base}/{ip}?vpn=1&asn=1&risk=1[&key=…]`
    ///
    /// The optional key rides in `key=`, never as a header, so [`scrub_secrets`]
    /// has one predictable place to clean up if it is echoed back.
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        match &self.token {
            Some(key) => format!("{}/{}?{}&key={}", self.base_url, ip, QUERY_FLAGS, key),
            None => format!("{}/{}?{}", self.base_url, ip, QUERY_FLAGS),
        }
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers
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
        Category::Fraud
    }

    fn upstream(&self) -> &'static str {
        UPSTREAM
    }

    fn requires_key(&self) -> bool {
        false
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        self.rate_limiter.acquire().await;

        let (mut body, _, latency_ms) =
            get_json(&self.client, ID, &self.endpoint(ip), Self::headers(), self.timeout).await?;

        if let Some(token) = self.token.as_deref() {
            scrub_secrets(&mut body, &[token]);
        }

        build_evidence(ip, &body, self.thresholds.as_ref(), latency_ms)
    }
}

/// ProxyCheck payload → fraud [`ProviderEvidence`].
///
/// The body is keyed by the queried IP, plus a top-level `status`. A `denied` /
/// `error` status is a quota or key problem, not a verdict (§6.1).
pub fn build_evidence(
    ip: &IpAddr,
    body: &Value,
    thresholds: Option<&Thresholds>,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    let status = body.get("status").and_then(Value::as_str).unwrap_or("");

    let ip_node = body
        .get(ip.to_string())
        .or_else(|| {
            body.as_object().and_then(|o| {
                o.iter()
                    .find(|(k, _)| k.parse::<IpAddr>().map(|p| &p == ip).unwrap_or(false))
                    .map(|(_, v)| v)
            })
        });

    if status != "ok" && (status != "warning" || ip_node.is_none()) {
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("ProxyCheck trả về status khác ok");
        let lower = message.to_ascii_lowercase();
        if status == "denied" || lower.contains("limit") || lower.contains("quota") {
            return Err(super::ip_api::err_quota(ID, 403, Some(message)));
        }
        if lower.contains("key") || lower.contains("invalid") {
            return Err(super::ip_api::err_no_key(ID));
        }
        return Err(err_parse(ID, message));
    }

    let node = ip_node.ok_or_else(|| err_parse(ID, "thiếu node kết quả cho IP đã hỏi"))?;

    let Some(risk) = node.get("risk").and_then(Value::as_f64) else {
        return Err(err_parse(ID, "thiếu risk score"));
    };

    let proxy_flag = node
        .get("proxy")
        .and_then(Value::as_str)
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    let node_type = node.get("type").and_then(Value::as_str).unwrap_or("");

    let signal = threshold_signal(Some(risk), thresholds);

    let reason = if proxy_flag {
        Some(format!(
            "ProxyCheck risk = {risk}; proxy = yes (type: {node_type})"
        ))
    } else {
        Some(format!("ProxyCheck risk = {risk}"))
    };

    let raw = serde_json::json!({
        "risk": risk,
        "proxy": node.get("proxy"),
        "proxy_bool": proxy_flag,
        "type": node.get("type"),
        "asn": node.get("asn"),
        "range": node.get("range"),
        "hostname": node.get("hostname"),
        "provider": node.get("provider"),
        "continent": node.get("continent"),
        "country": node.get("country"),
        "isocode": node.get("isocode"),
        "region": node.get("region"),
        "city": node.get("city"),
        "timezone": node.get("timezone"),
        "latitude": node.get("latitude"),
        "longitude": node.get("longitude"),
        "query_time": body.get("query_time"),
    });

    Ok(evidence(
        ID,
        Category::Fraud,
        UPSTREAM,
        signal,
        Some(risk),
        Some(raw),
        "https://proxycheck.io/",
        Some(latency_ms),
        reason,
    ))
}

/// ProxyCheck doubles as a geo source (§5.1 lists the ip-api/ipinfo flags, but
/// ProxyCheck's free answer already carries country/city/lat/lon — usable for
/// triangulation without spending another request).
pub fn to_geo_point(ip: &IpAddr, body: &Value) -> Option<GeoPoint> {
    let node = body.get(ip.to_string()).or_else(|| {
        body.as_object().and_then(|o| {
            o.iter()
                .find(|(k, _)| k.parse::<IpAddr>().map(|p| &p == ip).unwrap_or(false))
                .map(|(_, v)| v)
        })
    })?;

    let isocode = node.get("isocode").and_then(Value::as_str);
    let country = node.get("country").and_then(Value::as_str);
    if isocode.is_none() && country.is_none() {
        return None;
    }

    Some(GeoPoint {
        source: ID.to_string(),
        source_kind: "api".to_string(),
        country: country.map(str::to_string),
        country_code: isocode.map(str::to_string),
        region: node.get("region").and_then(Value::as_str).map(str::to_string),
        city: node.get("city").and_then(Value::as_str).map(str::to_string),
        postal: None,
        latitude: node.get("latitude").and_then(Value::as_f64),
        longitude: node.get("longitude").and_then(Value::as_f64),
        timezone: node.get("timezone").and_then(Value::as_str).map(str::to_string),
        accuracy_radius_km: None,
        db_version: None,
        db_updated_at: None,
        distance_from_centroid_km: None,
        over_precise: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Signal;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Thresholds exactly as declared in `providers.yaml`.
    fn yaml_thresholds() -> Thresholds {
        Thresholds {
            clean_below: 20.0,
            bad_above: 70.0,
        }
    }

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
        Adapter::with_base_url(client(), server.uri(), None, Some(yaml_thresholds()))
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
    async fn proxycheck_clean_risk_maps_to_clean() {
        let server = serve("proxycheck.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "proxycheck");
        assert_eq!(ev.raw_score, Some(0.0));
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.source_url, "https://proxycheck.io/");
    }

    #[tokio::test]
    async fn proxycheck_suspicious_risk_maps_to_suspicious() {
        let server = serve("proxycheck.suspicious.json", 200).await;
        let ip: IpAddr = "185.244.1.1".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.raw_score, Some(48.0));
        assert_eq!(ev.signal, Signal::Suspicious);
    }

    #[tokio::test]
    async fn proxycheck_bad_risk_maps_to_bad() {
        let server = serve("proxycheck.bad.json", 200).await;
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.raw_score, Some(91.0));
        assert_eq!(ev.signal, Signal::Bad);
    }

    #[tokio::test]
    async fn proxycheck_denied_body_maps_to_quota() {
        let server = serve("proxycheck.quota-403.json", 403).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn proxycheck_denied_with_http_200_maps_to_quota() {
        let server = serve("proxycheck.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn proxycheck_timeout_maps_to_timeout() {
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

    #[tokio::test]
    async fn proxycheck_runs_keyless_and_scrubs_optional_key() {
        let server = MockServer::start().await;
        let body = r#"{"status":"ok","8.8.8.8":{"risk":5,"proxy":"no","country":"Singapore","isocode":"SG"},"key":"pc-secret-123456"}"#;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;

        let a = Adapter::with_base_url(
            client(),
            server.uri(),
            Some("pc-secret-123456".into()),
            Some(yaml_thresholds()),
        );
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = a.check(&ip).await.expect("phải thành công");
        // Keyless is the default, so requires_key must stay false.
        assert!(!a.requires_key());
        let text = ev.raw.unwrap().to_string();
        assert!(!text.contains("pc-secret-123456"));
    }

    #[test]
    fn proxycheck_geo_point_from_payload() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let body: Value = serde_json::from_str(&fixture("proxycheck.clean.json")).unwrap();
        let gp = to_geo_point(&ip, &body).expect("có country ⇒ có GeoPoint");
        assert_eq!(gp.country_code.as_deref(), Some("SG"));
        assert!(gp.accuracy_radius_km.is_none());
    }

    #[test]
    fn proxycheck_rate_limiter_uses_yaml_ceiling() {
        let a = Adapter::with_base_url(client(), API_BASE, None, Some(yaml_thresholds()));
        assert_eq!(a.rate_limiter().limit_per_minute(), 60);
    }
}
