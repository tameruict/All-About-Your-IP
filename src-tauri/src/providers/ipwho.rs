//! `ipwho` adapter — ipwho.is — geo fallback + ASN, independent of ip-api (§5.1).
//!
//! Keyless. Used by the location engine to cross-check ip-api: the two APIs are
//! different data sources, so a disagreement between them is a real signal
//! (§6.2 de-duplication is by `upstream`, and `ipwho.is` is its own upstream).
//!
//! source_url: https://ipwho.is/

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{default_client, err_parse, evidence, get_json};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "ipwho";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "ipwho.is";

/// Production endpoint.
pub const API_BASE: &str = "https://ipwho.is";

/// Adapter for ipwho.is.
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    thresholds: Option<Thresholds>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`). Keyless.
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None)
    }

    /// Attach the shared HTTP client.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Production constructor with thresholds from `providers.yaml`.
    pub fn with_thresholds_from(mut self, thresholds: Option<Thresholds>) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Mock/test constructor (offline localhost wiremock).
    pub fn with_base_url(
        client: reqwest::Client,
        base_url: impl Into<String>,
        thresholds: Option<Thresholds>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            thresholds,
            timeout: Duration::from_millis(6000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// ipwho.is takes the address as a path segment: `/{ip}`.
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        format!("{}/{}", self.base_url, ip)
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
        let started = Instant::now();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let (body, _, latency_ms) = get_json(&self.client, ID, &self.endpoint(ip), headers, self.timeout)
            .await
            .map_err(|mut e| {
                // Keep a stable latency figure even on the error path.
                e.message = format!("{} ({} ms)", e.message, started.elapsed().as_millis());
                e
            })?;

        build_geo_evidence(&body, latency_ms)
    }
}

/// ipwho.is payload → geo [`ProviderEvidence`].
///
/// The API answers HTTP 200 with `"success": false` for application failures
/// (rate limit, reserved range), so that must be checked before trusting fields.
pub fn build_geo_evidence(body: &Value, latency_ms: u64) -> Result<ProviderEvidence, ProviderError> {
    if !body.get("success").and_then(Value::as_bool).unwrap_or(false) {
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("ipwho.is trả về success=false");
        if message.to_ascii_lowercase().contains("rate limit") {
            return Err(super::ip_api::err_quota(ID, 429, Some(message)));
        }
        return Err(err_parse(ID, message));
    }

    if body.get("country_code").and_then(Value::as_str).is_none() {
        return Err(err_parse(ID, "thiếu country_code"));
    }

    let connection = body.get("connection");
    let asn = connection.and_then(|c| c.get("asn"));
    let org = connection.and_then(|c| c.get("org"));
    let isp = connection.and_then(|c| c.get("isp"));

    let raw = serde_json::json!({
        "country": body.get("country"),
        "country_code": body.get("country_code"),
        "region": body.get("region"),
        "city": body.get("city"),
        "postal": body.get("postal"),
        "latitude": body.get("latitude"),
        "longitude": body.get("longitude"),
        "timezone": body.get("timezone").and_then(|t| t.get("id")),
        "asn": asn,
        "org": org,
        "isp": isp,
        "connection_domain": connection.and_then(|c| c.get("domain")),
        "type": body.get("type"),
        "ip": body.get("ip"),
    });

    // ipwho.is publishes no proxy/hosting flag, so geo alone cannot say "bad".
    // Signal encodes availability + completeness, never a fabricated risk score.
    Ok(evidence(
        ID,
        Category::Geo,
        UPSTREAM,
        Signal::Clean,
        None,
        Some(raw),
        "https://ipwho.is/",
        Some(latency_ms),
        Some("Nguồn geo độc lập — dùng để đối chiếu với ip-api (§7.3)".to_string()),
    ))
}

/// ASN view of an ipwho.is payload, for the ASN module (§7.4).
///
/// ipwho.is does not publish the announced prefix, so it stays `None` rather
/// than being guessed (§7.1: never overstate precision).
pub fn asn_record(body: &Value) -> (Option<u32>, Option<String>, Option<String>) {
    let connection = match body.get("connection") {
        Some(c) => c,
        None => return (None, None, None),
    };
    let asn = connection.get("asn").and_then(|a| a.as_u64()).map(|a| a as u32);
    let org = connection
        .get("org")
        .and_then(Value::as_str)
        .map(str::to_string);
    let isp = connection.get("isp").and_then(Value::as_str).map(str::to_string);
    (asn, org.or(isp), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipwho_is_keyless_and_geo() {
        let a = Adapter::new();
        assert!(!a.requires_key());
        assert_eq!(a.id(), "ipwho");
        assert_eq!(a.category(), Category::Geo);
        assert_eq!(a.upstream(), "ipwho.is");
    }

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        Adapter::with_base_url(client(), server.uri(), None).with_timeout(Duration::from_millis(800))
    }

    #[tokio::test]
    async fn ipwho_success_clean() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(fixture("ipwho.clean.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "ipwho");
        assert_eq!(ev.upstream, "ipwho.is");
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.source_url, "https://ipwho.is/");
        assert_eq!(ev.raw.unwrap()["country_code"], "SG");
    }

    #[test]
    fn ipwho_ipv6_payload_parses() {
        let body: Value = serde_json::from_str(&fixture("ipwho.ipv6.json")).unwrap();
        let ev = build_geo_evidence(&body, 5).expect("IPv6 phải parse được");
        assert_eq!(ev.raw.unwrap()["country_code"], "SG");
    }

    #[tokio::test]
    async fn ipwho_rate_limit_body_maps_to_quota() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                fixture("ipwho.quota-403.json"),
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn ipwho_http_429_maps_to_quota() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(429).set_body_raw(
                r#"{"success":false,"message":"Too Many Requests"}"#,
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert_eq!(err.status, Some(429));
    }

    #[tokio::test]
    async fn ipwho_timeout_maps_to_timeout() {
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
    fn ipwho_asn_record_extracts_asn() {
        let body: Value = serde_json::from_str(&fixture("ipwho.clean.json")).unwrap();
        let (asn, org, prefix) = asn_record(&body);
        assert_eq!(asn, Some(15169));
        assert_eq!(org.as_deref(), Some("Google LLC"));
        assert!(prefix.is_none(), "ipwho.is không công bố prefix — không được bịa");
    }
}
