//! `ipinfo` adapter — ipinfo.io — geo + ASN + privacy flags, free token 50k/tháng (§5.1).
//!
//! Optional provider: without a token it returns [`ProviderError`] `no_key` and
//! the orchestrator marks it `skipped(missing_key)`. It MUST NOT block a verdict
//! and MUST NOT make the whole check fail (§5.1, §6.3, §13.4).
//!
//! source_url: https://ipinfo.io/
//!
//! Two call shapes exist:
//! * Geo endpoint `/ip/{ip}/json?token=…` (free tier) → country/region/city/loc.
//! * Privacy endpoint `/privacy/{ip}?token=…` → vpn/proxy/tor/relay/hosting.
//! Both use the same upstream, so §6.2 collapses them into one vote.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{
    default_client, err_no_key, err_parse, evidence, get_json, scrub_secrets, status_error,
};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "ipinfo";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "ipinfo";

/// Production endpoint.
pub const API_BASE: &str = "https://ipinfo.io";

/// Where to get the free token, shown in Settings (§11).
pub const KEY_HELP_URL: &str = "https://ipinfo.io/signup";

/// Adapter for ipinfo.io.
///
/// The token is held as `Option<String>` and injected by the caller (the
/// orchestrator reads it from Credential Manager via `config::get_api_key`), so
/// this module never touches the keyring and never hardcodes a key.
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
    thresholds: Option<Thresholds>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`).
    ///
    /// Starts **without** a token; the orchestrator injects one with
    /// [`Adapter::with_token`] after reading Credential Manager, so the registry
    /// stays key-free and a missing key surfaces as a clean `no_key`.
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
    }

    /// Attach the shared HTTP client.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the token resolved from `config::get_api_key("ipinfo")`.
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    /// Apply the §6.1 thresholds loaded from `providers.yaml`.
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
            timeout: Duration::from_millis(6000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// `GET {base}/{ip}/json?token=…`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        let token = self.token.as_deref().unwrap_or("");
        format!("{}/{}/json?token={}", self.base_url, ip, token)
    }

    /// Request headers. The token also goes in `Authorization` so it can be
    /// scrubbed in one place if the API ever echoes it.
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(token) = &self.token {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, value);
            }
        }
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
        Category::Geo
    }

    fn upstream(&self) -> &'static str {
        UPSTREAM
    }

    fn requires_key(&self) -> bool {
        true
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        // §5.1: no token ⇒ clean NoKey, never a panic and never a fake result.
        let token = self.token.as_deref().ok_or_else(|| err_no_key(ID))?;

        let (mut body, _, latency_ms) =
            get_json(&self.client, ID, &self.endpoint(ip), self.headers(), self.timeout).await?;

        // ipinfo answers 200 with an `error` object for token problems on some
        // plans; treat that as no_key/quota instead of returning empty geo.
        if let Some(error) = body.get("error") {
            let code = error.get("code").and_then(Value::as_u64).unwrap_or(0) as u16;
            let title = error.get("title").and_then(Value::as_str).unwrap_or("");
            return Err(status_error(ID, if code == 0 { 401 } else { code }, Some(title)));
        }

        // §5.4 / §11: the token must never reach `raw`.
        scrub_secrets(&mut body, &[token]);

        build_geo_evidence(&body, latency_ms)
    }
}

/// ipinfo payload → geo [`ProviderEvidence`].
pub fn build_geo_evidence(body: &Value, latency_ms: u64) -> Result<ProviderEvidence, ProviderError> {
    if body.get("country").and_then(Value::as_str).is_none() {
        return Err(err_parse(ID, "thiếu country"));
    }

    let privacy = body.get("privacy");
    let vpn = privacy.and_then(|p| p.get("vpn")).and_then(Value::as_bool).unwrap_or(false);
    let proxy = privacy.and_then(|p| p.get("proxy")).and_then(Value::as_bool).unwrap_or(false);
    let tor = privacy.and_then(|p| p.get("tor")).and_then(Value::as_bool).unwrap_or(false);
    let relay = privacy.and_then(|p| p.get("relay")).and_then(Value::as_bool).unwrap_or(false);
    let hosting = privacy
        .and_then(|p| p.get("hosting"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let anycast = body.get("anycast").and_then(Value::as_bool);

    let (lat, lon) = parse_loc(body.get("loc").and_then(Value::as_str));

    let raw = serde_json::json!({
        "country": body.get("country"),
        "country_code": body.get("country"),
        "region": body.get("region"),
        "city": body.get("city"),
        "postal": body.get("postal"),
        "loc": body.get("loc"),
        "latitude": lat,
        "longitude": lon,
        "timezone": body.get("timezone"),
        "org": body.get("org"),
        "hostname": body.get("hostname"),
        "anycast": anycast,
        "privacy": {
            "vpn": vpn,
            "proxy": proxy,
            "tor": tor,
            "relay": relay,
            "hosting": hosting,
            "service": privacy.and_then(|p| p.get("service")),
        },
    });

    // Privacy flags are a strong signal (§5.2 secondary hint); hosting alone is
    // only "suspicious" because datacenters are not inherently malicious.
    let signal = if tor || vpn || proxy {
        Signal::Bad
    } else if hosting || relay {
        Signal::Suspicious
    } else {
        Signal::Clean
    };

    let reason = if tor {
        Some("ipinfo: IP là Tor exit".to_string())
    } else if vpn {
        Some("ipinfo: IP thuộc VPN".to_string())
    } else if proxy {
        Some("ipinfo: IP là proxy".to_string())
    } else if relay {
        Some("ipinfo: IP là relay (iCloud Private Relay ／ tương tự)".to_string())
    } else if hosting {
        Some("ipinfo: IP thuộc dải hosting/datacenter".to_string())
    } else if anycast == Some(true) {
        Some("ipinfo: anycast — không chốt thành phố (§7.5)".to_string())
    } else {
        None
    };

    let _ = (lat, lon);
    Ok(evidence(
        ID,
        Category::Geo,
        UPSTREAM,
        signal,
        None,
        Some(raw),
        "https://ipinfo.io/",
        Some(latency_ms),
        reason,
    ))
}

/// Split ipinfo's `"lat,lon"` string. Returns `(None, None)` when malformed
/// instead of substituting `0.0` (which would land in the Gulf of Guinea).
pub fn parse_loc(loc: Option<&str>) -> (Option<f64>, Option<f64>) {
    let Some(loc) = loc else {
        return (None, None);
    };
    let mut parts = loc.split(',');
    let lat = parts.next().and_then(|v| v.trim().parse::<f64>().ok());
    let lon = parts.next().and_then(|v| v.trim().parse::<f64>().ok());
    match (lat, lon) {
        (Some(a), Some(b)) => (Some(a), Some(b)),
        _ => (None, None),
    }
}

/// ASN from ipinfo's `"org": "AS15169 Google LLC"` field (§7.4).
pub fn asn_record(body: &Value) -> (Option<u32>, Option<String>, Option<String>) {
    let org = body.get("org").and_then(Value::as_str).unwrap_or("");
    let mut parts = org.splitn(2, ' ');
    let first = parts.next().unwrap_or("");
    let name = parts.next().map(str::trim).filter(|s| !s.is_empty());
    if let Some(digits) = first.strip_prefix("AS") {
        if let Ok(asn) = digits.parse::<u32>() {
            return (Some(asn), name.map(str::to_string), None);
        }
    }
    (None, name.map(str::to_string), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Token used in tests — must never surface in `raw`.
    const TEST_TOKEN: &str = "test-token-abc123456";

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

    fn adapter(server: &MockServer, token: Option<&str>) -> Adapter {
        Adapter::with_base_url(client(), server.uri(), token.map(str::to_string), None)
            .with_timeout(Duration::from_millis(800))
    }

    #[tokio::test]
    async fn ipinfo_success_clean() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(fixture("ipinfo.clean.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        assert_eq!(ev.provider, "ipinfo");
        assert_eq!(ev.upstream, "ipinfo");
        // hosting:true, no vpn/proxy/tor → Suspicious, not Bad.
        assert_eq!(ev.signal, Signal::Suspicious);
        assert_eq!(ev.source_url, "https://ipinfo.io/");
        let raw = ev.raw.unwrap();
        assert_eq!(raw["country"], "US");
        assert_eq!(raw["anycast"], true);
    }

    #[tokio::test]
    async fn ipinfo_vpn_tor_payload_is_bad() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(fixture("ipinfo.bad.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        assert_eq!(ev.signal, Signal::Bad);
    }

    #[tokio::test]
    async fn ipinfo_missing_key_returns_no_key_without_network() {
        // No mock mounted: if the adapter tried the network this would fail
        // differently. It must short-circuit to `no_key` (§13.4).
        let server = MockServer::start().await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, None)
            .check(&ip)
            .await
            .expect_err("thiếu token phải trả NoKey");
        assert_eq!(err.kind, "no_key");
        assert!(!err.retryable);
        assert!(err.message.contains("ipinfo"));
    }

    #[tokio::test]
    async fn ipinfo_empty_token_is_treated_as_missing() {
        let server = MockServer::start().await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some("   "))
            .check(&ip)
            .await
            .expect_err("token rỗng phải trả NoKey");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn ipinfo_quota_429_maps_to_quota() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(ResponseTemplate::new(429).set_body_raw(
                fixture("ipinfo.quota-403.json"),
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert_eq!(err.status, Some(429));
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn ipinfo_401_body_maps_to_no_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(ResponseTemplate::new(401).set_body_raw(
                fixture("ipinfo.no-key.json"),
                "application/json",
            ))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("phải là no_key");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn ipinfo_timeout_maps_to_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(3000)))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("phải là timeout");
        assert_eq!(err.kind, "timeout");
    }

    #[tokio::test]
    async fn ipinfo_raw_never_contains_the_token() {
        // The API echoes the token in a field this time — the scrubber must win.
        let server = MockServer::start().await;
        let body = format!(
            r#"{{"country":"SG","city":"Singapore","token":"{TEST_TOKEN}","note":"token={TEST_TOKEN}"}}"#
        );
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*/json.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        let raw = ev.raw.unwrap();
        let text = raw.to_string();
        assert!(!text.contains(TEST_TOKEN), "token lọt vào raw: {text}");
        assert_eq!(raw["country"], "SG");
    }

    #[test]
    fn ipinfo_parse_loc_rejects_garbage() {
        assert_eq!(parse_loc(Some("37.4056,-122.0775")), (Some(37.4056), Some(-122.0775)));
        assert_eq!(parse_loc(Some("nope")), (None, None));
        assert_eq!(parse_loc(None), (None, None));
    }

    #[test]
    fn ipinfo_asn_record_parses_org_prefix() {
        let body: Value = serde_json::from_str(&fixture("ipinfo.clean.json")).unwrap();
        let (asn, name, _) = asn_record(&body);
        assert_eq!(asn, Some(15169));
        assert_eq!(name.as_deref(), Some("Google LLC"));
    }
}
