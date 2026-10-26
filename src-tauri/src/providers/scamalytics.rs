//! `scamalytics` adapter — Scamalytics — CHỈ gọi API chính thức khi có key, KHÔNG scrape (§5.4).
//!
//! §5.4 is a hard rule: Scamalytics is an interactive website, not a public
//! free API. This adapter therefore
//!   * never fetches an HTML page,
//!   * never solves or bypasses a CAPTCHA,
//!   * never falls back to the website when the key is missing.
//!
//! Without a key it returns [`ProviderError`] `no_key` and exposes
//! [`manual_lookup_url`] so the UI can offer "tra tay" plus the
//! "Chưa có nguồn này" label (§5.4), and Confidence is deducted upstream.
//!
//! source_url: https://scamalytics.com/

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{
    default_client, err_no_key, err_parse, evidence, get_json, scrub_secrets, status_error,
    threshold_signal,
};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "scamalytics";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "scamalytics";

/// Production API endpoint pattern: `/v3/{user}/{key}/?ip={ip}`.
///
/// Scamalytics issues a *user id* and an *API key* as a pair, so the credential
/// stored in Credential Manager is `"user:key"`.
pub const API_BASE: &str = "https://api11.scamalytics.com/v3";

/// Human-facing manual lookup page. This is a LINK for the user to click, not
/// something this adapter ever requests (§5.4).
pub const MANUAL_LOOKUP_BASE: &str = "https://scamalytics.com/ip";

/// Where the user gets an API credential, shown in Settings (§11).
pub const KEY_HELP_URL: &str = "https://scamalytics.com/ip/api";

/// Adapter for Scamalytics (official API only).
#[derive(Debug, Clone)]
pub struct Adapter {
    client: reqwest::Client,
    base_url: String,
    /// `(user, key)` parsed from the `"user:key"` credential.
    credential: Option<(String, String)>,
    thresholds: Option<Thresholds>,
    timeout: Duration,
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`).
    ///
    /// Starts with no credential, so `check()` returns `no_key` until the user
    /// configures one — no HTML fetch, no CAPTCHA, no scraping (§5.4).
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the `"<user>:<key>"` credential from Credential Manager.
    pub fn with_credential(mut self, credential: Option<String>) -> Self {
        self.credential = parse_credential(credential);
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
        credential: Option<String>,
        thresholds: Option<Thresholds>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            credential: parse_credential(credential),
            thresholds,
            timeout: Duration::from_millis(8000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn has_token(&self) -> bool {
        self.credential.is_some()
    }

    /// `GET {base}/{user}/{key}/?ip={ip}`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        match &self.credential {
            Some((user, key)) => format!("{}/{}/{}/?ip={}", self.base_url, user, key, ip),
            None => format!("{}/?ip={}", self.base_url, ip),
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

/// Split a `"user:key"` credential. A credential without `:` is treated as
/// unusable rather than being guessed into one half.
pub fn parse_credential(raw: Option<String>) -> Option<(String, String)> {
    let raw = raw?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (user, key) = raw.split_once(':')?;
    let (user, key) = (user.trim(), key.trim());
    if user.is_empty() || key.is_empty() {
        return None;
    }
    Some((user.to_string(), key.to_string()))
}

/// Manual lookup link for the UI (§5.4): the only thing we may do without a key.
pub fn manual_lookup_url(ip: &IpAddr) -> String {
    format!("{MANUAL_LOOKUP_BASE}/{ip}")
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
        true
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        // §5.4: no key ⇒ clean NoKey. No HTML fetch, no CAPTCHA, no scraping.
        let (_, key) = self.credential.clone().ok_or_else(|| err_no_key(ID))?;

        let (mut body, _, latency_ms) =
            get_json(&self.client, ID, &self.endpoint(ip), Self::headers(), self.timeout).await?;

        // The key is a path segment, so scrub it from any echo in the payload.
        scrub_secrets(&mut body, &[key.as_str()]);

        build_evidence(&body, self.thresholds.as_ref(), latency_ms)
    }
}

/// Scamalytics payload → fraud [`ProviderEvidence`].
///
/// The API's score is `scamalytics_score` on a 0–100 scale where higher is
/// worse (same direction as IPQS), so the YAML thresholds apply directly.
pub fn build_evidence(
    body: &Value,
    thresholds: Option<&Thresholds>,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    let status = body.get("status").and_then(Value::as_str).unwrap_or("");

    if status == "error" {
        let error = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("scamalytics error");
        let message = body.get("message").and_then(Value::as_str).unwrap_or("");
        let lower = format!("{error} {message}").to_ascii_lowercase();
        if lower.contains("quota") || lower.contains("credit") || lower.contains("limit") {
            return Err(super::ip_api::err_quota(ID, 403, Some(message)));
        }
        if lower.contains("key") || lower.contains("auth") || lower.contains("permission") {
            return Err(err_no_key(ID));
        }
        return Err(err_parse(ID, format!("{error}: {message}")));
    }

    if status != "ok" {
        return Err(status_error(ID, 400, Some(status)));
    }

    let score = body
        .get("scamalytics_score")
        .and_then(Value::as_f64)
        .ok_or_else(|| err_parse(ID, "thiếu scamalytics_score"))?;

    let proxy = body.get("proxy").and_then(Value::as_bool).unwrap_or(false);
    let vpn = body.get("vpn").and_then(Value::as_bool).unwrap_or(false);
    let tor = body.get("tor").and_then(Value::as_bool).unwrap_or(false);
    let server = body.get("server").and_then(Value::as_bool).unwrap_or(false);
    let anonymizing_vpn = body
        .get("anonymizing_vpn_network")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let blocklisted = body
        .get("blocklisted_ips")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let signal = threshold_signal(Some(score), thresholds);

    let mut reasons: Vec<String> = Vec::new();
    if tor {
        reasons.push("Tor".to_string());
    }
    if vpn {
        reasons.push("VPN".to_string());
    }
    if anonymizing_vpn {
        reasons.push("anonymizing VPN network".to_string());
    }
    if proxy {
        reasons.push("proxy".to_string());
    }
    if server {
        reasons.push("server/hosting".to_string());
    }
    if blocklisted > 0 {
        reasons.push(format!("{blocklisted} IP bị blocklist"));
    }
    let reason = if reasons.is_empty() {
        Some(format!("Scamalytics score = {score}"))
    } else {
        Some(format!("Scamalytics score = {score}; {}", reasons.join(", ")))
    };

    let raw = serde_json::json!({
        "scamalytics_score": score,
        "scamalytics_risk": body.get("scamalytics_risk"),
        "score_color": body.get("score_color"),
        "country": body.get("country"),
        "country_code": body.get("country_code"),
        "isp": body.get("isp"),
        "organization": body.get("organization"),
        "asn": body.get("asn"),
        "proxy": proxy,
        "vpn": vpn,
        "tor": tor,
        "server": server,
        "anonymizing_vpn_network": anonymizing_vpn,
        "blocklisted_ips": blocklisted,
        "last_seen": body.get("last_seen"),
    });

    Ok(evidence(
        ID,
        Category::Fraud,
        UPSTREAM,
        signal,
        Some(score),
        Some(raw),
        "https://scamalytics.com/",
        Some(latency_ms),
        reason,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Signal;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_USER: &str = "testuser";
    const TEST_KEY: &str = "scam-key-abcdef123456";

    fn credential() -> String {
        format!("{TEST_USER}:{TEST_KEY}")
    }

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

    /// Base URL is the *API* host. There is no code path that can reach the
    /// website, so a missing mock simply yields a connection error — proving
    /// there is no scraping fallback.
    fn adapter(server: &MockServer, with_key: bool) -> Adapter {
        Adapter::with_base_url(
            client(),
            server.uri(),
            if with_key { Some(credential()) } else { None },
            Some(yaml_thresholds()),
        )
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
    async fn scamalytics_clean_score_maps_to_clean() {
        let server = serve("scamalytics.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "scamalytics");
        assert_eq!(ev.raw_score, Some(3.0));
        assert_eq!(ev.signal, Signal::Clean);
    }

    #[tokio::test]
    async fn scamalytics_suspicious_score_maps_to_suspicious() {
        let server = serve("scamalytics.suspicious.json", 200).await;
        let ip: IpAddr = "185.244.1.1".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.raw_score, Some(41.0));
        assert_eq!(ev.signal, Signal::Suspicious);
    }

    #[tokio::test]
    async fn scamalytics_bad_score_maps_to_bad() {
        let server = serve("scamalytics.bad.json", 200).await;
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.raw_score, Some(78.0));
        assert_eq!(ev.signal, Signal::Bad);
    }

    #[tokio::test]
    async fn scamalytics_missing_key_returns_no_key_and_never_scrapes() {
        // No mock mounted. A `no_key` here (rather than an HTTP error) proves the
        // adapter short-circuits before any request — there is no scrape fallback.
        let server = MockServer::start().await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, false)
            .check(&ip)
            .await
            .expect_err("thiếu key phải trả NoKey");
        assert_eq!(err.kind, "no_key");
        assert!(!err.retryable);
        // §5.4: the user still gets a manual link.
        assert_eq!(
            manual_lookup_url(&ip),
            "https://scamalytics.com/ip/8.8.8.8"
        );
    }

    #[tokio::test]
    async fn scamalytics_malformed_credential_is_no_key() {
        let server = MockServer::start().await;
        let a = Adapter::with_base_url(client(), server.uri(), Some("onlykey".into()), None);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = a.check(&ip).await.expect_err("credential sai định dạng");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn scamalytics_quota_body_maps_to_quota() {
        let server = serve("scamalytics.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, true).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn scamalytics_http_403_maps_to_quota() {
        let server = serve("scamalytics.quota-403.json", 403).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, true).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert_eq!(err.status, Some(403));
    }

    #[tokio::test]
    async fn scamalytics_timeout_maps_to_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(3000)))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, true).check(&ip).await.expect_err("phải là timeout");
        assert_eq!(err.kind, "timeout");
    }

    #[tokio::test]
    async fn scamalytics_raw_never_contains_the_key() {
        let server = MockServer::start().await;
        let body = format!(
            r#"{{"status":"ok","scamalytics_score":10,"api_key":"{TEST_KEY}","note":"key {TEST_KEY}"}}"#
        );
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        let text = ev.raw.unwrap().to_string();
        assert!(!text.contains(TEST_KEY), "key lọt vào raw: {text}");
    }

    #[test]
    fn scamalytics_credential_parsing() {
        assert_eq!(
            parse_credential(Some("user:key".into())),
            Some(("user".into(), "key".into()))
        );
        assert_eq!(parse_credential(Some("nocolon".into())), None);
        assert_eq!(parse_credential(Some(" : ".into())), None);
        assert_eq!(parse_credential(None), None);
    }
}
