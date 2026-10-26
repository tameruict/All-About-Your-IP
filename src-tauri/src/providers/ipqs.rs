//! `ipqualityscore` adapter — IPQualityScore — fraud score chính, ~5.000/tháng free (§5.2).
//!
//! Primary fraud vote (§6.3 quorum needs ≥2 non-Unknown fraud votes). Without a
//! key it returns `no_key` cleanly and the check continues on the free sources
//! (§13.4).
//!
//! source_url: https://www.ipqualityscore.com/
//!
//! Thresholds: `clean_below: 25`, `bad_above: 75` are declared in
//! `providers.yaml` and injected here — never hardcoded (§6.1).

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{
    default_client, err_no_key, err_parse, evidence, get_json, scrub_secrets, threshold_signal,
};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "ipqualityscore";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "ipqualityscore";

/// Production endpoint — key and IP are both path segments.
pub const API_BASE: &str = "https://ipqualityscore.com/api/json/ip";
/// Where to get a free key, shown in Settings (§11).
pub const KEY_HELP_URL: &str = "https://www.ipqualityscore.com/create-account";

/// Extra query flags.
///
/// `strictness=1` is IPQS's default behaviour (higher recall); the API docs use
/// 0–2 where 1 is "recommended". `fast=1` keeps the request inside the 8 s
/// budget from `providers.yaml` by skipping the deeper (slower) probes.
pub const QUERY_FLAGS: &str = "strictness=1&fast=1";

/// Adapter for IPQualityScore.
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
    /// [`Adapter::with_token`] after reading Credential Manager. Missing key
    /// therefore surfaces as a clean `no_key` (§13.4).
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the token resolved from `config::get_api_key("ipqualityscore")`.
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    /// Apply the §6.1 thresholds loaded from `providers.yaml`
    /// (`clean_below: 25`, `bad_above: 75`).
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
            timeout: Duration::from_millis(8000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// `GET {base}/{token}/{ip}?strictness=1&fast=1`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        let token = self.token.as_deref().unwrap_or("");
        format!("{}/{}/{}?{}", self.base_url, token, ip, QUERY_FLAGS)
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
        true
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        let token = self.token.as_deref().ok_or_else(|| err_no_key(ID))?;

        let (mut body, _, latency_ms) =
            get_json(&self.client, ID, &self.endpoint(ip), Self::headers(), self.timeout).await?;

        // §5.4 / §11: the key travels in the URL path, so it must be scrubbed
        // from anything echoed back before `raw` is stored.
        scrub_secrets(&mut body, &[token]);

        build_evidence(&body, self.thresholds.as_ref(), latency_ms)
    }
}

/// IPQS payload → fraud [`ProviderEvidence`].
///
/// IPQS reports application errors with HTTP 200 + `"success": false`, and the
/// message distinguishes "invalid key" from "quota exceeded" — both must map to
/// a *clean* error, never to a fabricated score of 0 (§13.4: no placeholder).
pub fn build_evidence(
    body: &Value,
    thresholds: Option<&Thresholds>,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    let success = body.get("success").and_then(Value::as_bool).unwrap_or(false);
    if !success {
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("IPQS trả về success=false");
        let lower = message.to_ascii_lowercase();
        if lower.contains("quota")
            || lower.contains("exceeded")
            || lower.contains("limit")
            || lower.contains("insufficient")
            || lower.contains("credit")
        {
            return Err(super::ip_api::err_quota(ID, 403, Some(message)));
        }
        if lower.contains("key") || lower.contains("invalid") || lower.contains("missing") {
            return Err(err_no_key(ID));
        }
        return Err(err_parse(ID, message));
    }

    let Some(fraud_score) = body.get("fraud_score").and_then(Value::as_f64) else {
        return Err(err_parse(ID, "thiếu fraud_score"));
    };

    let proxy = bool_field(body, "proxy");
    let vpn = bool_field(body, "vpn");
    let tor = bool_field(body, "tor");
    let active_vpn = bool_field(body, "active_vpn");
    let active_tor = bool_field(body, "active_tor");
    let recent_abuse = bool_field(body, "recent_abuse");
    let bot_status = bool_field(body, "bot_status");

    // §6.1: the score decides the vote; the boolean flags only sharpen the
    // reason string. Both are preserved in `raw` for the UI.
    let signal = threshold_signal(Some(fraud_score), thresholds);

    let mut reasons: Vec<&str> = Vec::new();
    if tor || active_tor {
        reasons.push("Tor");
    }
    if vpn || active_vpn {
        reasons.push("VPN");
    }
    if proxy {
        reasons.push("proxy");
    }
    if recent_abuse {
        reasons.push("recent_abuse");
    }
    if bot_status {
        reasons.push("bot");
    }
    let reason = if reasons.is_empty() {
        Some(format!("IPQS fraud_score = {fraud_score}"))
    } else {
        Some(format!("IPQS fraud_score = {fraud_score}; cờ: {}", reasons.join(", ")))
    };

    let raw = serde_json::json!({
        "fraud_score": fraud_score,
        "country_code": body.get("country_code"),
        "region": body.get("region"),
        "city": body.get("city"),
        "ISP": body.get("ISP"),
        "ASN": body.get("ASN"),
        "organization": body.get("organization"),
        "timezone": body.get("timezone"),
        "mobile": body.get("mobile"),
        "host": body.get("host"),
        "proxy": proxy,
        "vpn": vpn,
        "tor": tor,
        "active_vpn": active_vpn,
        "active_tor": active_tor,
        "recent_abuse": recent_abuse,
        "bot_status": bot_status,
        "is_crawler": body.get("is_crawler"),
        "connection_type": body.get("connection_type"),
        "abuse_velocity": body.get("abuse_velocity"),
        "latitude": body.get("latitude"),
        "longitude": body.get("longitude"),
        "request_id": body.get("request_id"),
    });

    Ok(evidence(
        ID,
        Category::Fraud,
        UPSTREAM,
        signal,
        Some(fraud_score),
        Some(raw),
        "https://www.ipqualityscore.com/",
        Some(latency_ms),
        reason,
    ))
}

fn bool_field(body: &Value, key: &str) -> bool {
    body.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Map the payload onto [`crate::models::IpFlags`] for the ASN/IpType module.
pub fn ip_flags(body: &Value) -> crate::models::IpFlags {
    crate::models::IpFlags {
        hosting: body
            .get("connection_type")
            .and_then(Value::as_str)
            .map(|c| c.to_ascii_lowercase().contains("data center"))
            .unwrap_or(false),
        proxy: bool_field(body, "proxy"),
        vpn: bool_field(body, "vpn") || bool_field(body, "active_vpn"),
        tor: bool_field(body, "tor") || bool_field(body, "active_tor"),
        mobile: bool_field(body, "mobile"),
        anycast: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Signal;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_TOKEN: &str = "ipqs-test-key-987654";

    /// Thresholds exactly as declared in `providers.yaml` (§6.1).
    fn yaml_thresholds() -> Thresholds {
        Thresholds {
            clean_below: 25.0,
            bad_above: 75.0,
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

    fn adapter(server: &MockServer, token: Option<&str>) -> Adapter {
        Adapter::with_base_url(
            client(),
            server.uri(),
            token.map(str::to_string),
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
    async fn ipqs_clean_score_maps_to_clean() {
        let server = serve("ipqs.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        assert_eq!(ev.provider, "ipqualityscore");
        assert_eq!(ev.category, Category::Fraud);
        assert_eq!(ev.raw_score, Some(12.0));
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.source_url, "https://www.ipqualityscore.com/");
    }

    #[tokio::test]
    async fn ipqs_suspicious_score_maps_to_suspicious() {
        let server = serve("ipqs.suspicious.json", 200).await;
        let ip: IpAddr = "185.244.1.1".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        assert_eq!(ev.raw_score, Some(55.0));
        assert_eq!(ev.signal, Signal::Suspicious);
    }

    #[tokio::test]
    async fn ipqs_bad_score_maps_to_bad() {
        let server = serve("ipqs.bad.json", 200).await;
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        assert_eq!(ev.raw_score, Some(89.0));
        assert_eq!(ev.signal, Signal::Bad);
    }

    #[tokio::test]
    async fn ipqs_quota_403_maps_to_quota_not_a_zero_score() {
        // HTTP 403 + success:false + "exceeded ... quota" must never become a
        // Clean score of 0 (§13.4, manifest quota_403 assertion).
        let server = serve("ipqs.quota-403.json", 403).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn ipqs_quota_body_with_http_200_still_maps_to_quota() {
        let server = serve("ipqs.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn ipqs_missing_key_returns_no_key() {
        let server = MockServer::start().await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, None)
            .check(&ip)
            .await
            .expect_err("thiếu key phải trả NoKey");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn ipqs_invalid_key_body_maps_to_no_key() {
        let server = serve("ipqs.no-key.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect_err("key sai phải là no_key");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn ipqs_timeout_maps_to_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
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
    async fn ipqs_raw_never_contains_the_token() {
        let server = MockServer::start().await;
        let body = format!(
            r#"{{"success":true,"fraud_score":10,"country_code":"SG","api_key":"{TEST_TOKEN}"}}"#
        );
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, Some(TEST_TOKEN))
            .check(&ip)
            .await
            .expect("phải thành công");
        let text = ev.raw.unwrap().to_string();
        assert!(!text.contains(TEST_TOKEN), "key lọt vào raw: {text}");
    }

    #[test]
    fn ipqs_endpoint_puts_token_and_ip_in_path() {
        let a = Adapter::with_base_url(client(), API_BASE, Some("K".into()), Some(yaml_thresholds()));
        let ep = a.endpoint(&"8.8.8.8".parse().unwrap());
        assert_eq!(
            ep,
            format!("{API_BASE}/K/8.8.8.8?{QUERY_FLAGS}")
        );
    }

    #[test]
    fn ipqs_flags_feed_ip_type() {
        let body: Value = serde_json::from_str(&fixture("ipqs.bad.json")).unwrap();
        let flags = ip_flags(&body);
        assert!(flags.vpn || flags.proxy || flags.tor);
        assert!(flags.hosting, "connection_type 'Data Center' phải là hosting");
    }
}
