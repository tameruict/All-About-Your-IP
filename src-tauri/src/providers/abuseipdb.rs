//! `abuseipdb` adapter — AbuseIPDB — community reports, ~1.000/ngày free (§5.3).
//!
//! Abuse history vote. The score is `abuseConfidenceScore` (0–100) and the YAML
//! thresholds are `clean_below: 10`, `bad_above: 50` — "< 10% là ngưỡng sạch"
//! per the user requirement in §6.1.
//!
//! Fields the adapter must surface (§5.3 + `providers.yaml`):
//! `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`,
//! `lastReportedAt`, `usageType`.
//!
//! The key travels in a `Key` header (AbuseIPDB's documented scheme), never in
//! the query string, so it cannot leak through a logged URL (§11).
//!
//! source_url: https://www.abuseipdb.com/

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{
    default_client, err_no_key, err_parse, evidence, get_json, scrub_secrets, status_error,
    threshold_signal,
};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "abuseipdb";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "abuseipdb";

/// Production endpoint.
pub const API_BASE: &str = "https://api.abuseipdb.com/api/v2";
/// Where to get a free key, shown in Settings (§11).
pub const KEY_HELP_URL: &str = "https://www.abuseipdb.com/account/api";

/// Look-back window required by §5.3 ("số report 90 ngày").
pub const MAX_AGE_DAYS: u32 = 90;

/// Adapter for AbuseIPDB.
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
    /// [`Adapter::with_token`] after reading Credential Manager.
    pub fn new() -> Self {
        Self::with_base_url(default_client(), API_BASE, None, None)
    }

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Attach the token resolved from `config::get_api_key("abuseipdb")`.
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    /// Apply the §6.1 thresholds from `providers.yaml`
    /// (`clean_below: 10`, `bad_above: 50`).
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

    /// `GET {base}/check?ipAddress={ip}&maxAgeInDays=90`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        format!(
            "{}/check?ipAddress={}&maxAgeInDays={}&verbose=true",
            self.base_url, ip, MAX_AGE_DAYS
        )
    }

    /// AbuseIPDB requires the key in a `Key` header plus an explicit `Accept`.
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
        Category::Abuse
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
            get_json(&self.client, ID, &self.endpoint(ip), self.headers(), self.timeout).await?;

        scrub_secrets(&mut body, &[token]);

        build_evidence(&body, self.thresholds.as_ref(), latency_ms)
    }
}

/// AbuseIPDB payload → abuse [`ProviderEvidence`].
pub fn build_evidence(
    body: &Value,
    thresholds: Option<&Thresholds>,
    latency_ms: u64,
) -> Result<ProviderEvidence, ProviderError> {
    // Errors arrive as `{"errors":[{"detail":…,"status":…}]}` with a 4xx code,
    // but be defensive in case a 200 carries them.
    if let Some(errors) = body.get("errors").and_then(Value::as_array) {
        let first = errors.first();
        let detail = first
            .and_then(|e| e.get("detail"))
            .and_then(Value::as_str)
            .unwrap_or("AbuseIPDB trả về lỗi");
        let status = first
            .and_then(|e| e.get("status"))
            .and_then(Value::as_u64)
            .unwrap_or(400) as u16;
        return Err(status_error(ID, status, Some(detail)));
    }

    let data = body
        .get("data")
        .ok_or_else(|| err_parse(ID, "thiếu object data"))?;

    let Some(score) = data.get("abuseConfidenceScore").and_then(Value::as_f64) else {
        return Err(err_parse(ID, "thiếu abuseConfidenceScore"));
    };

    let total_reports = data.get("totalReports").and_then(Value::as_u64).unwrap_or(0);
    let distinct_users = data.get("numDistinctUsers").and_then(Value::as_u64).unwrap_or(0);
    let is_tor = data.get("isTor").and_then(Value::as_bool).unwrap_or(false);
    let whitelisted = data
        .get("isWhitelisted")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // §6.5: a whitelisted IP is an explicit "this is fine" from the community,
    // so it can never be voted Bad on a stale score.
    let signal = if whitelisted {
        Signal::Clean
    } else {
        threshold_signal(Some(score), thresholds)
    };

    let last_reported = data
        .get("lastReportedAt")
        .and_then(Value::as_str)
        .map(str::to_string);

    let reason = if whitelisted {
        Some(format!("AbuseIPDB: IP nằm trong whitelist (score {score})"))
    } else if total_reports == 0 {
        Some("AbuseIPDB: 0 report trong 90 ngày".to_string())
    } else {
        Some(format!(
            "AbuseIPDB: score {score}, {total_reports} report / {distinct_users} người, gần nhất {}",
            last_reported.as_deref().unwrap_or("không rõ")
        ))
    };

    let raw = serde_json::json!({
        "abuseConfidenceScore": score,
        "totalReports": total_reports,
        "numDistinctUsers": distinct_users,
        "lastReportedAt": last_reported,
        "usageType": data.get("usageType"),
        "isTor": is_tor,
        "isWhitelisted": whitelisted,
        "isPublic": data.get("isPublic"),
        "ipVersion": data.get("ipVersion"),
        "countryCode": data.get("countryCode"),
        "countryName": data.get("countryName"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames"),
        "maxAgeInDays": MAX_AGE_DAYS,
        "generatedAt": body.get("meta").and_then(|m| m.get("generatedAt")),
    });

    Ok(evidence(
        ID,
        Category::Abuse,
        UPSTREAM,
        signal,
        Some(score),
        Some(raw),
        "https://www.abuseipdb.com/",
        Some(latency_ms),
        reason,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header_exists, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_TOKEN: &str = "abuse-key-1234567890";

    /// Thresholds exactly as declared in `providers.yaml` (§6.1 user rule).
    fn yaml_thresholds() -> Thresholds {
        Thresholds {
            clean_below: 10.0,
            bad_above: 50.0,
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

    fn adapter(server: &MockServer, with_key: bool) -> Adapter {
        Adapter::with_base_url(
            client(),
            server.uri(),
            if with_key { Some(TEST_TOKEN.into()) } else { None },
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
    async fn abuseipdb_clean_score_maps_to_clean() {
        let server = serve("abuseipdb.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "abuseipdb");
        assert_eq!(ev.category, Category::Abuse);
        assert_eq!(ev.raw_score, Some(0.0));
        assert_eq!(ev.signal, Signal::Clean);
        let raw = ev.raw.unwrap();
        // §5.3 required fields must be surfaced.
        assert_eq!(raw["totalReports"], 0);
        assert_eq!(raw["abuseConfidenceScore"], 0.0);
        assert!(raw.get("usageType").is_some());
    }

    #[tokio::test]
    async fn abuseipdb_suspicious_score_maps_to_suspicious() {
        let server = serve("abuseipdb.suspicious.json", 200).await;
        let ip: IpAddr = "185.244.1.1".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        // 30 is between 10 and 50 → Suspicious.
        assert_eq!(ev.raw_score, Some(30.0));
        assert_eq!(ev.signal, Signal::Suspicious);
        assert_eq!(ev.raw.unwrap()["numDistinctUsers"], 4);
    }

    #[tokio::test]
    async fn abuseipdb_bad_score_maps_to_bad() {
        let server = serve("abuseipdb.bad.json", 200).await;
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.raw_score, Some(88.0));
        assert_eq!(ev.signal, Signal::Bad);
        assert_eq!(ev.raw.unwrap()["totalReports"], 412);
    }

    #[tokio::test]
    async fn abuseipdb_missing_key_returns_no_key() {
        let server = MockServer::start().await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, false)
            .check(&ip)
            .await
            .expect_err("thiếu key phải trả NoKey");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn abuseipdb_daily_limit_maps_to_quota() {
        let server = serve("abuseipdb.quota-403.json", 429).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, true).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert_eq!(err.status, Some(429));
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn abuseipdb_401_maps_to_no_key() {
        let server = serve("abuseipdb.no-key.json", 401).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server, true).check(&ip).await.expect_err("phải là no_key");
        assert_eq!(err.kind, "no_key");
    }

    #[tokio::test]
    async fn abuseipdb_timeout_maps_to_timeout() {
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
    async fn abuseipdb_sends_key_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/check.*"))
            .and(header_exists("key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(fixture("abuseipdb.clean.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("key header phải được gửi");
        assert_eq!(ev.signal, Signal::Clean);
    }

    #[tokio::test]
    async fn abuseipdb_whitelisted_overrides_high_score() {
        let server = MockServer::start().await;
        let body = r#"{"data":{"abuseConfidenceScore":97,"isWhitelisted":true,"totalReports":5,"numDistinctUsers":2,"isTor":false}}"#;
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.signal, Signal::Clean, "whitelist phải thắng score cao");
    }

    #[tokio::test]
    async fn abuseipdb_raw_never_contains_the_key() {
        let server = MockServer::start().await;
        let body = format!(
            r#"{{"data":{{"abuseConfidenceScore":0,"api_key":"{TEST_TOKEN}"}},"note":"key {TEST_TOKEN}"}}"#
        );
        Mock::given(method("GET"))
            .and(path_regex(r"^/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server, true).check(&ip).await.expect("phải thành công");
        let text = ev.raw.unwrap().to_string();
        assert!(!text.contains(TEST_TOKEN), "key lọt vào raw: {text}");
    }

    #[test]
    fn abuseipdb_endpoint_requests_90_day_window() {
        let a = Adapter::with_base_url(client(), API_BASE, Some("k".into()), None);
        let ep = a.endpoint(&"8.8.8.8".parse().unwrap());
        assert!(ep.contains("maxAgeInDays=90"));
        assert!(ep.contains("ipAddress=8.8.8.8"));
    }
}
