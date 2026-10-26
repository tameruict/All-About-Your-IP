//! `ripestat` adapter — RIPEstat — ASN, prefix, quan hệ RIR/BGP (§5.1, §7.4).
//!
//! Keyless. This is RIR/BGP data, *not* a commercial geo database, so it is the
//! independent cross-check for ASN and registration country (§7.4 "đăng ký vs
//! sử dụng").
//!
//! source_url: https://stat.ripe.net/
//!
//! Endpoint: `data/prefix-overview` — one call gives the routed prefix, every
//! announcing ASN and the ASN holder string (which carries the RIR country).

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{AsnRecord, Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{default_client, err_parse, evidence, get_json, status_error};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "ripestat";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "ripestat";

/// Production endpoint.
pub const API_BASE: &str = "https://stat.ripe.net/data/prefix-overview/data.json";

/// Adapter for RIPEstat.
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

    /// Attach the shared HTTP client (one pool for the whole app).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Kept for signature symmetry: ASN has no score scale (§6.1).
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
            base_url: base_url.into(),
            thresholds,
            timeout: Duration::from_millis(8000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `GET {base}?resource={ip}`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        let sep = if self.base_url.contains('?') { '&' } else { '?' };
        format!("{}{}resource={}", self.base_url, sep, ip)
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
        Category::Asn
    }

    fn upstream(&self) -> &'static str {
        UPSTREAM
    }

    fn requires_key(&self) -> bool {
        false
    }

    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError> {
        let (body, _, latency_ms) =
            get_json(&self.client, ID, &self.endpoint(ip), Self::headers(), self.timeout).await?;

        let _ = &self.thresholds;
        build_evidence(&body, latency_ms)
    }
}

/// RIPEstat payload → ASN [`ProviderEvidence`].
///
/// ASN has no "score" (§6.1), so the signal encodes data completeness: a routed
/// prefix with at least one announcing ASN is `Clean`, an unannounced or empty
/// answer is `Unknown` rather than a silent "no problem".
pub fn build_evidence(body: &Value, latency_ms: u64) -> Result<ProviderEvidence, ProviderError> {
    if body.get("status").and_then(Value::as_str) == Some("error") {
        let code = body
            .get("status_code")
            .and_then(Value::as_u64)
            .unwrap_or(400) as u16;
        let message = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("RIPEstat trả về lỗi");
        return Err(status_error(ID, code, Some(message)));
    }

    let data = body
        .get("data")
        .ok_or_else(|| err_parse(ID, "thiếu object data"))?;

    let prefix = data
        .get("prefix")
        .and_then(Value::as_str)
        .or_else(|| data.get("resource").and_then(Value::as_str));
    let announced = data
        .get("is_announced")
        .and_then(Value::as_bool)
        .or_else(|| data.get("announced").and_then(Value::as_bool))
        .unwrap_or(false);
    let asns = data.get("asns").and_then(Value::as_array);
    let first_asn = asns.and_then(|a| a.first());
    let asn = first_asn
        .and_then(|a| a.get("asn"))
        .and_then(Value::as_u64)
        .map(|a| a as u32);
    let holder = first_asn
        .and_then(|a| a.get("holder"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let (holder_name, rir_country) = split_holder(holder.as_deref());

    let signal = if asn.is_some() && (announced || prefix.is_some()) {
        Signal::Clean
    } else {
        Signal::Unknown
    };

    let reason = match (&prefix, asn) {
        (Some(p), Some(a)) => Some(format!("RIPEstat: AS{a} công bố {p}")),
        (Some(p), None) => Some(format!("RIPEstat: {p} chưa được ASN nào công bố")),
        _ => Some("RIPEstat: không có dữ liệu prefix".to_string()),
    };

    let raw = serde_json::json!({
        "asn": asn,
        "holder": holder_name,
        "rir_country": rir_country,
        "prefix": prefix,
        "block": data.get("block"),
        "resource": data.get("resource"),
        "name": data.get("name"),
        "shortname": data.get("shortname"),
        "is_announced": announced,
        "category": data.get("category"),
        "irr_sources": data.get("irr_sources"),
        "announced_asns": asns.map(|a| a.len()),
    });

    Ok(evidence(
        ID,
        Category::Asn,
        UPSTREAM,
        signal,
        None,
        Some(raw),
        "https://stat.ripe.net/",
        Some(latency_ms),
        reason,
    ))
}

/// RIPEstat holder strings look like `"GOOGLE, US"` or `"STARK-INDUSTRIES, MD"`.
///
/// The trailing token is the RIR registration country — the "đăng ký" half of
/// §7.4, deliberately kept separate from the geo "sử dụng" country.
pub fn split_holder(holder: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(holder) = holder else {
        return (None, None);
    };
    if let Some((name, country)) = holder.rsplit_once(',') {
        let country_trim = country.trim();
        if country_trim.len() == 2 && country_trim.chars().all(|c| c.is_ascii_alphabetic()) {
            let name = name.trim();
            let name = if name.is_empty() { None } else { Some(name.to_string()) };
            return (name, Some(country_trim.to_ascii_uppercase()));
        }
    }
    let trimmed = holder.trim();
    if trimmed.is_empty() {
        (None, None)
    } else {
        (Some(trimmed.to_string()), None)
    }
}

/// Map the payload onto an [`AsnRecord`] for `asn::aggregate` (§6.3 quorum needs
/// ≥2 sources agreeing on country + ASN).
pub fn to_asn_record(body: &Value) -> Option<AsnRecord> {
    let data = body.get("data")?;
    let first_asn = data.get("asns").and_then(Value::as_array).and_then(|a| a.first());
    let asn = first_asn
        .and_then(|a| a.get("asn"))
        .and_then(Value::as_u64)
        .map(|a| a as u32);
    let holder = first_asn.and_then(|a| a.get("holder")).and_then(Value::as_str);
    let (name, rir_country) = split_holder(holder);
    let prefix = data
        .get("prefix")
        .and_then(Value::as_str)
        .or_else(|| data.get("resource").and_then(Value::as_str));

    if asn.is_none() && prefix.is_none() {
        return None;
    }

    Some(AsnRecord {
        source: ID.to_string(),
        asn,
        asn_name: data
            .get("shortname")
            .or_else(|| data.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| name.clone()),
        organisation: name,
        prefix: prefix.map(str::to_string),
        rir_country,
        registry: Some("RIR/BGP (RIPEstat)".to_string()),
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn ripestat_clean_returns_asn_and_rir_country() {
        let server = serve("ripestat.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "ripestat");
        assert_eq!(ev.category, Category::Asn);
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.source_url, "https://stat.ripe.net/");
        let raw = ev.raw.unwrap();
        assert_eq!(raw["asn"], 15169);
        assert_eq!(raw["rir_country"], "US");
        assert_eq!(raw["prefix"], "8.8.8.0/24");
        // ASN has no score scale (§6.1) — never fabricate one.
        assert!(ev.raw_score.is_none());
    }

    #[tokio::test]
    async fn ripestat_rate_limit_maps_to_quota() {
        let server = serve("ripestat.quota-403.json", 429).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là lỗi");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[test]
    fn ripestat_is_keyless() {
        // §5.2: RIPEstat needs no credential; a `no_key` path must not exist.
        assert!(!Adapter::new().requires_key());
        assert_eq!(Adapter::new().id(), "ripestat");
        assert_eq!(Adapter::new().category(), Category::Asn);
        assert_eq!(Adapter::new().upstream(), "ripestat");
    }

    #[tokio::test]
    async fn ripestat_error_body_with_200_maps_to_http() {
        let server = serve("ripestat.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là lỗi");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn ripestat_timeout_maps_to_timeout() {
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
    fn ripestat_holder_split_reads_rir_country() {
        assert_eq!(
            split_holder(Some("GOOGLE, US")),
            (Some("GOOGLE".to_string()), Some("US".to_string()))
        );
        assert_eq!(
            split_holder(Some("STARK-INDUSTRIES, MD")),
            (Some("STARK-INDUSTRIES".to_string()), Some("MD".to_string()))
        );
        assert_eq!(split_holder(Some("JUSTNAME")), (Some("JUSTNAME".to_string()), None));
        assert_eq!(split_holder(None), (None, None));
    }

    #[test]
    fn ripestat_asn_record_feeds_aggregate() {
        let body: Value = serde_json::from_str(&fixture("ripestat.clean.json")).unwrap();
        let rec = to_asn_record(&body).expect("phải có record");
        assert_eq!(rec.asn, Some(15169));
        assert_eq!(rec.rir_country.as_deref(), Some("US"));
        assert_eq!(rec.prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(rec.source, "ripestat");
    }

    #[test]
    fn ripestat_endpoint_uses_resource_param() {
        let a = Adapter::with_base_url(client(), API_BASE, None);
        let ep = a.endpoint(&"8.8.8.8".parse().unwrap());
        assert!(ep.contains("resource=8.8.8.8"));
    }
}
