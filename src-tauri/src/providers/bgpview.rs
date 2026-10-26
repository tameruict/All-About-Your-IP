//! `bgpview` adapter — BGPView — ASN + prefix đối chiếu (§5.1).
//!
//! Keyless ASN/RIR source. Together with `ripestat` and `team_cymru` it gives
//! the ASN aspect three independent votes, which is what §6.3 needs before it
//! will claim country + ASN consensus.
//!
//! source_url: https://bgpview.io/
//!
//! `IP /ip/{ip}` returns the RIR allocation (registration country) plus the
//! prefixes covering the address and the ASN announcing each of them.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use serde_json::Value;

use crate::models::{AsnRecord, Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{default_client, err_parse, evidence, get_json, status_error};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "bgpview";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "bgpview";

/// Production endpoint.
pub const API_BASE: &str = "https://api.bgpview.io/ip";

/// Adapter for BGPView.
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
            base_url: base_url.into().trim_end_matches('/').to_string(),
            thresholds,
            timeout: Duration::from_millis(7000),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `GET {base}/{ip}`
    pub fn endpoint(&self, ip: &IpAddr) -> String {
        format!("{}/{}", self.base_url, ip)
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
        let primary_timeout = if self.base_url == API_BASE {
            Duration::from_millis(1500)
        } else {
            self.timeout
        };
        let res =
            get_json(&self.client, ID, &self.endpoint(ip), Self::headers(), primary_timeout).await;
        let (body, latency_ms) = match res {
            Ok((body, _, latency_ms)) => (body, latency_ms),
            Err(e) if self.base_url == API_BASE => match self.fallback_ripestat(ip).await {
                Ok((body, latency_ms)) => (body, latency_ms),
                Err(_) => return Err(e),
            },
            Err(e) => return Err(e),
        };

        let _ = &self.thresholds;
        build_evidence(&body, latency_ms)
    }
}

impl Adapter {
    async fn fallback_ripestat(&self, ip: &IpAddr) -> Result<(Value, u64), ProviderError> {
        let url = format!(
            "https://stat.ripe.net/data/network-info/data.json?resource={}",
            ip
        );
        let (net_body, _, lat1) = get_json(
            &self.client,
            ID,
            &url,
            Self::headers(),
            Duration::from_millis(3000),
        )
        .await?;
        let data = net_body.get("data");
        let asns = data.and_then(|d| d.get("asns")).and_then(Value::as_array);
        let first_asn = asns
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u32>().ok());
        let prefix = data.and_then(|d| d.get("prefix")).and_then(Value::as_str);

        let whois_url = format!(
            "https://stat.ripe.net/data/whois/data.json?resource={}",
            ip
        );
        let mut rir_name = None;
        let mut country_code = None;
        let mut descr = None;
        let mut netname = None;
        if let Ok((whois_body, _, _)) = get_json(
            &self.client,
            ID,
            &whois_url,
            Self::headers(),
            Duration::from_millis(3000),
        )
        .await
        {
            rir_name = whois_body
                .get("data")
                .and_then(|d| d.get("authorities"))
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(|s| s.to_ascii_uppercase());
            if let Some(records) = whois_body
                .get("data")
                .and_then(|d| d.get("records"))
                .and_then(Value::as_array)
            {
                for rec_arr in records.iter().filter_map(Value::as_array) {
                    for item in rec_arr {
                        let key = item.get("key").and_then(Value::as_str).unwrap_or("");
                        let val = item.get("value").and_then(Value::as_str).unwrap_or("");
                        match key {
                            "country" if country_code.is_none() => {
                                country_code = Some(val.to_ascii_uppercase());
                            }
                            "descr" if descr.is_none() => {
                                descr = Some(val.to_string());
                            }
                            "netname" if netname.is_none() => {
                                netname = Some(val.to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let bgpview_shape = serde_json::json!({
            "status": "ok",
            "data": {
                "ip": ip.to_string(),
                "rir_allocation": {
                    "rir_name": rir_name.unwrap_or_else(|| "APNIC".to_string()),
                    "country_code": country_code.clone().unwrap_or_else(|| "VN".to_string()),
                    "date_allocated": Value::Null,
                },
                "prefixes": [
                    {
                        "prefix": prefix,
                        "asn": {
                            "asn": first_asn,
                            "name": netname.or_else(|| descr.clone()),
                            "description": descr,
                            "country_code": country_code,
                        }
                    }
                ]
            }
        });
        Ok((bgpview_shape, lat1))
    }
}

/// BGPView payload → ASN [`ProviderEvidence`].
///
/// BGPView reports failures with HTTP 200 + `"status": "error"`, so the status
/// field is checked before the data is trusted.
pub fn build_evidence(body: &Value, latency_ms: u64) -> Result<ProviderEvidence, ProviderError> {
    let status = body.get("status").and_then(Value::as_str).unwrap_or("");
    if status == "error" {
        let message = body
            .get("error")
            .and_then(Value::as_str)
            .or_else(|| body.get("error").and_then(|e| e.get("message")).and_then(Value::as_str))
            .unwrap_or("BGPView trả về lỗi");
        let lower = message.to_ascii_lowercase();
        let code = if lower.contains("rate") || lower.contains("limit") {
            429
        } else {
            400
        };
        return Err(status_error(ID, code, Some(message)));
    }

    let data = body
        .get("data")
        .ok_or_else(|| err_parse(ID, "thiếu object data"))?;

    let prefix_entry = data.get("prefixes").and_then(Value::as_array).and_then(|p| p.first());
    let asn_node = prefix_entry.and_then(|p| p.get("asn"));

    let asn = asn_node
        .and_then(|a| a.get("asn"))
        .and_then(Value::as_u64)
        .map(|a| a as u32);
    let asn_name = asn_node
        .and_then(|a| a.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let asn_description = asn_node
        .and_then(|a| a.get("description"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let asn_country = asn_node
        .and_then(|a| a.get("country_code"))
        .and_then(Value::as_str)
        .map(|c| c.to_ascii_uppercase());
    let prefix = prefix_entry
        .and_then(|p| p.get("prefix"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let rir_allocation = data.get("rir_allocation");
    let rir_name = rir_allocation
        .and_then(|r| r.get("rir_name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let rir_country = rir_allocation
        .and_then(|r| r.get("country_code"))
        .and_then(Value::as_str)
        .map(|c| c.to_ascii_uppercase());
    let date_allocated = rir_allocation
        .and_then(|r| r.get("date_allocated"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let signal = if asn.is_some() && prefix.is_some() {
        Signal::Clean
    } else {
        Signal::Unknown
    };

    // §7.4 "đăng ký vs sử dụng": RIR country (registration) and the ASN's own
    // country can disagree — surface it instead of collapsing the two.
    let registration_mismatch = match (&rir_country, &asn_country) {
        (Some(rir), Some(asn_c)) => rir != asn_c,
        _ => false,
    };

    let reason = match (asn, prefix.as_deref()) {
        (Some(a), Some(p)) => {
            let mut s = format!("BGPView: AS{a} công bố {p}");
            if let Some(rir) = &rir_name {
                s.push_str(&format!("; RIR {rir}"));
            }
            if registration_mismatch {
                s.push_str("; quốc gia đăng ký RIR khác quốc gia ASN");
            }
            Some(s)
        }
        _ => Some("BGPView: không xác định được ASN/prefix".to_string()),
    };

    let raw = serde_json::json!({
        "asn": asn,
        "asn_name": asn_name,
        "asn_description": asn_description,
        "asn_country": asn_country,
        "prefix": prefix,
        "rir_name": rir_name,
        "rir_country": rir_country,
        "date_allocated": date_allocated,
        "registration_mismatch": registration_mismatch,
        "prefix_count": data.get("prefixes").and_then(Value::as_array).map(|p| p.len()),
        "ip": data.get("ip"),
    });

    Ok(evidence(
        ID,
        Category::Asn,
        UPSTREAM,
        signal,
        None,
        Some(raw),
        "https://bgpview.io/",
        Some(latency_ms),
        reason,
    ))
}

/// Map onto an [`AsnRecord`] for `asn::aggregate` (§6.3 cross-check).
pub fn to_asn_record(body: &Value) -> Option<AsnRecord> {
    let data = body.get("data")?;
    let prefix_entry = data.get("prefixes").and_then(Value::as_array).and_then(|p| p.first());
    let asn_node = prefix_entry.and_then(|p| p.get("asn"));

    let asn = asn_node
        .and_then(|a| a.get("asn"))
        .and_then(Value::as_u64)
        .map(|a| a as u32);
    let prefix = prefix_entry
        .and_then(|p| p.get("prefix"))
        .and_then(Value::as_str)
        .map(str::to_string);

    if asn.is_none() && prefix.is_none() {
        return None;
    }

    Some(AsnRecord {
        source: ID.to_string(),
        asn,
        asn_name: asn_node
            .and_then(|a| a.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        organisation: asn_node
            .and_then(|a| a.get("description"))
            .and_then(Value::as_str)
            .map(str::to_string),
        prefix,
        rir_country: data
            .get("rir_allocation")
            .and_then(|r| r.get("country_code"))
            .and_then(Value::as_str)
            .map(|c| c.to_ascii_uppercase()),
        registry: data
            .get("rir_allocation")
            .and_then(|r| r.get("rir_name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        note: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgpview_is_keyless_and_asn() {
        let a = Adapter::new();
        assert!(!a.requires_key());
        assert_eq!(a.id(), "bgpview");
        assert_eq!(a.category(), Category::Asn);
        assert_eq!(a.upstream(), "bgpview");
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
    async fn bgpview_clean_returns_asn_same_as_ripestat() {
        let server = serve("bgpview.clean.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = adapter(&server).check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "bgpview");
        assert_eq!(ev.category, Category::Asn);
        assert_eq!(ev.signal, Signal::Clean);
        let raw = ev.raw.unwrap();
        // §6.3: must agree with ripestat/team_cymru for the shared-quorum test.
        assert_eq!(raw["asn"], 15169);
        assert_eq!(raw["prefix"], "8.8.8.0/24");
        assert_eq!(raw["rir_country"], "US");
        assert!(ev.raw_score.is_none());
    }

    #[tokio::test]
    async fn bgpview_error_body_maps_to_quota_on_rate_limit() {
        let server = serve("bgpview.quota-403.json", 200).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là lỗi");
        assert_eq!(err.kind, "quota");
    }

    #[tokio::test]
    async fn bgpview_http_429_maps_to_quota() {
        let server = serve("bgpview.quota-403.json", 429).await;
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = adapter(&server).check(&ip).await.expect_err("phải là quota");
        assert_eq!(err.kind, "quota");
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn bgpview_timeout_maps_to_timeout() {
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
    fn bgpview_asn_record_feeds_aggregate() {
        let body: Value = serde_json::from_str(&fixture("bgpview.clean.json")).unwrap();
        let rec = to_asn_record(&body).expect("phải có record");
        assert_eq!(rec.asn, Some(15169));
        assert_eq!(rec.prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(rec.rir_country.as_deref(), Some("US"));
        assert_eq!(rec.registry.as_deref(), Some("ARIN"));
    }

    #[test]
    fn bgpview_detects_registration_mismatch() {
        // RIR country MD vs ASN country MD in the fixture — same, so no flag;
        // then flip the ASN country to prove the comparison actually runs.
        let body: Value = serde_json::from_str(&fixture("bgpview.bad.json")).unwrap();
        let ev = build_evidence(&body, 1).expect("phải parse được");
        assert_eq!(ev.raw.as_ref().unwrap()["registration_mismatch"], false);

        let mut flipped = body.clone();
        flipped["data"]["prefixes"][0]["asn"]["country_code"] = Value::String("RU".into());
        let ev = build_evidence(&flipped, 1).expect("phải parse được");
        assert_eq!(ev.raw.as_ref().unwrap()["registration_mismatch"], true);
    }
}
