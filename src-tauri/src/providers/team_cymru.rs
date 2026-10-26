//! `team_cymru` adapter — Team Cymru DNS — IP → ASN qua origin.asn.cymru.com, không cần HTTP (§5.1).
//!
//! A DNS query, not an HTTP call: `method: dns` in `providers.yaml`. The reverse
//! the octets of the IP and look up
//! `<reversed-ip>.origin.asn.cymru.com` for a TXT record shaped like
//!
//! ```text
//! "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
//! ```
//!
//! Fields: ASN | BGP prefix | country (RIR registration) | RIR | allocation date.
//!
//! source_url: https://team-cymru.com/
//!
//! Error semantics that matter here (§5.3 DNSBL analogy):
//! * **NXDOMAIN / no record** → a valid "no data" answer, NOT an error: the
//!   provider simply abstains and votes `Unknown`.
//! * **SERVFAIL / timeout / IO** → a real error, mapped to `http` (resolver) or
//!   `timeout`. It must never be read as "not listed".

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::TokioAsyncResolver;

use crate::models::{AsnRecord, Category, ProviderError, ProviderEvidence, Signal};
use crate::providers::{Provider, Thresholds};

use super::ip_api::{err_timeout, evidence, perr};

/// Registry id used in `providers.yaml`.
pub const ID: &str = "team_cymru";
/// Root data source, for vote de-duplication (§6.2).
pub const UPSTREAM: &str = "team-cymru";

/// DNS zone for the origin ASN lookup (§5.1).
pub const ZONE: &str = "origin.asn.cymru.com";
/// Human-facing documentation page.
pub const SOURCE_URL: &str = "https://team-cymru.com/community-services/ip-asn-mapping/";

/// Undo the IP so it can be used as a DNS label (§5.3 convention):
/// `8.8.8.8` → `8.8.8.8` (octets reversed) and the IPv6 nibble form.
pub fn lookup_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{}", o[3], o[2], o[1], o[0], ZONE)
        }
        IpAddr::V6(v6) => {
            // Nibble-reversed, dot-separated, low nibble of the last byte first.
            let mut labels: Vec<String> = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            format!("{}.{}", labels.join("."), ZONE)
        }
    }
}

/// A parsed Team Cymru answer.
#[derive(Debug, Clone, PartialEq)]
pub struct CymruRecord {
    pub asn: Option<u32>,
    pub prefix: Option<String>,
    pub rir_country: Option<String>,
    pub registry: Option<String>,
    pub allocated_at: Option<String>,
}

/// Parse the TXT payload: `"ASN | prefix | country | rir | date"`.
///
/// The record is quoted and space-padded; extra fields may exist in future
/// revisions, so parsing is positional but tolerant of trailing extras.
pub fn parse_record(txt: &str) -> Option<CymruRecord> {
    let cleaned = txt.trim().trim_matches('"').trim();
    if cleaned.is_empty() {
        return None;
    }
    let fields: Vec<&str> = cleaned.split('|').map(str::trim).collect();
    if fields.len() < 2 {
        return None;
    }

    let asn = fields[0]
        .split_whitespace()
        .next()
        .and_then(|tok| tok.trim_start_matches("AS").trim_start_matches("as").parse::<u32>().ok());
    let prefix = non_empty(fields.get(1).copied());
    let rir_country = non_empty(fields.get(2).copied()).map(|c| c.to_ascii_uppercase());
    let registry = non_empty(fields.get(3).copied());
    let allocated_at = non_empty(fields.get(4).copied());

    if asn.is_none() && prefix.is_none() {
        return None;
    }

    Some(CymruRecord {
        asn,
        prefix,
        rir_country,
        registry,
        allocated_at,
    })
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("NA"))
        .map(str::to_string)
}

/// Transport used to fetch the TXT record — injectable so the tests can run
/// completely offline (no DNS traffic in CI).
#[async_trait]
pub trait DnsTransport: Send + Sync {
    /// Return every TXT string for `name`.
    ///
    /// `Ok(vec![])` means "the name exists but has no TXT"; `NoRecordsFound`
    /// is also mapped to `Ok(vec![])` by the resolver transport.
    async fn txt(&self, name: &str) -> Result<Vec<String>, ProviderError>;
}

/// Real resolver transport (system-configured resolvers).
#[derive(Debug, Clone)]
pub struct SystemResolver {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

impl SystemResolver {
    pub fn new(timeout: Duration) -> Self {
        use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, Protocol};

        let mut config = ResolverConfig::new();
        let mut opts = match hickory_resolver::system_conf::read_system_conf() {
            Ok((sys_cfg, sys_opts)) => {
                for ns in sys_cfg.name_servers() {
                    if let std::net::SocketAddr::V4(v4) = ns.socket_addr {
                        let ip = v4.ip();
                        if !ip.is_unspecified() && !ip.is_loopback() {
                            config.add_name_server(ns.clone());
                        }
                    }
                }
                sys_opts
            }
            Err(_) => ResolverOpts::default(),
        };

        if config.name_servers().is_empty() {
            for ip in [
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            ] {
                let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, 53));
                config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            }
        }

        opts.ip_strategy = LookupIpStrategy::Ipv4Only;
        opts.timeout = timeout;
        opts.attempts = 1;
        Self {
            resolver: TokioAsyncResolver::tokio(config, opts),
            timeout,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[async_trait]
impl DnsTransport for SystemResolver {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ProviderError> {
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let lookup = self.resolver.txt_lookup(fqdn.as_str()).await;
        match lookup {
            Ok(records) => {
                let mut out = Vec::new();
                for record in records.iter() {
                    let mut joined = String::new();
                    for chunk in record.iter() {
                        joined.push_str(&String::from_utf8_lossy(chunk));
                    }
                    if !joined.is_empty() {
                        out.push(joined);
                    }
                }
                Ok(out)
            }
            // NXDOMAIN / no TXT ⇒ "no data for this IP", not a failure.
            Err(err) if is_no_data(&err) => Ok(Vec::new()),
            Err(err) if err_kind_is_timeout(&err) => {
                Err(err_timeout(ID))
            }
            Err(err) => Err(perr("http", format!("{ID}: {err}"), None, true)),
        }
    }
}

fn err_kind_is_timeout(err: &ResolveError) -> bool {
    matches!(err.kind(), ResolveErrorKind::Timeout)
}

/// True for the "this name has no such record" family, which is a valid answer.
pub fn is_no_data(err: &ResolveError) -> bool {
    matches!(
        err.kind(),
        ResolveErrorKind::NoRecordsFound { .. }
    )
}

/// Adapter for Team Cymru's origin-AS DNS service.
pub struct Adapter {
    transport: Box<dyn DnsTransport>,
    thresholds: Option<Thresholds>,
    timeout: Duration,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("team_cymru::Adapter")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Adapter {
    /// Registry-construction constructor (§5.5 `all_adapters`). Keyless.
    pub fn new() -> Self {
        let timeout = Duration::from_millis(5000);
        Self {
            transport: Box::new(SystemResolver::new(timeout)),
            thresholds: None,
            timeout,
        }
    }

    /// Inject a custom transport (offline tests, or a hardened resolver).
    pub fn with_transport(mut self, transport: Box<dyn DnsTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Kept for signature symmetry: ASN has no score scale (§6.1).
    pub fn with_thresholds_from(mut self, thresholds: Option<Thresholds>) -> Self {
        self.thresholds = thresholds;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
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
        let started = Instant::now();
        let name = lookup_name(*ip);

        let answers = tokio::time::timeout(self.timeout, self.transport.txt(&name))
            .await
            .map_err(|_| err_timeout(ID))??;
        let latency_ms = started.elapsed().as_millis() as u64;

        let record = answers.iter().find_map(|txt| parse_record(txt));

        let Some(record) = record else {
            // NXDOMAIN / empty answer: abstain explicitly instead of erroring.
            let raw = serde_json::json!({
                "query": name,
                "answers": answers,
                "found": false,
            });
            return Ok(evidence(
                ID,
                Category::Asn,
                UPSTREAM,
                Signal::Unknown,
                None,
                Some(raw),
                SOURCE_URL,
                Some(latency_ms),
                Some("Team Cymru: không có bản ghi ASN cho IP này (NXDOMAIN)".to_string()),
            ));
        };

        let signal = if record.asn.is_some() && record.prefix.is_some() {
            Signal::Clean
        } else {
            Signal::Unknown
        };

        let reason = match (record.asn, record.prefix.as_deref()) {
            (Some(asn), Some(prefix)) => Some(format!("Team Cymru: AS{asn} công bố {prefix}")),
            _ => Some("Team Cymru: bản ghi thiếu ASN hoặc prefix".to_string()),
        };

        let raw = serde_json::json!({
            "query": name,
            "asn": record.asn,
            "prefix": record.prefix,
            "rir_country": record.rir_country,
            "registry": record.registry,
            "allocated_at": record.allocated_at,
            "found": true,
            "raw_txt": answers.first(),
        });

        Ok(evidence(
            ID,
            Category::Asn,
            UPSTREAM,
            signal,
            None,
            Some(raw),
            SOURCE_URL,
            Some(latency_ms),
            reason,
        ))
    }
}

/// Map an answer onto an [`AsnRecord`] for `asn::aggregate` (§6.3).
pub fn to_asn_record(txt: &str) -> Option<AsnRecord> {
    let parsed = parse_record(txt)?;
    Some(AsnRecord {
        source: ID.to_string(),
        asn: parsed.asn,
        asn_name: None,
        organisation: None,
        prefix: parsed.prefix,
        rir_country: parsed.rir_country,
        registry: parsed.registry,
        note: parsed.allocated_at.map(|d| format!("allocated {d}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_cymru_is_keyless_and_dns_only() {
        // §5.1: Team Cymru is answered over DNS, not HTTP.
        let a = Adapter::new();
        assert!(!a.requires_key());
        assert_eq!(a.id(), "team_cymru");
        assert_eq!(a.category(), Category::Asn);
        assert_eq!(a.upstream(), "team-cymru");
    }


    /// Offline transport: replays a fixture string, or one of the error modes.
    #[derive(Debug)]
    struct FixtureTransport {
        mode: FixtureMode,
    }

    #[derive(Debug)]
    enum FixtureMode {
        Answer(String),
        NoData,
        Servfail,
        Slow,
    }

    #[async_trait]
    impl DnsTransport for FixtureTransport {
        async fn txt(&self, name: &str) -> Result<Vec<String>, ProviderError> {
            match &self.mode {
                FixtureMode::Answer(body) => {
                    let cleaned = body.trim().trim_matches('"');
                    Ok(vec![cleaned.to_string()])
                }
                FixtureMode::NoData => Ok(Vec::new()),
                FixtureMode::Servfail => Err(perr("http", format!("{ID}: SERVFAIL for {name}"), None, true)),
                FixtureMode::Slow => {
                    tokio::time::sleep(Duration::from_millis(3000)).await;
                    Ok(Vec::new())
                }
            }
        }
    }

    fn fixture(name: &str) -> String {
        let path = format!("{}/../tests/fixtures/providers/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("đọc fixture {path}: {e}"))
    }

    fn adapter(mode: FixtureMode) -> Adapter {
        Adapter::new()
            .with_transport(Box::new(FixtureTransport { mode }))
            .with_timeout(Duration::from_millis(500))
    }

    #[test]
    fn cymru_lookup_name_reverses_octets() {
        assert_eq!(
            lookup_name("8.8.8.8".parse().unwrap()),
            "8.8.8.8.origin.asn.cymru.com"
        );
        assert_eq!(
            lookup_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.origin.asn.cymru.com"
        );
    }

    #[test]
    fn cymru_lookup_name_handles_ipv6() {
        let name = lookup_name("2001:4860:4860::8888".parse().unwrap());
        assert!(name.ends_with(".origin.asn.cymru.com"), "{name}");
        // 32 nibble labels + zone.
        assert_eq!(name.trim_end_matches(".origin.asn.cymru.com").split('.').count(), 32);
    }

    #[tokio::test]
    async fn cymru_clean_answer_maps_to_asn() {
        let a = adapter(FixtureMode::Answer(fixture("team_cymru.clean.txt")));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = a.check(&ip).await.expect("phải thành công");
        assert_eq!(ev.provider, "team_cymru");
        assert_eq!(ev.category, Category::Asn);
        assert_eq!(ev.signal, Signal::Clean);
        assert_eq!(ev.source_url, SOURCE_URL);
        let raw = ev.raw.unwrap();
        assert_eq!(raw["asn"], 15169);
        assert_eq!(raw["rir_country"], "US");
        assert_eq!(raw["registry"], "arin");
        assert!(ev.raw_score.is_none());
    }

    #[tokio::test]
    async fn cymru_bad_answer_still_parses() {
        let a = adapter(FixtureMode::Answer(fixture("team_cymru.bad.txt")));
        let ip: IpAddr = "45.155.205.1".parse().unwrap();
        let ev = a.check(&ip).await.expect("phải thành công");
        let raw = ev.raw.unwrap();
        assert_eq!(raw["asn"], 44477);
        assert_eq!(raw["rir_country"], "MD");
    }

    #[tokio::test]
    async fn cymru_nxdomain_is_unknown_not_an_error() {
        let a = adapter(FixtureMode::NoData);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ev = a.check(&ip).await.expect("NXDOMAIN không phải lỗi");
        assert_eq!(ev.signal, Signal::Unknown);
        assert_eq!(ev.raw.unwrap()["found"], false);
    }

    #[tokio::test]
    async fn cymru_servfail_is_an_error_not_not_listed() {
        let a = adapter(FixtureMode::Servfail);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = a.check(&ip).await.expect_err("SERVFAIL phải là lỗi");
        assert_eq!(err.kind, "http");
    }

    #[tokio::test]
    async fn cymru_timeout_maps_to_timeout() {
        let a = adapter(FixtureMode::Slow).with_timeout(Duration::from_millis(300));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let err = a.check(&ip).await.expect_err("phải là timeout");
        assert_eq!(err.kind, "timeout");
    }

    #[test]
    fn cymru_parse_record_tolerates_quotes_and_spaces() {
        let rec = parse_record("\"15169 | 8.8.8.0/24 | US | arin | 2014-03-14\"").unwrap();
        assert_eq!(rec.asn, Some(15169));
        assert_eq!(rec.prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(rec.rir_country.as_deref(), Some("US"));
        assert_eq!(rec.registry.as_deref(), Some("arin"));
        assert_eq!(rec.allocated_at.as_deref(), Some("2014-03-14"));
    }

    #[test]
    fn cymru_parse_record_rejects_garbage() {
        assert!(parse_record("").is_none());
        assert!(parse_record("   ").is_none());
        assert!(parse_record("not an answer").is_none());
        assert!(parse_record("NA | NA").is_none());
    }

    #[test]
    fn cymru_to_asn_record_feeds_aggregate() {
        let rec = to_asn_record(&fixture("team_cymru.clean.txt")).expect("phải parse được");
        assert_eq!(rec.asn, Some(15169));
        assert_eq!(rec.prefix.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(rec.rir_country.as_deref(), Some("US"));
        assert_eq!(rec.source, "team_cymru");
    }

    #[test]
    fn cymru_is_no_data_recognises_timeout_distinctly() {
        // Guard the semantics that matter: timeout is NOT "no data".
        let timeout_err = ResolveError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));
        assert!(!is_no_data(&timeout_err));
    }
}
