//! Shared data model for IP Checker.
//!
//! Every struct here is serialised to JSON and consumed by
//! `src/lib/types.ts`. Field names are snake_case and MUST stay in sync with
//! that file (spec §4.4, §6.6, §10.1). Producers live in the module that owns
//! the data (`validator`, `dnsbl`, `network`, ...); the orchestrator assembles
//! them into [`FullCheckResult`].

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// §1.2 — the two mandatory modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckMode {
    IpOnly,
    Proxy,
    #[default]
    Unknown,
}

/// §4.4 `Provider::category`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Geo,
    Asn,
    Fraud,
    Abuse,
    ThreatIntel,
    Blacklist,
    Network,
    Leak,
    Speed,
    LocalDb,
}

/// §6.1 normalised provider verdict.
///
/// Deliberately PascalCase: spec §6.6 shows `"signal": "Clean"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    Clean,
    Suspicious,
    Bad,
    Unknown,
}

impl Default for Signal {
    fn default() -> Self {
        Signal::Unknown
    }
}

/// §6.5 final verdict. Vietnamese labels, kept verbatim.
///
/// The wire value is the **display label**, not the Rust variant name: the TS
/// contract (`src/lib/types.ts`) declares
/// `"Sạch" | "Tạm" | "Nghi ngờ" | "Bẩn" | "Chưa đủ dữ liệu"`.
/// `rename_all` cannot express that because two labels contain a space, so every
/// variant is renamed explicitly. Keep these in lock-step with [`Verdict::as_str`]
/// — `verdict_wire_value_equals_as_str` guards it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "Sạch")]
    Sạch,
    #[serde(rename = "Tạm")]
    Tạm,
    #[serde(rename = "Nghi ngờ")]
    NghiNgờ,
    #[serde(rename = "Bẩn")]
    Bẩn,
    #[serde(rename = "Chưa đủ dữ liệu")]
    ChưaĐủDữLiệu,
}

// The Vietnamese variants contain spaces / diacritics, so spell them out.
#[allow(non_upper_case_globals)]
impl Verdict {
    pub const Sach: Verdict = Verdict::Sạch;
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict::ChưaĐủDữLiệu
    }
}

impl Verdict {
    /// Label as rendered in the UI.
    ///
    /// This is also the serialised value — `as_str()` and the `#[serde(rename)]`
    /// attributes above MUST stay in sync; `verdict_wire_value_equals_as_str`
    /// asserts it on every build.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Sạch => "Sạch",
            Verdict::Tạm => "Tạm",
            Verdict::NghiNgờ => "Nghi ngờ",
            Verdict::Bẩn => "Bẩn",
            Verdict::ChưaĐủDữLiệu => "Chưa đủ dữ liệu",
        }
    }

    /// Does this verdict mean "we could not conclude anything"?
    ///
    /// Used by the orchestrator to drop `clean_score` before it reaches the UI:
    /// showing `88.9` next to an inconclusive verdict reads as "this IP is
    /// clean" while the machine is saying the opposite (§1.2, §6.4).
    pub fn is_inconclusive(&self) -> bool {
        matches!(self, Verdict::ChưaĐủDữLiệu)
    }
}

/// §3.3 per-module progress state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleStatus {
    Pending,
    Running,
    Done,
    Error,
    Skipped,
}

/// §3.3 why a module was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    MissingKey,
    RequiresProxy,
    QuotaExhausted,
    Disabled,
    CircuitOpen,
    NotImplemented,
    UnsupportedIp,
}

/// IP classification used for location-confidence weighting (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpType {
    Residential,
    Datacenter,
    Mobile,
    Cgnat,
    Vpn,
    Tor,
    Proxy,
    Anycast,
    Edu,
    Unknown,
}

impl Default for IpType {
    fn default() -> Self {
        IpType::Unknown
    }
}

/// §4.2 / §10.3 export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Json,
    Csv,
}

/// §5.5 provider health colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Green,
    Yellow,
    Red,
    Unknown,
}

/// §6.1 how a listed DNSBL hit must be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListedVerdict {
    Bad,
    Suspicious,
}

/// §5.3 — a DNSBL *group* is one vote, individual zones are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsblGroup {
    Spamhaus,
    Commercial,
    Community,
    Specialist,
}

/// §3.3 module identifiers used in the streaming progress event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    Validate,
    Geo,
    Asn,
    Fraud,
    Abuse,
    ThreatIntel,
    Dnsbl,
    Network,
    Location,
    ExitIp,
    Leak,
    Speed,
    Scoring,
}

/// Proxy protocol for §8 proxy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks5,
    Socks4,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// §4.4 `ProviderError`, serialised uniformly for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderError {
    pub kind: String,
    pub message: String,
    pub status: Option<u16>,
    pub retryable: bool,
}

impl ProviderError {
    pub fn new(kind: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            status: None,
            retryable,
        }
    }

    pub fn timeout() -> Self {
        Self::new("timeout", "Provider không phản hồi trong thời gian cho phép", true)
    }

    /// Thiếu credential — không retry, không chặn toàn bộ check (§13.4).
    ///
    /// `retryable` MUST stay `false`: §4.3 forbids a retry storm when a key is
    /// simply missing, and `orchestrator` asserts this in tests.
    pub fn no_key(provider: &str) -> Self {
        Self::new(
            "no_key",
            format!("{provider}: chưa cấu hình API key"),
            false,
        )
    }
}

/// Uniform rejection shape for every Tauri command (§3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    pub kind: String,
    pub message: String,
    pub detail: Option<String>,
}

impl CommandError {
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            detail: None,
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for CommandError {}

// ---------------------------------------------------------------------------
// Evidence (§4.4)
// ---------------------------------------------------------------------------

/// Normalised provider result — scoring and UI never read provider-private fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEvidence {
    pub provider: String,
    pub category: Category,
    pub upstream: String,
    pub signal: Signal,
    pub raw_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
    pub checked_at: String,
    pub source_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProviderError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub from_cache: bool,
}

/// Spec wording alias (§4.4 uses `Evidence` in prose).
pub type Evidence = ProviderEvidence;

// ---------------------------------------------------------------------------
// Geo / location (§7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoPoint {
    pub source: String,
    pub source_kind: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub postal: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub accuracy_radius_km: Option<f64>,
    pub db_version: Option<String>,
    pub db_updated_at: Option<String>,
    pub distance_from_centroid_km: Option<f64>,
    #[serde(default)]
    pub over_precise: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocationResult {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub country_confidence: f64,
    pub city: Option<String>,
    pub region: Option<String>,
    pub centroid_latitude: Option<f64>,
    pub centroid_longitude: Option<f64>,
    pub radius_km: Option<f64>,
    pub spread: String,
    pub points: Vec<GeoPoint>,
    #[serde(default)]
    pub big_divergence: bool,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_since_last_check: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_city: Option<String>,
}

// ---------------------------------------------------------------------------
// ASN (§5.1, §7.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsnRecord {
    pub source: String,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub organisation: Option<String>,
    pub prefix: Option<String>,
    pub rir_country: Option<String>,
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// §5.1 hosting / proxy / mobile / tor flags.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct IpFlags {
    #[serde(default)]
    pub hosting: bool,
    #[serde(default)]
    pub proxy: bool,
    #[serde(default)]
    pub vpn: bool,
    #[serde(default)]
    pub tor: bool,
    #[serde(default)]
    pub mobile: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anycast: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsnResult {
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub organisation: Option<String>,
    pub prefix: Option<String>,
    pub isp: Option<String>,
    pub rir_country: Option<String>,
    #[serde(default)]
    pub consensus: bool,
    #[serde(default)]
    pub country_mismatch: bool,
    pub records: Vec<AsnRecord>,
    pub ip_type: IpType,
    pub flags: IpFlags,
}

// ---------------------------------------------------------------------------
// Network probe (§9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TracerouteHop {
    pub hop: u32,
    pub address: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_international: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkResult {
    pub ping_method: String,
    pub latency_avg_ms: Option<f64>,
    pub latency_min_ms: Option<f64>,
    pub latency_max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub packets_sent: Option<u32>,
    pub packets_received: Option<u32>,
    pub packet_loss_pct: Option<f64>,
    pub reverse_dns: Option<String>,
    pub reverse_dns_matches_isp: Option<bool>,
    pub ttl: Option<u32>,
    pub os_guess: Option<String>,
    pub traceroute_hops: Vec<TracerouteHop>,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// DNSBL (§5.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblEntry {
    pub provider: String,
    pub zone: String,
    pub group: DnsblGroup,
    pub listed: bool,
    pub return_codes: Vec<String>,
    pub signal: Signal,
    pub listed_verdict: ListedVerdict,
    pub reason: Option<String>,
    pub source_url: String,
    pub checked_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProviderError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblGroupResult {
    pub group: DnsblGroup,
    pub label: String,
    pub checked: u32,
    pub listed: u32,
    pub signal: Signal,
    #[serde(default)]
    pub answered: bool,
    pub entries: Vec<DnsblEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsblResult {
    pub groups: Vec<DnsblGroupResult>,
    pub total_listed: u32,
    pub groups_answered: u32,
    #[serde(default)]
    pub hard_hit: bool,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Proxy mode: exit IP / leak / speed (§8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitIpEndpoint {
    pub endpoint: String,
    pub ok: bool,
    pub exit_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExitIpResult {
    #[serde(default)]
    pub reachable: bool,
    pub endpoint_results: Vec<ExitIpEndpoint>,
    pub exit_ip: Option<String>,
    #[serde(default)]
    pub differs_from_input: bool,
    #[serde(default)]
    pub endpoints_disagree: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeakResult {
    #[serde(default)]
    pub measured: bool,
    #[serde(default)]
    pub webrtc_leak: bool,
    pub webrtc_candidates: Vec<String>,
    pub dns_leak: Option<bool>,
    pub dns_method: String,
    pub dns_resolver_seen: Option<String>,
    pub browser_timezone: Option<String>,
    pub ip_timezone: Option<String>,
    #[serde(default)]
    pub timezone_mismatch: bool,
    pub browser_language: Option<String>,
    pub ip_country: Option<String>,
    #[serde(default)]
    pub country_mismatch: bool,
    pub headless_flags: Vec<String>,
    pub ja3: Option<String>,
    pub ja3_source: Option<String>,
    pub tcp_fingerprint_mismatch: Option<bool>,
    #[serde(default)]
    pub downgrade: bool,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProviderError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedEndpoint {
    pub endpoint: String,
    pub ok: bool,
    pub download_mbps: Option<f64>,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub bytes: Option<u64>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpeedResult {
    #[serde(default)]
    pub measured: bool,
    pub endpoints: Vec<SpeedEndpoint>,
    pub download_mbps: Option<f64>,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub measured_at: Option<String>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProviderError>,
}

// ---------------------------------------------------------------------------
// Scoring (§6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub aspect: String,
    pub weight: f64,
    pub aspect_score: Option<f64>,
    pub weighted: Option<f64>,
    pub votes: u32,
    #[serde(default)]
    pub quorum_met: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictFlag {
    pub severity: String,
    pub aspect: String,
    pub dissenting: Vec<String>,
    pub agreeing: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumStatus {
    pub aspect: String,
    pub required: u32,
    pub actual: u32,
    #[serde(default)]
    pub met: bool,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScoringResult {
    pub clean_score: Option<f64>,
    pub confidence_score: f64,
    pub verdict: Verdict,
    pub verdict_reason: String,
    pub breakdown: Vec<ScoreBreakdown>,
    pub conflicts: Vec<ConflictFlag>,
    pub quorum: Vec<QuorumStatus>,
    #[serde(default)]
    pub single_source_evidence: bool,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Progress / session (§3.3, §4.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleState {
    pub module: ModuleId,
    pub status: ModuleStatus,
    pub progress: u8,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub providers_done: u32,
    pub providers_total: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProviderError>,
}

impl ModuleState {
    pub fn new(module: ModuleId) -> Self {
        Self {
            module,
            status: ModuleStatus::Pending,
            progress: 0,
            started_at: None,
            finished_at: None,
            providers_done: 0,
            providers_total: 0,
            skip_reason: None,
            message: String::new(),
            error: None,
        }
    }
}

/// Payload of the `check-progress` Tauri event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckProgressEvent {
    pub check_id: String,
    pub started_at: String,
    pub module: ModuleId,
    pub status: ModuleStatus,
    pub progress: u8,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<serde_json::Value>,
    pub modules: Vec<ModuleState>,
}

/// One console line for the streaming log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckLogLine {
    pub check_id: String,
    pub at: String,
    pub module: ModuleId,
    pub level: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Request inputs
// ---------------------------------------------------------------------------

/// Transient proxy credentials — never persisted (§8.4, §10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckOptions {
    #[serde(default)]
    pub protocol: Option<ProxyProtocol>,
    #[serde(default)]
    pub credentials: Option<ProxyCredentials>,
    #[serde(default)]
    pub use_cache: Option<bool>,
    #[serde(default)]
    pub save_to_history: Option<bool>,
    #[serde(default)]
    pub run_leak_check: Option<bool>,
    #[serde(default)]
    pub run_speed_check: Option<bool>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub modules: Option<Vec<ModuleId>>,
}

// ---------------------------------------------------------------------------
// Core result (§4.2, §6.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCheckResult {
    pub check_id: String,
    /// Convenience alias, always equal to `check_id`.
    pub id: String,
    pub ip: String,
    pub mode: CheckMode,
    pub clean_score: Option<f64>,
    #[serde(default)]
    pub clean_score_provisional: bool,
    #[serde(default)]
    pub clean_score_is_provisional: bool,
    pub confidence_score: f64,
    pub verdict: Verdict,
    pub verdict_reason: String,
    pub evidence: Vec<ProviderEvidence>,
    pub checked_at: String,
    #[serde(default)]
    pub from_cache: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<ProxyProtocol>,

    #[serde(default)]
    pub is_private: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<LocationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<AsnResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsbl: Option<DnsblResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<ExitIpResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leak: Option<LeakResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<SpeedResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<ScoringResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_health: Option<Vec<ProviderHealth>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_db_versions: Option<Vec<GeoDbVersion>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modules: Option<Vec<ModuleState>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
}

impl FullCheckResult {
    /// Minimal valid result for the "private / invalid IP" short-circuit (§3.4).
    pub fn short_circuit(check_id: String, ip: String, reason: String) -> Self {
        Self {
            id: check_id.clone(),
            check_id,
            ip,
            mode: CheckMode::Unknown,
            clean_score: None,
            clean_score_provisional: true,
            clean_score_is_provisional: true,
            confidence_score: 0.0,
            verdict: Verdict::ChưaĐủDữLiệu,
            verdict_reason: reason.clone(),
            evidence: Vec::new(),
            checked_at: chrono::Utc::now().to_rfc3339(),
            from_cache: false,
            proxy_host: None,
            proxy_port: None,
            proxy_protocol: None,
            is_private: false,
            validation_error: Some(reason),
            ip_version: None,
            location: None,
            asn: None,
            dnsbl: None,
            network: None,
            exit_ip: None,
            leak: None,
            speed: None,
            scoring: None,
            provider_health: None,
            geo_db_versions: None,
            modules: None,
            duration_ms: None,
            app_version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSession {
    pub check_id: String,
    pub input: String,
    pub ip: String,
    pub mode: CheckMode,
    pub started_at: String,
    pub finished_at: Option<String>,
    #[serde(default)]
    pub complete: bool,
    pub result: Option<FullCheckResult>,
    pub modules: Vec<ModuleState>,
    pub errors: Vec<ProviderError>,
}

/// §10.1 `checks` row projected for the history panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSummary {
    pub check_id: String,
    pub ip: String,
    pub mode: CheckMode,
    pub proxy_host: Option<String>,
    pub proxy_port: Option<u16>,
    pub proxy_protocol: Option<ProxyProtocol>,
    pub clean_score: Option<f64>,
    pub confidence_score: Option<f64>,
    pub verdict: Option<Verdict>,
    pub verdict_reason: Option<String>,
    pub checked_at: String,
}

// ---------------------------------------------------------------------------
// Health / settings (§5.5, §10.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub provider: String,
    pub category: Category,
    pub upstream: String,
    pub state: HealthState,
    pub success_rate: f64,
    pub latency_avg_ms: Option<f64>,
    pub last_error_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    #[serde(default)]
    pub circuit_open: bool,
    pub circuit_open_until: Option<String>,
    pub effective_weight: f64,
    pub configured_weight: f64,
    #[serde(default)]
    pub requires_key: bool,
    #[serde(default)]
    pub has_key: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub quota_exhausted: bool,
    pub quota_reset_at: Option<String>,
    pub db_version: Option<String>,
    pub db_updated_at: Option<String>,
    pub total_checks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDbVersion {
    pub db_name: String,
    pub version: Option<String>,
    pub updated_at: Option<String>,
    #[serde(default)]
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSetting {
    pub provider: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub timeout_ms: Option<u64>,
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub has_key: bool,
    #[serde(default)]
    pub key_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblGroupSetting {
    pub group: DnsblGroup,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Global settings. API keys are NOT part of this struct — they live in
/// Windows Credential Manager via [`crate::config`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub providers: Vec<ProviderSetting>,
    pub default_timeout_ms: u64,
    pub max_concurrency: usize,
    pub circuit_failure_threshold: u32,
    pub circuit_cooldown_minutes: u32,

    pub dnsbl_groups: Vec<DnsblGroupSetting>,
    pub dnsbl_enabled: bool,

    pub save_history: bool,
    pub cache_ttl_geo_hours: u32,
    pub cache_ttl_reputation_hours: u32,
    pub cache_ttl_blacklist_hours: u32,
    pub cache_ttl_abuse_hours: u32,

    pub leak_check_enabled: bool,
    pub speed_check_enabled: bool,
    pub browser_path: String,

    pub export_dir: String,
    pub app_data_dir: String,
    pub log_retention_days: u32,

    pub ui_language: String,
    pub auto_update_check: bool,
    pub settings_version: u32,
}

impl Default for Settings {
    /// Defaults from §4.3, §10.2 and §3.3.
    fn default() -> Self {
        let app_data_dir = dirs::data_dir()
            .map(|d| d.join("ip-checker").to_string_lossy().to_string())
            .unwrap_or_else(|| "./ip-checker-data".to_string());
        let export_dir = dirs::document_dir()
            .map(|d| d.join("IPChecker").to_string_lossy().to_string())
            .unwrap_or_else(|| app_data_dir.clone());

        Self {
            providers: Vec::new(),
            default_timeout_ms: 8000,
            max_concurrency: 8,
            circuit_failure_threshold: 5,
            circuit_cooldown_minutes: 10,

            dnsbl_groups: vec![
                DnsblGroupSetting { group: DnsblGroup::Spamhaus, enabled: true },
                DnsblGroupSetting { group: DnsblGroup::Commercial, enabled: true },
                DnsblGroupSetting { group: DnsblGroup::Community, enabled: true },
                DnsblGroupSetting { group: DnsblGroup::Specialist, enabled: true },
            ],
            dnsbl_enabled: true,

            save_history: true,
            cache_ttl_geo_hours: 168,
            cache_ttl_reputation_hours: 24,
            cache_ttl_blacklist_hours: 12,
            cache_ttl_abuse_hours: 24,

            leak_check_enabled: true,
            speed_check_enabled: true,
            browser_path: String::new(),

            export_dir,
            app_data_dir,
            log_retention_days: 7,

            ui_language: "vi".to_string(),
            auto_update_check: true,
            settings_version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VERDICTS: [Verdict; 5] = [
        Verdict::Sạch,
        Verdict::Tạm,
        Verdict::NghiNgờ,
        Verdict::Bẩn,
        Verdict::ChưaĐủDữLiệu,
    ];

    /// The wire value must be the human label, not the Rust variant name.
    ///
    /// `src/lib/types.ts` declares
    /// `"Sạch" | "Tạm" | "Nghi ngờ" | "Bẩn" | "Chưa đủ dữ liệu"`, and the UI
    /// looks labels up in `VERDICT_LABELS`. Deriving `Serialize` without the
    /// per-variant `rename` emitted `"NghiNgờ"` and `"ChưaĐủDữLiệu"`, so every
    /// `verdict === "Bẩn"` comparison and every label lookup silently missed.
    #[test]
    fn verdict_wire_value_equals_as_str() {
        for v in ALL_VERDICTS {
            let wire = serde_json::to_string(&v).expect("verdict must serialize");
            assert_eq!(
                wire,
                format!("\"{}\"", v.as_str()),
                "verdict {v:?}: wire value must equal as_str()"
            );

            // The front-end sends the same string back (history filters, IPC).
            let back: Verdict = serde_json::from_str(&wire).expect("verdict must deserialize");
            assert_eq!(back, v, "verdict round-trip qua wire phải giữ nguyên");
        }
    }

    /// The exact strings the TS union declares — pinned so a rename in Rust
    /// cannot drift away from `types.ts` without failing here first.
    #[test]
    fn verdict_wire_values_match_types_ts_union() {
        let wire: Vec<String> = ALL_VERDICTS
            .iter()
            .map(|v| serde_json::to_string(v).unwrap().trim_matches('"').to_string())
            .collect();
        assert_eq!(
            wire,
            vec!["Sạch", "Tạm", "Nghi ngờ", "Bẩn", "Chưa đủ dữ liệu"]
        );
    }

    #[test]
    fn only_chua_du_du_lieu_is_inconclusive() {
        for v in ALL_VERDICTS {
            assert_eq!(
                v.is_inconclusive(),
                v == Verdict::ChưaĐủDữLiệu,
                "{v:?}: chỉ Chưa đủ dữ liệu mới là 'không kết luận được'"
            );
        }
    }

    #[test]
    fn verdict_default_is_inconclusive() {
        assert_eq!(Verdict::default(), Verdict::ChưaĐủDữLiệu);
        assert!(Verdict::default().is_inconclusive());
    }

    /// §2.3: `Signal` is the one enum that stays PascalCase on the wire, because
    /// the spec's sample payload (§6.6) spells it `"Clean"`.
    #[test]
    fn signal_wire_value_is_pascal_case() {
        for (signal, expected) in [
            (Signal::Clean, "\"Clean\""),
            (Signal::Suspicious, "\"Suspicious\""),
            (Signal::Bad, "\"Bad\""),
            (Signal::Unknown, "\"Unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&signal).unwrap(), expected);
        }
    }

    /// `ProviderError::no_key` must never be retried (§4.3, §13.4).
    #[test]
    fn no_key_error_is_not_retryable_and_names_the_provider() {
        let err = ProviderError::no_key("ipqualityscore");
        assert_eq!(err.kind, "no_key");
        assert!(!err.retryable, "thiếu key KHÔNG được retry (§4.3)");
        assert!(err.message.contains("ipqualityscore"), "message: {}", err.message);
        assert!(err.message.contains("chưa cấu hình API key"));
    }
}
