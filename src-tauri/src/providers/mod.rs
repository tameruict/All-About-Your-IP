//! Provider trait + registry models (§4.4, §5.5).
//!
//! Owners: provider adapters live in `crate::providers::*`. This module declares
//! the shared trait, the registry metadata structs and the adapter catalogue so
//! every agent compiles against the same shapes.

// --- adapter modules -------------------------------------------------------
pub mod abuseipdb;
pub mod bgpview;
pub mod greynoise;
pub mod ip_api;
pub mod ipinfo;
pub mod ipqs;
pub mod ipwho;
pub mod proxycheck;
pub mod registry;
pub mod ripestat;
pub mod scamalytics;
pub mod team_cymru;

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::models::{Category, ProviderError, ProviderEvidence, ProviderHealth};

/// Every provider adapter implements exactly this (§4.4).
///
/// Scoring and UI MUST NOT read provider-private fields — everything they need
/// is inside [`ProviderEvidence`].
#[async_trait]
pub trait Provider: Send + Sync {
    /// Registry id, e.g. "ipqualityscore".
    fn id(&self) -> &'static str;

    /// Aspect this provider votes in.
    fn category(&self) -> Category;

    /// Root data source, used to de-duplicate votes (§6.2).
    fn upstream(&self) -> &'static str;

    /// True when the provider cannot answer without an API key.
    fn requires_key(&self) -> bool;

    /// Run the check. Implementations must never leak the API key into `raw`.
    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError>;

    /// Optional convenience: return health metadata (defaults to a neutral row).
    fn health(&self) -> Option<ProviderHealth> {
        None
    }
}

/// One row of `providers.yaml` (§5.5).
///
/// Every optional field is `#[serde(default)]` so an unknown / extra key in the
/// YAML is dropped instead of aborting the whole registry load (§5.5 + §13.4:
/// a malformed or extended registry must never stop the app from starting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMeta {
    pub id: String,
    pub category: Category,
    pub upstream: String,
    /// api | dns | bgp | local_db
    pub method: String,
    #[serde(default)]
    pub requires_key: bool,
    #[serde(default = "default_weight")]
    pub weight_in_category: f64,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Requests per minute for the free tier; 0 = unlimited / unknown.
    #[serde(default)]
    pub rate_limit: u32,
    #[serde(default)]
    pub enabled_by_default: bool,
    /// §6.1 score → signal thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<Thresholds>,
    /// Present only for DNSBL entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed_verdict: Option<String>,
    /// Local DB rows only (§7.3): MaxMind / IP2Location / DB-IP file names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_update_url: Option<String>,
    /// §7.3 — a DB older than this many days loses confidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after_days: Option<u32>,
    /// Free-form adapter hints kept verbatim from the YAML (`fields`, `notes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ProviderMeta {
    /// Group label for a DNSBL row, lower-cased (`spamhaus` / `commercial` / …).
    pub fn dnsbl_group_key(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// A registry row is usable for DNSBL lookups only when it names a zone.
    pub fn is_dnsbl_zone(&self) -> bool {
        self.category == Category::Blacklist && self.zone.is_some() && self.group.is_some()
    }

    /// §6.4 — clamp the configured weight into the legal (0, 0.40] window.
    pub fn sanitised_weight(&self) -> f64 {
        if !self.weight_in_category.is_finite() || self.weight_in_category <= 0.0 {
            default_weight()
        } else {
            self.weight_in_category.min(MAX_WEIGHT_IN_CATEGORY)
        }
    }
}

/// §6.4: no provider may own more than 40 % of its aspect's weight.
pub const MAX_WEIGHT_IN_CATEGORY: f64 = 0.40;

fn default_weight() -> f64 {
    0.2
}

fn default_timeout_ms() -> u64 {
    8000
}

/// §6.1 normalisation thresholds, expressed in the provider's own scale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub clean_below: f64,
    pub bad_above: f64,
}

/// Whole `providers.yaml` document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderRegistryFile {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub providers: Vec<ProviderMeta>,
}

// ---------------------------------------------------------------------------
// Adapter catalogue
// ---------------------------------------------------------------------------

/// Config an adapter needs at construction time, resolved from
/// `providers.yaml` + Windows Credential Manager (§5.5).
#[derive(Debug, Clone, Default)]
pub struct AdapterConfig {
    /// Shared HTTP client so connections are pooled across providers.
    pub client: Option<reqwest::Client>,
    /// Registry row for this provider (thresholds, timeout, weight).
    pub meta: Option<ProviderMeta>,
    /// API key / credential read from Credential Manager. NEVER logged.
    pub credential: Option<String>,
}

impl AdapterConfig {
    pub fn from_registry(registry: &crate::providers::registry::Registry, id: &str) -> Self {
        Self {
            client: Some(default_client()),
            meta: registry.get(id).cloned(),
            credential: crate::config::get_api_key(id),
        }
    }

    pub fn thresholds(&self) -> Option<Thresholds> {
        self.meta.as_ref().and_then(|m| m.thresholds.clone())
    }

    fn client(&self) -> reqwest::Client {
        self.client.clone().unwrap_or_else(default_client)
    }
}

/// One shared, timeout-aware HTTP client for every adapter (§4.3).
///
/// Built once per call site; `reqwest::Client` clones share the same pool, so
/// adapters constructed from [`AdapterConfig`] reuse connections.
pub fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .user_agent(concat!("ip-checker/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// Build every HTTP/DNS adapter that is implemented in this build.
///
/// The list is deliberately explicit: `providers.yaml` carries more rows than
/// there are adapters (46 vs 11 in phase 1), and the difference is *skipped with
/// a warning*, never an `expect()`/`unwrap()` that would kill the app on start
/// (§5.5, §13.4). Callers diff the two sets with
/// [`crate::providers::registry::Registry::unmatched_adapters`].
///
/// Adding a provider = add an adapter module + one line here + one YAML row.
pub fn all_adapters() -> Vec<Box<dyn Provider>> {
    build_adapters(&AdapterConfig::default())
}

/// Build the adapters with per-provider config resolved from the registry.
///
/// A provider whose constructor needs a credential still gets built when the key
/// is missing — the adapter reports `ProviderError::no_key` instead, so the UI
/// can show `skipped (thiếu key)` rather than silently omitting the row (§3.3).
pub fn build_adapters(config: &AdapterConfig) -> Vec<Box<dyn Provider>> {
    let client = config.client();
    let _meta = config.meta.as_ref();
    let thr = config.thresholds();
    let cred = config.credential.clone();

    // Each adapter is boxed as `Box<dyn Provider>` *individually* before being
    // pushed. A `vec![Box::new(a), Box::new(b), …]` literal would infer
    // `Vec<Box<ip_api::Adapter>>` from its first element and then reject every
    // other adapter type with E0308, because `Box<T>` does not coerce inside a
    // collection literal.
    //
    // Thresholds (§6.1) and the client are applied per concrete type *before*
    // boxing, which is why the calls look repetitive: the trait deliberately has
    // no `set_thresholds`, so scoring can never be configured through it.
    let mut adapters: Vec<Box<dyn Provider>> = Vec::with_capacity(ADAPTER_IDS.len());

    adapters.push(Box::new(
        crate::providers::ip_api::Adapter::new()
            .with_client(client.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::ipwho::Adapter::new()
            .with_client(client.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::ipinfo::Adapter::new()
            .with_client(client.clone())
            .with_token(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::ipqs::Adapter::new()
            .with_client(client.clone())
            .with_token(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::proxycheck::Adapter::new()
            .with_client(client.clone())
            .with_token(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::scamalytics::Adapter::new()
            .with_client(client.clone())
            .with_credential(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::abuseipdb::Adapter::new()
            .with_client(client.clone())
            .with_token(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::greynoise::Adapter::new()
            .with_client(client.clone())
            .with_token(cred.clone())
            .with_thresholds_from(thr.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::ripestat::Adapter::new().with_client(client.clone()),
    ));
    adapters.push(Box::new(
        crate::providers::bgpview::Adapter::new().with_client(client.clone()),
    ));
    adapters.push(Box::new(crate::providers::team_cymru::Adapter::new()));

    let _ = _meta;
    adapters
}

/// Build the adapters with per-provider config resolved from the registry and
/// Windows Credential Manager (§5.5).
pub fn build_adapters_from_registry(
    registry: &crate::providers::registry::Registry,
) -> Vec<Box<dyn Provider>> {
    let client = default_client();
    let thr_of = |id: &str| registry.get(id).and_then(|m| m.thresholds.clone());
    let cred_of = |id: &str| crate::config::get_api_key(id);
    let timeout_of = |id: &str| {
        std::time::Duration::from_millis(
            registry
                .get(id)
                .map(|m| m.timeout_ms)
                .unwrap_or(8000)
                .clamp(1000, 30_000),
        )
    };

    let mut adapters: Vec<Box<dyn Provider>> = Vec::with_capacity(ADAPTER_IDS.len());

    adapters.push(Box::new(
        crate::providers::ip_api::Adapter::new()
            .with_client(client.clone())
            .with_thresholds_from(thr_of("ip_api")),
    ));
    adapters.push(Box::new(
        crate::providers::ipwho::Adapter::new()
            .with_client(client.clone())
            .with_timeout(timeout_of("ipwho"))
            .with_thresholds_from(thr_of("ipwho")),
    ));
    adapters.push(Box::new(
        crate::providers::ipinfo::Adapter::new()
            .with_client(client.clone())
            .with_token(cred_of("ipinfo"))
            .with_timeout(timeout_of("ipinfo"))
            .with_thresholds_from(thr_of("ipinfo")),
    ));
    adapters.push(Box::new(
        crate::providers::ipqs::Adapter::new()
            .with_client(client.clone())
            .with_token(cred_of("ipqualityscore"))
            .with_timeout(timeout_of("ipqualityscore"))
            .with_thresholds_from(thr_of("ipqualityscore")),
    ));
    adapters.push(Box::new(
        crate::providers::proxycheck::Adapter::new()
            .with_client(client.clone())
            .with_token(cred_of("proxycheck"))
            .with_timeout(timeout_of("proxycheck"))
            .with_thresholds_from(thr_of("proxycheck")),
    ));
    adapters.push(Box::new(
        crate::providers::scamalytics::Adapter::new()
            .with_client(client.clone())
            .with_credential(cred_of("scamalytics"))
            .with_timeout(timeout_of("scamalytics"))
            .with_thresholds_from(thr_of("scamalytics")),
    ));
    adapters.push(Box::new(
        crate::providers::abuseipdb::Adapter::new()
            .with_client(client.clone())
            .with_token(cred_of("abuseipdb"))
            .with_timeout(timeout_of("abuseipdb"))
            .with_thresholds_from(thr_of("abuseipdb")),
    ));
    adapters.push(Box::new(
        crate::providers::greynoise::Adapter::new()
            .with_client(client.clone())
            .with_token(cred_of("greynoise"))
            .with_timeout(timeout_of("greynoise"))
            .with_thresholds_from(thr_of("greynoise")),
    ));
    adapters.push(Box::new(
        crate::providers::ripestat::Adapter::new()
            .with_client(client.clone())
            .with_timeout(timeout_of("ripestat")),
    ));
    adapters.push(Box::new(
        crate::providers::bgpview::Adapter::new()
            .with_client(client.clone())
            .with_timeout(timeout_of("bgpview")),
    ));
    adapters.push(Box::new(
        crate::providers::team_cymru::Adapter::new().with_timeout(timeout_of("team_cymru")),
    ));

    adapters
}

/// Ids the current build can actually run — used to compute skip lists.
///
/// Static and side-effect free: it must not touch Credential Manager or the
/// network, because it is called from registry diagnostics at startup.
pub fn supported_ids() -> Vec<&'static str> {
    SUPPORTED_IDS.to_vec()
}

/// Every in-tree provider or module ID supported in this build.
pub const SUPPORTED_IDS: [&str; 42] = [
    // 11 HTTP/DNS standalone adapters
    "ip_api",
    "ipwho",
    "ipinfo",
    "ipqualityscore",
    "proxycheck",
    "scamalytics",
    "abuseipdb",
    "greynoise",
    "ripestat",
    "bgpview",
    "team_cymru",
    // Derived fraud adapters
    "ip_api_flags",
    "ipinfo_privacy",
    // In-tree modules
    "network_probe",
    "exit_ip",
    "browser_leak",
    "speed_test",
    // Local DBs
    "maxmind_geolite2_city",
    "maxmind_geolite2_country",
    "ip2location_lite",
    "dbip_lite",
    // DNSBL zones
    "spamhaus_zen",
    "spamhaus_sbl",
    "spamhaus_xbl",
    "spamhaus_pbl",
    "spamhaus_dbl",
    "barracuda",
    "spamrats",
    "hostkarma",
    "inps_de",
    "mailspike",
    "spamcop",
    "sorbs",
    "uceprotect_1",
    "uceprotect_2",
    "njabl",
    "cbl_abuseat",
    "psbl",
    "tor_exit_dan",
    "dronebl",
    "efnet_rbl",
    "backscatterer",
];

/// Every adapter id this build ships, in catalogue order.
pub const ADAPTER_IDS: [&str; 11] = [
    "ip_api",
    "ipwho",
    "ipinfo",
    "ipqualityscore",
    "proxycheck",
    "scamalytics",
    "abuseipdb",
    "greynoise",
    "ripestat",
    "bgpview",
    "team_cymru",
];

/// Borrowed adapter views for dispatch, keyed by registry id.
pub struct AdapterSet {
    adapters: Vec<Box<dyn Provider>>,
}

impl AdapterSet {
    pub fn new() -> Self {
        Self {
            adapters: all_adapters(),
        }
    }

    pub fn from_registry(registry: &crate::providers::registry::Registry) -> Self {
        Self {
            adapters: build_adapters_from_registry(registry),
        }
    }

    pub fn get(&self, id: &str) -> Option<&dyn Provider> {
        self.adapters
            .iter()
            .find(|a| a.id() == id)
            .map(|a| a.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Provider> {
        self.adapters.iter().map(|a| a.as_ref())
    }

    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }
}

impl Default for AdapterSet {
    fn default() -> Self {
        Self::new()
    }
}
