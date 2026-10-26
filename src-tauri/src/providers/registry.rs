//! `providers.yaml` loader + provider metadata cache (§5.5).
//!
//! The YAML is the single source of truth for category, upstream, weight,
//! timeout, rate limit and DNSBL zone metadata. Loading is *defensive* by
//! design:
//!
//!   * a missing file → empty registry + warning, the app still starts;
//!   * an unknown YAML key → dropped, not fatal;
//!   * a registry row with no adapter in this build → **skipped with a warning**,
//!     never `expect()`ed (§5.5, §13.4).
//!
//! Phase 1 ships 46 registry rows and 11 adapters, so the skip list is normal
//! and must stay non-fatal.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::models::{Category, DnsblGroup, ListedVerdict};
use crate::providers::{ProviderMeta, ProviderRegistryFile};

/// Loaded registry: rows plus lookup indexes.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub version: String,
    pub updated_at: String,
    pub providers: Vec<ProviderMeta>,
    by_id: HashMap<String, usize>,
    /// Registry rows that could not be parsed into a usable row at all.
    pub rejected: Vec<String>,
}

impl Registry {
    /// Is this row `enabled_by_default` and does it name a category we can use?
    pub fn is_usable(&self, id: &str) -> bool {
        match self.get(id) {
            Some(meta) => {
                meta.enabled_by_default
                    && !meta.id.trim().is_empty()
                    && !meta.upstream.trim().is_empty()
                    && (meta.category != Category::Blacklist || meta.zone.is_some())
            }
            None => false,
        }
    }

    /// Look a provider up by its registry id.
    pub fn get(&self, id: &str) -> Option<&ProviderMeta> {
        self.by_id.get(id).and_then(|i| self.providers.get(*i))
    }

    /// All providers of one category, in file order.
    pub fn by_category(&self, category: Category) -> Vec<&ProviderMeta> {
        self.providers
            .iter()
            .filter(|p| p.category == category)
            .collect()
    }

    /// Enabled providers of one category.
    pub fn enabled_in(&self, category: Category) -> Vec<&ProviderMeta> {
        self.providers
            .iter()
            .filter(|p| p.category == category && p.enabled_by_default)
            .collect()
    }

    /// Every DNSBL zone registered for a group (§5.3).
    ///
    /// A *group* is one vote no matter how many zones it holds.
    pub fn dnsbl_by_group(&self, group: DnsblGroup) -> Vec<&ProviderMeta> {
        let wanted = group_key(group);
        self.providers
            .iter()
            .filter(|p| p.category == Category::Blacklist && p.enabled_by_default)
            .filter(|p| p.group.as_deref() == Some(wanted))
            .filter(|p| p.zone.is_some())
            .collect()
    }

    /// Every enabled DNSBL zone regardless of group.
    pub fn enabled_dnsbl_zones(&self) -> Vec<&ProviderMeta> {
        self.providers
            .iter()
            .filter(|p| p.is_dnsbl_zone() && p.enabled_by_default)
            .collect()
    }

    /// Interpret a registry row's `listed_verdict` string (§6.1).
    pub fn listed_verdict_for(&self, id: &str) -> ListedVerdict {
        match self.get(id).and_then(|p| p.listed_verdict.as_deref()) {
            Some("bad") => ListedVerdict::Bad,
            _ => ListedVerdict::Suspicious,
        }
    }

    /// §6.4 hard cap: the effective weight of a row, clamped to ≤ 0.40.
    pub fn weight_of(&self, id: &str) -> f64 {
        self.get(id).map(|p| p.sanitised_weight()).unwrap_or(0.0)
    }

    /// Per-provider timeout from the YAML, clamped into the §4.3 window.
    pub fn timeout_ms_of(&self, id: &str) -> u64 {
        self.get(id)
            .map(|p| p.timeout_ms)
            .unwrap_or(crate::orchestrator::DEFAULT_TIMEOUT_MS)
            .clamp(1_000, 30_000)
    }

    /// Rate limit (requests per minute); 0 means unknown / unlimited.
    pub fn rate_limit_of(&self, id: &str) -> u32 {
        self.get(id).map(|p| p.rate_limit).unwrap_or(0)
    }

    /// Rows present in the YAML but with no adapter in this build.
    ///
    /// Phase 1 is expected to return ~35 ids; the orchestrator logs each one and
    /// marks the module `skipped`, it never panics (§5.5, §13.4).
    pub fn unmatched_adapters(&self) -> Vec<String> {
        let supported: std::collections::HashSet<&'static str> =
            crate::providers::supported_ids().into_iter().collect();
        self.providers
            .iter()
            .filter(|p| !supported.contains(p.id.as_str()))
            .map(|p| p.id.clone())
            .collect()
    }

    /// Rows whose adapter (per the static catalogue) would disagree with the
    /// YAML on `upstream` — which silently breaks §6.2 de-duplication.
    ///
    /// Uses [`crate::providers::ADAPTER_IDS`] only: building real adapters here
    /// would touch the network/Credential Manager at startup.
    pub fn adapter_mismatches(&self) -> Vec<String> {
        let mut out = Vec::new();
        // (id, category, upstream) the adapter hardcodes.
        let expected: [(&str, Category, &str); 11] = [
            ("ip_api", Category::Geo, "ip-api"),
            ("ipwho", Category::Geo, "ipwho.is"),
            ("ipinfo", Category::Geo, "ipinfo"),
            ("ipqualityscore", Category::Fraud, "ipqualityscore"),
            ("proxycheck", Category::Fraud, "proxycheck"),
            ("scamalytics", Category::Fraud, "scamalytics"),
            ("abuseipdb", Category::Abuse, "abuseipdb"),
            ("greynoise", Category::ThreatIntel, "greynoise"),
            ("ripestat", Category::Asn, "ripestat"),
            ("bgpview", Category::Asn, "bgpview"),
            ("team_cymru", Category::Asn, "team-cymru"),
        ];
        for (id, category, upstream) in expected {
            let Some(meta) = self.get(id) else { continue };
            if meta.category != category {
                out.push(format!(
                    "{id}: category YAML={:?} adapter={:?}",
                    meta.category, category
                ));
            }
            if meta.upstream != upstream {
                out.push(format!(
                    "{id}: upstream YAML={} adapter={} (§6.2 de-dup sẽ sai)",
                    meta.upstream, upstream
                ));
            }
        }
        out
    }

    /// Log every problem found at load time. Called once at startup.
    pub fn log_diagnostics(&self) {
        for id in self.unmatched_adapters() {
            tracing::warn!(
                "providers.yaml: '{id}' không có adapter trong build này — sẽ bỏ qua (skip), không panic"
            );
        }
        for problem in self.adapter_mismatches() {
            tracing::warn!("providers.yaml không khớp adapter: {problem}");
        }
        for id in &self.rejected {
            tracing::warn!("providers.yaml: bỏ qua entry không hợp lệ '{id}'");
        }
        tracing::info!(
            "providers.yaml {} ({} entry, {} adapter khả dụng, {} bị skip)",
            self.version,
            self.providers.len(),
            self.providers.len() - self.unmatched_adapters().len(),
            self.unmatched_adapters().len()
        );
    }

    /// Build the index after loading.
    pub fn reindex(&mut self) {
        self.by_id = self
            .providers
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
    }
}

/// Map a [`DnsblGroup`] onto its YAML `group` string.
pub fn group_key(group: DnsblGroup) -> &'static str {
    match group {
        DnsblGroup::Spamhaus => "spamhaus",
        DnsblGroup::Commercial => "commercial",
        DnsblGroup::Community => "community",
        DnsblGroup::Specialist => "specialist",
    }
}

/// Reverse of [`group_key`].
pub fn group_from_key(key: &str) -> Option<DnsblGroup> {
    match key {
        "spamhaus" => Some(DnsblGroup::Spamhaus),
        "commercial" => Some(DnsblGroup::Commercial),
        "community" => Some(DnsblGroup::Community),
        "specialist" => Some(DnsblGroup::Specialist),
        _ => None,
    }
}

/// Default location of `providers.yaml`.
///
/// The file ships at the repo root; at runtime Tauri bundles it as a resource,
/// so every plausible path is probed before giving up.
pub fn default_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(p) = std::env::var("IP_CHECKER_PROVIDERS_YAML") {
        paths.push(PathBuf::from(p));
    }
    paths.push(PathBuf::from("providers.yaml"));
    paths.push(PathBuf::from("ip-checker/providers.yaml"));
    paths.push(PathBuf::from("../providers.yaml"));
    paths.push(PathBuf::from("../ip-checker/providers.yaml"));
    paths.push(PathBuf::from("../../providers.yaml"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("providers.yaml"));
            paths.push(dir.join("resources").join("providers.yaml"));
            if let Some(p2) = dir.parent() {
                paths.push(p2.join("providers.yaml"));
                paths.push(p2.join("ip-checker").join("providers.yaml"));
            }
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest = PathBuf::from(manifest);
        paths.push(manifest.join("providers.yaml"));
        if let Some(parent) = manifest.parent() {
            paths.push(parent.join("providers.yaml"));
            paths.push(parent.join("ip-checker").join("providers.yaml"));
        }
    }
    paths
}

/// Parse `providers.yaml` text into a [`Registry`].
///
/// A single bad row must not discard the whole file, so parsing is attempted
/// row by row when the document-level parse fails.
pub fn parse(text: &str) -> Result<Registry, String> {
    match serde_yaml::from_str::<ProviderRegistryFile>(text) {
        Ok(file) => Ok(build(file.version, file.updated_at, file.providers, Vec::new())),
        Err(doc_err) => {
            // Fallback: parse the envelope only, then each `providers` element.
            let doc: serde_yaml::Value = serde_yaml::from_str(text)
                .map_err(|e| format!("providers.yaml không hợp lệ: {e}"))?;
            let version = doc
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let updated_at = doc
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut providers = Vec::new();
            let mut rejected = Vec::new();
            if let Some(items) = doc.get("providers").and_then(|v| v.as_sequence()) {
                for (index, item) in items.iter().enumerate() {
                    match serde_yaml::from_value::<ProviderMeta>(item.clone()) {
                        Ok(meta) => providers.push(meta),
                        Err(err) => {
                            let id = item
                                .get("id")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| format!("#{index}"));
                            tracing::warn!("providers.yaml: entry '{id}' không hợp lệ: {err}");
                            rejected.push(id);
                        }
                    }
                }
            }
            if providers.is_empty() {
                return Err(format!("providers.yaml không hợp lệ: {doc_err}"));
            }
            Ok(build(version, updated_at, providers, rejected))
        }
    }
}

fn build(
    version: String,
    updated_at: String,
    providers: Vec<ProviderMeta>,
    rejected: Vec<String>,
) -> Registry {
    let mut registry = Registry {
        version,
        updated_at,
        providers,
        by_id: HashMap::new(),
        rejected,
    };
    registry.reindex();
    registry
}

/// Load the registry from disk, trying every known path.
pub fn load() -> Result<Registry, String> {
    let mut last_err = None;
    for candidate in default_paths() {
        if candidate.is_file() {
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if !text.trim().is_empty() {
                    match parse(&text) {
                        Ok(registry) => {
                            registry.log_diagnostics();
                            return Ok(registry);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
            }
        }
    }
    // Compile-time embedded fallback so portable single-file binary works anywhere
    const EMBEDDED_YAML: &str = include_str!("../../../providers.yaml");
    if let Ok(registry) = parse(EMBEDDED_YAML) {
        registry.log_diagnostics();
        return Ok(registry);
    }
    Err(last_err.unwrap_or_else(|| "Không tìm thấy providers.yaml".to_string()))
}

/// Load from an explicit path (tests, diagnostics).
pub fn load_from(path: &Path) -> Result<Registry, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Không đọc được {}: {e}", path.display()))?;
    let registry = parse(&text)?;
    registry.log_diagnostics();
    Ok(registry)
}

/// Registry with no rows — used before the file is loaded, never panics.
pub fn empty() -> Registry {
    Registry::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature registry with the same shape as the shipped file.
    const MINI: &str = r#"
version: "1.0.0"
updated_at: "2026-10-25"
providers:
  - id: ip_api
    category: geo
    upstream: ip-api
    method: api
    requires_key: false
    weight_in_category: 0.30
    timeout_ms: 5000
    rate_limit: 45
    enabled_by_default: true
  - id: spamhaus_zen
    category: blacklist
    upstream: spamhaus
    method: dns
    weight_in_category: 0.40
    timeout_ms: 5000
    enabled_by_default: true
    zone: zen.spamhaus.org
    group: spamhaus
    listed_verdict: bad
  - id: not_implemented_yet
    category: fraud
    upstream: ghost
    method: api
    requires_key: false
    weight_in_category: 0.10
    timeout_ms: 7000
    enabled_by_default: true
    thresholds:
      clean_below: 20
      bad_above: 70
"#;

    #[test]
    fn parses_real_shape() {
        let registry = parse(MINI).expect("phải parse được");
        assert_eq!(registry.providers.len(), 3);
        assert_eq!(registry.version, "1.0.0");
        assert_eq!(
            registry.get("ip_api").map(|p| p.category),
            Some(Category::Geo)
        );
        assert_eq!(registry.get("spamhaus_zen").and_then(|p| p.zone.as_deref()), Some("zen.spamhaus.org"));
    }

    #[test]
    fn registry_rows_without_adapter_are_skipped_not_fatal() {
        let registry = parse(MINI).unwrap();
        let unmatched = registry.unmatched_adapters();
        // `not_implemented_yet` has no adapter; ip_api does.
        assert!(unmatched.contains(&"not_implemented_yet".to_string()));
        assert!(!unmatched.contains(&"ip_api".to_string()));
        // Diagnostics must not panic even when nothing matches.
        registry.log_diagnostics();
    }

    #[test]
    fn empty_registry_diagnostics_do_not_panic() {
        let registry = empty();
        registry.log_diagnostics();
        assert_eq!(registry.providers.len(), 0);
        assert!(registry.unmatched_adapters().is_empty());
        assert!(registry.get("anything").is_none());
        assert_eq!(registry.weight_of("anything"), 0.0);
    }

    #[test]
    fn unknown_yaml_keys_are_dropped_not_fatal() {
        // `fields`, `notes`, `db_name`, `stale_after_days` appear in the real
        // file; an entirely made-up key must also survive.
        let text = r#"
version: "9"
providers:
  - id: x
    category: abuse
    upstream: x
    method: api
    weight_in_category: 0.2
    enabled_by_default: true
    fields: [a, b]
    notes: "hello"
    db_name: GeoLite2-City
    stale_after_days: 60
    completely_unknown_key: { nested: [1, 2, 3] }
"#;
        let registry = parse(text).expect("unknown key phải bị bỏ qua, không abort");
        let meta = registry.get("x").unwrap();
        assert_eq!(meta.fields.as_ref().map(|f| f.len()), Some(2));
        assert_eq!(meta.notes.as_deref(), Some("hello"));
        assert_eq!(meta.db_name.as_deref(), Some("GeoLite2-City"));
        assert_eq!(meta.stale_after_days, Some(60));
    }

    #[test]
    fn weight_is_clamped_to_forty_percent() {
        let text = r#"
version: "1"
providers:
  - id: greedy
    category: fraud
    upstream: greedy
    method: api
    weight_in_category: 0.95
    enabled_by_default: true
"#;
        let registry = parse(text).unwrap();
        assert!(
            (registry.weight_of("greedy") - 0.40).abs() < 1e-9,
            "§6.4 cap: không provider nào > 40% khía cạnh"
        );
    }

    #[test]
    fn dnsbl_group_lookup_returns_zones() {
        let registry = parse(MINI).unwrap();
        let spamhaus = registry.dnsbl_by_group(DnsblGroup::Spamhaus);
        assert_eq!(spamhaus.len(), 1);
        assert_eq!(spamhaus[0].id, "spamhaus_zen");
        assert!(registry.dnsbl_by_group(DnsblGroup::Community).is_empty());
        assert_eq!(
            registry.listed_verdict_for("spamhaus_zen"),
            ListedVerdict::Bad
        );
    }

    #[test]
    fn timeout_is_clamped_into_spec_window() {
        let text = r#"
version: "1"
providers:
  - id: slow
    category: geo
    upstream: slow
    method: api
    timeout_ms: 600000
    enabled_by_default: true
"#;
        let registry = parse(text).unwrap();
        assert_eq!(registry.timeout_ms_of("slow"), 30_000);
    }

    #[test]
    fn missing_file_is_an_error_but_empty_registry_is_not() {
        assert!(load_from(Path::new("definitely-not-here.yaml")).is_err());
        assert!(parse("version: '1'\nproviders: []\n").is_ok());
    }
}
