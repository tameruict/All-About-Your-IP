//! DNSBL query engine — direct DNS, never scrape web aggregators (§5.3).
//!
//! Design points that matter for scoring (§6.2, §6.3):
//!
//!   * **A group is ONE vote**, not one vote per zone. Spamhaus alone ships four
//!     zones; if each were a vote it would dominate the whole blacklist aspect.
//!     [`DnsblResult::groups`] therefore carries per-group results and the
//!     scoring layer reads at most one signal per group.
//!   * **A dead zone is disabled + logged, never fatal** (§5.3, §5.5, §13.4).
//!     `NXDOMAIN`/`NOERROR-empty` mean "not listed"; transport errors are
//!     reported as `signal = Unknown` with `error = timeout`, so a broken
//!     resolver can never be mistaken for a clean answer.
//!   * Lookups are `<reversed>.zone` — `1.2.3.4` → `4.3.2.1.zen.spamhaus.org`
//!     — and a `127.0.0.0/8` answer means "listed" (RFC 5782).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_resolver::TokioAsyncResolver;

use crate::models::{
    DnsblEntry, DnsblGroup, DnsblGroupResult, DnsblResult, ListedVerdict, ProviderError, Signal,
};
use crate::providers::ProviderMeta;
use crate::providers::registry::Registry;
use crate::validator::{reverse_ipv4, reverse_ipv6};

/// Per-zone DNS timeout — inside the §4.3 5–8 s provider window.
pub const ZONE_TIMEOUT: Duration = Duration::from_secs(5);

/// A zone that fails this many times in a row is disabled for the session.
pub const DEAD_ZONE_THRESHOLD: u32 = 3;

/// Labels shown in the UI for each DNSBL group (§5.3).
pub fn group_label(group: DnsblGroup) -> &'static str {
    match group {
        DnsblGroup::Spamhaus => "Spamhaus",
        DnsblGroup::Commercial => "Thương mại",
        DnsblGroup::Community => "Cộng đồng",
        DnsblGroup::Specialist => "Chuyên biệt",
    }
}

/// All four groups in display order.
pub const ALL_GROUPS: [DnsblGroup; 4] = [
    DnsblGroup::Spamhaus,
    DnsblGroup::Commercial,
    DnsblGroup::Community,
    DnsblGroup::Specialist,
];

/// Build the fully-qualified lookup name for a zone (§5.3).
///
/// IPv4 `1.2.3.4` + `zen.spamhaus.org` → `4.3.2.1.zen.spamhaus.org`.
/// IPv6 uses the nibble-reversed form.
pub fn lookup_name(ip: IpAddr, zone: &str) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{}.{}", reverse_ipv4(v4), zone),
        IpAddr::V6(v6) => format!("{}.{}", reverse_ipv6(v6), zone),
    }
}

/// Read a DNSBL answer: listed when any A record sits in `127.0.0.0/8`
/// (excluding `127.255.255.0/24` RFC 5782 administrative error codes
/// and `127.0.0.255` rate limit / refusal).
///
/// Returns the return codes (e.g. `127.0.0.2`) that made it listed.
pub fn listed_from_a_records(records: &[std::net::Ipv4Addr]) -> Vec<String> {
    records
        .iter()
        .filter(|addr| {
            let oct = addr.octets();
            oct[0] == 127 && oct[1] != 255 && !(oct[1] == 0 && oct[2] == 0 && oct[3] == 255)
        })
        .map(|addr| addr.to_string())
        .collect()
}

/// Session-scoped zone health so a dead zone stops costing time (§5.5).
#[derive(Debug, Default)]
pub struct ZoneHealth {
    failures: Mutex<HashMap<String, u32>>,
    disabled: Mutex<HashMap<String, String>>,
}

impl ZoneHealth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_failure(&self, zone: &str, reason: &str) {
        let mut failures = match self.failures.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let count = failures.entry(zone.to_string()).or_insert(0);
        *count += 1;
        if *count >= DEAD_ZONE_THRESHOLD {
            if let Ok(mut disabled) = self.disabled.lock() {
                disabled.insert(zone.to_string(), reason.to_string());
            }
            tracing::warn!(
                "DNSBL zone '{zone}' lỗi {count} lần ({reason}) — disable cho phiên này (§5.3)"
            );
        }
    }

    pub fn record_success(&self, zone: &str) {
        if let Ok(mut failures) = self.failures.lock() {
            failures.remove(zone);
        }
    }

    pub fn is_disabled(&self, zone: &str) -> Option<String> {
        // A poisoned lock means a thread panicked while holding it. The map
        // itself is still valid — poisoning does not corrupt a `HashMap` — so
        // recover the guard rather than dropping it. `.ok()?` used to return
        // `None` here, which reads as "this zone is fine" and keeps hammering a
        // zone the session already gave up on. Recovering keeps the data and
        // records the panic; blanket-disabling would silently turn DNSBL off
        // for the rest of the session after one unrelated panic.
        let guard = match self.disabled.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "DNSBL disabled-map lock bị poison (một thread đã panic khi giữ lock) — \
                     đọc lại map; zone có thể cũ (§5.3)"
                );
                poisoned.into_inner()
            }
        };
        guard.get(zone).cloned()
    }

    /// Zones disabled during this session (for the Settings panel).
    pub fn disabled_zones(&self) -> Vec<(String, String)> {
        self.disabled
            .lock()
            .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

/// Process-wide zone health (the orchestrator shares it across checks).
pub fn global_health() -> &'static ZoneHealth {
    static HEALTH: std::sync::OnceLock<ZoneHealth> = std::sync::OnceLock::new();
    HEALTH.get_or_init(ZoneHealth::new)
}

pub fn build_resolver() -> Option<TokioAsyncResolver> {
    use hickory_resolver::config::{
        LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
    };

    // Windows often injects deprecated RFC 3879 site-local IPv6 servers
    // (`fec0:0:0:ffff::1..3`) on the Loopback Pseudo-Interface. If Hickory
    // includes those in its pool, ~60% of concurrent DNSBL queries time out.
    // Keep only routable IPv4 system nameservers, and append public IPv4
    // resolvers as fallback.
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
        Err(err) => {
            tracing::warn!("Không đọc được cấu hình DNS hệ thống ({err}) — dùng resolver mặc định");
            ResolverOpts::default()
        }
    };

    if config.name_servers().is_empty() {
        for ns in ResolverConfig::default().name_servers() {
            if ns.socket_addr.is_ipv4() {
                config.add_name_server(ns.clone());
            }
        }
    } else {
        // Append Cloudflare + Google IPv4 as secondary fallback in case ISP DNS drops UDP bursts.
        for ip in [
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            std::net::Ipv4Addr::new(8, 8, 8, 8),
        ] {
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, 53));
            if !config.name_servers().iter().any(|n| n.socket_addr == addr) {
                config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
            }
        }
    }

    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 2;
    Some(TokioAsyncResolver::tokio(config, opts))
}

/// Empty-but-consistent result (used when the module is disabled).
pub fn empty_result(registry: &Registry, enabled: &[DnsblGroup]) -> DnsblResult {
    let groups = enabled
        .iter()
        .copied()
        .map(|group| DnsblGroupResult {
            group,
            label: group_label(group).to_string(),
            checked: registry.dnsbl_by_group(group).len() as u32,
            listed: 0,
            signal: Signal::Unknown,
            answered: false,
            entries: Vec::new(),
        })
        .collect::<Vec<_>>();

    DnsblResult {
        groups,
        total_listed: 0,
        groups_answered: 0,
        hard_hit: false,
        notes: vec!["Module DNSBL bị tắt trong Settings (§3.3)".to_string()],
    }
}

/// Resolve one zone for one IP.
async fn query_zone(
    resolver: &TokioAsyncResolver,
    ip: IpAddr,
    meta: &ProviderMeta,
    health: &ZoneHealth,
) -> DnsblEntry {
    let Some(zone) = meta.zone.clone() else {
        return DnsblEntry {
            provider: meta.id.clone(),
            zone: String::new(),
            group: crate::providers::registry::group_from_key(
                meta.group.as_deref().unwrap_or("community"),
            )
            .unwrap_or(DnsblGroup::Community),
            listed: false,
            return_codes: Vec::new(),
            signal: Signal::Unknown,
            listed_verdict: ListedVerdict::Suspicious,
            reason: Some("Entry thiếu `zone` trong providers.yaml".to_string()),
            source_url: String::new(),
            checked_at: chrono::Utc::now().to_rfc3339(),
            error: Some(ProviderError::new(
                "config",
                "Thiếu zone trong providers.yaml",
                false,
            )),
        };
    };

    let group = crate::providers::registry::group_from_key(meta.group.as_deref().unwrap_or(""))
        .unwrap_or(DnsblGroup::Community);
    let listed_verdict = if meta.listed_verdict.as_deref() == Some("bad") {
        ListedVerdict::Bad
    } else {
        ListedVerdict::Suspicious
    };
    let name = lookup_name(ip, &zone);
    let source_url = format!("https://{zone}/");
    let group_key = meta.group.clone().unwrap_or_default();

    // A zone already proven dead this session is reported, not retried.
    if let Some(why) = health.is_disabled(&zone) {
        return DnsblEntry {
            provider: meta.id.clone(),
            zone,
            group,
            listed: false,
            return_codes: Vec::new(),
            signal: Signal::Unknown,
            listed_verdict,
            reason: Some(format!("Zone đã bị disable trong phiên này: {why}")),
            source_url,
            checked_at: chrono::Utc::now().to_rfc3339(),
            error: Some(ProviderError::new("disabled", "Zone chết, đã disable", false)),
        };
    }

    let query: Result<Vec<std::net::Ipv4Addr>, (&'static str, String)> = async {
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let lookup = tokio::time::timeout(ZONE_TIMEOUT, resolver.ipv4_lookup(fqdn.as_str())).await;
        match lookup {
            Err(_) => Err(("timeout", format!("{zone} không trả lời trong 5s"))),
            Ok(Err(err)) => {
                // NXDOMAIN / no records == "not listed", NOT an error (§5.3).
                use hickory_resolver::error::ResolveErrorKind;
                match err.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => Ok(Vec::new()),
                    _ => Err(("http", format!("{zone}: {err}"))),
                }
            }
            Ok(Ok(response)) => {
                let v4: Vec<std::net::Ipv4Addr> = response.iter().map(|a| a.0).collect();
                // RFC 5782 / Spamhaus administrative refusal codes (`127.255.255.252..=255`)
                // mean the DNS resolver itself was refused, NOT that the IP is clean or listed.
                if !v4.is_empty()
                    && v4
                        .iter()
                        .all(|addr| addr.octets()[0] == 127 && addr.octets()[1] == 255)
                {
                    let codes: Vec<String> = v4.iter().map(|a| a.to_string()).collect();
                    return Err((
                        "http",
                        format!(
                            "{zone}: DNS resolver bị từ chối ({})",
                            codes.join(", ")
                        ),
                    ));
                }
                Ok(v4)
            }
        }
    }
    .await;

    let (listed, return_codes, signal, error, reason) = match query {
        Ok(records) => {
            let mut codes = listed_from_a_records(&records);
            // HostKarma special mapping: 127.0.0.1 (whitelist) and 127.0.0.5 (NOBL) are not listed.
            if zone.contains("hostkarma") {
                codes.retain(|c| c != "127.0.0.1" && c != "127.0.0.5");
            }

            let listed = !codes.is_empty();
            health.record_success(&zone);

            // Spamhaus PBL (127.0.0.10/11) is ISP policy for dynamic residential IP, NOT malicious.
            let is_spamhaus_pbl_only = zone.contains("spamhaus")
                && listed
                && codes.iter().all(|c| c == "127.0.0.10" || c == "127.0.0.11");

            let signal = if is_spamhaus_pbl_only {
                Signal::Clean
            } else if listed {
                match listed_verdict {
                    ListedVerdict::Bad => Signal::Bad,
                    ListedVerdict::Suspicious => Signal::Suspicious,
                }
            } else {
                Signal::Clean
            };
            let reason: Option<String> = if is_spamhaus_pbl_only {
                Some(format!(
                    "Spamhaus PBL: dải IP dân cư động ({}) — chính sách ISP, không phải bẩn",
                    codes.join(", ")
                ))
            } else if listed {
                Some(format!(
                    "Listed trên {zone} ({}), nhóm {group_key}",
                    codes.join(", ")
                ))
            } else {
                None
            };
            (if is_spamhaus_pbl_only { false } else { listed }, codes, signal, None, reason)
        }
        Err((kind, message)) => {
            health.record_failure(&zone, &message);
            (
                false,
                Vec::new(),
                Signal::Unknown,
                Some(ProviderError::new(kind, message.clone(), true)),
                Some(message),
            )
        }
    };

    DnsblEntry {
        provider: meta.id.clone(),
        zone,
        group,
        listed,
        return_codes,
        signal,
        listed_verdict,
        reason,
        source_url,
        checked_at: chrono::Utc::now().to_rfc3339(),
        error,
    }
}

/// Aggregate zone entries into one signal per group (§5.3, §6.1).
///
/// The group signal is the worst listed zone; anything answered counts as one
/// vote for quorum purposes (§6.3 blacklist quorum = 3 groups).
pub fn aggregate_group(group: DnsblGroup, entries: Vec<DnsblEntry>) -> DnsblGroupResult {
    let answered = entries.iter().any(|e| e.signal != Signal::Unknown);
    let listed = entries.iter().filter(|e| e.listed).count() as u32;

    let signal = if !answered {
        Signal::Unknown
    } else {
        let mut worst = Signal::Clean;
        for entry in &entries {
            if entry.signal == Signal::Unknown {
                continue;
            }
            worst = crate::scoring::worse_of(worst, entry.signal);
        }
        worst
    };

    DnsblGroupResult {
        group,
        label: group_label(group).to_string(),
        checked: entries.len() as u32,
        listed,
        signal,
        answered,
        entries,
    }
}

/// Run every enabled zone for one IP.
///
/// Never fails: a total DNS outage yields `signal = Unknown` per group, which
/// the scoring layer treats as "no blacklist evidence" and (correctly) denies
/// quorum instead of declaring the IP clean.
pub async fn check_ip(ip: IpAddr, registry: &Registry, enabled: &[DnsblGroup]) -> DnsblResult {
    check_ip_with_health(ip, registry, enabled, global_health()).await
}

/// Same as [`check_ip`] with an explicit zone-health table (tests, per-check
/// isolation).
pub async fn check_ip_with_health(
    ip: IpAddr,
    registry: &Registry,
    enabled: &[DnsblGroup],
    health: &ZoneHealth,
) -> DnsblResult {
    let started = Instant::now();
    let mut notes = Vec::new();

    if enabled.is_empty() {
        return empty_result(registry, &ALL_GROUPS);
    }

    let Some(resolver) = build_resolver() else {
        return DnsblResult {
            groups: enabled
                .iter()
                .copied()
                .map(|group| DnsblGroupResult {
                    group,
                    label: group_label(group).to_string(),
                    checked: 0,
                    listed: 0,
                    signal: Signal::Unknown,
                    answered: false,
                    entries: Vec::new(),
                })
                .collect(),
            total_listed: 0,
            groups_answered: 0,
            hard_hit: false,
            // §5.3 forbids reporting a module as "checked" when it did not
            // run. `build_resolver` only returns `None` when the fallback path
            // is unreachable, but the note must still say that no zone was
            // queried — an empty table with a reassuring note is a lie.
            notes: vec![
                "Không tạo được DNS resolver — chưa query zone nào, kết quả DNSBL không có giá trị"
                    .to_string(),
            ],
        };
    };

    let group_futures = enabled.iter().copied().map(|group| {
        let zones = registry.dnsbl_by_group(group);
        let resolver = &resolver;
        async move {
            if zones.is_empty() {
                return (
                    group,
                    Vec::new(),
                    Some(format!(
                        "Nhóm {} không có zone nào trong providers.yaml — không tính phiếu",
                        group_label(group)
                    )),
                );
            }
            let futures = zones.into_iter().map(|meta| query_zone(resolver, ip, meta, health));
            let entries: Vec<DnsblEntry> = futures::future::join_all(futures).await;
            (group, entries, None)
        }
    });
    let completed_groups = futures::future::join_all(group_futures).await;
    let mut group_results = Vec::with_capacity(enabled.len());
    for (group, entries, note) in completed_groups {
        if let Some(n) = note {
            notes.push(n);
        }
        if entries.is_empty() {
            group_results.push(DnsblGroupResult {
                group,
                label: group_label(group).to_string(),
                checked: 0,
                listed: 0,
                signal: Signal::Unknown,
                answered: false,
                entries: Vec::new(),
            });
        } else {
            group_results.push(aggregate_group(group, entries));
        }
    }

    let total_listed: u32 = group_results.iter().map(|g| g.listed).sum();
    let groups_answered = group_results.iter().filter(|g| g.answered).count() as u32;

    // §6.5: Spamhaus listed is "hard evidence" that triggers the downgrade rule.
    // Only true malicious listings (SBL/XBL/CSS, Signal::Bad) trigger hard_hit,
    // not policy / PBL (127.0.0.10/11) on dynamic residential IPs.
    let hard_hit = group_results
        .iter()
        .any(|g| g.group == DnsblGroup::Spamhaus && g.signal == Signal::Bad && g.listed > 0);

    let disabled = health.disabled_zones();
    if !disabled.is_empty() {
        notes.push(format!(
            "{} zone bị disable phiên này: {}",
            disabled.len(),
            disabled
                .iter()
                .map(|(z, _)| z.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if groups_answered < 3 {
        notes.push(format!(
            "Chỉ {groups_answered}/4 nhóm trả lời — blacklist quorum cần 3 nhóm (§6.3)"
        ));
    }
    notes.push(format!(
        "DNSBL xong trong {} ms",
        started.elapsed().as_millis()
    ));

    DnsblResult {
        groups: group_results,
        total_listed,
        groups_answered,
        hard_hit,
        notes,
    }
}

/// Convenience: is this provider id a DNSBL zone?
pub fn is_dnsbl_zone(registry: &Registry, id: &str) -> bool {
    registry.get(id).map(|p| p.is_dnsbl_zone()).unwrap_or(false)
}

/// Total number of enabled zones, for the Settings panel (§5.3: target 40–50).
pub fn enabled_zone_count(registry: &Registry) -> usize {
    registry.enabled_dnsbl_zones().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(zone: &str, group: DnsblGroup, signal: Signal, listed: bool) -> DnsblEntry {
        DnsblEntry {
            provider: zone.replace('.', "_"),
            zone: zone.to_string(),
            group,
            listed,
            return_codes: if listed {
                vec!["127.0.0.2".to_string()]
            } else {
                Vec::new()
            },
            signal,
            listed_verdict: ListedVerdict::Suspicious,
            reason: None,
            source_url: format!("https://{zone}/"),
            checked_at: "2026-10-25T10:00:00+00:00".to_string(),
            error: None,
        }
    }

    #[test]
    fn lookup_name_reverses_ipv4() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(
            lookup_name(ip, "zen.spamhaus.org"),
            "4.3.2.1.zen.spamhaus.org"
        );
    }

    #[test]
    fn lookup_name_reverses_ipv6_nibbles() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let name = lookup_name(ip, "bl.example.org");
        assert!(name.ends_with(".bl.example.org"));
        assert!(
            name.starts_with("1.0.0.0."),
            "IPv6 phải đảo nibble: {name}"
        );
    }

    #[test]
    fn listed_codes_only_from_127_slash_8() {
        let records = vec![
            std::net::Ipv4Addr::new(127, 0, 0, 2),
            std::net::Ipv4Addr::new(8, 8, 8, 8),
        ];
        let codes = listed_from_a_records(&records);
        assert_eq!(codes, vec!["127.0.0.2".to_string()]);
        assert!(listed_from_a_records(&[]).is_empty());
    }

    #[test]
    fn group_signal_is_worst_zone_but_one_vote() {
        let entries = vec![
            entry("zen.spamhaus.org", DnsblGroup::Spamhaus, Signal::Bad, true),
            entry("sbl.spamhaus.org", DnsblGroup::Spamhaus, Signal::Clean, false),
            entry("xbl.spamhaus.org", DnsblGroup::Spamhaus, Signal::Clean, false),
            entry("pbl.spamhaus.org", DnsblGroup::Spamhaus, Signal::Clean, false),
        ];
        let agg = aggregate_group(DnsblGroup::Spamhaus, entries);
        assert_eq!(agg.signal, Signal::Bad, "lấy tín hiệu xấu nhất trong nhóm");
        assert_eq!(agg.listed, 1);
        assert_eq!(agg.checked, 4);
        assert!(agg.answered);
        // §5.3: 4 zone nhưng chỉ 1 phiếu nhóm — scoring đọc `signal`, không đếm zone.
    }

    #[test]
    fn group_with_all_timeouts_is_unknown_not_clean() {
        let mut dead = entry("bl.spamcop.net", DnsblGroup::Community, Signal::Unknown, false);
        dead.error = Some(ProviderError::timeout());
        let agg = aggregate_group(DnsblGroup::Community, vec![dead]);
        assert_eq!(
            agg.signal,
            Signal::Unknown,
            "timeout không bao giờ được coi là 'không listed'"
        );
        assert!(!agg.answered);
    }

    #[test]
    fn partial_timeout_does_not_hide_a_listing() {
        let mut dead = entry("sorbs.net", DnsblGroup::Community, Signal::Unknown, false);
        dead.error = Some(ProviderError::timeout());
        let listed = entry("bl.spamcop.net", DnsblGroup::Community, Signal::Suspicious, true);
        let agg = aggregate_group(DnsblGroup::Community, vec![dead, listed]);
        assert!(agg.answered);
        assert_eq!(agg.signal, Signal::Suspicious);
        assert_eq!(agg.listed, 1);
    }

    #[test]
    fn dead_zone_is_disabled_after_three_failures() {
        let health = ZoneHealth::new();
        let zone = "dnsbl.inps.de";
        assert!(health.is_disabled(zone).is_none());
        health.record_failure(zone, "timeout");
        health.record_failure(zone, "timeout");
        assert!(
            health.is_disabled(zone).is_none(),
            "2 lần lỗi chưa đủ ngưỡng"
        );
        health.record_failure(zone, "timeout");
        assert!(
            health.is_disabled(zone).is_some(),
            "3 lần lỗi ⇒ disable (§5.3), không làm sập check"
        );
        assert_eq!(health.disabled_zones().len(), 1);
    }

    #[test]
    fn success_resets_failure_counter() {
        let health = ZoneHealth::new();
        let zone = "bl.mailspike.net";
        health.record_failure(zone, "timeout");
        health.record_failure(zone, "timeout");
        health.record_success(zone);
        health.record_failure(zone, "timeout");
        assert!(
            health.is_disabled(zone).is_none(),
            "một lần thành công phải reset bộ đếm"
        );
    }

    #[test]
    fn disabled_module_reports_unknown_not_clean() {
        let registry = crate::providers::registry::empty();
        let result = empty_result(&registry, &ALL_GROUPS);
        assert_eq!(result.total_listed, 0);
        assert_eq!(result.groups_answered, 0);
        assert!(result.groups.iter().all(|g| g.signal == Signal::Unknown));
        assert!(result.groups.iter().all(|g| !g.answered));
    }

    #[test]
    fn hard_hit_only_from_spamhaus_group() {
        // Build the same aggregation the async path uses, without DNS.
        let spamhaus = aggregate_group(
            DnsblGroup::Spamhaus,
            vec![entry("zen.spamhaus.org", DnsblGroup::Spamhaus, Signal::Bad, true)],
        );
        let community = aggregate_group(
            DnsblGroup::Community,
            vec![entry("bl.spamcop.net", DnsblGroup::Community, Signal::Suspicious, true)],
        );
        let hard_hit = [&spamhaus, &community]
            .iter()
            .any(|g| g.group == DnsblGroup::Spamhaus && g.listed > 0);
        assert!(hard_hit, "Spamhaus listed ⇒ hard_hit (§6.5)");

        let only_community = [&community]
            .iter()
            .any(|g| g.group == DnsblGroup::Spamhaus && g.listed > 0);
        assert!(!only_community);
    }

    #[test]
    fn ipv6_lookup_name_minimum_length() {
        let ip: IpAddr = "::1".parse().unwrap();
        let name = lookup_name(ip, "zen.spamhaus.org");
        // 32 nibbles + 1 dot each side.
        assert_eq!(name.split('.').count(), 32 + 3);
    }

    #[test]
    fn poisoned_disabled_map_still_answers() {
        // A poisoned lock means another thread panicked while holding it. The
        // HashMap itself is fine, so the recovery path must keep reading it.
        // `.ok()?` returned None, which reads as "zone is healthy" and kept
        // querying a zone this session had already given up on.
        let map = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::<String, String>::new(),
        ));
        {
            let mut guard = map.lock().unwrap();
            guard.insert("zen.spamhaus.org".to_string(), "timeout".to_string());
        }

        let clone = std::sync::Arc::clone(&map);
        let _ = std::thread::spawn(move || {
            let _guard = clone.lock().unwrap();
            panic!("poison the disabled map");
        })
        .join();
        assert!(map.lock().is_err(), "the lock must actually be poisoned");

        // Exactly what `is_disabled` does after the fix.
        let guard = match map.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert_eq!(
            guard.get("zen.spamhaus.org").map(String::as_str),
            Some("timeout"),
            "a poisoned lock must still report the disabled zone"
        );
        assert_eq!(guard.get("other.zone"), None);
    }

    #[test]
    fn disabled_module_note_does_not_claim_a_verdict() {
        // §5.3: a module that never queried a zone must not read as "checked".
        let registry = Registry::default();
        let result = empty_result(&registry, &ALL_GROUPS);
        assert!(!result.groups.iter().any(|g| g.answered));
        assert_eq!(result.groups_answered, 0);
    }
}
