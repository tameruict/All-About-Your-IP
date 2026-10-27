//! ASN aggregation — consensus, RIR-vs-geo mismatch, IP type classification
//! (§5.1, §5.2, §7.4).
//!
//! Two invariants the rest of the app depends on:
//!
//!   * **Consensus needs two independent sources** (§6.3). One provider claiming
//!     an ASN is reported but never marked `consensus = true`, because scoring
//!     treats consensus as the quorum signal for the ASN aspect.
//!   * **`ip_type` is decided in a documented priority order** (§7.5): Tor wins
//!     over VPN, VPN over proxy, proxy over datacenter, and so on. A residential
//!     label is only inferred from positively-absent flags *plus* an ISP that
//!     looks residential — never from silence alone.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::models::{AsnRecord, AsnResult, IpFlags, IpType};

/// ISP / organisation names that indicate a hosting provider. Used only to
/// *suspect* datacenter when no adapter set the `hosting` flag explicitly.
pub const HOSTING_KEYWORDS: [&str; 18] = [
    "hosting",
    "datacenter",
    "data center",
    "cloud",
    "server",
    "vps",
    "amazon",
    "aws",
    "google cloud",
    "azure",
    "microsoft",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "contabo",
    "leaseweb",
];

/// ISP names that are clearly consumer ISPs (a weak *residential* hint).
pub const RESIDENTIAL_KEYWORDS: [&str; 13] = [
    "viettel",
    "vietel",
    "vnpt",
    "fpt telecom",
    "comcast",
    "verizon",
    "at&t",
    "spectrum",
    "centurylink",
    "deutsche telekom",
    "orange",
    "bt ",
    "telstra",
];

/// Aggregate per-source ASN records into one answer (§5.1, §5.2, §7.4).
///
/// * `consensus` — ≥ 2 sources agree on the same ASN (§6.3).
/// * `country_mismatch` — the RIR country says one thing, geo says another.
/// * `ip_type` — from [`classify_with_context`], which also looks at the
///   organisation name when flags are all false.
pub fn aggregate(
    records: Vec<AsnRecord>,
    flags: IpFlags,
    isp: Option<String>,
    geo_country: Option<String>,
) -> AsnResult {
    let mut tally: HashMap<u32, u32> = HashMap::new();
    for record in &records {
        if let Some(asn) = record.asn {
            *tally.entry(asn).or_insert(0) += 1;
        }
    }

    // Deterministic winner: most votes, then the smallest ASN so two runs over
    // the same evidence can never disagree.
    let best = tally
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(asn, _)| *asn);
    let consensus = tally
        .values()
        .copied()
        .max()
        .map(|n| n >= 2)
        .unwrap_or(false);

    let chosen = best.and_then(|asn| records.iter().find(|r| r.asn == Some(asn)).cloned());

    let best_records: Vec<&AsnRecord> = records.iter().filter(|r| r.asn == best).collect();
    let asn_name = chosen
        .as_ref()
        .and_then(|c| c.asn_name.clone())
        .or_else(|| best_records.iter().find_map(|r| r.asn_name.clone()));
    let organisation = chosen
        .as_ref()
        .and_then(|c| c.organisation.clone())
        .or_else(|| best_records.iter().find_map(|r| r.organisation.clone()))
        .or_else(|| records.iter().find_map(|r| r.organisation.clone()))
        .or_else(|| asn_name.clone());
    let isp = isp
        .or_else(|| organisation.clone())
        .or_else(|| asn_name.clone());
    let prefix = chosen
        .as_ref()
        .and_then(|c| c.prefix.clone())
        .or_else(|| best_records.iter().find_map(|r| r.prefix.clone()))
        .or_else(|| records.iter().find_map(|r| r.prefix.clone()));

    let rir_country = records.iter().find_map(|r| r.rir_country.clone());

    let country_mismatch = match (&geo_country, &rir_country) {
        (Some(geo), Some(rir)) => !normalise_country(geo).eq_ignore_ascii_case(&normalise_country(rir)),
        _ => false,
    };

    // The organisation name is the only extra signal available when every flag
    // is false, so pass it into the classifier (§5.1).
    let mut org_hints = Vec::new();
    if let Some(ref org) = organisation {
        if !org.trim().is_empty() {
            org_hints.push(org.clone());
        }
    }
    if let Some(ref i) = isp {
        if !i.trim().is_empty() {
            org_hints.push(i.clone());
        }
    }
    if let Some(ref name) = asn_name {
        if !name.trim().is_empty() {
            org_hints.push(name.clone());
        }
    }
    let combined_org = org_hints.join(" ");
    let org_hint = if combined_org.is_empty() {
        None
    } else {
        Some(combined_org)
    };

    let ip_type = classify_with_context(&flags, org_hint.as_deref(), &records);

    AsnResult {
        asn: best,
        asn_name,
        organisation,
        prefix,
        isp,
        rir_country,
        consensus,
        country_mismatch,
        records,
        ip_type,
        flags,
    }
}

/// Compare country codes tolerantly (`"VN"` vs `"Vietnam"` vs `"viet nam"`).
///
/// Two spellings only match when they resolve to the same ISO-3166 alpha-2
/// code; otherwise the raw strings are compared.
fn normalise_country(value: &str) -> String {
    let key = value
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '_', '.'], "");
    if key.len() == 2 {
        return key;
    }
    for (code, name) in COUNTRY_ALIASES {
        if key == *name || key == *code {
            return (*code).to_string();
        }
    }
    key
}

/// Minimal ISO-3166 alpha-2 ↔ English-name table covering the countries the RIR
/// and geo sources disagree about most often. Anything absent falls back to a
/// raw string comparison, which is correct while both sources use one wording.
const COUNTRY_ALIASES: &[(&str, &str)] = &[
    ("us", "unitedstates"),
    ("us", "unitedstatesofamerica"),
    ("us", "usa"),
    ("gb", "unitedkingdom"),
    ("gb", "greatbritain"),
    ("vn", "vietnam"),
    ("vn", "vietnam"),
    ("sg", "singapore"),
    ("de", "germany"),
    ("de", "deutschland"),
    ("fr", "france"),
    ("nl", "netherlands"),
    ("nl", "thenetherlands"),
    ("jp", "japan"),
    ("cn", "china"),
    ("hk", "hongkong"),
    ("kr", "southkorea"),
    ("kr", "korea"),
    ("ru", "russia"),
    ("ru", "russianfederation"),
    ("br", "brazil"),
    ("in", "india"),
    ("au", "australia"),
    ("ca", "canada"),
    ("it", "italy"),
    ("es", "spain"),
    ("se", "sweden"),
    ("ch", "switzerland"),
    ("pl", "poland"),
    ("ua", "ukraine"),
    ("id", "indonesia"),
    ("th", "thailand"),
    ("my", "malaysia"),
    ("ph", "philippines"),
    ("tw", "taiwan"),
    ("tr", "turkey"),
    ("ae", "unitedarabemirates"),
];

/// Map provider flags onto an [`IpType`] using the §7.5 priority order.
pub fn classify(flags: &IpFlags) -> IpType {
    if flags.tor {
        IpType::Tor
    } else if flags.vpn {
        IpType::Vpn
    } else if flags.proxy {
        IpType::Proxy
    } else if flags.anycast == Some(true) {
        IpType::Anycast
    } else if flags.hosting {
        IpType::Datacenter
    } else if flags.mobile {
        IpType::Mobile
    } else {
        IpType::Unknown
    }
}

/// Same as [`classify`] but falls back to the organisation name, then to the
/// absence of any suspicious flag plus a residential ISP name (§5.1).
///
/// The order matters: an explicit provider flag always beats a name heuristic,
/// and `Unknown` beats a wrong guess — the UI must show
/// "Chưa xác định" rather than a confident lie.
pub fn classify_with_context(flags: &IpFlags, org: Option<&str>, records: &[AsnRecord]) -> IpType {
    let flagged = classify(flags);
    if flagged != IpType::Unknown {
        return flagged;
    }

    // CGNAT shows up as a shared-address prefix rather than a flag (§5.1).
    if records.iter().any(|r| {
        r.prefix
            .as_deref()
            .map(is_cgnat_prefix)
            .unwrap_or(false)
    }) {
        return IpType::Cgnat;
    }

    let Some(org) = org else {
        return IpType::Unknown;
    };
    let lowered = org.to_ascii_lowercase();

    // Education is checked first: "Vietnam National University" would otherwise
    // be swallowed by the residential list, and a campus network is its own
    // bucket in the UI (§5.1).
    if lowered.contains("universit")
        || lowered.contains("college")
        || lowered.contains("education")
        || lowered.contains("school")
        || lowered.contains("academy")
        || lowered.contains("institute")
        || lowered.contains(".edu")
    {
        return IpType::Edu;
    }
    if HOSTING_KEYWORDS.iter().any(|k| lowered.contains(k)) {
        return IpType::Datacenter;
    }
    if RESIDENTIAL_KEYWORDS.iter().any(|k| lowered.contains(k)) {
        return IpType::Residential;
    }

    IpType::Unknown
}

/// True for the CGNAT range `100.64.0.0/10` (§5.1).
pub fn is_cgnat_prefix(prefix: &str) -> bool {
    let Some(addr) = prefix.split('/').next() else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

/// Vietnamese label for the UI badge.
pub fn ip_type_label(ip_type: IpType) -> &'static str {
    match ip_type {
        IpType::Residential => "Residential",
        IpType::Datacenter => "Datacenter",
        IpType::Mobile => "Mobile",
        IpType::Cgnat => "CGNAT",
        IpType::Vpn => "VPN",
        IpType::Tor => "Tor",
        IpType::Proxy => "Proxy",
        IpType::Anycast => "Anycast",
        IpType::Edu => "Giáo dục",
        IpType::Unknown => "Chưa xác định",
    }
}

/// §7.5 — does this IP type mean the city is a network egress, not a person?
pub fn is_egress_type(ip_type: IpType) -> bool {
    matches!(
        ip_type,
        IpType::Datacenter | IpType::Vpn | IpType::Tor | IpType::Proxy | IpType::Anycast
    )
}

/// A human warning for the UI when the location is only an egress point (§7.5).
pub fn location_caveat(ip_type: IpType) -> Option<&'static str> {
    match ip_type {
        IpType::Datacenter => Some("IP datacenter — vị trí là trung tâm dữ liệu, không phải người dùng"),
        IpType::Vpn => Some("IP VPN — vị trí là máy chủ VPN, không phải người dùng"),
        IpType::Tor => Some("IP Tor exit — vị trí là node thoát Tor, không xác định được người dùng"),
        IpType::Proxy => Some("IP proxy — vị trí là proxy, không phải người dùng"),
        IpType::Anycast => Some("IP anycast — cùng một IP tồn tại ở nhiều nơi (§7.5)"),
        IpType::Cgnat => Some("IP CGNAT — nhiều người dùng chung một IP, vị trí là gateway nhà mạng"),
        IpType::Mobile => Some("IP mobile — vị trí là gateway nhà mạng di động"),
        _ => None,
    }
}

/// Convenience wrapper used before any adapter has answered.
pub fn unknown(_ip: IpAddr) -> AsnResult {
    AsnResult {
        records: Vec::new(),
        ip_type: IpType::Unknown,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(source: &str, asn: u32) -> AsnRecord {
        AsnRecord {
            source: source.to_string(),
            asn: Some(asn),
            asn_name: Some(format!("AS{asn}-NAME")),
            organisation: None,
            prefix: None,
            rir_country: None,
            registry: None,
            note: None,
        }
    }

    #[test]
    fn two_sources_agreeing_is_consensus() {
        let result = aggregate(
            vec![record("ripestat", 15169), record("bgpview", 15169)],
            IpFlags::default(),
            None,
            None,
        );
        assert_eq!(result.asn, Some(15169));
        assert!(result.consensus, "2 nguồn cùng ASN ⇒ consensus (§6.3)");
    }

    #[test]
    fn single_source_is_not_consensus() {
        let result = aggregate(
            vec![record("ripestat", 15169)],
            IpFlags::default(),
            None,
            None,
        );
        assert_eq!(result.asn, Some(15169));
        assert!(
            !result.consensus,
            "§6.3: một nguồn không đủ để gọi là đồng thuận"
        );
    }

    #[test]
    fn majority_wins_with_deterministic_tiebreak() {
        let result = aggregate(
            vec![
                record("a", 64500),
                record("b", 64500),
                record("c", 64501),
            ],
            IpFlags::default(),
            None,
            None,
        );
        assert_eq!(result.asn, Some(64500));
        assert!(result.consensus);

        // A 1‑1 tie must resolve to the smaller ASN, run after run.
        let tie = aggregate(
            vec![record("a", 65001), record("b", 65000)],
            IpFlags::default(),
            None,
            None,
        );
        assert_eq!(tie.asn, Some(65000), "hoà phiếu ⇒ lấy ASN nhỏ hơn");
        assert!(!tie.consensus);
    }

    #[test]
    fn empty_records_yield_unknown_not_zero() {
        let result = aggregate(Vec::new(), IpFlags::default(), None, None);
        assert_eq!(result.asn, None);
        assert!(!result.consensus);
        assert_eq!(result.ip_type, IpType::Unknown);
    }

    #[test]
    fn country_mismatch_between_rir_and_geo_is_flagged() {
        let mut r = record("ripestat", 15169);
        r.rir_country = Some("US".to_string());
        let result = aggregate(vec![r], IpFlags::default(), None, Some("SG".to_string()));
        assert!(result.country_mismatch, "§7.4: RIR US vs geo SG ⇒ lệch");

        let mut ok = record("ripestat", 15169);
        ok.rir_country = Some("United States".to_string());
        let same = aggregate(vec![ok], IpFlags::default(), None, Some("us".to_string()));
        assert!(!same.country_mismatch, "US vs us phải coi là khớp");
    }

    #[test]
    fn tor_beats_every_other_flag() {
        let flags = IpFlags {
            tor: true,
            vpn: true,
            proxy: true,
            hosting: true,
            mobile: true,
            anycast: Some(true),
        };
        assert_eq!(classify(&flags), IpType::Tor);
    }

    #[test]
    fn flag_priority_order_is_vpn_then_proxy_then_datacenter() {
        let vpn = IpFlags {
            vpn: true,
            proxy: true,
            ..Default::default()
        };
        assert_eq!(classify(&vpn), IpType::Vpn);

        let proxy = IpFlags {
            proxy: true,
            hosting: true,
            ..Default::default()
        };
        assert_eq!(classify(&proxy), IpType::Proxy);

        let hosting = IpFlags {
            hosting: true,
            mobile: true,
            ..Default::default()
        };
        assert_eq!(classify(&hosting), IpType::Datacenter);
    }

    #[test]
    fn hosting_name_without_flags_is_datacenter() {
        let result = aggregate(
            vec![record("ripestat", 16509)],
            IpFlags::default(),
            Some("Amazon.com, Inc.".to_string()),
            None,
        );
        assert_eq!(
            result.ip_type,
            IpType::Datacenter,
            "tên ISP hosting ⇒ Datacenter (§5.1)"
        );
    }

    #[test]
    fn residential_isp_name_is_residential() {
        let result = aggregate(
            vec![record("ripestat", 7552)],
            IpFlags::default(),
            Some("Viettel Group".to_string()),
            None,
        );
        assert_eq!(result.ip_type, IpType::Residential);
    }

    #[test]
    fn edu_network_is_edu() {
        let result = aggregate(
            vec![record("ripestat", 4538)],
            IpFlags::default(),
            Some("Vietnam National University".to_string()),
            None,
        );
        assert_eq!(result.ip_type, IpType::Edu);
    }

    #[test]
    fn cgnat_prefix_is_detected() {
        assert!(is_cgnat_prefix("100.64.0.0/10"));
        assert!(is_cgnat_prefix("100.127.255.1"));
        assert!(!is_cgnat_prefix("100.63.0.1"), "100.63 ngoài dải CGNAT");
        assert!(!is_cgnat_prefix("100.128.0.1"));
        assert!(!is_cgnat_prefix("8.8.8.8"));
        assert!(!is_cgnat_prefix("not-an-ip"));

        let mut r = record("ripestat", 64500);
        r.prefix = Some("100.64.0.0/10".to_string());
        assert_eq!(
            classify_with_context(&IpFlags::default(), None, &[r]),
            IpType::Cgnat
        );
    }

    #[test]
    fn silent_evidence_stays_unknown() {
        let result = aggregate(
            vec![record("ripestat", 15169)],
            IpFlags::default(),
            Some("Some Unknown Network LLC".to_string()),
            None,
        );
        assert_eq!(
            result.ip_type,
            IpType::Unknown,
            "không có cờ + tên lạ ⇒ Chưa xác định, không đoán bừa"
        );
    }

    #[test]
    fn anycast_flag_maps_to_anycast() {
        let flags = IpFlags {
            anycast: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&flags), IpType::Anycast);
    }

    #[test]
    fn egress_types_are_flagged_for_location_caveats() {
        assert!(is_egress_type(IpType::Datacenter));
        assert!(is_egress_type(IpType::Vpn));
        assert!(is_egress_type(IpType::Tor));
        assert!(is_egress_type(IpType::Proxy));
        assert!(is_egress_type(IpType::Anycast));
        assert!(!is_egress_type(IpType::Residential));
        assert!(!is_egress_type(IpType::Mobile));

        assert!(location_caveat(IpType::Datacenter).is_some());
        assert!(location_caveat(IpType::Residential).is_none());
    }

    #[test]
    fn ip_type_labels_are_vietnamese_for_ui() {
        assert_eq!(ip_type_label(IpType::Unknown), "Chưa xác định");
        assert_eq!(ip_type_label(IpType::Edu), "Giáo dục");
        assert_eq!(ip_type_label(IpType::Cgnat), "CGNAT");
        assert_eq!(ip_type_label(IpType::Datacenter), "Datacenter");
    }

    #[test]
    fn unknown_helper_keeps_type_unknown() {
        let result = unknown("8.8.8.8".parse().unwrap());
        assert_eq!(result.ip_type, IpType::Unknown);
        assert!(result.records.is_empty());
        assert_eq!(result.asn, None);
    }
}
