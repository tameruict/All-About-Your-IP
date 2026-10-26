//! Scoring engine — normalisation, upstream de-duplication, quorum, Clean +
//! Confidence, verdict mapping (§6).
//!
//! # The golden rule (§6)
//!
//! **No single provider decides clean/dirty.** Concretely, this module enforces:
//!
//! 1. **Normalise first** (§6.1) — every provider scale is mapped to a
//!    [`Signal`] using the thresholds in `providers.yaml`, never hardcoded.
//! 2. **De-duplicate by `(upstream, category)`** (§6.2) — three resellers of
//!    Spamhaus cast ONE vote. When they disagree internally the worst wins.
//! 3. **Quorum** (§6.3) — fraud needs ≥ 2 non-Unknown votes, blacklist needs
//!    ≥ 3 groups, ASN needs ≥ 2 agreeing sources. Missing quorum caps the verdict
//!    at `Chưa đủ dữ liệu` regardless of the score.
//! 4. **Weights with a 40 % cap** (§6.4) — Fraud 35, Blacklist 25, ASN/IP-type
//!    20, Abuse 10, Consistency 10; inside an aspect no provider exceeds 40 %,
//!    so one rogue source can move the total by ~14 points at most.
//! 5. **Confidence is separate** (§6.4) — coverage × agreement; a confident
//!    "dirty" and a shaky "clean" are never conflated.
//! 6. **Conflict demotion** (§6.5) — one bad source among clean ones ⇒ at most
//!    `Nghi ngờ`; a lone Spamhaus/Tor hit ⇒ at most `Nghi ngờ` with an explicit
//!    "single strong evidence" reason; one clean source among dirty ones ⇒ never
//!    clean.
//! 7. **Verdict from the §6.5 table**, never from the score alone.

use std::collections::HashMap;

use crate::models::{
    Category, ConflictFlag, DnsblGroup, DnsblResult, FullCheckResult, ProviderEvidence, QuorumStatus,
    ScoreBreakdown, ScoringResult, Signal, Verdict,
};

// ---------------------------------------------------------------------------
// Constants (§6.3, §6.4, §6.5)
// ---------------------------------------------------------------------------

/// §6.4 aspect weights — must sum to 1.0.
pub const WEIGHTS: [(&str, f64); 5] = [
    ("fraud", 0.35),
    ("blacklist", 0.25),
    ("asn", 0.20),
    ("abuse", 0.10),
    ("consistency", 0.10),
];

/// §6.4 hard cap: no single provider may own more than 40 % of an aspect.
pub const MAX_PROVIDER_SHARE: f64 = 0.40;

/// §6.5 verdict thresholds on the Clean Score.
pub const CLEAN_VERDICT_MIN: f64 = 85.0;
pub const TEM_VERDICT_MIN: f64 = 65.0;
pub const NGHI_NGO_VERDICT_MIN: f64 = 40.0;

/// Points a signal contributes on the 0–100 clean scale.
pub const POINTS_CLEAN: f64 = 100.0;
pub const POINTS_SUSPICIOUS: f64 = 50.0;
pub const POINTS_BAD: f64 = 0.0;

/// §6.3 quorum requirements per aspect.
pub fn quorum_requirement(aspect: &str) -> u32 {
    match aspect {
        "fraud" => 2,
        "blacklist" => 3,
        "asn" => 2,
        "abuse" => 1,
        "consistency" => 2,
        _ => 1,
    }
}

/// Aspect label → the provider categories that vote in it.
pub fn aspect_categories(aspect: &str) -> &'static [Category] {
    match aspect {
        "fraud" => &[Category::Fraud],
        "blacklist" => &[Category::Blacklist],
        "asn" => &[Category::Asn, Category::LocalDb],
        "abuse" => &[Category::Abuse, Category::ThreatIntel],
        // Consistency is computed from geo/timezone/ASN agreement, not votes.
        "consistency" => &[],
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Normalisation (§6.1)
// ---------------------------------------------------------------------------

/// Map a provider's raw score onto a [`Signal`] using its own thresholds (§6.1).
///
/// `clean_below` / `bad_above` come from `providers.yaml`, never hardcoded here.
pub fn classify_score(score: f64, clean_below: f64, bad_above: f64) -> Signal {
    if !score.is_finite() {
        return Signal::Unknown;
    }
    if score < clean_below {
        Signal::Clean
    } else if score > bad_above {
        Signal::Bad
    } else {
        Signal::Suspicious
    }
}

/// Normalise a raw score when the caller only has `Option<f64>`.
pub fn classify_opt(score: Option<f64>, clean_below: f64, bad_above: f64) -> Signal {
    match score {
        Some(s) => classify_score(s, clean_below, bad_above),
        None => Signal::Unknown,
    }
}

/// Numeric value of a signal on the 0–100 clean scale (§6.4).
pub fn signal_points(signal: Signal) -> Option<f64> {
    match signal {
        Signal::Clean => Some(POINTS_CLEAN),
        Signal::Suspicious => Some(POINTS_SUSPICIOUS),
        Signal::Bad => Some(POINTS_BAD),
        Signal::Unknown => None,
    }
}

/// The more pessimistic of two signals.
pub fn worse_of(a: Signal, b: Signal) -> Signal {
    let rank = |s: Signal| match s {
        Signal::Clean => 0,
        Signal::Suspicious => 1,
        Signal::Bad => 2,
        Signal::Unknown => 3,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// The more optimistic of two signals (Unknown never wins over a real answer).
pub fn better_of(a: Signal, b: Signal) -> Signal {
    match (a, b) {
        (Signal::Unknown, other) => other,
        (other, Signal::Unknown) => other,
        _ => {
            if worse_of(a, b) == a {
                b
            } else {
                a
            }
        }
    }
}

// ---------------------------------------------------------------------------
// De-duplication (§6.2)
// ---------------------------------------------------------------------------

/// One de-duplicated vote.
#[derive(Debug, Clone)]
pub struct Vote {
    pub upstream: String,
    pub category: Category,
    /// Worst signal reported by any provider sharing this upstream.
    pub signal: Signal,
    /// Providers that collapsed into this vote.
    pub providers: Vec<String>,
    /// Raw severity hint (worst raw_score among the group), for reporting only.
    pub raw_score: Option<f64>,
}

impl Vote {
    /// §6.4 weight of this vote inside its aspect, capped at 40 %.
    pub fn weight(&self, configured: f64) -> f64 {
        if configured.is_finite() && configured > 0.0 {
            configured.min(MAX_PROVIDER_SHARE)
        } else {
            MAX_PROVIDER_SHARE * 0.5
        }
    }
}

/// §6.2 de-duplicate votes by `upstream + category`.
///
/// When several providers share one upstream, only the **worst** signal is kept
/// (conservative), and every contributing provider name is retained so the UI
/// can explain *why* a single upstream spoke once.
pub fn dedupe_by_upstream(evidence: &[ProviderEvidence]) -> Vec<(String, Category, Signal, u32)> {
    group_votes(evidence)
        .into_iter()
        .map(|v| (v.upstream, v.category, v.signal, v.providers.len() as u32))
        .collect()
}

/// Full de-duplication, returning richer [`Vote`]s.
pub fn group_votes(evidence: &[ProviderEvidence]) -> Vec<Vote> {
    let mut groups: HashMap<(String, Category), Vote> = HashMap::new();
    for ev in evidence {
        if ev.signal == Signal::Unknown {
            continue;
        }
        // §5.3 / BUG-02: For blacklist evidence, cbl_abuseat (group: community)
        // and spamhaus_dbl (group: specialist) must not collapse into the
        // "spamhaus" group vote even if their root upstream in providers.yaml is spamhaus.
        let upstream = if ev.category == Category::Blacklist {
            if ev.provider == "cbl_abuseat"
                || ev.provider.contains("cbl.abuseat")
                || ev.upstream == "cbl_abuseat"
            {
                "cbl_abuseat".to_string()
            } else if ev.provider == "spamhaus_dbl"
                || ev.provider.contains("dbl.spamhaus")
                || ev.upstream == "spamhaus_dbl"
            {
                "spamhaus_dbl".to_string()
            } else {
                ev.upstream.clone()
            }
        } else {
            ev.upstream.clone()
        };
        let key = (upstream.clone(), ev.category);
        match groups.get_mut(&key) {
            Some(vote) => {
                vote.signal = worse_of(vote.signal, ev.signal);
                vote.providers.push(ev.provider.clone());
                vote.raw_score = match (vote.raw_score, ev.raw_score) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (a, None) => a,
                };
            }
            None => {
                groups.insert(
                    key,
                    Vote {
                        upstream,
                        category: ev.category,
                        signal: ev.signal,
                        providers: vec![ev.provider.clone()],
                        raw_score: ev.raw_score,
                    },
                );
            }
        }
    }
    let mut out: Vec<Vote> = groups.into_values().collect();
    out.sort_by(|a, b| {
        a.upstream
            .cmp(&b.upstream)
            .then_with(|| category_sort_key(a.category).cmp(category_sort_key(b.category)))
    });
    out
}

/// Stable sort key for [`Category`] (`Category` deliberately does not derive
/// `Ord`, and scoring must never depend on declaration order anyway).
pub fn category_sort_key(category: Category) -> &'static str {
    match category {
        Category::Geo => "0-geo",
        Category::LocalDb => "1-localdb",
        Category::Asn => "2-asn",
        Category::Fraud => "3-fraud",
        Category::Abuse => "4-abuse",
        Category::ThreatIntel => "5-threatintel",
        Category::Blacklist => "6-blacklist",
        Category::Network => "7-network",
        Category::Leak => "8-leak",
        Category::Speed => "9-speed",
    }
}

// ---------------------------------------------------------------------------
// Aspect evaluation (§6.3, §6.4)
// ---------------------------------------------------------------------------

/// Outcome of scoring one aspect.
#[derive(Debug, Clone)]
pub struct AspectOutcome {
    pub aspect: String,
    pub weight: f64,
    pub score: Option<f64>,
    pub votes: u32,
    pub required: u32,
    pub quorum_met: bool,
    pub note: String,
    pub signals: Vec<Signal>,
    pub upstreams: Vec<String>,
}

/// Weighted mean of the votes inside one aspect, with the 40 % cap applied.
///
/// Returns `None` when no vote has a usable signal.
pub fn aspect_score(votes: &[Vote], weight_lookup: impl Fn(&Vote) -> f64) -> Option<f64> {
    let mut total_weight = 0.0;
    let mut total_points = 0.0;
    for vote in votes {
        let Some(points) = signal_points(vote.signal) else {
            continue;
        };
        let w = vote.weight(weight_lookup(vote));
        total_weight += w;
        total_points += w * points;
    }
    if total_weight <= 0.0 {
        None
    } else {
        Some(total_points / total_weight)
    }
}

/// Evaluate the vote-based aspects (fraud, blacklist, asn, abuse).
fn evaluate_vote_aspect(
    aspect: &str,
    votes: &[Vote],
    registry_weights: &HashMap<String, f64>,
    expected: u32,
) -> AspectOutcome {
    let categories = aspect_categories(aspect);
    let mine: Vec<Vote> = votes
        .iter()
        .filter(|v| categories.contains(&v.category))
        .cloned()
        .collect();

    let weight = WEIGHTS
        .iter()
        .find(|(name, _)| *name == aspect)
        .map(|(_, w)| *w)
        .unwrap_or(0.0);
    let required = quorum_requirement(aspect);

    // For blacklist a "vote" is a DNSBL *group*; group_votes already collapsed
    // by upstream, so blacklist votes are additionally collapsed per group.
    let effective: Vec<Vote> = if aspect == "blacklist" {
        collapse_dnsbl_groups(&mine)
    } else {
        mine.clone()
    };

    let usable: Vec<&Vote> = effective
        .iter()
        .filter(|v| v.signal != Signal::Unknown)
        .collect();
    let votes_count = usable.len() as u32;
    let quorum_met = votes_count >= required;

    let score = aspect_score(&effective, |v| {
        registry_weights
            .get(&format!("{}::{}", v.category as u8 as char, v.upstream))
            .copied()
            .or_else(|| registry_weights.get(&v.upstream).copied())
            .unwrap_or(MAX_PROVIDER_SHARE)
    });

    let note = if !quorum_met {
        format!(
            "Thiếu quorum: {votes_count}/{required} phiếu — không được kết luận (§6.3)"
        )
    } else if votes_count < expected {
        format!("Đủ quorum tối thiểu ({votes_count}/{required}), còn thiếu nguồn phụ")
    } else {
        format!("Đủ quorum ({votes_count}/{required})")
    };

    AspectOutcome {
        aspect: aspect.to_string(),
        weight,
        score,
        votes: votes_count,
        required,
        quorum_met,
        note,
        signals: usable.iter().map(|v| v.signal).collect(),
        upstreams: usable.iter().map(|v| v.upstream.clone()).collect(),
    }
}

/// §5.3 — a DNSBL *group* is one vote, no matter how many zones it holds.
///
/// The group vote is the worst listed signal among its zones, so Spamhaus can
/// never outvote the rest of the world by shipping four zones.
fn collapse_dnsbl_groups(votes: &[Vote]) -> Vec<Vote> {
    let mut by_group: HashMap<&'static str, Vote> = HashMap::new();
    for vote in votes {
        let group = group_of_vote(vote);
        match by_group.get_mut(group) {
            Some(existing) => {
                existing.signal = worse_of(existing.signal, vote.signal);
                existing.providers.extend(vote.providers.clone());
            }
            None => {
                by_group.insert(
                    group,
                    Vote {
                        upstream: group.to_string(),
                        category: Category::Blacklist,
                        signal: vote.signal,
                        providers: vote.providers.clone(),
                        raw_score: vote.raw_score,
                    },
                );
            }
        }
    }
    let mut out: Vec<Vote> = by_group.into_values().collect();
    out.sort_by(|a, b| a.upstream.cmp(&b.upstream));
    out
}

/// Resolve the canonical §5.3 DNSBL group for a [`Vote`].
///
/// Checks contributing provider IDs first (to honor declared groups such as
/// `cbl_abuseat` => community, `spamhaus_dbl` => specialist), then falls back
/// to the upstream name.
pub fn group_of_vote(vote: &Vote) -> &'static str {
    for p in &vote.providers {
        match p.as_str() {
            "cbl_abuseat" | "cbl" => return "community",
            "spamhaus_dbl" => return "specialist",
            _ if p.contains("cbl.abuseat") => return "community",
            _ if p.contains("dbl.spamhaus") => return "specialist",
            _ => {}
        }
    }
    group_of_upstream(&vote.upstream)
}

/// Convenience alias for [`group_of_vote`].
pub fn vote_dnsbl_group(vote: &Vote) -> &'static str {
    group_of_vote(vote)
}

/// Map a blacklist upstream onto its §5.3 group.
pub fn group_of_upstream(upstream: &str) -> &'static str {
    match upstream {
        "spamhaus" | "spamhaus_zen" | "spamhaus_sbl" | "spamhaus_xbl" | "spamhaus_pbl" => {
            "spamhaus"
        }
        "commercial" | "barracuda" | "spamrats" | "hostkarma" | "inps.de" | "inps_de"
        | "mailspike" => "commercial",
        "community" | "spamcop" | "sorbs" | "uceprotect" | "uceprotect_1" | "uceprotect_2"
        | "njabl" | "psbl" | "cbl_abuseat" | "abuseat" | "cbl" => "community",
        "specialist" | "tor-project" | "tor_exit_dan" | "dronebl" | "efnet" | "efnet_rbl"
        | "backscatterer" | "spamhaus_dbl" => "specialist",
        _ => "community",
    }
}

/// The §5.3 group a [`DnsblGroup`] maps to for reporting.
pub fn dnsbl_group_aspect_label(group: DnsblGroup) -> &'static str {
    match group {
        DnsblGroup::Spamhaus => "spamhaus",
        DnsblGroup::Commercial => "commercial",
        DnsblGroup::Community => "community",
        DnsblGroup::Specialist => "specialist",
    }
}

/// §6.4 consistency aspect: how much the independent sources agree.
///
/// `None` when there is nothing to compare (never a fabricated 100).
pub fn consistency_score(result: &FullCheckResult) -> (Option<f64>, u32, String) {
    let mut signals: Vec<Signal> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ASN consensus (§6.3: ≥2 sources agreeing on ASN).
    if let Some(asn) = &result.asn {
        if asn.consensus {
            signals.push(Signal::Clean);
            notes.push("ASN: ≥2 nguồn đồng ý".to_string());
        } else if !asn.records.is_empty() {
            signals.push(Signal::Suspicious);
            notes.push("ASN: chưa đủ 2 nguồn đồng ý".to_string());
        }
        if asn.country_mismatch {
            signals.push(Signal::Bad);
            notes.push("Quốc gia RIR khác quốc gia geo".to_string());
        }
    }

    // Location consistency (§7.3, §7.7).
    if let Some(location) = &result.location {
        if location.big_divergence {
            signals.push(Signal::Bad);
            notes.push("Các nguồn geo lệch > 2.000 km".to_string());
        } else {
            match location.spread.as_str() {
                "high" => {
                    signals.push(Signal::Clean);
                    notes.push("Geo: các nguồn chụm < 50 km".to_string());
                }
                "medium" => {
                    signals.push(Signal::Suspicious);
                    notes.push("Geo: lệch 50–200 km".to_string());
                }
                "low" => {
                    signals.push(Signal::Suspicious);
                    notes.push("Geo: lệch > 200 km".to_string());
                }
                _ => {}
            }
        }
    }

    // Timezone agreement between geo sources.
    if let Some(location) = &result.location {
        let timezones: Vec<&str> = location
            .points
            .iter()
            .filter_map(|p| p.timezone.as_deref())
            .filter(|t| !t.is_empty())
            .collect();
        let distinct: std::collections::HashSet<&str> = timezones.iter().copied().collect();
        if timezones.len() >= 2 {
            if distinct.len() == 1 {
                signals.push(Signal::Clean);
                notes.push("Timezone: các nguồn khớp".to_string());
            } else {
                signals.push(Signal::Suspicious);
                notes.push(format!("Timezone: {} giá trị khác nhau", distinct.len()));
            }
        }
    }

    // Leak signals only exist in proxy mode (§8.2).
    if let Some(leak) = &result.leak {
        if leak.measured {
            let mut leak_points = 0;
            if leak.webrtc_leak {
                signals.push(Signal::Bad);
                notes.push("WebRTC lòi IP thật".to_string());
                leak_points += 1;
            }
            if leak.dns_leak == Some(true) {
                signals.push(Signal::Bad);
                notes.push("DNS leak".to_string());
                leak_points += 1;
            }
            if leak.timezone_mismatch {
                signals.push(Signal::Suspicious);
                notes.push("Timezone browser lệch timezone IP".to_string());
                leak_points += 1;
            }
            if leak_points == 0 {
                signals.push(Signal::Clean);
                notes.push("Không thấy leak".to_string());
            }
        }
    }

    let votes = signals.len() as u32;
    if signals.is_empty() {
        return (None, 0, "Chưa có dữ liệu để đối chiếu".to_string());
    }

    let total: f64 = signals.iter().copied().filter_map(signal_points).sum();
    let count = signals.iter().filter(|s| signal_points(**s).is_some()).count() as f64;
    let score = if count > 0.0 { Some(total / count) } else { None };

    (score, votes, notes.join("; "))
}

/// §6.3 consistency quorum: ≥ 2 comparable facts.
pub fn consistency_quorum_met(votes: u32) -> bool {
    votes >= quorum_requirement("consistency")
}

// ---------------------------------------------------------------------------
// Confidence (§6.4, separate from Clean Score)
// ---------------------------------------------------------------------------

/// Confidence = coverage × agreement, both on 0–1, expressed 0–100.
///
/// Deliberately NOT derived from the Clean Score: a lone "bad" source and a
/// unanimous "clean" panel must not look equally trustworthy.
pub fn confidence_score(
    aspects: &[AspectOutcome],
    evidence: &[ProviderEvidence],
    expected_votes: u32,
) -> f64 {
    let total_votes: u32 = aspects.iter().map(|a| a.votes).sum();

    // Coverage: how many expected voices actually answered.
    let denom = expected_votes.max(total_votes).max(1) as f64;
    let coverage = (total_votes as f64 / denom).clamp(0.0, 1.0);

    // Agreement: share of votes that sit in the majority camp per aspect.
    let mut agreement_num = 0.0_f64;
    let mut agreement_den = 0.0_f64;
    for aspect in aspects {
        if aspect.signals.is_empty() {
            continue;
        }
        let mut tally: HashMap<&'static str, u32> = HashMap::new();
        for s in &aspect.signals {
            *tally.entry(signal_key(*s)).or_insert(0) += 1;
        }
        let top = tally.values().copied().max().unwrap_or(0) as f64;
        let total = aspect.signals.len() as f64;
        agreement_num += top / total;
        agreement_den += 1.0;
    }
    let agreement = if agreement_den > 0.0 {
        agreement_num / agreement_den
    } else {
        0.0
    };

    // Providers that errored out silently reduce confidence (§6.3),
    // but missing API keys for optional providers do not penalize confidence.
    let error_penalty = evidence
        .iter()
        .filter(|e| {
            e.error.as_ref().map(|err| err.kind != "no_key").unwrap_or(false)
        })
        .count()
        .min(4) as f64
        * 3.0;

    let raw = 100.0 * (0.6 * coverage + 0.4 * agreement) - error_penalty;
    raw.clamp(0.0, 100.0)
}

fn signal_key(signal: Signal) -> &'static str {
    match signal {
        Signal::Clean => "clean",
        Signal::Suspicious => "suspicious",
        Signal::Bad => "bad",
        Signal::Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Verdict (§6.5)
// ---------------------------------------------------------------------------

/// Verdict from a clean score alone (§6.5 table rows 1–4).
///
/// Only used *after* quorum and conflict rules passed — the public verdict is
/// [`decide_verdict`], which combines this with §6.3/§6.5.
pub fn verdict_from_score(clean: f64) -> Verdict {
    if clean >= CLEAN_VERDICT_MIN {
        Verdict::Sạch
    } else if clean >= TEM_VERDICT_MIN {
        Verdict::Tạm
    } else if clean >= NGHI_NGO_VERDICT_MIN {
        Verdict::NghiNgờ
    } else {
        Verdict::Bẩn
    }
}

/// Severity ordering used to demote a verdict (§6.5).
fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Sạch => 3,
        Verdict::Tạm => 2,
        Verdict::NghiNgờ => 1,
        Verdict::Bẩn => 0,
        Verdict::ChưaĐủDữLiệu => 0,
    }
}

/// The more pessimistic of two verdicts (§6.5 "hạ bậc").
pub fn demote(a: Verdict, b: Verdict) -> Verdict {
    if verdict_rank(a) <= verdict_rank(b) {
        a
    } else {
        b
    }
}

/// Inputs the verdict table needs beyond the score.
#[derive(Debug, Clone, Default)]
pub struct VerdictInputs {
    pub clean_score: Option<f64>,
    pub quorum_ok: bool,
    pub quorum_missing: Vec<String>,
    pub hard_conflict: bool,
    pub soft_conflict: bool,
    /// Any Spamhaus ZEN / Tor-exit style hit (§6.5 hard-evidence rule).
    pub strong_single_hit: bool,
    /// Another blacklist group or abuse history confirms the strong hit.
    pub independent_confirmation: bool,
    /// Number of distinct blacklist groups reporting a listing.
    pub blacklist_groups_listed: u32,
    /// Multi-source consensus that the IP is bad.
    pub multi_source_bad: bool,
    /// Number of usable fraud votes (quorum gate, §6.3).
    pub fraud_votes: u32,
    /// Distinct upstreams reporting bad/suspicious.
    pub bad_upstreams: Vec<String>,
}

/// §6.5 verdict table: score + quorum + conflict, NOT score alone.
pub fn decide_verdict(inputs: &VerdictInputs) -> (Verdict, String) {
    // Row 5 first: missing quorum anywhere mandatory ⇒ "Chưa đủ dữ liệu",
    // no matter how good or bad the provisional score looks.
    if !inputs.quorum_ok {
        let missing = if inputs.quorum_missing.is_empty() {
            "khía cạnh bắt buộc".to_string()
        } else {
            inputs.quorum_missing.join(", ")
        };
        return (
            Verdict::ChưaĐủDữLiệu,
            format!("Chưa đủ dữ liệu: thiếu quorum ở {missing} — không được kết luận"),
        );
    }

    let Some(clean) = inputs.clean_score else {
        return (
            Verdict::ChưaĐủDữLiệu,
            "Chưa đủ dữ liệu: không có phiếu nào dùng được".to_string(),
        );
    };

    let base = verdict_from_score(clean);
    let mut verdict = base;
    let mut reason = String::new();

    // §6.5 — one clean source among dirty ones may never produce "Sạch".
    if inputs.hard_conflict && verdict == Verdict::Sạch {
        verdict = Verdict::NghiNgờ;
        reason.push_str(
            "Có nguồn báo bẩn trong khi phần còn lại sạch — không kết luận sạch (§6.5). ",
        );
    }

    // §6.5 — a lone strong hit (Spamhaus ZEN / Tor exit) is capped.
    if inputs.strong_single_hit {
        if !inputs.independent_confirmation {
            verdict = demote(verdict, Verdict::NghiNgờ);
            reason.push_str(
                "Bằng chứng đơn lẻ mạnh (Spamhaus/Tor) chưa có nguồn thứ hai xác nhận — verdict tối đa Nghi ngờ (§6.5). ",
            );
        } else if verdict == Verdict::Sạch || verdict == Verdict::Tạm {
            // Confirmed but the score was dragged up by weaker aspects: a
            // confirmed hard listing can never be "Sạch".
            verdict = Verdict::NghiNgờ;
            reason.push_str("Dính blacklist nghiêm trọng đã được xác nhận. ");
        }
    } else if inputs.blacklist_groups_listed >= 2 && verdict == Verdict::Sạch {
        verdict = Verdict::Tạm;
        reason.push_str("Dính blacklist ở ≥2 nhóm — không thể Sạch. ");
    }

    // §6.5 — multi-source bad consensus forces "Bẩn" even at a middling score.
    if inputs.multi_source_bad {
        verdict = demote(verdict, Verdict::Bẩn);
        reason.push_str("Nhiều nguồn độc lập cùng báo bẩn (§6.5). ");
    }

    // Soft conflict ⇒ at best "Tạm": when the sources disagree, the check is not
    // clean enough to call "Sạch", but the demotion must not stop at "Tạm".
    if inputs.soft_conflict && verdict == Verdict::Sạch {
        verdict = Verdict::Tạm;
        reason.push_str("Các nguồn không hoàn toàn đồng thuận. ");
    }

    // §6.5 bullet: exactly one source claims bad while the others are clean.
    // The verdict is capped at "Nghi ngờ" — never "Sạch" (already handled by
    // `hard_conflict`) and never merely "Tạm", because a real bad signal exists
    // and the user must see it. `bad_upstreams` already carries the names, so
    // the count is the number of distinct upstreams reporting bad.
    if inputs.bad_upstreams.len() == 1 && verdict == Verdict::Tạm {
        verdict = Verdict::NghiNgờ;
        reason.push_str(&format!(
            "Chỉ 1 nguồn ({}) báo bẩn trong khi các nguồn khác sạch — chưa đủ để kết luận Bẩn, nhưng không thể coi là Tạm (§6.5). ",
            inputs.bad_upstreams[0]
        ));
    }

    // Score-driven row of the table (§6.5).
    if inputs.clean_score.map(|s| s < NGHI_NGO_VERDICT_MIN).unwrap_or(false)
        && verdict != Verdict::Bẩn
    {
        verdict = demote(verdict, Verdict::Bẩn);
        reason.push_str("Clean Score < 40 (§6.5). ");
    }

    if reason.is_empty() {
        reason = match verdict {
            Verdict::Sạch => "Đủ quorum, các nguồn đồng thuận sạch, không dính blacklist.".to_string(),
            Verdict::Tạm => "Đủ quorum, có xung đột nhẹ hoặc 1 DNSBL cộng đồng.".to_string(),
            Verdict::NghiNgờ => format!("Clean Score {clean:.0} nằm trong dải 40–64 (§6.5)."),
            Verdict::Bẩn => "Đồng thuận đa nguồn báo bẩn / dính nhiều nhóm blacklist.".to_string(),
            Verdict::ChưaĐủDữLiệu => "Chưa đủ dữ liệu.".to_string(),
        };
    }

    (verdict, reason.trim().to_string())
}

// ---------------------------------------------------------------------------
// Conflicts (§6.5)
// ---------------------------------------------------------------------------

/// Detect cross-source disagreement inside each vote-based aspect.
pub fn detect_conflicts(aspects: &[AspectOutcome]) -> Vec<ConflictFlag> {
    let mut out = Vec::new();
    for aspect in aspects {
        if aspect.signals.is_empty() {
            continue;
        }
        let bad = aspect
            .signals
            .iter()
            .filter(|s| **s == Signal::Bad)
            .count();
        let clean = aspect
            .signals
            .iter()
            .filter(|s| **s == Signal::Clean)
            .count();

        if bad > 0 && clean > 0 {
            // One bad source among clean ones (§6.5 first bullet), or the
            // reverse (§6.5 second bullet) — both are real conflicts.
            let severity = if bad == 1 && clean >= 2 {
                "soft"
            } else if clean == 1 && bad >= 1 {
                "hard"
            } else {
                "hard"
            };
            let dissenting = if bad <= clean {
                aspect
                    .upstreams
                    .iter()
                    .zip(aspect.signals.iter())
                    .filter(|(_, s)| **s == Signal::Bad)
                    .map(|(u, _)| u.clone())
                    .collect::<Vec<_>>()
            } else {
                aspect
                    .upstreams
                    .iter()
                    .zip(aspect.signals.iter())
                    .filter(|(_, s)| **s == Signal::Clean)
                    .map(|(u, _)| u.clone())
                    .collect::<Vec<_>>()
            };
            out.push(ConflictFlag {
                severity: severity.to_string(),
                aspect: aspect.aspect.clone(),
                dissenting,
                agreeing: aspect
                    .upstreams
                    .iter()
                    .zip(aspect.signals.iter())
                    .filter(|(_, s)| match severity {
                        _ if bad <= clean => **s != Signal::Bad,
                        _ => **s != Signal::Clean,
                    })
                    .map(|(u, _)| u.clone())
                    .collect(),
                message: format!(
                    "{} nguồn báo bẩn / {} nguồn báo sạch trong khía cạnh {}",
                    bad, clean, aspect.aspect
                ),
            });
        } else if aspect.signals.iter().any(|s| *s == Signal::Suspicious)
            && aspect.signals.iter().any(|s| *s == Signal::Clean)
        {
            out.push(ConflictFlag {
                severity: "soft".to_string(),
                aspect: aspect.aspect.clone(),
                dissenting: Vec::new(),
                agreeing: aspect.upstreams.clone(),
                message: format!("Khía cạnh {} trộn lẫn nghi ngờ và sạch", aspect.aspect),
            });
        }
    }
    out
}

/// Turn a set of conflicts into the single strongest one, for the HUD reason line.
pub fn strongest_conflict(conflicts: &[ConflictFlag]) -> Option<&ConflictFlag> {
    conflicts
        .iter()
        .find(|c| c.severity == "hard")
        .or_else(|| conflicts.first())
}

// ---------------------------------------------------------------------------
// Generic helpers retained for callers / tests
// ---------------------------------------------------------------------------

/// Build an empty-but-typed quorum report for every aspect (§6.3).
pub fn empty_quorum() -> Vec<QuorumStatus> {
    WEIGHTS
        .iter()
        .map(|(aspect, _)| QuorumStatus {
            aspect: (*aspect).to_string(),
            required: quorum_requirement(aspect),
            actual: 0,
            met: false,
            missing: vec![format!(
                "cần {} phiếu, chưa có phiếu nào",
                quorum_requirement(aspect)
            )],
        })
        .collect()
}

/// Placeholder scoring output: `"Chưa đủ dữ liệu"`, never a fabricated number.
pub fn not_enough_data(reason: impl Into<String>) -> ScoringResult {
    ScoringResult {
        clean_score: None,
        confidence_score: 0.0,
        verdict: Verdict::ChưaĐủDữLiệu,
        verdict_reason: reason.into(),
        breakdown: WEIGHTS
            .iter()
            .map(|(aspect, weight)| ScoreBreakdown {
                aspect: (*aspect).to_string(),
                weight: *weight,
                aspect_score: None,
                weighted: None,
                votes: 0,
                quorum_met: false,
                note: String::new(),
            })
            .collect(),
        conflicts: Vec::new(),
        quorum: empty_quorum(),
        single_source_evidence: false,
        notes: Vec::new(),
    }
}

/// Convenience: number of usable (non-Unknown) votes in a category.
pub fn usable_votes(evidence: &[ProviderEvidence], category: Category) -> u32 {
    evidence
        .iter()
        .filter(|e| e.category == category && e.signal != Signal::Unknown)
        .count() as u32
}

/// Expected number of voices, used as the confidence denominator (§6.4).
///
/// `blacklist` counts groups (4 max), not zones, because a group is one vote.
pub fn expected_votes() -> u32 {
    let mut total = 0;
    for (aspect, _) in WEIGHTS.iter() {
        match *aspect {
            "blacklist" => total += 4,
            "consistency" => total += 3,
            _ => total += quorum_requirement(aspect).max(2),
        }
    }
    total
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Full scoring pass (§6.4–§6.6).
///
/// `registry_weights` maps `upstream` (or `"category::upstream"`) to the
/// configured `weight_in_category`. Missing entries fall back to the 40 % cap
/// so a provider is never silently weightless.
pub fn score(
    result: &FullCheckResult,
    evidence: &[ProviderEvidence],
    registry_weights: &HashMap<String, f64>,
) -> ScoringResult {
    score_with_expected(result, evidence, registry_weights, None)
}

/// Same as [`score`] with an explicit blacklist-group count override (tests).
pub fn score_with_expected(
    result: &FullCheckResult,
    evidence: &[ProviderEvidence],
    registry_weights: &HashMap<String, f64>,
    dnsbl_override: Option<&DnsblResult>,
) -> ScoringResult {
    let votes = group_votes(evidence);

    let fraud = evaluate_vote_aspect("fraud", &votes, registry_weights, 2);
    let blacklist = evaluate_vote_aspect("blacklist", &votes, registry_weights, 4);
    let asn = evaluate_vote_aspect("asn", &votes, registry_weights, 2);
    let abuse = evaluate_vote_aspect("abuse", &votes, registry_weights, 1);

    // Consistency (§6.4) comes from geo/ASN/timezone/leak agreement, and is
    // also allowed to use the parsed DNSBL block for group accounting.
    let (consistency_value, consistency_votes, consistency_note) = consistency_score(result);
    let consistency = AspectOutcome {
        aspect: "consistency".to_string(),
        weight: WEIGHTS[4].1,
        score: consistency_value,
        votes: consistency_votes,
        required: quorum_requirement("consistency"),
        quorum_met: consistency_quorum_met(consistency_votes),
        note: consistency_note,
        signals: Vec::new(),
        upstreams: Vec::new(),
    };

    let aspects = vec![
        fraud.clone(),
        blacklist.clone(),
        asn.clone(),
        abuse.clone(),
        consistency.clone(),
    ];

    // ---- Clean Score: weighted mean over aspects that produced a value ----
    let mut weighted_sum = 0.0;
    let mut weight_sum = 0.0;
    let mut breakdown = Vec::with_capacity(aspects.len());
    for aspect in &aspects {
        let weighted = aspect.score.map(|s| s * aspect.weight);
        if let Some(w) = weighted {
            weighted_sum += w;
            weight_sum += aspect.weight;
        }
        breakdown.push(ScoreBreakdown {
            aspect: aspect.aspect.clone(),
            weight: aspect.weight,
            aspect_score: aspect.score,
            weighted,
            votes: aspect.votes,
            quorum_met: aspect.quorum_met,
            note: aspect.note.clone(),
        });
    }
    let clean_score = if weight_sum > 0.0 {
        Some(weighted_sum / weight_sum)
    } else {
        None
    };

    // ---- Quorum report (§6.3). Mandatory aspects: fraud + blacklist. ----
    let mut quorum = Vec::new();
    let mut quorum_missing = Vec::new();
    for aspect in &aspects {
        quorum.push(QuorumStatus {
            aspect: aspect.aspect.clone(),
            required: aspect.required,
            actual: aspect.votes,
            met: aspect.quorum_met,
            missing: if aspect.quorum_met {
                Vec::new()
            } else {
                vec![format!(
                    "{}: cần {} phiếu, có {}",
                    aspect.aspect, aspect.required, aspect.votes
                )]
            },
        });
    }
    // §6.3: fraud quorum and blacklist quorum are the mandatory gates. ASN and
    // consistency only demote confidence when thin, they do not force "unknown".
    if !fraud.quorum_met {
        quorum_missing.push("fraud".to_string());
    }
    if !blacklist.quorum_met {
        quorum_missing.push("blacklist".to_string());
    }
    let quorum_ok = quorum_missing.is_empty();

    // ---- Conflicts (§6.5) ----
    let conflicts = detect_conflicts(&aspects);
    let hard_conflict = conflicts.iter().any(|c| c.severity == "hard");
    let soft_conflict = conflicts.iter().any(|c| c.severity == "soft");

    // ---- Strong single evidence (Spamhaus ZEN / Tor exit) ----
    let dnsbl = dnsbl_override.or(result.dnsbl.as_ref());
    let (strong_single_hit, blacklist_groups_listed, independent_confirmation) =
        strong_hit_analysis(&votes, dnsbl, result);

    // ---- Multi-source bad consensus ----
    let bad_upstreams: Vec<String> = votes
        .iter()
        .filter(|v| v.signal == Signal::Bad)
        .map(|v| v.upstream.clone())
        .collect();
    let multi_source_bad = bad_upstreams.len() >= 3 || (bad_upstreams.len() >= 2 && !soft_conflict);

    let verdict_inputs = VerdictInputs {
        clean_score,
        quorum_ok,
        quorum_missing: quorum_missing.clone(),
        hard_conflict,
        soft_conflict,
        strong_single_hit,
        independent_confirmation,
        blacklist_groups_listed,
        multi_source_bad,
        fraud_votes: fraud.votes,
        bad_upstreams: bad_upstreams.clone(),
    };
    let (verdict, mut verdict_reason) = decide_verdict(&verdict_inputs);

    // Append the winning conflict so the HUD line is actionable (§3.2).
    if let Some(conflict) = strongest_conflict(&conflicts) {
        if !conflict.dissenting.is_empty() {
            verdict_reason.push_str(&format!(
                " Nguồn lệch: {}.",
                conflict.dissenting.join(", ")
            ));
        }
    }

    let confidence = confidence_score(&aspects, evidence, expected_votes());

    let mut notes = Vec::new();
    if !quorum_ok {
        notes.push(format!(
            "Verdict bị chặn bởi quorum thiếu: {} (§6.3)",
            quorum_missing.join(", ")
        ));
    }
    let unknown = evidence
        .iter()
        .filter(|e| e.signal == Signal::Unknown)
        .count();
    if unknown > 0 {
        notes.push(format!(
            "{unknown} nguồn trả Unknown (timeout/hết quota/thiếu key) — Confidence bị trừ"
        ));
    }
    if let Some(asn_aspect) = aspects.get(2) {
        if !asn_aspect.quorum_met {
            notes.push("ASN chưa đủ 2 nguồn đồng ý — geo/ASN kém tin cậy (§6.3)".to_string());
        }
    }
    notes.push(
        "Không provider nào quyết định verdict: trọng số mỗi provider ≤ 40% khía cạnh (§6.4)"
            .to_string(),
    );

    let single_source_evidence = strong_single_hit && !independent_confirmation;

    ScoringResult {
        clean_score,
        confidence_score: confidence,
        verdict,
        verdict_reason,
        breakdown,
        conflicts,
        quorum,
        single_source_evidence,
        notes,
    }
}

/// §6.5 hard-evidence analysis.
///
/// Returns `(strong_single_hit, groups_listed, confirmed_by_second_source)`.
fn strong_hit_analysis(
    votes: &[Vote],
    dnsbl: Option<&DnsblResult>,
    result: &FullCheckResult,
) -> (bool, u32, bool) {
    // A Spamhaus group hit or a Tor-exit hit is "hard evidence".
    let spamhaus_hit = votes.iter().any(|v| {
        v.category == Category::Blacklist
            && v.signal == Signal::Bad
            && vote_dnsbl_group(v) == "spamhaus"
    });
    let tor_hit = votes.iter().any(|v| {
        v.category == Category::Blacklist
            && v.signal != Signal::Clean
            && (v.upstream == "tor-project" || v.providers.iter().any(|p| p.contains("tor")))
    }) || result
        .asn
        .as_ref()
        .map(|a| a.flags.tor)
        .unwrap_or(false);

    let groups_listed = match dnsbl {
        Some(d) => d
            .groups
            .iter()
            .filter(|g| g.answered && g.signal != Signal::Clean)
            .count() as u32,
        None => votes
            .iter()
            .filter(|v| v.category == Category::Blacklist && v.signal != Signal::Clean)
            .map(|v| vote_dnsbl_group(v))
            .collect::<std::collections::HashSet<_>>()
            .len() as u32,
    };

    let strong = spamhaus_hit || tor_hit;

    // A second, independent blacklist group or an abuse-history hit confirms it.
    let other_group_hit = match dnsbl {
        Some(d) => d.groups.iter().any(|g| {
            g.answered
                && g.signal != Signal::Clean
                && dnsbl_group_aspect_label(g.group) != "spamhaus"
                && dnsbl_group_aspect_label(g.group) != "specialist"
        }),
        None => votes.iter().any(|v| {
            v.category == Category::Blacklist
                && v.signal != Signal::Clean
                && !matches!(
                    vote_dnsbl_group(v),
                    "spamhaus" | "specialist"
                )
        }),
    };
    let abuse_hit = votes
        .iter()
        .any(|v| matches!(v.category, Category::Abuse) && v.signal == Signal::Bad);

    (
        strong,
        groups_listed,
        other_group_hit || abuse_hit,
    )
}

/// Build the `upstream → weight` map the scoring pass expects.
pub fn weight_lookup(registry: &crate::providers::registry::Registry) -> HashMap<String, f64> {
    registry
        .providers
        .iter()
        .map(|p| (p.upstream.clone(), p.sanitised_weight()))
        .collect()
}

// ---------------------------------------------------------------------------
// Anti-Bot / Reg-Account Scoring Profile (DeepSeek teammate contribution)
// ---------------------------------------------------------------------------

/// Profile for scoring. Default is `Standard`, `AntiBot` prioritizes reg-acc safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScoringProfile {
    #[default]
    Standard,
    AntiBot,
}

/// Apply Anti-Bot / Reg-Account rules to Clean Score:
/// A Datacenter/Hosting IP is fundamentally unsuitable for registration, capping it at 45.0.
/// Any Tor flag caps at 10.0, Proxy/VPN further penalizes by 15.0.
pub fn apply_anti_bot_profile(
    score: f64,
    flags: Option<&crate::models::IpFlags>,
    ip_type: crate::models::IpType,
) -> f64 {
    let flags_hosting = flags.map(|f| f.hosting).unwrap_or(false);
    let flags_proxy = flags.map(|f| f.proxy).unwrap_or(false);
    let flags_vpn = flags.map(|f| f.vpn).unwrap_or(false);
    let flags_tor = flags.map(|f| f.tor).unwrap_or(false);

    let is_dc = flags_hosting || ip_type == crate::models::IpType::Datacenter;
    let is_tor = flags_tor || ip_type == crate::models::IpType::Tor;
    let is_vpn = flags_vpn || ip_type == crate::models::IpType::Vpn;
    let is_proxy = flags_proxy || ip_type == crate::models::IpType::Proxy;

    let ceiling = if is_tor {
        10.0
    } else if is_dc {
        45.0
    } else if is_vpn || is_proxy {
        35.0
    } else {
        100.0
    };

    let mut s = score.min(ceiling);
    if is_proxy || is_vpn {
        s -= 15.0;
    }
    if is_tor {
        s -= 30.0;
    }
    s.clamp(0.0, 100.0)
}

// ---------------------------------------------------------------------------
// Tests — the five mandatory §6 scenarios plus guards
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DnsblGroup, DnsblGroupResult, GeoPoint, ProviderEvidence};

    fn ev(provider: &str, category: Category, upstream: &str, signal: Signal) -> ProviderEvidence {
        ProviderEvidence {
            provider: provider.to_string(),
            category,
            upstream: upstream.to_string(),
            signal,
            raw_score: signal_points(signal).map(|p| 100.0 - p),
            raw: None,
            checked_at: "2026-10-25T10:00:00+00:00".to_string(),
            source_url: "https://example.invalid/".to_string(),
            latency_ms: Some(100),
            error: None,
            reason: None,
            from_cache: false,
        }
    }

    fn base_result() -> FullCheckResult {
        let mut result = FullCheckResult::short_circuit(
            "check".to_string(),
            "8.8.8.8".to_string(),
            String::new(),
        );
        result.validation_error = None;
        result
    }

    fn full_clean_evidence() -> Vec<ProviderEvidence> {
        vec![
            // fraud: 3 distinct upstreams, all clean
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Clean),
            ev("proxycheck", Category::Fraud, "proxycheck", Signal::Clean),
            ev("scamalytics", Category::Fraud, "scamalytics", Signal::Clean),
            // blacklist: 4 groups answered, all clean
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Clean),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Clean),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Clean),
            ev("dronebl", Category::Blacklist, "dronebl", Signal::Clean),
            // asn: 2 sources agreeing
            ev("ripestat", Category::Asn, "ripestat", Signal::Clean),
            ev("bgpview", Category::Asn, "bgpview", Signal::Clean),
            // abuse: clean
            ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Clean),
        ]
    }

    fn registry_weights() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        for upstream in [
            "ipqualityscore",
            "proxycheck",
            "scamalytics",
            "spamhaus",
            "barracuda",
            "spamcop",
            "dronebl",
            "ripestat",
            "bgpview",
            "abuseipdb",
        ] {
            map.insert(upstream.to_string(), 0.30);
        }
        map
    }

    fn consistent_result() -> FullCheckResult {
        let mut result = base_result();
        result.asn = Some(crate::models::AsnResult {
            consensus: true,
            ..Default::default()
        });
        result.location = Some(crate::models::LocationResult {
            spread: "high".to_string(),
            points: vec![
                GeoPoint {
                    timezone: Some("Asia/Ho_Chi_Minh".to_string()),
                    ..Default::default()
                },
                GeoPoint {
                    timezone: Some("Asia/Ho_Chi_Minh".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        result
    }

    // ------------------------------------------------------------------
    // TEST 1 (§6.3) — quorum fail ⇒ "Chưa đủ dữ liệu"
    // ------------------------------------------------------------------
    #[test]
    fn quorum_fail_returns_chua_du_du_lieu() {
        // Only ONE fraud vote ⇒ quorum (2) fails ⇒ no conclusion allowed,
        // even though that single vote is perfectly clean.
        let evidence = vec![
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Clean),
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Clean),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Clean),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Clean),
        ];
        let result = consistent_result();
        let scored = score(&result, &evidence, &registry_weights());

        assert_eq!(
            scored.verdict,
            Verdict::ChưaĐủDữLiệu,
            "1 phiếu fraud < quorum 2 ⇒ không được kết luận (§6.3)"
        );
        assert!(
            scored.verdict_reason.contains("quorum"),
            "lý do phải nêu quorum: {}",
            scored.verdict_reason
        );
        assert_eq!(
            scored.clean_score.map(|s| s >= CLEAN_VERDICT_MIN),
            Some(true),
            "score tạm tính vẫn cao — nhưng verdict bị chặn, đó chính là điểm §6.5"
        );
        let fraud_q = scored
            .quorum
            .iter()
            .find(|q| q.aspect == "fraud")
            .expect("phải có báo cáo quorum cho fraud");
        assert!(!fraud_q.met);
        assert_eq!(fraud_q.actual, 1);
        assert_eq!(fraud_q.required, 2);
    }

    #[test]
    fn blacklist_quorum_needs_three_groups() {
        let mut evidence = full_clean_evidence();
        // Drop two blacklist groups ⇒ only 2 answered ⇒ blacklist quorum fails.
        evidence.retain(|e| {
            !(e.category == Category::Blacklist && (e.upstream == "spamcop" || e.upstream == "dronebl"))
        });
        let scored = score(&consistent_result(), &evidence, &registry_weights());
        assert_eq!(scored.verdict, Verdict::ChưaĐủDữLiệu);
        assert!(scored.verdict_reason.contains("blacklist"));
    }

    // ------------------------------------------------------------------
    // TEST 2 (§6.5) — a single bad source among clean ones ⇒ "Nghi ngờ"
    // ------------------------------------------------------------------
    #[test]
    fn single_bad_source_returns_nghi_ngo() {
        let mut evidence = full_clean_evidence();
        // Exactly one fraud source claims bad; every other fraud source is clean.
        evidence[0] = ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Bad);

        let scored = score(&consistent_result(), &evidence, &registry_weights());

        assert_eq!(
            scored.verdict,
            Verdict::NghiNgờ,
            "1 nguồn báo bẩn giữa các nguồn sạch ⇒ Nghi ngờ, không Bẩn (§6.5)"
        );
        assert!(
            scored.conflicts.iter().any(|c| c.aspect == "fraud"),
            "phải ghi rõ xung đột ở khía cạnh fraud"
        );
        // ONE provider may not flip the verdict: its max influence is 35% × 40%.
        let fraud_breakdown = scored
            .breakdown
            .iter()
            .find(|b| b.aspect == "fraud")
            .unwrap();
        assert!(
            fraud_breakdown.aspect_score.unwrap() > 50.0,
            "1/3 phiếu bad không được kéo khía cạnh fraud xuống đáy: {:?}",
            fraud_breakdown.aspect_score
        );
    }

    // ------------------------------------------------------------------
    // TEST 3 (§6.5) — Spamhaus-only ⇒ maxed at "Nghi ngờ"
    // ------------------------------------------------------------------
    #[test]
    fn spamhaus_only_capped_at_nghi_ngo() {
        let evidence = vec![
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Clean),
            ev("proxycheck", Category::Fraud, "proxycheck", Signal::Clean),
            // only Spamhaus is listed; other groups clean
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Clean),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Clean),
            ev("dronebl", Category::Blacklist, "dronebl", Signal::Clean),
            ev("ripestat", Category::Asn, "ripestat", Signal::Clean),
            ev("bgpview", Category::Asn, "bgpview", Signal::Clean),
            ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Clean),
        ];

        let mut result = consistent_result();
        result.dnsbl = Some(DnsblResult {
            groups: vec![
                DnsblGroupResult {
                    group: DnsblGroup::Spamhaus,
                    label: "Spamhaus".to_string(),
                    checked: 4,
                    listed: 1,
                    signal: Signal::Bad,
                    answered: true,
                    entries: Vec::new(),
                },
                DnsblGroupResult {
                    group: DnsblGroup::Commercial,
                    label: "Thương mại".to_string(),
                    checked: 1,
                    listed: 0,
                    signal: Signal::Clean,
                    answered: true,
                    entries: Vec::new(),
                },
                DnsblGroupResult {
                    group: DnsblGroup::Community,
                    label: "Cộng đồng".to_string(),
                    checked: 3,
                    listed: 0,
                    signal: Signal::Clean,
                    answered: true,
                    entries: Vec::new(),
                },
            ],
            total_listed: 1,
            groups_answered: 3,
            hard_hit: true,
            notes: Vec::new(),
        });

        let scored = score(&result, &evidence, &registry_weights());

        assert_eq!(
            scored.verdict,
            Verdict::NghiNgờ,
            "chỉ Spamhaus, không nguồn thứ hai ⇒ tối đa Nghi ngờ, KHÔNG được Bẩn (§6.5)"
        );
        assert!(
            scored.verdict_reason.contains("Bằng chứng đơn lẻ mạnh")
                || scored.verdict_reason.contains("đơn lẻ"),
            "lý do phải nói rõ bằng chứng đơn lẻ: {}",
            scored.verdict_reason
        );
        assert!(
            scored.single_source_evidence,
            "cờ single_source_evidence phải bật để UI cảnh báo"
        );
    }

    #[test]
    fn spamhaus_confirmed_by_abuse_history_can_be_ban() {
        let mut evidence = full_clean_evidence();
        evidence[3] = ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad);
        evidence[9] = ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Bad);

        let result = consistent_result();
        let scored = score(&result, &evidence, &registry_weights());

        assert!(
            matches!(scored.verdict, Verdict::Bẩn | Verdict::NghiNgờ),
            "Spamhaus + abuse xác nhận: được phép Bẩn, không bao giờ Sạch (got {:?})",
            scored.verdict
        );
        assert_ne!(scored.verdict, Verdict::Sạch);
    }

    // ------------------------------------------------------------------
    // TEST 4 (§6.5) — everything clean ⇒ "Sạch"
    // ------------------------------------------------------------------
    #[test]
    fn full_clean_returns_sach() {
        let scored = score(
            &consistent_result(),
            &full_clean_evidence(),
            &registry_weights(),
        );

        assert_eq!(
            scored.verdict,
            Verdict::Sạch,
            "đủ quorum + đồng thuận sạch + không blacklist ⇒ Sạch (reason: {})",
            scored.verdict_reason
        );
        assert_eq!(scored.clean_score.map(|s| s.round()), Some(100.0));
        assert!(
            scored.confidence_score >= 60.0,
            "confidence phải cao khi mọi nguồn trả lời: {}",
            scored.confidence_score
        );
        assert!(scored.conflicts.is_empty(), "không được có xung đột");
        assert!(!scored.single_source_evidence);
        assert!(scored.quorum.iter().all(|q| q.met));
    }

    // ------------------------------------------------------------------
    // TEST 5 (§6.5) — clean score 40–64 ⇒ "Nghi ngờ"
    // ------------------------------------------------------------------
    #[test]
    fn clean_score_40_to_64_returns_nghi_ngo() {
        // Aim squarely at the 40–64 band: with POINTS_CLEAN=100,
        // POINTS_SUSPICIOUS=50, POINTS_BAD=0, the aspect scores must average
        // out to the high 40s / low 50s. Fraud is all-Suspicious (50), abuse is
        // Suspicious (50), ASN has one Suspicious + one Clean (75) and
        // blacklist is clean-but-soft (100) — blended by the §6.4 weights this
        // lands inside 40–64 instead of the previous 75.9.
        let evidence = vec![
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Suspicious),
            ev("proxycheck", Category::Fraud, "proxycheck", Signal::Suspicious),
            ev("scamalytics", Category::Fraud, "scamalytics", Signal::Suspicious),
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Clean),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Clean),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Clean),
            ev("dronebl", Category::Blacklist, "dronebl", Signal::Clean),
            ev("ripestat", Category::Asn, "ripestat", Signal::Bad),
            ev("bgpview", Category::Asn, "bgpview", Signal::Suspicious),
            ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Suspicious),
        ];

        // ASN not agreed + a geo spread of "medium" keeps consistency below
        // clean without pushing it to Bad.
        let mut result = base_result();
        result.asn = Some(crate::models::AsnResult {
            consensus: false,
            ..Default::default()
        });
        result.location = Some(crate::models::LocationResult {
            spread: "medium".to_string(),
            points: vec![
                GeoPoint {
                    timezone: Some("Asia/Ho_Chi_Minh".to_string()),
                    ..Default::default()
                },
                GeoPoint {
                    timezone: Some("Asia/Ho_Chi_Minh".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });

        let scored = score(&result, &evidence, &registry_weights());
        let clean = scored.clean_score.expect("phải có score");

        assert!(
            (40.0..65.0).contains(&clean),
            "dữ liệu test phải rơi vào dải 40–64, thực tế {clean}"
        );
        assert_eq!(
            scored.verdict,
            Verdict::NghiNgờ,
            "Clean Score {clean:.1} trong 40–64 ⇒ Nghi ngờ (§6.5), reason: {}",
            scored.verdict_reason
        );
    }

    #[test]
    fn clean_score_below_40_returns_ban() {
        let evidence = vec![
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Bad),
            ev("proxycheck", Category::Fraud, "proxycheck", Signal::Bad),
            ev("scamalytics", Category::Fraud, "scamalytics", Signal::Bad),
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Bad),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Bad),
            ev("dronebl", Category::Blacklist, "dronebl", Signal::Bad),
            ev("ripestat", Category::Asn, "ripestat", Signal::Suspicious),
            ev("bgpview", Category::Asn, "bgpview", Signal::Suspicious),
            ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Bad),
        ];
        let scored = score(&base_result(), &evidence, &registry_weights());
        assert_eq!(scored.verdict, Verdict::Bẩn);
        assert!(scored.clean_score.unwrap() < NGHI_NGO_VERDICT_MIN);
    }

    // ------------------------------------------------------------------
    // §6.2 — upstream de-duplication
    // ------------------------------------------------------------------
    #[test]
    fn upstream_dedupe_collapses_resellers() {
        // Three zones sharing the Spamhaus upstream.
        let evidence = vec![
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("spamhaus_xbl", Category::Blacklist, "spamhaus", Signal::Clean),
            ev("spamhaus_sbl", Category::Blacklist, "spamhaus", Signal::Suspicious),
        ];
        let votes = dedupe_by_upstream(&evidence);
        assert_eq!(votes.len(), 1, "3 tên nhưng 1 upstream ⇒ 1 phiếu (§6.2)");
        let (upstream, category, signal, count) = &votes[0];
        assert_eq!(upstream, "spamhaus");
        assert_eq!(*category, Category::Blacklist);
        assert_eq!(*signal, Signal::Bad, "khi nội bộ lệch, lấy tín hiệu xấu nhất");
        assert_eq!(*count, 3, "vẫn giữ số provider để giải thích cho người dùng");
    }

    #[test]
    fn cbl_abuseat_and_dbl_do_not_collapse_into_spamhaus_group() {
        // cbl_abuseat (group: community) and spamhaus_dbl (group: specialist)
        // must not collapse into spamhaus group (BUG-02 / §5.3).
        let evidence = vec![
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("cbl_abuseat", Category::Blacklist, "spamhaus", Signal::Clean),
            ev("spamhaus_dbl", Category::Blacklist, "spamhaus", Signal::Suspicious),
        ];
        let votes = group_votes(&evidence);
        let collapsed = collapse_dnsbl_groups(&votes);
        assert_eq!(
            collapsed.len(),
            3,
            "cbl_abuseat (community), spamhaus_dbl (specialist), spamhaus_zen (spamhaus) ⇒ 3 nhóm khác nhau (§5.3 / BUG-02)"
        );
        assert!(collapsed.iter().any(|v| v.upstream == "spamhaus"));
        assert!(collapsed.iter().any(|v| v.upstream == "community"));
        assert!(collapsed.iter().any(|v| v.upstream == "specialist"));
    }

    #[test]
    fn upstream_dedupe_is_per_category() {
        // Same upstream, different aspect ⇒ two votes, not one.
        let evidence = vec![
            ev("ip_api", Category::Geo, "ip-api", Signal::Clean),
            ev("ip_api_flags", Category::Fraud, "ip-api", Signal::Clean),
        ];
        let votes = dedupe_by_upstream(&evidence);
        assert_eq!(votes.len(), 2, "khoá de-dup là (upstream, category) (§6.2)");
    }

    #[test]
    fn dnsbl_group_is_one_vote_regardless_of_zone_count() {
        // 4 Spamhaus zones + spamcop + sorbs. Per §5.3 a *group* is one vote,
        // and `spamcop`/`sorbs` both belong to the "community" group — so the
        // whole set is spamhaus + community = 2 votes, not 6 zones, and not 3.
        let evidence = vec![
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("spamhaus_sbl", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("spamhaus_xbl", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("spamhaus_pbl", Category::Blacklist, "spamhaus", Signal::Suspicious),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Suspicious),
            ev("sorbs", Category::Blacklist, "sorbs", Signal::Clean),
        ];
        let votes = group_votes(&evidence);
        let collapsed = collapse_dnsbl_groups(&votes);
        assert_eq!(
            collapsed.len(),
            2,
            "6 zone ⇒ 2 nhóm (spamhaus + community), không phải 6 phiếu (§5.3)"
        );

        let spamhaus = collapsed
            .iter()
            .find(|v| v.upstream == "spamhaus")
            .unwrap();
        assert_eq!(
            spamhaus.signal,
            Signal::Bad,
            "nhóm lấy tín hiệu xấu nhất trong các zone của nó"
        );

        let community = collapsed
            .iter()
            .find(|v| v.upstream == "community")
            .unwrap();
        assert_eq!(
            community.signal,
            Signal::Suspicious,
            "spamcop(Suspicious) tệ hơn sorbs(Clean) ⇒ nhóm là Suspicious"
        );
        assert_eq!(
            community.providers.len(),
            2,
            "vẫn giữ đủ tên provider để giải thích cho người dùng"
        );
    }

    #[test]
    fn every_dnsbl_group_maps_to_exactly_one_key() {
        // Guards the group_of_upstream table used by collapse_dnsbl_groups:
        // two providers of the same group must never land in two buckets.
        for (upstream, expected) in [
            ("spamhaus", "spamhaus"),
            ("barracuda", "commercial"),
            ("spamrats", "commercial"),
            ("spamcop", "community"),
            ("sorbs", "community"),
            ("uceprotect", "community"),
            ("cbl_abuseat", "community"),
            ("dronebl", "specialist"),
            ("tor-project", "specialist"),
            ("spamhaus_dbl", "specialist"),
        ] {
            assert_eq!(
                group_of_upstream(upstream),
                expected,
                "{upstream} phải thuộc nhóm {expected} (§5.3)"
            );
        }
        assert_eq!(
            group_of_upstream("spamcop"),
            group_of_upstream("sorbs"),
            "spamcop và sorbs cùng nhóm cộng đồng ⇒ chỉ 1 phiếu"
        );
    }

    // ------------------------------------------------------------------
    // §6.4 — weights and the 40 % cap
    // ------------------------------------------------------------------
    #[test]
    fn weights_sum_to_one() {
        let sum: f64 = WEIGHTS.iter().map(|(_, w)| *w).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights sum = {sum}");
    }

    #[test]
    fn one_provider_cannot_own_more_than_40_percent() {
        let vote = Vote {
            upstream: "greedy".to_string(),
            category: Category::Fraud,
            signal: Signal::Bad,
            providers: vec!["greedy".to_string()],
            raw_score: Some(99.0),
        };
        assert!(
            (vote.weight(0.95) - MAX_PROVIDER_SHARE).abs() < 1e-9,
            "0.95 phải bị clamp về 0.40"
        );
        // Worst case influence on the total = 0.35 × 0.40 = 14 points a aspect.
        let max_damage = 0.35 * MAX_PROVIDER_SHARE * 100.0;
        assert!(
            (max_damage - 14.0).abs() < 1e-9,
            "1 provider xấu nhất chỉ kéo ~14% tổng điểm (§6.4)"
        );
    }

    #[test]
    fn thresholds_map_as_spec() {
        // §6.1 IPQS example: <25 clean, >75 bad
        assert_eq!(classify_score(12.0, 25.0, 75.0), Signal::Clean);
        assert_eq!(classify_score(50.0, 25.0, 75.0), Signal::Suspicious);
        assert_eq!(classify_score(90.0, 25.0, 75.0), Signal::Bad);
        // §6.1 AbuseIPDB example: <10 clean, >50 bad
        assert_eq!(classify_score(5.0, 10.0, 50.0), Signal::Clean);
        assert_eq!(classify_score(10.0, 10.0, 50.0), Signal::Suspicious);
        assert_eq!(classify_score(51.0, 10.0, 50.0), Signal::Bad);
        assert_eq!(classify_score(f64::NAN, 10.0, 50.0), Signal::Unknown);
    }

    #[test]
    fn verdict_thresholds_match_table() {
        assert_eq!(verdict_from_score(90.0), Verdict::Sạch);
        assert_eq!(verdict_from_score(85.0), Verdict::Sạch);
        assert_eq!(verdict_from_score(84.9), Verdict::Tạm);
        assert_eq!(verdict_from_score(70.0), Verdict::Tạm);
        assert_eq!(verdict_from_score(64.9), Verdict::NghiNgờ);
        assert_eq!(verdict_from_score(40.0), Verdict::NghiNgờ);
        assert_eq!(verdict_from_score(39.9), Verdict::Bẩn);
        assert_eq!(verdict_from_score(0.0), Verdict::Bẩn);
    }

    // ------------------------------------------------------------------
    // §6.4 — confidence is independent of the clean score
    // ------------------------------------------------------------------
    #[test]
    fn confidence_is_separate_from_clean_score() {
        // Same clean score, different amount of evidence ⇒ different confidence.
        let thin = score(
            &consistent_result(),
            &[
                ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Clean),
                ev("proxycheck", Category::Fraud, "proxycheck", Signal::Clean),
                ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Clean),
                ev("barracuda", Category::Blacklist, "barracuda", Signal::Clean),
                ev("spamcop", Category::Blacklist, "spamcop", Signal::Clean),
            ],
            &registry_weights(),
        );
        let thick = score(
            &consistent_result(),
            &full_clean_evidence(),
            &registry_weights(),
        );

        assert!(
            thick.confidence_score > thin.confidence_score,
            "nhiều nguồn hơn ⇒ Confidence cao hơn ({} vs {})",
            thick.confidence_score,
            thin.confidence_score
        );
        assert_eq!(thin.clean_score, thick.clean_score, "Clean Score giống nhau");
    }

    #[test]
    fn network_errors_reduce_confidence() {
        let mut evidence = full_clean_evidence();
        let mut broken = ev("scamalytics", Category::Fraud, "scamalytics", Signal::Unknown);
        broken.error = Some(crate::models::ProviderError::timeout());
        evidence[2] = broken;

        let scored = score(&consistent_result(), &evidence, &registry_weights());
        assert!(
            scored.confidence_score < 100.0,
            "provider timeout phải trừ Confidence (§6.3): {}",
            scored.confidence_score
        );
        assert!(scored.notes.iter().any(|n| n.contains("Unknown")));
    }

    // ------------------------------------------------------------------
    // §6.5 — one clean source among dirty ones never yields "Sạch"
    // ------------------------------------------------------------------
    #[test]
    fn one_clean_source_among_dirty_never_clean() {
        let evidence = vec![
            ev("ipqualityscore", Category::Fraud, "ipqualityscore", Signal::Clean),
            ev("proxycheck", Category::Fraud, "proxycheck", Signal::Bad),
            ev("scamalytics", Category::Fraud, "scamalytics", Signal::Bad),
            ev("spamhaus_zen", Category::Blacklist, "spamhaus", Signal::Bad),
            ev("barracuda", Category::Blacklist, "barracuda", Signal::Bad),
            ev("spamcop", Category::Blacklist, "spamcop", Signal::Suspicious),
            ev("dronebl", Category::Blacklist, "dronebl", Signal::Clean),
            ev("ripestat", Category::Asn, "ripestat", Signal::Clean),
            ev("bgpview", Category::Asn, "bgpview", Signal::Clean),
            ev("abuseipdb", Category::Abuse, "abuseipdb", Signal::Bad),
        ];
        let scored = score(&consistent_result(), &evidence, &registry_weights());
        assert_ne!(scored.verdict, Verdict::Sạch);
        assert_ne!(scored.verdict, Verdict::Tạm);
        assert!(matches!(scored.verdict, Verdict::NghiNgờ | Verdict::Bẩn));
    }

    #[test]
    fn empty_evidence_is_chua_du_du_lieu_without_score() {
        let scored = score(&base_result(), &[], &registry_weights());
        assert_eq!(scored.verdict, Verdict::ChưaĐủDữLiệu);
        assert_eq!(scored.clean_score, None, "không được bịa score");
        assert_eq!(scored.confidence_score, 0.0);
    }

    #[test]
    fn all_unknown_evidence_never_fabricates_a_verdict() {
        let mut evidence = full_clean_evidence();
        for e in evidence.iter_mut() {
            e.signal = Signal::Unknown;
            e.error = Some(crate::models::ProviderError::timeout());
        }
        let scored = score(&base_result(), &evidence, &registry_weights());
        assert_eq!(scored.verdict, Verdict::ChưaĐủDữLiệu);
        assert_eq!(scored.clean_score, None);
    }

    #[test]
    fn placeholder_matches_chua_du_du_lieu_shape() {
        let scored = not_enough_data("thiếu nguồn");
        assert_eq!(scored.verdict, Verdict::ChưaĐủDữLiệu);
        assert_eq!(scored.clean_score, None);
        assert_eq!(scored.breakdown.len(), WEIGHTS.len());
        assert!(scored.quorum.iter().all(|q| !q.met));
    }

    #[test]
    fn expected_votes_counts_groups_not_zones() {
        let expected = expected_votes();
        assert!(expected >= 10, "phải kỳ vọng đủ nguồn: {expected}");
        assert!(expected <= 25, "không được kỳ vọng vô lý: {expected}");
    }

    #[test]
    fn demote_prefers_the_pessimistic_verdict() {
        assert_eq!(demote(Verdict::Sạch, Verdict::NghiNgờ), Verdict::NghiNgờ);
        assert_eq!(demote(Verdict::Bẩn, Verdict::Tạm), Verdict::Bẩn);
        assert_eq!(demote(Verdict::Tạm, Verdict::Sạch), Verdict::Tạm);
    }

    #[test]
    fn consistency_uses_geo_spread_and_timezone() {
        let mut result = base_result();
        result.asn = Some(crate::models::AsnResult {
            consensus: true,
            country_mismatch: false,
            ..Default::default()
        });
        result.location = Some(crate::models::LocationResult {
            spread: "high".to_string(),
            points: vec![
                GeoPoint {
                    timezone: Some("Asia/Singapore".to_string()),
                    ..Default::default()
                },
                GeoPoint {
                    timezone: Some("Asia/Singapore".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let (score_value, votes, note) = consistency_score(&result);
        assert_eq!(score_value, Some(100.0), "mọi thứ khớp ⇒ consistency sạch");
        assert!(votes >= 2);
        assert!(note.contains("ASN"));

        // Divergent timezones must lower the aspect.
        result.location = Some(crate::models::LocationResult {
            spread: "low".to_string(),
            points: vec![
                GeoPoint {
                    timezone: Some("Asia/Singapore".to_string()),
                    ..Default::default()
                },
                GeoPoint {
                    timezone: Some("Asia/Ho_Chi_Minh".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let (score_value, _, _) = consistency_score(&result);
        assert!(score_value.unwrap() < 80.0, "lệch timezone phải bị trừ");
    }

    #[test]
    fn anti_bot_profile_caps_datacenter_and_penalizes_proxy() {
        let dc_flags = crate::models::IpFlags {
            hosting: true,
            proxy: true,
            ..Default::default()
        };
        // Baseline clean score 81.0 (like OVH datacenter proxy 5.196.80.66)
        let capped = apply_anti_bot_profile(81.0, Some(&dc_flags), crate::models::IpType::Datacenter);
        // Cap is 45, minus 15 for proxy = 30.0
        assert_eq!(capped, 30.0, "DC proxy phải bị trảm xuống 30 trong profile anti-bot");

        // Clean residential with no flags should keep its score
        let res_flags = crate::models::IpFlags::default();
        let res_score = apply_anti_bot_profile(95.0, Some(&res_flags), crate::models::IpType::Residential);
        assert_eq!(res_score, 95.0, "Residential sạch giữ nguyên điểm");
    }
}
