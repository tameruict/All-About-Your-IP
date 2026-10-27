//! Export — JSON (§10.3 full result), CSV (§10.3 one line per IP) and the
//! copy-summary text.
//!
//! §13.10 is a hard requirement: **an exported file must never contain an API
//! key or a proxy credential**. Two independent guards enforce it:
//!
//!   * [`scrub_value`] replaces secret-bearing keys with `[redacted]` before the
//!     bytes are written (defence in depth — adapters already strip keys, §4.4);
//!   * [`assert_no_secrets`] re-reads the produced text and returns an error if
//!     anything still looks like a credential, so `export_report` fails loudly
//!     instead of leaking.

use std::path::{Path, PathBuf};

use crate::models::{Category, ExportFormat, FullCheckResult, Signal};

/// CSV columns mandated by §10.3.
pub const CSV_COLUMNS: [&str; 12] = [
    "ip",
    "verdict",
    "clean_score",
    "confidence",
    "country",
    "city",
    "asn",
    "isp",
    "ip_type",
    "fraud_signals",
    "blacklist_listed_count",
    "checked_at",
];

/// Prefix markers that must never appear as a **value** in an exported artefact.
///
/// Deliberately conservative about *values*, not about key names: a JSON report
/// legitimately contains the literal text `"api_key": "[redacted]"` — the key
/// name is schema documentation, the value is the secret. Flagging the key name
/// would make every honest export fail, which is why [`assert_no_secrets_text`]
/// only inspects the payload after [`scrub_value`] has already emptied it.
///
/// ### Why each marker carries a minimum tail length
///
/// A bare prefix such as `"sk-"` is only three characters, and honest data
/// contains it: a hostname like `task-node.example`, a registrar called
/// `Malakia Hosting`, an ISP named `K-SK Telecom`. Matching the prefix alone
/// cancelled the export of a perfectly clean report and told the user their
/// report "contains a secret" — a §13.10 guard that fires on non-secrets is
/// worse than useless, because the user cannot act on it. Each marker therefore
/// declares the shortest tail that a *real* credential of that shape always has:
///
/// | marker | tail | why that number |
/// |---|---|---|
/// | `sk-`  | ≥ 20 alphanumerics | OpenAI keys are `sk-` + 48 chars, Anthropic `sk-ant-` + 95. 20 is a safe floor. |
/// | `akia` | ≥ 16 alphanumerics **and ≤ 20 total** | AWS access-key ids are exactly `AKIA` + 16 uppercase chars. |
/// | `ghp_` | ≥ 30 alphanumerics | GitHub PATs are `ghp_` + 36 chars. |
///
/// The structural markers (`user:pass@`, `://user:`, `://<user>:<pass>@`) have
/// no realistic false positive — no honest report contains a URL userinfo
/// section — so they keep matching as plain substrings.
pub const SECRET_MARKER_PREFIXES: [&str; 3] = [
    "sk-",  // OpenAI / Anthropic style secret key prefix
    "akia", // AWS access-key id prefix
    "ghp_", // GitHub personal access token prefix
];

/// Structural signatures that are secret by shape, not by length.
pub const SECRET_MARKERS_STRUCTURAL: [&str; 3] = [
    "user:pass@",
    "://user:",
    "://<user>:<pass>@",
];

/// Minimum number of alphanumerics that must follow each prefix in
/// [`SECRET_MARKER_PREFIXES`] for the match to count as a real credential.
pub const SECRET_MARKER_MIN_TAIL: [(&str, usize, Option<usize>); 3] = [
    ("sk-", 20, None),
    ("akia", 16, Some(20)), // AWS ids are fixed-length: `AKIA` + 16
    ("ghp_", 30, None),
];

/// JSON keys that hold secrets and are replaced by [`scrub_value`].
///
/// This is the **single** list for the whole crate. `cache.rs` used to keep its
/// own copy and the two drifted: the export list lacked `user`/`username`, the
/// cache list lacked `passwd`/`api-key`/`credentials`. Two security lists that
/// each miss something different is a bug no single-file review can catch, so
/// there is now one `pub const` and one [`is_secret_key`] predicate.
pub const SECRET_KEYS: [&str; 15] = [
    "key",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "auth",
    "authorization",
    "password",
    "pass",
    "passwd",
    "secret",
    "credential",
    "credentials",
    // Fraud/abuse upstreams return the *offender's* account name; proxy
    // credentials never reach `FullCheckResult` (see `ProxyCredentials`), but
    // an account name is still personal data worth not writing to disk.
    "user",
    "username",
];

/// Length of the key-shaped run starting at `from`: alphanumerics **and** the
/// `-` / `_` separators real keys use.
///
/// Anthropic keys look like `sk-ant-api03-<95 chars>`, GitHub's like
/// `ghp_<36>`. Counting only `is_ascii_alphanumeric` stopped at the first `-`
/// and measured `sk-ant-…` as a 3-character tail, so a genuine Anthropic key
/// slipped past the guard — the threshold was right, the run was wrong.
fn key_run(text: &str, from: usize) -> usize {
    text[from.min(text.len())..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .count()
}

/// Does `haystack` (already lower-cased) contain a marker that is really a
/// credential?
///
/// Structural markers match as substrings; prefix markers must be followed by a
/// tail long enough to be a real key (see [`SECRET_MARKER_MIN_TAIL`]).
pub fn find_secret_marker(haystack: &str) -> Option<&'static str> {
    for marker in SECRET_MARKERS_STRUCTURAL {
        if haystack.contains(marker) {
            return Some(marker);
        }
    }
    for (prefix, min_tail, max_total) in SECRET_MARKER_MIN_TAIL {
        let mut search = 0usize;
        while let Some(found) = haystack[search..].find(prefix) {
            let start = search + found;
            let tail = key_run(haystack, start + prefix.len());
            let long_enough = tail >= min_tail;
            let short_enough = max_total.map(|cap| prefix.len() + tail <= cap).unwrap_or(true);
            if long_enough && short_enough {
                return Some(prefix);
            }
            search = start + prefix.len();
        }
    }
    None
}

/// Build the CSV header line.
pub fn csv_header() -> String {
    CSV_COLUMNS.join(",")
}

/// Serialise one result as a CSV row (RFC-4180 quoting).
pub fn to_csv_row(result: &FullCheckResult) -> String {
    let country = result
        .location
        .as_ref()
        .and_then(|l| l.country.clone())
        .unwrap_or_default();
    let city = result
        .location
        .as_ref()
        .and_then(|l| l.city.clone())
        .unwrap_or_default();
    let asn = result
        .asn
        .as_ref()
        .and_then(|a| a.asn.map(|n| format!("AS{n}")))
        .unwrap_or_default();
    let isp = result
        .asn
        .as_ref()
        .and_then(|a| a.isp.clone())
        .unwrap_or_default();
    let ip_type = result
        .asn
        .as_ref()
        .map(|a| format!("{:?}", a.ip_type).to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

    // §10.3 "fraud signals" — how many fraud sources answered non-Unknown, plus
    // how many of those said suspicious/bad (so the column is actionable).
    let fraud_signals = match result.scoring.as_ref() {
        Some(scoring) => scoring
            .breakdown
            .iter()
            .find(|b| b.aspect == "fraud")
            .map(|b| b.votes)
            .unwrap_or(0),
        None => result
            .evidence
            .iter()
            .filter(|e| e.category == Category::Fraud && e.signal != Signal::Unknown)
            .count() as u32,
    };

    let blacklist_listed = result
        .dnsbl
        .as_ref()
        .map(|d| d.total_listed)
        .or_else(|| {
            // Fall back to the scoring aspect when the DNSBL block was reloaded
            // from SQLite (it is not part of §10.1).
            result.scoring.as_ref().and_then(|s| {
                s.breakdown
                    .iter()
                    .find(|b| b.aspect == "blacklist")
                    .map(|b| b.votes)
            })
        })
        .unwrap_or(0);

    let fields = vec![
        result.ip.clone(),
        result.verdict.as_str().to_string(),
        result
            .clean_score
            .map(|s| format!("{s:.0}"))
            .unwrap_or_default(),
        format!("{:.0}", result.confidence_score),
        country,
        city,
        asn,
        isp,
        ip_type,
        fraud_signals.to_string(),
        blacklist_listed.to_string(),
        result.checked_at.clone(),
    ];

    fields
        .into_iter()
        .map(|f| csv_escape(&f))
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Target file path for an export (§10.3).
pub fn target_path(export_dir: &Path, check_id: &str, format: ExportFormat) -> PathBuf {
    let ext = match format {
        ExportFormat::Json => "json",
        ExportFormat::Csv => "csv",
    };
    export_dir.join(format!("ip-checker-{check_id}.{ext}"))
}

/// Recursively redact secret-looking keys in a JSON value before export.
pub fn scrub_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_secret_key(k) {
                    out.insert(
                        k.clone(),
                        serde_json::Value::String(REDACTED.to_string()),
                    );
                } else {
                    out.insert(k.clone(), scrub_value(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(scrub_value).collect())
        }
        other => other.clone(),
    }
}

/// A clone of the result with every provider payload scrubbed.
fn scrubbed_result(result: &FullCheckResult) -> FullCheckResult {
    let mut clean = result.clone();
    for evidence in clean.evidence.iter_mut() {
        if let Some(raw) = evidence.raw.as_ref() {
            evidence.raw = Some(scrub_value(raw));
        }
    }
    clean
}

/// Render the export body (JSON or CSV) for a result.
pub fn render(result: &FullCheckResult, format: ExportFormat) -> Result<String, String> {
    let clean = scrubbed_result(result);
    let body = match format {
        ExportFormat::Json => serde_json::to_string_pretty(&clean)
            .map_err(|e| format!("Không serialize được JSON: {e}"))?,
        ExportFormat::Csv => format!("{}\n{}\n", csv_header(), to_csv_row(&clean)),
    };
    // §13.10 — fail the export rather than write a leaking file.
    assert_no_secrets_text(&body)?;
    Ok(body)
}

/// Write the report and return the absolute path written (§4.2 contract).
pub fn write(
    result: &FullCheckResult,
    export_dir: &Path,
    format: ExportFormat,
) -> std::io::Result<String> {
    std::fs::create_dir_all(export_dir)?;
    let path = target_path(export_dir, &result.check_id, format);
    let body = render(result, format)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, body)?;
    Ok(path.to_string_lossy().to_string())
}

/// Verify that a rendered report carries no credential (§13.10).
///
/// Two layers, in this order:
///
/// 1. **Structural** — parse the JSON (or read the CSV cells) and look for any
///    object member whose *name* is a secret key but whose *value* is a
///    non-empty string other than `[redacted]`. This is the real check: it
///    catches `{"api_key": "abc123"}` while allowing `{"api_key":
///    "[redacted]"}`.
/// 2. **Textual** — reject payload signatures that no honest report contains
///    (`user:pass@`, `sk-…`, `ghp_…`, `AKIA…`).
pub fn assert_no_secrets_text(text: &str) -> Result<(), String> {
    // ---- 1. structural pass ----
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(path) = find_live_secret(&value, "$") {
            return Err(format!(
                "Báo cáo chứa giá trị bí mật chưa che tại {path} — huỷ xuất file (§13.10)"
            ));
        }
    }

    // ---- 2. textual pass ----
    let lower = text.to_ascii_lowercase();
    if let Some(marker) = find_secret_marker(&lower) {
        return Err(format!(
            "Báo cáo chứa chuỗi nghi là bí mật ({marker}) — huỷ xuất file (§13.10)"
        ));
    }
    Ok(())
}

/// Redaction marker written by [`scrub_value`].
pub const REDACTED: &str = "[redacted]";

/// Walk a JSON value and return the path of the first live secret, if any.
///
/// "Live" means a secret-named key whose value is a non-empty string that is
/// not already [`REDACTED`]. Numbers and booleans are ignored: no API key is
/// stored as a JSON number, and flagging them would produce false positives on
/// fields like `"has_key": true`.
fn find_live_secret(value: &serde_json::Value, path: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if is_secret_key(key) {
                    match child {
                        serde_json::Value::String(s) if !s.trim().is_empty() && s != REDACTED => {
                            return Some(child_path);
                        }
                        serde_json::Value::Array(items) if !items.is_empty() => {
                            return Some(child_path);
                        }
                        serde_json::Value::Object(inner) if !inner.is_empty() => {
                            return Some(child_path);
                        }
                        _ => {}
                    }
                }
                if let Some(found) = find_live_secret(child, &child_path) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, child)| find_live_secret(child, &format!("{path}[{i}]"))),
        _ => None,
    }
}

/// Is this JSON key name one that may only ever hold a secret?
///
/// The one predicate the whole crate uses — `cache.rs` scrubs its provider
/// payloads with [`scrub_value`] rather than keeping a second list.
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS
        .iter()
        .any(|s| lower == *s || lower.ends_with(&format!("_{s}")))
}

/// Verify that a result carries no credential before it is exported.
pub fn assert_no_secrets(result: &FullCheckResult) -> Result<(), String> {
    let json = serde_json::to_string(result)
        .map_err(|e| format!("Không kiểm tra được bí mật: {e}"))?;
    assert_no_secrets_text(&json)
}

/// Short summary text for the "Copy báo cáo tóm tắt" button (§10.3).
///
/// Includes verdict, score, country/city, ASN, the main reason and the primary
/// evidence links, so it can be pasted into a chat and still be traceable (§15.4).
pub fn summary_text(result: &FullCheckResult) -> String {
    let country = result
        .location
        .as_ref()
        .and_then(|l| l.country.clone())
        .unwrap_or_else(|| "?".to_string());
    let city = result
        .location
        .as_ref()
        .and_then(|l| l.city.clone())
        .unwrap_or_else(|| "?".to_string());
    let asn = result
        .asn
        .as_ref()
        .and_then(|a| a.asn.map(|n| format!("AS{n}")))
        .unwrap_or_else(|| "?".to_string());
    let isp = result
        .asn
        .as_ref()
        .and_then(|a| a.isp.clone())
        .unwrap_or_else(|| "?".to_string());

    let mut lines = vec![
        format!(
            "IP {ip} — {verdict} (Clean {clean}, Confidence {conf})",
            ip = result.ip,
            verdict = result.verdict.as_str(),
            clean = result
                .clean_score
                .map(|s| {
                    if result.clean_score_provisional {
                        format!("{s:.0} [tạm tính]")
                    } else {
                        format!("{s:.0}")
                    }
                })
                .unwrap_or_else(|| "—".to_string()),
            conf = format!("{:.0}%", result.confidence_score),
        ),
        format!("Vị trí: {city}, {country} | {asn} {isp}"),
        format!("Lý do: {}", result.verdict_reason),
    ];

    if let Some(dnsbl) = result.dnsbl.as_ref() {
        let listed: Vec<String> = dnsbl
            .groups
            .iter()
            .filter(|g| g.listed > 0)
            .map(|g| format!("{} ({})", g.label, g.listed))
            .collect();
        if !listed.is_empty() {
            lines.push(format!("Blacklist: {}", listed.join(", ")));
        }
    }

    // Primary evidence links — at most five, so the paste stays readable.
    let links: Vec<String> = result
        .evidence
        .iter()
        .filter(|e| e.signal != Signal::Clean && e.signal != Signal::Unknown)
        .filter(|e| !e.source_url.is_empty())
        .take(5)
        .map(|e| format!("{} {:?} → {}", e.provider, e.signal, e.source_url))
        .collect();
    if !links.is_empty() {
        lines.push(format!("Bằng chứng chính:\n  {}", links.join("\n  ")));
    }

    if result.from_cache {
        lines.push(format!(
            "(kết quả cũ từ cache, check lúc {})",
            result.checked_at
        ));
    } else {
        lines.push(format!("Check lúc: {}", result.checked_at));
    }

    let mut text = lines.join("\n");
    // The summary is pasted into chats — scrub it too, just in case.
    if assert_no_secrets_text(&text).is_err() {
        text = text
            .lines()
            .filter(|line| assert_no_secrets_text(line).is_ok())
            .collect::<Vec<_>>()
            .join("\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AsnResult, Category, DnsblGroupResult, DnsblResult, LocationResult, ProviderEvidence,
        Signal, Verdict,
    };

    fn sample() -> FullCheckResult {
        let mut result = FullCheckResult::short_circuit(
            "check-1".to_string(),
            "8.8.8.8".to_string(),
            "Đủ quorum".to_string(),
        );
        result.validation_error = None;
        result.clean_score = Some(82.0);
        result.confidence_score = 91.0;
        result.verdict = Verdict::Tạm;
        result.verdict_reason = "Dính 1 DNSBL cộng đồng".to_string();
        result.checked_at = "2026-10-25T11:30:00+07:00".to_string();
        result.location = Some(LocationResult {
            country: Some("United States".to_string()),
            city: Some("Mountain View".to_string()),
            ..Default::default()
        });
        result.asn = Some(AsnResult {
            asn: Some(15169),
            isp: Some("Google LLC".to_string()),
            ..Default::default()
        });
        result.dnsbl = Some(DnsblResult {
            groups: vec![DnsblGroupResult {
                group: crate::models::DnsblGroup::Community,
                label: "Cộng đồng".to_string(),
                checked: 3,
                listed: 1,
                signal: Signal::Suspicious,
                answered: true,
                entries: Vec::new(),
            }],
            total_listed: 1,
            groups_answered: 3,
            hard_hit: false,
            notes: Vec::new(),
        });
        result.evidence = vec![ProviderEvidence {
            provider: "ipqualityscore".to_string(),
            category: Category::Fraud,
            upstream: "ipqualityscore".to_string(),
            signal: Signal::Bad,
            raw_score: Some(88.0),
            raw: Some(serde_json::json!({
                "fraud_score": 88,
                "api_key": "SUPER-SECRET-KEY",
                "token": "another-secret"
            })),
            checked_at: "2026-10-25T11:30:00+07:00".to_string(),
            source_url: "https://www.ipqualityscore.com/".to_string(),
            latency_ms: Some(210),
            error: None,
            reason: None,
            from_cache: false,
        }];
        result
    }

    #[test]
    fn csv_header_matches_spec_columns() {
        assert_eq!(CSV_COLUMNS.len(), 12);
        assert_eq!(
            csv_header(),
            "ip,verdict,clean_score,confidence,country,city,asn,isp,ip_type,fraud_signals,blacklist_listed_count,checked_at"
        );
    }

    #[test]
    fn csv_row_has_one_field_per_column() {
        let row = to_csv_row(&sample());
        // No embedded commas/newlines in this sample, so a naive split works.
        assert_eq!(row.split(',').count(), CSV_COLUMNS.len(), "row = {row}");
        assert!(row.starts_with("8.8.8.8,"));
        assert!(row.contains("Tạm"));
        assert!(row.contains("82"));
        assert!(row.contains("AS15169"));
        assert!(row.contains("Google LLC"));
        assert!(row.contains("Mountain View"));
        assert!(row.ends_with("2026-10-25T11:30:00+07:00"));
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        let mut result = sample();
        result.asn = Some(AsnResult {
            asn: Some(1),
            isp: Some("Evil, \"Quoted\" ISP".to_string()),
            ..Default::default()
        });
        let row = to_csv_row(&result);
        assert!(row.contains("\"Evil, \"\"Quoted\"\" ISP\""), "row = {row}");
    }

    #[test]
    fn json_export_redacts_api_key() {
        let json = render(&sample(), ExportFormat::Json).expect("xuất JSON được");
        assert!(
            !json.contains("SUPER-SECRET-KEY"),
            "§13.10: key không được có trong file xuất"
        );
        assert!(!json.contains("another-secret"));
        assert!(json.contains("[redacted]"));
        // Non-secret data survives.
        assert!(json.contains("fraud_score"));
    }

    #[test]
    fn csv_export_never_contains_raw_payload() {
        // CSV only carries the §10.3 columns, so no provider payload at all.
        let csv = render(&sample(), ExportFormat::Csv).unwrap();
        assert!(!csv.contains("SUPER-SECRET-KEY"));
        assert!(!csv.contains("api_key"));
        assert!(csv.contains("8.8.8.8"));
    }

    #[test]
    fn assert_no_secrets_rejects_a_real_key_blob() {
        // Raw provider payload that a careless adapter might forward.
        let bad = r#"{"data":{"api_key":"abcdef123456"}}"#;
        assert!(
            assert_no_secrets_text(bad).is_err(),
            "§13.10: giá trị api_key chưa che phải bị chặn"
        );

        // A redacted key name is legitimate schema — must NOT be rejected.
        let ok = r#"{"data":{"api_key":"[redacted]"}}"#;
        assert!(
            assert_no_secrets_text(ok).is_ok(),
            "key đã che thì báo cáo hợp lệ, không được chặn oan: {:?}",
            assert_no_secrets_text(ok)
        );

        let mut result = sample();
        // Simulate an adapter that forgot to strip the key.
        result.evidence[0].raw = Some(serde_json::json!({"password": "hunter2"}));
        // The raw result is rejected…
        assert!(assert_no_secrets(&result).is_err());
        // …but the export path scrubs it before writing.
        let json = render(&result, ExportFormat::Json).unwrap();
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn assert_no_secrets_allows_secret_key_names_once_redacted() {
        // Regression: the first version of the scanner searched the whole text
        // for `"api_key"`, so every honest export failed because the *name*
        // appeared in the schema. Only live values may trip the check.
        let json = render(&sample(), ExportFormat::Json).expect("xuất JSON phải thành công");
        assert!(json.contains("\"api_key\""), "tên field vẫn còn (schema)");
        assert!(json.contains(REDACTED), "giá trị đã bị che");
        assert!(assert_no_secrets_text(&json).is_ok());
    }

    #[test]
    fn assert_no_secrets_rejects_proxy_credentials() {
        assert!(assert_no_secrets_text("proxy http://user:pass@1.2.3.4:8080").is_err());
        assert!(assert_no_secrets_text(r#"{"proxy_pass":"x"}"#).is_err());
        assert!(assert_no_secrets_text("clean report about 8.8.8.8").is_ok());
    }

    #[test]
    fn export_path_is_inside_export_dir() {
        let dir = PathBuf::from("C:\\tmp\\ip");
        let path = target_path(&dir, "abc-123", ExportFormat::Json);
        assert_eq!(path.file_name().unwrap(), "ip-checker-abc-123.json");
        assert_eq!(path.parent().unwrap(), dir.as_path());

        let csv = target_path(&dir, "abc-123", ExportFormat::Csv);
        assert_eq!(csv.file_name().unwrap(), "ip-checker-abc-123.csv");
    }

    #[test]
    fn write_creates_readable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&sample(), dir.path(), ExportFormat::Json).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("8.8.8.8"));
        assert!(!text.contains("SUPER-SECRET-KEY"));
    }

    #[test]
    fn summary_contains_verdict_score_geo_and_reason() {
        let text = summary_text(&sample());
        assert!(text.contains("8.8.8.8"));
        assert!(text.contains("Tạm"));
        assert!(text.contains("82"));
        assert!(text.contains("91%"));
        assert!(text.contains("Mountain View"));
        assert!(text.contains("United States"));
        assert!(text.contains("AS15169"));
        assert!(text.contains("Dính 1 DNSBL cộng đồng"));
        assert!(text.contains("ipqualityscore"));
        assert!(text.contains("https://www.ipqualityscore.com/"));
    }

    #[test]
    fn summary_marks_cached_results() {
        let mut result = sample();
        result.from_cache = true;
        let text = summary_text(&result);
        assert!(
            text.contains("từ cache"),
            "§3.4: phải ghi rõ là kết quả cũ: {text}"
        );
        assert!(text.contains("2026-10-25T11:30:00+07:00"));
    }

    #[test]
    fn summary_lists_blacklist_groups() {
        let text = summary_text(&sample());
        assert!(text.contains("Blacklist:"));
        assert!(text.contains("Cộng đồng"));
    }

    #[test]
    fn json_export_round_trips_through_serde() {
        let json = render(&sample(), ExportFormat::Json).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ip"], "8.8.8.8");
        assert_eq!(parsed["verdict"], "Tạm");
        assert_eq!(parsed["clean_score"], 82.0);
    }

    // -----------------------------------------------------------------------
    // §13.10 marker thresholds
    //
    // A bare prefix is three or four characters, and honest data contains them:
    // a hostname `task-node.example`, a registrar `Malakia Hosting`, an ISP
    // `K-SK Telecom`. Matching the prefix alone cancelled the export of a clean
    // report and told the user their report "contains a secret". These tests pin
    // *both* directions: the false positive must be gone **and** the real key
    // must still be caught. Without the second half, "fix the false positive"
    // becomes "turn off the guard".
    // -----------------------------------------------------------------------

    #[test]
    fn isp_containing_sk_prefix_does_not_block_export() {
        // "K-SK Telecom" contains "sk-" but is not a key.
        assert!(assert_no_secrets_text("ISP: K-SK Telecom").is_ok());
        assert!(assert_no_secrets_text("host: task-node.example").is_ok());
        assert!(assert_no_secrets_text("host: k-sk-01.example").is_ok());
    }

    #[test]
    fn malakia_hosting_is_not_an_aws_key() {
        assert!(assert_no_secrets_text("REGISTRAR: Malakia Hosting Ltd").is_ok());
        assert!(assert_no_secrets_text("REGISTRAR: Prakia Networks").is_ok());
    }

    #[test]
    fn real_aws_key_still_blocks_export() {
        // AWS Access Key ID is exactly AKIA + 16 upper-alnum = 20 chars total.
        let key = format!("AKIA{}", "A1B2C3D4E5F6G7H8");
        assert_eq!(key.len(), 20);
        assert!(
            assert_no_secrets_text(&key).is_err(),
            "a real 20-char AWS id must not slip through"
        );
    }

    #[test]
    fn real_openai_key_still_blocks_export() {
        let key = format!("sk-{}", "a".repeat(48));
        assert!(
            assert_no_secrets_text(&key).is_err(),
            "a real OpenAI-style key must not slip through"
        );
        let ant = format!("sk-ant-{}", "b".repeat(95));
        assert!(assert_no_secrets_text(&ant).is_err());
    }

    #[test]
    fn real_github_pat_still_blocks_export() {
        let pat = format!("ghp_{}", "c".repeat(36));
        assert!(
            assert_no_secrets_text(&pat).is_err(),
            "a real GitHub PAT must not slip through"
        );
    }

    #[test]
    fn structural_url_credentials_still_block_export() {
        // These have no realistic false positive, so they keep matching as
        // plain substrings with no length threshold.
        assert!(assert_no_secrets_text("proxy http://user:pass@1.2.3.4:8080").is_err());
        assert!(assert_no_secrets_text("http://user:pw@host").is_err());
    }

    #[test]
    fn secret_key_union_covers_both_old_lists() {
        // cache.rs used to carry its own SECRET_KEYS; if the union regresses,
        // a key that one side scrubbed would leak through the other side.
        for key in [
            "key",
            "api_key",
            "apikey",
            "api-key",
            "token",
            "auth",
            "authorization",
            "password",
            "pass",
            "passwd",
            "secret",
            "credential",
            "credentials",
            // These two were only in the cache list before the union.
            "user",
            "username",
        ] {
            assert!(is_secret_key(key), "{key} must be scrubbed");
        }
        // Nested keys keep the `_suffix` behaviour.
        assert!(is_secret_key("provider_api_key"));
        assert!(is_secret_key("PROXY_PASSWORD"));
        assert!(!is_secret_key("isp"));
    }

    #[test]
    fn scrub_value_redacts_every_union_key_and_keeps_honest_fields() {
        let payload = serde_json::json!({
            "isp": "K-SK Telecom",
            "api_key": "abc123",
            "user": "offender@example",
            "username": "offender",
            "passwd": "hunter2",
            "provider_api_key": "abc123",
            "country": "VN"
        });
        let clean = scrub_value(&payload);
        assert_eq!(clean["api_key"], REDACTED);
        assert_eq!(clean["user"], REDACTED);
        assert_eq!(clean["username"], REDACTED);
        assert_eq!(clean["passwd"], REDACTED);
        assert_eq!(clean["provider_api_key"], REDACTED);
        assert_eq!(clean["isp"], "K-SK Telecom");
        assert_eq!(clean["country"], "VN");
    }
}
