//! SQLite cache + history (§10.1, §10.2).
//!
//! The schema is exactly §10.1. Every value that could identify the user's
//! proxy credentials is deliberately absent (§8.4, §10.1): a row stores proxy
//! host/port/protocol only — never username/password.
//!
//! Two responsibilities:
//!   * **history** — append-only log of every check, read newest-first.
//!   * **cache** — a *reuse* check over the same IP, honouring the TTL table
//!     from §10.2. A cache hit keeps the ORIGINAL `checked_at`; it is never
//!     rewritten to "now" (§3.4: "kết quả cũ từ cache phải ghi rõ thời gian").

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};

use crate::models::{
    CheckMode, CheckSummary, Category, DnsblResult, FullCheckResult, ProviderEvidence,
    ProxyProtocol, Signal, Verdict,
};

/// Schema from §10.1 — executed with `CREATE TABLE IF NOT EXISTS`.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  mode TEXT NOT NULL,
  proxy_host TEXT,
  proxy_port INTEGER,
  proxy_protocol TEXT,
  clean_score INTEGER,
  confidence_score INTEGER,
  verdict TEXT,
  verdict_reason TEXT,
  checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  category TEXT NOT NULL,
  upstream TEXT NOT NULL,
  signal TEXT NOT NULL,
  raw_score REAL,
  raw_json TEXT,
  source_url TEXT,
  checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS geo_db_versions (
  db_name TEXT PRIMARY KEY,
  version TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE INDEX IF NOT EXISTS idx_checks_checked_at ON checks (checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_checks_ip ON checks (ip, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_results_check ON provider_results (check_id);
"#;

/// §10.2 TTL defaults, in hours. Overridable through [`Settings`].
///
/// `crate::models::Settings` carries the same numbers; these constants are the
/// fallback when a caller has no settings at hand (and are what the unit tests
/// assert against).
pub const TTL_GEO_HOURS: u32 = 24 * 7; // 7 ngày — geo ít đổi
pub const TTL_REPUTATION_HOURS: u32 = 24; // fraud
pub const TTL_BLACKLIST_HOURS: u32 = 12; // 6–12 giờ
pub const TTL_ABUSE_HOURS: u32 = 24;
/// Leak / speed are NEVER cached (§10.2).
pub const TTL_NEVER: u32 = 0;

/// TTL bucket for a cached category (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlClass {
    Geo,
    Reputation,
    Blacklist,
    Abuse,
    Never,
}

impl TtlClass {
    /// Map a provider category onto its §10.2 TTL bucket.
    pub fn for_category(category: Category) -> Self {
        match category {
            Category::Geo | Category::LocalDb => TtlClass::Geo,
            Category::Asn => TtlClass::Geo,
            Category::Fraud => TtlClass::Reputation,
            Category::Blacklist => TtlClass::Blacklist,
            Category::Abuse | Category::ThreatIntel => TtlClass::Abuse,
            Category::Leak | Category::Speed => TtlClass::Never,
            Category::Network => TtlClass::Reputation,
        }
    }

    /// Default hours for this bucket.
    pub fn default_hours(self) -> u32 {
        match self {
            TtlClass::Geo => TTL_GEO_HOURS,
            TtlClass::Reputation => TTL_REPUTATION_HOURS,
            TtlClass::Blacklist => TTL_BLACKLIST_HOURS,
            TtlClass::Abuse => TTL_ABUSE_HOURS,
            TtlClass::Never => TTL_NEVER,
        }
    }
}

/// Thin wrapper around the single local DB file.
pub struct Cache {
    conn: Connection,
    path: PathBuf,
}

impl Cache {
    /// Open (or create) the DB at `path`, creating the parent directory.
    pub fn open(path: &Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// In-memory instance used by tests.
    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn,
            path: PathBuf::from(":memory:"),
        })
    }

    /// DB file location.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the raw connection (settings/config use it for the `settings` table).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Default DB path: `%APPDATA%/ip-checker/app.db` (§2.1).
    pub fn default_path() -> PathBuf {
        dirs::data_dir()
            .map(|d| d.join("ip-checker").join("app.db"))
            .unwrap_or_else(|| PathBuf::from("app.db"))
    }

    /// Row count of `checks` — cheap smoke check.
    pub fn count_checks(&self) -> SqlResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM checks", [], |r| r.get(0))
    }

    // -----------------------------------------------------------------
    // Write path
    // -----------------------------------------------------------------

    /// Persist one completed check: the `checks` row plus every provider vote.
    ///
    /// Nothing from `result` that could carry a secret is written: proxy
    /// credentials are not part of [`FullCheckResult`] and API keys never enter
    /// [`ProviderEvidence::raw`] (adapters strip them, §4.4). As a second line
    /// of defence [`scrub_secrets`] runs over `raw` before the insert.
    pub fn save_check(&mut self, result: &FullCheckResult) -> SqlResult<()> {
        let tx = self.conn.transaction()?;

        let mode = match result.mode {
            CheckMode::IpOnly => "ip_only",
            CheckMode::Proxy => "proxy",
            CheckMode::Unknown => "unknown",
        };
        let protocol = result.proxy_protocol.map(protocol_str);

        tx.execute(
            "INSERT OR REPLACE INTO checks
               (id, ip, mode, proxy_host, proxy_port, proxy_protocol,
                clean_score, confidence_score, verdict, verdict_reason, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                result.check_id,
                result.ip,
                mode,
                result.proxy_host,
                result.proxy_port.map(|p| p as i64),
                protocol,
                result.clean_score.map(|s| s.round() as i64),
                result.confidence_score.round() as i64,
                result.verdict.as_str(),
                result.verdict_reason,
                result.checked_at,
            ],
        )?;

        // Replace any previous votes for this exact check_id (idempotent re-save).
        tx.execute(
            "DELETE FROM provider_results WHERE check_id = ?1",
            params![result.check_id],
        )?;

        for ev in &result.evidence {
            let raw_json = ev
                .raw
                .as_ref()
                .map(|v| serde_json::to_string(&crate::export::scrub_value(v)).unwrap_or_default());
            tx.execute(
                "INSERT INTO provider_results
                   (check_id, provider, category, upstream, signal,
                    raw_score, raw_json, source_url, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    result.check_id,
                    ev.provider,
                    category_str(ev.category),
                    ev.upstream,
                    signal_str(ev.signal),
                    ev.raw_score,
                    raw_json,
                    ev.source_url,
                    ev.checked_at,
                ],
            )?;
        }

        tx.commit()
    }

    /// Record a local geo-DB version (§10.1 `geo_db_versions`).
    pub fn upsert_geo_db(&self, db_name: &str, version: &str, updated_at: &str) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO geo_db_versions (db_name, version, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(db_name) DO UPDATE SET version = ?2, updated_at = ?3",
            params![db_name, version, updated_at],
        )?;
        Ok(())
    }

    /// Read every known local geo-DB version, oldest DB first.
    pub fn geo_db_versions(&self) -> SqlResult<Vec<(String, Option<String>, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT db_name, version, updated_at FROM geo_db_versions ORDER BY db_name")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    // -----------------------------------------------------------------
    // Read path — history (§4.2 get_history)
    // -----------------------------------------------------------------

    /// §4.2 `get_history`: newest first, at most `limit` rows.
    pub fn history(&self, limit: u32) -> Vec<CheckSummary> {
        match self.try_history(limit) {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!("get_history thất bại: {err}");
                Vec::new()
            }
        }
    }

    /// Fallible variant so commands can surface a real error to the UI.
    pub fn try_history(&self, limit: u32) -> SqlResult<Vec<CheckSummary>> {
        let limit = limit.clamp(1, 500) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, mode, proxy_host, proxy_port, proxy_protocol,
                    clean_score, confidence_score, verdict, verdict_reason, checked_at
             FROM checks
             ORDER BY checked_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |r| {
            let mode_raw: String = r.get(2)?;
            let protocol_raw: Option<String> = r.get(5)?;
            let verdict_raw: Option<String> = r.get(8)?;
            Ok(CheckSummary {
                check_id: r.get(0)?,
                ip: r.get(1)?,
                mode: mode_from_str(&mode_raw),
                proxy_host: r.get(3)?,
                proxy_port: r.get::<_, Option<i64>>(4)?.map(|p| p as u16),
                proxy_protocol: protocol_raw.as_deref().and_then(protocol_from_str),
                clean_score: r.get::<_, Option<i64>>(6)?.map(|s| s as f64),
                confidence_score: r.get::<_, Option<i64>>(7)?.map(|s| s as f64),
                verdict: verdict_raw.as_deref().and_then(verdict_from_str),
                verdict_reason: r.get(9)?,
                checked_at: r.get(10)?,
            })
        })?;

        rows.collect()
    }

    /// §4.2 `get_check_detail`: rebuild the stored part of a result.
    ///
    /// The heavy per-module payloads (location, dnsbl, network, leak, speed)
    /// are not part of §10.1, so a re-loaded detail carries `checks` +
    /// `provider_results` + score/verdict and is flagged `from_cache = true`
    /// with its ORIGINAL `checked_at`. It is never presented as a fresh check.
    pub fn load_check(&self, check_id: &str) -> SqlResult<Option<FullCheckResult>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, ip, mode, proxy_host, proxy_port, proxy_protocol,
                        clean_score, confidence_score, verdict, verdict_reason, checked_at
                 FROM checks WHERE id = ?1",
                params![check_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, Option<i64>>(7)?,
                        r.get::<_, Option<String>>(8)?,
                        r.get::<_, Option<String>>(9)?,
                        r.get::<_, String>(10)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            id,
            ip,
            mode,
            proxy_host,
            proxy_port,
            proxy_protocol,
            clean_score,
            confidence_score,
            verdict,
            verdict_reason,
            checked_at,
        )) = row
        else {
            return Ok(None);
        };

        let mut result = FullCheckResult::short_circuit(
            id.clone(),
            ip,
            verdict_reason.clone().unwrap_or_default(),
        );
        result.validation_error = None;
        result.mode = mode_from_str(&mode);
        result.proxy_host = proxy_host;
        result.proxy_port = proxy_port.map(|p| p as u16);
        result.proxy_protocol = proxy_protocol.as_deref().and_then(protocol_from_str);
        result.clean_score = clean_score.map(|s| s as f64);
        result.confidence_score = confidence_score.unwrap_or(0) as f64;
        result.verdict = verdict.as_deref().and_then(verdict_from_str).unwrap_or_default();
        result.clean_score_provisional = result.verdict.is_inconclusive() && result.clean_score.is_some();
        result.verdict_reason = verdict_reason.unwrap_or_default();
        result.checked_at = checked_at;
        result.from_cache = true;
        // A failed evidence read must not look like "this check had no votes":
        // the panel would show an empty evidence table while the score above it
        // still claims three sources agreed. Say what happened instead.
        match self.load_evidence(&id) {
            Ok(evidence) => {
                result.evidence = evidence;
                crate::orchestrator::hydrate_cached_result(&mut result);
            }
            Err(err) => {
                // `FullCheckResult` has no free-form note field (§2.3 is a
                // fixed contract), so the failure is written to the reason the
                // user actually reads, and logged for support.
                tracing::warn!("load_evidence({id}) thất bại: {err}");
                result.evidence = Vec::new();
                result.verdict_reason = format!(
                    "{} (không đọc được bằng chứng đã lưu: {err})",
                    result.verdict_reason
                );
            }
        }

        Ok(Some(result))
    }

    /// Provider votes stored for one check (§10.1 `provider_results`).
    pub fn load_evidence(&self, check_id: &str) -> SqlResult<Vec<ProviderEvidence>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider, category, upstream, signal, raw_score, raw_json, source_url, checked_at
             FROM provider_results WHERE check_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![check_id], |r| {
            let category_raw: String = r.get(1)?;
            let signal_raw: String = r.get(3)?;
            let raw_json: Option<String> = r.get(5)?;
            Ok(ProviderEvidence {
                provider: r.get(0)?,
                category: category_from_str(&category_raw),
                upstream: r.get(2)?,
                signal: signal_from_str(&signal_raw),
                raw_score: r.get(4)?,
                raw: raw_json.and_then(|s| serde_json::from_str(&s).ok()),
                checked_at: r.get(7)?,
                source_url: r.get(6)?,
                latency_ms: None,
                error: None,
                reason: None,
                from_cache: true,
            })
        })?;
        rows.collect()
    }

    // -----------------------------------------------------------------
    // Read path — cache reuse (§10.2)
    // -----------------------------------------------------------------

    /// §10.2 TTL guard: is the newest check of `ip` still usable?
    ///
    /// Returns the matching [`CheckSummary`] (whose `checked_at` is the ORIGINAL
    /// timestamp) when the row is younger than `max_age_hours`. `max_age_hours == 0`
    /// means "never cache" (leak / speed).
    pub fn cache_lookup(&self, ip: &str, max_age_hours: u32) -> Option<CheckSummary> {
        match self.try_cache_lookup(ip, max_age_hours) {
            Ok(hit) => hit,
            Err(err) => {
                tracing::warn!("cache_lookup({ip}) thất bại: {err}");
                None
            }
        }
    }

    /// Fallible variant of [`Cache::cache_lookup`].
    pub fn try_cache_lookup(
        &self,
        ip: &str,
        max_age_hours: u32,
    ) -> SqlResult<Option<CheckSummary>> {
        if max_age_hours == 0 {
            return Ok(None);
        }
        let mut rows = self.try_history_for_ip(ip, 1)?;
        let Some(newest) = rows.pop() else {
            return Ok(None);
        };
        if is_fresh(&newest.checked_at, max_age_hours) {
            Ok(Some(newest))
        } else {
            Ok(None)
        }
    }

    /// Newest-first history rows for a single IP.
    pub fn try_history_for_ip(&self, ip: &str, limit: u32) -> SqlResult<Vec<CheckSummary>> {
        let limit = limit.clamp(1, 500) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, mode, proxy_host, proxy_port, proxy_protocol,
                    clean_score, confidence_score, verdict, verdict_reason, checked_at
             FROM checks
             WHERE ip = ?1
             ORDER BY checked_at DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ip, limit], |r| {
            let mode_raw: String = r.get(2)?;
            let protocol_raw: Option<String> = r.get(5)?;
            let verdict_raw: Option<String> = r.get(8)?;
            Ok(CheckSummary {
                check_id: r.get(0)?,
                ip: r.get(1)?,
                mode: mode_from_str(&mode_raw),
                proxy_host: r.get(3)?,
                proxy_port: r.get::<_, Option<i64>>(4)?.map(|p| p as u16),
                proxy_protocol: protocol_raw.as_deref().and_then(protocol_from_str),
                clean_score: r.get::<_, Option<i64>>(6)?.map(|s| s as f64),
                confidence_score: r.get::<_, Option<i64>>(7)?.map(|s| s as f64),
                verdict: verdict_raw.as_deref().and_then(verdict_from_str),
                verdict_reason: r.get(9)?,
                checked_at: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    /// §10.2 TTL guard for a specific check id (kept for API compatibility).
    pub fn cache_fresh(&self, check_id: &str, max_age_hours: u32) -> bool {
        if max_age_hours == 0 {
            return false;
        }
        let checked_at: Option<String> = match self
            .conn
            .query_row(
                "SELECT checked_at FROM checks WHERE id = ?1",
                params![check_id],
                |r| r.get(0),
            )
            .optional()
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("cache_fresh({check_id}) thất bại: {err}");
                return false;
            }
        };
        match checked_at {
            Some(ts) => is_fresh(&ts, max_age_hours),
            None => false,
        }
    }

    /// Delete checks older than `days` (§11 log/history rotation).
    pub fn prune_older_than_days(&self, days: u32) -> SqlResult<usize> {
        if days == 0 {
            return Ok(0);
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let cutoff = cutoff.to_rfc3339();
        // One transaction: `§10.1` declares no foreign key, so the child rows
        // must be deleted by hand. Without a transaction a failure between the
        // two statements leaves vote rows whose `checks` parent is gone — not
        // corrupt, but orphaned garbage that grows with every rotation.
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM provider_results WHERE check_id IN
               (SELECT id FROM checks WHERE checked_at < ?1)",
            params![cutoff],
        )?;
        let removed = tx.execute("DELETE FROM checks WHERE checked_at < ?1", params![cutoff])?;
        tx.commit()?;
        Ok(removed)
    }

    /// Which cached categories may be reused for a new check of the same IP.
    ///
    /// Leak and Speed always come back empty (§10.2: never cached).
    pub fn reusable_categories(&self) -> Vec<Category> {
        [
            Category::Geo,
            Category::LocalDb,
            Category::Asn,
            Category::Fraud,
            Category::Abuse,
            Category::ThreatIntel,
            Category::Blacklist,
        ]
        .into_iter()
        .filter(|c| TtlClass::for_category(*c) != TtlClass::Never)
        .collect()
    }

    /// Simplest possible DNSBL reuse: the stored grouped result for an IP.
    pub fn cached_dnsbl(&self, check_id: &str) -> Option<DnsblResult> {
        // §10.1 has no dnsbl table (it is not required), so a DNSBL block is
        // reconstructed from the blacklist votes instead of invented.
        let evidence = self.load_evidence(check_id).ok()?;
        let blacklist: Vec<&ProviderEvidence> = evidence
            .iter()
            .filter(|e| e.category == Category::Blacklist)
            .collect();
        if blacklist.is_empty() {
            return None;
        }
        let total_listed = blacklist.iter().filter(|e| e.signal != Signal::Clean).count() as u32;
        Some(DnsblResult {
            groups: Vec::new(),
            total_listed,
            groups_answered: blacklist.len() as u32,
            hard_hit: blacklist
                .iter()
                .any(|e| e.signal == Signal::Bad && e.upstream == "spamhaus"),
            notes: vec!["Dựng lại từ cache — nhóm chi tiết không được lưu (§10.1)".to_string()],
        })
    }
}

/// Open the default database.
pub fn open_default() -> SqlResult<Cache> {
    Cache::open(&Cache::default_path())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Is an RFC-3339 timestamp younger than `max_age_hours`?
///
/// An unparseable timestamp is treated as stale: better a re-check than a
/// silently wrong "fresh" answer.
pub fn is_fresh(checked_at: &str, max_age_hours: u32) -> bool {
    if max_age_hours == 0 {
        return false;
    }
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(checked_at) else {
        return false;
    };
    let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
    // A timestamp in the future is clock skew, not freshness. `num_hours()`
    // truncates toward zero, so a negative age became 0 and every future row
    // counted as fresh forever — the cache would never expire a row written by
    // a machine whose clock was ahead. Treat it as stale and let it re-check.
    if age.num_seconds() < 0 {
        return false;
    }
    age.num_hours() < max_age_hours as i64
}

/// Recursively drop obvious secret-bearing keys from a stored payload.
///
/// Defence in depth: adapters must strip keys themselves (§4.4), but a single
/// slip must not turn into an API key on disk.
///
/// This used to carry its own `SECRET_KEYS` list, which drifted from the export
/// list: the cache knew `user`/`username` but not `passwd`/`api-key`/
/// `credentials`, and the export knew the reverse. Two security lists that each
/// miss something different is a hole no single-file review can see, so the
/// list now lives in exactly one place — [`crate::export`] — and this is a thin
/// delegation.
///
/// Kept as a thin alias so the cache has one import instead of two. The actual
/// scrubbing lives in [`crate::export::scrub_value`] — do not add logic here;
/// this wrapper existing is not permission for the two implementations to
/// drift apart again (that was the original bug).
pub fn scrub_secrets(value: &serde_json::Value) -> serde_json::Value {
    crate::export::scrub_value(value)
}

fn mode_from_str(value: &str) -> CheckMode {
    match value {
        "ip_only" => CheckMode::IpOnly,
        "proxy" => CheckMode::Proxy,
        _ => CheckMode::Unknown,
    }
}

fn protocol_str(protocol: ProxyProtocol) -> &'static str {
    match protocol {
        ProxyProtocol::Http => "http",
        ProxyProtocol::Https => "https",
        ProxyProtocol::Socks5 => "socks5",
        ProxyProtocol::Socks4 => "socks4",
    }
}

fn protocol_from_str(value: &str) -> Option<ProxyProtocol> {
    match value {
        "http" => Some(ProxyProtocol::Http),
        "https" => Some(ProxyProtocol::Https),
        "socks5" => Some(ProxyProtocol::Socks5),
        "socks4" => Some(ProxyProtocol::Socks4),
        _ => None,
    }
}

fn category_str(category: Category) -> &'static str {
    category.as_str()
}

fn category_from_str(value: &str) -> Category {
    match value {
        "geo" => Category::Geo,
        "asn" => Category::Asn,
        "fraud" => Category::Fraud,
        "abuse" => Category::Abuse,
        "threat_intel" => Category::ThreatIntel,
        "blacklist" => Category::Blacklist,
        "network" => Category::Network,
        "leak" => Category::Leak,
        "speed" => Category::Speed,
        "local_db" => Category::LocalDb,
        _ => Category::Geo,
    }
}

fn signal_str(signal: Signal) -> &'static str {
    match signal {
        Signal::Clean => "Clean",
        Signal::Suspicious => "Suspicious",
        Signal::Bad => "Bad",
        Signal::Unknown => "Unknown",
    }
}

fn signal_from_str(value: &str) -> Signal {
    match value {
        "Clean" => Signal::Clean,
        "Suspicious" => Signal::Suspicious,
        "Bad" => Signal::Bad,
        _ => Signal::Unknown,
    }
}

fn verdict_from_str(value: &str) -> Option<Verdict> {
    match value {
        "Sạch" => Some(Verdict::Sạch),
        "Tạm" => Some(Verdict::Tạm),
        "Nghi ngờ" => Some(Verdict::NghiNgờ),
        "Bẩn" => Some(Verdict::Bẩn),
        "Chưa đủ dữ liệu" => Some(Verdict::ChưaĐủDữLiệu),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProviderEvidence, Signal};

    fn sample_result(check_id: &str, ip: &str, checked_at: &str) -> FullCheckResult {
        let mut result =
            FullCheckResult::short_circuit(check_id.to_string(), ip.to_string(), "test".into());
        result.mode = CheckMode::IpOnly;
        result.validation_error = None;
        result.clean_score = Some(82.0);
        result.confidence_score = 91.0;
        result.verdict = Verdict::Tạm;
        result.verdict_reason = "Dính 1 DNSBL cộng đồng".to_string();
        result.checked_at = checked_at.to_string();
        result.evidence = vec![ProviderEvidence {
            provider: "ipqualityscore".to_string(),
            category: Category::Fraud,
            upstream: "ipqualityscore".to_string(),
            signal: Signal::Clean,
            raw_score: Some(12.0),
            raw: Some(serde_json::json!({"fraud_score": 12, "api_key": "SHOULD_BE_REDACTED"})),
            checked_at: checked_at.to_string(),
            source_url: "https://www.ipqualityscore.com/".to_string(),
            latency_ms: Some(120),
            error: None,
            reason: None,
            from_cache: false,
        }];
        result
    }

    #[test]
    fn history_returns_rows_newest_first() {
        let mut cache = Cache::open_in_memory().unwrap();
        let old = sample_result("id-old", "8.8.8.8", "2026-10-20T10:00:00+00:00");
        let new = sample_result("id-new", "1.1.1.1", "2026-10-25T10:00:00+00:00");
        cache.save_check(&old).unwrap();
        cache.save_check(&new).unwrap();

        let rows = cache.history(10);
        assert_eq!(rows.len(), 2, "history phải trả cả 2 dòng");
        assert_eq!(rows[0].check_id, "id-new", "dòng mới nhất đứng đầu");
        assert_eq!(rows[1].check_id, "id-old");
        assert_eq!(rows[0].verdict, Some(Verdict::Tạm));
        assert_eq!(rows[0].clean_score, Some(82.0));
    }

    #[test]
    fn history_limit_is_respected() {
        let mut cache = Cache::open_in_memory().unwrap();
        for i in 0..5 {
            let r = sample_result(
                &format!("id-{i}"),
                "8.8.8.8",
                &format!("2026-10-2{}T10:00:00+00:00", i + 1),
            );
            cache.save_check(&r).unwrap();
        }
        assert_eq!(cache.history(2).len(), 2);
        assert_eq!(cache.history(0).len(), 1, "limit 0 bị clamp lên 1");
    }

    #[test]
    fn cache_hit_keeps_original_timestamp() {
        let mut cache = Cache::open_in_memory().unwrap();
        let recent = chrono::Utc::now().to_rfc3339();
        cache
            .save_check(&sample_result("id-recent", "8.8.8.8", &recent))
            .unwrap();

        let hit = cache
            .cache_lookup("8.8.8.8", TTL_REPUTATION_HOURS)
            .expect("phải hit cache trong TTL");
        assert_eq!(hit.checked_at, recent, "cache hit phải giữ timestamp gốc");
        assert_eq!(hit.check_id, "id-recent");
    }

    #[test]
    fn stale_row_is_a_cache_miss() {
        let mut cache = Cache::open_in_memory().unwrap();
        let old = (chrono::Utc::now() - chrono::Duration::hours(48)).to_rfc3339();
        cache
            .save_check(&sample_result("id-old", "9.9.9.9", &old))
            .unwrap();
        assert!(
            cache.cache_lookup("9.9.9.9", TTL_REPUTATION_HOURS).is_none(),
            "48h > TTL 24h ⇒ miss"
        );
        // Geo TTL is 7 days, so the same row is still usable for geo.
        assert!(cache.cache_lookup("9.9.9.9", TTL_GEO_HOURS).is_some());
    }

    #[test]
    fn leak_and_speed_are_never_cached() {
        assert_eq!(TtlClass::for_category(Category::Leak), TtlClass::Never);
        assert_eq!(TtlClass::for_category(Category::Speed), TtlClass::Never);
        assert_eq!(TtlClass::Never.default_hours(), 0);

        let mut cache = Cache::open_in_memory().unwrap();
        cache
            .save_check(&sample_result("x", "8.8.8.8", &chrono::Utc::now().to_rfc3339()))
            .unwrap();
        assert!(cache.cache_lookup("8.8.8.8", 0).is_none(), "TTL 0 ⇒ luôn miss");
        assert!(!cache.reusable_categories().contains(&Category::Leak));
        assert!(!cache.reusable_categories().contains(&Category::Speed));
    }

    #[test]
    fn cache_fresh_uses_real_timestamp() {
        let mut cache = Cache::open_in_memory().unwrap();
        cache
            .save_check(&sample_result("id-1", "8.8.8.8", &chrono::Utc::now().to_rfc3339()))
            .unwrap();
        assert!(cache.cache_fresh("id-1", 24));
        assert!(!cache.cache_fresh("id-1", 0));
        assert!(!cache.cache_fresh("missing-id", 24));
    }

    #[test]
    fn load_check_marks_from_cache_and_roundtrips() {
        let mut cache = Cache::open_in_memory().unwrap();
        cache
            .save_check(&sample_result("id-rt", "8.8.8.8", "2026-10-25T10:00:00+00:00"))
            .unwrap();

        let detail = cache.load_check("id-rt").unwrap().expect("phải có row");
        assert!(detail.from_cache, "detail đọc từ DB phải cờ from_cache");
        assert_eq!(detail.checked_at, "2026-10-25T10:00:00+00:00");
        assert_eq!(detail.verdict, Verdict::Tạm);
        assert_eq!(detail.evidence.len(), 1);
        assert_eq!(detail.evidence[0].provider, "ipqualityscore");
        assert!(detail.evidence[0].from_cache);

        assert!(cache.load_check("nope").unwrap().is_none());
    }

    #[test]
    fn api_key_is_never_stored() {
        let mut cache = Cache::open_in_memory().unwrap();
        cache
            .save_check(&sample_result("id-secret", "8.8.8.8", "2026-10-25T10:00:00+00:00"))
            .unwrap();

        let evidence = cache.load_evidence("id-secret").unwrap();
        let raw = evidence[0].raw.as_ref().expect("raw phải còn");
        assert_ne!(raw["api_key"], serde_json::json!("SHOULD_BE_REDACTED"));
        assert_eq!(raw["api_key"], serde_json::json!("[redacted]"));
        // The non-secret field survives.
        assert_eq!(raw["fraud_score"], serde_json::json!(12));
    }

    #[test]
    fn proxy_credentials_are_never_persisted() {
        // §8.4: only host/port/protocol may be stored. The struct has no field
        // for credentials at all — this test pins that invariant.
        let mut cache = Cache::open_in_memory().unwrap();
        let mut result = sample_result("id-proxy", "1.2.3.4", "2026-10-25T10:00:00+00:00");
        result.mode = CheckMode::Proxy;
        result.proxy_host = Some("1.2.3.4".to_string());
        result.proxy_port = Some(8080);
        result.proxy_protocol = Some(ProxyProtocol::Socks5);
        cache.save_check(&result).unwrap();

        let rows = cache.history(1);
        assert_eq!(rows[0].mode, CheckMode::Proxy);
        assert_eq!(rows[0].proxy_host.as_deref(), Some("1.2.3.4"));
        assert_eq!(rows[0].proxy_port, Some(8080));
        assert_eq!(rows[0].proxy_protocol, Some(ProxyProtocol::Socks5));

        // The raw SQL surface must contain no credential column at all.
        let sql: String = cache
            .conn()
            .query_row(
                "SELECT group_concat(name) FROM pragma_table_info('checks')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for banned in ["password", "username", "user", "credential", "proxy_pass"] {
            assert!(
                !sql.to_ascii_lowercase().contains(banned),
                "bảng checks không được có cột {banned}: {sql}"
            );
        }
    }

    #[test]
    fn prune_removes_old_rows_and_their_votes() {
        let mut cache = Cache::open_in_memory().unwrap();
        let long_ago = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let now = chrono::Utc::now().to_rfc3339();
        cache
            .save_check(&sample_result("id-old", "8.8.8.8", &long_ago))
            .unwrap();
        cache
            .save_check(&sample_result("id-new", "1.1.1.1", &now))
            .unwrap();

        let removed = cache.prune_older_than_days(7).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(cache.count_checks().unwrap(), 1);
        assert!(cache.load_evidence("id-old").unwrap().is_empty());
    }

    #[test]
    fn schema_matches_spec_tables() {
        let cache = Cache::open_in_memory().unwrap();
        let tables: String = cache
            .conn()
            .query_row(
                "SELECT group_concat(name, ',') FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for required in ["checks", "provider_results", "geo_db_versions", "settings"] {
            assert!(tables.contains(required), "thiếu bảng {required}: {tables}");
        }
    }

    #[test]
    fn geo_db_version_upsert() {
        let cache = Cache::open_in_memory().unwrap();
        cache
            .upsert_geo_db("GeoLite2-City", "2026.10", "2026-10-01")
            .unwrap();
        cache
            .upsert_geo_db("GeoLite2-City", "2026.11", "2026-11-01")
            .unwrap();
        let rows = cache.geo_db_versions().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.as_deref(), Some("2026.11"));
    }

    #[test]
    fn is_fresh_rejects_garbage() {
        assert!(!is_fresh("not-a-date", 24));
        assert!(!is_fresh("2026-10-25T10:00:00+00:00", 0));
    }
}
