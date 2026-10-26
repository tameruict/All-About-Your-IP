//! Local geo databases — MaxMind GeoLite2, IP2Location LITE, DB-IP Lite (§5.1, §7.3).
//!
//! These are the *offline* half of the location engine: they answer without a
//! network call, they carry their own edition/date metadata, and their age is
//! part of the confidence calculation (§7.3: "DB cũ > 60 ngày → trừ điểm tin
//! cậy"). Everything here degrades gracefully — a missing or corrupt file makes
//! the source report [`GeoDbStatus::Missing`] / [`GeoDbStatus::Invalid`] instead
//! of failing the check.
//!
//! Precedence notes (§7.1):
//!   * A city/postal answer is only ever a *vote*; [`crate::location`] decides.
//!   * `accuracy_radius_km` is propagated from MaxMind verbatim. When a database
//!     provides none, it stays `None` — never invented.
//!   * MaxMind's `subdivisions[]` is used for region; `city` is used for city.
//!     Street-level fields do not exist in these DBs and are never produced.
//!
//! Supported artefacts:
//!   * MaxMind `.mmdb` — GeoLite2-City and GeoLite2-Country (binary reader via
//!     the `maxminddb` crate).
//!   * IP2Location LITE / DB-IP Lite CSV — the free "LITE" dumps are CSV, so a
//!     CSV reader handles both. Column layout differs per product, so the header
//!     is inspected instead of assuming a fixed order.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{GeoDbVersion, GeoPoint};

/// A local DB older than this many days is "stale" (§7.3).
///
/// Mirrors [`crate::location::DB_STALE_AFTER_DAYS`]; duplicated as a `u32`
/// because this module works in whole days rather than `i64`.
pub const STALE_AFTER_DAYS: u32 = 60;

/// Which family a database belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoDbKind {
    MaxMindCity,
    MaxMindCountry,
    Ip2LocationLite,
    DbIpLite,
}

impl GeoDbKind {
    /// Registry id, matching the `local_db` rows in `providers.yaml` (§5.5).
    pub fn id(&self) -> &'static str {
        match self {
            GeoDbKind::MaxMindCity => "maxmind_geolite2_city",
            GeoDbKind::MaxMindCountry => "maxmind_geolite2_country",
            GeoDbKind::Ip2LocationLite => "ip2location_lite",
            GeoDbKind::DbIpLite => "dbip_lite",
        }
    }

    /// Human label shown in the Geo DB table (§7.7).
    pub fn label(&self) -> &'static str {
        match self {
            GeoDbKind::MaxMindCity => "MaxMind GeoLite2 City",
            GeoDbKind::MaxMindCountry => "MaxMind GeoLite2 Country",
            GeoDbKind::Ip2LocationLite => "IP2Location LITE",
            GeoDbKind::DbIpLite => "DB-IP Lite",
        }
    }

    /// Root upstream, for §6.2 vote de-duplication: the two MaxMind editions
    /// collapse into one vote, exactly like the YAML says.
    pub fn upstream(&self) -> &'static str {
        match self {
            GeoDbKind::MaxMindCity | GeoDbKind::MaxMindCountry => "maxmind",
            GeoDbKind::Ip2LocationLite => "ip2location",
            GeoDbKind::DbIpLite => "db-ip",
        }
    }

    /// Default filename inside the geo DB directory.
    pub fn default_filename(&self) -> &'static str {
        match self {
            GeoDbKind::MaxMindCity => "GeoLite2-City.mmdb",
            GeoDbKind::MaxMindCountry => "GeoLite2-Country.mmdb",
            GeoDbKind::Ip2LocationLite => "IP2LOCATION-LITE-DB1.CSV",
            GeoDbKind::DbIpLite => "dbip-city-lite.csv",
        }
    }
}

/// Load state of one database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoDbStatus {
    /// Loaded and queryable.
    Ready,
    /// The file is not installed (the normal state on a fresh install).
    Missing,
    /// The file exists but could not be parsed.
    Invalid,
}

/// One loaded database plus its metadata.
#[derive(Debug)]
pub struct GeoDb {
    pub kind: GeoDbKind,
    pub path: PathBuf,
    pub status: GeoDbStatus,
    /// Edition string, e.g. the MaxMind build date `2026-10-20`.
    pub version: Option<String>,
    /// Build/installation date used for the staleness calculation (§7.3).
    pub updated_at: Option<DateTime<Utc>>,
    /// Parse error detail when `status == Invalid`.
    pub error: Option<String>,
    backend: Backend,
}

impl GeoDb {
    /// True when the DB answers queries.
    pub fn is_ready(&self) -> bool {
        self.status == GeoDbStatus::Ready
    }

    /// How many days old the DB is, if the build date is known.
    pub fn age_days(&self, now: DateTime<Utc>) -> Option<u32> {
        self.updated_at
            .map(|then| (now - then).num_days().max(0) as u32)
    }

    /// True when the DB is older than [`STALE_AFTER_DAYS`] (§7.3).
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        Durations::stale(self.updated_at, now)
    }

    /// Look one IP up. Returns `None` when the DB is not usable or has no entry.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoPoint> {
        match &self.backend {
            Backend::None => None,
            Backend::MaxMind(reader) => maxmind_lookup(self.kind, reader, ip, self),
            Backend::Csv(table) => csv_lookup(self.kind, table, ip, self),
        }
    }

    /// Metadata row for the `geo_db_versions` table (§10.1) and the UI.
    pub fn version_row(&self, now: DateTime<Utc>) -> GeoDbVersion {
        GeoDbVersion {
            db_name: self.kind.id().to_string(),
            version: self.version.clone(),
            updated_at: self.updated_at.map(|t| t.to_rfc3339()),
            stale: self.is_stale(now),
        }
    }
}

/// Small helper so the staleness rule is expressed once.
struct Durations;

impl Durations {
    fn stale(updated_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
        match updated_at {
            Some(then) => (now - then).num_days() >= STALE_AFTER_DAYS as i64,
            // Unknown age is not the same as fresh: the engine must not claim
            // the data is current when it cannot prove it (§7.1).
            None => false,
        }
    }
}

/// Concrete reader behind a [`GeoDb`].
#[derive(Debug)]
enum Backend {
    None,
    MaxMind(maxminddb::Reader<Vec<u8>>),
    Csv(CsvTable),
}

/// Minimal in-memory table for the CSV products.
#[derive(Debug)]
struct CsvTable {
    /// Sorted by start address so a lookup is a binary search.
    rows: Vec<CsvRow>,
}

#[derive(Debug)]
struct CsvRow {
    start: u128,
    end: u128,
    fields: CsvFields,
}

#[derive(Debug, Clone, Default)]
struct CsvFields {
    country_code: Option<String>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    postal: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
}

/// Map an IP onto the inclusive integer range used for CSV comparisons.
fn ip_to_range(ip: IpAddr) -> (u128, u128) {
    match ip {
        IpAddr::V4(v4) => {
            let value = u32::from(v4) as u128;
            (value, value)
        }
        IpAddr::V6(v6) => {
            let value = u128::from(v6);
            (value, value)
        }
    }
}

/// Parse an IPv4/IPv6 literal, or a dotted IPv4 range like `1.2.3.0/24`.
///
/// Deliberately strict: the range columns of both products are IP literals.
/// Accepting bare integers here would let a malformed file (e.g. `1,2,3`)
/// produce plausible-looking bounds and be reported as `Ready`, masking a
/// corrupt database (§7.4 — the UI must not show "DB OK" for a broken file).
fn parse_bound(raw: &str) -> Option<u128> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip_to_range(ip).0);
    }
    // DB-IP Lite uses CIDR for the end column in some editions.
    if let Some((addr, bits)) = raw.split_once('/') {
        let ip: IpAddr = addr.trim().parse().ok()?;
        let bits: u32 = bits.trim().parse().ok()?;
        return match ip {
            IpAddr::V4(v4) => {
                let width = 32u32;
                let mask = if bits == 0 { 0 } else { u32::MAX << (width - bits.min(width)) };
                Some((u32::from(v4) & mask) as u128)
            }
            IpAddr::V6(v6) => {
                let width = 128u32;
                let mask = if bits == 0 { 0 } else { u128::MAX << (width - bits.min(width)) };
                Some(u128::from(v6) & mask)
            }
        };
    }
    None
}

/// Index of a column by any of several accepted header spellings.
fn column_index(headers: &[String], candidates: &[&str]) -> Option<usize> {
    headers.iter().position(|h| {
        let h = h.trim().trim_matches('"').to_ascii_lowercase();
        candidates.iter().any(|c| h == *c)
    })
}

/// Load one database from an explicit path.
pub fn load(kind: GeoDbKind, path: impl AsRef<Path>) -> GeoDb {
    let path = path.as_ref().to_path_buf();

    if !path.is_file() {
        return GeoDb {
            kind,
            path,
            status: GeoDbStatus::Missing,
            version: None,
            updated_at: None,
            error: None,
            backend: Backend::None,
        };
    }

    let result = match kind {
        GeoDbKind::MaxMindCity | GeoDbKind::MaxMindCountry => load_maxmind(&path),
        GeoDbKind::Ip2LocationLite | GeoDbKind::DbIpLite => load_csv(&path),
    };

    match result {
        Ok((backend, version, updated_at)) => GeoDb {
            kind,
            path,
            status: GeoDbStatus::Ready,
            version,
            updated_at,
            error: None,
            backend,
        },
        Err(err) => GeoDb {
            kind,
            path,
            status: GeoDbStatus::Invalid,
            version: None,
            updated_at: None,
            error: Some(err),
            backend: Backend::None,
        },
    }
}

/// Load a MaxMind `.mmdb` file and read its build date from metadata.
fn load_maxmind(path: &Path) -> Result<(Backend, Option<String>, Option<DateTime<Utc>>), String> {
    let reader =
        maxminddb::Reader::open_readfile(path).map_err(|e| format!("không mở được mmdb: {e}"))?;

    // `metadata.build_epoch` is the authoritative build time; the human-facing
    // version string for GeoLite2 is exactly that date.
    let epoch = reader.metadata.build_epoch;
    let updated_at = DateTime::from_timestamp(epoch as i64, 0);
    let version = updated_at.map(|t| t.format("%Y-%m-%d").to_string());

    Ok((Backend::MaxMind(reader), version, updated_at))
}

/// Load an IP2Location LITE / DB-IP Lite CSV dump.
fn load_csv(path: &Path) -> Result<(Backend, Option<String>, Option<DateTime<Utc>>), String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .map_err(|e| format!("không mở được CSV: {e}"))?;

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("không đọc được header: {e}"))?
        .iter()
        .map(|h| h.trim().to_string())
        .collect();

    // Both products start with an IP range in the first two columns; the older
    // IP2Location LITE layout uses "0.0.0.0","0.0.0.0" with no header names, in
    // which case positional indices apply.
    let start_idx = column_index(&headers, &["ip_from", "start_ip", "range_start", "ip_start"]).unwrap_or(0);
    let end_idx = column_index(&headers, &["ip_to", "end_ip", "range_end", "ip_end"]).unwrap_or(1);

    let country_code_idx = column_index(&headers, &["country_code", "country_short", "countryshort", "iso_code"]);
    let country_idx = column_index(&headers, &["country_long", "country_name", "countrylong", "country"]);
    let region_idx = column_index(&headers, &["region", "region_name", "regionname", "stateprov"]);
    let city_idx = column_index(&headers, &["city_name", "city", "cityname"]);
    let postal_idx = column_index(&headers, &["zip_code", "postal_code", "zipcode", "zip"]);
    let lat_idx = column_index(&headers, &["latitude", "lat"]);
    let lon_idx = column_index(&headers, &["longitude", "lon", "lng"]);
    let tz_idx = column_index(&headers, &["time_zone", "timezone", "time_zone_name"]);

    let mut rows: Vec<CsvRow> = Vec::new();
    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            // A single malformed line must not discard the whole database.
            Err(_) => continue,
        };
        let (Some(start), Some(end)) = (
            record.get(start_idx).and_then(parse_bound),
            record.get(end_idx).and_then(parse_bound),
        ) else {
            continue;
        };

        let text = |idx: Option<usize>| -> Option<String> {
            idx.and_then(|i| record.get(i))
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty() && v != "-")
        };
        let number = |idx: Option<usize>| -> Option<f64> { text(idx).and_then(|v| v.parse::<f64>().ok()) };

        rows.push(CsvRow {
            start,
            end,
            fields: CsvFields {
                country_code: text(country_code_idx),
                country: text(country_idx),
                region: text(region_idx),
                city: text(city_idx),
                postal: text(postal_idx),
                latitude: number(lat_idx),
                longitude: number(lon_idx),
                timezone: text(tz_idx),
            },
        });
    }

    if rows.is_empty() {
        return Err("CSV không có dòng dữ liệu hợp lệ".to_string());
    }

    rows.sort_by_key(|r| r.start);

    // The dump's own date is in the filename for both products, which is the
    // only date available; fall back to the file mtime when it is absent.
    let version = version_from_filename(path);
    let updated_at = version
        .as_deref()
        .and_then(parse_date_string)
        .or_else(|| file_modified(path));

    Ok((Backend::Csv(CsvTable { rows }), version, updated_at))
}

/// IP2Location `..._2026_10_01.CSV` / DB-IP `dbip-city-lite-2026-10.csv`.
fn version_from_filename(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_string();
    // Look for a YYYY-MM-DD or YYYY_MM_DD or YYYY-MM group in the name.
    let digits: Vec<char> = name.chars().collect();
    for (i, chunk) in digits.windows(4).enumerate() {
        if !chunk.iter().all(char::is_ascii_digit) {
            continue;
        }
        let year: String = chunk.iter().collect();
        if !("1990"..="2100").contains(&year.as_str()) {
            continue;
        }
        let rest: String = digits[i..].iter().collect();
        if let Some(date) = parse_date_string(&rest) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }
    None
}

/// Accept `YYYY-MM-DD`, `YYYY_MM_DD`, `YYYY-MM` and `YYYYMMDD`.
fn parse_date_string(raw: &str) -> Option<DateTime<Utc>> {
    let cleaned: String = raw
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect();
    // Keep only the digits and separators of the leading date-ish run, so a
    // trailing extension (".csv") or junk ("-lite") cannot poison the parse.
    let head: String = cleaned
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let head = head.trim_end_matches('-');
    if head.is_empty() {
        return None;
    }

    // Longest form first: a month-only value must not shadow a full date.
    for fmt in ["%Y-%m-%d", "%Y%m%d"] {
        if let Ok(date) = NaiveDate::parse_from_str(head, fmt) {
            return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    // Month-only (`2026-10`, the DB-IP Lite filename form): `NaiveDate` requires
    // a day component, so build it with day 1 — the DB is dated by month.
    let parts: Vec<&str> = head.split('-').collect();
    if parts.len() == 2 {
        if let (Ok(year), Ok(month)) = (parts[0].parse::<i32>(), parts[1].parse::<u32>()) {
            if let Some(date) = NaiveDate::from_ymd_opt(year, month, 1) {
                return Some(date.and_hms_opt(0, 0, 0)?.and_utc());
            }
        }
    }
    None
}

fn file_modified(path: &Path) -> Option<DateTime<Utc>> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

/// Read a MaxMind record into a [`GeoPoint`].
fn maxmind_lookup(
    kind: GeoDbKind,
    reader: &maxminddb::Reader<Vec<u8>>,
    ip: IpAddr,
    db: &GeoDb,
) -> Option<GeoPoint> {
    // `geoloc` is present in City editions; the fully typed call keeps the
    // country-only edition working too (its record type differs).
    if kind == GeoDbKind::MaxMindCity {
        let record: maxminddb::geoip2::City = reader.lookup(ip).ok()?;
        let country_code = record.country.as_ref().and_then(|c| c.iso_code).map(str::to_string);
        let country = record
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en")).map(|s| s.to_string());
        let region = record
            .subdivisions
            .as_ref()
            .and_then(|s| s.first())
            .and_then(|s| s.names.as_ref())
            .and_then(|n| n.get("en")).map(|s| s.to_string());
        let city = record
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en")).map(|s| s.to_string());
        let postal = record.postal.as_ref().and_then(|p| p.code).map(str::to_string);
        let (latitude, longitude, accuracy_radius_km) = match record.location.as_ref() {
            Some(loc) => (loc.latitude, loc.longitude, loc.accuracy_radius.map(f64::from)),
            None => (None, None, None),
        };
        let timezone = record
            .location
            .as_ref()
            .and_then(|l| l.time_zone).map(str::to_string);

        if country_code.is_none() && country.is_none() {
            return None;
        }

        return Some(GeoPoint {
            source: kind.id().to_string(),
            source_kind: "local_db".to_string(),
            country,
            country_code,
            region,
            city,
            postal,
            latitude,
            longitude,
            timezone,
            accuracy_radius_km,
            db_version: db.version.clone(),
            db_updated_at: db.updated_at.map(|t| t.to_rfc3339()),
            distance_from_centroid_km: None,
            over_precise: false,
        });
    }

    let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
    let country_code = record.country.as_ref().and_then(|c| c.iso_code).map(str::to_string);
    let country = record
        .country
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|n| n.get("en")).map(|s| s.to_string());

    if country_code.is_none() && country.is_none() {
        return None;
    }

    // Country edition: no city/postal/coords by definition (§7.1 — do not
    // pretend to a precision the data does not have).
    Some(GeoPoint {
        source: kind.id().to_string(),
        source_kind: "local_db".to_string(),
        country,
        country_code,
        region: None,
        city: None,
        postal: None,
        latitude: None,
        longitude: None,
        timezone: None,
        accuracy_radius_km: None,
        db_version: db.version.clone(),
        db_updated_at: db.updated_at.map(|t| t.to_rfc3339()),
        distance_from_centroid_km: None,
        over_precise: false,
    })
}

/// Binary-search a CSV table.
fn csv_lookup(kind: GeoDbKind, table: &CsvTable, ip: IpAddr, db: &GeoDb) -> Option<GeoPoint> {
    let (value, _) = ip_to_range(ip);

    let idx = match table.rows.binary_search_by(|row| {
        if value < row.start {
            std::cmp::Ordering::Greater
        } else if value > row.end {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    }) {
        Ok(i) => i,
        Err(_) => return None,
    };

    let fields = &table.rows[idx].fields;
    if fields.country_code.is_none() && fields.country.is_none() {
        return None;
    }

    Some(GeoPoint {
        source: kind.id().to_string(),
        source_kind: "local_db".to_string(),
        country: fields.country.clone(),
        country_code: fields.country_code.clone(),
        region: fields.region.clone(),
        city: fields.city.clone(),
        postal: fields.postal.clone(),
        latitude: fields.latitude,
        longitude: fields.longitude,
        timezone: fields.timezone.clone(),
        // Neither free CSV dump publishes an accuracy radius; leaving it `None`
        // is what §7.1 requires instead of a made-up number.
        accuracy_radius_km: None,
        db_version: db.version.clone(),
        db_updated_at: db.updated_at.map(|t| t.to_rfc3339()),
        distance_from_centroid_km: None,
        over_precise: false,
    })
}

// ---------------------------------------------------------------------------
// Registry of installed databases
// ---------------------------------------------------------------------------

/// Every local DB, wrapped so the orchestrator can look an IP up once and get
/// all votes for §7.3.
#[derive(Debug, Default)]
pub struct GeoDbSet {
    pub databases: Vec<GeoDb>,
}

/// Directory held by [`install_dir`]-style discovery.
static DISCOVERED: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

/// Default directory that holds the bundled/updated DB files.
///
/// Mirrors the app's data directory layout; the environment override exists so
/// tests and portable builds can point elsewhere.
pub fn default_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("IP_CHECKER_GEO_DB_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(base) = dirs::data_dir() {
        return base.join("ip-checker").join("geo-db");
    }
    PathBuf::from("geo-db")
}

/// Remember the directory that was discovered, so a second call is cheap.
pub fn install_dir(dir: impl AsRef<Path>) {
    let cell = DISCOVERED.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        *guard = Some(dir.as_ref().to_path_buf());
    }
}

impl GeoDbSet {
    /// Load every known DB kind from `dir`.
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        let databases = [
            GeoDbKind::MaxMindCity,
            GeoDbKind::MaxMindCountry,
            GeoDbKind::Ip2LocationLite,
            GeoDbKind::DbIpLite,
        ]
        .into_iter()
        .map(|kind| load(kind, dir.join(kind.default_filename())))
        .collect();
        Self { databases }
    }

    /// Load from the default directory (after [`install_dir`] if it was used).
    pub fn load_default() -> Self {
        let dir = DISCOVERED
            .get_or_init(|| Mutex::new(None))
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(default_dir);
        Self::load_from_dir(dir)
    }

    /// An empty set — used when the user has installed no DB at all.
    pub fn empty() -> Self {
        Self {
            databases: Vec::new(),
        }
    }

    /// True when at least one DB can answer.
    pub fn has_any(&self) -> bool {
        self.databases.iter().any(GeoDb::is_ready)
    }

    /// All geo votes for one IP, one per ready database (§7.3).
    pub fn lookup(&self, ip: IpAddr) -> Vec<GeoPoint> {
        self.databases
            .iter()
            .filter_map(|db| db.lookup(ip))
            .collect()
    }

    /// Rows for `geo_db_versions` and the UI table (§7.7).
    pub fn version_rows(&self) -> Vec<GeoDbVersion> {
        let now = Utc::now();
        self.databases.iter().map(|db| db.version_row(now)).collect()
    }

    /// True when a *ready* database is stale, i.e. a confidence penalty applies.
    pub fn any_stale(&self) -> bool {
        let now = Utc::now();
        self.databases
            .iter()
            .any(|db| db.is_ready() && db.is_stale(now))
    }

    /// Upstreams that actually answered — used to de-duplicate votes (§6.2).
    ///
    /// MaxMind City and Country collapse to a single `maxmind` entry so the
    /// location engine cannot double-count one data source (§7.3).
    pub fn answering_upstreams(&self) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        for db in self.databases.iter().filter(|d| d.is_ready()) {
            let upstream = db.kind.upstream();
            if !seen.contains(&upstream) {
                seen.push(upstream);
            }
        }
        seen
    }

    /// Lookup that also requires the DB to be fresh (§7.3).
    pub fn lookup_fresh(&self, ip: IpAddr) -> Vec<GeoPoint> {
        let now = Utc::now();
        self.databases
            .iter()
            .filter(|db| db.is_ready() && !db.is_stale(now))
            .filter_map(|db| db.lookup(ip))
            .collect()
    }
}

/// Convenience: a map of `db_name → GeoDbVersion` for the SQLite upsert.
pub fn version_map(set: &GeoDbSet) -> HashMap<String, GeoDbVersion> {
    set.version_rows()
        .into_iter()
        .map(|row| (row.db_name.clone(), row))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write one test fixture into a **per-thread directory**, keeping the file
    /// name exactly as the test asked for it.
    ///
    /// Six tests legitimately ask for a `dbip-city-lite-2026-10.csv` body and
    /// `cargo test` runs them in parallel threads. One shared path turned that
    /// into a race: a test read the body another thread had just written, which
    /// surfaced as `status: Ready` where `Invalid` was expected — a flaky,
    /// machine-speed-dependent failure.
    ///
    /// Isolation lives in the *directory*, never in the file name, because
    /// `version_from_filename` parses the `YYYY-MM` date out of the name and
    /// would break if it were decorated with a PID or thread id.
    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ipchecker-geodb-{}", std::process::id()))
            .join(thread_dir());
        std::fs::create_dir_all(&dir).expect("temp dir");

        let stem = std::path::Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("fixture");
        let ext = std::path::Path::new(name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        // Same thread, same test binary: the name below is unique per thread too,
        // so two tests on one thread still cannot collide on a re-run.
        let unique = if ext.is_empty() {
            format!("{stem}-{}", thread_dir())
        } else {
            format!("{stem}-{}.{ext}", thread_dir())
        };
        let path = dir.join(unique);
        std::fs::write(&path, contents).expect("ghi file");
        path
    }

    /// A filesystem-safe token for the current thread.
    ///
    /// `ThreadId` renders as `ThreadId(12)`, so the punctuation is folded away;
    /// the leading `t` keeps `version_from_filename` from mistaking the digits
    /// for part of the date.
    fn thread_dir() -> String {
        let raw = format!("{:?}", std::thread::current().id());
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        format!("t{digits}")
    }

    const DBIP_CSV: &str = "ip_start,ip_end,country_code,country_name,region,city,latitude,longitude\n\
1.0.0.0,1.0.0.255,AU,Australia,Queensland,Brisbane,-27.4679,153.0281\n\
8.8.8.0,8.8.8.255,US,United States,California,Mountain View,37.4056,-122.0775\n\
45.155.204.0,45.155.207.255,RU,Russia,Moscow,Moscow,55.7558,37.6173\n";

    #[test]
    fn missing_file_reports_missing_not_invalid() {
        let db = load(GeoDbKind::DbIpLite, std::env::temp_dir().join("no-such-file-xyz.csv"));
        assert_eq!(db.status, GeoDbStatus::Missing);
        assert!(!db.is_ready());
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(db.error.is_none());
    }

    #[test]
    fn csv_lookup_finds_the_right_row() {
        let path = write_temp("dbip-city-lite-2026-10.csv", DBIP_CSV);
        let db = load(GeoDbKind::DbIpLite, &path);
        assert_eq!(db.status, GeoDbStatus::Ready, "error={:?}", db.error);

        let gp = db.lookup("8.8.8.8".parse().unwrap()).expect("phải tìm thấy");
        assert_eq!(gp.country_code.as_deref(), Some("US"));
        assert_eq!(gp.city.as_deref(), Some("Mountain View"));
        assert_eq!(gp.source, "dbip_lite");
        assert_eq!(gp.source_kind, "local_db");
        // §7.1: no invented accuracy radius for a CSV product.
        assert!(gp.accuracy_radius_km.is_none());
        assert!(gp.db_version.is_some());
    }

    #[test]
    fn csv_lookup_returns_none_outside_ranges() {
        let path = write_temp("dbip-city-lite-2026-10.csv", DBIP_CSV);
        let db = load(GeoDbKind::DbIpLite, &path);
        assert!(db.lookup("192.0.2.1".parse().unwrap()).is_none());
    }

    #[test]
    fn csv_version_comes_from_filename_date() {
        let path = write_temp("dbip-city-lite-2026-10.csv", DBIP_CSV);
        let db = load(GeoDbKind::DbIpLite, &path);
        assert_eq!(db.version.as_deref(), Some("2026-10-01"));
        assert!(db.updated_at.is_some());
        // Fresh DB is not stale.
        assert!(!db.is_stale(Utc::now()));
    }

    #[test]
    fn stale_flag_true_after_60_days() {
        // §7.3 — build date older than 60 days must raise the flag.
        let path = write_temp("dbip-city-lite-2020-01-01.csv", DBIP_CSV);
        let db = load(GeoDbKind::DbIpLite, &path);
        let now = Utc::now();
        assert!(db.is_stale(now), "DB 2020 phải bị coi là cũ");
        assert_eq!(db.version_row(now).stale, true);
        let age = db.age_days(now).unwrap();
        assert!(age >= STALE_AFTER_DAYS);
    }

    #[test]
    fn ip2location_header_layout_is_detected() {
        let csv = "ip_from,ip_to,country_code,country_name,region,city,latitude,longitude,zip_code,time_zone\n\
\"1.0.0.0\",\"1.0.0.255\",\"AU\",\"Australia\",\"Queensland\",\"Brisbane\",\"-27.46794\",\"153.02809\",\"4000\",\"Australia/Brisbane\"\n";
        let path = write_temp("IP2LOCATION-LITE-DB1-2026-09-01.CSV", csv);
        let db = load(GeoDbKind::Ip2LocationLite, &path);
        assert_eq!(db.status, GeoDbStatus::Ready, "error={:?}", db.error);

        let gp = db.lookup("1.0.0.5".parse().unwrap()).expect("phải tìm thấy");
        assert_eq!(gp.country_code.as_deref(), Some("AU"));
        assert_eq!(gp.postal.as_deref(), Some("4000"));
        assert_eq!(gp.timezone.as_deref(), Some("Australia/Brisbane"));
        assert_eq!(gp.source, "ip2location_lite");
    }

    #[test]
    fn malformed_csv_is_invalid_not_panic() {
        let path = write_temp("dbip-city-lite-2026-10.csv", "garbage without columns\n1,2,3\n");
        let db = load(GeoDbKind::DbIpLite, &path);
        assert_eq!(db.status, GeoDbStatus::Invalid);
        assert!(db.error.is_some());
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn corrupt_mmdb_is_invalid_not_panic() {
        let path = write_temp("GeoLite2-City.mmdb", "definitely not an mmdb");
        let db = load(GeoDbKind::MaxMindCity, &path);
        assert_eq!(db.status, GeoDbStatus::Invalid);
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn maxmind_city_and_country_collapse_to_one_upstream() {
        // §6.2: the two GeoLite2 editions must not double-vote.
        assert_eq!(GeoDbKind::MaxMindCity.upstream(), GeoDbKind::MaxMindCountry.upstream());
        assert_ne!(GeoDbKind::Ip2LocationLite.upstream(), GeoDbKind::MaxMindCity.upstream());
    }

    #[test]
    fn db_set_lookup_and_versions() {
        let path = write_temp("dbip-city-lite-2026-10.csv", DBIP_CSV);
        let set = GeoDbSet {
            databases: vec![load(GeoDbKind::DbIpLite, &path)],
        };
        assert!(set.has_any());
        let points = set.lookup("45.155.205.1".parse().unwrap());
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].country_code.as_deref(), Some("RU"));

        let rows = set.version_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].db_name, "dbip_lite");
        assert_eq!(set.answering_upstreams(), vec!["db-ip"]);
    }

    #[test]
    fn empty_set_never_panics() {
        let set = GeoDbSet::empty();
        assert!(!set.has_any());
        assert!(set.lookup("8.8.8.8".parse().unwrap()).is_empty());
        assert!(!set.any_stale());
        assert!(set.version_rows().is_empty());
    }

    #[test]
    fn bound_parsing_handles_cidr_and_literals() {
        assert_eq!(parse_bound("8.8.8.8"), Some(u32::from("8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap()) as u128));
        let network = parse_bound("1.2.3.0/24").unwrap();
        assert_eq!(network, u32::from("1.2.3.0".parse::<std::net::Ipv4Addr>().unwrap()) as u128);
        assert!(parse_bound("").is_none());
        assert!(parse_bound("not-an-ip").is_none());
    }

    #[test]
    fn date_parsing_accepts_common_layouts() {
        assert!(parse_date_string("2026-10-01").is_some());
        assert!(parse_date_string("2026_10_01").is_some());
        assert!(parse_date_string("20261001").is_some());
        assert!(parse_date_string("2026-10").is_some());
        assert!(parse_date_string("nodate").is_none());
    }

    #[test]
    fn stale_threshold_boundary() {
        // Exactly 60 days ⇒ stale; 59 days ⇒ fresh (§7.3).
        let now = Utc::now();
        let path = write_temp("dbip-city-lite-2026-10.csv", DBIP_CSV);
        let mut db = load(GeoDbKind::DbIpLite, &path);
        db.updated_at = Some(now - chrono::Duration::days(59));
        assert!(!db.is_stale(now));
        db.updated_at = Some(now - chrono::Duration::days(60));
        assert!(db.is_stale(now));
        // Unknown age must not be reported as stale.
        db.updated_at = None;
        assert!(!db.is_stale(now));
    }
}
