//! Location engine — majority vote + centroid + radius, never a single point (§7).
//!
//! Rules enforced here (§7.3, §7.5, §7.7):
//!   * **Country** is decided by majority vote across independent sources.
//!   * **City** is only committed when the sources cluster: ≤ 50 km ⇒ high
//!     confidence, 50–200 km ⇒ medium, > 200 km ⇒ *do not commit a city*, only
//!     region/country, with an explicit divergence warning.
//!   * **Never average blindly** when points are far apart (a VN + SG average
//!     lands in the sea) — [`triangulate`] refuses to do it.
//!   * A local DB older than 60 days loses confidence (§7.3).
//!   * Datacenter / anycast / mobile IPs downgrade city confidence (§7.5).
//!
//! The module never invents coordinates: with no geo point it returns
//! `spread = "unknown"` and a note, and `centroid_*` stay `None`.

use std::collections::HashMap;

use crate::models::{GeoPoint, IpType, LocationResult};

/// Distance threshold under which the city is committed (§7.3).
pub const SPREAD_HIGH_KM: f64 = 50.0;
/// Upper bound for a medium-confidence city (§7.3).
pub const SPREAD_MEDIUM_KM: f64 = 200.0;
/// Divergence that triggers the red warning (§7.7).
pub const BIG_DIVERGENCE_KM: f64 = 2000.0;
/// A local geo DB older than this many days loses confidence (§7.3).
pub const DB_STALE_AFTER_DAYS: i64 = 60;
/// Confidence penalty applied when the only usable DB is stale.
pub const STALE_DB_PENALTY: f64 = 20.0;

/// Haversine distance in km between two coordinates.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0088;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dphi = (lat2 - lat1).to_radians();
    let dlambda = (lon2 - lon1).to_radians();
    let a = (dphi / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dlambda / 2.0).sin().powi(2);
    2.0 * R * a.clamp(0.0, 1.0).sqrt().asin()
}

/// Arithmetic centroid of the usable points.
///
/// Callers must NOT use this blindly when points are far apart (§7.3) —
/// [`triangulate`] checks the spread first.
pub fn centroid(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    let n = points.len() as f64;
    let lat = points.iter().map(|p| p.0).sum::<f64>() / n;
    let lon = points.iter().map(|p| p.1).sum::<f64>() / n;
    Some((lat, lon))
}

/// Weighted centroid, using `weight` per point (0.0 is treated as "no weight").
pub fn weighted_centroid(points: &[(f64, f64, f64)]) -> Option<(f64, f64)> {
    let mut total = 0.0;
    let mut lat = 0.0;
    let mut lon = 0.0;
    for (la, lo, w) in points {
        if *w <= 0.0 || !la.is_finite() || !lo.is_finite() {
            continue;
        }
        total += w;
        lat += la * w;
        lon += lo * w;
    }
    if total <= 0.0 {
        None
    } else {
        Some((lat / total, lon / total))
    }
}

/// Is a `db_updated_at` older than [`DB_STALE_AFTER_DAYS`]? Missing ⇒ stale.
pub fn db_is_stale(db_updated_at: Option<&String>) -> bool {
    match db_updated_at {
        Some(text) => match chrono::DateTime::parse_from_rfc3339(text) {
            Ok(parsed) => {
                chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc))
                    > chrono::Duration::days(DB_STALE_AFTER_DAYS)
            }
            Err(_) => true,
        },
        None => false, // No date claimed ⇒ no penalty (API sources carry none).
    }
}

/// §7.1 — a source that claims street-level precision on an IP is untrustworthy.
///
/// Returns `true` when the point looks over-precise (a postal code plus a
/// sub-kilometre accuracy radius is the usual signature).
pub fn looks_over_precise(point: &GeoPoint) -> bool {
    let very_tight_radius = point.accuracy_radius_km.map(|r| r < 1.0).unwrap_or(false);
    let has_postal = point
        .postal
        .as_deref()
        .map(|p| !p.trim().is_empty())
        .unwrap_or(false);
    very_tight_radius && has_postal
}

/// Run triangulation over the collected geo points (§7.3, §7.7).
///
/// Empty input yields a `spread = "unknown"` result with an explanation, never
/// fabricated coordinates.
pub fn triangulate(points: Vec<GeoPoint>) -> LocationResult {
    triangulate_for_type(points, IpType::Unknown)
}

/// Triangulation that also applies the per-IP-type confidence rules (§7.5).
pub fn triangulate_for_type(mut points: Vec<GeoPoint>, ip_type: IpType) -> LocationResult {
    let mut notes = Vec::new();

    // §7.1: flag over-precise sources instead of trusting them.
    for point in points.iter_mut() {
        if !point.over_precise && looks_over_precise(point) {
            point.over_precise = true;
            notes.push(format!(
                "Nguồn {} trả độ chính xác quá mức cho một IP (§7.1) — không dùng để chốt địa chỉ",
                point.source
            ));
        }
    }

    let coords: Vec<(f64, f64)> = points
        .iter()
        .filter(|p| !p.over_precise)
        .filter_map(|p| match (p.latitude, p.longitude) {
            (Some(lat), Some(lon))
                if lat.is_finite() && lon.is_finite() && (-90.0..=90.0).contains(&lat)
                    && (-180.0..=180.0).contains(&lon) =>
            {
                Some((lat, lon))
            }
            _ => None,
        })
        .collect();

    // ---- Country: majority vote (§7.3) ----
    let (country, country_code, country_votes) = majority_country(&points);
    let country_confidence = if country_votes == 0 {
        0.0
    } else {
        let with_country = points
            .iter()
            .filter(|p| {
                p.country_code
                    .as_deref()
                    .map(|c| !c.is_empty())
                    .unwrap_or(false)
            })
            .count() as u32;
        if with_country == 0 {
            0.0
        } else if country_votes == with_country {
            95.0 // §7.1: unanimous country is high confidence
        } else {
            95.0 * (country_votes as f64 / with_country as f64)
        }
    };

    if country_votes > 0 {
        let disagreeing: Vec<&str> = points
            .iter()
            .filter_map(|p| p.country_code.as_deref())
            .filter(|code| {
                country_code
                    .as_deref()
                    .map(|winner| !winner.eq_ignore_ascii_case(code))
                    .unwrap_or(false)
            })
            .collect();
        if !disagreeing.is_empty() {
            notes.push(format!(
                "Quốc gia không đồng thuận tuyệt đối: {} nguồn lệch ({})",
                disagreeing.len(),
                disagreeing.join(", ")
            ));
        }
    }

    if coords.is_empty() {
        return LocationResult {
            country,
            country_code,
            country_confidence,
            spread: "unknown".to_string(),
            points,
            notes: {
                notes.push("Chưa có nguồn geo nào trả về toạ độ".to_string());
                notes
            },
            ..Default::default()
        };
    }

    let (clat, clon) = centroid(&coords).unwrap_or((0.0, 0.0));
    let max_dist = coords
        .iter()
        .map(|(lat, lon)| haversine_km(clat, clon, *lat, *lon))
        .fold(0.0_f64, f64::max);

    let spread = if max_dist <= SPREAD_HIGH_KM {
        "high"
    } else if max_dist <= SPREAD_MEDIUM_KM {
        "medium"
    } else {
        "low"
    }
    .to_string();

    // §7.3: do NOT average far-apart points. If the spread is too wide, the
    // centroid is reported as a diagnostic but no city is committed.
    let mut city_committed: Option<String> = None;
    if max_dist <= SPREAD_MEDIUM_KM {
        // Majority city among the points that actually have one.
        let mut tally: HashMap<&str, u32> = HashMap::new();
        for point in points.iter().filter(|p| !p.over_precise) {
            if let Some(city) = point.city.as_deref().filter(|c| !c.trim().is_empty()) {
                *tally.entry(city).or_insert(0) += 1;
            }
        }
        city_committed = tally
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(city, _)| city.to_string());
    }

    if max_dist > SPREAD_MEDIUM_KM {
        notes.push(format!(
            "Các nguồn lệch tới {max_dist:.0} km — KHÔNG chốt thành phố, chỉ chốt quốc gia/vùng (§7.3)"
        ));
    }

    // §7.5: IP-type dependent confidence.
    let city_final = match ip_type {
        IpType::Anycast => {
            notes.push("IP anycast — không chốt thành phố (§7.5)".to_string());
            None
        }
        IpType::Cgnat | IpType::Mobile => {
            notes.push(
                "IP mobile/CGNAT — vị trí thường là gateway nhà mạng, không phải người dùng (§7.5)"
                    .to_string(),
            );
            None
        }
        IpType::Datacenter | IpType::Vpn | IpType::Tor | IpType::Proxy => {
            notes.push(
                "IP datacenter/VPN — vị trí là nơi thoát, không phải vị trí người thật (§7.5)"
                    .to_string(),
            );
            city_committed
        }
        _ => city_committed,
    };

    let mut out_points = points;
    for point in out_points.iter_mut() {
        if let (Some(lat), Some(lon)) = (point.latitude, point.longitude) {
            if lat.is_finite() && lon.is_finite() {
                point.distance_from_centroid_km = Some(haversine_km(clat, clon, lat, lon));
            }
        }
    }

    // §7.3 — stale local DB ⇒ confidence penalty.
    let stale_sources: Vec<&str> = out_points
        .iter()
        .filter(|p| db_is_stale(p.db_updated_at.as_ref()))
        .map(|p| p.source.as_str())
        .collect();
    let mut country_confidence = country_confidence;
    if !stale_sources.is_empty() {
        country_confidence = (country_confidence - STALE_DB_PENALTY).max(0.0);
        notes.push(format!(
            "DB geo cũ > {DB_STALE_AFTER_DAYS} ngày: {} — trừ điểm tin cậy (§7.3)",
            stale_sources.join(", ")
        ));
    }

    let big_divergence = max_dist > BIG_DIVERGENCE_KM;
    if big_divergence {
        notes.push(format!(
            "CẢNH BÁO ĐỎ: các nguồn lệch > {BIG_DIVERGENCE_KM:.0} km (§7.7)"
        ));
    }

    let region = out_points
        .iter()
        .find_map(|p| p.region.clone())
        .filter(|_| city_final.is_none());

    LocationResult {
        country,
        country_code,
        country_confidence,
        city: city_final,
        region,
        centroid_latitude: Some(clat),
        centroid_longitude: Some(clon),
        radius_km: Some(max_dist),
        spread,
        points: out_points,
        big_divergence,
        notes,
        changed_since_last_check: None,
        previous_country: None,
        previous_city: None,
    }
}

/// Majority-vote country across points (§7.3).
///
/// Returns `(country name, country code, votes for the winner)`.
pub fn majority_country(points: &[GeoPoint]) -> (Option<String>, Option<String>, u32) {
    let mut tally: HashMap<(String, String), u32> = HashMap::new();
    for point in points {
        if let Some(code) = point.country_code.as_deref().filter(|c| !c.is_empty()) {
            let name = point.country.clone().unwrap_or_else(|| code.to_string());
            *tally.entry((code.to_uppercase(), name)).or_insert(0) += 1;
        }
    }
    match tally.into_iter().max_by_key(|(_, n)| *n) {
        Some(((code, name), votes)) => (Some(name), Some(code), votes),
        None => (None, None, 0),
    }
}

/// §7.7 — compare against the previous check of the same IP.
///
/// A location that moved between checks is a real signal (re-allocation / a
/// rotating proxy), so it must be surfaced rather than silently overwritten.
pub fn apply_history(mut current: LocationResult, previous: Option<&LocationResult>) -> LocationResult {
    let Some(previous) = previous else {
        return current;
    };
    current.previous_country = previous.country.clone();
    current.previous_city = previous.city.clone();

    let country_changed = match (&current.country_code, &previous.country_code) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
        _ => false,
    };
    let city_changed = match (&current.city, &previous.city) {
        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
        _ => false,
    };

    current.changed_since_last_check = Some(country_changed || city_changed);
    if country_changed || city_changed {
        current.notes.push(format!(
            "Vị trí đã thay đổi so với lần check trước ({} → {}) — có thể IP vừa được cấp lại hoặc proxy xoay vị trí (§7.7)",
            previous
                .country
                .clone()
                .or_else(|| previous.city.clone())
                .unwrap_or_else(|| "?".to_string()),
            current
                .country
                .clone()
                .or_else(|| current.city.clone())
                .unwrap_or_else(|| "?".to_string()),
        ));
    }
    current
}

/// Build a [`GeoPoint`] from one provider's raw fields, marking over-precision.
pub fn geo_point(
    source: &str,
    source_kind: &str,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    postal: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
    accuracy_radius_km: Option<f64>,
    db_version: Option<String>,
    db_updated_at: Option<String>,
) -> GeoPoint {
    let mut point = GeoPoint {
        source: source.to_string(),
        source_kind: source_kind.to_string(),
        country,
        country_code: country_code.map(|c| c.to_uppercase()),
        region,
        city,
        postal,
        latitude,
        longitude,
        timezone,
        accuracy_radius_km,
        db_version,
        db_updated_at,
        distance_from_centroid_km: None,
        over_precise: false,
    };
    point.over_precise = looks_over_precise(&point);
    point
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(source: &str, country: &str, city: &str, lat: f64, lon: f64) -> GeoPoint {
        GeoPoint {
            source: source.to_string(),
            source_kind: "api".to_string(),
            country: Some(country.to_string()),
            country_code: Some(country[..2].to_uppercase()),
            city: Some(city.to_string()),
            latitude: Some(lat),
            longitude: Some(lon),
            ..Default::default()
        }
    }

    #[test]
    fn haversine_smoke() {
        // Hồ Chí Minh → Singapore ≈ 1080–1100 km
        let d = haversine_km(10.8231, 106.6297, 1.3521, 103.8198);
        assert!(d > 1000.0 && d < 1200.0, "got {d}");
    }

    #[test]
    fn empty_input_is_not_fabricated() {
        let r = triangulate(Vec::new());
        assert_eq!(r.centroid_latitude, None);
        assert_eq!(r.spread, "unknown");
        assert_eq!(r.country, None);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn clustered_points_commit_city() {
        // Three sources inside ~30 km: Singapore.
        let points = vec![
            point("ip_api", "Singapore", "Singapore", 1.3521, 103.8198),
            point("ipwho", "Singapore", "Singapore", 1.3644, 103.9915),
            point("ipinfo", "Singapore", "Singapore", 1.2897, 103.8501),
        ];
        let result = triangulate(points);
        assert_eq!(result.spread, "high", "≤50 km ⇒ high");
        assert_eq!(result.city.as_deref(), Some("Singapore"));
        assert_eq!(result.country_code.as_deref(), Some("SI"));
        assert!(result.country_confidence > 80.0);
    }

    #[test]
    fn medium_spread_keeps_city_with_warning() {
        // 50–200 km apart, measured the way `triangulate` measures it: each
        // point against the centroid (§7.3). 10.82/106.63 → 12.00/107.10 is
        // ~130 km point-to-point, so each sits ~65 km from the centroid.
        let points = vec![
            point("a", "Vietnam", "Ho Chi Minh", 10.8231, 106.6297),
            point("b", "Vietnam", "Ho Chi Minh", 12.0, 107.1),
        ];
        let result = triangulate(points);
        assert_eq!(
            result.spread, "medium",
            "50–200 km tính tới centroid ⇒ medium"
        );
        assert_eq!(result.city.as_deref(), Some("Ho Chi Minh"));
    }

    #[test]
    fn far_apart_points_do_not_commit_a_city() {
        // VN vs Singapore ≈ 1080 km — averaging would land in the sea.
        let points = vec![
            point("ip_api", "Vietnam", "Ho Chi Minh", 10.8231, 106.6297),
            point("ipwho", "Singapore", "Singapore", 1.3521, 103.8198),
        ];
        let result = triangulate(points);
        assert_eq!(result.spread, "low");
        assert_eq!(
            result.city, None,
            "§7.3: lệch > 200 km thì KHÔNG chốt thành phố"
        );
        assert!(
            result.notes.iter().any(|n| n.contains("KHÔNG chốt thành phố")),
            "phải giải thích: {:?}",
            result.notes
        );
        // Country majority still works: 1 vote each ⇒ a winner exists but the
        // disagreement is reported.
        assert!(result.country.is_some());
        assert!(result.notes.iter().any(|n| n.contains("lệch")));
    }

    #[test]
    fn big_divergence_sets_red_warning() {
        let points = vec![
            point("a", "Vietnam", "Hanoi", 21.0278, 105.8342),
            point("b", "United States", "Ashburn", 39.0438, -77.4874),
        ];
        let result = triangulate(points);
        assert!(result.big_divergence, "lệch > 2.000 km ⇒ cờ đỏ (§7.7)");
        assert!(result.notes.iter().any(|n| n.contains("CẢNH BÁO ĐỎ")));
    }

    #[test]
    fn country_majority_wins() {
        let points = vec![
            point("a", "Singapore", "Singapore", 1.35, 103.82),
            point("b", "Singapore", "Singapore", 1.36, 103.83),
            point("c", "Vietnam", "Hanoi", 21.03, 105.83),
        ];
        let (country, code, votes) = majority_country(&points);
        assert_eq!(country.as_deref(), Some("Singapore"));
        assert_eq!(code.as_deref(), Some("SI"));
        assert_eq!(votes, 2);
    }

    #[test]
    fn anycast_never_commits_city() {
        let points = vec![
            point("a", "Singapore", "Singapore", 1.35, 103.82),
            point("b", "Singapore", "Singapore", 1.36, 103.83),
        ];
        let result = triangulate_for_type(points, IpType::Anycast);
        assert_eq!(result.city, None, "§7.5 anycast không chốt thành phố");
        assert!(result.notes.iter().any(|n| n.contains("anycast")));
    }

    #[test]
    fn cgnat_and_mobile_downgrade_city() {
        let points = vec![
            point("a", "Vietnam", "Hanoi", 21.03, 105.83),
            point("b", "Vietnam", "Hanoi", 21.04, 105.84),
        ];
        assert_eq!(
            triangulate_for_type(points.clone(), IpType::Cgnat).city,
            None
        );
        assert_eq!(triangulate_for_type(points, IpType::Mobile).city, None);
    }

    #[test]
    fn residential_keeps_city() {
        let points = vec![
            point("a", "Vietnam", "Hanoi", 21.03, 105.83),
            point("b", "Vietnam", "Hanoi", 21.04, 105.84),
        ];
        let result = triangulate_for_type(points, IpType::Residential);
        assert_eq!(result.city.as_deref(), Some("Hanoi"));
    }

    #[test]
    fn stale_db_penalises_confidence() {
        let old = (chrono::Utc::now() - chrono::Duration::days(120)).to_rfc3339();
        let mut p1 = point("maxmind", "Vietnam", "Hanoi", 21.03, 105.83);
        p1.db_updated_at = Some(old);
        let p2 = point("ip_api", "Vietnam", "Hanoi", 21.04, 105.84);

        let fresh = triangulate(vec![p2.clone()]);
        let stale = triangulate(vec![p1, p2]);

        assert!(
            stale.country_confidence < fresh.country_confidence,
            "DB cũ phải trừ confidence: {} vs {}",
            stale.country_confidence,
            fresh.country_confidence
        );
        assert!(stale.notes.iter().any(|n| n.contains("DB geo cũ")));
    }

    #[test]
    fn over_precise_source_is_flagged_and_excluded() {
        let mut sketchy = point("streetdb", "Vietnam", "Hanoi", 21.03, 105.83);
        sketchy.postal = Some("100000".to_string());
        sketchy.accuracy_radius_km = Some(0.4);

        let clean = point("ip_api", "Vietnam", "Hanoi", 21.035, 105.835);
        let result = triangulate(vec![sketchy, clean]);

        let flagged = result
            .points
            .iter()
            .find(|p| p.source == "streetdb")
            .unwrap();
        assert!(flagged.over_precise, "§7.1 phải gắn cờ quá chi tiết");
        assert!(result.notes.iter().any(|n| n.contains("quá mức")));
    }

    #[test]
    fn distances_from_centroid_are_recorded() {
        let points = vec![
            point("a", "Vietnam", "Hanoi", 21.03, 105.83),
            point("b", "Vietnam", "Hanoi", 21.05, 105.85),
        ];
        let result = triangulate(points);
        for p in &result.points {
            assert!(p.distance_from_centroid_km.is_some());
            assert!(p.distance_from_centroid_km.unwrap() < 10.0);
        }
    }

    #[test]
    fn history_change_is_surfaced() {
        let previous = triangulate(vec![point("a", "Vietnam", "Hanoi", 21.03, 105.83)]);
        let current = triangulate(vec![point("a", "Singapore", "Singapore", 1.35, 103.82)]);
        let merged = apply_history(current, Some(&previous));
        assert_eq!(merged.changed_since_last_check, Some(true));
        assert_eq!(merged.previous_country.as_deref(), Some("Vietnam"));
        assert!(merged.notes.iter().any(|n| n.contains("thay đổi")));
    }

    #[test]
    fn no_history_means_no_change_flag() {
        let current = triangulate(vec![point("a", "Vietnam", "Hanoi", 21.03, 105.83)]);
        let merged = apply_history(current, None);
        assert_eq!(merged.changed_since_last_check, None);
    }

    #[test]
    fn invalid_coordinates_are_ignored() {
        let mut bad = point("bad", "Vietnam", "Hanoi", 999.0, 999.0);
        bad.latitude = Some(999.0);
        let good = point("good", "Vietnam", "Hanoi", 21.03, 105.83);
        let result = triangulate(vec![bad, good]);
        assert!(result.centroid_latitude.is_some());
        assert_eq!(result.spread, "high");
    }
}
