//! Tauri commands — the ONLY API surface the front-end may call (§4.2).
//!
//! Names are frozen and match `src/lib/api.ts` / `src/lib/types.ts`:
//! `check_ip`, `check_ip_stream`, `get_history`, `get_check_detail`,
//! `export_report`, `get_provider_health`, `save_settings`, `get_settings`,
//! plus the Settings-panel commands `save_provider_key`, `clear_provider_key`
//! and `get_geo_db_versions`.
//!
//! IPC naming: Tauri v2 camelCases command argument names by default, but every
//! caller in `src/lib/api.ts` sends snake_case (`check_id`, `provider_id`) and
//! `api.ts` explicitly documents that convention. Commands that take a
//! snake_case argument therefore carry
//! `#[tauri::command(rename_all = "snake_case")]`.
//!
//! Do NOT switch to camelCase in `api.ts` instead — one convention, one place.
//! Unit tests call these functions directly and never cross the IPC boundary,
//! so a missing `rename_all` is invisible to them; the guard test
//! `every_snake_case_command_declares_rename_all` is what catches it.
//!
//! Hard rules enforced here:
//!   * an API key is written to Windows Credential Manager and never returned,
//!     logged or echoed back (§2.1, §11);
//!   * a private / invalid IP short-circuits before any provider call (§3.4);
//!   * `check_ip_stream` emits `check-progress` **per module**, not once at the
//!     end (§3.3, §4.3).

use std::collections::HashMap;

use tauri::{AppHandle, Emitter, State};

use crate::config;
use crate::export;
use crate::models::{
    CheckOptions, CheckProgressEvent, CheckSession, CheckSummary, CommandError, ExportFormat,
    FullCheckResult, GeoDbVersion, HealthState, ProviderHealth, Settings,
};
use crate::orchestrator;
use crate::state::AppState;

/// §4.2 event name — must equal `CHECK_PROGRESS_EVENT` in `src/lib/types.ts`.
pub const CHECK_PROGRESS_EVENT: &str = "check-progress";

/// §7.3 — a local geo DB older than this loses location confidence.
pub const GEO_DB_STALE_DAYS: i64 = 60;

/// Map an internal error into the uniform `CommandError` shape.
fn cmd_err(kind: &str, err: impl std::fmt::Display) -> CommandError {
    CommandError::new(kind, err.to_string())
}

/// A locked SQLite handle, mapped to the uniform error type.
fn lock_cache(state: &AppState) -> Result<std::sync::MutexGuard<'_, crate::cache::Cache>, CommandError> {
    state
        .cache
        .lock()
        .map_err(|e| cmd_err("db", format!("Không khoá được SQLite: {e}")))
}

// ---------------------------------------------------------------------------
// Check commands (§4.2)
// ---------------------------------------------------------------------------

/// `check_ip(input, options?) -> CheckSession`
///
/// Runs the full pipeline and resolves once every module finished.
#[tauri::command]
pub async fn check_ip(
    state: State<'_, AppState>,
    input: String,
    options: Option<CheckOptions>,
) -> Result<CheckSession, CommandError> {
    if input.trim().is_empty() {
        return Err(CommandError::invalid_input("Vui lòng nhập IP cần kiểm tra"));
    }
    let options = options.unwrap_or_default();
    let _guard = state.settings_lock.read().await;

    let outcome = orchestrator::run_check(&input, options.clone()).await;

    // Persist to history unless the user turned it off (§3.3 checkbox).
    let save_to_history = options.save_to_history.unwrap_or(true);
    if save_to_history {
        if let Some(result) = outcome.session.result.as_ref() {
            // §3.4: private / invalid IP is never stored as a real check.
            if result.validation_error.is_none() {
                if let Ok(mut cache) = lock_cache(&state) {
                    if let Err(err) = cache.save_check(result) {
                        tracing::warn!("Không lưu được lịch sử: {err}");
                    }
                }
            }
        }
    }

    Ok(outcome.session)
}

/// `check_ip_stream(input, options?) -> void`
///
/// Emits `check-progress` for **each module as it completes** (§3.3, §4.3) so
/// `ScanProgress` can render incrementally instead of waiting for the slowest
/// provider.
///
/// **Returns the finished [`CheckSession`]**, not `()`.
///
/// Each orchestrator run mints its own `check_id` (`Uuid::new_v4` inside
/// `run_check_inner`). When this command returned `()`, the front-end had no id
/// to keep and called `check_ip` a second time just to obtain one — which ran
/// every module twice (double provider quota, double latency) and produced a
/// *different* id (`B`). Only the first run (`A`) was persisted, so exporting or
/// re-opening the row the UI was holding failed with "no data". Returning the
/// session gives the caller the id that actually went into SQLite, and makes a
/// second run unnecessary.
#[tauri::command]
pub async fn check_ip_stream(
    app: AppHandle,
    state: State<'_, AppState>,
    input: String,
    options: Option<CheckOptions>,
) -> Result<CheckSession, CommandError> {
    if input.trim().is_empty() {
        return Err(CommandError::invalid_input("Vui lòng nhập IP cần kiểm tra"));
    }
    let options = options.unwrap_or_default();
    let _guard = state.settings_lock.read().await;

    let emitter = app.clone();
    let sink: orchestrator::ProgressSink<'_> = Box::new(move |event: CheckProgressEvent| {
        if let Err(err) = emitter.emit(CHECK_PROGRESS_EVENT, &event) {
            tracing::warn!("emit {CHECK_PROGRESS_EVENT} thất bại: {err}");
        }
    });

    let session = orchestrator::run_check_streaming(&input, options.clone(), sink).await;

    let save_to_history = options.save_to_history.unwrap_or(true);
    if save_to_history {
        if let Some(result) = session.result.as_ref() {
            if result.validation_error.is_none() {
                if let Ok(mut cache) = lock_cache(&state) {
                    if let Err(err) = cache.save_check(result) {
                        tracing::warn!("Không lưu được lịch sử: {err}");
                    }
                }
            }
        }
    }
    Ok(session)
}

// ---------------------------------------------------------------------------
// History / detail (§4.2, §10.1)
// ---------------------------------------------------------------------------

/// `get_history(limit) -> CheckSummary[]` — newest first.
#[tauri::command]
pub async fn get_history(
    state: State<'_, AppState>,
    limit: u32,
) -> Result<Vec<CheckSummary>, CommandError> {
    let limit = limit.clamp(1, 500);
    let cache = lock_cache(&state)?;
    cache.try_history(limit).map_err(|e| cmd_err("db", e))
}

/// `get_check_detail(check_id) -> FullCheckResult`
///
/// Reads the stored row + provider votes. The result carries `from_cache = true`
/// and the ORIGINAL `checked_at`, so the UI can show
/// "từ cache, check lúc HH:MM DD/MM" instead of pretending it is fresh (§3.4).
/// A cache miss returns an error, never a fabricated result.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_check_detail(
    state: State<'_, AppState>,
    check_id: String,
) -> Result<FullCheckResult, CommandError> {
    let cache = lock_cache(&state)?;
    match cache.load_check(&check_id) {
        Ok(Some(mut result)) => {
            // §7.3 — surface local geo DB versions alongside the detail.
            if let Ok(rows) = cache.geo_db_versions() {
                result.geo_db_versions = Some(rows.into_iter().map(geo_db_version).collect());
            }
            Ok(result)
        }
        Ok(None) => Err(CommandError::new(
            "not_found",
            format!("Không có bản ghi cho check_id {check_id}"),
        )),
        Err(e) => Err(cmd_err("db", e)),
    }
}

// ---------------------------------------------------------------------------
// Export (§4.2, §10.3)
// ---------------------------------------------------------------------------

/// `export_report(check_id, format) -> string` (absolute path written)
#[tauri::command(rename_all = "snake_case")]
pub async fn export_report(
    state: State<'_, AppState>,
    check_id: String,
    format: ExportFormat,
) -> Result<String, CommandError> {
    let settings = config::load_settings();
    let dir = config::export_dir(&settings);

    let cache = lock_cache(&state)?;
    let mut result = match cache.load_check(&check_id) {
        Ok(Some(result)) => result,
        Ok(None) => {
            return Err(CommandError::new(
                "not_found",
                format!("Không có dữ liệu để xuất cho check_id {check_id}"),
            ))
        }
        Err(e) => return Err(cmd_err("db", e)),
    };
    if let Ok(rows) = cache.geo_db_versions() {
        result.geo_db_versions = Some(rows.into_iter().map(geo_db_version).collect());
    }
    drop(cache);

    // §13.10 — an export must never contain an API key or proxy credential.
    export::assert_no_secrets(&result).map_err(|e| cmd_err("export", e))?;

    // §10.3 — the message has to tell the user which folder failed and what to
    // do about it. A bare "os error 2" is unexplainable: on Windows a Known
    // Folder can exist, list, show Full Control, and still refuse every write
    // (OneDrive redirection, Controlled Folder Access, EDR).
    export::write(&result, &dir, format).map_err(|e| {
        cmd_err(
            "io",
            format!(
                "Không ghi được báo cáo vào {} ({}). Chọn thư mục khác trong Cài đặt.",
                dir.display(),
                e
            ),
        )
    })
}

// ---------------------------------------------------------------------------
// Provider health (§4.2, §5.5)
// ---------------------------------------------------------------------------

/// `get_provider_health() -> ProviderHealth[]`
///
/// Projects the registry + tracked runtime stats. Providers without an adapter
/// appear with `enabled = false` and `state = Unknown` — visible, never silently
/// dropped (§5.5, §13.4).
#[tauri::command]
pub async fn get_provider_health(
    state: State<'_, AppState>,
) -> Result<Vec<ProviderHealth>, CommandError> {
    let registry = state.registry.read().await;
    let stats = orchestrator::health_snapshot();

    let mut out = Vec::with_capacity(registry.providers.len());
    for meta in &registry.providers {
        let supported = crate::providers::supported_ids().contains(&meta.id.as_str());
        let has_key = config::has_api_key(&meta.id);

        if let Some(runtime) = stats.get(&meta.id) {
            let mut health = runtime.clone();
            health.requires_key = meta.requires_key;
            health.has_key = has_key;
            health.enabled = supported && meta.enabled_by_default;
            health.configured_weight = meta.sanitised_weight();
            if !supported {
                health.enabled = false;
            }
            out.push(health);
            continue;
        }

        out.push(ProviderHealth {
            provider: meta.id.clone(),
            category: meta.category,
            upstream: meta.upstream.clone(),
            state: HealthState::Unknown,
            success_rate: 0.0,
            latency_avg_ms: None,
            last_error_at: None,
            last_error: None,
            consecutive_failures: 0,
            circuit_open: false,
            circuit_open_until: None,
            effective_weight: meta.sanitised_weight(),
            configured_weight: meta.sanitised_weight(),
            requires_key: meta.requires_key,
            has_key,
            enabled: supported && meta.enabled_by_default,
            quota_exhausted: false,
            quota_reset_at: None,
            db_version: meta.db_name.clone(),
            db_updated_at: None,
            total_checks: 0,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Settings (§4.2, §3.3)
// ---------------------------------------------------------------------------

/// `save_settings(settings) -> void`
///
/// Settings only — API keys travel through `save_provider_key`, never in this
/// blob (§10.1: the `settings` table holds no keys).
#[tauri::command]
pub async fn save_settings(
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<(), CommandError> {
    let _guard = state.settings_lock.write().await;
    let mut settings = config::normalise(settings);

    // Keep `has_key` truthful instead of trusting the front-end (§3.3),
    // and reset circuit breakers for enabled providers so user retries take effect.
    for provider in settings.providers.iter_mut() {
        provider.has_key = config::has_api_key(&provider.provider);
        if provider.enabled {
            orchestrator::stats_for(&provider.provider).reset_circuit();
        }
    }

    {
        let cache = lock_cache(&state)?;
        config::save_settings_to(&cache, &settings).map_err(|e| cmd_err("settings", e))?;
    }

    *state.settings.write().await = settings;
    Ok(())
}

/// `get_settings() -> Settings`
#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<Settings, CommandError> {
    let _guard = state.settings_lock.read().await;
    let mut settings = {
        let cache = lock_cache(&state)?;
        config::load_settings_from(&cache)
    };

    // Merge registry defaults so the Settings panel always lists every provider.
    let registry = state.registry.read().await;
    config::merge_registry_defaults(&mut settings, &registry);
    drop(registry);

    for provider in settings.providers.iter_mut() {
        provider.has_key = config::has_api_key(&provider.provider);
    }

    Ok(settings)
}

// ---------------------------------------------------------------------------
// Settings panel — provider keys (§3.3, §2.1)
// ---------------------------------------------------------------------------

/// `save_provider_key(provider_id, key) -> void`
///
/// Stores the key in Windows Credential Manager. The value is **never** logged,
/// echoed back, or written to SQLite (§2.1, §11). An empty `key` deletes it.
///
/// NOTE: the argument MUST stay `provider_id` — `api.ts` invokes
/// `{ provider_id, key }`.
#[tauri::command(rename_all = "snake_case")]
pub async fn save_provider_key(
    state: State<'_, AppState>,
    provider_id: String,
    key: String,
) -> Result<(), CommandError> {
    if provider_id.trim().is_empty() {
        return Err(CommandError::invalid_input("Thiếu provider_id"));
    }
    let provider_id = provider_id.trim().to_string();

    if !key.trim().is_empty() {
        config::set_api_key(&provider_id, &key)
            .map_err(|e| cmd_err("keyring", e))?;
    }
    // Always reset the circuit breaker when saving a key or triggering a provider retry.
    orchestrator::stats_for(&provider_id).reset_circuit();

    // Reflect the new state in the persisted provider row (flag only).
    let has_key = config::has_api_key(&provider_id);
    {
        let cache = lock_cache(&state)?;
        let mut settings = config::load_settings_from(&cache);
        if let Some(provider) = settings
            .providers
            .iter_mut()
            .find(|p| p.provider == provider_id)
        {
            provider.has_key = has_key;
        }
        config::save_settings_to(&cache, &settings).map_err(|e| cmd_err("settings", e))?;
    }
    if let Ok(mut settings) = state.settings.try_write() {
        if let Some(provider) = settings
            .providers
            .iter_mut()
            .find(|p| p.provider == provider_id)
        {
            provider.has_key = has_key;
        }
    }

    tracing::info!("Đã cập nhật key cho provider '{provider_id}' (giá trị không được log)");
    Ok(())
}

/// `clear_provider_key(provider_id) -> void`
///
/// Deletes the Credential Manager entry. Removing a key that does not exist is
/// not an error.
#[tauri::command(rename_all = "snake_case")]
pub async fn clear_provider_key(
    state: State<'_, AppState>,
    provider_id: String,
) -> Result<(), CommandError> {
    if provider_id.trim().is_empty() {
        return Err(CommandError::invalid_input("Thiếu provider_id"));
    }
    let provider_id = provider_id.trim().to_string();

    config::clear_api_key(&provider_id).map_err(|e| cmd_err("keyring", e))?;

    {
        let cache = lock_cache(&state)?;
        let mut settings = config::load_settings_from(&cache);
        if let Some(provider) = settings
            .providers
            .iter_mut()
            .find(|p| p.provider == provider_id)
        {
            provider.has_key = false;
        }
        config::save_settings_to(&cache, &settings).map_err(|e| cmd_err("settings", e))?;
    }
    if let Ok(mut settings) = state.settings.try_write() {
        if let Some(provider) = settings
            .providers
            .iter_mut()
            .find(|p| p.provider == provider_id)
        {
            provider.has_key = false;
        }
    }

    tracing::info!("Đã xoá key của provider '{provider_id}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Geo DB versions (§3.3, §7.3)
// ---------------------------------------------------------------------------

/// `get_geo_db_versions() -> GeoDbVersion[]`
///
/// Reads the `geo_db_versions` table so Settings can show each local DB's
/// version + update date immediately at startup, without waiting for a check.
/// A DB older than 60 days is flagged `stale` (§7.3). No network access.
#[tauri::command]
pub async fn get_geo_db_versions(
    state: State<'_, AppState>,
) -> Result<Vec<GeoDbVersion>, CommandError> {
    let cache = lock_cache(&state)?;
    let rows = cache.geo_db_versions().map_err(|e| cmd_err("db", e))?;
    if rows.is_empty() {
        return Ok(crate::geo_db::GeoDbSet::load_default().version_rows());
    }
    Ok(rows.into_iter().map(geo_db_version).collect())
}

/// Map a `geo_db_versions` row onto the UI shape, computing `stale` (§7.3).
fn geo_db_version(row: (String, Option<String>, Option<String>)) -> GeoDbVersion {
    let (db_name, version, updated_at) = row;
    let stale = updated_at
        .as_deref()
        .map(is_geo_db_stale)
        .unwrap_or(true);
    GeoDbVersion {
        db_name,
        version,
        updated_at,
        stale,
    }
}

/// True when a geo DB's `updated_at` is older than [`GEO_DB_STALE_DAYS`].
///
/// An unparseable or missing date counts as stale: better a warning than a
/// silently wrong "fresh" badge.
pub fn is_geo_db_stale(updated_at: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(updated_at) {
        Ok(parsed) => {
            chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc))
                > chrono::Duration::days(GEO_DB_STALE_DAYS)
        }
        Err(_) => true,
    }
}

/// Convenience for the orchestrator: a `HashMap` of provider health by id.
pub async fn health_map(state: &AppState) -> HashMap<String, ProviderHealth> {
    let registry = state.registry.read().await;
    let stats = orchestrator::health_snapshot();
    registry
        .providers
        .iter()
        .filter_map(|meta| stats.get(&meta.id).cloned().map(|h| (meta.id.clone(), h)))
        .collect()
}

/// Open an http(s) URL in the user's default browser.
///
/// Tauri v2 dropped the implicit `<a target="_blank">` handler, and this app
/// ships no shell/opener plugin, so every "source" link in the UI was
/// decorative in the packaged build. Routing it through one Rust command keeps
/// the capability surface unchanged: no plugin permission, no generic shell the
/// webview could aim at an arbitrary executable, and the scheme is validated
/// here rather than trusted from the renderer.
#[tauri::command]
pub fn open_external(url: String) -> Result<(), CommandError> {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err(CommandError::invalid_input("Chỉ mở được link http/https"));
    }
    // Whitespace/quotes/control chars would break the handoff to the shell
    // handler; a URL with them is malformed anyway.
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"') {
        return Err(CommandError::invalid_input("URL không hợp lệ"));
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        // `rundll32 url.dll,FileProtocolHandler` hands the URL to ShellExecute
        // directly — there is no cmd.exe in the chain to inject into.
        Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", trimmed])
            .spawn()
            .map_err(|e| CommandError::new("io", format!("Không mở được trình duyệt: {e}")))?;
        Ok(())
    }

    #[cfg(not(windows))]
    {
        Err(CommandError::new(
            "unsupported",
            "Chưa hỗ trợ mở link trên nền tảng này",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_db_older_than_sixty_days_is_stale() {
        let old = (chrono::Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        assert!(is_geo_db_stale(&old), "DB 90 ngày phải bị đánh dấu cũ (§7.3)");
    }

    #[test]
    fn fresh_geo_db_is_not_stale() {
        let fresh = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
        assert!(!is_geo_db_stale(&fresh));
    }

    #[test]
    fn unparseable_date_is_treated_as_stale() {
        assert!(is_geo_db_stale("not-a-date"));
        assert!(is_geo_db_stale(""));
    }

    #[test]
    fn geo_db_version_mapping_sets_stale_flag() {
        let row = (
            "GeoLite2-City".to_string(),
            Some("2026.10".to_string()),
            Some((chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
        );
        let mapped = geo_db_version(row);
        assert_eq!(mapped.db_name, "GeoLite2-City");
        assert_eq!(mapped.version.as_deref(), Some("2026.10"));
        assert!(!mapped.stale);

        let missing = geo_db_version(("DB11.LITE".to_string(), None, None));
        assert!(missing.stale, "thiếu ngày ⇒ phải cảnh báo là cũ");
    }

    // ------------------------------------------------------------------
    // IPC boundary — the bug unit tests structurally cannot see
    // ------------------------------------------------------------------

    #[test]
    fn every_snake_case_command_declares_rename_all() {
        // Tauri v2 camelCases argument names at the IPC layer by default. These
        // functions are called *directly* by unit tests, so the translation never
        // runs and the tests pass while the real app fails with
        // `invalid args checkId for command get_check_detail`.
        //
        // This test reads the source and enforces the attribute where a
        // snake_case parameter exists.
        let src = include_str!("commands.rs");
        for needle in [
            "pub async fn get_check_detail",
            "pub async fn export_report",
            "pub async fn save_provider_key",
            "pub async fn clear_provider_key",
        ] {
            let idx = src.find(needle).expect("command phải tồn tại");
            let head = &src[idx.saturating_sub(200)..idx];
            assert!(
                head.contains("rename_all = \"snake_case\""),
                "{needle} nhận tham số snake_case nhưng thiếu \
                 #[tauri::command(rename_all = \"snake_case\")] — \
                 app thật sẽ báo 'invalid args'"
            );
        }
    }

    #[test]
    fn single_word_argument_commands_stay_default() {
        // `input`, `options`, `limit`, `settings` are single words: camelCasing
        // them is a no-op, so they must NOT carry the attribute (keeping the
        // surface minimal and the convention obvious).
        let src = include_str!("commands.rs");
        for needle in [
            "pub async fn check_ip(",
            "pub async fn check_ip_stream(",
            "pub async fn get_history(",
            "pub async fn save_settings(",
        ] {
            let idx = src.find(needle).expect("command phải tồn tại");
            let head = &src[idx.saturating_sub(120)..idx];
            assert!(
                !head.contains("rename_all"),
                "{needle} không có tham số snake_case nên không cần rename_all"
            );
        }
    }

    // ------------------------------------------------------------------
    // One user click == one orchestrator run
    // ------------------------------------------------------------------

    #[test]
    fn check_ip_stream_returns_the_session() {
        // Guards the architecture, not just a signature. `run_check_inner`
        // mints a fresh `check_id` every run, and only the persisted run's id
        // exists in SQLite. While this command returned `()`, the front-end had
        // to call `check_ip` a second time just to get an id — running every
        // module twice and handing the UI an id that was never saved, which
        // broke export, history and doubled provider quota.
        let src = include_str!("commands.rs");
        let idx = src
            .find("pub async fn check_ip_stream")
            .expect("check_ip_stream phải tồn tại");
        // Look at the return type: everything up to the opening brace.
        let tail = &src[idx..];
        let signature = &tail[..tail.find('{').unwrap_or(tail.len())];
        assert!(
            signature.contains("Result<CheckSession, CommandError>"),
            "check_ip_stream phải trả CheckSession để caller không cần chạy lần hai; \
             chữ ký hiện tại: {signature}"
        );
        assert!(
            !signature.contains("Result<(), CommandError>"),
            "trả () là tái phát bug check_id mismatch"
        );
    }

    #[test]
    fn every_orchestrator_entry_mints_its_own_id() {
        // Documents *why* one click must be one run: both entry points go
        // through `run_check_inner`, which creates the id.
        let src = include_str!("orchestrator.rs");
        assert!(
            src.contains("Uuid::new_v4()"),
            "orchestrator phải tự sinh check_id — đó là lý do không được chạy hai lần"
        );
        let count = src.matches("Uuid::new_v4()").count();
        assert_eq!(
            count, 1,
            "chỉ được có ĐÚNG MỘT chỗ sinh check_id; thấy {count} chỗ"
        );
    }
}
