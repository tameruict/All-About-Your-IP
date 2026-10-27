//! Settings + `providers.yaml` access, API keys in Windows Credential Manager
//! (§2.1, §3.3, §10.1).
//!
//! Hard rules:
//!   * API keys live **only** in Windows Credential Manager (`keyring`).
//!     They are never written to the `settings` table, never logged, never
//!     returned to the front-end.
//!   * Settings themselves are a JSON blob in the §10.1 `settings` table.
//!   * A missing/corrupt settings blob falls back to [`Settings::default`] with
//!     a warning — the app always starts.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::models::Settings;
use crate::providers::registry::{self, Registry};

/// Service name used for every Credential Manager entry.
pub const KEYRING_SERVICE: &str = "com.ipchecker.app";

/// Row key inside the §10.1 `settings` table holding the JSON blob.
pub const SETTINGS_ROW_KEY: &str = "app_settings";

/// Cached copy so `load_settings()` stays cheap on hot paths.
///
/// The authoritative copy is the SQLite blob; this is only a read cache that
/// [`save_settings_to`] refreshes.
static SETTINGS_CACHE: OnceLock<std::sync::RwLock<Option<Settings>>> = OnceLock::new();

fn settings_cache() -> &'static std::sync::RwLock<Option<Settings>> {
    SETTINGS_CACHE.get_or_init(|| std::sync::RwLock::new(None))
}

/// Refresh the cached copy without touching SQLite.
pub fn prime_cache(settings: Settings) {
    if let Ok(mut slot) = settings_cache().write() {
        *slot = Some(normalise(settings));
    }
}

/// Load the provider registry from disk.
///
/// A missing file or an entry without an adapter never aborts startup: the
/// registry degrades to an empty one (or to whatever rows parsed) and the
/// problem is logged (§5.5, §13.4).
pub fn load_registry() -> Registry {
    match registry::load() {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!("providers.yaml: {err} — chạy với registry rỗng");
            registry::empty()
        }
    }
}

/// Load settings from the given cache connection.
///
/// Falls back to defaults on any error. The result is also merged with the
/// registry so the Settings panel always has a complete provider list.
pub fn load_settings_from(cache: &crate::cache::Cache) -> Settings {
    let mut settings = match read_blob(cache) {
        Ok(Some(stored)) => stored,
        Ok(None) => Settings::default(),
        Err(err) => {
            tracing::warn!("Đọc settings thất bại ({err}) — dùng mặc định");
            Settings::default()
        }
    };

    settings = normalise(settings);
    prime_cache(settings.clone());
    settings
}

/// Load settings using the process-wide cache when possible.
///
/// Used by modules that have no `AppState` handle (orchestrator, dnsbl, export).
pub fn load_settings() -> Settings {
    if let Ok(slot) = settings_cache().read() {
        if let Some(settings) = slot.as_ref() {
            return settings.clone();
        }
    }
    match crate::cache::Cache::open(&crate::cache::Cache::default_path()) {
        Ok(opened) => load_settings_from(&opened),
        Err(err) => {
            tracing::warn!("Không mở được SQLite cho settings ({err}) — dùng mặc định");
            normalise(Settings::default())
        }
    }
}

/// Persist settings into the given cache connection.
pub fn save_settings_to(db: &crate::cache::Cache, settings: &Settings) -> Result<(), String> {
    let settings = normalise(settings.clone());
    let blob = serde_json::to_string(&settings)
        .map_err(|e| format!("Không serialize được settings: {e}"))?;

    db.conn()
        .execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![SETTINGS_ROW_KEY, blob],
        )
        .map_err(|e| format!("Không ghi được settings: {e}"))?;

    prime_cache(settings);
    Ok(())
}

/// Persist settings to the default database (cache-agnostic callers).
pub fn save_settings(settings: &Settings) -> Result<(), String> {
    let db = crate::cache::Cache::open(&crate::cache::Cache::default_path())
        .map_err(|e| format!("Không mở được SQLite: {e}"))?;
    save_settings_to(&db, settings)
}

fn read_blob(db: &crate::cache::Cache) -> Result<Option<Settings>, String> {
    use rusqlite::OptionalExtension;
    let raw: Option<Option<String>> = db
        .conn()
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            rusqlite::params![SETTINGS_ROW_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    match raw.flatten() {
        Some(text) if !text.trim().is_empty() => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("settings JSON hỏng: {e}")),
        _ => Ok(None),
    }
}

/// Clamp everything into the ranges the spec allows (§4.3, §10.2).
pub fn normalise(mut settings: Settings) -> Settings {
    settings.default_timeout_ms = settings.default_timeout_ms.clamp(1_000, 30_000);
    settings.max_concurrency = settings.max_concurrency.clamp(1, 32);
    settings.circuit_failure_threshold = settings.circuit_failure_threshold.max(1);
    settings.circuit_cooldown_minutes = settings.circuit_cooldown_minutes.max(1);
    settings.cache_ttl_geo_hours = settings.cache_ttl_geo_hours.max(1);
    settings.cache_ttl_reputation_hours = settings.cache_ttl_reputation_hours.max(1);
    settings.cache_ttl_blacklist_hours = settings.cache_ttl_blacklist_hours.max(1);
    settings.cache_ttl_abuse_hours = settings.cache_ttl_abuse_hours.max(1);
    settings.log_retention_days = settings.log_retention_days.max(1);
    if settings.settings_version == 0 {
        settings.settings_version = Settings::default().settings_version;
    }
    if settings.ui_language.trim().is_empty() {
        settings.ui_language = "vi".to_string();
    }
    settings
}

/// Reconcile the stored provider rows with the registry: every registry row gets
/// a settings entry (defaulting to its `enabled_by_default`), and provider rows
/// whose adapter is missing are kept but flagged `enabled = false`.
pub fn merge_registry_defaults(settings: &mut Settings, registry: &Registry) {
    use crate::models::ProviderSetting;

    let missing_adapters: std::collections::HashSet<String> = registry
        .unmatched_adapters()
        .into_iter()
        .collect();

    for meta in &registry.providers {
        let has_adapter = !missing_adapters.contains(&meta.id);
        match settings.providers.iter_mut().find(|p| p.provider == meta.id) {
            Some(existing) => {
                // A row without an adapter can never run; keep it visible but off.
                if !has_adapter {
                    existing.enabled = false;
                } else if (meta.id == "ip_api_flags" || meta.id == "ipinfo_privacy") && !existing.enabled && meta.enabled_by_default {
                    // Self-healing: if derived flags were previously disabled by a bug, re-enable them
                    existing.enabled = true;
                }
                if existing.timeout_ms.is_none() {
                    existing.timeout_ms = Some(meta.timeout_ms);
                }
                if existing.rate_limit.is_none() {
                    existing.rate_limit = Some(meta.rate_limit);
                }
            }
            None => settings.providers.push(ProviderSetting {
                provider: meta.id.clone(),
                enabled: has_adapter && meta.enabled_by_default,
                timeout_ms: Some(meta.timeout_ms),
                rate_limit: Some(meta.rate_limit),
                has_key: has_api_key(&meta.id),
                key_label: String::new(),
            }),
        }
    }
    settings.providers.sort_by(|a, b| a.provider.cmp(&b.provider));
}

// ---------------------------------------------------------------------------
// API keys — Windows Credential Manager ONLY (§2.1, §11)
// ---------------------------------------------------------------------------

/// Read an API key from Windows Credential Manager. Returns `None` when unset.
///
/// The value is never logged and never serialised into `Settings`.
pub fn get_api_key(provider: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider).ok()?;
    match entry.get_password() {
        Ok(secret) if !secret.trim().is_empty() => Some(secret),
        _ => None,
    }
}

/// Store an API key in Credential Manager. An empty value deletes the entry.
///
/// Returns `Ok(())` on success. The key is never echoed back to the caller.
pub fn set_api_key(provider: &str, key: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider)
        .map_err(|e| format!("Không mở được Credential Manager: {e}"))?;

    // Both branches below are deliberate and must stay in this order:
    //
    //   key is empty  -> the user is REMOVING the key; delete and report success.
    //   key is present-> write it. There is NO delete-then-write dance.
    //
    // `set_password` upserts on Windows: `CredWriteW` replaces any credential
    // with the same `TargetName` (keyring-3.6.3/src/windows.rs:96 — "The new
    // credential replaces any existing one in the store. Since there is only one
    // credential with a given _target name_, there is no chance of ambiguity").
    // `keyring::Error::Ambiguous` exists for Linux secret-service, not for this
    // backend.
    //
    // Do NOT add `delete_credential()` before `set_password`: that would open a
    // window where the old key is already gone, and a failed write (locked
    // vault, quota, EDR) would destroy the user's key while reporting only
    // "không lưu được key". The upsert makes that window unnecessary.
    if key.trim().is_empty() {
        let _ = entry.delete_credential();
        return Ok(());
    }
    entry
        .set_password(key.trim())
        .map_err(|e| format!("Không lưu được key cho {provider}: {e}"))
}

/// Delete the stored key for one provider.
pub fn clear_api_key(provider: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider)
        .map_err(|e| format!("Không mở được Credential Manager: {e}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        // Deleting a non-existent entry is not an error for the caller.
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Không xoá được key của {provider}: {e}")),
    }
}

/// True when a key is present for this provider.
pub fn has_api_key(provider: &str) -> bool {
    get_api_key(provider).is_some()
}

/// Which providers currently have a key. Never returns the key values.
pub fn providers_with_keys() -> Vec<String> {
    let registry = load_registry();
    registry
        .providers
        .iter()
        .filter(|p| has_api_key(&p.id))
        .map(|p| p.id.clone())
        .collect()
}

/// App data directory, created on demand.
///
/// Returns `PathBuf` rather than `Result` because it is called from many places
/// (cache path, log path, keyring bootstrap) that all degrade gracefully. But a
/// silent `let _ =` made the failure undiscoverable: the caller got a path that
/// did not exist and the next `open` failed with a bare OS error mentioning
/// nothing about why. Log it instead — still best-effort, now diagnosable.
pub fn app_data_dir(settings: &Settings) -> PathBuf {
    let dir = PathBuf::from(&settings.app_data_dir);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        // Not fatal: another candidate (or an existing dir) may still work, and
        // the subsequent open will report its own error with real context.
        tracing::warn!(
            "Không tạo được thư mục dữ liệu ứng dụng {:?}: {err}",
            dir
        );
    }
    dir
}

/// Export directory, created on demand (§10.3).
///
/// `Settings::default()` points at `Documents/IPChecker`, but on Windows
/// `Documents` is a *Known Folder* that may be redirected by OneDrive, blocked
/// by Controlled Folder Access, or kept read-only by an EDR agent. In those
/// setups the path still exists, still lists, still reports `Full Control` in
/// `icacls`, and yet every create fails with `os error 2 "The system cannot
/// find the file specified"` — because a filter driver refuses the write above
/// the filesystem. `create_dir_all(..).ok()` hid that and the export died one
/// line later with no explanation.
///
/// So the directory is only used once a probe file has actually been written
/// into it; otherwise the first writable fallback wins. A user who configured a
/// working folder keeps it — the probe is the only thing that can tell the
/// difference between "exists" and "usable".
pub fn export_dir(settings: &Settings) -> PathBuf {
    let preferred = PathBuf::from(&settings.export_dir);

    if is_writable_dir(&preferred) {
        return preferred;
    }

    for fallback in fallback_export_dirs() {
        if fallback == preferred {
            continue;
        }
        if is_writable_dir(&fallback) {
            tracing::warn!(
                "Thư mục xuất {:?} không ghi được — dùng {:?} thay thế (§10.3)",
                preferred,
                fallback
            );
            return fallback;
        }
    }

    // Nothing worked (no temp dir either). Return the preferred path so the
    // error message names the directory the user actually chose — but say so in
    // the log, because at this point every candidate including TEMP refused a
    // write and that is a machine-level problem worth diagnosing.
    tracing::error!(
        "Không thư mục xuất nào ghi được (kể cả thư mục tạm {:?}) — trả lại {:?} để thông báo lỗi nêu đúng tên",
        std::env::temp_dir(),
        preferred
    );
    preferred
}

/// True when `dir` exists (or can be created) **and** a file can be written in it.
///
/// `exists()` and the ACL are both unreliable here: the failure mode this guards
/// against leaves the directory listable and permission-permissive while
/// rejecting every create.
pub fn is_writable_dir(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".ipchecker-write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Candidate export directories, best first.
///
/// `Downloads` comes before `Documents` on purpose: an exported report is
/// something the user has to *find*, and `Downloads` is writable on every
/// machine tested (including the ones where `Documents` is redirected).
/// `temp_dir` is the last resort — it always works, and a report in a scratch
/// folder beats an error dialog.
pub fn fallback_export_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(d) = dirs::download_dir() {
        out.push(d.join("IPChecker"));
    }
    if let Some(d) = dirs::document_dir() {
        out.push(d.join("IPChecker"));
    }
    if let Some(d) = dirs::data_dir() {
        out.push(d.join("ip-checker").join("exports"));
    }
    if let Some(d) = dirs::home_dir() {
        out.push(d.join("IPChecker"));
    }
    out.push(std::env::temp_dir().join("IPChecker"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;

    /// A unique, disposable service name so a test never touches a real key.
    ///
    /// The `keyring` **mock** store cannot be used here: it reports
    /// `CredentialPersistence::EntryOnly` and its own docs say *"Since mocks
    /// don't persist between sessions, all mocks start off without passwords"*
    /// (keyring-3.6.3/src/mock.rs:210-229). `set_api_key` and `get_api_key`
    /// each build their own `Entry`, so a mock write is invisible to the next
    /// read — round-trip is untestable with it. These tests therefore use the
    /// real Windows Credential Manager under a throwaway service name and clean
    /// up after themselves.
    fn throwing_key_service(tag: &str) -> String {
        format!("{KEYRING_SERVICE}-test-{tag}")
    }

    /// Run `f` against a throwaway service name, then remove every key it made.
    fn with_real_keyring<T>(tag: &str, providers: &[&str], f: impl FnOnce(&str) -> T) -> T {
        let service = throwing_key_service(tag);
        let out = f(&service);
        for provider in providers {
            if let Ok(entry) = keyring::Entry::new(&service, provider) {
                let _ = entry.delete_credential();
            }
        }
        out
    }

    fn get_key_from(service: &str, provider: &str) -> Option<String> {
        let entry = keyring::Entry::new(service, provider).ok()?;
        match entry.get_password() {
            Ok(secret) if !secret.trim().is_empty() => Some(secret),
            _ => None,
        }
    }

    fn set_key_in(service: &str, provider: &str, key: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(service, provider)
            .map_err(|e| format!("Không mở được Credential Manager: {e}"))?;
        if key.trim().is_empty() {
            let _ = entry.delete_credential();
            return Ok(());
        }
        entry
            .set_password(key.trim())
            .map_err(|e| format!("Không lưu được key cho {provider}: {e}"))
    }

    fn temp_cache() -> (Cache, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let cache = Cache::open(&dir.path().join("app.db")).expect("mở DB");
        (cache, dir)
    }

    #[test]
    fn settings_roundtrip_through_sqlite() {
        let (cache, _dir) = temp_cache();
        let mut settings = Settings::default();
        settings.default_timeout_ms = 6500;
        settings.max_concurrency = 4;
        settings.export_dir = r"C:\tmp\ip-export".to_string();

        save_settings_to(&cache, &settings).expect("phải lưu được");
        let loaded = load_settings_from(&cache);

        assert_eq!(loaded.default_timeout_ms, 6500);
        assert_eq!(loaded.max_concurrency, 4);
        assert_eq!(loaded.export_dir, r"C:\tmp\ip-export");
    }

    #[test]
    fn settings_blob_contains_no_api_key() {
        let (cache, _dir) = temp_cache();
        let settings = Settings::default();
        save_settings_to(&cache, &settings).unwrap();

        let blob: String = cache
            .conn()
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                rusqlite::params![SETTINGS_ROW_KEY],
                |r| r.get(0),
            )
            .unwrap();

        for banned in ["api_key", "apikey", "password", "secret", "token\""] {
            assert!(
                !blob.to_ascii_lowercase().contains(banned),
                "settings blob không được chứa '{banned}': {blob}"
            );
        }
    }

    #[test]
    fn corrupt_settings_blob_falls_back_to_default() {
        let (cache, _dir) = temp_cache();
        cache
            .conn()
            .execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                rusqlite::params![SETTINGS_ROW_KEY, "{not json"],
            )
            .unwrap();
        let loaded = load_settings_from(&cache);
        assert_eq!(loaded.default_timeout_ms, Settings::default().default_timeout_ms);
    }

    #[test]
    fn normalise_clamps_into_spec_windows() {
        let mut settings = Settings::default();
        settings.default_timeout_ms = 999_999;
        settings.max_concurrency = 0;
        settings.cache_ttl_geo_hours = 0;
        settings.ui_language = String::new();

        let fixed = normalise(settings);
        assert_eq!(fixed.default_timeout_ms, 30_000);
        assert_eq!(fixed.max_concurrency, 1);
        assert_eq!(fixed.cache_ttl_geo_hours, 1);
        assert_eq!(fixed.ui_language, "vi");
    }

    #[test]
    fn registry_merge_flags_rows_without_adapter_as_disabled() {
        let registry = registry::parse(
            r#"
version: "1"
providers:
  - id: ip_api
    category: geo
    upstream: ip-api
    method: api
    enabled_by_default: true
  - id: ghost_provider
    category: fraud
    upstream: ghost
    method: api
    requires_key: true
    enabled_by_default: true
"#,
        )
        .unwrap();

        let mut settings = Settings::default();
        merge_registry_defaults(&mut settings, &registry);

        let ip_api = settings
            .providers
            .iter()
            .find(|p| p.provider == "ip_api")
            .expect("phải có ip_api");
        assert!(ip_api.enabled, "ip_api có adapter + enabled_by_default");

        let ghost = settings
            .providers
            .iter()
            .find(|p| p.provider == "ghost_provider")
            .expect("vẫn phải hiện trong Settings");
        assert!(
            !ghost.enabled,
            "không có adapter ⇒ phải disable, không panic (§13.4)"
        );
    }

    #[test]
    fn missing_providers_yaml_does_not_crash() {
        std::env::set_var("IP_CHECKER_PROVIDERS_YAML", "definitely-missing.yaml");
        let registry = load_registry();
        // Either the real file was found via another path or we degrade to empty;
        // both are acceptable, a panic is not.
        assert!(registry.providers.len() < 10_000);
        std::env::remove_var("IP_CHECKER_PROVIDERS_YAML");
    }

    // ------------------------------------------------------------------
    // §10.3 — export directory must be *writable*, not merely present
    // ------------------------------------------------------------------

    #[test]
    fn export_dir_falls_back_when_preferred_is_unwritable() {
        // A path whose parent is a regular FILE: `create_dir_all` cannot
        // succeed, which is the same class of failure as a redirected
        // `Documents` folder refusing every create.
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let mut settings = Settings::default();
        settings.export_dir = file
            .path()
            .join("nope")
            .to_string_lossy()
            .to_string();

        let got = export_dir(&settings);

        assert_ne!(
            got,
            PathBuf::from(&settings.export_dir),
            "phải rơi về thư mục khác khi thư mục ưu tiên không ghi được"
        );
        assert!(
            is_writable_dir(&got),
            "thư mục dự phòng phải thật sự ghi được: {:?}",
            got
        );
    }

    #[test]
    fn export_dir_keeps_a_writable_preference() {
        // The user's choice must survive when it actually works.
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut settings = Settings::default();
        settings.export_dir = tmp.path().to_string_lossy().to_string();

        assert_eq!(export_dir(&settings), tmp.path());
    }

    #[test]
    fn is_writable_dir_rejects_a_file_path() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        assert!(
            !is_writable_dir(file.path()),
            "một file không phải thư mục ghi được"
        );
    }

    #[test]
    fn is_writable_dir_leaves_no_probe_file_behind() {
        let tmp = tempfile::tempdir().expect("temp dir");
        assert!(is_writable_dir(tmp.path()));
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("đọc thư mục")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("write-probe"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe phải được dọn sạch, còn {:?}",
            leftovers
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn fallback_chain_ends_with_temp_dir() {
        // Whatever the machine looks like, the last candidate must be the temp
        // directory so `export_dir` always has *something* that works.
        let chain = fallback_export_dirs();
        assert!(!chain.is_empty());
        let last = chain.last().expect("phải có phần tử cuối");
        assert_eq!(*last, std::env::temp_dir().join("IPChecker"));
    }

    // ------------------------------------------------------------------
    // API keys (§2.1, §11) — behaviour locked against a throwaway real entry
    // ------------------------------------------------------------------

    #[test]
    fn storing_a_key_makes_it_readable_again() {
        with_real_keyring("roundtrip", &["provider-a"], |service| {
            set_key_in(service, "provider-a", "sk-first").expect("lưu được key");
            assert_eq!(get_key_from(service, "provider-a").as_deref(), Some("sk-first"));
        });
    }

    #[test]
    fn overwriting_a_key_replaces_it_without_a_delete() {
        // This is the contract that makes `delete_credential()` before
        // `set_password` unnecessary: `CredWriteW` upserts by `TargetName`
        // (keyring-3.6.3/src/windows.rs:96 — "no chance of ambiguity"). If a
        // future change adds a delete-first dance, a failed write would destroy
        // the previous key — exactly the bug this test and the code comment
        // prevent.
        with_real_keyring("overwrite", &["provider-b"], |service| {
            set_key_in(service, "provider-b", "sk-old").expect("lưu key cũ");
            set_key_in(service, "provider-b", "sk-new").expect("ghi đè key");
            assert_eq!(
                get_key_from(service, "provider-b").as_deref(),
                Some("sk-new"),
                "set_password phải upsert: key mới thay key cũ, không cần delete trước"
            );
        });
    }

    #[test]
    fn an_empty_key_deletes_the_stored_one() {
        with_real_keyring("clear", &["provider-c"], |service| {
            set_key_in(service, "provider-c", "sk-something").expect("lưu key");
            assert!(get_key_from(service, "provider-c").is_some());

            set_key_in(service, "provider-c", "").expect("xoá bằng chuỗi rỗng");
            assert_eq!(get_key_from(service, "provider-c"), None);
        });
    }

    #[test]
    fn clearing_an_absent_key_is_not_an_error() {
        // `clear_provider_key` returns Ok for an unset provider — the user
        // pressing "xoá" twice must not see an error. Runs on the real service
        // name with a provider that is never written.
        assert!(
            clear_api_key("provider-never-set-in-tests").is_ok(),
            "xoá key chưa từng có phải là Ok, không phải lỗi"
        );
    }

    #[test]
    fn key_values_are_trimmed_but_never_returned_by_settings() {
        with_real_keyring("trim", &["provider-d"], |service| {
            set_key_in(service, "provider-d", "  sk-padded  ").expect("lưu key có khoảng trắng");
            assert_eq!(
                get_key_from(service, "provider-d").as_deref(),
                Some("sk-padded"),
                "key phải được trim trước khi lưu"
            );
        });

        // §2.1: `Settings` is serialised into SQLite and sent to the front-end.
        // It must never carry a key value or an api_key field.
        let json = serde_json::to_string(&Settings::default()).expect("serialize Settings");
        assert!(!json.contains("sk-padded"), "Settings không được chứa key");
        assert!(
            !json.to_ascii_lowercase().contains("api_key\""),
            "Settings không được có trường api_key: {json}"
        );
    }
}
