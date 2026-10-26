//! Shared application state injected into commands via `State<AppState>`.
//!
//! Phase 0: holds the SQLite handle and two locks. Provider statistics, the
//! circuit breaker table and the HTTP client pool get added in phase 1 — keep
//! adding fields here rather than changing command signatures.

use std::sync::Mutex;

use tokio::sync::RwLock;

use crate::cache::Cache;
use crate::models::Settings;
use crate::providers::registry::Registry;

/// Singleton managed by Tauri (`app.manage(AppState::new())`).
pub struct AppState {
    /// Local SQLite (history + cache). `Mutex` because rusqlite is not `Sync`.
    pub cache: Mutex<Cache>,
    /// Provider registry loaded from `providers.yaml`.
    pub registry: RwLock<Registry>,
    /// Currently active settings (also persisted to the `settings` table).
    pub settings: RwLock<Settings>,
    /// Serialises settings read/write so a save cannot race a check.
    pub settings_lock: RwLock<()>,
}

impl AppState {
    pub fn new() -> Self {
        let cache = match Cache::open(&Cache::default_path()) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!("Không mở được SQLite: {err} — dùng DB tạm trong RAM");
                Cache::open_in_memory().expect("in-memory SQLite phải mở được")
            }
        };

        Self {
            cache: Mutex::new(cache),
            registry: RwLock::new(crate::config::load_registry()),
            settings: RwLock::new(Settings::default()),
            settings_lock: RwLock::new(()),
        }
    }

    /// Replace the registry (used after a `providers.yaml` reload).
    pub async fn set_registry(&self, registry: Registry) {
        *self.registry.write().await = registry;
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
