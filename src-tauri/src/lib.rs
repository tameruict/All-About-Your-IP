//! IP Checker — Tauri v2 library root.
//!
//! Module layout mirrors spec §2.3. Each module owns one responsibility and is
//! wired together by `orchestrator`; `commands` is the only IPC surface.
//!
//! Ownership note for parallel agents: this file is scaffold-owned. Add modules
//! to the `pub mod` list here, then put the logic in the module's own file.

pub mod asn;
pub mod browser_leak;
pub mod cache;
pub mod commands;
pub mod config;
pub mod dnsbl;
pub mod exit_ip;
pub mod export;
pub mod geo_db;
pub mod location;
pub mod models;
pub mod network;
pub mod orchestrator;
pub mod providers;
pub mod scoring;
pub mod speed;
pub mod state;
pub mod validator;

use tauri::Manager;

/// Build and run the Tauri application.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,ip_checker_lib=debug")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Shared state: SQLite handle, provider registry, settings.
            let state = state::AppState::new();
            app.manage(state);

            // Log where the local DB lives so support requests are actionable.
            if let Some(state) = app.try_state::<state::AppState>() {
                if let Ok(cache) = state.cache.lock() {
                    tracing::info!("SQLite: {}", cache.path().display());
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::check_ip,
            commands::check_ip_stream,
            commands::get_history,
            commands::get_check_detail,
            commands::export_report,
            commands::get_provider_health,
            commands::save_settings,
            commands::get_settings,
            // Settings-panel extensions: API keys live in Windows Credential
            // Manager (§2.1), geo DB versions are shown in Settings (§7.3).
            commands::save_provider_key,
            commands::clear_provider_key,
            commands::get_geo_db_versions,
            // External links: the webview has no new-window handler of its own.
            commands::open_external,
        ])
        .run(tauri::generate_context!())
        .expect("Lỗi khi chạy IP Checker");
}
