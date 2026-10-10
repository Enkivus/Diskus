//! Diskus — a desktop app for finding exactly what is consuming storage, and
//! what is wasted.
//!
//! This crate is only the Tauri shell. Everything interesting lives in
//! `diskus-core`, which has no Tauri dependency and is unit-tested headlessly.
//! That split exists so the analysis pipeline can be tested without spinning up
//! a window, and so the privacy guarantee can be enforced structurally: the
//! core crate has no networking dependency at all, so there is no code path that
//! could transmit file data even by accident.

mod commands;
mod state;

use diskus_core::config::ScanConfig;
use state::AppState;
use std::sync::Arc;

/// Build and run the application.
///
/// # Panics
///
/// Panics only if Tauri cannot create the runtime, which is unrecoverable for a
/// GUI application and not something a user can act on.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = Arc::new(AppState::default());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        // Hand the app an Arc so the scan guard can reach it during unwinding.
        .manage(Arc::clone(&state))
        .setup(move |_app| {
            state::install(Arc::clone(&state));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_default_config,
            commands::list_volumes,
            commands::list_user_profiles,
            commands::start_scan,
            commands::cancel_scan,
            commands::scan_status,
            commands::rerun_detect,
            commands::get_results,
            commands::export_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Diskus");
}

/// The payload shape `start_scan` accepts, mirrored into TypeScript.
///
/// Declared here only so the configuration type has a single source of truth
/// in Rust; the frontend mirrors it in `src/lib/ipc.ts`.
pub type ScanConfigPayload = ScanConfig;
