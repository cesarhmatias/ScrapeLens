//! ScrapeLens — shell Tauri 2.
//!
//! The React UI (app/) consumes the v1 contract (`docs/03-contracts.md`). The capture,
//! import and open commands operate on real data via `scrapelens-core`
//! (crate dependency, no sidecar); the synthetic fixture exists only for the
//! browser demo mode and arrives labeled as `synthetic: true`.

pub mod adapters;
pub mod browser_check;
pub mod capture;
pub mod chrome;
pub mod capture_proxy;
pub mod cli;
#[cfg(feature = "test-hooks")]
pub mod cli_test;
pub mod commands;
pub mod cookie_import;
pub mod export;
pub mod listing;
pub mod menu;
pub mod prefs;
pub mod validation;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::Manager;

#[cfg(feature = "test-hooks")]
use cli_test::CliAction;

#[derive(Default)]
pub struct AppState {
    pub chrome_path: Mutex<Option<PathBuf>>,
    pub last_session_dir: Mutex<Option<PathBuf>>,
    pub capture: Mutex<Option<capture::CaptureSession>>,
    /// Test CLI action (`--import-har` / `--import-netlog` / `--open-capture`), consumed once.
    #[cfg(feature = "test-hooks")]
    pub pending_cli: Mutex<Option<CliAction>>,
    /// Error or warning from the test CLI for the window to show (consumed once).
    #[cfg(feature = "test-hooks")]
    pub cli_message: Mutex<Option<(String, String)>>,
    /// Recording in progress; read by the menu without blocking (A9-B8).
    pub recording: std::sync::atomic::AtomicBool,
    /// Opening/importing/closing in progress: refuses a second one in parallel.
    pub loading: std::sync::atomic::AtomicBool,
    /// The proxy link the user gave, credentials included. Memory only: never serialized,
    /// never saved, gone when the app closes.
    pub proxy: Mutex<Option<scrapelens_capture::proxy::ProxyLink>>,
}

/// App startup: cleans up Chrome/profile of captures whose owner died (e.g. SIGKILL).
/// Never propagates errors — a failure becomes a log entry. May run off the UI thread.
pub fn cleanup_orphans_on_start(state_root: &Path) {
    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture::cleanup_orphans(state_root)
    }));
    match report {
        Ok(report) => {
            eprintln!(
                "scrapelens: cleanup_orphans markers_removed={} processes_killed={} profiles_removed={}",
                report.markers_removed, report.processes_killed, report.profiles_removed
            );
        }
        Err(_) => {
            eprintln!("scrapelens: cleanup_orphans failed (ignored; app startup continues)");
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            menu::install(app.handle())?;
            let state = app.state::<AppState>();
            // A saved browser is used only if it still passes the browser check (an old or
            // edited preference may point at a shell or a script); otherwise detection runs.
            if let Some(path) = prefs::load_chrome_path(app.handle()).and_then(|p| browser_check::accept(&p).ok()) {
                *state.chrome_path.lock().expect("chrome_path lock") = Some(path);
            }
            // Test-only command line: release builds read no arguments and no test variable.
            #[cfg(feature = "test-hooks")]
            {
                let args = std::env::args().collect::<Vec<_>>();
                let test_mode = std::env::var("SCRAPELENS_TEST_MODE").ok();
                match cli_test::cli_outcome(&args, test_mode.as_deref()) {
                    cli_test::CliOutcome::None => {}
                    cli_test::CliOutcome::Action(action) => {
                        *state.pending_cli.lock().expect("pending_cli lock") = Some(action);
                    }
                    cli_test::CliOutcome::Ignored(warning) => {
                        eprintln!("scrapelens: {warning}");
                        *state.cli_message.lock().expect("cli_message lock") = Some(("warning".into(), warning));
                    }
                    cli_test::CliOutcome::Error(error) => {
                        eprintln!("scrapelens: invalid CLI argument: {error}");
                        *state.cli_message.lock().expect("cli_message lock") = Some(("error".into(), error));
                    }
                }
            }
            // leftovers from execution validations (crash/kill): the trace keeps session data
            if let Ok(data) = app.path().app_data_dir() {
                validation::cleanup_on_start(&data);
            }
            // Orphaned Chrome/profile after the app was SIGKILLed — once, off the UI thread.
            std::thread::spawn(|| {
                cleanup_orphans_on_start(&capture::default_state_root());
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::demo_session,
            commands::open_session,
            commands::list_requests,
            commands::get_request,
            commands::import_har,
            commands::import_netlog,
            commands::start_session,
            commands::list_cookie_sources,
            commands::set_capture_cookie_source,
            commands::get_proxy_state,
            commands::set_proxy_link,
            commands::clear_proxy_link,
            commands::stop_session,
            commands::capture_status,
            commands::capture_start_url,
            commands::set_capture_start_url,
            commands::take_cli_action,
            commands::detect_chrome,
            commands::set_chrome_path,
            commands::read_attachment,
            commands::search_session,
            commands::read_body,
            commands::request_origins,
            commands::request_chain,
            commands::assess_session,
            commands::adapter_view,
            commands::session_timeline,
            commands::validate_execution,
            commands::discard_validation,
            commands::keep_validation,
            commands::compare_open,
            commands::compare_page,
            commands::compare_fields,
            commands::export_request,
            commands::save_export_file,
            commands::preview_sanitized,
            commands::save_sanitized,
            commands::reveal_path,
        ])
        .build(tauri::generate_context!())
        .expect("error starting ScrapeLens")
        .run(|handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Ok(data) = handle.path().app_data_dir() {
                    validation::cleanup_all(&data.join("validate-tmp"));
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// Mirrors the capture marker contract (dead ownerPid → cleanup).
    #[test]
    fn startup_removes_orphan_capture_with_dead_owner() {
        let tag = format!("app-startup-{}-{}", std::process::id(), millis());
        let root = std::env::temp_dir().join(format!("scrapelens-capture-state-test-{tag}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let profile = std::env::temp_dir().join(format!(
            "scrapelens-chrome-test-{tag}"
        ));
        let _ = fs::remove_dir_all(&profile);
        fs::create_dir_all(profile.join("Default")).unwrap();
        fs::write(profile.join("Default/Prefs"), b"{}").unwrap();

        let marker = root.join(format!("capture-{tag}.json"));
        let body = serde_json::json!({
            "ownerPid": dead_pid(),
            "chromePid": dead_pid(),
            "profile": profile.display().to_string(),
            "port": 9999,
        });
        fs::write(&marker, body.to_string()).unwrap();
        assert!(marker.exists());
        assert!(profile.exists());

        // same entry point that Tauri's setup calls (synchronous here, like cleanup_on_start)
        cleanup_orphans_on_start(&root);

        assert!(root.is_dir(), "the state root still exists");
        assert!(!marker.exists(), "dead-PID marker was removed");
        assert!(!profile.exists(), "dedicated profile of the marker was removed");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&profile);
    }
}
