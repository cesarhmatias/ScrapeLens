//! ScrapeLens — shell Tauri 2.
//!
//! A UI React (app/) consome o contrato v1 (`docs/03-contratos.md`). Os commands
//! de captura, importação e abertura operam dados reais via `scrapelens-core`
//! (dependência crate, sem sidecar); a fixture sintética existe apenas para o
//! modo demo do navegador e chega rotulada como `synthetic: true`.

pub mod adapters;
pub mod capture;
pub mod chrome;
pub mod cli;
pub mod commands;
pub mod export;
pub mod menu;
pub mod prefs;
pub mod validation;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::{Emitter, Manager};

use cli::CliAction;

#[derive(Default)]
pub struct AppState {
    pub chrome_path: Mutex<Option<PathBuf>>,
    pub last_session_dir: Mutex<Option<PathBuf>>,
    pub capture: Mutex<Option<capture::CaptureSession>>,
    /// Ação CLI de teste (`--import-har` / `--import-netlog` / `--open-capture`), consumida uma vez.
    pub pending_cli: Mutex<Option<CliAction>>,
}

/// Partida do app: limpa Chrome/perfil de capturas cujo dono morreu (ex.: SIGKILL).
/// Nunca propaga erro — falha vira log. Pode rodar fora da thread de UI.
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
            eprintln!("scrapelens: cleanup_orphans falhou (ignorado; a abertura do app segue)");
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
            if let Some(path) = prefs::load_chrome_path(app.handle()) {
                *state.chrome_path.lock().expect("chrome_path lock") = Some(path);
            }
            match cli::parse_cli_args(&std::env::args().collect::<Vec<_>>()) {
                Ok(action) => {
                    *state.pending_cli.lock().expect("pending_cli lock") = action;
                }
                Err(error) => {
                    eprintln!("scrapelens: argumento CLI inválido: {error}");
                    *state.pending_cli.lock().expect("pending_cli lock") = None;
                    // Guarda o erro para a UI mostrar no boot.
                    let _ = app.emit(
                        "cli://error",
                        error,
                    );
                }
            }
            // sobras de validações de execução (crash/kill): o trace guarda dados da sessão
            if let Ok(data) = app.path().app_data_dir() {
                validation::cleanup_on_start(&data);
            }
            // Chrome/perfil órfãos após SIGKILL do app — uma vez, fora da thread de UI.
            std::thread::spawn(|| {
                cleanup_orphans_on_start(&capture::default_state_root());
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::demo_session,
            commands::open_session,
            commands::import_har,
            commands::import_netlog,
            commands::start_session,
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
        .expect("erro ao iniciar o ScrapeLens")
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

    /// Espelha o contrato do marcador da Captura (ownerPid morto → limpeza).
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

        // mesma entrada que o setup do Tauri chama (aqui síncrono, como cleanup_on_start)
        cleanup_orphans_on_start(&root);

        assert!(root.is_dir(), "a raiz de estado continua");
        assert!(!marker.exists(), "marcador de PID morto foi removido");
        assert!(!profile.exists(), "perfil dedicado do marcador foi removido");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&profile);
    }
}
