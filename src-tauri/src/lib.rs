//! ScrapeLens — shell Tauri 2.
//!
//! A UI React (app/) consome o contrato v1 (`docs/03-contratos.md`). Os commands
//! de captura, importação e abertura operam dados reais via `scrapelens-core`
//! (dependência crate, sem sidecar); a fixture sintética existe apenas para o
//! modo demo do navegador e chega rotulada como `synthetic: true`.

pub mod adapters;
pub mod capture;
pub mod chrome;
pub mod commands;
pub mod export;
pub mod menu;
pub mod prefs;
pub mod validation;

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::Manager;

#[derive(Default)]
pub struct AppState {
    pub chrome_path: Mutex<Option<PathBuf>>,
    pub last_session_dir: Mutex<Option<PathBuf>>,
    pub capture: Mutex<Option<capture::CaptureSession>>,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            menu::install(app.handle())?;
            if let Some(path) = prefs::load_chrome_path(app.handle()) {
                let state = app.state::<AppState>();
                *state.chrome_path.lock().expect("chrome_path lock") = Some(path);
            }
            // sobras de validações de execução (crash/kill): o trace guarda dados da sessão
            if let Ok(data) = app.path().app_data_dir() {
                validation::cleanup_on_start(&data);
            }
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
