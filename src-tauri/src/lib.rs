//! ScrapeLens — shell Tauri 2.
//!
//! A UI React (app/) consome o contrato v1 (`docs/03-contratos.md`). Este
//! processo expõe os commands que o core/ Rust vai preencher; enquanto o core
//! não entrega a captura e os importadores, os commands que dependem dele
//! retornam a fixture sintética **rotulada** (`synthetic: true`) e um aviso
//! explícito. Nada é apresentado como captura real.

pub mod capture;
pub mod chrome;
pub mod commands;
pub mod menu;
pub mod prefs;

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
            commands::reveal_path,
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o ScrapeLens");
}
