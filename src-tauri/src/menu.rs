//! Menu nativo do macOS com os atalhos usuais da spec.
//! O evento chega à UI como `menu://action` com um destes payloads:
//! open | import-har | import-netlog | start-session | stop-session |
//! find | copy | theme | demo | choose-chrome.
//!
//! Atalhos nativos (funcionam via invoke_menu / menu bar, sem foco na WebView):
//! Abrir captura… ⌘O · Importar HAR… ⌘⇧H · Importar NetLog… ⌘⇧N ·
//! Iniciar sessão ⌘⇧R · Encerrar ⌘.

use tauri::menu::{
    MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder,
};
use tauri::{AppHandle, Emitter, Runtime};

/// Itens desabilitados durante uma gravação (A8-B7): importações e Iniciar (⌘⇧R).
pub const RECORDING_DISABLED_IDS: [&str; 3] = ["import-har", "import-netlog", "start-session"];

/// O menu não toca no `capture.lock()` (A9-B8): `start_session` pode segurá-lo
/// por até 35 s; o estado vem do `AtomicBool` `recording`.
pub fn blocked_while_recording(action: &str, recording: &std::sync::atomic::AtomicBool) -> bool {
    RECORDING_DISABLED_IDS.contains(&action) && recording.load(std::sync::atomic::Ordering::SeqCst)
}

/// Liga/desliga Importar HAR/NetLog e Iniciar sessão (com ⌘⇧H, ⌘⇧N e ⌘⇧R).
pub fn set_recording_menu<R: Runtime>(app: &AppHandle<R>, recording: bool) {
    let Some(menu) = app.menu() else { return };
    let Ok(items) = menu.items() else { return };
    for item in items {
        if let tauri::menu::MenuItemKind::Submenu(sub) = item {
            for id in RECORDING_DISABLED_IDS {
                if let Some(tauri::menu::MenuItemKind::MenuItem(entry)) = sub.get(id) {
                    let _ = entry.set_enabled(!recording);
                }
            }
        }
    }
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let app_menu = SubmenuBuilder::new(app, "ScrapeLens")
        .item(&PredefinedMenuItem::about(app, None, None)?)
        .separator()
        .item(&PredefinedMenuItem::hide(app, None)?)
        .item(&PredefinedMenuItem::hide_others(app, None)?)
        .separator()
        .item(&PredefinedMenuItem::quit(app, None)?)
        .build()?;

    let file_menu = SubmenuBuilder::new(app, "Arquivo")
        .item(
            &MenuItemBuilder::with_id("open", "Abrir captura…")
                .accelerator("CmdOrCtrl+O")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("import-har", "Importar HAR…")
                .accelerator("CmdOrCtrl+Shift+H")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("import-netlog", "Importar NetLog…")
                .accelerator("CmdOrCtrl+Shift+N")
                .build(app)?,
        )
        .separator()
        .item(&MenuItemBuilder::with_id("choose-chrome", "Selecionar Chrome…").build(app)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("demo", "Carregar demonstração")
                .accelerator("CmdOrCtrl+Shift+D")
                .build(app)?,
        )
        .separator()
        .item(&PredefinedMenuItem::close_window(app, None)?)
        .build()?;

    let capture_menu = SubmenuBuilder::new(app, "Captura")
        .item(
            &MenuItemBuilder::with_id("start-session", "Iniciar sessão")
                .accelerator("CmdOrCtrl+Shift+R")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("stop-session", "Encerrar")
                .accelerator("CmdOrCtrl+.")
                .build(app)?,
        )
        .build()?;

    let edit_menu = SubmenuBuilder::new(app, "Editar")
        .item(&PredefinedMenuItem::undo(app, None)?)
        .item(&PredefinedMenuItem::redo(app, None)?)
        .separator()
        .item(&PredefinedMenuItem::cut(app, None)?)
        .item(&PredefinedMenuItem::copy(app, None)?)
        .item(&PredefinedMenuItem::paste(app, None)?)
        .item(&PredefinedMenuItem::select_all(app, None)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("copy", "Copiar URL da requisição")
                .accelerator("CmdOrCtrl+Shift+C")
                .build(app)?,
        )
        .separator()
        .item(
            &MenuItemBuilder::with_id("find", "Buscar requisições")
                .accelerator("CmdOrCtrl+F")
                .build(app)?,
        )
        .build()?;

    let view_menu = SubmenuBuilder::new(app, "Visualizar")
        .item(&MenuItemBuilder::with_id("theme", "Alternar tema claro/escuro").build(app)?)
        .item(&PredefinedMenuItem::fullscreen(app, None)?)
        .build()?;

    let window_menu = SubmenuBuilder::new(app, "Janela")
        .item(&PredefinedMenuItem::minimize(app, None)?)
        .item(&PredefinedMenuItem::maximize(app, None)?)
        .build()?;

    let menu = MenuBuilder::new(app)
        .items(&[
            &app_menu,
            &file_menu,
            &capture_menu,
            &edit_menu,
            &view_menu,
            &window_menu,
        ])
        .build()?;
    app.set_menu(menu)?;

    app.on_menu_event(|app, event| {
        let action = event.id().as_ref().to_string();
        {
            use tauri::Manager;
            if let Some(state) = app.try_state::<crate::AppState>() {
                if blocked_while_recording(&action, &state.recording) {
                    return;
                }
            }
        }
        let _ = app.emit("menu://action", action);
    });

    Ok(())
}
