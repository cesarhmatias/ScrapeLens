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

/// Itens de importação desabilitados durante uma gravação (A8-B7).
pub const IMPORT_MENU_IDS: [&str; 2] = ["import-har", "import-netlog"];

/// Liga/desliga Importar HAR/NetLog (e seus atalhos ⌘⇧H/⌘⇧N) no menu nativo.
pub fn set_imports_enabled<R: Runtime>(app: &AppHandle<R>, enabled: bool) {
    let Some(menu) = app.menu() else { return };
    let Ok(items) = menu.items() else { return };
    for item in items {
        if let tauri::menu::MenuItemKind::Submenu(sub) = item {
            for id in IMPORT_MENU_IDS {
                if let Some(tauri::menu::MenuItemKind::MenuItem(entry)) = sub.get(id) {
                    let _ = entry.set_enabled(enabled);
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
        if IMPORT_MENU_IDS.contains(&action.as_str()) {
            use tauri::Manager;
            let recording = app
                .try_state::<crate::AppState>()
                .map(|state| state.capture.lock().map(|slot| slot.is_some()).unwrap_or(true))
                .unwrap_or(false);
            if recording {
                return;
            }
        }
        // Copy nativo continua sendo o do sistema; o "copy" do app é emitido
        // pelo atalho da UI (⌘C) e copia a URL da requisição selecionada.
        let _ = app.emit("menu://action", action);
    });

    Ok(())
}
