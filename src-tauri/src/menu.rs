//! Native macOS menu with the usual shortcuts from the spec.
//! The event reaches the UI as `menu://action` with one of these payloads:
//! open | import-har | import-netlog | start-session | stop-session |
//! find | copy | theme | demo | choose-chrome.
//!
//! Native shortcuts (work via invoke_menu / menu bar, without WebView focus):
//! Open capture… ⌘O · Import HAR… ⌘⇧H · Import NetLog… ⌘⇧N ·
//! Start session ⌘⇧R · Stop ⌘.

use tauri::menu::{
    MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder,
};
use tauri::{AppHandle, Emitter, Runtime};

/// Items disabled during a recording (A8-B7): imports and Start (⌘⇧R).
pub const RECORDING_DISABLED_IDS: [&str; 3] = ["import-har", "import-netlog", "start-session"];

/// The menu does not touch `capture.lock()` (A9-B8): `start_session` can hold it
/// for up to 35 s; the state comes from the `recording` `AtomicBool`.
pub fn blocked_while_recording(action: &str, recording: &std::sync::atomic::AtomicBool) -> bool {
    RECORDING_DISABLED_IDS.contains(&action) && recording.load(std::sync::atomic::Ordering::SeqCst)
}

/// Enables/disables Import HAR/NetLog and Start session (with ⌘⇧H, ⌘⇧N and ⌘⇧R).
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

    let file_menu = SubmenuBuilder::new(app, "File")
        .item(
            &MenuItemBuilder::with_id("open", "Open capture…")
                .accelerator("CmdOrCtrl+O")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("import-har", "Import HAR…")
                .accelerator("CmdOrCtrl+Shift+H")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("import-netlog", "Import NetLog…")
                .accelerator("CmdOrCtrl+Shift+N")
                .build(app)?,
        )
        .separator()
        .item(&MenuItemBuilder::with_id("choose-chrome", "Select Chrome…").build(app)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("demo", "Load demo")
                .accelerator("CmdOrCtrl+Shift+D")
                .build(app)?,
        )
        .separator()
        .item(&PredefinedMenuItem::close_window(app, None)?)
        .build()?;

    let capture_menu = SubmenuBuilder::new(app, "Capture")
        .item(
            &MenuItemBuilder::with_id("start-session", "Start session")
                .accelerator("CmdOrCtrl+Shift+R")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("stop-session", "Stop")
                .accelerator("CmdOrCtrl+.")
                .build(app)?,
        )
        .build()?;

    let edit_menu = SubmenuBuilder::new(app, "Edit")
        .item(&PredefinedMenuItem::undo(app, None)?)
        .item(&PredefinedMenuItem::redo(app, None)?)
        .separator()
        .item(&PredefinedMenuItem::cut(app, None)?)
        .item(&PredefinedMenuItem::copy(app, None)?)
        .item(&PredefinedMenuItem::paste(app, None)?)
        .item(&PredefinedMenuItem::select_all(app, None)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("copy", "Copy request URL")
                .accelerator("CmdOrCtrl+Shift+C")
                .build(app)?,
        )
        .separator()
        .item(
            &MenuItemBuilder::with_id("find", "Find requests")
                .accelerator("CmdOrCtrl+F")
                .build(app)?,
        )
        .build()?;

    let view_menu = SubmenuBuilder::new(app, "View")
        .item(&MenuItemBuilder::with_id("theme", "Toggle light/dark theme").build(app)?)
        .item(&PredefinedMenuItem::fullscreen(app, None)?)
        .build()?;

    let window_menu = SubmenuBuilder::new(app, "Window")
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
