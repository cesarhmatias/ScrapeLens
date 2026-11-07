//! The Chrome the App uses: detection, and the browser the user chooses.

use super::*;

#[tauri::command]
pub fn detect_chrome(state: State<'_, AppState>) -> ChromeStatus {
    let saved = state.chrome_path.lock().expect("chrome_path lock").clone();
    let notice = state
        .chrome_notice
        .lock()
        .expect("chrome_notice lock")
        .clone();
    let mut info = chrome::detect(saved.as_deref());
    // `detect` takes the first file it finds; keep only a browser the App accepts.
    let refused = info
        .path
        .as_deref()
        .is_some_and(|path| crate::browser_check::accept(Path::new(path)).is_err());
    if refused {
        match crate::browser_check::first_accepted(&info.candidates) {
            Some(path) => {
                info.path = Some(path.display().to_string());
                info.found = true;
                info.source = "detected".to_string();
            }
            None => {
                info.path = None;
                info.found = false;
                info.source = "none".to_string();
            }
        }
    }
    ChromeStatus { info, notice }
}

/// The Chrome status the window shows: what was found (only browsers the App accepts), and why
/// a saved browser preference was not used, if it was not.
#[derive(Debug, Clone, Serialize)]
pub struct ChromeStatus {
    #[serde(flatten)]
    pub info: ChromeInfo,
    pub notice: Option<String>,
}

#[tauri::command]
pub async fn choose_chrome(app: AppHandle) -> Result<Option<ChromeInfo>, String> {
    let pick = if cfg!(target_os = "macos") {
        Pick::Folder
    } else {
        Pick::OpenFile
    };
    let Some(path) = pick_path(&app, "Select Google Chrome", pick, None, None).await? else {
        return Ok(None);
    };
    set_chrome_path_from(&app, &path).map(Some)
}

/// Validates a Chrome the user picked and saves it (see `browser_check`); nothing is run.
pub(super) fn set_chrome_path_from(app: &AppHandle, path: &Path) -> Result<ChromeInfo, String> {
    let state = app.state::<AppState>();
    let resolved = chrome::normalize_binary_path(path)
        .ok_or_else(|| format!("could not find the Chrome binary at {}", path.display()))?;
    if !resolved.is_file() {
        return Err(format!(
            "the chosen path is not an executable: {}",
            resolved.display()
        ));
    }
    // Only a Chromium-based browser is accepted (see `browser_check`); nothing is run.
    let resolved = crate::browser_check::accept(&resolved)?;
    prefs::save_chrome_path(app, &resolved)?;
    *state.chrome_path.lock().expect("chrome_path lock") = Some(resolved.clone());
    *state.chrome_notice.lock().expect("chrome_notice lock") = None;
    Ok(ChromeInfo {
        found: true,
        path: Some(resolved.display().to_string()),
        source: "manual".to_string(),
        candidates: chrome::candidates(),
    })
}
