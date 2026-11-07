//! Native dialogs the backend opens, and the pickers that hand back tokens for what was chosen.

use super::*;

/// Which native dialog to open.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pick {
    Folder,
    OpenFile,
    SaveFile,
}

/// A native dialog in the backend: the path the user chooses, or `None` if cancelled. The path
/// stays here; a command that must hand a path to the webview returns a token for it instead.
pub(super) async fn pick_path(
    app: &AppHandle,
    title: &str,
    pick: Pick,
    filter: Option<(&str, &[&str])>,
    default_name: Option<String>,
) -> Result<Option<PathBuf>, String> {
    let app = app.clone();
    let title = title.to_string();
    let filter = filter.map(|(name, extensions)| {
        (
            name.to_string(),
            extensions
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>(),
        )
    });
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app.dialog().file().set_title(title);
        if let Some(name) = default_name {
            dialog = dialog.set_file_name(name);
        }
        if let Some((name, extensions)) = filter {
            let extensions: Vec<&str> = extensions.iter().map(String::as_str).collect();
            dialog = dialog.add_filter(name, &extensions);
        }
        match pick {
            Pick::Folder => dialog.blocking_pick_folder(),
            Pick::OpenFile => dialog.blocking_pick_file(),
            Pick::SaveFile => dialog.blocking_save_file(),
        }
    })
    .await
    .map_err(|error| format!("the dialog was interrupted: {error}"))?;
    picked
        .map(|path| {
            path.into_path()
                .map_err(|error| format!("the chosen location is not usable: {error}"))
        })
        .transpose()
}

/// The file behind an import token (HAR, NetLog or trace).
pub(super) fn import_path_for_token(token: &str) -> Result<String, String> {
    Ok(grants::resolve(token, &[grants::Kind::ImportFile])?
        .display()
        .to_string())
}

/// The file to import: the token's file, or the file the user picks (`None` if cancelled).
pub(super) async fn import_path(
    app: &AppHandle,
    token: Option<String>,
    title: &str,
    name: &str,
    extensions: &[&str],
) -> Result<Option<String>, String> {
    match token {
        Some(token) => Ok(Some(import_path_for_token(&token)?)),
        None => Ok(
            pick_path(app, title, Pick::OpenFile, Some((name, extensions)), None)
                .await?
                .map(|path| path.display().to_string()),
        ),
    }
}

/// A file or folder the user picked in the backend's dialog: a token for the webview, and the path
/// for display only (the webview never passes the path back).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedPath {
    pub token: String,
    pub path: String,
}

/// The execution trace (`scrapelens.trace/1`) to validate; `None` if cancelled.
#[tauri::command]
pub async fn pick_trace_file(app: AppHandle) -> Result<Option<PickedPath>, String> {
    let Some(path) = pick_path(
        &app,
        "Choose the trace of the script run",
        Pick::OpenFile,
        Some(("Trace", &["json"][..])),
        None,
    )
    .await?
    else {
        return Ok(None);
    };
    let token = grants::issue(grants::Kind::ImportFile, &path)?;
    Ok(Some(PickedPath {
        token,
        path: path.display().to_string(),
    }))
}

/// The second session to compare (a folder); `None` if cancelled.
#[tauri::command]
pub async fn pick_compare_session(app: AppHandle) -> Result<Option<PickedPath>, String> {
    let Some(path) = pick_path(
        &app,
        "Choose the 2nd capture (session B folder)",
        Pick::Folder,
        None,
        None,
    )
    .await?
    else {
        return Ok(None);
    };
    let token = grants::issue(grants::Kind::Session, &path)?;
    Ok(Some(PickedPath {
        token,
        path: path.display().to_string(),
    }))
}
