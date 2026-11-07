//! Exports and saved files: request exports, the sanitized session, saving and revealing files.

use super::*;

/// Priming script (full chain up to the request); uses the protocol adapter's encoder
/// when it claims the field, and reports that in the preview.
pub(super) fn priming_preview(
    dir: &Path,
    request_id: &str,
    lenient_parts: bool,
) -> Result<crate::export::ExportPreview, String> {
    let lazy = cached_session(dir)?;
    let request = lazy
        .session
        .requests
        .iter()
        .find(|r| r.id == request_id)
        .ok_or_else(|| format!("request {request_id} not found in the session"))?;
    let options = scrapelens_core::export::priming::PrimingOptions {
        flow: crate::adapters::flow_options(),
        adapter_encoders: crate::adapters::priming_encoders(),
        lenient_parts,
        ..Default::default()
    };
    let output = scrapelens_core::export::priming::to_python(
        &lazy.session,
        &scrapelens_core::search::LazyBodies(&lazy),
        request_id,
        &options,
    )
    .map_err(|error| format!("could not generate the priming script: {error}"))?;
    let adapter = crate::adapters::script_uses_adapter(&output.text).map(str::to_string);
    Ok(crate::export::ExportPreview {
        session_id: lazy.session.session.id.clone(),
        request_id: request.id.clone(),
        request_method: request.method.clone(),
        request_url: request.url.clone(),
        protocol: request.protocol.as_str().to_string(),
        header_verification: request.request_headers.verification().as_str().to_string(),
        format: "priming".to_string(),
        text: output.text,
        warnings: output.warnings,
        skipped_headers: output.skipped_headers,
        body_included: output.body_included,
        body_note: output.body_note,
        body_state: request.request_body.state.as_str().to_string(),
        adapter,
    })
}

/// Export preview; with `annotate` it calculates the origins (LazySession cache).
pub(super) fn export_preview(
    dir: &Path,
    request_id: &str,
    format: &str,
    annotate: bool,
    lenient_parts: bool,
) -> Result<crate::export::ExportPreview, String> {
    if format == "priming" {
        return priming_preview(dir, request_id, lenient_parts);
    }
    let origins = annotate.then(|| {
        cached_session(dir).and_then(|lazy| {
            scrapelens_core::flow::value_origins(
                &lazy.session,
                &scrapelens_core::search::LazyBodies(&lazy),
                request_id,
                &crate::adapters::flow_options(),
            )
            .map_err(|error| error.to_string())
        })
    });
    crate::export::preview_with(dir, request_id, format, origins)
}

/// Generates the cURL/Python export of a request from the persisted session.
///
/// Runs off the UI thread: reading attachments and generating text can be heavy on
/// large sessions. The returned text is the source for the preview, the copy and the
/// saved file.
#[tauri::command]
pub async fn export_request(
    session_token: String,
    request_id: String,
    format: String,
    annotate_origins: Option<bool>,
    lenient_parts: Option<bool>,
) -> Result<crate::export::ExportPreview, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        export_preview(
            Path::new(&session_dir),
            &request_id,
            &format,
            annotate_origins.unwrap_or(false),
            lenient_parts.unwrap_or(false),
        )
    })
    .await
    .map_err(|error| format!("generating the export failed: {error}"))?
}

/// What the export returns: the file, and a token for `reveal_path`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedExport {
    pub path: String,
    pub bytes: u64,
    pub token: String,
}

/// Writes the exported text to a new file (0600), refusing overwrites and symbolic links. The
/// native save dialog is opened here, with the name the export proposes; cancelling returns `None`.
#[tauri::command]
pub async fn save_export_file(
    app: AppHandle,
    default_name: String,
    text: String,
) -> Result<Option<SavedExport>, String> {
    let (filter_name, extension) = if default_name.ends_with(".py") {
        ("Python", "py")
    } else {
        ("Shell", "sh")
    };
    let dialog_name = default_name.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Save export")
            .set_file_name(dialog_name)
            .add_filter(filter_name, &[extension])
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("saving was interrupted: {error}"))?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let target = picked
        .into_path()
        .map_err(|error| format!("the chosen location is not a file: {error}"))?;
    tauri::async_runtime::spawn_blocking(move || finish_save(&target, &text).map(Some))
        .await
        .map_err(|error| format!("saving failed: {error}"))?
}

/// The file part of the save: write, then grant the file for `reveal_path`.
pub(super) fn finish_save(target: &Path, text: &str) -> Result<SavedExport, String> {
    let saved = crate::export::write_text_file(target, text)?;
    let token = grants::issue(grants::Kind::SavedFile, target)?;
    Ok(SavedExport {
        path: saved.path,
        bytes: saved.bytes,
        token,
    })
}

/// Sanitization counts and warnings, without writing anything.
#[tauri::command]
pub async fn preview_sanitized(
    session_token: String,
    include_sensitive: Option<bool>,
) -> Result<crate::export::SanitizePreview, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::export::sanitize_preview_with_options(
            Path::new(&session_dir),
            include_sensitive.unwrap_or(false),
        )
    })
    .await
    .map_err(|error| format!("the sanitization preview failed: {error}"))?
}

/// What `save_sanitized` returns: the export's result, and a token for opening the new folder.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizeSavedDto {
    #[serde(flatten)]
    pub saved: crate::export::SanitizeSaved,
    pub token: String,
}

/// Writes the sanitized session to a new folder chosen by the user.
#[tauri::command]
pub async fn save_sanitized(
    app: AppHandle,
    session_token: String,
    suggested_name: String,
    include_sensitive: Option<bool>,
) -> Result<Option<SanitizeSavedDto>, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    let include = include_sensitive.unwrap_or(false);
    let title = if include {
        "Export full capture with sensitive data"
    } else {
        "Choose a new folder for the sanitized session"
    };
    // Only the file name of the suggestion is used, as the dialog's default; never as a target.
    let default_name = Path::new(&suggested_name)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let Some(destination) = pick_path(&app, title, Pick::SaveFile, None, default_name).await?
    else {
        return Ok(None);
    };
    let saved = tauri::async_runtime::spawn_blocking(move || {
        crate::export::sanitize_to_with_options(Path::new(&session_dir), &destination, include)
    })
    .await
    .map_err(|error| format!("sanitization failed: {error}"))??;
    let token = grants::issue(grants::Kind::Session, Path::new(&saved.path))?;
    Ok(Some(SanitizeSavedDto { saved, token }))
}

/// The path behind a reveal token, when it still exists. A path or another kind of token is
/// refused before anything is started.
pub(super) fn reveal_target(token: &str) -> Result<PathBuf, String> {
    let target = grants::resolve(token, &[grants::Kind::Session, grants::Kind::SavedFile])?;
    if !target.exists() {
        return Err(format!("not found: {}", target.display()));
    }
    Ok(target)
}

#[tauri::command]
pub fn reveal_path(token: String) -> Result<(), String> {
    let target = reveal_target(&token)?;
    #[cfg(target_os = "macos")]
    {
        let status = if target.is_dir() {
            std::process::Command::new("open").arg(&target).status()
        } else {
            std::process::Command::new("open")
                .arg("-R")
                .arg(&target)
                .status()
        };
        match status {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("open exited with {status}")),
            Err(error) => Err(format!("could not open Finder: {error}")),
        }
    }
    #[cfg(target_os = "linux")]
    {
        // xdg-open does not select files: it opens the folder (the parent, when it is a file).
        let dir = reveal_dir(&target);
        match std::process::Command::new("xdg-open").arg(&dir).status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("xdg-open exited with {status}")),
            Err(error) => Err(format!(
                "could not open the file manager (xdg-open): {error}"
            )),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("revealing a file is not supported on this platform".to_string())
    }
}

/// Folder to open in the file manager: the folder itself or the file's parent.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(super) fn reveal_dir(target: &std::path::Path) -> PathBuf {
    if target.is_dir() {
        target.to_path_buf()
    } else {
        target
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"))
    }
}
