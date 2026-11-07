//! Export (cURL/Python) and sanitized session, reusing the core.
//!
//! Rules of this bridge:
//! - the exported text is generated **in Rust** from the persisted session; the UI
//!   never builds or edits the exported code;
//! - nothing is executed and no network is opened;
//! - writes only go to a destination explicitly chosen by the user, using
//!   `create_new` (refuses overwrites), with no symbolic links and 0600;
//! - the original session is never modified.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use scrapelens_core::export::curl::to_curl_with_origins;
use scrapelens_core::export::python::to_python_with_origins;
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions, SanitizedExport};
use scrapelens_core::export::{ExportOptions, ExportOutput};
use scrapelens_core::model::{BodyState, LogicalRequest, SessionBundle, Warning};
use scrapelens_core::store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Curl,
    Python,
}

impl Format {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "curl" => Ok(Self::Curl),
            "python" => Ok(Self::Python),
            other => Err(format!(
                "unknown export format: {other:?} (use \"curl\" or \"python\")"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Python => "python",
        }
    }
}

/// Generation result: exactly the text the UI shows, copies, and saves.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPreview {
    pub session_id: String,
    pub request_id: String,
    pub request_method: String,
    pub request_url: String,
    pub protocol: String,
    pub header_verification: String,
    pub format: String,
    pub text: String,
    pub warnings: Vec<Warning>,
    pub skipped_headers: Vec<String>,
    pub body_included: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_note: Option<String>,
    pub body_state: String,
    /// Protocol adapter whose encoder was included in the priming script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedFile {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionCount {
    pub key: String,
    pub count: usize,
}

/// Sanitization preview: nothing is written.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizePreview {
    pub include_sensitive: bool,
    pub raw_artifacts_kept: Vec<String>,
    pub session_id: String,
    pub original_dir: String,
    pub suggested_destination: String,
    pub requests: usize,
    pub redactions: Vec<RedactionCount>,
    pub total_redactions: usize,
    pub warnings: Vec<Warning>,
    pub omitted_attachments: Vec<String>,
    pub attachments_kept: usize,
    pub raw_artifacts_dropped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizeSaved {
    pub include_sensitive: bool,
    pub attachments_written: usize,
    pub path: String,
    pub session_id: String,
    pub requests: usize,
    pub total_redactions: usize,
    pub omitted_attachments: Vec<String>,
    pub attachments_kept: usize,
    pub raw_artifacts_dropped: Vec<String>,
    pub session_bytes: u64,
}

fn load(dir: &Path) -> Result<SessionBundle, String> {
    if !dir.exists() {
        return Err(format!("session folder not found: {}", dir.display()));
    }
    if !dir.is_dir() {
        return Err(format!(
            "the export needs the session folder (containing session.json), not the file: {}",
            dir.display()
        ));
    }
    scrapelens_core::import_session_dir(dir)
        .map(|imported| imported.bundle)
        .map_err(|error| format!("could not read the session: {error}"))
}

fn find_request<'a>(
    bundle: &'a SessionBundle,
    request_id: &str,
) -> Result<&'a LogicalRequest, String> {
    bundle
        .session
        .requests
        .iter()
        .find(|request| request.id == request_id)
        .ok_or_else(|| {
            format!(
                "request {request_id} not found in this session ({} request(s) in the file)",
                bundle.session.requests.len()
            )
        })
}

/// The body is only exported when the source says it was captured and the bytes
/// are actually in the bundle. Unavailable state stays unavailable.
fn body_bytes<'a>(
    request: &LogicalRequest,
    attachments: &'a BTreeMap<String, Vec<u8>>,
) -> Option<&'a [u8]> {
    match request.request_body.state {
        BodyState::Captured | BodyState::Truncated => request
            .request_body
            .attachment
            .as_ref()
            .and_then(|name| attachments.get(name))
            .map(Vec::as_slice),
        BodyState::Empty | BodyState::Unavailable | BodyState::Discarded => None,
    }
}

fn generate(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    format: Format,
    origins: Option<&scrapelens_core::flow::ValueOrigins>,
) -> Result<ExportOutput, String> {
    let options = ExportOptions::default();
    let output = match format {
        Format::Curl => to_curl_with_origins(request, body, &options, origins),
        Format::Python => to_python_with_origins(request, body, &options, origins),
    };
    output.map_err(|error| format!("could not generate the export: {error}"))
}

pub fn preview(dir: &Path, request_id: &str, format: &str) -> Result<ExportPreview, String> {
    preview_with(dir, request_id, format, None)
}

/// Same as [`preview`]; `origins` is `None` (no annotation), `Some(Ok(..))` (annotates
/// in the comment the fields with observed origin), or `Some(Err(..))` (origins
/// unavailable: exports without annotations and warns). The generated command does not change.
/// The caller computes the origins, so this module does not depend on
/// `commands`.
pub fn preview_with(
    dir: &Path,
    request_id: &str,
    format: &str,
    origins: Option<Result<scrapelens_core::flow::ValueOrigins, String>>,
) -> Result<ExportPreview, String> {
    let format = Format::parse(format)?;
    let bundle = load(dir)?;
    let request = find_request(&bundle, request_id)?;
    let body = body_bytes(request, &bundle.attachments);
    let (origins, origins_error) = match origins {
        None => (None, None),
        Some(Ok(found)) => (Some(found), None),
        Some(Err(error)) => (None, Some(error)),
    };
    let mut output = generate(request, body, format, origins.as_ref())?;
    if let Some(error) = origins_error {
        // The export proceeds without annotations; the preview says why.
        output.warnings.push(Warning::new(
            "export.origins_unavailable",
            format!("origins not annotated: {error}"),
        ));
    }

    Ok(ExportPreview {
        session_id: bundle.session.session.id.clone(),
        request_id: request.id.clone(),
        request_method: request.method.clone(),
        request_url: request.url.clone(),
        protocol: request.protocol.as_str().to_string(),
        header_verification: request.request_headers.verification().as_str().to_string(),
        format: format.as_str().to_string(),
        text: output.text,
        warnings: output.warnings,
        skipped_headers: output.skipped_headers,
        body_included: output.body_included,
        body_note: output.body_note,
        body_state: request.request_body.state.as_str().to_string(),
        adapter: None,
    })
}

/// Root-level macOS aliases (`/var`, `/tmp`, `/etc` → `/private/...`).
const SYSTEM_ALIASES: [&str; 3] = ["/var", "/tmp", "/etc"];

fn is_system_alias(path: &Path) -> bool {
    SYSTEM_ALIASES.iter().any(|alias| path == Path::new(alias))
        && fs::read_link(path)
            .map(|target| target.starts_with("private") || target.starts_with("/private"))
            .unwrap_or(false)
}

/// Refuses the path if it or ANY existing ancestor is a symbolic link.
/// Policy: the only exception is the root-level macOS system aliases
/// (`/var`, `/tmp`, `/etc`) that point to `/private/...`; any other
/// link, at any position, is refused. Nonexistent components are ignored.
fn reject_symlink(path: &Path, label: &str) -> Result<(), String> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            if metadata.file_type().is_symlink() && !is_system_alias(ancestor) {
                return Err(format!(
                    "{label} goes through a symbolic link ({}); choose a real path",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(())
}

/// Writes a new file with 0600; never overwrites or follows a symbolic link.
pub fn write_text_file(path: &Path, text: &str) -> Result<SavedFile, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("destination has no folder: {}", path.display()))?;
    reject_symlink(parent, "the destination folder")?;
    if !parent.is_dir() {
        return Err(format!(
            "the destination folder does not exist: {}",
            parent.display()
        ));
    }
    if path.file_name().is_none() {
        return Err("the destination needs a file name".to_string());
    }
    reject_symlink(path, "the destination file")?;
    if path.exists() {
        return Err(format!(
            "the file already exists ({}); choose another name to avoid overwriting",
            path.display()
        ));
    }

    // Created inside the parent's descriptor, so a name swapped for a link cannot send the text elsewhere.
    let parent_abs = std::path::absolute(parent).map_err(|error| format!("invalid destination folder ({}): {error}", parent.display()))?;
    let dir = crate::fsfd::open_dir_nofollow(&parent_abs)
        .map_err(|error| format!("invalid destination folder ({}): {error}", parent.display()))?;
    let file_name = path.file_name().ok_or_else(|| "the destination needs a file name".to_string())?;
    let mut file = match crate::fsfd::create_file_at(&dir, file_name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "the file already exists ({}); choose another name to avoid overwriting",
                path.display()
            ));
        }
        Err(error) => return Err(format!("could not create {}: {error}", path.display())),
    };
    file.write_all(text.as_bytes())
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", path.display()))?;

    Ok(SavedFile {
        path: path.display().to_string(),
        bytes: text.len() as u64,
    })
}

fn raw_artifacts(dir: &Path) -> Vec<String> {
    [store::CDP_EVENTS_FILE, store::NETLOG_FILE]
        .into_iter()
        .filter(|name| dir.join(name).exists())
        .map(str::to_string)
        .collect()
}

// Regular files only; databases/events must not be able to redirect the copy.
fn full_raw_artifacts(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for name in [store::CDP_EVENTS_FILE, store::NETLOG_FILE, "cdp-bodies.jsonl"] {
        match fs::symlink_metadata(dir.join(name)) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => names.push(name.to_string()),
            Ok(_) => return Err(format!("raw artifact is not a regular file (symlink refused): {name}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(format!("failed to read raw artifact {name}: {error}")),
        }
    }
    Ok(names)
}

fn copy_raw_private(src: &Path, dest_dir: &Path, name: &str) -> Result<(), String> {
    // The destination is opened (0700, ours, no symlink in the chain) and the copy
    // is written relative to that descriptor: a later swap of the name cannot
    // redirect the raw artifact outside.
    let out = store::PrivateDir::open(dest_dir)
        .map_err(|error| format!("could not open {}: {error}", dest_dir.display()))?;
    out.copy_from(name, src)
        .map_err(|error| format!("failed to copy raw artifact {}: {error}", src.display()))
}

fn sanitized(dir: &Path) -> Result<(SessionBundle, SanitizedExport), String> {
    let bundle = load(dir)?;
    // Conservative core policy: no raw events, unstructured bodies omitted,
    // default placeholders.
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    Ok((bundle, export))
}

pub fn sanitize_preview(dir: &Path) -> Result<SanitizePreview, String> {
    sanitize_preview_with_options(dir, false)
}

pub fn sanitize_preview_with_options(dir: &Path, include_sensitive: bool) -> Result<SanitizePreview, String> {
    if include_sensitive {
        let raw_artifacts_kept = full_raw_artifacts(dir)?;
        let bundle = load(dir)?;
        let session_id = bundle.session.session.id.clone();
        return Ok(SanitizePreview {
            include_sensitive: true,
            suggested_destination: dir.parent().unwrap_or(dir).join(format!("{session_id}-full")).display().to_string(),
            session_id, original_dir: dir.display().to_string(), requests: bundle.session.requests.len(),
            redactions: Vec::new(), total_redactions: 0, warnings: Vec::new(),
            omitted_attachments: Vec::new(), attachments_kept: bundle.attachments.len(),
            raw_artifacts_dropped: Vec::new(), raw_artifacts_kept,
        });
    }
    let (bundle, export) = sanitized(dir)?;
    let redactions: Vec<RedactionCount> = export
        .redactions
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(key, count)| RedactionCount {
            key: key.clone(),
            count: *count,
        })
        .collect();
    let session_id = bundle.session.session.id.clone();
    let parent = dir.parent().unwrap_or(dir);
    let suggested_destination = parent
        .join(format!("{session_id}-sanitized"))
        .display()
        .to_string();

    Ok(SanitizePreview {
        include_sensitive: false,
        raw_artifacts_kept: Vec::new(),
        session_id,
        original_dir: dir.display().to_string(),
        suggested_destination,
        requests: bundle.session.requests.len(),
        total_redactions: redactions.iter().map(|item| item.count).sum(),
        redactions,
        warnings: export.warnings,
        omitted_attachments: export.omitted_attachments,
        attachments_kept: export.bundle.attachments.len(),
        raw_artifacts_dropped: raw_artifacts(dir),
    })
}

/// Writes the sanitized session to `destination`, which must be a new (or empty)
/// folder outside the source. On error, removes what this call created.
pub fn sanitize_to(src: &Path, destination: &Path) -> Result<SanitizeSaved, String> {
    sanitize_to_with_options(src, destination, false)
}

pub fn sanitize_to_with_options(src: &Path, destination: &Path, include_sensitive: bool) -> Result<SanitizeSaved, String> {
    let src_abs = fs::canonicalize(src)
        .map_err(|error| format!("invalid session folder ({}): {error}", src.display()))?;
    if !src_abs.is_dir() {
        return Err(format!("the source is not a folder: {}", src.display()));
    }

    let file_name = destination
        .file_name()
        .ok_or_else(|| format!("destination has no folder name: {}", destination.display()))?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    reject_symlink(parent, "the chosen folder")?;
    let parent_abs = fs::canonicalize(parent)
        .map_err(|error| format!("invalid destination folder ({}): {error}", parent.display()))?;
    let dest_abs = parent_abs.join(file_name);

    if dest_abs == src_abs {
        return Err("the destination is the original session itself; choose a new folder".to_string());
    }
    if dest_abs.starts_with(&src_abs) {
        return Err(
            "the destination is inside the original session; choose a folder outside it so raw and sanitized data are not mixed"
                .to_string(),
        );
    }
    reject_symlink(&dest_abs, "the destination")?;

    let mut created = false;
    match fs::metadata(&dest_abs) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "the destination exists and is not a folder: {}",
                dest_abs.display()
            ));
        }
        Ok(_) => {
            let mut entries = fs::read_dir(&dest_abs)
                .map_err(|error| format!("could not read {}: {error}", dest_abs.display()))?;
            if entries.next().is_some() {
                return Err(format!(
                    "the destination folder is not empty ({}); choose a new folder",
                    dest_abs.display()
                ));
            }
        }
        Err(_) => created = true,
    }

    store::ensure_private_dir(&dest_abs)
        .map_err(|error| format!("could not create {}: {error}", dest_abs.display()))?;

    let outcome = (|| -> Result<SanitizeSaved, String> {
        if include_sensitive {
            let raw = full_raw_artifacts(&src_abs)?;
            let mut bundle = load(&src_abs)?;
            // The three raw files are copied below, without duplicating the writes
            // of the two that the store can also write.
            bundle.cdp_events_jsonl = None;
            bundle.netlog_json = None;
            store::write_session_dir(&bundle, &dest_abs).map_err(|error| format!("could not write the full capture: {error}"))?;
            for name in raw {
                copy_raw_private(&src_abs.join(&name), &dest_abs, &name)?;
            }
            return Ok(SanitizeSaved {
                include_sensitive: true, attachments_written: bundle.attachments.len(),
                path: dest_abs.display().to_string(), session_id: bundle.session.session.id.clone(),
                requests: bundle.session.requests.len(), total_redactions: 0,
                omitted_attachments: Vec::new(), attachments_kept: bundle.attachments.len(),
                raw_artifacts_dropped: Vec::new(),
                session_bytes: fs::metadata(dest_abs.join(store::SESSION_FILE)).map_err(|error| error.to_string())?.len(),
            });
        }
        let (bundle, export) = sanitized(&src_abs)?;
        let raw_dropped = raw_artifacts(&src_abs);
        export
            .write_to(&dest_abs)
            .map_err(|error| format!("could not write the sanitized session: {error}"))?;
        let total_redactions = export.redactions.values().sum();
        let session_bytes = fs::metadata(dest_abs.join(store::SESSION_FILE))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Ok(SanitizeSaved {
            include_sensitive: false,
            attachments_written: export.bundle.attachments.len(),
            path: dest_abs.display().to_string(),
            session_id: bundle.session.session.id.clone(),
            requests: bundle.session.requests.len(),
            total_redactions,
            omitted_attachments: export.omitted_attachments,
            attachments_kept: export.bundle.attachments.len(),
            raw_artifacts_dropped: raw_dropped,
            session_bytes,
        })
    })();

    if outcome.is_err() && created {
        // Relative to the parent's descriptor: a name swapped for a link is never followed.
        let _ = crate::fsfd::remove_path(&dest_abs);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-export-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SESSION_JSON: &str = r#"{
      "schemaVersion": 1,
      "session": {
        "id": "export-fixture",
        "startedAt": "2026-10-27T10:00:00Z",
        "labels": ["synthetic-fixture"],
        "completeness": { "state": "complete", "counts": {} }
      },
      "requests": [
        {
          "id": "req-body",
          "url": "http://127.0.0.1:8781/echo?x=1",
          "method": "POST",
          "protocol": "h1",
          "status": 200,
          "requestHeaders": {
            "headers": [
              { "name": "Host", "value": "127.0.0.1:8781", "source": "capture", "method": "fixture", "verification": "verified" },
              { "name": "Cookie", "value": "sid=ZZSECRET-1; theme=dark", "source": "capture", "method": "fixture", "verification": "verified" },
              { "name": "X-Quote", "value": "a'b", "source": "capture", "method": "fixture", "verification": "verified" }
            ]
          },
          "requestBody": {
            "state": "captured",
            "attachment": "req-body.bin",
            "bytes": 7
          }
        },
        {
          "id": "req-no-body",
          "url": "http://127.0.0.1:8781/page",
          "method": "GET",
          "protocol": "h1",
          "status": 200,
          "requestHeaders": {
            "headers": [
              { "name": "Host", "value": "127.0.0.1:8781", "source": "capture", "method": "fixture", "verification": "verified" }
            ]
          },
          "requestBody": { "state": "unavailable", "note": "CDP did not provide the body" }
        }
      ]
    }"#;

    fn fixture(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        fs::write(dir.join("session.json"), SESSION_JSON).unwrap();
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("attachments/req-body.bin"), b"a=1&b=2").unwrap();
        dir
    }


    #[test]
    fn full_export_preserves_secrets_raw_files_and_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture("full");
        fs::write(dir.join("attachments/req-body.bin"), b"password=BODY_SECRET").unwrap();
        for name in [store::CDP_EVENTS_FILE, store::NETLOG_FILE, "cdp-bodies.jsonl"] {
            fs::write(dir.join(name), b"RAW_TOKEN_SECRET").unwrap();
        }
        let preview = sanitize_preview_with_options(&dir, true).unwrap();
        assert!(preview.include_sensitive);
        assert!(preview.suggested_destination.ends_with("-full"));
        assert_eq!(preview.total_redactions, 0);
        assert!(preview.redactions.is_empty() && preview.omitted_attachments.is_empty());
        assert!(preview.raw_artifacts_dropped.is_empty());
        assert_eq!(preview.raw_artifacts_kept.len(), 3);
        let dest = dir.with_extension("full");
        let saved = sanitize_to_with_options(&dir, &dest, true).unwrap();
        assert!(saved.include_sensitive);
        assert_eq!(saved.total_redactions, 0);
        assert_eq!(saved.attachments_written, preview.attachments_kept);
        assert!(fs::read_to_string(dest.join("session.json")).unwrap().contains("ZZSECRET-1"));
        assert_eq!(fs::read(dest.join("attachments/req-body.bin")).unwrap(), b"password=BODY_SECRET");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o700);
        for name in [store::SESSION_FILE, store::CDP_EVENTS_FILE, store::NETLOG_FILE, "cdp-bodies.jsonl", "attachments/req-body.bin"] {
            let path = dest.join(name);
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            if name != store::SESSION_FILE {
                assert_eq!(fs::read(&path).unwrap(), fs::read(dir.join(name)).unwrap());
            }
        }
        assert!(sanitize_preview(&dir).unwrap().total_redactions > 0);
        fs::remove_dir_all(dest).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_export_refuses_unsafe_destinations_and_raw_symlinks() {
        let dir = fixture("full-unsafe");
        assert!(sanitize_to_with_options(&dir, &dir, true).is_err());
        assert!(sanitize_to_with_options(&dir, &dir.join("child"), true).is_err());
        let dest = dir.with_extension("full");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("existing"), "keep").unwrap();
        assert!(sanitize_to_with_options(&dir, &dest, true).is_err());
        fs::remove_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(&dir, &dest).unwrap();
        assert!(sanitize_to_with_options(&dir, &dest, true).is_err());
        fs::remove_file(&dest).unwrap();
        std::os::unix::fs::symlink(dir.join("session.json"), dir.join("netlog.json")).unwrap();
        assert!(sanitize_preview_with_options(&dir, true).is_err());
        assert!(sanitize_to_with_options(&dir, &dest, true).is_err());
        assert!(!dest.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn curl_includes_body_and_escapes_quotes() {
        let dir = fixture("curl");
        let preview = preview(&dir, "req-body", "curl").unwrap();
        assert!(preview.body_included, "{:?}", preview.body_note);
        assert!(
            preview.text.contains("--data-binary 'a=1&b=2'"),
            "{}",
            preview.text
        );
        // Single quotes in the value must not break the command: the shell receives
        // `a'\''b` inside the single-quoted argument.
        assert!(preview.text.contains("a'\\''b"), "{}", preview.text);
        assert_eq!(preview.body_state, "captured");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_preview_uses_same_source_without_executing() {
        let dir = fixture("python");
        let preview = preview(&dir, "req-body", "python").unwrap();
        assert_eq!(preview.format, "python");
        assert!(preview.text.contains("http.client"), "{}", preview.text);
        assert!(!preview.text.contains("requests.post"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unavailable_body_is_reported_not_invented() {
        let dir = fixture("no-body");
        let preview = preview(&dir, "req-no-body", "curl").unwrap();
        assert!(!preview.body_included);
        let note = preview.body_note.unwrap_or_default();
        assert!(
            note.to_lowercase().contains("not included") && note.contains("Unavailable"),
            "{note}"
        );
        assert!(!preview.text.contains("--data-binary"), "{}", preview.text);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_request_and_missing_dir_are_actionable_errors() {
        let dir = fixture("missing");
        let error = preview(&dir, "req-missing", "curl").unwrap_err();
        assert!(error.contains("req-missing"), "{error}");
        assert!(error.contains("2 request"), "{error}");

        let gone = dir.join("does-not-exist");
        let error = preview(&gone, "req-body", "curl").unwrap_err();
        assert!(error.contains("not found"), "{error}");

        let error = preview(&dir, "req-body", "wget").unwrap_err();
        assert!(error.contains("unknown"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_refuses_overwrite_and_symlink_with_0600() {
        let dir = temp_dir("save");
        let target = dir.join("export.sh");
        let saved = write_text_file(&target, "#!/bin/sh\necho ok\n").unwrap();
        assert_eq!(saved.bytes as usize, "#!/bin/sh\necho ok\n".len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }

        let error = write_text_file(&target, "something else").unwrap_err();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "#!/bin/sh\necho ok\n");

        let link = dir.join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = write_text_file(&link, "x").unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_preview_reports_counts_without_writing() {
        let dir = fixture("preview");
        let before: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        let preview = sanitize_preview(&dir).unwrap();
        assert_eq!(preview.requests, 2);
        assert!(preview.total_redactions >= 1, "{:?}", preview.redactions);
        assert!(!preview.suggested_destination.is_empty());
        let after: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(before, after, "preview must not write to the source");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_writes_new_private_dir_and_keeps_origin() {
        let dir = fixture("sanitize");
        let session_before = fs::read(dir.join("session.json")).unwrap();
        let dest = dir.parent().unwrap().join(format!(
            "{}-out",
            dir.file_name().unwrap().to_string_lossy()
        ));
        let saved = sanitize_to(&dir, &dest).unwrap();
        assert_eq!(
            fs::canonicalize(&saved.path).unwrap(),
            fs::canonicalize(&dest).unwrap()
        );
        assert!(saved.total_redactions >= 1);

        let sanitized = fs::read_to_string(dest.join("session.json")).unwrap();
        assert!(!sanitized.contains("ZZSECRET-1"), "cookie not redacted");
        assert!(sanitized.contains("[REDACTED]"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "mode {dir_mode:o}");
            let file_mode = fs::metadata(dest.join("session.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "mode {file_mode:o}");
        }

        assert_eq!(fs::read(dir.join("session.json")).unwrap(), session_before);
        assert!(dir.join("attachments/req-body.bin").exists());
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn sanitize_refuses_origin_inside_origin_and_occupied_destination() {
        let dir = fixture("dest");
        let error = sanitize_to(&dir, &dir).unwrap_err();
        assert!(error.contains("original session itself"), "{error}");

        let inside = dir.join("sanitized");
        let error = sanitize_to(&dir, &inside).unwrap_err();
        assert!(error.contains("inside the original session"), "{error}");
        assert!(!inside.exists());

        let occupied = temp_dir("occupied");
        fs::write(occupied.join("file.txt"), b"x").unwrap();
        let error = sanitize_to(&dir, &occupied).unwrap_err();
        assert!(error.contains("is not empty"), "{error}");
        assert!(occupied.join("file.txt").exists());

        let link = dir.parent().unwrap().join(format!(
            "{}-link",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::os::unix::fs::symlink(&occupied, &link).unwrap();
        let error = sanitize_to(&dir, &link).unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");

        fs::remove_file(&link).ok();
        fs::remove_dir_all(&occupied).ok();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_into_missing_parent_is_refused() {
        let dir = temp_dir("parent");
        let error = write_text_file(&dir.join("missing/file.sh"), "x").unwrap_err();
        assert!(error.contains("does not exist"), "{error}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn annotated_preview_without_origins_warns_and_keeps_text() {
        let dir = fixture("export-annotate");
        let plain = preview(&dir, "req-body", "curl").unwrap();
        let noted = preview_with(&dir, "req-body", "curl", Some(Err("no attempts".to_string()))).unwrap();
        assert_eq!(plain.text, noted.text);
        assert!(noted.warnings.iter().any(|w| w.code == "export.origins_unavailable"));
    }

    /// The folder is swapped for a link to `outside` while text files are written into it. A write
    /// may fail; no file may land in `outside`.
    #[test]
    fn text_export_never_lands_outside_when_the_folder_is_swapped_for_a_link() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let base = temp_dir("text-swap");
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let folder = base.join("picked");
        fs::create_dir_all(&folder).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let stop = Arc::clone(&running);
        let (flip_folder, flip_outside) = (folder.clone(), outside.clone());
        let aside = base.join("aside");
        let flipper = std::thread::spawn(move || {
            // The folder moves aside (its contents with it), a link takes its name, then both are restored.
            while stop.load(Ordering::SeqCst) {
                let _ = fs::rename(&flip_folder, &aside);
                let _ = std::os::unix::fs::symlink(&flip_outside, &flip_folder);
                std::thread::yield_now();
                let _ = fs::remove_file(&flip_folder);
                let _ = fs::rename(&aside, &flip_folder);
            }
        });
        for i in 0..2000 {
            let _ = write_text_file(&folder.join(format!("script-{i}.sh")), "#!/bin/sh\necho ok\n");
        }
        running.store(false, Ordering::SeqCst);
        flipper.join().unwrap();

        let landed: Vec<_> = fs::read_dir(&outside).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(landed.is_empty(), "text files landed outside the chosen folder: {landed:?}");
    }
}
