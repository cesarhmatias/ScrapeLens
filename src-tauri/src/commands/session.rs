//! Sessions: opening, importing, reading and searching captured sessions, their bodies,
//! origins, timelines and assessments.

use super::*;

/// Uniform response for the commands that load a session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub session: Value,
    pub session_dir: Option<String>,
    /// Token for `session_dir`: what the webview passes back to read bodies or reveal the
    /// folder. Absent for the demo. Issued by the backend (see `grants`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    pub synthetic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    /// What the cookie import of the capture recorded (undecryptable or zero imported).
    /// Absent for sessions without a browser import and for sessions from older captures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_import: Option<crate::cookie_import::CookieImportReport>,
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPayload {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub bytes: u64,
}

/// Opens a real v1 session (a folder with session.json, or the file itself). With a `token`
/// (from an earlier payload, or a finished export), opens that session. Without one, the user
/// picks the folder in the native dialog; cancelling returns `None`. The webview never supplies
/// a path. This part already works and does not depend on the core to read the document.
#[tauri::command]
pub async fn open_session(
    app: AppHandle,
    token: Option<String>,
) -> Result<Option<SessionPayload>, String> {
    let chosen = match token {
        Some(token) => grants::resolve(&token, &[grants::Kind::Session])?,
        None => {
            let dialog_app = app.clone();
            let picked = tauri::async_runtime::spawn_blocking(move || {
                dialog_app
                    .dialog()
                    .file()
                    .set_title("Open ScrapeLens session")
                    .blocking_pick_folder()
            })
            .await
            .map_err(|error| format!("the dialog was interrupted: {error}"))?;
            let Some(picked) = picked else {
                return Ok(None);
            };
            picked
                .into_path()
                .map_err(|error| format!("the chosen location is not a folder: {error}"))?
        }
    };
    let chosen = chosen.display().to_string();
    let payload = run_loading(app, move |app| {
        let payload = read_session_payload(&chosen)?;
        let state = app.state::<AppState>();
        *state.last_session_dir.lock().expect("session_dir lock") =
            payload.session_dir.as_ref().map(PathBuf::from);
        Ok(payload)
    })
    .await?;
    Ok(Some(payload))
}

/// Sets an `AtomicBool` and clears it on exit (including on error or panic).
pub(crate) struct FlagGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> FlagGuard<'a> {
    /// `None` if the flag was already set (another operation is in progress).
    pub(crate) fn acquire(flag: &'a std::sync::atomic::AtomicBool) -> Option<Self> {
        use std::sync::atomic::Ordering;
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Opens/imports/stops off the main thread (reading 20 thousand
/// requests takes ~10 s) and refuses a second operation in parallel.
pub(super) async fn run_loading<F>(app: AppHandle, work: F) -> Result<SessionPayload, String>
where
    F: FnOnce(&AppHandle) -> Result<SessionPayload, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = FlagGuard::acquire(&state.loading).ok_or_else(|| {
            "A session is already being opened or imported. Wait for it to finish.".to_string()
        })?;
        work(&app)
    })
    .await
    .map_err(|error| format!("the operation was interrupted: {error}"))?
}

pub(super) fn read_session_payload(path: &str) -> Result<SessionPayload, String> {
    let chosen = PathBuf::from(path);
    if !chosen.exists() {
        return Err(format!("path not found: {path}"));
    }
    // A folder with session.json, or a session file with any name
    // (absolute, regular, with no symlink in any component).
    let session_dir = if chosen.is_dir() {
        if !chosen.join("session.json").is_file() {
            return Err(format!("session.json not found in {}", chosen.display()));
        }
        chosen
    } else {
        cli::validate_absolute_regular_file(&chosen)?
    };
    header_payload(&session_dir, |requests, partial| {
        format!(
            "Session opened: {requests} request(s){}.",
            if partial {
                " · partial session, as declared by the source"
            } else {
                ""
            }
        )
    })
}

/// P5: reads the typed session (`LazySession` cache, no `Value`) and returns only the
/// header + count. The requests come from `list_requests`/`get_request`.
pub(crate) fn header_payload(
    session_dir: &Path,
    notice: impl FnOnce(usize, bool) -> String,
) -> Result<SessionPayload, String> {
    let lazy = cached_session(session_dir)?;
    let session = &lazy.session;
    if session.schema_version != 1 {
        return Err(format!(
            "schemaVersion {} is not supported by this app (expected: 1)",
            session.schema_version
        ));
    }
    let header = crate::listing::header_of(session)?;
    let synthetic = session
        .session
        .labels
        .iter()
        .any(|label| label == "synthetic-fixture");
    let partial = serde_json::to_value(session.session.completeness.state)
        .ok()
        .and_then(|v| v.as_str().map(|s| s != "complete"))
        .unwrap_or(true);
    let requests = header.request_count;
    Ok(SessionPayload {
        session: serde_json::to_value(&header)
            .map_err(|error| format!("invalid header: {error}"))?,
        session_dir: Some(session_dir.display().to_string()),
        session_token: Some(grants::issue(grants::Kind::Session, session_dir)?),
        synthetic,
        notice: Some(notice(requests, partial)),
        cookie_import: crate::cookie_import::read_report(session_dir),
        pending: false,
    })
}

/// Page of summaries (P5). `limit` up to 2000; filters run here, not in the front end.
#[tauri::command]
pub async fn list_requests(
    session_token: String,
    offset: usize,
    limit: usize,
    filter: Option<crate::listing::ListFilter>,
) -> Result<crate::listing::RequestPage, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let page =
            crate::listing::list_page(&lazy.session, offset, limit, &filter.unwrap_or_default());
        // Test-hooks builds only: proves, without reading the screen, that the list came through the paginated contract.
        #[cfg(feature = "test-hooks")]
        {
            if std::env::var("SCRAPELENS_TEST_MODE").as_deref() == Ok("1") {
                eprintln!(
                    "scrapelens: list_requests offset={offset} items={} matched={} total={}",
                    page.items.len(),
                    page.matched,
                    page.total
                );
            }
        }
        Ok(page)
    })
    .await
    .map_err(|error| format!("the listing was interrupted: {error}"))?
}

/// On-demand detail of a request (P5).
#[tauri::command]
pub async fn get_request(session_token: String, id: String) -> Result<Value, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let detail = crate::listing::detail(&lazy.session, &id)
            .ok_or_else(|| format!("request {id} not found in the session"))?;
        serde_json::to_value(&detail).map_err(|error| format!("invalid detail: {error}"))
    })
    .await
    .map_err(|error| format!("reading the detail was interrupted: {error}"))?
}

pub(super) fn sessions_root(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("no app data directory: {error}"))?
        .join("sessions");
    store::ensure_private_dir(&root)
        .map_err(|error| format!("could not create {}: {error}", root.display()))?;
    Ok(root)
}

pub(super) fn sanitize_dir_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '-']).to_string();
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.chars().take(96).collect()
    }
}

pub(super) fn unique_session_dir(root: &Path, base: &str) -> PathBuf {
    let mut candidate = root.join(base);
    let mut index = 2;
    while candidate.exists() {
        candidate = root.join(format!("{base}-{index}"));
        index += 1;
    }
    candidate
}

pub(super) fn persist_imported(
    app: &AppHandle,
    imported: ImportedSession,
    label: &str,
) -> Result<SessionPayload, String> {
    let session_id = imported.bundle.session.session.id.clone();
    let root = sessions_root(app)?;
    let dir = unique_session_dir(&root, &sanitize_dir_name(&session_id));
    store::write_session_dir(&imported.bundle, &dir)
        .map_err(|error| format!("could not write the imported session: {error}"))?;
    let counts = imported.bundle.session.session.completeness.counts.requests;
    let warnings = imported.report.warnings.len();
    let completeness = format!("{:?}", imported.bundle.session.session.completeness.state);
    drop(imported);
    let shown = dir.display().to_string();
    header_payload(&dir, move |_, _| {
        format!("{label} imported: {counts} request(s), {warnings} warning(s), completeness {completeness}. Directory: {shown}.")
    })
}

pub(super) fn read_import_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    read_import_file_max(path, label, 256 * 1024 * 1024)
}

pub(super) fn read_import_file_max(path: &str, label: &str, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // O_NOFOLLOW + O_NONBLOCK (a FIFO does not block); type and size checked by fstat
    // on the descriptor itself, and the read uses the same descriptor (no TOCTOU).
    let handle = open_beneath_parent(Path::new(path)).map_err(|error| {
        format!("{label} could not be opened at {path} (symlink is refused): {error}")
    })?;
    let metadata = handle
        .metadata()
        .map_err(|error| format!("{label}: failed to inspect {path}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{label}: {path} is a directory, select a file"));
    }
    if !metadata.is_file() {
        return Err(format!("{label}: {path} is not a regular file"));
    }
    if metadata.len() > max {
        return Err(format!(
            "{label} is larger than {} MiB ({} bytes); split the capture or use the v1 session format",
            max / (1024 * 1024),
            metadata.len()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    handle
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {label} at {path}: {error}"))?;
    if bytes.len() as u64 > max {
        return Err(format!(
            "{label} grew beyond {} MiB while being read",
            max / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

/// A9-B5: opens the parent directory by descriptor (O_DIRECTORY|O_NOFOLLOW) and the
/// file with `openat` relative to it (O_NOFOLLOW|O_NONBLOCK). Swapping the parent for a
/// symlink after validation makes the open fail instead of reading another file.
pub(crate) fn open_beneath_parent(path: &Path) -> std::io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let invalid =
        |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string());
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| invalid("no parent directory"))?;
    let name = path.file_name().ok_or_else(|| invalid("no file name"))?;
    let parent_c =
        CString::new(parent.as_os_str().as_bytes()).map_err(|_| invalid("NUL in the path"))?;
    let name_c = CString::new(name.as_bytes()).map_err(|_| invalid("NUL in the name"))?;
    let dir_fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dir = unsafe { fs::File::from_raw_fd(dir_fd) };
    let fd = unsafe {
        use std::os::fd::AsRawFd;
        libc::openat(
            dir.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Imports stay blocked while a recording is in progress (A8-B7).
pub(crate) fn ensure_not_recording(recording: bool) -> Result<(), String> {
    if recording {
        Err("A capture is in progress. Stop the recording before importing.".to_string())
    } else {
        Ok(())
    }
}

#[tauri::command]
pub async fn import_har(
    app: AppHandle,
    token: Option<String>,
) -> Result<Option<SessionPayload>, String> {
    let Some(path) = import_path(&app, token, "Import HAR", "HAR", &["har", "json"]).await? else {
        return Ok(None);
    };
    run_loading(app, move |app| {
        ensure_not_recording(
            app.state::<AppState>()
                .recording
                .load(std::sync::atomic::Ordering::SeqCst),
        )?;
        let bytes = read_import_file(&path, "HAR")?;
        let imported = scrapelens_core::import_har(&bytes).map_err(|error| {
            format!("invalid HAR: {error}. Use a HAR 1.2 file exported from Chrome.")
        })?;
        persist_imported(app, imported, "HAR")
    })
    .await
    .map(Some)
}

#[tauri::command]
pub async fn import_netlog(
    app: AppHandle,
    token: Option<String>,
) -> Result<Option<SessionPayload>, String> {
    let Some(path) = import_path(&app, token, "Import NetLog", "NetLog", &["json"]).await? else {
        return Ok(None);
    };
    run_loading(app, move |app| {
        ensure_not_recording(
            app.state::<AppState>()
                .recording
                .load(std::sync::atomic::Ordering::SeqCst),
        )?;
        let bytes = read_import_file(&path, "NetLog")?;
        let imported = scrapelens_core::import_netlog(&bytes)
            .map_err(|error| format!("invalid NetLog: {error}. Use the full JSON from Chrome."))?;
        persist_imported(app, imported, "NetLog")
    })
    .await
    .map(Some)
}

/// Reads a text preview of a session attachment (hard limit, never leaves the folder).
#[tauri::command]
pub fn read_attachment(session_token: String, name: String) -> Result<AttachmentPayload, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    use std::io::Read;
    let (file, total) = open_attachment(&session_dir, &name)?;
    if total > 1024 * 1024 {
        return Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: total,
        });
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read attachment: {error}"))?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(AttachmentPayload {
            kind: "text".to_string(),
            text: Some(text),
            bytes: total,
        }),
        Err(_) => Ok(AttachmentPayload {
            kind: "binary".to_string(),
            text: None,
            bytes: total,
        }),
    }
}

/// Opens a regular attachment from `attachments/` (refuses symlinks and checks the inode
/// after opening); the check lives in `store::open_regular_attachment`.
pub(super) fn open_attachment(session_dir: &str, name: &str) -> Result<(fs::File, u64), String> {
    store::open_regular_attachment(Path::new(session_dir), name).map_err(|error| error.to_string())
}

/// Searches the payload via `scrapelens_core::search`, off the UI thread.
/// `max_matches` limits the result; the front end does not reimplement the search.
#[tauri::command]
pub async fn search_session(
    session_token: String,
    text: String,
    scopes: Vec<String>,
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        run_search(&session_dir, &text, &scopes, case_sensitive, max_matches)
    })
    .await
    .map_err(|error| format!("the search was interrupted: {error}"))?
}

/// Lazy sessions (up to two) used by search, origins, chain and comparison (attachments read one at a time). Key: folder + (size, mtime) of
/// `session.json` + mtime of `attachments/`; if changed, reload. Keeps only one
/// session (opening another replaces it) and retains neither bodies nor the raw CDP/NetLog.
pub(super) struct CachedSession {
    pub(super) dir: PathBuf,
    pub(super) fingerprint: Vec<Option<(u64, SystemTime)>>,
    pub(super) lazy: Arc<scrapelens_core::lazy::LazySession>,
}

/// Two cached sessions (the open one and the compared one); the oldest leaves first.
pub(super) static SESSION_CACHE: Mutex<Vec<CachedSession>> = Mutex::new(Vec::new());

pub(super) static SESSION_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) fn session_fingerprint(path: &Path) -> Vec<Option<(u64, SystemTime)>> {
    let stat = |p: PathBuf| {
        fs::metadata(p)
            .ok()
            .and_then(|meta| Some((meta.len(), meta.modified().ok()?)))
    };
    if path.is_file() {
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return vec![stat(path.to_path_buf()), stat(parent.join("attachments"))];
    }
    ["session.json", "attachments"]
        .iter()
        .map(|name| stat(path.join(name)))
        .collect()
}

/// Session file with any name: read typed as a stream (no `Value`),
/// opened through the parent without following symlinks; attachments are relative to the file's folder.
pub(super) fn open_session_file_lazy(file: &Path) -> Result<scrapelens_core::lazy::LazySession, String> {
    let handle = open_beneath_parent(file).map_err(|error| {
        format!(
            "could not open {} (symlink is refused): {error}",
            file.display()
        )
    })?;
    let meta = handle
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", file.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    let session: scrapelens_core::model::SessionV1 =
        serde_json::from_reader(std::io::BufReader::with_capacity(1 << 20, handle))
            .map_err(|error| format!("invalid session file: {error}"))?;
    let parent = file
        .parent()
        .map(Path::to_path_buf)
        .ok_or("the file has no parent folder")?;
    Ok(scrapelens_core::lazy::LazySession::new(session, parent))
}

pub(crate) fn cached_session(
    dir: &Path,
) -> Result<Arc<scrapelens_core::lazy::LazySession>, String> {
    // Canonical key: `./s`, `s` and symlinks to the same folder share the entry.
    let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let dir = canonical.as_path();
    let mut guard = SESSION_CACHE
        .lock()
        .map_err(|_| "search cache corrupted".to_string())?;
    let fingerprint = session_fingerprint(dir);
    if let Some(index) = guard.iter().position(|cached| cached.dir == dir) {
        if guard[index].fingerprint == fingerprint {
            let hit = guard.remove(index);
            let lazy = hit.lazy.clone();
            guard.push(hit); // most recent last
            return Ok(lazy);
        }
        guard.remove(index); // file changed: reload
    }
    while guard.len() >= 2 {
        guard.remove(0); // free the oldest before loading another
    }
    SESSION_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let lazy = if dir.is_file() {
        open_session_file_lazy(dir)?
    } else {
        scrapelens_core::open_session_dir_lazy(dir)
            .map_err(|error| format!("could not read the session: {error}"))?
            .0
    };
    let lazy = Arc::new(lazy);
    guard.push(CachedSession {
        dir: dir.to_path_buf(),
        fingerprint,
        lazy: lazy.clone(),
    });
    Ok(lazy)
}

pub(super) fn run_search(
    session_dir: &str,
    text: &str,
    scopes: &[String],
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    use scrapelens_core::search::{Scope, SearchQuery};
    if text.is_empty() {
        return Err("type some text to search for".to_string());
    }
    let mut parsed = Vec::new();
    for scope in scopes {
        parsed.push(Scope::parse(scope).ok_or_else(|| format!("unknown scope: {scope}"))?);
    }
    let lazy = cached_session(Path::new(session_dir))?;
    let mut query = SearchQuery::new(text);
    query.scopes = parsed;
    query.case_sensitive = case_sensitive;
    query.max_matches = max_matches.unwrap_or(2000).clamp(1, 20_000);
    Ok(scrapelens_core::search::search_lazy(&lazy, &query))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPayload {
    /// `text` (valid UTF-8), `binary` (never rendered; hex preview only).
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// First bytes in hexadecimal (limited), only for `binary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    pub bytes: u64,
    /// Bytes actually returned in `text`; less than `bytes` if cut.
    pub shown_bytes: u64,
    pub cut: bool,
}

pub(super) const HEX_PREVIEW_BYTES: usize = 256;

/// Reads an attached body up to `limit` bytes. Text becomes a `String` (the front end
/// shows it in `<pre>`); the rest becomes only a size and a hex preview.
/// The session folder behind a session token; a path or another kind of token is refused.
pub(super) fn session_dir_for_token(token: &str) -> Result<String, String> {
    Ok(grants::resolve(token, &[grants::Kind::Session])?
        .display()
        .to_string())
}

#[tauri::command]
pub async fn read_body(
    session_token: String,
    name: String,
    limit: Option<u64>,
) -> Result<BodyPayload, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        read_body_blocking(&session_dir, &name, limit.unwrap_or(262_144))
    })
    .await
    .map_err(|error| format!("the read was interrupted: {error}"))?
}

pub(super) fn read_body_blocking(session_dir: &str, name: &str, limit: u64) -> Result<BodyPayload, String> {
    use std::io::Read;
    let (file, total) = open_attachment(session_dir, name)?;
    let mut buf = Vec::new();
    file.take(limit.min(16 * 1024 * 1024))
        .read_to_end(&mut buf)
        .map_err(|error| format!("failed to read attachment: {error}"))?;
    let cut = (buf.len() as u64) < total;
    // A cut at the limit may split a character: accepts a valid UTF-8 prefix.
    let text = match std::str::from_utf8(&buf) {
        Ok(text) => Some(text.to_string()),
        Err(error) if cut && error.error_len().is_none() => {
            Some(String::from_utf8_lossy(&buf[..error.valid_up_to()]).into_owned())
        }
        Err(_) => None,
    };
    Ok(match text {
        Some(text) => BodyPayload {
            kind: "text".into(),
            shown_bytes: text.len() as u64,
            text: Some(text),
            hex: None,
            bytes: total,
            cut,
        },
        None => BodyPayload {
            kind: "binary".into(),
            text: None,
            hex: Some(
                buf.iter()
                    .take(HEX_PREVIEW_BYTES)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            bytes: total,
            shown_bytes: buf.len().min(HEX_PREVIEW_BYTES) as u64,
            cut: total > HEX_PREVIEW_BYTES as u64,
        },
    })
}

/// Origin of a request's values (`flow::value_origins`), off the UI thread.
#[tauri::command]
pub async fn request_origins(
    session_token: String,
    request_id: String,
) -> Result<scrapelens_core::flow::ValueOrigins, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        scrapelens_core::flow::value_origins(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &request_id,
            &crate::adapters::flow_options(),
        )
        .map_err(|error| format!("could not calculate the origins: {error}"))
    })
    .await
    .map_err(|error| format!("the calculation was interrupted: {error}"))?
}

/// Priming chain of a request (`flow::priming_chain`).
#[tauri::command]
pub async fn request_chain(
    session_token: String,
    request_id: String,
) -> Result<scrapelens_core::flow::PrimingChain, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        scrapelens_core::flow::priming_chain(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &request_id,
            &crate::adapters::flow_options(),
        )
        .map_err(|error| format!("could not calculate the chain: {error}"))
    })
    .await
    .map_err(|error| format!("the calculation was interrupted: {error}"))?
}

/// Structured (derived) view of the body fields that a protocol adapter claims.
#[tauri::command]
pub async fn adapter_view(
    session_token: String,
    request_id: String,
    side: String,
) -> Result<crate::adapters::AdapterView, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let request = lazy
            .session
            .requests
            .iter()
            .find(|r| r.id == request_id)
            .ok_or_else(|| format!("request {request_id} not found in the session"))?;
        crate::adapters::view(&lazy, request, &side)
    })
    .await
    .map_err(|error| format!("the read was interrupted: {error}"))?
}

/// Application timeline (`timeline::timeline`), with the app's adapter registry.
#[tauri::command]
pub async fn session_timeline(
    session_token: String,
) -> Result<scrapelens_core::timeline::Timeline, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || {
        let dir = Path::new(&session_dir);
        let rules = load_rules(dir)?;
        let lazy = cached_session(dir)?;
        Ok(scrapelens_core::timeline::timeline(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &scrapelens_core::timeline::TimelineOptions {
                flow: crate::adapters::flow_options(),
                rules,
            },
        ))
    })
    .await
    .map_err(|error| format!("the calculation was interrupted: {error}"))?
}

/// Application success × HTTP (`assess::assess_session`). Optional rules in
/// `<session>/assess-rules.json`; invalid rules become an actionable error.
#[tauri::command]
pub async fn assess_session(session_token: String) -> Result<serde_json::Value, String> {
    let session_dir = session_dir_for_token(&session_token)?;
    tauri::async_runtime::spawn_blocking(move || assess_blocking(Path::new(&session_dir)))
        .await
        .map_err(|error| format!("the assessment was interrupted: {error}"))?
}

/// Optional rules `<session>/assess-rules.json` (regular file, up to 256 KiB); default when the file is absent.
pub(super) fn load_rules(dir: &Path) -> Result<scrapelens_core::assess::AssessRules, String> {
    use scrapelens_core::assess::AssessRules;
    let rules_path = dir.join("assess-rules.json");
    match read_rules_file(&rules_path)? {
        Some(text) => AssessRules::from_json(&text).map_err(|_| {
            format!(
                "the rules in {} are not valid (JSON, schema, or fields outside the scrapelens.assess-rules/1 schema); fix or remove the file",
                rules_path.display()
            )
        }),
        None => Ok(AssessRules::default()),
    }
}

pub(super) const RULES_MAX_BYTES: u64 = 256 * 1024;

/// Reads `assess-rules.json` only if it is a regular file without a symlink (symlink_metadata + inode) and up to 256 KiB.
/// `None` when it does not exist.
pub(super) fn read_rules_file(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not check {}: {error}", path.display())),
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!(
            "{} is not a regular file (symbolic link refused); remove it",
            path.display()
        ));
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(format!(
                "{} changed while being opened; refused",
                path.display()
            ));
        }
    }
    if !opened.is_file() || opened.len() > RULES_MAX_BYTES {
        return Err(format!(
            "{} exceeds 256 KiB or is not a regular file; reduce or remove the file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(RULES_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.len() as u64 > RULES_MAX_BYTES {
        return Err(format!(
            "{} exceeds 256 KiB; reduce or remove the file",
            path.display()
        ));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        format!(
            "{} is not valid UTF-8; fix or remove the file",
            path.display()
        )
    })
}

pub(crate) fn assess_blocking(dir: &Path) -> Result<serde_json::Value, String> {
    use scrapelens_core::assess::assess_session;
    let rules_path = dir.join("assess-rules.json");
    let rules = load_rules(dir)?;
    let lazy = cached_session(dir)?;
    let outcomes = assess_session(
        &lazy.session,
        &scrapelens_core::search::LazyBodies(&lazy),
        &rules,
    );
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for outcome in &outcomes {
        *counts
            .entry(outcome.verdict_kind.count_key().to_string())
            .or_default() += 1;
    }
    Ok(serde_json::json!({
        "schema": "scrapelens.assess/1",
        "rules": if rules_path.is_file() { rules_path.display().to_string() } else { "default".to_string() },
        "counts": counts,
        "warnings": rules.warnings(),
        "outcomes": outcomes,
    }))
}
