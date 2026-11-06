//! Commands for the UI ↔ shell bridge. Contract v1: docs/03-contracts.md.
//!
//! Integration note: `start_session`, `import_har` and `import_netlog` call
//! `scrapelens-core` (a crate dependency, no sidecar) and operate on real data. The
//! capture opens the external Chrome in `capture.rs`; the `SessionPayload` envelope
//! stays stable for the UI.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use scrapelens_core::{store, ImportedSession};

use crate::capture::{self, CaptureConfig, CaptureSession, CaptureStatus};
use crate::chrome::{self, ChromeInfo};
use crate::cli;
#[cfg(feature = "test-hooks")]
use crate::cli_test::CliAction;
use crate::prefs;
use crate::AppState;

/// Uniform response for the commands that load a session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub session: Value,
    pub session_dir: Option<String>,
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
pub struct AppInfo {
    pub version: String,
    pub tauri: String,
    pub arch: String,
    pub platform: String,
    pub demo_fixture: bool,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPayload {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub bytes: u64,
}

fn demo_session_value() -> Result<Value, String> {
    let raw = include_str!("../../app/src/demo/session.v1.json");
    let value: Value = serde_json::from_str(raw).map_err(|error| format!("invalid demo fixture: {error}"))?;
    Ok(value)
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tauri: tauri::VERSION.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        platform: std::env::consts::OS.to_string(),
        demo_fixture: true,
        schema_version: 1,
    }
}

/// Contract v1 fixture, always labeled as synthetic.
#[tauri::command]
pub fn demo_session() -> Result<SessionPayload, String> {
    let session = demo_session_value()?;
    Ok(SessionPayload {
        session,
        session_dir: None,
        synthetic: true,
        notice: None,
        cookie_import: None,
        pending: false,
    })
}

/// Opens a real v1 session (a folder with session.json, or the file itself).
/// This part already works and does not depend on the core to read the document.
#[tauri::command]
pub async fn open_session(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        let payload = read_session_payload(&path)?;
        let state = app.state::<AppState>();
        *state.last_session_dir.lock().expect("session_dir lock") =
            payload.session_dir.as_ref().map(PathBuf::from);
        Ok(payload)
    })
    .await
}

/// Sets an `AtomicBool` and clears it on exit (including on error or panic).
pub(crate) struct FlagGuard<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> FlagGuard<'a> {
    /// `None` if the flag was already set (another operation is in progress).
    pub(crate) fn acquire(flag: &'a std::sync::atomic::AtomicBool) -> Option<Self> {
        use std::sync::atomic::Ordering;
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).ok().map(|_| Self(flag))
    }
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Opens/imports/stops off the main thread (reading 20 thousand
/// requests takes ~10 s) and refuses a second operation in parallel.
async fn run_loading<F>(app: AppHandle, work: F) -> Result<SessionPayload, String>
where
    F: FnOnce(&AppHandle) -> Result<SessionPayload, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _guard = FlagGuard::acquire(&state.loading)
            .ok_or_else(|| "A session is already being opened or imported. Wait for it to finish.".to_string())?;
        work(&app)
    })
    .await
    .map_err(|error| format!("the operation was interrupted: {error}"))?
}

fn read_session_payload(path: &str) -> Result<SessionPayload, String> {
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
            if partial { " · partial session, as declared by the source" } else { "" }
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
    let synthetic = session.session.labels.iter().any(|label| label == "synthetic-fixture");
    let partial = serde_json::to_value(session.session.completeness.state)
        .ok()
        .and_then(|v| v.as_str().map(|s| s != "complete"))
        .unwrap_or(true);
    let requests = header.request_count;
    Ok(SessionPayload {
        session: serde_json::to_value(&header).map_err(|error| format!("invalid header: {error}"))?,
        session_dir: Some(session_dir.display().to_string()),
        synthetic,
        notice: Some(notice(requests, partial)),
        cookie_import: crate::cookie_import::read_report(session_dir),
        pending: false,
    })
}

/// Page of summaries (P5). `limit` up to 2000; filters run here, not in the front end.
#[tauri::command]
pub async fn list_requests(
    session_dir: String,
    offset: usize,
    limit: usize,
    filter: Option<crate::listing::ListFilter>,
) -> Result<crate::listing::RequestPage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let page = crate::listing::list_page(&lazy.session, offset, limit, &filter.unwrap_or_default());
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
pub async fn get_request(session_dir: String, id: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let lazy = cached_session(Path::new(&session_dir))?;
        let detail = crate::listing::detail(&lazy.session, &id)
            .ok_or_else(|| format!("request {id} not found in the session"))?;
        serde_json::to_value(&detail).map_err(|error| format!("invalid detail: {error}"))
    })
    .await
    .map_err(|error| format!("reading the detail was interrupted: {error}"))?
}

fn sessions_root(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("no app data directory: {error}"))?
        .join("sessions");
    store::ensure_private_dir(&root)
        .map_err(|error| format!("could not create {}: {error}", root.display()))?;
    Ok(root)
}

fn sanitize_dir_name(name: &str) -> String {
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

fn unique_session_dir(root: &Path, base: &str) -> PathBuf {
    let mut candidate = root.join(base);
    let mut index = 2;
    while candidate.exists() {
        candidate = root.join(format!("{base}-{index}"));
        index += 1;
    }
    candidate
}

fn persist_imported(
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

fn read_import_file(path: &str, label: &str) -> Result<Vec<u8>, String> {
    read_import_file_max(path, label, 256 * 1024 * 1024)
}

fn read_import_file_max(path: &str, label: &str, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // O_NOFOLLOW + O_NONBLOCK (a FIFO does not block); type and size checked by fstat
    // on the descriptor itself, and the read uses the same descriptor (no TOCTOU).
    let handle = open_beneath_parent(Path::new(path))
        .map_err(|error| format!("{label} could not be opened at {path} (symlink is refused): {error}"))?;
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
        return Err(format!("{label} grew beyond {} MiB while being read", max / (1024 * 1024)));
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
    let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string());
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| invalid("no parent directory"))?;
    let name = path.file_name().ok_or_else(|| invalid("no file name"))?;
    let parent_c = CString::new(parent.as_os_str().as_bytes()).map_err(|_| invalid("NUL in the path"))?;
    let name_c = CString::new(name.as_bytes()).map_err(|_| invalid("NUL in the name"))?;
    let dir_fd = unsafe {
        libc::open(parent_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

/// "starting" state: sets `recording` and notifies the menu; if the start does not reach
/// `commit()`, it clears the flag and re-enables the menu on exit (error, `?` or panic).
pub(crate) struct StartingGuard<'a, F: FnMut(bool)> {
    flag: &'a std::sync::atomic::AtomicBool,
    notify: F,
    committed: bool,
}

impl<'a, F: FnMut(bool)> StartingGuard<'a, F> {
    pub(crate) fn begin(flag: &'a std::sync::atomic::AtomicBool, mut notify: F) -> Self {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        notify(true);
        Self { flag, notify, committed: false }
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl<F: FnMut(bool)> Drop for StartingGuard<'_, F> {
    fn drop(&mut self) {
        if !self.committed {
            self.flag.store(false, std::sync::atomic::Ordering::SeqCst);
            (self.notify)(false);
        }
    }
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
pub async fn import_har(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        ensure_not_recording(app.state::<AppState>().recording.load(std::sync::atomic::Ordering::SeqCst))?;
        let bytes = read_import_file(&path, "HAR")?;
        let imported = scrapelens_core::import_har(&bytes)
            .map_err(|error| format!("invalid HAR: {error}. Use a HAR 1.2 file exported from Chrome."))?;
        persist_imported(app, imported, "HAR")
    })
    .await
}

#[tauri::command]
pub async fn import_netlog(app: AppHandle, path: String) -> Result<SessionPayload, String> {
    run_loading(app, move |app| {
        ensure_not_recording(app.state::<AppState>().recording.load(std::sync::atomic::Ordering::SeqCst))?;
        let bytes = read_import_file(&path, "NetLog")?;
        let imported = scrapelens_core::import_netlog(&bytes)
            .map_err(|error| format!("invalid NetLog: {error}. Use the full JSON from Chrome."))?;
        persist_imported(app, imported, "NetLog")
    })
    .await
}

/// Starting URL suggested in the UI: the saved preference, otherwise `SCRAPELENS_CAPTURE_URL`.
#[tauri::command]
pub fn capture_start_url(app: AppHandle) -> String {
    prefs::load_capture_start_url(&app).unwrap_or_else(test_capture_url)
}

/// Test-hooks builds may suggest a start URL from the environment; release builds never do.
#[cfg(feature = "test-hooks")]
fn test_capture_url() -> String {
    std::env::var("SCRAPELENS_CAPTURE_URL").unwrap_or_default()
}

#[cfg(not(feature = "test-hooks"))]
fn test_capture_url() -> String {
    String::new()
}

/// Persists the starting URL (empty clears the preference). Only `http`/`https` when not empty.
#[tauri::command]
pub fn set_capture_start_url(app: AppHandle, url: String) -> Result<String, String> {
    let trimmed = url.trim().to_string();
    if !trimmed.is_empty() {
        cli::validate_http_url(&trimmed)?;
    }
    prefs::save_capture_start_url(&app, if trimmed.is_empty() { None } else { Some(trimmed.as_str()) })?;
    Ok(trimmed)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliActionPayload {
    /// `import-har` | `import-netlog` | `open-capture` | `error` | `warning`.
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Consumes the test CLI action, or the CLI error/warning (at most once per process).
/// Release builds have no command-line test actions: this returns nothing.
#[cfg(not(feature = "test-hooks"))]
#[tauri::command]
pub fn take_cli_action(_state: State<'_, AppState>) -> Option<CliActionPayload> {
    None
}

/// An action only exists with `SCRAPELENS_TEST_MODE=1` (test-hooks builds).
#[cfg(feature = "test-hooks")]
#[tauri::command]
pub fn take_cli_action(state: State<'_, AppState>) -> Option<CliActionPayload> {
    if let Some((kind, message)) = state.cli_message.lock().ok()?.take() {
        return Some(CliActionPayload { kind, path: String::new(), message: Some(message) });
    }
    let action = state.pending_cli.lock().ok()?.take()?;
    let (kind, path) = match action {
        CliAction::ImportHar(path) => ("import-har", path),
        CliAction::ImportNetlog(path) => ("import-netlog", path),
        CliAction::OpenCapture(path) => ("open-capture", path),
    };
    Some(CliActionPayload { kind: kind.to_string(), path: path.display().to_string(), message: None })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieSourceDto {
    id: String,
    browser: String,
    profile: String,
    label: String,
    kind: scrapelens_capture::BrowserKind,
}

impl From<scrapelens_capture::BrowserCookieSource> for CookieSourceDto {
    fn from(source: scrapelens_capture::BrowserCookieSource) -> Self {
        Self { id: source.id, browser: source.browser, profile: source.profile,
            label: source.label, kind: source.kind }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieSourcesPayload {
    sources: Vec<CookieSourceDto>,
    selected: Option<String>,
}

fn resolve_cookie_source<'a>(source: Option<&str>, sources: &'a [CookieSourceDto]) -> Result<Option<&'a CookieSourceDto>, String> {
    match source.filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(id) => sources.iter().find(|item| item.id == id).map(Some)
            .ok_or_else(|| "Cookie source unavailable. Select another browser or a clean session.".to_string()),
    }
}

fn cookie_sources() -> Vec<CookieSourceDto> {
    scrapelens_capture::list_browser_cookie_sources().into_iter().map(Into::into).collect()
}

#[tauri::command]
pub fn list_cookie_sources(app: AppHandle) -> CookieSourcesPayload {
    let sources = cookie_sources();
    let saved = prefs::load_capture_cookie_source(&app);
    let selected = resolve_cookie_source(saved.as_deref(), &sources).ok().flatten().map(|s| s.id.clone());
    CookieSourcesPayload { sources, selected }
}

#[tauri::command]
pub fn set_capture_cookie_source(app: AppHandle, source: Option<String>) -> Result<Option<String>, String> {
    let sources = cookie_sources();
    let selected = resolve_cookie_source(source.as_deref(), &sources)?.map(|s| s.id.clone());
    prefs::save_capture_cookie_source(&app, selected.as_deref())?;
    Ok(selected)
}

/// The Proxy field's state. No credentials in it.
#[tauri::command]
pub fn get_proxy_state(app: AppHandle, state: State<'_, AppState>) -> Result<crate::capture_proxy::ProxyState, String> {
    let active = state.proxy.lock().map_err(|_| "proxy state unavailable")?.clone();
    Ok(crate::capture_proxy::state(prefs::load_capture_proxy(&app), active.as_ref()))
}

/// Parses the link with the capture's own parser, keeps it in memory and saves only its
/// server address. The link itself is never returned. Refused while a capture runs.
#[tauri::command]
pub fn set_proxy_link(
    app: AppHandle,
    state: State<'_, AppState>,
    link: String,
) -> Result<crate::capture_proxy::ProxyInfo, String> {
    ensure_proxy_editable(state.recording.load(std::sync::atomic::Ordering::SeqCst))?;
    let parsed = parse_and_store(&state.proxy, &link)?;
    prefs::save_capture_proxy(&app, Some(&parsed.server_url()))?;
    Ok(crate::capture_proxy::ProxyInfo::of(&parsed))
}

#[tauri::command]
pub fn clear_proxy_link(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    ensure_proxy_editable(state.recording.load(std::sync::atomic::Ordering::SeqCst))?;
    *state.proxy.lock().map_err(|_| "proxy state unavailable")? = None;
    prefs::save_capture_proxy(&app, None)
}

fn ensure_proxy_editable(recording: bool) -> Result<(), String> {
    if recording {
        Err("Stop the capture before changing the proxy.".to_string())
    } else {
        Ok(())
    }
}

/// Parses `text` and, when it is valid, replaces the link kept in memory. The error never
/// contains the input (the parser's messages are fixed).
fn parse_and_store(
    slot: &std::sync::Mutex<Option<scrapelens_capture::proxy::ProxyLink>>,
    text: &str,
) -> Result<scrapelens_capture::proxy::ProxyLink, String> {
    let link = scrapelens_capture::proxy::ProxyLink::parse(text).map_err(|error| error.to_string())?;
    *slot.lock().map_err(|_| "proxy state unavailable")? = Some(link.clone());
    Ok(link)
}

/// Switches that only the test suites use. Without `test-hooks` (release builds) they
/// are off and no test variable is read: normal headless setting, certificate checks on,
/// open network, and loopback through the proxy like any other host.
struct CaptureTestSwitches {
    headless: bool,
    ignore_cert: bool,
    network: scrapelens_capture::NetworkMode,
    proxy_bypass_loopback: bool,
}

#[cfg(feature = "test-hooks")]
fn capture_test_switches() -> CaptureTestSwitches {
    CaptureTestSwitches {
        headless: std::env::var("SCRAPELENS_CAPTURE_HEADLESS").as_deref() == Ok("1"),
        ignore_cert: std::env::var("SCRAPELENS_CAPTURE_IGNORE_CERT").as_deref() == Ok("1"),
        // Normal network by default; the test suites enable loopback-only with
        // `SCRAPELENS_CAPTURE_NETWORK=loopback`.
        network: scrapelens_capture::NetworkMode::from_env(),
        // Loopback targets must really pass through the proxy in the test suites.
        proxy_bypass_loopback: std::env::var("SCRAPELENS_TEST_MODE").as_deref() == Ok("1")
            && std::env::var("SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK").as_deref() == Ok("1"),
    }
}

#[cfg(not(feature = "test-hooks"))]
fn capture_test_switches() -> CaptureTestSwitches {
    CaptureTestSwitches {
        headless: false,
        ignore_cert: false,
        network: scrapelens_capture::NetworkMode::Open,
        proxy_bypass_loopback: false,
    }
}

/// Starts a real capture with an external Chrome. The command returns as soon as
/// CDP is ready; the final v1 session is returned by `stop_session`.
/// `start_url` (optional): a UI field; empty → `about:blank`; only http/https.
#[tauri::command]
pub fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    start_url: Option<String>,
    cookie_source: Option<String>,
) -> Result<SessionPayload, String> {
    // "starting" (A9-B8/A8-B7): the menu disables ⌘⇧R and imports right away;
    // if the start fails, `StartingGuard` re-enables them.
    if state.recording.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("A capture is already in progress or starting. Click Stop before starting another.".to_string());
    }
    // The saved server is the authority: a saved proxy whose password is not in memory
    // stops the start here, before Chrome is launched.
    let proxy = {
        let active = state.proxy.lock().map_err(|_| "proxy state unavailable")?.clone();
        crate::capture_proxy::resolve_for_start(prefs::load_capture_proxy(&app).as_deref(), active.as_ref())?
    };
    let menu_app = app.clone();
    let mut starting = StartingGuard::begin(&state.recording, move |recording| {
        crate::menu::set_recording_menu(&menu_app, recording)
    });
    let slot = state.capture.lock().map_err(|_| "capture state unavailable")?;
    if slot.is_some() {
        return Err("A capture is already in progress. Click Stop before starting another.".to_string());
    }

    let chrome_path = {
        let saved = state.chrome_path.lock().map_err(|_| "Chrome state unavailable")?.clone();
        chrome::detect(saved.as_deref())
            .path
            .map(PathBuf::from)
            .ok_or_else(|| {
                "Chrome not found. Select Google Chrome manually in the banner on screen or in the File menu."
                    .to_string()
            })?
    };

    let resolved_url = cli::resolve_capture_start_url(start_url.as_deref())?;
    // The UI sends the choice explicitly; absence means a clean session.
    let sources = cookie_sources();
    let selected_cookie_source = if resolved_url == "about:blank" { None } else {
        resolve_cookie_source(cookie_source.as_deref(), &sources)?
    };
    let cookie_notice = selected_cookie_source.map(|source| format!(
        " Cookies from {} loaded for the starting URL's site.", source.label
    )).unwrap_or_default();
    let proxy_notice = proxy
        .as_ref()
        .map(|link| format!(" Through the proxy {} (no credentials shown).", link.server_url()))
        .unwrap_or_default();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let session_id = format!("capture-{now}");
    let started_at = iso_now();
    let dir = unique_session_dir(&sessions_root(&app)?, &session_id);
    store::ensure_private_dir(&dir).map_err(|error| format!("session directory: {error}"))?;

    let start_url_for_notice = resolved_url.clone();
    let switches = capture_test_switches();
    let config = CaptureConfig {
        chrome: chrome_path.clone(),
        session_dir: dir.clone(),
        start_url: resolved_url,
        headless: switches.headless,
        ignore_cert: switches.ignore_cert,
        network: switches.network,
        cookie_source: selected_cookie_source.map(|source| source.id.clone()),
        initial_cookies: Vec::new(),
        proxy,
        test_proxy_bypass_loopback: switches.proxy_bypass_loopback,
    };

    let status = Arc::new(Mutex::new(CaptureStatus {
        recording: true,
        events: 0,
        chrome_pid: None,
        session_id: session_id.clone(),
        session_dir: dir.display().to_string(),
        started_at: started_at.clone(),
        page_url: config.start_url.clone(),
        last_error: None,
    }));
    let thread_status = status.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let join = thread::spawn(move || capture::run(config, thread_status, stop_rx, ready_tx));

    // The capture lock is released while the capture starts: Stop and the other commands
    // never wait for a start that is stuck (for example a keyring prompt nobody answers).
    drop(slot);
    let join = await_capture_ready(&ready_rx, &stop_tx, join, &dir, CAPTURE_READY_TIMEOUT)?;
    let Ok(mut slot) = state.capture.lock() else {
        let _ = stop_tx.send(());
        return Err("capture state unavailable".to_string());
    };
    *slot = Some(CaptureSession {
        id: session_id.clone(),
        dir: dir.clone(),
        started_at: started_at.clone(),
        stop: stop_tx,
        join,
        status,
    });
    drop(slot);
    starting.commit();

    Ok(SessionPayload {
        session: json!({
            "schemaVersion": 1,
            "session": {
                "id": session_id,
                "browser": { "name": "Chrome" },
                "startedAt": started_at,
                "completeness": {
                    "state": "partial",
                    "reasons": ["capture in progress; the final session is written by stop_session"]
                },
                "labels": [],
                "notes": ["live capture in progress"]
            },
            "requests": []
        }),
        session_dir: Some(dir.display().to_string()),
        synthetic: false,
        notice: Some((if start_url_for_notice == "about:blank" {
            format!(
                "Capture started with external Chrome at {}. The capture started blank; browse in Chrome or enter a URL.",
                chrome_path.display()
            )
        } else {
            format!(
                "Capture started with external Chrome at {} · {}. Click Stop to record the session.",
                chrome_path.display(),
                start_url_for_notice
            )
        }) + &cookie_notice + &proxy_notice),
        cookie_import: None,
        pending: false,
    })
}

/// Stops the capture, waits for the NetLog flush, imports with the core and writes the
/// v1 session. Returns the session ready for the UI.
#[tauri::command]
pub async fn stop_session(app: AppHandle) -> Result<SessionPayload, String> {
    // Off the main thread; does not use the `loading` flag (stopping never
    // waits for an open in progress).
    tauri::async_runtime::spawn_blocking(move || stop_blocking(&app))
        .await
        .map_err(|error| format!("stopping was interrupted: {error}"))?
}

fn stop_blocking(app: &AppHandle) -> Result<SessionPayload, String> {
    let state = app.state::<AppState>();
    let capture = {
        let mut slot = state.capture.lock().map_err(|_| "capture state unavailable")?;
        slot.take()
    };
    state.recording.store(false, std::sync::atomic::Ordering::SeqCst);
    crate::menu::set_recording_menu(app, false);
    let Some(capture) = capture else {
        return Err("No capture in progress to stop.".to_string());
    };
    let _ = capture.stop.send(());
    let payload = capture
        .join
        .join()
        .map_err(|_| "the capture thread ended unexpectedly".to_string())??;
    if let Ok(mut last) = state.last_session_dir.lock() {
        *last = Some(capture.dir.clone());
    }
    Ok(payload)
}

#[tauri::command]
pub fn capture_status(state: State<'_, AppState>) -> Option<CaptureStatus> {
    state
        .capture
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|capture| capture.status.lock().map(|status| status.clone()).unwrap_or_default()))
}

fn iso_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = now.as_secs();
    let millis = now.subsec_millis();
    let days = (seconds / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    let day_seconds = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}

/// civil_from_days algorithm (Howard Hinnant), without a chrono dependency.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

#[tauri::command]
pub fn detect_chrome(state: State<'_, AppState>) -> ChromeInfo {
    let saved = state.chrome_path.lock().expect("chrome_path lock").clone();
    chrome::detect(saved.as_deref())
}

#[tauri::command]
pub fn set_chrome_path(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ChromeInfo, String> {
    let resolved = chrome::normalize_binary_path(Path::new(&path))
        .ok_or_else(|| format!("could not find the Chrome binary at {path}"))?;
    if !resolved.is_file() {
        return Err(format!(
            "the chosen path is not an executable: {}",
            resolved.display()
        ));
    }
    // Only a Chromium-based browser is accepted (see `browser_check`); nothing is run.
    let resolved = crate::browser_check::accept(&resolved)?;
    prefs::save_chrome_path(&app, &resolved)?;
    *state.chrome_path.lock().expect("chrome_path lock") = Some(resolved.clone());
    Ok(ChromeInfo {
        found: true,
        path: Some(resolved.display().to_string()),
        source: "manual".to_string(),
        candidates: chrome::candidates(),
    })
}

/// Reads a text preview of a session attachment (hard limit, never leaves the folder).
#[tauri::command]
pub fn read_attachment(session_dir: String, name: String) -> Result<AttachmentPayload, String> {
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
fn open_attachment(session_dir: &str, name: &str) -> Result<(fs::File, u64), String> {
    store::open_regular_attachment(Path::new(session_dir), name).map_err(|error| error.to_string())
}

/// Searches the payload via `scrapelens_core::search`, off the UI thread.
/// `max_matches` limits the result; the front end does not reimplement the search.
#[tauri::command]
pub async fn search_session(
    session_dir: String,
    text: String,
    scopes: Vec<String>,
    case_sensitive: bool,
    max_matches: Option<usize>,
) -> Result<scrapelens_core::search::SearchResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        run_search(&session_dir, &text, &scopes, case_sensitive, max_matches)
    })
    .await
    .map_err(|error| format!("the search was interrupted: {error}"))?
}

/// Lazy sessions (up to two) used by search, origins, chain and comparison (attachments read one at a time). Key: folder + (size, mtime) of
/// `session.json` + mtime of `attachments/`; if changed, reload. Keeps only one
/// session (opening another replaces it) and retains neither bodies nor the raw CDP/NetLog.
struct CachedSession {
    dir: PathBuf,
    fingerprint: Vec<Option<(u64, SystemTime)>>,
    lazy: Arc<scrapelens_core::lazy::LazySession>,
}

/// Two cached sessions (the open one and the compared one); the oldest leaves first.
static SESSION_CACHE: Mutex<Vec<CachedSession>> = Mutex::new(Vec::new());
static SESSION_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn session_fingerprint(path: &Path) -> Vec<Option<(u64, SystemTime)>> {
    let stat = |p: PathBuf| fs::metadata(p).ok().and_then(|meta| Some((meta.len(), meta.modified().ok()?)));
    if path.is_file() {
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return vec![stat(path.to_path_buf()), stat(parent.join("attachments"))];
    }
    ["session.json", "attachments"].iter().map(|name| stat(path.join(name))).collect()
}

/// Session file with any name: read typed as a stream (no `Value`),
/// opened through the parent without following symlinks; attachments are relative to the file's folder.
fn open_session_file_lazy(file: &Path) -> Result<scrapelens_core::lazy::LazySession, String> {
    let handle = open_beneath_parent(file)
        .map_err(|error| format!("could not open {} (symlink is refused): {error}", file.display()))?;
    let meta = handle.metadata().map_err(|error| format!("failed to inspect {}: {error}", file.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    let session: scrapelens_core::model::SessionV1 =
        serde_json::from_reader(std::io::BufReader::with_capacity(1 << 20, handle))
            .map_err(|error| format!("invalid session file: {error}"))?;
    let parent = file.parent().map(Path::to_path_buf).ok_or("the file has no parent folder")?;
    Ok(scrapelens_core::lazy::LazySession::new(session, parent))
}

pub(crate) fn cached_session(dir: &Path) -> Result<Arc<scrapelens_core::lazy::LazySession>, String> {
    // Canonical key: `./s`, `s` and symlinks to the same folder share the entry.
    let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let dir = canonical.as_path();
    let mut guard = SESSION_CACHE.lock().map_err(|_| "search cache corrupted".to_string())?;
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
    guard.push(CachedSession { dir: dir.to_path_buf(), fingerprint, lazy: lazy.clone() });
    Ok(lazy)
}

fn run_search(
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

const HEX_PREVIEW_BYTES: usize = 256;

/// Reads an attached body up to `limit` bytes. Text becomes a `String` (the front end
/// shows it in `<pre>`); the rest becomes only a size and a hex preview.
#[tauri::command]
pub async fn read_body(session_dir: String, name: String, limit: Option<u64>) -> Result<BodyPayload, String> {
    tauri::async_runtime::spawn_blocking(move || read_body_blocking(&session_dir, &name, limit.unwrap_or(262_144)))
        .await
        .map_err(|error| format!("the read was interrupted: {error}"))?
}

fn read_body_blocking(session_dir: &str, name: &str, limit: u64) -> Result<BodyPayload, String> {
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
    session_dir: String,
    request_id: String,
) -> Result<scrapelens_core::flow::ValueOrigins, String> {
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
    session_dir: String,
    request_id: String,
) -> Result<scrapelens_core::flow::PrimingChain, String> {
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
    session_dir: String,
    request_id: String,
    side: String,
) -> Result<crate::adapters::AdapterView, String> {
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
pub async fn session_timeline(session_dir: String) -> Result<scrapelens_core::timeline::Timeline, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = Path::new(&session_dir);
        let rules = load_rules(dir)?;
        let lazy = cached_session(dir)?;
        Ok(scrapelens_core::timeline::timeline(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            &scrapelens_core::timeline::TimelineOptions { flow: crate::adapters::flow_options(), rules },
        ))
    })
    .await
    .map_err(|error| format!("the calculation was interrupted: {error}"))?
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    /// New folder (0700) with the session imported from the trace; contains execution data.
    pub trace_dir: String,
    pub trace_requests: usize,
    pub validation: scrapelens_core::validate::Validation,
}

fn validation_root(app: &AppHandle) -> Result<PathBuf, String> {
    let data = app.path().app_data_dir().map_err(|error| format!("no app data directory: {error}"))?;
    crate::validation::tmp_root(&data)
}

/// Discards the trace's temporary session (closing the validation screen).
#[tauri::command]
pub fn discard_validation(app: AppHandle, trace_dir: String) -> Result<(), String> {
    crate::validation::discard(&validation_root(&app)?, Path::new(&trace_dir))
}

/// "Keep this execution": copies the trace's session to a new folder and deletes the temporary one.
#[tauri::command]
pub async fn keep_validation(app: AppHandle, trace_dir: String, destination: String) -> Result<String, String> {
    let root = validation_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::validation::keep(&root, Path::new(&trace_dir), Path::new(&destination)).map(|p| p.display().to_string())
    })
    .await
    .map_err(|error| format!("saving failed: {error}"))?
}

/// Imports the script's execution trace (`scrapelens.trace/1`) into a new folder and validates
/// it against the open session. Nothing is executed and no network is used.
#[tauri::command]
pub async fn validate_execution(
    app: AppHandle,
    session_dir: String,
    trace_path: String,
    map_origin: Option<String>,
) -> Result<ValidationResult, String> {
    let root = validation_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        validate_execution_blocking(&root, Path::new(&session_dir), &trace_path, map_origin.as_deref())
    })
    .await
    .map_err(|error| format!("the validation was interrupted: {error}"))?
}

fn validate_execution_blocking(
    root: &Path,
    capture_dir: &Path,
    trace_path: &str,
    map_origin: Option<&str>,
) -> Result<ValidationResult, String> {
    use scrapelens_core::validate::{validate, ValidateOptions};
    let map = match map_origin.map(str::trim).filter(|m| !m.is_empty()) {
        None => None,
        Some(text) => Some(
            scrapelens_core::compare::OriginMap::parse(text)
                .ok_or_else(|| format!("invalid origin mapping ({text}); use <capture-origin>=<trace-origin>, for example https://app.example.com=http://127.0.0.1:8080"))?,
        ),
    };
    let bytes = read_import_file_max(trace_path, "execution trace", crate::validation::TRACE_MAX_BYTES)?;
    let imported = scrapelens_core::parse::import_trace(&bytes).map_err(|error| {
        format!("invalid trace: {error}. Use the file generated by the priming script with --trace (scrapelens.trace/1).")
    })?;
    let dir = unique_session_dir(root, &sanitize_dir_name(&imported.bundle.session.session.id));
    store::write_session_dir(&imported.bundle, &dir)
        .map_err(|error| format!("could not write the trace session: {error}"))?;
    let rules = load_rules(capture_dir)?;
    let capture = cached_session(capture_dir)?;
    let trace = cached_session(&dir)?;
    let mut options = ValidateOptions { rules, ..Default::default() };
    options.compare.flow = crate::adapters::flow_options();
    // `plan.hash` is recalculated with the same adapters used for generation (the app always generates and validates with the adapter)
    options.compare.map_origin = map;
    let validation = validate(
        &capture.session,
        &scrapelens_core::search::LazyBodies(&capture),
        &trace.session,
        &scrapelens_core::search::LazyBodies(&trace),
        &options,
    );
    Ok(ValidationResult {
        trace_dir: dir.display().to_string(),
        trace_requests: trace.session.requests.len(),
        validation,
    })
}

/// Application success × HTTP (`assess::assess_session`). Optional rules in
/// `<session>/assess-rules.json`; invalid rules become an actionable error.
#[tauri::command]
pub async fn assess_session(session_dir: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || assess_blocking(Path::new(&session_dir)))
        .await
        .map_err(|error| format!("the assessment was interrupted: {error}"))?
}

/// Optional rules `<session>/assess-rules.json` (regular file, up to 256 KiB); default when the file is absent.
fn load_rules(dir: &Path) -> Result<scrapelens_core::assess::AssessRules, String> {
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

const RULES_MAX_BYTES: u64 = 256 * 1024;

/// Reads `assess-rules.json` only if it is a regular file without a symlink (symlink_metadata + inode) and up to 256 KiB.
/// `None` when it does not exist.
fn read_rules_file(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not check {}: {error}", path.display())),
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("{} is not a regular file (symbolic link refused); remove it", path.display()));
    }
    let file = fs::File::open(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let opened = file.metadata().map_err(|error| format!("could not read {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(format!("{} changed while being opened; refused", path.display()));
        }
    }
    if !opened.is_file() || opened.len() > RULES_MAX_BYTES {
        return Err(format!("{} exceeds 256 KiB or is not a regular file; reduce or remove the file", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(RULES_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.len() as u64 > RULES_MAX_BYTES {
        return Err(format!("{} exceeds 256 KiB; reduce or remove the file", path.display()));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| format!("{} is not valid UTF-8; fix or remove the file", path.display()))
}

pub(crate) fn assess_blocking(dir: &Path) -> Result<serde_json::Value, String> {
    use scrapelens_core::assess::assess_session;
    let rules_path = dir.join("assess-rules.json");
    let rules = load_rules(dir)?;
    let lazy = cached_session(dir)?;
    let outcomes = assess_session(&lazy.session, &scrapelens_core::search::LazyBodies(&lazy), &rules);
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for outcome in &outcomes {
        *counts.entry(outcome.verdict_kind.count_key().to_string()).or_default() += 1;
    }
    Ok(serde_json::json!({
        "schema": "scrapelens.assess/1",
        "rules": if rules_path.is_file() { rules_path.display().to_string() } else { "default".to_string() },
        "counts": counts,
        "warnings": rules.warnings(),
        "outcomes": outcomes,
    }))
}

/// Comparison kept in Rust: the UI receives only the summary and requests pages of pairs
/// and the fields of a pair on demand (avoids tens of MB of JSON over IPC).
struct StoredComparison {
    id: u64,
    result: Arc<scrapelens_core::compare::SessionComparison>,
}

static COMPARISON: Mutex<Option<StoredComparison>> = Mutex::new(None);
static COMPARISON_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const ONLY_LIST_CAP: usize = 200;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareSummary {
    pub handle: u64,
    pub pairs: usize,
    /// Pairs with at least one field that is not static (candidates for the "only dynamic" filter).
    pub dynamic_pairs: usize,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub redacted_fields: usize,
    pub ambiguities: Vec<String>,
    pub warnings: Vec<String>,
    pub only_in_a: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_a_total: usize,
    pub only_in_b: Vec<scrapelens_core::compare::RequestRef>,
    pub only_in_b_total: usize,
    /// Leftovers of the same model on both sides (probable reordering), limited.
    pub reordered: Vec<scrapelens_core::compare::ReorderedPair>,
    pub reordered_total: usize,
    /// Paired rounds, unpaired rounds and the entry request (docs/10 L6).
    pub rounds: Vec<scrapelens_core::compare::RoundInfo>,
    pub unpaired_rounds: Vec<scrapelens_core::compare::UnpairedRound>,
    pub entry_request: Option<String>,
    /// Protection/static fields outside the alignment: type + totals, with limited lists.
    pub groups: Vec<GroupSummary>,
    pub include_all: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub kind: String,
    pub a: Vec<scrapelens_core::compare::RequestRef>,
    pub a_total: usize,
    pub b: Vec<scrapelens_core::compare::RequestRef>,
    pub b_total: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSummary {
    pub index: usize,
    /// Index into `rounds`.
    pub round: usize,
    pub a: scrapelens_core::compare::RequestRef,
    pub b: scrapelens_core::compare::RequestRef,
    pub aligned_by: String,
    pub out_of_order: bool,
    pub counts: scrapelens_core::compare::PairCounts,
    pub parts_counts: scrapelens_core::compare::PartsCounts,
    pub field_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparePage {
    /// Pairs that pass the filter (not only those on this page).
    pub total: usize,
    pub items: Vec<PairSummary>,
}

fn pair_is_dynamic(pair: &scrapelens_core::compare::PairComparison) -> bool {
    let c = &pair.counts;
    c.dynamic + c.only_a + c.only_b + c.redacted > 0
}

/// Compares the open session (A) with another folder (B), off the UI thread.
#[tauri::command]
pub async fn compare_open(
    dir_a: String,
    dir_b: String,
    include_all: Option<bool>,
    a_range: Option<String>,
    b_range: Option<String>,
) -> Result<CompareSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let options = compare_options(include_all.unwrap_or(false), a_range.as_deref(), b_range.as_deref())?;
        open_comparison_with(&dir_a, &dir_b, options)
    })
        .await
        .map_err(|error| format!("the comparison was interrupted: {error}"))?
}

/// Page of pairs (summaries, without fields).
#[tauri::command]
pub async fn compare_page(handle: u64, offset: usize, limit: usize, only_dynamic: bool) -> Result<ComparePage, String> {
    tauri::async_runtime::spawn_blocking(move || comparison_page(handle, offset, limit, only_dynamic))
        .await
        .map_err(|error| format!("the read was interrupted: {error}"))?
}

/// Fields of a pair (in source order), loaded on expansion.
#[tauri::command]
pub async fn compare_fields(handle: u64, index: usize) -> Result<Vec<scrapelens_core::compare::FieldDiff>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = stored_comparison(handle)?;
        result
            .pairs
            .get(index)
            .map(|pair| pair.fields.clone())
            .ok_or_else(|| format!("pair {index} does not exist"))
    })
    .await
    .map_err(|error| format!("the read was interrupted: {error}"))?
}

fn stored_comparison(handle: u64) -> Result<Arc<scrapelens_core::compare::SessionComparison>, String> {
    let guard = COMPARISON.lock().map_err(|_| "comparison corrupted".to_string())?;
    match guard.as_ref() {
        Some(stored) if stored.id == handle => Ok(stored.result.clone()),
        _ => Err("this comparison was replaced by another; compare again".to_string()),
    }
}

fn comparison_page(handle: u64, offset: usize, limit: usize, only_dynamic: bool) -> Result<ComparePage, String> {
    let result = stored_comparison(handle)?;
    let limit = limit.clamp(1, 500);
    let mut total = 0usize;
    let mut items = Vec::new();
    for (index, pair) in result.pairs.iter().enumerate() {
        if only_dynamic && !pair_is_dynamic(pair) {
            continue;
        }
        if total >= offset && items.len() < limit {
            items.push(PairSummary {
                index,
                round: pair.round,
                a: pair.a.clone(),
                b: pair.b.clone(),
                aligned_by: pair.aligned_by.clone(),
                out_of_order: pair.out_of_order,
                counts: pair.counts.clone(),
                parts_counts: pair.parts_counts.clone(),
                field_count: pair.fields.len(),
            });
        }
        total += 1;
    }
    Ok(ComparePage { total, items })
}

/// Canonicalized paths (resolves `./s`, `s` and symlinks): the same session through
/// two paths is refused.
fn compare_options(
    include_all: bool,
    a_range: Option<&str>,
    b_range: Option<&str>,
) -> Result<scrapelens_core::compare::CompareOptions, String> {
    use scrapelens_core::compare::RequestRange;
    let range = |label: &str, text: Option<&str>| -> Result<Option<RequestRange>, String> {
        match text.map(str::trim).filter(|t| !t.is_empty()) {
            None => Ok(None),
            Some(text) => RequestRange::parse(text)
                .map(Some)
                .ok_or_else(|| format!("invalid {label} range ({text}); use from:to, for example 10:50 or har-0010:har-0050")),
        }
    };
    Ok(scrapelens_core::compare::CompareOptions {
        include_all,
        a_range: range("A", a_range)?,
        b_range: range("B", b_range)?,
        flow: crate::adapters::flow_options(),
        ..Default::default()
    })
}

#[cfg(test)]
fn open_comparison(dir_a: &str, dir_b: &str) -> Result<CompareSummary, String> {
    open_comparison_with(dir_a, dir_b, scrapelens_core::compare::CompareOptions::default())
}

fn open_comparison_with(
    dir_a: &str,
    dir_b: &str,
    options: scrapelens_core::compare::CompareOptions,
) -> Result<CompareSummary, String> {
    let canon = |label: &str, dir: &str| {
        fs::canonicalize(dir).map_err(|error| format!("session {label} is inaccessible ({dir}): {error}"))
    };
    let a_path = canon("A", dir_a)?;
    let b_path = canon("B", dir_b)?;
    if a_path == b_path {
        return Err(format!(
            "A and B are the same session ({}); choose another folder to compare",
            a_path.display()
        ));
    }
    let a = cached_session(&a_path)?;
    let b = cached_session(&b_path).map_err(|error| format!("session B: {error}"))?;
    let result = scrapelens_core::compare::compare_sessions(
        &a.session,
        &scrapelens_core::search::LazyBodies(&a),
        &b.session,
        &scrapelens_core::search::LazyBodies(&b),
        &options,
    );
    let id = COMPARISON_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let summary = CompareSummary {
        handle: id,
        pairs: result.pairs.len(),
        dynamic_pairs: result.pairs.iter().filter(|pair| pair_is_dynamic(pair)).count(),
        counts: result.counts.clone(),
        parts_counts: result.parts_counts.clone(),
        redacted_fields: result.redacted_fields,
        ambiguities: result.ambiguities.iter().take(ONLY_LIST_CAP).cloned().collect(),
        warnings: result.warnings.clone(),
        only_in_a: result.only_in_a.iter().take(ONLY_LIST_CAP).cloned().collect(),
        only_in_a_total: result.only_in_a.len(),
        only_in_b: result.only_in_b.iter().take(ONLY_LIST_CAP).cloned().collect(),
        only_in_b_total: result.only_in_b.len(),
        reordered: result.reordered.iter().take(ONLY_LIST_CAP).cloned().collect(),
        reordered_total: result.reordered.len(),
        rounds: result.rounds.clone(),
        unpaired_rounds: result.unpaired_rounds.clone(),
        entry_request: result.entry_request.clone(),
        groups: result
            .groups
            .iter()
            .map(|group| GroupSummary {
                kind: group.kind.clone(),
                a: group.a.iter().take(ONLY_LIST_CAP).cloned().collect(),
                a_total: group.a.len(),
                b: group.b.iter().take(ONLY_LIST_CAP).cloned().collect(),
                b_total: group.b.len(),
            })
            .collect(),
        include_all: options.include_all,
    };
    *COMPARISON.lock().map_err(|_| "comparison corrupted".to_string())? =
        Some(StoredComparison { id, result: Arc::new(result) });
    Ok(summary)
}

/// Priming script (full chain up to the request); uses the protocol adapter's encoder
/// when it claims the field, and reports that in the preview.
fn priming_preview(dir: &Path, request_id: &str, lenient_parts: bool) -> Result<crate::export::ExportPreview, String> {
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
fn export_preview(
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
    session_dir: String,
    request_id: String,
    format: String,
    annotate_origins: Option<bool>,
    lenient_parts: Option<bool>,
) -> Result<crate::export::ExportPreview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        export_preview(Path::new(&session_dir), &request_id, &format, annotate_origins.unwrap_or(false), lenient_parts.unwrap_or(false))
    })
    .await
    .map_err(|error| format!("generating the export failed: {error}"))?
}

/// Writes the exported text to a new file (0600), refusing overwrites and
/// symbolic links. The path comes from the native save dialog.
#[tauri::command]
pub async fn save_export_file(path: String, text: String) -> Result<crate::export::SavedFile, String> {
    tauri::async_runtime::spawn_blocking(move || crate::export::write_text_file(Path::new(&path), &text))
        .await
        .map_err(|error| format!("saving failed: {error}"))?
}

/// Sanitization counts and warnings, without writing anything.
#[tauri::command]
pub async fn preview_sanitized(session_dir: String, include_sensitive: Option<bool>) -> Result<crate::export::SanitizePreview, String> {
    tauri::async_runtime::spawn_blocking(move || crate::export::sanitize_preview_with_options(Path::new(&session_dir), include_sensitive.unwrap_or(false)))
        .await
        .map_err(|error| format!("the sanitization preview failed: {error}"))?
}

/// Writes the sanitized session to a new folder chosen by the user.
#[tauri::command]
pub async fn save_sanitized(
    session_dir: String,
    destination: String,
    include_sensitive: Option<bool>,
) -> Result<crate::export::SanitizeSaved, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::export::sanitize_to_with_options(Path::new(&session_dir), Path::new(&destination), include_sensitive.unwrap_or(false))
    })
    .await
    .map_err(|error| format!("sanitization failed: {error}"))?
}

#[tauri::command]
pub fn reveal_path(path: String) -> Result<(), String> {
    let target = PathBuf::from(&path);
    if !target.exists() {
        return Err(format!("path not found: {path}"));
    }
    #[cfg(target_os = "macos")]
    {
        let status = if target.is_dir() {
            std::process::Command::new("open").arg(&target).status()
        } else {
            std::process::Command::new("open").arg("-R").arg(&target).status()
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
            Err(error) => Err(format!("could not open the file manager (xdg-open): {error}")),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("revealing a file is not supported on this platform".to_string())
    }
}

/// Folder to open in the file manager: the folder itself or the file's parent.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn reveal_dir(target: &std::path::Path) -> PathBuf {
    if target.is_dir() {
        target.to_path_buf()
    } else {
        target.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("/"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reveal_dir_uses_parent_for_files() {
        let dir = std::env::temp_dir().join(format!("sl-reveal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(super::reveal_dir(&file), dir);
        assert_eq!(super::reveal_dir(&dir), dir);
        std::fs::remove_dir_all(&dir).unwrap();
    }


    #[test]
    fn import_read_uses_fd_refusing_symlink_fifo_and_dir() {
        use std::os::unix::fs::symlink;
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-fdread-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("a.har");
        std::fs::write(&file, b"{\"log\":{}}").unwrap();
        assert_eq!(read_import_file_max(file.to_str().unwrap(), "HAR", 1024).unwrap(), b"{\"log\":{}}");
        assert!(read_import_file_max(file.to_str().unwrap(), "HAR", 3).unwrap_err().contains("larger"));
        let link = root.join("l.har");
        symlink(&file, &link).unwrap();
        assert!(read_import_file_max(link.to_str().unwrap(), "HAR", 1024).is_err());
        let fifo = root.join("p.har");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // FIFO with no writer: O_NONBLOCK does not block; fstat refuses it for not being regular.
        assert!(read_import_file_max(fifo.to_str().unwrap(), "HAR", 1024).unwrap_err().contains("regular"));
        assert!(read_import_file_max(root.to_str().unwrap(), "HAR", 1024).unwrap_err().contains("directory"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn import_open_fails_when_parent_is_swapped_for_symlink() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-openat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("dir/a.har"), b"good").unwrap();
        std::fs::write(root.join("other/a.har"), b"evil").unwrap();
        let path = root.join("dir/a.har");
        crate::cli::validate_absolute_regular_file(&path).unwrap();
        assert_eq!(read_import_file_max(path.to_str().unwrap(), "HAR", 64).unwrap(), b"good");
        // swap the parent for a symlink after validation
        std::fs::rename(root.join("dir"), root.join("dir-old")).unwrap();
        std::os::unix::fs::symlink(root.join("other"), root.join("dir")).unwrap();
        assert!(read_import_file_max(path.to_str().unwrap(), "HAR", 64).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn second_open_is_refused_while_one_is_loading() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        let first = FlagGuard::acquire(&flag).expect("first open");
        assert!(FlagGuard::acquire(&flag).is_none(), "a second parallel open must be refused");
        drop(first);
        assert!(FlagGuard::acquire(&flag).is_some(), "released when finished");
        let result = std::panic::catch_unwind(|| {
            let _g = FlagGuard::acquire(&flag).unwrap();
            panic!("open failed");
        });
        assert!(result.is_err());
        assert!(!flag.load(std::sync::atomic::Ordering::SeqCst), "a panic also releases it");
    }

    #[test]
    fn starting_state_disables_menu_and_reenables_on_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = AtomicBool::new(false);
        let calls = std::cell::RefCell::new(Vec::new());
        {
            let _g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
            assert!(flag.load(Ordering::SeqCst));
            assert!(crate::menu::blocked_while_recording("start-session", &flag));
            // start fails (exits without commit)
        }
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(*calls.borrow(), vec![true, false]);
        calls.borrow_mut().clear();
        {
            let mut g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
            g.commit();
        }
        assert!(flag.load(Ordering::SeqCst), "a successful start keeps recording");
        assert_eq!(*calls.borrow(), vec![true]);
    }

    #[test]
    fn opens_session_file_with_any_name_but_not_symlink() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
            "scrapelens-anyname-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("my-capture.json");
        std::fs::write(&file, MINIMAL_SESSION).unwrap();
        let payload = read_session_payload(file.to_str().unwrap()).unwrap();
        assert_eq!(payload.session["requestCount"], 0);
        assert_eq!(payload.session.pointer("/session/id").unwrap(), "test-session");
        assert_eq!(payload.session_dir.as_deref(), file.to_str());
        let page = crate::listing::list_page(&cached_session(&file).unwrap().session, 0, 10, &Default::default());
        assert_eq!(page.total, 0);

        let link = root.join("shortcut.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_session_payload(link.to_str().unwrap()).unwrap_err().contains("symlink"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn imports_are_refused_while_recording() {
        assert!(ensure_not_recording(true).unwrap_err().contains("Stop the recording"));
        assert!(ensure_not_recording(false).is_ok());
        assert_eq!(crate::menu::RECORDING_DISABLED_IDS, ["import-har", "import-netlog", "start-session"]);
    }

    #[test]
    fn menu_guard_never_waits_on_capture_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let state = crate::AppState::default();
        // start_session holds the lock (up to 35 s); the menu must respond right away.
        let _held = state.capture.lock().unwrap();
        let started = std::time::Instant::now();
        assert!(!crate::menu::blocked_while_recording("start-session", &state.recording));
        state.recording.store(true, Ordering::SeqCst);
        assert!(crate::menu::blocked_while_recording("start-session", &state.recording));
        assert!(crate::menu::blocked_while_recording("import-har", &state.recording));
        assert!(!crate::menu::blocked_while_recording("stop-session", &state.recording));
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        let _ = AtomicBool::new(false);
    }
    use super::*;

    static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_session_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("attachments")).unwrap();
        dir
    }

    const MINIMAL_SESSION: &str = r#"{
      "schemaVersion": 1,
      "session": {
        "id": "test-session",
        "startedAt": "2026-10-26T20:00:00Z",
        "labels": ["synthetic-fixture"],
        "completeness": { "state": "partial", "reasons": ["test fixture"] }
      },
      "requests": []
    }"#;

    #[test]
    fn opens_a_v1_session_directory_and_flags_synthetic() {
        let dir = temp_session_dir("ok");
        fs::write(dir.join("session.json"), MINIMAL_SESSION).unwrap();
        let payload = read_session_payload(dir.to_str().unwrap()).unwrap();
        assert!(payload.synthetic);
        assert_eq!(payload.session["schemaVersion"], 1);
        assert_eq!(payload.session["requestCount"], 0);
        assert_eq!(payload.session["requests"], serde_json::json!([]));
        assert_eq!(payload.session.pointer("/session/id").unwrap(), "test-session");
        assert!(payload.session_dir.is_some());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let dir = temp_session_dir("version");
        fs::write(
            dir.join("session.json"),
            MINIMAL_SESSION.replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
        )
        .unwrap();
        let error = read_session_payload(dir.to_str().unwrap()).unwrap_err();
        assert!(error.contains("schemaVersion 2"), "{error}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rejects_missing_session_file() {
        let error = read_session_payload("/path/that/does/not/exist/scrapelens").unwrap_err();
        assert!(error.contains("not found"), "{error}");
    }

    #[test]
    fn attachment_preview_is_text_inside_attachments() {
        let dir = temp_session_dir("attachment");
        fs::write(dir.join("attachments/req.bin"), b"hello").unwrap();
        let payload = read_attachment(dir.to_str().unwrap().to_string(), "req.bin".to_string()).unwrap();
        assert_eq!(payload.kind, "text");
        assert_eq!(payload.text.as_deref(), Some("hello"));
        assert!(read_attachment(dir.to_str().unwrap().to_string(), "../escape".to_string()).is_err());
        fs::remove_dir_all(dir).ok();
    }

    fn detran_session(name: &str) -> PathBuf {
        fixture_session(name, "detran-pb", "detran-pb")
    }

    fn fixture_session(name: &str, folder: &str, stem: &str) -> PathBuf {
        use scrapelens_core::correlate::CorrelationOptions;
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(folder);
        let read = |file: String| fs::read(fixtures.join(file)).unwrap();
        let imported = scrapelens_core::parse::import_capture_with_bodies(
            &read(format!("{stem}.cdp.jsonl")),
            &read(format!("{stem}.netlog.json")),
            Some(&read(format!("{stem}.cdp-bodies.jsonl"))),
            CorrelationOptions::default(),
        )
        .unwrap();
        let dir = temp_session_dir(name);
        fs::remove_dir_all(&dir).ok();
        store::write_session_dir(&imported.bundle, &dir).unwrap();
        dir
    }

    #[test]
    fn search_session_finds_body_only_and_reports_partial() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("search");
        let found = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &[], false, None).unwrap();
        assert_eq!(found.matches.len(), 2);
        assert!(found.matches.iter().all(|m| m.decoded && m.scope == scrapelens_core::search::Scope::RequestBody));
        assert!(found.partial && !found.partial_attempts.is_empty());
        let url_only = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &["url".into()], false, None).unwrap();
        assert!(url_only.matches.is_empty());
        let capped = run_search(dir.to_str().unwrap(), "cmd_consultar_placa", &[], false, Some(1)).unwrap();
        assert_eq!(capped.matches.len(), 1);
        assert!(capped.limit_reached);
        assert!(run_search(dir.to_str().unwrap(), "x", &["nope".into()], false, None).is_err());
        assert!(run_search(dir.to_str().unwrap(), "", &[], false, None).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn read_body_text_binary_and_cut() {
        let dir = temp_session_dir("body");
        let att = dir.join("attachments");
        // Non-ASCII UTF-8 text (multi-byte characters), so the cut must respect character boundaries.
        fs::write(att.join("t.bin"), "áéíóú".repeat(100)).unwrap();
        fs::write(att.join("b.bin"), [0u8, 159, 146, 150, 255]).unwrap();
        let d = dir.to_str().unwrap();
        let text = read_body_blocking(d, "t.bin", 1000).unwrap();
        assert_eq!(text.kind, "text");
        assert!(!text.cut);
        let cut = read_body_blocking(d, "t.bin", 101).unwrap();
        assert!(cut.cut && cut.kind == "text" && cut.shown_bytes < 101);
        let bin = read_body_blocking(d, "b.bin", 1000).unwrap();
        assert_eq!(bin.kind, "binary");
        assert_eq!(bin.hex.as_deref(), Some("00 9f 92 96 ff"));
        assert!(bin.text.is_none());
        assert!(read_body_blocking(d, "../x", 10).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn bundle_cache_reuses_and_invalidates() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("cache");
        let first = cached_session(&dir).unwrap();
        let second = cached_session(&dir).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "the second search must reuse the bundle");
        // file changed (size/mtime) → reload
        let session_file = dir.join("session.json");
        let mut text = fs::read_to_string(&session_file).unwrap();
        text.push('\n');
        fs::write(&session_file, text).unwrap();
        let third = cached_session(&dir).unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        // another session replaces the previous one
        let other = detran_session("cache-other");
        let fourth = cached_session(&other).unwrap();
        assert!(!Arc::ptr_eq(&third, &fourth));
        fs::remove_dir_all(dir).ok();
        fs::remove_dir_all(other).ok();
    }

    #[cfg(unix)]
    #[test]
    fn attachments_refuse_symlinks() {
        let dir = temp_session_dir("symlink");
        let outside = temp_session_dir("symlink-outside");
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        let att = dir.join("attachments");
        std::os::unix::fs::symlink(outside.join("secret.txt"), att.join("link.bin")).unwrap();
        fs::write(att.join("ok.bin"), "ok").unwrap();
        let d = dir.to_str().unwrap();
        assert!(read_body_blocking(d, "link.bin", 100).unwrap_err().contains("symbolic link"));
        assert!(read_attachment(d.to_string(), "link.bin".to_string()).unwrap_err().contains("symbolic link"));
        assert_eq!(read_body_blocking(d, "ok.bin", 100).unwrap().kind, "text");
        // attachments/ folder as a link
        let dir2 = temp_session_dir("symlink2");
        fs::remove_dir_all(dir2.join("attachments")).unwrap();
        std::os::unix::fs::symlink(&att, dir2.join("attachments")).unwrap();
        assert!(read_body_blocking(dir2.to_str().unwrap(), "ok.bin", 100).unwrap_err().contains("symbolic link"));
        // directory in place of a file
        fs::create_dir(att.join("sub")).unwrap();
        assert!(read_body_blocking(d, "sub", 100).is_err());
        for d in [dir, dir2, outside] {
            fs::remove_dir_all(d).ok();
        }
    }

    /// Manual measurement: `SL_LARGE_DIR=<session> cargo test --release -- --ignored large_search --nocapture`.
    #[test]
    #[ignore]
    fn large_search_timing() {
        let dir = std::env::var("SL_LARGE_DIR").expect("set SL_LARGE_DIR");
        for round in 1..=3 {
            let start = std::time::Instant::now();
            let found = run_search(&dir, "zzzz", &[], false, None).unwrap();
            eprintln!("search {round}: {:?}, {} matches, loads={}, current_rss={}", start.elapsed(), found.matches.len(), SESSION_LOADS.load(std::sync::atomic::Ordering::SeqCst), String::from_utf8_lossy(&std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap().stdout).trim());
        }
    }

    #[test]
    fn origins_chain_and_compare_on_detran_fixtures() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = detran_session("flow-a");
        let b = fixture_session("flow-b", "detran-pb-b", "detran-pb-b");
        let lazy = cached_session(&a).unwrap();
        let source = scrapelens_core::search::LazyBodies(&lazy);
        let options = scrapelens_core::flow::FlowOptions::default();
        let origins = scrapelens_core::flow::value_origins(&lazy.session, &source, "cdp-r0011", &options).unwrap();
        assert!(origins.values.iter().any(|v| v.field == "JSESSIONID"));
        let chain = scrapelens_core::flow::priming_chain(&lazy.session, &source, "cdp-r0011", &options).unwrap();
        assert!(!chain.steps.is_empty() && !chain.protection.is_empty());
        let cmp = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert!(cmp.counts.dynamic > 0 && cmp.pairs > 0);
        let page = comparison_page(cmp.handle, 0, 5, true).unwrap();
        assert!(page.total <= cmp.pairs && page.items.len() <= 5 && !page.items.is_empty());
        let all = comparison_page(cmp.handle, 0, 500, false).unwrap();
        assert_eq!(all.total, cmp.pairs);
        let fields = stored_comparison(cmp.handle).unwrap().pairs[page.items[0].index].fields.len();
        assert_eq!(fields, page.items[0].field_count);
        assert!(comparison_page(cmp.handle + 99, 0, 5, false).is_err());
        // the same session through different paths (./, symlink) is refused
        let same = a.to_str().unwrap().to_string();
        assert!(open_comparison(&same, &format!("{same}/../{}", a.file_name().unwrap().to_str().unwrap())).unwrap_err().contains("same session"));
        let link = std::env::temp_dir().join(format!("sl-link-{}", std::process::id()));
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert!(open_comparison(&same, link.to_str().unwrap()).unwrap_err().contains("same session"));
        fs::remove_file(&link).ok();
        // both sessions stay cached at the same time
        let again = cached_session(&a).unwrap();
        assert!(Arc::ptr_eq(&lazy, &again));
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    #[test]
    fn assess_marks_blocked_responses_on_detran_fixture() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("assess");
        let result = assess_blocking(&dir).unwrap();
        assert_eq!(result["schema"], "scrapelens.assess/1");
        let outcomes = result["outcomes"].as_array().unwrap();
        assert!(!outcomes.is_empty());
        assert!(outcomes.iter().any(|o| o["verdictKind"] == "app-ok"));
        // the keys of `counts` are the same as `verdictKind` (kebab-case)
        let counts = result["counts"].as_object().unwrap();
        assert!(!counts.is_empty());
        for (key, value) in counts {
            assert_eq!(value.as_u64().unwrap() as usize, outcomes.iter().filter(|o| o["verdictKind"] == key.as_str()).count(), "key {key} outside the schema");
            // `undetermined` is the canonical verdict; `indeterminado` is the legacy value, still accepted.
            assert!(["app-ok", "app-error", "blocked", "undetermined", "indeterminado", "not-assessed"].contains(&key.as_str()), "unexpected key: {key}");
        }
        // invalid rules become an actionable error
        fs::write(dir.join("assess-rules.json"), "{\"schema\":\"x\"}").unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("fix or remove"));
        // the parse error does not echo the file's content
        fs::write(dir.join("assess-rules.json"), "SECRET-IN-FILE").unwrap();
        assert!(!assess_blocking(&dir).unwrap_err().contains("SECRET"));
        // a large file is refused
        fs::write(dir.join("assess-rules.json"), vec![b' '; 256 * 1024 + 1]).unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("256 KiB"));
        // a symlink is refused, without reading the target
        let outside = dir.join("outside.json");
        fs::write(&outside, "{\"schema\":\"scrapelens.assess-rules/1\"}").unwrap();
        fs::remove_file(dir.join("assess-rules.json")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("assess-rules.json")).unwrap();
        assert!(assess_blocking(&dir).unwrap_err().contains("symbolic link"));
        fs::remove_file(dir.join("assess-rules.json")).unwrap();
        // without rules or with sound rules, no warnings; rules that distort return the core's warnings
        fs::remove_file(dir.join("assess-rules.json")).ok();
        assert_eq!(result["warnings"].as_array().unwrap().len(), 0);
        fs::write(
            dir.join("assess-rules.json"),
            "{\"schema\":\"scrapelens.assess-rules/1\",\"protectionPaths\":[\"/\"]}",
        )
        .unwrap();
        let warned = assess_blocking(&dir).unwrap();
        let warnings = warned["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("protectionPaths")), "{warnings:?}");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn annotated_export_adds_only_comments_on_detran() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = detran_session("annot");
        let d = Path::new(&dir);
        let plain = export_preview(d, "cdp-r0011", "curl", false, false).unwrap();
        let noted = export_preview(d, "cdp-r0011", "curl", true, false).unwrap();
        let strip = |text: &str| text.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
        assert_eq!(strip(&plain.text), strip(&noted.text));
        assert!(noted.text.len() > plain.text.len(), "there must be origin comments");
        assert!(noted.warnings.iter().all(|w| w.code != "export.origins_unavailable"));
        fs::remove_dir_all(dir).ok();
    }

    /// Generates the real previews (with and without origins) for the UI harness:
    /// `SL_SESSION=<folder> SL_REQUEST=<id> SL_DUMP=<file.json> cargo test -- --ignored dump_export_previews`.
    #[test]
    #[ignore]
    fn dump_export_previews() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let request = std::env::var("SL_REQUEST").expect("SL_REQUEST");
        let out = std::env::var("SL_DUMP").expect("SL_DUMP");
        let mut all = serde_json::Map::new();
        for format in ["curl", "python"] {
            for annotate in [false, true] {
                let preview = export_preview(Path::new(&dir), &request, format, annotate, false).unwrap();
                all.insert(format!("{format}-{annotate}"), serde_json::to_value(&preview).unwrap());
            }
        }
        fs::write(out, serde_json::to_string_pretty(&all).unwrap()).unwrap();
    }

    /// Manual measurement: `SL_LARGE_A=<session> SL_LARGE_B=<copy> cargo test --release -- --ignored large_compare --nocapture`.
    #[test]
    #[ignore]
    fn large_compare_timing() {
        let rss = || {
            String::from_utf8_lossy(
                &std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap().stdout,
            )
            .trim()
            .to_string()
        };
        let a = std::env::var("SL_LARGE_A").expect("SL_LARGE_A");
        let b = std::env::var("SL_LARGE_B").expect("SL_LARGE_B");
        let start = std::time::Instant::now();
        let summary = open_comparison(&a, &b).unwrap();
        let opened = start.elapsed();
        let filtered = comparison_page(summary.handle, 0, 50, summary.pairs > 500).unwrap();
        let first = start.elapsed();
        eprintln!("1st page with the default filter (only dynamic if >500 pairs): {} item(s) of {}", filtered.items.len(), filtered.total);
        let page = comparison_page(summary.handle, 0, 50, false).unwrap();
        let fields = stored_comparison(summary.handle).unwrap().pairs[page.items[0].index].fields.len();
        eprintln!(
            "pairs={} dynamic={} summary_json={}B page50_json={}B fields_of_1st_pair={} open={:?} 1st_page={:?} rss_kb={}",
            summary.pairs,
            summary.dynamic_pairs,
            serde_json::to_string(&summary).unwrap().len(),
            serde_json::to_string(&page).unwrap().len(),
            fields,
            opened,
            first,
            rss()
        );
        let full = scrapelens_core::compare::compare_sessions(
            &cached_session(Path::new(&a)).unwrap().session,
            &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&a)).unwrap()),
            &cached_session(Path::new(&b)).unwrap().session,
            &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&b)).unwrap()),
            &scrapelens_core::compare::CompareOptions::default(),
        );
        eprintln!("full_json_old={}B", serde_json::to_string(&full).unwrap().len());
    }

    #[test]
    fn compare_summary_carries_reordered_leftovers() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let a = detran_session("reorder-a");
        let b = fixture_session("reorder-b", "detran-pb-b", "detran-pb-b");
        // B with the 4th request moved to the end: a leftover of the same model on both sides.
        let file = b.join("session.json");
        let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        let requests = doc["requests"].as_array_mut().unwrap();
        let moved = requests.remove(3);
        requests.push(moved);
        fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
        let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert_eq!(summary.reordered_total, 1);
        assert_eq!(summary.reordered[0].a.request_id, "cdp-r0004");
        assert!(summary.only_in_a.iter().any(|r| r.request_id == "cdp-r0004"));
        assert!(summary.only_in_b.iter().any(|r| r.request_id == "cdp-r0004"));
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    #[test]
    fn compare_options_parse_ranges_and_reject_garbage() {
        let ok = compare_options(true, Some("2:9"), Some(" ")).unwrap();
        assert!(ok.include_all && ok.a_range.is_some() && ok.b_range.is_none());
        assert!(compare_options(false, Some("norange"), None).is_err());
    }

    #[test]
    fn real_shape_compare_reports_rounds_and_groups() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let har = |name: &str| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/detran-pb-real-shape").join(name);
            let imported = scrapelens_core::import_har(&fs::read(path).unwrap()).unwrap();
            let dir = temp_session_dir(&format!("rs-{name}"));
            fs::remove_dir_all(&dir).ok();
            store::write_session_dir(&imported.bundle, &dir).unwrap();
            dir
        };
        let a = har("real-shape-1round.har");
        let b = har("real-shape-2rounds.har");
        let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert!(!summary.rounds.is_empty());
        assert!(!summary.unpaired_rounds.is_empty(), "B's 2nd round is left without a pair");
        assert!(summary.groups.iter().any(|g| g.kind == "protection"));
        let all = open_comparison_with(
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            compare_options(true, None, None).unwrap(),
        )
        .unwrap();
        assert!(all.include_all && all.groups.is_empty());
        fs::remove_dir_all(a).ok();
        fs::remove_dir_all(b).ok();
    }

    fn real_shape_session(name: &str) -> PathBuf {
        let har = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/detran-pb-real-shape/real-shape-1round.har")).unwrap();
        let imported = scrapelens_core::parse::import_har(&har).unwrap();
        let dir = temp_session_dir(name);
        fs::remove_dir_all(&dir).ok();
        store::write_session_dir(&imported.bundle, &dir).unwrap();
        dir
    }

    #[test]
    fn natural_adapter_names_view_and_priming_encoder() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = real_shape_session("natural");
        let d = dir.to_str().unwrap();
        let lazy = cached_session(&dir).unwrap();
        // origins use the adapter's internal names
        let origins = scrapelens_core::flow::value_origins(
            &lazy.session,
            &scrapelens_core::search::LazyBodies(&lazy),
            "har-0026",
            &crate::adapters::flow_options(),
        )
        .unwrap();
        let json = serde_json::to_string(&origins).unwrap();
        assert!(json.contains("XML.delta") || json.contains("XML.p."), "no internal adapter names");
        // structured view: raw + named parts
        let request = lazy.session.requests.iter().find(|r| r.id == "har-0026").unwrap();
        let view = crate::adapters::view(&lazy, request, "request").unwrap();
        assert!(!view.fields.is_empty() && view.fields[0].error.is_none());
        assert!(view.fields[0].parts.iter().any(|p| p.name == "delta" || p.name.starts_with("p.")));
        assert!(!view.fields[0].raw.is_empty());
        assert!(crate::adapters::view(&lazy, request, "invalid-side").is_err());
        // the priming script uses the adapter's encoder and the preview says so
        let preview = export_preview(&dir, "har-0026", "priming", false, false).unwrap();
        assert_eq!(preview.format, "priming");
        assert_eq!(preview.adapter.as_deref(), Some("natural-ajax"));
        // `--lenient-parts` is an advanced option: off by default; when on, it generates the script without error (in this fixture the text comes out the same as strict)
        let lenient = export_preview(&dir, "har-0026", "priming", false, true).unwrap();
        assert_eq!(lenient.adapter.as_deref(), Some("natural-ajax"));
        let _ = d;
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn adapter_view_refuses_oversized_field_and_keeps_raw() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = real_shape_session("natural-big");
        let name = {
            let session: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("session.json")).unwrap()).unwrap();
            let req = session["requests"].as_array().unwrap().iter().find(|r| r["id"] == "har-0026").unwrap();
            req["requestBody"]["attachment"].as_str().unwrap().to_string()
        };
        let big = format!("XML=v{}", "0".repeat(crate::adapters::MAX_FIELD_BYTES + 10));
        fs::write(dir.join("attachments").join(&name), big).unwrap();
        let lazy = cached_session(&dir).unwrap();
        let request = lazy.session.requests.iter().find(|r| r.id == "har-0026").unwrap();
        let view = crate::adapters::view(&lazy, request, "request").unwrap();
        assert_eq!(view.fields.len(), 1);
        let field = &view.fields[0];
        // needle must match `TOO_BIG_MESSAGE` in src-tauri/src/adapters.rs (not owned by this file)
        assert!(field.error.as_deref().unwrap().contains("field too large for the adapter view"));
        assert!(field.parts.is_empty());
        assert!(field.raw.starts_with("v000") && field.raw.len() < 70 * 1024, "raw cut, not whole");
        fs::remove_dir_all(dir).ok();
    }

    fn sim_trace(name: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/bodies-search").join(name).display().to_string()
    }

    #[test]
    fn timeline_and_validate_execution_on_real_shape_with_sim_traces() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let capture = real_shape_session("timeline-cap");
        // timeline: application events with the adapter label and collapsed groups
        let rt = tauri::async_runtime::block_on(session_timeline(capture.display().to_string())).unwrap();
        assert!(rt.counts.events > 0 && rt.counts.protection > 0);
        let json = serde_json::to_value(&rt).unwrap();
        assert!(json["items"].as_array().unwrap().iter().any(|i| i["type"] == "group" && i["kind"] == "protection"));
        assert!(json["items"].as_array().unwrap().iter().any(|i| i["label"].as_str().is_some_and(|l| l.contains("cmd_consultar_placa"))), "event label from the adapter");
        // validation: trace ok = equivalent; 403 = diverges; trace in a new 0700 folder
        let root = temp_session_dir("timeline-root");
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        let ok = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-ok.json"), None).unwrap();
        assert!(ok.validation.summary.starts_with("execution equivalent to capture"), "{}", ok.validation.summary);
        assert!(ok.validation.summary.contains("[mapped origin:"));
        // faithful trace (plan.version 2): no parameter or plan warning; only the mapped-origin one
        assert!(
            ok.validation.warnings.iter().all(|w| w.starts_with("different application origins")),
            "a faithful trace must not generate warnings beyond the mapped-origin one: {:?}",
            ok.validation.warnings
        );
        assert!(
            // English and legacy Portuguese reason text (legacy matcher kept for old sessions).
            !ok.validation.warnings.iter().any(|w| w.contains("parameter") || w.contains("plan") || w.contains("parâmetro") || w.contains("plano")),
            "spurious parameter/plan warnings: {:?}",
            ok.validation.warnings
        );
        assert!(
            // legacy Portuguese reason kept for old sessions
            ok.validation.steps.iter().flat_map(|st| &st.expected).any(|n| n.reason.contains("user parameter") || n.reason.contains("parâmetro do usuário")),
            "plate/CPF provided become expected (user parameter)"
        );
        let bad = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-403.json"), None).unwrap();
        assert!(bad.validation.summary.starts_with("diverges at step 3"), "{}", bad.validation.summary);
        let down = validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-incomplete.json"), None).unwrap();
        assert_eq!(serde_json::to_value(down.validation.verdict).unwrap(), "incomplete");
        assert!(down.validation.summary.starts_with("incomplete: stopped at step 1"), "{}", down.validation.summary);
        assert_ne!(ok.trace_dir, bad.trace_dir);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&bad.trace_dir).unwrap().permissions().mode() & 0o777, 0o700);
        // actionable errors
        let invalid = root.join("not-a-trace.json");
        fs::write(&invalid, "{\"schema\":\"x\"}").unwrap();
        assert!(validate_execution_blocking(&root, &capture, invalid.to_str().unwrap(), None).unwrap_err().contains("invalid trace"));
        assert!(validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-ok.json"), Some("no-equals-sign")).unwrap_err().contains("invalid origin mapping"));
        assert!(validate_execution_blocking(&root, &capture, "/does/not/exist.json", None).is_err());
        // trace above 64 MiB: actionable error, without reading or creating a session
        let huge = root.join("huge.json");
        fs::File::create(&huge).unwrap().set_len(crate::validation::TRACE_MAX_BYTES + 1).unwrap();
        let before = fs::read_dir(&root).unwrap().count();
        let err = validate_execution_blocking(&root, &capture, huge.to_str().unwrap(), None).unwrap_err();
        assert!(err.contains("larger than 64 MiB"), "{err}");
        assert_eq!(fs::read_dir(&root).unwrap().count(), before);
        fs::remove_dir_all(capture).ok();
        fs::remove_dir_all(root).ok();
    }

    /// Real Round 9 data for the UI harness:
    /// `SL_SESSION=<folder> SL_TRACES=<a.json,b.json> SL_DUMP=<dir> cargo test -- --ignored dump_round9_evidence`.
    #[test]
    #[ignore]
    fn dump_round9_evidence() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
        fs::create_dir_all(&out).unwrap();
        let t = tauri::async_runtime::block_on(session_timeline(dir.clone())).unwrap();
        fs::write(out.join("timeline.json"), serde_json::to_string(&t).unwrap()).unwrap();
        let root = out.join("traces");
        fs::create_dir_all(&root).unwrap();
        for (n, trace) in std::env::var("SL_TRACES").expect("SL_TRACES").split(',').enumerate() {
            let r = validate_execution_blocking(&root, Path::new(&dir), trace, None).unwrap();
            fs::write(out.join(format!("validate-{n}.json")), serde_json::to_string(&r).unwrap()).unwrap();
        }
    }

    /// Real data (Natural adapter registered) for the UI harness:
    /// `SL_SESSION=<folder> SL_DUMP=<dir> cargo test -- --ignored dump_adapter_evidence`.
    #[test]
    #[ignore]
    fn dump_adapter_evidence() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
        fs::create_dir_all(&out).unwrap();
        let lazy = cached_session(Path::new(&dir)).unwrap();
        let source = scrapelens_core::search::LazyBodies(&lazy);
        let opts = crate::adapters::flow_options();
        for request in &lazy.session.requests {
            let id = &request.id;
            let write = |name: &str, value: serde_json::Value| fs::write(out.join(format!("{id}.{name}.json")), serde_json::to_string(&value).unwrap()).unwrap();
            if let Ok(o) = scrapelens_core::flow::value_origins(&lazy.session, &source, id, &opts) { write("origins", serde_json::to_value(o).unwrap()); }
            if let Ok(c) = scrapelens_core::flow::priming_chain(&lazy.session, &source, id, &opts) { write("chain", serde_json::to_value(c).unwrap()); }
            for side in ["request", "response"] {
                if let Ok(v) = crate::adapters::view(&lazy, request, side) {
                    if !v.fields.is_empty() { write(side, serde_json::to_value(v).unwrap()); }
                }
            }
        }
        for id in ["har-0026"] {
            if let Ok(p) = priming_preview(Path::new(&dir), id, false) { fs::write(out.join(format!("{id}.priming.json")), serde_json::to_string(&p).unwrap()).unwrap(); }
        }
    }

    /// Real sanitization preview for the UI harness:
    /// `SL_SESSION=<folder> SL_DUMP=<file.json> cargo test -- --ignored dump_sanitize_preview`.
    #[test]
    #[ignore]
    fn dump_sanitize_preview() {
        let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
        let out = std::env::var("SL_DUMP").expect("SL_DUMP");
        let preview = crate::export::sanitize_preview(Path::new(&dir)).unwrap();
        fs::write(out, serde_json::to_string_pretty(&preview).unwrap()).unwrap();
    }
}

/// How long the capture thread may take to report that Chrome is ready.
const CAPTURE_READY_TIMEOUT: Duration = Duration::from_secs(35);

/// Waits for the capture thread to report readiness. Errors before Chrome starts (cookie
/// import, profile, executable) come back as the thread reported them.
///
/// A thread that does not answer within `timeout` is asked to stop and then detached: a
/// background reaper joins it and removes its session folder only when it really ends,
/// so the app never waits for a thread blocked in the keyring or elsewhere.
fn await_capture_ready<T: Send + 'static>(
    ready_rx: &mpsc::Receiver<Result<(), String>>,
    stop_tx: &mpsc::Sender<()>,
    join: thread::JoinHandle<Result<T, String>>,
    dir: &Path,
    timeout: Duration,
) -> Result<thread::JoinHandle<Result<T, String>>, String> {
    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(join),
        Ok(Err(error)) => {
            detach_and_reap(join, dir);
            Err(error)
        }
        // The thread drops its ready sender as it returns, so joining here is immediate.
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let error = match join.join() {
                Ok(Err(error)) => error,
                Ok(Ok(_)) => "The capture ended before Chrome was ready.".to_string(),
                Err(_) => "The capture thread stopped unexpectedly before Chrome was ready.".to_string(),
            };
            let _ = fs::remove_dir_all(dir);
            Err(error)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = stop_tx.send(());
            detach_and_reap(join, dir);
            Err("The capture was not ready within 35 s. If the browser or the keyring asks for permission, answer it and try again; otherwise check whether Chrome opened.".to_string())
        }
    }
}

/// Joins a thread the app no longer waits for, off the calling path, then removes the
/// session folder it may still be writing. A thread that never ends keeps only this
/// reaper; it cannot block the app or start a second capture.
fn detach_and_reap<T: Send + 'static>(join: thread::JoinHandle<Result<T, String>>, dir: &Path) {
    let dir = dir.to_path_buf();
    thread::spawn(move || {
        let _ = join.join();
        let _ = fs::remove_dir_all(&dir);
    });
}

#[cfg(all(test, not(feature = "test-hooks")))]
mod test_switch_tests {
    use super::*;

    /// Release builds (no `test-hooks`) start captures with the normal settings, whatever
    /// the environment says: nothing here reads a test variable.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_capture_switches_are_the_normal_settings() {
        let switches = capture_test_switches();
        assert!(!switches.headless);
        assert!(!switches.ignore_cert);
        assert!(!switches.proxy_bypass_loopback);
        assert_eq!(switches.network, scrapelens_capture::NetworkMode::Open);
    }

    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_has_no_test_start_url_suggestion() {
        assert_eq!(test_capture_url(), "");
    }
}

#[cfg(test)]
mod proxy_command_tests {
    use super::*;
    use scrapelens_capture::proxy::ProxyLink;
    use std::sync::Mutex;

    #[test]
    fn a_valid_link_is_kept_in_memory_and_only_its_address_is_returned() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        let link = parse_and_store(&slot, "http://reader:Hunter2-secret@proxy.example:8080").unwrap();
        assert_eq!(link.server_url(), "http://proxy.example:8080");
        let info = serde_json::to_string(&crate::capture_proxy::ProxyInfo::of(&link)).unwrap();
        assert!(!info.contains("Hunter2"), "{info}");
        assert!(!info.contains("reader"), "{info}");
        // The memory copy keeps the credentials for the relay.
        assert!(slot.lock().unwrap().as_ref().unwrap().authenticated());
    }

    #[test]
    fn an_invalid_link_is_refused_and_its_text_is_never_echoed() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        for input in [
            "socks4://reader:Hunter2-secret@proxy.example:1080",
            "http://reader:Hunter2-secret@proxy.example:99999",
            "http://reader:Hunter2-secret@proxy.example:8080/path",
            "http://reader:Hunter2-secret@proxy.example:8080\u{7}",
        ] {
            let error = parse_and_store(&slot, input).unwrap_err();
            assert!(!error.contains("Hunter2"), "{error}");
            assert!(!error.contains("reader"), "{error}");
            assert!(!error.contains("proxy.example"), "the input is not repeated: {error}");
        }
        assert!(slot.lock().unwrap().is_none(), "a refused link replaces nothing");
    }

    #[test]
    fn changing_or_clearing_the_proxy_is_refused_while_recording() {
        assert!(ensure_proxy_editable(false).is_ok());
        let err = ensure_proxy_editable(true).unwrap_err();
        assert!(err.contains("Stop the capture"), "{err}");
    }

    #[test]
    fn socks4_gets_its_own_message() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        let error = parse_and_store(&slot, "socks4://proxy.example:1080").unwrap_err();
        assert!(error.contains("socks4 is not supported"), "{error}");
    }
}

#[cfg(test)]
mod capture_start_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    fn temp_session_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("sl-start-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn startup_error_from_the_capture_thread_is_shown_not_the_timeout() {
        let dir = temp_session_dir("early-error");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, _stop_rx) = mpsc::channel::<()>();
        let message = "cookies could not be read: the profile database is locked; close Chrome and try again";
        let join = thread::spawn(move || {
            // Same as `capture::run` returning early with `?` before signalling readiness.
            drop(ready_tx);
            Err::<(), String>(message.to_string())
        });
        let started = Instant::now();
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, CAPTURE_READY_TIMEOUT).err().unwrap();
        assert_eq!(error, message);
        assert!(!error.contains("not ready within"));
        assert!(started.elapsed() < Duration::from_secs(5), "must not wait for the 35 s timeout");
        assert!(!dir.exists(), "the session folder of a failed start is removed");
    }

    #[test]
    fn silent_thread_still_times_out_and_is_stopped() {
        let dir = temp_session_dir("silent");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            // Keeps the channel open and only ends when the caller asks it to stop.
            let _keep = ready_tx;
            let _ = stop_rx.recv();
            Err::<(), String>("stopped".to_string())
        });
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, Duration::from_millis(50)).err().unwrap();
        assert!(error.contains("not ready within"), "{error}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while dir.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!dir.exists(), "the reaper removes the folder after the thread ends");
    }

    #[test]
    fn stuck_capture_thread_never_blocks_the_start_and_is_reaped_later() {
        // The thread ignores the stop request until something external releases it, like a
        // keyring unlock prompt that never completes. The start must still return promptly.
        let dir = temp_session_dir("stuck");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_in_thread = stopped.clone();
        let join = thread::spawn(move || {
            let _keep = ready_tx;
            let _ = release_rx.recv(); // blocked "in the keyring"; does not read `stop` yet
            if stop_rx.try_recv().is_ok() {
                stopped_in_thread.store(true, Ordering::SeqCst);
            }
            Err::<(), String>("cookie key lookup was abandoned".to_string())
        });

        let started = Instant::now();
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, Duration::from_millis(50)).err().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "the start must not wait for the stuck thread");
        assert!(error.contains("not ready within"), "{error}");
        assert!(dir.exists(), "the folder stays until the thread really ends");

        // The thread ends later: the reaper removes its folder and the stop request was sent.
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while dir.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!dir.exists(), "the reaper removes the folder once the thread ends");
        assert!(stopped.load(Ordering::SeqCst), "the stop request reached the thread");
    }

    #[test]
    fn ready_signal_returns_the_running_capture() {
        let dir = temp_session_dir("ready");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            let _ = ready_tx.send(Ok(()));
            let _ = stop_rx.recv();
            Ok::<(), String>(())
        });
        let join = await_capture_ready(&ready_rx, &stop_tx, join, &dir, CAPTURE_READY_TIMEOUT).expect("ready");
        let _ = stop_tx.send(());
        assert!(join.join().unwrap().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod cookie_source_tests {
    use super::*;

    #[test]
    fn validates_sources_without_exposing_database_path() {
        let sources = vec![CookieSourceDto::from(scrapelens_capture::BrowserCookieSource {
            id: "chrome:Default".into(), browser: "Google Chrome".into(),
            profile: "Default".into(), label: "Google Chrome — Default".into(),
            kind: scrapelens_capture::BrowserKind::Chromium,
            db_path: PathBuf::from("/private/cookie-database"),
        })];
        assert!(resolve_cookie_source(None, &sources).unwrap().is_none());
        assert!(resolve_cookie_source(Some(""), &sources).unwrap().is_none());
        assert!(resolve_cookie_source(Some("chrome:deleted"), &sources).is_err());
        assert_eq!(resolve_cookie_source(Some("chrome:Default"), &sources).unwrap().unwrap().id, "chrome:Default");
        let json = serde_json::to_string(&sources).unwrap();
        assert!(!json.contains("dbPath") && !json.contains("cookie-database"));
    }
}
