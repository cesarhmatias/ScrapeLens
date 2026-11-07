//! Live capture: start, stop and status, the start URL, the proxy and cookie-source settings,
//! and the test-only command-line actions.

use super::*;

/// "starting" state: sets `recording` and notifies the menu; if the start does not reach
/// `commit()`, it clears the flag and re-enables the menu on exit (error, `?` or panic).
pub(crate) struct StartingGuard<'a, F: FnMut(bool)> {
    pub(super) flag: &'a std::sync::atomic::AtomicBool,
    pub(super) notify: F,
    pub(super) committed: bool,
}

impl<'a, F: FnMut(bool)> StartingGuard<'a, F> {
    pub(crate) fn begin(flag: &'a std::sync::atomic::AtomicBool, mut notify: F) -> Self {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        notify(true);
        Self {
            flag,
            notify,
            committed: false,
        }
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

/// Starting URL suggested in the UI: the saved preference, otherwise `SCRAPELENS_CAPTURE_URL`.
#[tauri::command]
pub fn capture_start_url(app: AppHandle) -> String {
    prefs::load_capture_start_url(&app).unwrap_or_else(test_capture_url)
}

/// Test-hooks builds may suggest a start URL from the environment; release builds never do.
#[cfg(feature = "test-hooks")]
pub(super) fn test_capture_url() -> String {
    std::env::var("SCRAPELENS_CAPTURE_URL").unwrap_or_default()
}

#[cfg(not(feature = "test-hooks"))]
pub(super) fn test_capture_url() -> String {
    String::new()
}

/// Persists the starting URL (empty clears the preference). Only `http`/`https` when not empty.
#[tauri::command]
pub fn set_capture_start_url(app: AppHandle, url: String) -> Result<String, String> {
    let trimmed = url.trim().to_string();
    if !trimmed.is_empty() {
        cli::validate_http_url(&trimmed)?;
    }
    prefs::save_capture_start_url(
        &app,
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.as_str())
        },
    )?;
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
    /// For `open-capture`: a session token, so the path stays in the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
        return Some(CliActionPayload {
            kind,
            path: String::new(),
            message: Some(message),
            token: None,
        });
    }
    let action = state.pending_cli.lock().ok()?.take()?;
    let (kind, path, token_kind) = match action {
        CliAction::ImportHar(path) => ("import-har", path, grants::Kind::ImportFile),
        CliAction::ImportNetlog(path) => ("import-netlog", path, grants::Kind::ImportFile),
        CliAction::OpenCapture(path) => ("open-capture", path, grants::Kind::Session),
    };
    // The path stays in the backend: the webview gets a token for it.
    Some(match grants::issue(token_kind, &path) {
        Ok(token) => CliActionPayload {
            kind: kind.to_string(),
            path: String::new(),
            message: None,
            token: Some(token),
        },
        Err(message) => CliActionPayload {
            kind: "error".to_string(),
            path: String::new(),
            message: Some(message),
            token: None,
        },
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieSourceDto {
    pub(super) id: String,
    pub(super) browser: String,
    pub(super) profile: String,
    pub(super) label: String,
    pub(super) kind: scrapelens_capture::BrowserKind,
}

impl From<scrapelens_capture::BrowserCookieSource> for CookieSourceDto {
    fn from(source: scrapelens_capture::BrowserCookieSource) -> Self {
        Self {
            id: source.id,
            browser: source.browser,
            profile: source.profile,
            label: source.label,
            kind: source.kind,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieSourcesPayload {
    pub(super) sources: Vec<CookieSourceDto>,
    pub(super) selected: Option<String>,
}

pub(super) fn resolve_cookie_source<'a>(
    source: Option<&str>,
    sources: &'a [CookieSourceDto],
) -> Result<Option<&'a CookieSourceDto>, String> {
    match source.filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(id) => sources
            .iter()
            .find(|item| item.id == id)
            .map(Some)
            .ok_or_else(|| {
                "Cookie source unavailable. Select another browser or a clean session.".to_string()
            }),
    }
}

pub(super) fn cookie_sources() -> Vec<CookieSourceDto> {
    scrapelens_capture::list_browser_cookie_sources()
        .into_iter()
        .map(Into::into)
        .collect()
}

#[tauri::command]
pub fn list_cookie_sources(app: AppHandle) -> CookieSourcesPayload {
    let sources = cookie_sources();
    let saved = prefs::load_capture_cookie_source(&app);
    let selected = resolve_cookie_source(saved.as_deref(), &sources)
        .ok()
        .flatten()
        .map(|s| s.id.clone());
    CookieSourcesPayload { sources, selected }
}

#[tauri::command]
pub fn set_capture_cookie_source(
    app: AppHandle,
    source: Option<String>,
) -> Result<Option<String>, String> {
    let sources = cookie_sources();
    let selected = resolve_cookie_source(source.as_deref(), &sources)?.map(|s| s.id.clone());
    prefs::save_capture_cookie_source(&app, selected.as_deref())?;
    Ok(selected)
}

/// The Proxy field's state. No credentials in it.
#[tauri::command]
pub fn get_proxy_state(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::capture_proxy::ProxyState, String> {
    let active = state
        .proxy
        .lock()
        .map_err(|_| "proxy state unavailable")?
        .clone();
    Ok(crate::capture_proxy::state(
        prefs::load_capture_proxy(&app),
        active.as_ref(),
    ))
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

pub(super) fn ensure_proxy_editable(recording: bool) -> Result<(), String> {
    if recording {
        Err("Stop the capture before changing the proxy.".to_string())
    } else {
        Ok(())
    }
}

/// Parses `text` and, when it is valid, replaces the link kept in memory. The error never
/// contains the input (the parser's messages are fixed).
pub(super) fn parse_and_store(
    slot: &std::sync::Mutex<Option<scrapelens_capture::proxy::ProxyLink>>,
    text: &str,
) -> Result<scrapelens_capture::proxy::ProxyLink, String> {
    let link =
        scrapelens_capture::proxy::ProxyLink::parse(text).map_err(|error| error.to_string())?;
    *slot.lock().map_err(|_| "proxy state unavailable")? = Some(link.clone());
    Ok(link)
}

/// Switches that only the test suites use. Without `test-hooks` (release builds) they
/// are off and no test variable is read: normal headless setting, certificate checks on,
/// open network, and loopback through the proxy like any other host.
pub(super) struct CaptureTestSwitches {
    pub(super) headless: bool,
    pub(super) ignore_cert: bool,
    pub(super) network: scrapelens_capture::NetworkMode,
    pub(super) proxy_bypass_loopback: bool,
}

#[cfg(feature = "test-hooks")]
pub(super) fn capture_test_switches() -> CaptureTestSwitches {
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
pub(super) fn capture_test_switches() -> CaptureTestSwitches {
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
        return Err(
            "A capture is already in progress or starting. Click Stop before starting another."
                .to_string(),
        );
    }
    // The saved server is the authority: a saved proxy whose password is not in memory
    // stops the start here, before Chrome is launched.
    let proxy = {
        let active = state
            .proxy
            .lock()
            .map_err(|_| "proxy state unavailable")?
            .clone();
        crate::capture_proxy::resolve_for_start(
            prefs::load_capture_proxy(&app).as_deref(),
            active.as_ref(),
        )?
    };
    let menu_app = app.clone();
    let mut starting = StartingGuard::begin(&state.recording, move |recording| {
        crate::menu::set_recording_menu(&menu_app, recording)
    });
    let slot = state
        .capture
        .lock()
        .map_err(|_| "capture state unavailable")?;
    if slot.is_some() {
        return Err(
            "A capture is already in progress. Click Stop before starting another.".to_string(),
        );
    }

    let chrome_path = {
        let saved = state
            .chrome_path
            .lock()
            .map_err(|_| "Chrome state unavailable")?
            .clone();
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
    let selected_cookie_source = if resolved_url == "about:blank" {
        None
    } else {
        resolve_cookie_source(cookie_source.as_deref(), &sources)?
    };
    let cookie_notice = selected_cookie_source
        .map(|source| {
            format!(
                " Cookies from {} loaded for the starting URL's site.",
                source.label
            )
        })
        .unwrap_or_default();
    let proxy_notice = proxy
        .as_ref()
        .map(|link| {
            format!(
                " Through the proxy {} (no credentials shown).",
                link.server_url()
            )
        })
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
        session_token: Some(grants::issue(grants::Kind::Session, &dir)?),
        synthetic: false,
        notice: Some(
            (if start_url_for_notice == "about:blank" {
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
            }) + &cookie_notice
                + &proxy_notice,
        ),
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

pub(super) fn stop_blocking(app: &AppHandle) -> Result<SessionPayload, String> {
    let state = app.state::<AppState>();
    let capture = {
        let mut slot = state
            .capture
            .lock()
            .map_err(|_| "capture state unavailable")?;
        slot.take()
    };
    state
        .recording
        .store(false, std::sync::atomic::Ordering::SeqCst);
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
    state.capture.lock().ok().and_then(|slot| {
        slot.as_ref().map(|capture| {
            capture
                .status
                .lock()
                .map(|status| status.clone())
                .unwrap_or_default()
        })
    })
}

pub(super) fn iso_now() -> String {
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
pub(super) fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

/// How long the capture thread may take to report that Chrome is ready.
pub(super) const CAPTURE_READY_TIMEOUT: Duration = Duration::from_secs(35);

/// Waits for the capture thread to report readiness. Errors before Chrome starts (cookie
/// import, profile, executable) come back as the thread reported them.
///
/// A thread that does not answer within `timeout` is asked to stop and then detached: a
/// background reaper joins it and removes its session folder only when it really ends,
/// so the app never waits for a thread blocked in the keyring or elsewhere.
pub(super) fn await_capture_ready<T: Send + 'static>(
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
                Err(_) => {
                    "The capture thread stopped unexpectedly before Chrome was ready.".to_string()
                }
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
pub(super) fn detach_and_reap<T: Send + 'static>(join: thread::JoinHandle<Result<T, String>>, dir: &Path) {
    let dir = dir.to_path_buf();
    thread::spawn(move || {
        let _ = join.join();
        let _ = fs::remove_dir_all(&dir);
    });
}
