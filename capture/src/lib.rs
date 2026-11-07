//! Live capture: external Chrome with a dedicated profile + CDP + NetLog.
//!
//! Regras:
//! - its own temporary profile (never the personal profile), removed at the end;
//! - our client talks to Chrome over a **pipe** (`--remote-debugging-pipe`,
//!   no open port). `expose_cdp` does not open a TCP port either: the agent
//!   gets a mode-0600 unix socket. It forwards only events from sessions that
//!   client attached, never capture `Network.*` events, and allows only Page,
//!   Runtime, DOM, Input, Accessibility, Target attach/list/create, and
//!   Browser.getVersion. `file:` and `chrome:` URLs are refused (`cdp_expose`);
//! - it only terminates the process this module started;
//! - the NetLog is written to the session directory and imported by the core;
//! - no network beyond local debugging; no certificate is installed;
//! - nothing is written by following a symlink (`O_NOFOLLOW` + `create_new`).

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use transport::{CdpTransport, Incoming, ReadError, Transport};

use scrapelens_core::{correlate::CorrelationOptions, import_capture_labeled, store};

pub mod allowlist;
pub mod browser;
mod cdp_expose;
pub mod chrome;
pub mod cookies;
mod fdio;
pub mod proxy;
pub mod relay;
pub mod transport;

mod cdp;
mod launcher;
mod netlog;
pub(crate) use cdp::*;
pub(crate) use launcher::*;
pub(crate) use netlog::*;

pub use launcher::{cleanup_orphans, default_state_root, private_base_dir, OrphanCleanup};

pub use cookies::{
    list_browser_cookie_sources, load_cookies_for_url, BrowserCookieSource, BrowserKind,
    CookieImportOutcome, ImportedCookie,
};

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    pub recording: bool,
    pub events: usize,
    pub chrome_pid: Option<u32>,
    pub session_id: String,
    pub session_dir: String,
    pub started_at: String,
    pub page_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Result of a finished capture: the imported session (JSON of the
/// `session.json`), where it was left on disk, and the notice for the UI.
#[derive(Debug, Clone)]
pub struct CaptureOutcome {
    pub session: Value,
    pub session_dir: PathBuf,
    pub notice: String,
}

// Test-hook decisions (feature `test-hooks`, off in release). A release build of
// this crate contains none of the gated names. `SL_LIVE_START_URL`,
// `SL_LIVE_SESSION_DIR`, `SL_LIVE_STOP_FILE` and `SL_LIVE_HEADED` stay: they are
// the live-capture harness, not these switches.
//
// - `SCRAPELENS_TEST_PROXY_CA` — gate. Read only with `cfg(test)` or `test-hooks`.
// - `SCRAPELENS_CDP_TRANSPORT` — gate. Same. Release keeps the caller's default
//   (`run` passes the pipe).
// - `SCRAPELENS_RELAY_PEER_PROBE` — gate, and stricter than the feature: the name
//   exists only in the `#[cfg(test)]` probe, so a library built with the feature
//   still does not contain it.
// - `SCRAPELENS_CAPTURE_NETWORK` — gate. `from_env` returns open network unless
//   `cfg(test)` or `test-hooks` is on.
// - `SCRAPELENS_CAPTURE_URL`, `SCRAPELENS_CAPTURE_HEADLESS`,
//   `SCRAPELENS_CAPTURE_IGNORE_CERT`, `SCRAPELENS_TEST_MODE`,
//   `SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK` — keep, but not in this crate. The App
//   already reads them only behind its own `test-hooks` feature and passes plain
//   fields (`headless`, `ignore_cert`, `test_proxy_bypass_loopback`). This crate
//   does not read those names.
//
// The App's `test-hooks` must enable `scrapelens-capture/test-hooks`, or a test
// build of the App still gets the release behavior of the three gated reads.

/// How the Chrome of the COMMON capture (the App's) sees the network.
///
/// The MCP's controlled capture (`browser::BrowserCapture`) does not use this: it has
/// its own allowlist (`--host-resolver-rules` only with the approved hosts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Normal network (default): Chrome resolves and reaches any site. It has no
    /// `--host-resolver-rules` and no `--allow-insecure-localhost`.
    #[default]
    Open,
    /// LOOPBACK ONLY (`127.0.0.1` and `localhost`): any other name gives
    /// `ERR_NAME_NOT_RESOLVED`. For tests and lab experiments, where
    /// nothing may leave the machine; it also accepts a `localhost` certificate
    /// that is invalid (`--allow-insecure-localhost`).
    LoopbackOnly,
}

impl NetworkMode {
    /// Loopback-only when the test hook is enabled and the variable is `loopback`.
    /// Release builds do not read it and stay on the open network.
    pub fn from_env() -> NetworkMode {
        #[cfg(any(test, feature = "test-hooks"))]
        let value = std::env::var("SCRAPELENS_CAPTURE_NETWORK").ok();
        #[cfg(not(any(test, feature = "test-hooks")))]
        let value: Option<String> = None;
        Self::parse(value.as_deref())
    }

    fn parse(value: Option<&str>) -> NetworkMode {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("loopback") => NetworkMode::LoopbackOnly,
            _ => NetworkMode::Open,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub chrome: PathBuf,
    pub session_dir: PathBuf,
    pub start_url: String,
    pub headless: bool,
    pub ignore_cert: bool,
    /// Open network (default) or loopback only (tests).
    pub network: NetworkMode,
    /// Source of cookies from an installed browser (`BrowserCookieSource.id`).
    /// `None` = the capture starts without imported cookies.
    pub cookie_source: Option<String>,
    /// Cookies already resolved by the caller. When not empty, it takes precedence over
    /// `cookie_source` (useful for tests and for the MCP).
    pub initial_cookies: Vec<ImportedCookie>,
    /// The proxy link the user gave, if any. Its credentials stay in the relay.
    pub proxy: Option<proxy::ProxyLink>,
    /// TEST ONLY: adds `--proxy-bypass-list=<-loopback>` so that loopback targets really
    /// pass through the proxy. Production keeps Chrome's default loopback bypass.
    pub test_proxy_bypass_loopback: bool,
}

pub fn run(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
) -> Result<CaptureOutcome, String> {
    let opts = RunOptions {
        // Pipe by default (no open port); `SCRAPELENS_CDP_TRANSPORT=port`
        // goes back to WebSocket. Measured the same way in docs/16b §2.5.
        transport: CdpTransport::from_env(CdpTransport::Pipe),
        ..RunOptions::default()
    };
    run_with_options(config, status, stop, ready, &opts).map(|(outcome, _)| outcome)
}

/// Options for the controlled capture (`browser::BrowserCapture`). The default is
/// the App's common capture, with no change in behavior.
#[derive(Default)]
pub(crate) struct RunOptions {
    /// Mandatory allowlist in controlled mode: it replaces the fixed
    /// loopback rule of the resolver with the rules from the list.
    pub allowlist: Option<allowlist::Allowlist>,
    /// Commands (navigate) consumed by the recording loop.
    pub control: Option<Receiver<browser::Control>>,
    /// Filled in before `ready`: debugging address and version.
    pub endpoint: Option<Arc<Mutex<Option<browser::Endpoint>>>>,
    /// Only signals `ready` (and only publishes the CDP address) after our
    /// client is attached to the initial target: `Network.enable` and
    /// `Target.setAutoAttach` with a successful ACK and nothing pending on it. This way an
    /// external client that receives the address cannot act before we do.
    pub require_initial_target_ready: bool,
    /// How our client talks to Chrome (port or pipe).
    pub transport: CdpTransport,
}

/// What the `Capture.cookiesImported` event records about an import: counts and the reason
/// encrypted cookies could not be read. Never cookie values.
#[derive(Clone, Copy)]
struct CookieAudit<'a> {
    source: &'a str,
    domain: &'a str,
    skipped: usize,
    undecryptable: usize,
    undecryptable_reason: Option<&'a str>,
}

/// Shutdown data that the App does not use, but the controlled mode returns.
#[derive(Debug, Clone, Default)]
pub(crate) struct RunReport {
    pub allowlist: Option<allowlist::AllowlistReport>,
    pub requests: usize,
    pub netlog: String,
    pub graceful: bool,
    pub waited_ms: u64,
    pub warnings: Vec<String>,
}

pub(crate) fn run_with_options(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
    opts: &RunOptions,
) -> Result<(CaptureOutcome, RunReport), String> {
    let outcome = run_inner(&config, &status, stop, &ready, opts);
    if let Err(error) = &outcome {
        if let Ok(mut guard) = status.lock() {
            guard.last_error = Some(error.clone());
        }
    }
    if let Ok(mut guard) = status.lock() {
        guard.recording = false;
    }
    outcome
}

fn run_inner(
    config: &CaptureConfig,
    status: &Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: &Sender<Result<(), String>>,
    opts: &RunOptions,
) -> Result<(CaptureOutcome, RunReport), String> {
    eprintln!("capture transport: {:?}", opts.transport);
    // Cookies from an installed browser are read BEFORE Chrome starts: a
    // read failure (Keychain denied, database missing) aborts the capture without
    // launching the browser, and nothing from the personal profile is touched.
    let mut imported_cookies = config.initial_cookies.clone();
    let mut cookie_source_label: Option<String> = None;
    let mut cookie_domain = String::new();
    let mut cookie_skipped = 0usize;
    let mut cookie_undecryptable = 0usize;
    let mut cookie_undecryptable_reason: Option<String> = None;
    if imported_cookies.is_empty() {
        if let Some(source_id) = &config.cookie_source {
            let outcome = cookies::load_cookies_for_url(source_id, &config.start_url)?;
            imported_cookies = outcome.cookies;
            cookie_source_label = Some(outcome.label);
            cookie_domain = outcome.domain;
            cookie_skipped = outcome.skipped;
            cookie_undecryptable = outcome.undecryptable;
            cookie_undecryptable_reason = outcome.undecryptable_reason;
            for note in &outcome.notes {
                eprintln!("cookies: {note}");
            }
        }
    } else if let Some(domain) = imported_cookies.first().map(|c| c.domain.clone()) {
        cookie_domain = domain;
    }
    let undecryptable_suffix = match (cookie_undecryptable, &cookie_undecryptable_reason) {
        (0, _) => String::new(),
        (count, reason) => format!(
            "; {count} cookie(s) could not be decrypted: {}",
            reason.as_deref().unwrap_or("unknown reason")
        ),
    };
    let cookie_suffix = match (&cookie_source_label, imported_cookies.len()) {
        (Some(label), count) => {
            format!(" · {count} cookie(s) imported from {label}{undecryptable_suffix}")
        }
        (None, count) if count > 0 => format!(" · {count} cookie(s) imported"),
        _ => String::new(),
    };
    let profile = private_base_dir().join(format!(
        "scrapelens-chrome-{}-{}",
        std::process::id(),
        unix_nanos()
    ));
    // The profile is created by us, 0700 from creation, and checked after
    // opening. It is kept outside the session directory on purpose: Chrome writes the NetLog
    // in here (R3), never through a path another process could swap.
    create_private_dir_new(&profile).map_err(|error| format!("temporary profile: {error}"))?;
    // The session directory must not be a symlink: everything we write there would
    // go to the link's target.
    if std::fs::symlink_metadata(&config.session_dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir_all(&profile);
        return Err(format!(
            "session directory is a symlink and was refused: {}",
            config.session_dir.display()
        ));
    }
    store::ensure_private_dir(&config.session_dir)
        .map_err(|error| format!("session directory: {error}"))?;
    // Checked after opening (without following links): it is our own directory, 0700.
    // The identity (dev+inode) is rechecked in `stop` (A4-B5).
    let (session_handle, session_identity) = match verify_private_dir_handle(&config.session_dir) {
        Ok(found) => found,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&profile);
            return Err(format!("session directory: {error}"));
        }
    };
    // NetLog: Chrome creates it and writes it INSIDE the private profile (0700, ours,
    // fresh). Only after shutdown is it read without following links and copied
    // into the session directory by `write_private` (atomic rename).
    let netlog_path = profile.join("netlog.json");
    // The bodies are created relative to the directory's descriptor (A7-B7): with no path, nothing
    // goes to the attacker's directory if the name is swapped after the check.
    let bodies_file = fdio::create_replacing_at(&session_handle, "cdp-bodies.jsonl")
        .map_err(|error| format!("cdp-bodies.jsonl: {error}"))?;
    // Only for rescue (A5-B3): re-reads the bodies through the descriptor, even if
    // the session directory has been swapped.
    let mut bodies_reader = bodies_file
        .try_clone()
        .map_err(|error| format!("cdp-bodies.jsonl: {error}"))?;

    let resolver_rules = opts.allowlist.as_ref().map(allowlist::Allowlist::resolver_rules);
    // The proxy is prepared before Chrome starts, so a refused or unreachable proxy fails
    // the capture with its own message. The relay, if any, stops when this scope ends.
    let proxy_plan = match &config.proxy {
        Some(link) => {
            let allow: Option<relay::AllowFn> = opts.allowlist.clone().map(|al| {
                Arc::new(move |host: &str, port: u16| al.permits_destination(host, port))
                    as relay::AllowFn
            });
            // A refusal is reported through `ready` too: a caller waiting for the start
            // result must see the reason, not a closed channel.
            let plan = relay::ProxyPlan::prepare(link.clone(), allow).map_err(|e| {
                let message = e.to_string();
                let _ = ready.send(Err(message.clone()));
                message
            })?;
            Some(plan)
        }
        None => None,
    };
    let proxy_arg = proxy_plan.as_ref().map(relay::ProxyPlan::chrome_arg);
    if proxy_plan.is_some() {
        // Preferences of the DEDICATED profile only (never system policy): secure DNS off
        // (its lookups would leave the proxy), and WebRTC kept behind the proxy.
        write_proxy_profile_prefs(&profile).map_err(|error| {
            let message = format!("proxy profile preferences: {error}");
            let _ = ready.send(Err(message.clone()));
            message
        })?;
    }
    let mut pipe_ends = match opts.transport {
        CdpTransport::Pipe => Some(
            transport::make_pipe_ends().map_err(|error| format!("CDP pipe: {error}"))?,
        ),
        CdpTransport::Port => None,
    };
    let launch_args = chrome_args(
        config,
        &profile,
        &netlog_path,
        resolver_rules.as_deref(),
        pipe_ends.is_some(),
        proxy_arg.as_deref(),
    );
    // The relay refuses every client until it knows this pid. The child stops in the
    // shell, before Chrome runs, so the pid is published with no window where a
    // connection could arrive first. `exec` keeps the pid.
    let hold_for_relay = proxy_plan.as_ref().is_some_and(|plan| plan.route() == relay::ProxyRoute::Relay);
    let mut chrome = ChromeProcess::new(spawn_chrome(config, &launch_args, pipe_ends.as_ref(), hold_for_relay)?);
    if hold_for_relay {
        let pid = chrome.child_mut().id();
        if !wait_until_stopped(pid) {
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let message = "the capture browser did not pause so the relay could record its process".to_string();
            let _ = ready.send(Err(message.clone()));
            return Err(message);
        }
        if let Some(plan) = proxy_plan.as_ref() {
            plan.set_chrome_pid(pid);
        }
        // SAFETY: `pid` is the stopped child. SIGCONT is the resume paired with its SIGSTOP.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) } != 0 {
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let message = "the capture browser could not be resumed after the relay recorded its process".to_string();
            let _ = ready.send(Err(message.clone()));
            return Err(message);
        }
    }
    // Marker to clean up orphans if this process dies by SIGKILL; the Drop
    // removes it on any normal exit (success, error or panic).
    let marker = OrphanMarker::create(
        &default_state_root(),
        chrome.child_mut().id(),
        &profile,
        None,
    );
    if let Ok(mut guard) = status.lock() {
        guard.chrome_pid = Some(chrome.child_mut().id());
        guard.page_url = config.start_url.clone();
    }

    let fail_start = |chrome: &mut ChromeProcess, error: String| -> String {
        let _ = chrome.child_mut().kill();
        let _ = chrome.child_mut().wait();
        chrome.disarm();
        let _ = std::fs::remove_dir_all(&profile);
        let _ = ready.send(Err(error.clone()));
        error
    };
    // Port: reads DevToolsActivePort and opens the WebSocket on 127.0.0.1. Pipe: Chrome
    // inherited fds 3 and 4; we close its ends here and speak only through
    // them (no port exists).
    let (mut socket, ws_url): (Transport, Option<String>) = match pipe_ends.take() {
        None => {
            let ws_url = match wait_for_devtools(chrome.child_mut(), &profile, Duration::from_secs(25)) {
                Ok(url) => url,
                Err(error) => return Err(fail_start(&mut chrome, error)),
            };
            marker.set_port(port_from_ws_url(&ws_url));
            match Transport::connect_ws(&ws_url) {
                Ok(socket) => (socket, Some(ws_url)),
                Err(error) => return Err(fail_start(&mut chrome, error)),
            }
        }
        Some(ends) => {
            let transport::PipeEnds { child_read, child_write, parent_write, parent_read } = ends;
            drop(child_read);
            drop(child_write);
            (Transport::pipe(parent_write, parent_read), None)
        }
    };
    let mut cdp = match Cdp::new(status.clone(), bodies_file) {
        Ok(cdp) => cdp,
        Err(error) => return Err(fail_start(&mut chrome, error)),
    };

    let cookie_audit = if cookie_source_label.is_some() || !imported_cookies.is_empty() {
        Some(CookieAudit {
            source: cookie_source_label.as_deref().unwrap_or("initialCookies"),
            domain: cookie_domain.as_str(),
            skipped: cookie_skipped,
            undecryptable: cookie_undecryptable,
            undecryptable_reason: cookie_undecryptable_reason.as_deref(),
        })
    } else {
        None
    };
    let setup = cdp.setup(
        &mut socket,
        &config.start_url,
        &imported_cookies,
        cookie_audit,
    );
    if let Err(error) = setup {
        let _ = chrome.child_mut().kill();
        let _ = chrome.child_mut().wait();
        chrome.disarm();
        let _ = std::fs::remove_dir_all(&profile);
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    if opts.require_initial_target_ready {
        if let Err(reason) = cdp.wait_initial_target_ready(&mut socket, Duration::from_secs(15)) {
            let error = format!("the capture client did not attach to the initial tab: {reason}");
            let _ = chrome.child_mut().kill();
            let _ = chrome.child_mut().wait();
            chrome.disarm();
            let _ = std::fs::remove_dir_all(&profile);
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    }
    if let Some(endpoint) = &opts.endpoint {
        // Browser version and debugging address, before signaling `ready`.
        let version = cdp
            .send(
                &mut socket,
                "Browser.getVersion",
                json!({}),
                None,
                Duration::from_secs(5),
            )
            .ok();
        if let Ok(mut guard) = endpoint.lock() {
            *guard = Some(browser::Endpoint {
                http: ws_url
                    .as_deref()
                    .and_then(port_from_ws_url)
                    .map(|p| format!("http://127.0.0.1:{p}")),
                browser_ws: ws_url.clone().unwrap_or_default(),
                chrome_pid: chrome.child_mut().id(),
                page_target_id: cdp
                    .setup_seen
                    .get(&cdp.page_session_id)
                    .map(|t| t.target_id.clone()),
                product: version
                    .as_ref()
                    .and_then(|v| v.get("product"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                user_agent: version
                    .as_ref()
                    .and_then(|v| v.get("userAgent"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
    }
    let _ = ready.send(Ok(()));

    // Recording loop: every Network.* event is preserved in Chrome's order.
    let started = Instant::now();
    loop {
        if matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected)) {
            break;
        }
        if started.elapsed() > Duration::from_secs(30 * 60) {
            break;
        }
        if let Some(control) = &opts.control {
            while let Ok(message) = control.try_recv() {
                cdp.handle_control(&mut socket, message);
            }
        }
        match socket.read() {
            Ok(Incoming::Text(text)) => {
                if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                    cdp.record(&mut socket, &value);
                    cdp.flush_outbox(&mut socket);
                }
            }
            Ok(Incoming::Close) => break,
            Ok(Incoming::Ping(payload)) => {
                socket.pong(payload);
            }
            Ok(_) => {}
            Err(ReadError::WouldBlock) => {}
            Err(_) => break,
        }
    }

    // Gives a short window for the getResponseBody/getRequestPostData requests in flight
    // to return before closing; whatever does not return becomes an `unavailable` row.
    // Before closing: gives a short window for late setup ACKs, and only then
    // turns what is still unanswered into a warning.
    cdp.pump_until_setup_settled(&mut socket, Duration::from_millis(1500));
    cdp.finalize_pending_setups();
    cdp.drain_bodies(&mut socket, Duration::from_secs(3));
    cdp.finish_bodies();

    // Shut Chrome down gracefully so that the NetLog is finalized.
    let transport_closed = socket.abnormal_close_reason().map(str::to_string);
    let close_started = Instant::now();
    let close_result = cdp.send(
        &mut socket,
        "Browser.close",
        json!({}),
        None,
        Duration::from_secs(2),
    );
    socket.close();
    let exit = wait_or_kill(chrome.child_mut(), Duration::from_secs(20));
    chrome.disarm();
    let shutdown = ShutdownReport {
        browser_close: close_result.map(|_| ()),
        exit,
        waited_ms: close_started.elapsed().as_millis() as u64,
        transport_closed,
    };
    eprintln!("capture shutdown: {shutdown:?}");
    // Chrome has already exited: reads the NetLog from the private profile (without following links, only
    // a regular file of ours) before deleting the profile.
    let netlog_raw = read_private_regular(&netlog_path).filter(|bytes| !bytes.is_empty());
    // The profile is only deleted once the session has been written: if the destination
    // directory is no longer trustworthy (A4-B5), the data stays here.
    let mut profile_guard = ProfileCleanup {
        path: profile.clone(),
        keep: false,
    };

    let cdp_bytes = cdp.events_text().into_bytes();
    if cdp_bytes.is_empty() {
        if recheck_session_dir(&config.session_dir, session_identity).is_ok() {
            let _ = fdio::write_private_at(&session_handle, "cdp-events.jsonl", &cdp_bytes);
        }
        let error = "No CDP event was recorded. The session was not created; check whether Chrome stayed open during the capture.".to_string();
        let _ = ready.send(Err(error.clone()));
        return Err(error);
    }
    // From here on, ANY write failure rescues the capture files
    // (A5-B2) before the profile is deleted; the profile only goes away once the session was
    // written or the rescue worked.
    let finish = (|| -> Result<(CaptureOutcome, RunReport), String> {
    recheck_session_dir(&config.session_dir, session_identity).map_err(session_dir_changed)?;
    // The CDP and the bodies are already evidence: they are on disk before any
    // step that could fail (a bad NetLog never discards the capture).
    // Everything relative to the descriptor of the directory opened at the start (A6-B5): if the name
    // is swapped, nothing lands in the attacker's directory.
    fdio::write_private_at(&session_handle, "cdp-events.jsonl", &cdp_bytes)
        .map_err(|error| format!("cdp-events.jsonl: {error}"))?;

    if let Some(raw) = &netlog_raw {
        // Faithful copy of what Chrome wrote (the parsed/repaired version comes later).
        if let Err(error) = fdio::write_private_at(&session_handle, "netlog.json", raw) {
            eprintln!("netlog.json: {error}");
        }
    }
    let (netlog, netlog_status) = prepare_netlog(netlog_raw.as_deref());
    if let NetlogStatus::Repaired { .. } | NetlogStatus::Unusable { .. } = &netlog_status {
        // Keep Chrome's original file next to the session.
        if let Some(raw) = &netlog_raw {
            let _ = fdio::write_private_at(&session_handle, "netlog.original.json", raw);
        }
    }

    // Without the bodies file (write failure), the core warns once per session.
    // Re-read through the descriptor (not the path): this holds even if the directory was swapped.
    let bodies_bytes = read_all_from(&mut bodies_reader);
    let mut imported = import_capture_labeled(
        &cdp_bytes,
        &netlog,
        bodies_bytes.as_deref(),
        &["live-capture".to_string()],
        CorrelationOptions::default(),
    )
    .map_err(|error| format!("The core could not import the capture: {error}"))?;
    mark_incomplete(&mut imported.bundle.session, &netlog_status, &shutdown);
    // Capture metadata belongs to the pipeline, not the parser: the core builds the
    // document from the CDP and does not know this flow also wrote a NetLog.
    // D7: `chromeArgs` records the launch arguments (without temporary paths),
    // including `--disable-blink-features=AutomationControlled`, and
    // `notes` says so in text, so whoever reads the session knows the context.
    let recorded_args = recorded_chrome_args(&launch_args);
    let mut automation_note = format!(
        "capture with the automation notice suppressed (--disable-blink-features={AUTOMATION_FEATURE}): navigator.webdriver === false"
    );
    // Linux/arm64: stable Google Chrome has no build; Chromium is accepted and is
    // recorded in the session (docs/21-linux.md §3).
    if chrome::BrowserKind::from_path(&config.chrome) == chrome::BrowserKind::Chromium {
        automation_note.push_str(
            "; browser: Chromium (alternative to stable Google Chrome, which does not exist for this system/architecture)",
        );
    }
    if let Some(plan) = proxy_plan.as_ref() {
        let peer = plan.peer_check();
        if peer.checks > 0 {
            automation_note.push_str(&format!(
                "; relay peer check: {} connections, max {} us, refused {}",
                peer.checks,
                peer.max_nanos.div_ceil(1_000),
                peer.refused
            ));
        }
    }
    // `capture.proxy`: the scheme, the authentication flag and (full export only) the
    // address and route. The credentials are never part of it.
    let proxy_record = proxy_plan.as_ref().map(|plan| {
        scrapelens_core::model::ProxyRecord {
            scheme: plan.link().scheme().as_str().to_string(),
            host: Some(plan.link().host().to_string()),
            port: Some(plan.link().port()),
            authenticated: plan.link().authenticated(),
            route: Some(match plan.route() {
                relay::ProxyRoute::Direct => scrapelens_core::model::ProxyRoute::Direct,
                relay::ProxyRoute::Relay => scrapelens_core::model::ProxyRoute::Relay,
            }),
        }
    });
    match imported.bundle.session.session.capture.as_mut() {
        Some(capture) => {
            capture.proxy = proxy_record.clone();
            capture.mode = Some("cdp+netlog".to_string());
            capture.headless = Some(config.headless);
            capture.browser_binary = Some(config.chrome.display().to_string());
            capture.chrome_args = Some(recorded_args);
            capture.notes = Some(match capture.notes.take() {
                Some(previous) if !previous.is_empty() => format!("{previous}; {automation_note}"),
                _ => automation_note,
            });
        }
        None => {
            imported.bundle.session.session.capture = Some(scrapelens_core::model::CaptureMeta {
                mode: Some("cdp+netlog".to_string()),
                browser_binary: Some(config.chrome.display().to_string()),
                headless: Some(config.headless),
                chrome_args: Some(recorded_args),
                notes: Some(automation_note),
                proxy: proxy_record,
            });
        }
    }
    // Allowlist: what the resolver denied, and what escaped it, becomes a warning in the
    // session (visible to whoever only reads the session) and in the `stop_capture` report.
    let allowlist_report = opts
        .allowlist
        .as_ref()
        .map(|list| list.report_from_events(&cdp.events, &imported.bundle.session));
    let mut report_warnings: Vec<String> = Vec::new();
    if let Some(reason) = &shutdown.transport_closed {
        report_warnings.push(format!(
            "cdp_transport_closed: {reason}: the CDP channel closed before the stop request; the capture is incomplete."
        ));
    }
    if let Some(report) = &allowlist_report {
        for blocked in &report.blocked_hosts {
            let message = format!(
                "the page tried to load {} ({} request(s)); blocked by the allowlist; the protection or the resource may be hidden",
                blocked.host, blocked.requests
            );
            imported.bundle.session.add_warning(
                scrapelens_core::model::Warning::info("capture.third_party_blocked", message.clone())
                    .with_detail(json!({ "host": blocked.host, "requests": blocked.requests })),
            );
            report_warnings.push(message);
        }
        for violation in &report.violations {
            // `violation.url` already comes without query, fragment, `;params` or userinfo.
            let message = format!(
                "request outside the allowlist: {} ({})",
                violation.url, violation.reason
            );
            imported.bundle.session.add_warning(
                scrapelens_core::model::Warning::new("capture.allowlist_violation", message.clone())
                    .with_entity(violation.request_id.clone()),
            );
            report_warnings.push(message);
        }
    }
    // Proxy failures (relay, or Chrome's ERR_PROXY_* / ERR_TUNNEL_* on the direct route)
    // are a session warning and part of the notice, not a generic page failure.
    let mut proxy_reasons = proxy_plan.as_ref().map(relay::ProxyPlan::failures).unwrap_or_default();
    if let Some(plan) = proxy_plan.as_ref() {
        if plan.route() == relay::ProxyRoute::Direct {
            let server = plan.link().server_url();
            let events = std::str::from_utf8(&cdp_bytes).unwrap_or("");
            for reason in relay::direct_route_proxy_failures(true, events, &netlog) {
                let qualified = if reason.contains("://") {
                    reason
                } else {
                    reason.replacen("the proxy", &format!("the proxy {server}"), 1)
                };
                if !proxy_reasons.iter().any(|have| have == &qualified) {
                    proxy_reasons.push(qualified);
                }
            }
        }
    }
    for reason in &proxy_reasons {
        imported.bundle.session.add_warning(
            scrapelens_core::model::Warning::error("capture.proxy_failure", reason.clone()),
        );
        report_warnings.push(reason.clone());
    }
    // A3-B3/A6-B5: the session is written into a staging directory of OURS (inside the
    // 0700 profile) and moved into the session directory with `renameat` relative to the
    // descriptor opened at the start: a symlink planted under the name is replaced without
    // writing to the target, and swapping the directory's name sends nothing outside.
    for name in write_session_fd(&mut imported.bundle, &session_handle, &profile)? {
        report_warnings.push(format!(
            "{name}: there was a symbolic link where the session file goes; the link was replaced (the target was not touched) and the file was written normally."
        ));
    }
    // After writing, the directory must still be the one from the start: if the name
    // was swapped during the write, the session stayed in the ORIGINAL directory (moved),
    // not where the caller will look. Do not say OK (A6-B5).
    if let Err(why) = recheck_session_dir(&config.session_dir, session_identity) {
        return Err(session_dir_changed_after_write(why, &session_handle));
    }

    let session_value = serde_json::to_value(&imported.bundle.session)
        .map_err(|error| format!("Session invalid after import: {error}"))?;
    let requests = imported.report.source_events_used;
    let warnings = imported.report.warnings.len();

    let report = RunReport {
        allowlist: allowlist_report,
        requests: imported.bundle.session.requests.len(),
        netlog: match &netlog_status {
            NetlogStatus::Complete => "complete".to_string(),
            NetlogStatus::Repaired { .. } => "repaired".to_string(),
            NetlogStatus::Unusable { .. } => "unusable".to_string(),
        },
        graceful: matches!(shutdown.exit, ChromeExit::Graceful(_)) && shutdown.browser_close.is_ok(),
        waited_ms: shutdown.waited_ms,
        warnings: report_warnings,
    };
    let proxy_suffix = if proxy_reasons.is_empty() {
        String::new()
    } else {
        format!("; proxy: {}", proxy_reasons.join("; "))
    };
    Ok((
        CaptureOutcome {
            session: session_value,
            session_dir: config.session_dir.clone(),
            notice: format!(
                "Session captured and imported: {requests} CDP+NetLog event(s) used, {warnings} warning(s).{cookie_suffix}{proxy_suffix}"
            ),
        },
        report,
    ))
    })();
    match finish {
        Ok(done) => Ok(done),
        Err(message) => {
            // Remove the `.tmp-*` left by the write, in the ORIGINAL directory (through the
            // descriptor opened at the start), whether or not it is still in place.
            remove_stale_tmp(&session_handle);
            Err(rescue_or_adopt(
                &message,
                &default_state_root(),
                &profile,
                &mut profile_guard,
                &cdp_bytes,
                netlog_raw.as_deref(),
                &mut bodies_reader,
            ))
        }
    }
}

/// Blink feature disabled in every capture (D7, `docs/01-decisions.md`).
pub const AUTOMATION_FEATURE: &str = "AutomationControlled";

/// Ensures ONE single `--disable-blink-features=` with `features` combined with the ones
/// that already existed (without duplicating the flag or the values; the original order is kept).
/// Without the flag, it is added before the last argument (the URL).
fn mark_incomplete(
    document: &mut scrapelens_core::model::SessionV1,
    netlog: &NetlogStatus,
    shutdown: &ShutdownReport,
) {
    let detail = json!({
        "browserClose": shutdown.browser_close.clone().err(),
        "chromeExit": format!("{:?}", shutdown.exit),
        "waitedMs": shutdown.waited_ms,
        "netlog": format!("{netlog:?}"),
        "transportClosed": shutdown.transport_closed,
    });
    let killed = matches!(shutdown.exit, ChromeExit::Killed);
    let mut entries: Vec<(&str, String)> = Vec::new();
    // A3-B2: the CDP closed on its own (message above the ceiling). Chrome exits
    // afterwards gracefully and the NetLog looks complete, but the capture stopped
    // before the stop request: the explicit reason comes first.
    if let Some(reason) = &shutdown.transport_closed {
        entries.push((
            "capture.cdp_transport_closed",
            format!(
                "cdp_transport_closed: {reason}: the CDP channel closed before the stop request; events after that point were not captured."
            ),
        ));
    }
    match netlog {
        NetlogStatus::Complete if !killed => {}
        NetlogStatus::Complete => entries.push((
            "capture.chrome_killed",
            "Chrome did not exit within the deadline and was force-killed; the NetLog may not reflect the end of the capture.".to_string(),
        )),
        NetlogStatus::Repaired { original_bytes, kept_bytes } => entries.push((
            "capture.netlog_incomplete",
            format!("The Chrome NetLog was truncated ({original_bytes} bytes); the session uses only the complete events ({kept_bytes} bytes). The original is in netlog.original.json."),
        )),
        NetlogStatus::Unusable { reason } => entries.push((
            "capture.netlog_unusable",
            format!("{reason}: the session was imported with CDP and bodies only, without NetLog evidence. The original (if it exists) is in netlog.original.json."),
        )),
    }
    for (code, message) in entries {
        document
            .session
            .completeness
            .add_reason(format!("{code}: {message}"));
        document
            .warnings
            .push(scrapelens_core::model::Warning::new(code, message).with_detail(detail.clone()));
    }
}

/// Names that the session writes (files) or creates (`attachments`) in the session
/// directory, which a planted symlink could occupy.
const SESSION_DIR_LINK_NAMES: [&str; 4] =
    ["cdp-events.jsonl", "netlog.json", "session.json", "attachments"];

/// Writes the session (A3-B3, A4-B3, A6-B5) WITHOUT resolving the session directory's path
/// at any point:
/// 1. warns (in the document) which names were symlinks, through the descriptor;
/// 2. the core writes the bundle into a new 0700 staging directory inside
///    `stage_parent` (the temporary profile, ours and out of the attacker's reach);
/// 3. each item is moved into the session directory with `renameat` relative to the
///    descriptor (`session.json` last), replacing the name, including a
///    symlink, without writing to its target. Between different filesystems, it copies.
///
/// Re-planting links in a loop (A4-B4) no longer matters: `renameat` is atomic.
/// Returns the names that were symlinks and were replaced.
fn write_session_fd(
    bundle: &mut scrapelens_core::SessionBundle,
    session: &std::fs::File,
    stage_parent: &Path,
) -> Result<Vec<String>, String> {
    let fail = |what: &str, error: &dyn std::fmt::Display| {
        format!("Could not write the session: {what}: {error}")
    };
    for name in SESSION_DIR_LINK_NAMES {
        if fdio::kind_of(session, name).ok().flatten() == Some(fdio::EntryKind::Symlink) {
            bundle.session.add_warning(scrapelens_core::model::Warning::new(
                "capture.planted_symlink_removed",
                format!("{name} was a symbolic link in the session directory; the link was replaced and the target was not touched."),
            ));
        }
    }
    let stage = stage_parent.join(format!("stage-{}", unix_nanos()));
    create_private_dir_new(&stage).map_err(|e| fail("staging directory", &e))?;
    let result = (|| -> Result<Vec<String>, String> {
        store::write_session_dir(bundle, &stage).map_err(|e| fail("preparo", &e))?;
        let (stage_handle, _) =
            verify_private_dir_handle(&stage).map_err(|e| fail("staging directory", &e))?;
        let mut replaced: Vec<String> = Vec::new();
        // `session.json` last: it never points to files that do not exist yet.
        let mut order: Vec<String> = fdio::list(&stage_handle)
            .map_err(|e| fail("preparo", &e))?
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| name != "session.json")
            .collect();
        order.sort();
        order.push("session.json".to_string());
        for name in order {
            replaced.extend(
                fdio::move_entry(&stage_handle, session, &name).map_err(|e| fail(&name, &e))?,
            );
        }
        Ok(replaced)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result
}

/// Reads everything from the descriptor (from position 0). For the bodies: re-reads through the descriptor, not
/// through the path.
fn read_all_from(file: &mut std::fs::File) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Error message when the session directory stopped being trustworthy (A4-B5).
fn session_dir_changed(why: String) -> String {
    format!(
        "The session directory was swapped or stopped being ours during the capture ({why}); nothing was written to it and nothing outside it was deleted."
    )
}

/// Message when the directory was swapped DURING the write (A7): the session was
/// written in full to the ORIGINAL directory (the descriptor opened at the start), which the
/// system now finds at another path (`F_GETPATH`); nothing was written to the directory
/// that took its place. It does not repeat "nothing was written to it", which would be false.
fn session_dir_changed_after_write(why: String, original: &std::fs::File) -> String {
    let moved = descriptor_path(original)
        .map(|p| format!("now at {}", p.display()))
        .unwrap_or_else(|| "that we could not locate".to_string());
    format!(
        "The session directory was swapped during the write ({why}). The session was written in full to the ORIGINAL directory, {moved}; nothing was written to the directory that took its place, and nothing outside the original directory was deleted."
    )
}

/// CURRENT path of the directory that the descriptor represents, even if the name has
/// been moved (macOS: `F_GETPATH`; Linux: `/proc/self/fd/N`).
#[cfg(target_os = "macos")]
fn descriptor_path(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes at most PATH_MAX bytes into the buffer.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
    if result < 0 {
        return None;
    }
    let len = buffer.iter().position(|&b| b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..len])))
}

/// Linux: `readlink /proc/self/fd/N` (the directory's current path; the kernel appends
/// ` (deleted)` if it was deleted).
#[cfg(target_os = "linux")]
fn descriptor_path(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn descriptor_path(_file: &std::fs::File) -> Option<PathBuf> {
    None
}

const RESCUE_PREFIX: &str = "rescue-";
/// Age from which `cleanup_orphans` deletes a rescue folder.
const RESCUE_TTL_DAYS: u64 = 7;

/// Rescue (A5-B2, A5-B3): when the session could not be written, it keeps ONLY the
/// capture files (CDP events, bodies and NetLog) in a new 0700 folder inside
/// `state_root`, with a marker so that `cleanup_orphans` deletes it later, after
/// `RESCUE_TTL_DAYS`. The rest of the Chrome profile (Cookies, Login Data, History)
/// is never kept. Returns the folder.
fn rescue_capture_files(
    state_root: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> Result<PathBuf, String> {
    #[cfg(test)]
    if FORCE_PRIMARY_RESCUE_FAILURE.with(std::cell::Cell::get) {
        return Err("forced failure (test)".to_string());
    }
    ensure_private_state_root(state_root).map_err(|e| format!("state folder: {e}"))?;
    let name = format!("{RESCUE_PREFIX}{}-{}", std::process::id(), unix_nanos());
    let dir = state_root.join(&name);
    create_private_dir_new(&dir).map_err(|e| format!("rescue folder: {e}"))?;
    let result = fill_rescue_dir(&dir, cdp, netlog, bodies, reason)
        .and_then(|()| write_rescue_marker(state_root, &name));
    match result {
        Ok(()) => Ok(dir),
        Err(error) => {
            // A half-done rescue is no good: the caller tries plan B.
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_file(state_root.join(format!("{name}.json")));
            Err(error.to_string())
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test: makes the normal rescue fail on THIS thread (plan B kicks in).
    static FORCE_PRIMARY_RESCUE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Writes the capture files (and the reason) into a rescue folder.
fn fill_rescue_dir(
    dir: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    if !cdp.is_empty() {
        write_private(&dir.join("cdp-events.jsonl"), cdp)?;
    }
    if let Some(raw) = netlog {
        write_private(&dir.join("netlog.json"), raw)?;
    }
    let mut body_bytes = Vec::new();
    if bodies.seek(SeekFrom::Start(0)).is_ok()
        && bodies.read_to_end(&mut body_bytes).is_ok()
        && !body_bytes.is_empty()
    {
        write_private(&dir.join("cdp-bodies.jsonl"), &body_bytes)?;
    }
    write_private(&dir.join("motivo.txt"), reason.as_bytes())
}

/// Marker `<name>.json` next to the rescue folder. Its age does NOT come from it.
fn write_rescue_marker(state_root: &Path, name: &str) -> std::io::Result<()> {
    let marker = json!({
        "kind": "rescue",
        "ownerPid": std::process::id(),
        "dir": name,
    });
    write_private(
        &state_root.join(format!("{name}.json")),
        marker.to_string().as_bytes(),
    )
}

/// Plan B of the rescue (A6-B6), used when the normal rescue folder could not be
/// created (e.g. ENOSPC): the temporary profile ITSELF becomes the rescue. It deletes everything
/// that is not part of the capture (Cookies, Login Data, History..., which also frees
/// space), writes the CDP events, the bodies and the reason into it, and moves it to
/// `state_root` with a marker, under the same 7-day deadline. If it cannot
/// move or mark it, it stays where it is, already cleaned and holding the events, and the
/// return says there is no automatic deadline.
struct AdoptedProfile {
    dir: PathBuf,
    has_ttl: bool,
}

fn adopt_profile_as_rescue(
    state_root: &Path,
    profile: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> Result<AdoptedProfile, String> {
    // 1. Only the capture files survive in the profile.
    let keep_netlog = netlog.is_none() && profile.join("netlog.json").is_file();
    for entry in std::fs::read_dir(profile).map_err(|e| format!("profile: {e}"))?.flatten() {
        let path = entry.path();
        if keep_netlog && entry.file_name() == "netlog.json" {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let _ = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
    // 2. The events, the bodies and the reason.
    fill_rescue_dir(profile, cdp, netlog, bodies, reason).map_err(|e| format!("profile: {e}"))?;
    // 3. Move to the state root and mark it (same deadline).
    let name = format!("{RESCUE_PREFIX}{}-{}", std::process::id(), unix_nanos());
    let target = state_root.join(&name);
    let moved = ensure_private_state_root(state_root)
        .ok()
        .and_then(|()| std::fs::rename(profile, &target).ok());
    if moved.is_some() && write_rescue_marker(state_root, &name).is_ok() {
        return Ok(AdoptedProfile { dir: target, has_ttl: true });
    }
    Ok(AdoptedProfile {
        dir: if moved.is_some() { target } else { profile.to_path_buf() },
        has_ttl: false,
    })
}

/// Rescues the capture files after a write failure and returns the
/// final error for `stop_capture`: normal rescue folder; if that fails, plan B
/// (the profile becomes the rescue); if everything fails, the profile is kept.
fn rescue_or_adopt(
    message: &str,
    state_root: &Path,
    profile: &Path,
    profile_guard: &mut ProfileCleanup,
    cdp_bytes: &[u8],
    netlog_raw: Option<&[u8]>,
    bodies: &mut std::fs::File,
) -> String {
    match rescue_capture_files(state_root, cdp_bytes, netlog_raw, bodies, message) {
        Ok(dir) => format!(
            "{message} The capture files (CDP events, bodies and NetLog) were kept in the rescue folder {} (0700; automatically deleted after {} days).",
            dir.display(),
            RESCUE_TTL_DAYS
        ),
        Err(why) => {
            // Plan B: the profile becomes the rescue (cleaned, with the events and, if
            // possible, with a marker and deadline). Never lose the data.
            profile_guard.keep();
            match adopt_profile_as_rescue(state_root, profile, cdp_bytes, netlog_raw, bodies, message) {
                Ok(adopted) if adopted.has_ttl => format!(
                    "{message} The normal rescue failed ({why}); the capture files (CDP events, bodies and NetLog) were kept in {} (0700; automatically deleted after {} days).",
                    adopted.dir.display(),
                    RESCUE_TTL_DAYS
                ),
                Ok(adopted) => format!(
                    "{message} The normal rescue failed ({why}); the capture files (CDP events, bodies and NetLog) were kept in {}, WITHOUT an automatic deadline (it could not be marked): delete them when you recover.",
                    adopted.dir.display()
                ),
                Err(second) => format!(
                    "{message} The rescue failed ({why}) and so did plan B ({second}); the temporary profile {} was kept and may be incomplete (it contains Chrome data; delete it when you recover).",
                    profile.display()
                ),
            }
        }
    }
}

/// Removes the `.tmp-*` files that `write_atomic` (core) and `write_private` leave in the
/// session directory when the `rename` fails. It works through the directory's DESCRIPTOR (opened
/// at the start): it applies to the original directory even if the name was swapped or
/// moved, and never follows a path. Only files with the exact name of those
/// we write (`.<file>.tmp-…`).
fn remove_stale_tmp(dir: &std::fs::File) {
    use std::ffi::{CStr, CString};
    use std::os::fd::AsRawFd;
    const NAMES: [&str; 5] = [
        "cdp-events.jsonl",
        "netlog.json",
        "netlog.original.json",
        "session.json",
        "cdp-bodies.jsonl",
    ];
    // SAFETY: `dup` of the open descriptor; `fdopendir` takes over the copy and `closedir`
    // closes it; `readdir` returns valid entries until NULL; `unlinkat` only removes
    // the name (it never follows a symlink: without AT_REMOVEDIR it removes the link itself).
    unsafe {
        let copy = libc::dup(dir.as_raw_fd());
        if copy < 0 {
            return;
        }
        let stream = libc::fdopendir(copy);
        if stream.is_null() {
            libc::close(copy);
            return;
        }
        libc::rewinddir(stream);
        let mut found: Vec<CString> = Vec::new();
        loop {
            let entry = libc::readdir(stream);
            if entry.is_null() {
                break;
            }
            let name = CStr::from_ptr((*entry).d_name.as_ptr());
            let text = name.to_string_lossy();
            let regular = (*entry).d_type == libc::DT_REG;
            if regular && NAMES.iter().any(|n| text.starts_with(&format!(".{n}.tmp-"))) {
                found.push(name.to_owned());
            }
        }
        libc::closedir(stream);
        for name in found {
            libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
        }
    }
}

/// Atomic, symlink-safe write: writes into a new file with a unique name
/// (`create_new` + `O_NOFOLLOW`, 0600) in the same directory, and swaps the destination with
/// `rename`, which replaces the symlink itself (it never writes to its target).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp = path.with_file_name(format!(".{name}.tmp-{}-{}", std::process::id(), unix_nanos()));
    let result = (|| {
        let mut file = open_new_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Identity of a directory (device + inode) read from the open descriptor.
/// Used by `stop` to recognize that the session directory is the SAME one as at the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirIdentity {
    dev: u64,
    ino: u64,
}

/// Rechecks the session directory on `stop` (A4-B5): opened without following links, ours,
/// 0700 and with the identity (dev+inode) from the start. Swapping the directory for a symlink,
/// or for another directory, makes stop fail without writing anything to it.
fn recheck_session_dir(dir: &Path, expected: DirIdentity) -> Result<(), String> {
    match verify_private_dir(dir) {
        Ok(found) if found == expected => Ok(()),
        Ok(_) => Err("it is a different directory from the one at the start of the capture".to_string()),
        Err(error) => {
            let is_link = std::fs::symlink_metadata(dir)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            Err(if is_link {
                "now a symbolic link".to_string()
            } else {
                error.to_string()
            })
        }
    }
}

/// Deletes the temporary profile on exit, unless `keep()` was called
/// (the session was left there because the destination directory was not trustworthy).
struct ProfileCleanup {
    path: PathBuf,
    keep: bool,
}

impl ProfileCleanup {
    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Creates a NEW 0700 directory (fails if the name exists, including as a
/// symlink) and checks, while open, that it is ours, not a link, 0700.
fn create_private_dir_new(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(false).mode(0o700).create(path)?;
        verify_private_dir(path).map(|_| ())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

/// Opens the directory without following the final link, and checks through the open descriptor:
/// it is a directory, it belongs to our user, and the mode is exactly 0700.
#[cfg(unix)]
fn verify_private_dir(path: &Path) -> std::io::Result<DirIdentity> {
    verify_private_dir_handle(path).map(|(_, identity)| identity)
}

/// Like `verify_private_dir`, but also returns the open descriptor of the directory:
/// it keeps pointing to the SAME directory even if the name is swapped, and
/// is used to clean up the `.tmp-*` that the write left in it.
#[cfg(unix)]
fn verify_private_dir_handle(path: &Path) -> std::io::Result<(std::fs::File, DirIdentity)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let meta = dir.metadata()?;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o777 != 0o700 {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is not a 0700 directory of ours (mode {:o}, owner {})",
                path.display(),
                meta.mode() & 0o7777,
                meta.uid()
            ),
        ));
    }
    Ok((
        dir,
        DirIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        },
    ))
}

/// Reads a file without following symlinks: it only accepts a regular file of our
/// user (checked through the open descriptor). `None` if it is missing or refused.
fn read_private_regular(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return None;
        }
    }
    if !meta.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Creates a NEW 0600 file without following symlinks: `create_new` (O_EXCL) and
/// `O_NOFOLLOW`. Fails if the name already exists (including as a symlink).
fn open_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    // `read` too: the rescue re-reads the bodies through its own descriptor.
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(test)]
/// Opens the file for writing as NEW, without following symlinks. If the name already
/// exists (old file or planted symlink), it REMOVES the name (the link, never the
/// target) and creates it again; a race in which someone re-plants the name makes the
/// `create_new` fail instead of writing outside.
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    match open_new_private(path) {
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            open_new_private(path)
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Bodies (docs/08-body-search.md §1): collection without blocking the event loop.
// ---------------------------------------------------------------------------

/// Limit per body (decoded bytes).
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
/// Total budget of bodies written per session.
const SESSION_BODY_BUDGET: usize = 256 * 1024 * 1024;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BodyTag {
    Request {
        request_id: String,
        attempt: u32,
        timestamp: f64,
        /// `postData` (lossy) of the event, kept when `postDataEntries` came
        /// incomplete: it is only written (marked) if `getRequestPostData` fails.
        fallback_post_data: Option<String>,
        entries_incomplete: bool,
    },
    Response {
        request_id: String,
        attempt: u32,
        timestamp: f64,
        empty_evidence: Option<String>,
        charset: Option<String>,
    },
}

pub(crate) struct BodyCommand {
    method: &'static str,
    params: Value,
    tag: BodyTag,
}

#[derive(Default)]
struct RequestState {
    /// Number of `requestWillBeSent` events seen (next attemptIndex).
    attempts: u32,
    /// The current attempt's response already has a row (or a command in flight).
    response_resolved: bool,
    status: Option<u64>,
    content_length_zero: bool,
    method: String,
    /// charset declared by the response (Content-Type or `response.charset`).
    charset: Option<String>,
}

#[derive(Default)]
pub(crate) struct BodyCollector {
    requests: HashMap<String, RequestState>,
    lines: Vec<String>,
    used: usize,
}

struct Row<'a> {
    request_id: &'a str,
    attempt: u32,
    kind: &'a str,
    source: &'a str,
    timestamp: f64,
    /// Transformations between the wire and `data` (optional `transformed` field).
    transformed: Vec<String>,
}

impl<'a> Row<'a> {
    fn marked(mut self, marks: Vec<String>) -> Self {
        self.transformed = marks;
        self
    }
}

impl BodyCollector {
    pub(crate) fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    fn push(
        &mut self,
        row: Row,
        state: &str,
        encoding: Option<&str>,
        data: Option<String>,
        sizes: (Option<usize>, usize),
        reason: Option<String>,
    ) {
        let mut line = json!({
            "v": 1,
            "requestId": row.request_id,
            "attemptIndex": row.attempt,
            "kind": row.kind,
            "state": state,
            "encoding": encoding,
            "data": data,
            "originalSize": sizes.0,
            "capturedSize": sizes.1,
            "source": row.source,
            "reason": reason,
            "timestamp": row.timestamp,
        });
        if !row.transformed.is_empty() {
            line["transformed"] = json!(row.transformed);
        }
        self.lines.push(line.to_string());
    }

    fn unavailable(&mut self, row: Row, reason: impl Into<String>) {
        self.push(
            row,
            "unavailable",
            None,
            None,
            (None, 0),
            Some(reason.into()),
        );
    }

    /// Converts the body delivered by the CDP into a row, applying a per-body limit,
    /// the session budget, and the `empty` rule only with evidence.
    fn emit_body(
        &mut self,
        row: Row,
        text: &str,
        base64_encoded: bool,
        empty_evidence: Option<&str>,
    ) {
        let decoded;
        let (bytes, size): (Option<&[u8]>, usize) = if base64_encoded {
            match b64_decode(text) {
                Some(bytes) => {
                    decoded = bytes;
                    (Some(&decoded[..]), decoded.len())
                }
                None => {
                    return self.unavailable(row, "invalid base64 from CDP");
                }
            }
        } else {
            (None, text.len())
        };
        if size == 0 {
            return match empty_evidence {
                Some(evidence) => self.push(row, "empty", None, None, (Some(0), 0), Some(evidence.to_string())),
                None => self.unavailable(
                    row,
                    "CDP returned 0 bytes without evidence of an empty body (no 204/205/304 nor Content-Length: 0)",
                ),
            };
        }
        let keep = size.min(MAX_BODY_BYTES);
        if self.used + keep > SESSION_BODY_BUDGET {
            return self.push(
                row,
                "discarded",
                None,
                None,
                (Some(size), 0),
                Some("session body budget exceeded".to_string()),
            );
        }
        let truncated = size > keep;
        // `data` is the CDP string, byte by byte; we only cut it at the limit.
        let (encoding, data) = match (base64_encoded, bytes) {
            (true, Some(bytes)) if truncated => ("base64", b64_encode(&bytes[..keep])),
            (true, _) => ("base64", text.to_string()),
            (false, _) if truncated => {
                let mut end = keep;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                ("utf8", text[..end].to_string())
            }
            (false, _) => ("utf8", text.to_string()),
        };
        let captured = if encoding == "utf8" {
            data.len()
        } else if truncated {
            keep
        } else {
            size
        };
        self.used += captured;
        let reason = truncated.then(|| {
            format!("body above the limit of {MAX_BODY_BYTES} bytes; only the prefix was written")
        });
        self.push(
            row,
            if truncated { "truncated" } else { "captured" },
            Some(encoding),
            Some(data),
            (Some(size), captured),
            reason,
        );
    }

    fn request_row<'a>(
        request_id: &'a str,
        attempt: u32,
        source: &'a str,
        timestamp: f64,
    ) -> Row<'a> {
        Row {
            request_id,
            attempt,
            kind: "request",
            source,
            timestamp,
            transformed: Vec::new(),
        }
    }

    fn response_row(request_id: &str, attempt: u32, timestamp: f64) -> Row<'_> {
        Row {
            request_id,
            attempt,
            kind: "response",
            source: "Network.getResponseBody",
            timestamp,
            transformed: Vec::new(),
        }
    }

    /// Resolves the current attempt's response as unavailable (only once).
    fn resolve_response_unavailable(&mut self, request_id: &str, timestamp: f64, reason: String) {
        let Some(state) = self.requests.get_mut(request_id) else {
            return;
        };
        if state.attempts == 0 || state.response_resolved {
            return;
        }
        state.response_resolved = true;
        let attempt = state.attempts - 1;
        self.unavailable(Self::response_row(request_id, attempt, timestamp), reason);
    }

    pub(crate) fn on_event(&mut self, method: &str, params: &Value) -> Vec<BodyCommand> {
        let mut commands = Vec::new();
        let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
            return commands;
        };
        let timestamp = params
            .get("timestamp")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        match method {
            "Network.requestWillBeSent" => {
                let previous = self
                    .requests
                    .get(request_id)
                    .map(|s| (s.attempts, s.response_resolved));
                if let Some((attempts, resolved)) = previous {
                    if attempts > 0 && !resolved {
                        let reason = if params.get("redirectResponse").is_some_and(|v| !v.is_null())
                        {
                            "redirect response: CDP does not provide a body"
                        } else {
                            "attempt replaced by a new requestWillBeSent without redirectResponse; response not observed"
                        };
                        self.resolve_response_unavailable(
                            request_id,
                            timestamp,
                            reason.to_string(),
                        );
                    }
                }
                let request = params.get("request").unwrap_or(&Value::Null);
                let http_method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("GET")
                    .to_string();
                let state = self.requests.entry(request_id.to_string()).or_default();
                let attempt = state.attempts;
                state.attempts += 1;
                state.response_resolved = false;
                state.status = None;
                state.content_length_zero = false;
                state.charset = None;
                state.method = http_method.clone();
                let request_cl_zero = header_is_zero(request.get("headers"));
                self.request_body(
                    request_id,
                    attempt,
                    timestamp,
                    request,
                    &http_method,
                    request_cl_zero,
                    &mut commands,
                );
            }
            "Network.responseReceived" => {
                let response = params.get("response").unwrap_or(&Value::Null);
                let kind = params.get("type").and_then(Value::as_str).unwrap_or("");
                let mime = response
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some(state) = self.requests.get_mut(request_id) {
                    state.status = response.get("status").and_then(Value::as_u64);
                    state.content_length_zero = header_is_zero(response.get("headers"));
                    state.charset = declared_charset(response);
                }
                if kind == "EventSource" || mime.eq_ignore_ascii_case("text/event-stream") {
                    self.resolve_response_unavailable(
                        request_id,
                        timestamp,
                        "SSE/streaming: CDP does not provide the body of a stream; messages arrive as separate events and are not written".to_string(),
                    );
                }
            }
            "Network.webSocketCreated" => {
                let state = self.requests.entry(request_id.to_string()).or_default();
                if state.attempts == 0 {
                    state.attempts = 1;
                }
                self.resolve_response_unavailable(
                    request_id,
                    timestamp,
                    "WebSocket: there is no HTTP body; frames (Network.webSocketFrame*) are not written".to_string(),
                );
            }
            "Network.loadingFinished" => {
                let Some(state) = self.requests.get_mut(request_id) else {
                    return commands;
                };
                if state.attempts == 0 || state.response_resolved {
                    return commands;
                }
                state.response_resolved = true;
                let attempt = state.attempts - 1;
                let charset = state.charset.clone();
                let evidence = match state.status {
                    Some(status @ (204 | 205 | 304)) => {
                        Some(format!("status {status} has no body"))
                    }
                    _ if state.method.eq_ignore_ascii_case("HEAD") => {
                        Some("HEAD response has no body".to_string())
                    }
                    _ if state.content_length_zero => Some("Content-Length: 0".to_string()),
                    _ => None,
                };
                commands.push(BodyCommand {
                    method: "Network.getResponseBody",
                    params: json!({ "requestId": request_id }),
                    tag: BodyTag::Response {
                        request_id: request_id.to_string(),
                        attempt,
                        timestamp,
                        empty_evidence: evidence,
                        charset,
                    },
                });
            }
            "Network.loadingFailed" => {
                let text = params
                    .get("errorText")
                    .and_then(Value::as_str)
                    .unwrap_or("loadingFailed");
                // A proxy failure is the proxy's message, not a generic page error.
                let mut reason = relay::chrome_proxy_failure(text)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("loadingFailed: {text}"));
                if params.get("canceled").and_then(Value::as_bool) == Some(true) {
                    reason.push_str(" (cancelado)");
                }
                if let Some(blocked) = params.get("blockedReason").and_then(Value::as_str) {
                    reason.push_str(&format!(" [blockedReason: {blocked}]"));
                }
                self.resolve_response_unavailable(request_id, timestamp, reason);
            }
            _ => {}
        }
        commands
    }

    #[allow(clippy::too_many_arguments)]
    fn request_body(
        &mut self,
        request_id: &str,
        attempt: u32,
        timestamp: f64,
        request: &Value,
        http_method: &str,
        content_length_zero: bool,
        commands: &mut Vec<BodyCommand>,
    ) {
        let has_post_data = request
            .get("hasPostData")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // `postDataEntries` first: these are the exact bytes. `postData` is a
        // string already converted by Chrome (invalid bytes become U+FFFD).
        let cl_zero = content_length_zero.then_some("Content-Length: 0");
        let mut entries_incomplete = false;
        if let Some(entries) = request.get("postDataEntries").and_then(Value::as_array) {
            let mut bytes = Vec::new();
            let mut complete = !entries.is_empty();
            for entry in entries {
                match entry
                    .get("bytes")
                    .and_then(Value::as_str)
                    .and_then(b64_decode)
                {
                    Some(part) => bytes.extend_from_slice(&part),
                    None => complete = false,
                }
            }
            if complete {
                let row = Self::request_row(
                    request_id,
                    attempt,
                    "requestWillBeSent.postDataEntries",
                    timestamp,
                );
                return match String::from_utf8(bytes) {
                    Ok(text) => self.emit_body(row, &text, false, cl_zero),
                    Err(error) => self.emit_body(row, &b64_encode(error.as_bytes()), true, cl_zero),
                };
            }
            entries_incomplete = true;
        }
        let post_data = request.get("postData").and_then(Value::as_str);
        if has_post_data {
            // Incomplete entries: the event's postData is lossy; tries the
            // bytes via CDP before accepting it (marked).
            if post_data.is_none() || entries_incomplete {
                commands.push(BodyCommand {
                    method: "Network.getRequestPostData",
                    params: json!({ "requestId": request_id }),
                    tag: BodyTag::Request {
                        request_id: request_id.to_string(),
                        attempt,
                        timestamp,
                        fallback_post_data: entries_incomplete
                            .then(|| post_data.map(str::to_string))
                            .flatten(),
                        entries_incomplete,
                    },
                });
                return;
            }
        }
        if let Some(text) = post_data {
            let mut row =
                Self::request_row(request_id, attempt, "requestWillBeSent.postData", timestamp);
            if entries_incomplete {
                row = row.marked(vec!["lossy-postData".to_string()]);
            }
            return self.emit_body(row, text, false, cl_zero);
        }
        if matches!(http_method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
            return;
        }
        let row = Self::request_row(request_id, attempt, "requestWillBeSent.postData", timestamp);
        if content_length_zero {
            self.push(
                row,
                "empty",
                None,
                None,
                (Some(0), 0),
                Some("Content-Length: 0".to_string()),
            );
        } else {
            self.unavailable(
                row,
                "CDP gave no body (no postData, postDataEntries or hasPostData)",
            );
        }
    }

    pub(crate) fn on_result(&mut self, tag: BodyTag, outcome: Result<Value, String>) {
        match tag {
            BodyTag::Request {
                request_id,
                attempt,
                timestamp,
                fallback_post_data,
                entries_incomplete,
            } => {
                let row = Self::request_row(
                    &request_id,
                    attempt,
                    "Network.getRequestPostData",
                    timestamp,
                );
                let fetched = match &outcome {
                    Ok(result) => result.get("postData").and_then(Value::as_str).map(|text| {
                        let b64 = result
                            .get("base64Encoded")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        (text.to_string(), b64)
                    }),
                    Err(_) => None,
                };
                if let Some((text, b64)) = fetched {
                    // Incomplete entries + non-base64 string: there is no evidence
                    // that the string preserves the bytes.
                    let row = if entries_incomplete && !b64 {
                        row.marked(vec!["lossy-postData".to_string()])
                    } else {
                        row
                    };
                    self.emit_body(row, &text, b64, None);
                } else if let Some(text) = fallback_post_data {
                    let row = Self::request_row(
                        &request_id,
                        attempt,
                        "requestWillBeSent.postData",
                        timestamp,
                    )
                    .marked(vec!["lossy-postData".to_string()]);
                    self.emit_body(row, &text, false, None);
                } else {
                    match outcome {
                        Ok(_) => self
                            .unavailable(row, "Network.getRequestPostData did not return postData"),
                        Err(message) => {
                            self.unavailable(row, format!("Network.getRequestPostData: {message}"))
                        }
                    }
                }
            }
            BodyTag::Response {
                request_id,
                attempt,
                timestamp,
                empty_evidence,
                charset,
            } => {
                let row = Self::response_row(&request_id, attempt, timestamp);
                match outcome {
                    Ok(result) => match result.get("body").and_then(Value::as_str) {
                        Some(text) => {
                            let b64 = result
                                .get("base64Encoded")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            // getResponseBody delivers text already decoded by
                            // Chrome; the wire bytes are not recoverable.
                            let row = if b64 {
                                row
                            } else {
                                row.marked(response_transforms(charset.as_deref()))
                            };
                            self.emit_body(row, text, b64, empty_evidence.as_deref());
                        }
                        None => self.unavailable(row, "Network.getResponseBody did not return a body"),
                    },
                    Err(message) => {
                        self.unavailable(row, format!("Network.getResponseBody: {message}"))
                    }
                }
            }
        }
    }

    /// End of capture: responses without `loadingFinished`/`loadingFailed`.
    pub(crate) fn finish(&mut self) {
        let pending: Vec<String> = self
            .requests
            .iter()
            .filter(|(_, state)| state.attempts > 0 && !state.response_resolved)
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            self.resolve_response_unavailable(
                &id,
                0.0,
                "capture ended before loadingFinished/loadingFailed; response not collected"
                    .to_string(),
            );
        }
    }
}

/// charset declared by the response (Content-Type; otherwise `response.charset`).
fn declared_charset(response: &Value) -> Option<String> {
    let from_header = response
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|map| {
            map.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        })
        .and_then(|(_, value)| value.as_str())
        .and_then(|value| {
            value.split(';').skip(1).find_map(|part| {
                let (key, val) = part.split_once('=')?;
                key.trim()
                    .eq_ignore_ascii_case("charset")
                    .then(|| val.trim().trim_matches('"').to_ascii_lowercase())
            })
        });
    from_header
        .or_else(|| {
            response
                .get("charset")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
        })
        .filter(|charset| !charset.is_empty())
}

fn response_transforms(charset: Option<&str>) -> Vec<String> {
    let mut marks = vec!["chrome-decoded".to_string()];
    if let Some(charset) = charset {
        if !matches!(charset, "utf-8" | "utf8") {
            marks.push(format!("charset:{charset}->utf-8"));
        }
    }
    marks
}

fn header_is_zero(headers: Option<&Value>) -> bool {
    headers
        .and_then(Value::as_object)
        .and_then(|map| {
            map.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, value)| value.as_str())
        .is_some_and(|value| value.trim() == "0")
}

#[cfg(test)]
fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_base_dir_prefers_tmpdir_then_a_valid_xdg_runtime_dir_then_tmp() {
        use std::ffi::OsString;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = scratch_dir("xdg");
        let fallback = PathBuf::from("/fallback-tmp");
        let xdg = base.join("run-user");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();
        let os = |p: &Path| Some(OsString::from(p));
        // 1. Without TMPDIR, a valid XDG_RUNTIME_DIR (0700, ours, absolute) is the base.
        assert_eq!(pick_base_dir(None, os(&xdg), fallback.clone()), xdg);
        // 2. A TMPDIR set by the user wins over XDG; an empty one does not count.
        assert_eq!(pick_base_dir(Some("/my/tmp".into()), os(&xdg), fallback.clone()), fallback);
        assert_eq!(pick_base_dir(Some("".into()), os(&xdg), fallback.clone()), xdg);
        // 3. An invalid XDG falls back to /tmp: open mode, link, relative, missing, empty.
        let open = base.join("aberto");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = base.join("link");
        symlink(&xdg, &link).unwrap();
        for bad in [os(&open), os(&link), Some("relative/run".into()), os(&base.join("missing")), None] {
            assert_eq!(pick_base_dir(None, bad.clone(), fallback.clone()), fallback, "{bad:?}");
        }
        // 4. The state root's name carries the uid outside a valid XDG (in a shared /tmp).
        // SAFETY: `geteuid` has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            state_root_in(Path::new("/tmp")),
            PathBuf::from(format!("/tmp/scrapelens-capture-state-{uid}"))
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn the_state_root_is_created_0700_and_a_symlink_in_its_place_is_refused_untouched() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = scratch_dir("stateroot");
        let root = base.join("state");
        ensure_private_state_root(&root).unwrap();
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        // Already exists with a loose mode: the core tightens it to 0700 and the check passes.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_state_root(&root).unwrap();
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        // A link in its place is refused WITHOUT changing the target's mode.
        let target = base.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = base.join("state-link");
        symlink(&target, &link).unwrap();
        assert!(ensure_private_state_root(&link).is_err());
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o755, "the link target was changed");
        let _ = std::fs::remove_dir_all(base);
    }

    fn blink_flags(args: &[String]) -> Vec<&String> {
        args.iter().filter(|a| a.starts_with("--disable-blink-features")).collect()
    }

    /// D7: the automation notice is ALWAYS suppressed, once, in every
    /// mode: network (Open/LoopbackOnly), allowlist, headless, ignore_cert and transport
    /// (pipe and port).
    #[test]
    fn automation_flag_is_always_present_exactly_once_in_every_mode() {
        let flag = format!("--disable-blink-features={AUTOMATION_FEATURE}");
        for network in [NetworkMode::Open, NetworkMode::LoopbackOnly] {
            for rules in [None, Some("MAP * ~NOTFOUND, EXCLUDE a.test")] {
                for headless in [false, true] {
                    for ignore_cert in [false, true] {
                        for pipe in [false, true] {
                            let args = args_for(network, rules, headless, ignore_cert, pipe);
                            let found = blink_flags(&args);
                            assert_eq!(found, vec![&flag], "{network:?} {rules:?} h={headless} c={ignore_cert} p={pipe}: {args:?}");
                            assert_eq!(args.iter().filter(|a| *a == "about:blank").count(), 1);
                            // The other --disable-features flags stay separate.
                            assert_eq!(args.iter().filter(|a| a.starts_with("--disable-features=")).count(), 1);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn merge_blink_features_combines_without_duplicating_the_flag_or_the_values() {
        let base = |extra: &[&str]| {
            let mut v: Vec<String> = vec!["--a".to_string()];
            v.extend(extra.iter().map(|s| s.to_string()));
            v.push("about:blank".to_string());
            v
        };
        // No flag: it is added once, before the URL.
        let mut args = base(&[]);
        merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
        assert_eq!(args, ["--a", "--disable-blink-features=AutomationControlled", "about:blank"]);
        // Already has other features: combines them in the same position, without duplicating the flag.
        let mut args = base(&["--disable-blink-features=Foo,Bar", "--b"]);
        merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
        assert_eq!(args, ["--a", "--disable-blink-features=Foo,Bar,AutomationControlled", "--b", "about:blank"]);
        // Already has the feature (and repeated in two flags): keeps one flag, one value each.
        let mut args = base(&["--disable-blink-features=AutomationControlled,Foo", "--disable-blink-features=Foo,Baz"]);
        merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
        assert_eq!(blink_flags(&args).len(), 1, "{args:?}");
        assert_eq!(args[1], "--disable-blink-features=AutomationControlled,Foo,Baz");
        // Idempotente.
        let before = args.clone();
        merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
        assert_eq!(args, before);
    }

    #[test]
    fn recorded_args_keep_the_automation_flag_and_drop_temp_paths_and_the_url() {
        let args = args_for(NetworkMode::Open, None, false, false, true);
        let recorded = recorded_chrome_args(&args);
        assert!(recorded.contains(&"--disable-blink-features=AutomationControlled".to_string()), "{recorded:?}");
        assert!(recorded.iter().all(|a| !a.contains("/x/profile") && a != "about:blank"), "{recorded:?}");
        assert!(recorded.contains(&"--user-data-dir=<temporary-profile>".to_string()));
        assert!(recorded.contains(&"--log-net-log=<netlog>".to_string()));
    }

    fn args_for(network: NetworkMode, rules: Option<&str>, headless: bool, ignore_cert: bool, pipe: bool) -> Vec<String> {
        let config = CaptureConfig {
            chrome: PathBuf::from("/x/chrome"),
            session_dir: PathBuf::from("/x/session"),
            start_url: String::new(),
            headless,
            ignore_cert,
            network,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        chrome_args(&config, Path::new("/x/profile"), Path::new("/x/profile/netlog.json"), rules, pipe, None)
    }

    #[test]
    fn a_proxied_capture_without_an_allowlist_fails_closed_for_names() {
        assert_eq!(
            fail_closed_rules("socks5://127.0.0.1:40123"),
            "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
        );
        assert_eq!(
            fail_closed_rules("http://proxy.example:3128"),
            "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE proxy.example"
        );
        assert_eq!(
            fail_closed_rules("https://[2001:db8::7]:443"),
            "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE 2001:db8::7"
        );
        let config = CaptureConfig {
            chrome: PathBuf::from("/x/chrome"),
            session_dir: PathBuf::from("/x/session"),
            start_url: String::new(),
            headless: true,
            ignore_cert: false,
            network: NetworkMode::Open,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let direct = chrome_args(&config, Path::new("/x/p"), Path::new("/x/p/n.json"), None, true, Some("http://proxy.example:3128"));
        assert!(direct.contains(&"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE proxy.example".to_string()));
        assert!(!direct.iter().any(|a| a.contains("proxy-bypass-list")), "the default loopback bypass is kept");
        let none = chrome_args(&config, Path::new("/x/p"), Path::new("/x/p/n.json"), None, true, None);
        assert!(!none.iter().any(|a| a.starts_with("--host-resolver-rules")), "no proxy, no rule");
    }

    #[test]
    fn proxy_arguments_never_carry_credentials_and_keep_webrtc_behind_the_proxy() {
        let base = |bypass: bool, proxy: Option<&str>| {
            let config = CaptureConfig {
                chrome: PathBuf::from("/x/chrome"),
                session_dir: PathBuf::from("/x/session"),
                start_url: String::new(),
                headless: true,
                ignore_cert: false,
                network: NetworkMode::Open,
                cookie_source: None,
                initial_cookies: Vec::new(),
                proxy: None,
                test_proxy_bypass_loopback: bypass,
            };
            chrome_args(&config, Path::new("/x/p"), Path::new("/x/p/n.json"), None, true, proxy)
        };
        let with_relay = base(false, Some("socks5://127.0.0.1:40123"));
        // A controlled capture (rules present): loopback goes through the proxy, and the
        // relay's own address is excluded from the rules.
        let controlled = {
            let config = CaptureConfig {
                chrome: PathBuf::from("/x/chrome"),
                session_dir: PathBuf::from("/x/session"),
                start_url: String::new(),
                headless: true,
                ignore_cert: false,
                network: NetworkMode::LoopbackOnly,
                cookie_source: None,
                initial_cookies: Vec::new(),
                proxy: None,
                test_proxy_bypass_loopback: false,
            };
            chrome_args(
                &config,
                Path::new("/x/p"),
                Path::new("/x/p/n.json"),
                Some("MAP * ~NOTFOUND, EXCLUDE site-a.test"),
                true,
                Some("socks5://127.0.0.1:40123"),
            )
        };
        assert!(controlled.contains(&"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE site-a.test, EXCLUDE 127.0.0.1".to_string()));
        assert!(controlled.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(with_relay.contains(&"--proxy-server=socks5://127.0.0.1:40123".to_string()));
        assert!(with_relay.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string()));
        assert!(!with_relay.iter().any(|a| a.contains("proxy-bypass-list")), "production keeps the loopback bypass");
        let with_bypass = base(true, Some("socks5://127.0.0.1:40123"));
        assert!(with_bypass.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        let none = base(true, None);
        assert!(!none.iter().any(|a| a.starts_with("--proxy-server") || a.contains("webrtc")), "no proxy, no change");
        for args in [&with_relay, &with_bypass, &none] {
            for a in args {
                assert!(!a.contains("Pw-") && !a.contains("exp-user"), "{a}");
            }
        }
    }

    fn has(args: &[String], flag: &str) -> bool {
        args.iter().any(|a| a == flag || a.starts_with(&format!("{flag}=")))
    }

    /// The default is open network: the App's capture reaches real sites (before, the App
    /// only captured loopback and `https://google.com.br` gave DNS_PROBE_FINISHED_NXDOMAIN).
    #[test]
    fn network_mode_reads_the_test_hook() {
        // SAFETY: test process only. The variable is removed before return.
        // Serialized with the transport hook test via a distinct mutex; the two
        // variables do not overlap.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("SCRAPELENS_CAPTURE_NETWORK", "loopback") };
        assert_eq!(NetworkMode::from_env(), NetworkMode::LoopbackOnly);
        unsafe { std::env::set_var("SCRAPELENS_CAPTURE_NETWORK", "open") };
        assert_eq!(NetworkMode::from_env(), NetworkMode::Open);
        unsafe { std::env::remove_var("SCRAPELENS_CAPTURE_NETWORK") };
        assert_eq!(NetworkMode::from_env(), NetworkMode::Open);
    }

    #[test]
    fn network_mode_defaults_to_open() {
        assert_eq!(NetworkMode::default(), NetworkMode::Open);
        assert_eq!(NetworkMode::parse(None), NetworkMode::Open);
        assert_eq!(NetworkMode::parse(Some("")), NetworkMode::Open);
        assert_eq!(NetworkMode::parse(Some("open")), NetworkMode::Open);
        assert_eq!(NetworkMode::parse(Some("lixo")), NetworkMode::Open);
        assert_eq!(NetworkMode::parse(Some("loopback")), NetworkMode::LoopbackOnly);
        assert_eq!(NetworkMode::parse(Some(" LOOPBACK ")), NetworkMode::LoopbackOnly);
    }

    #[test]
    fn open_mode_passes_no_dns_rules_and_no_localhost_relaxation() {
        let args = args_for(NetworkMode::Open, None, false, false, true);
        assert!(!has(&args, "--host-resolver-rules"), "{args:?}");
        assert!(!has(&args, "--allow-insecure-localhost"), "{args:?}");
        assert!(!has(&args, "--ignore-certificate-errors"), "{args:?}");
        assert!(!has(&args, "--headless"), "{args:?}");
        // What the capture needs stays: NetLog Everything, QUIC, profile, pipe.
        assert!(has(&args, "--log-net-log") && has(&args, "--net-log-capture-mode"));
        assert!(args.contains(&"--net-log-capture-mode=Everything".to_string()));
        assert!(has(&args, "--enable-quic") && has(&args, "--user-data-dir"));
        assert!(has(&args, "--remote-debugging-pipe"));
        assert_eq!(args.last().map(String::as_str), Some("about:blank"), "{args:?}");
    }

    #[test]
    fn loopback_only_mode_keeps_the_lab_restrictions() {
        let args = args_for(NetworkMode::LoopbackOnly, None, true, false, false);
        assert!(args.contains(&"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost".to_string()), "{args:?}");
        assert!(has(&args, "--allow-insecure-localhost"));
        assert!(has(&args, "--headless"));
        assert!(has(&args, "--remote-debugging-port") && has(&args, "--remote-debugging-address"));
        assert!(!has(&args, "--remote-debugging-pipe"));
    }

    #[test]
    fn the_controlled_capture_allowlist_overrides_the_network_mode() {
        for mode in [NetworkMode::Open, NetworkMode::LoopbackOnly] {
            let args = args_for(mode, Some("MAP * ~NOTFOUND, EXCLUDE a.test"), false, false, true);
            let rules: Vec<&String> = args.iter().filter(|a| a.starts_with("--host-resolver-rules=")).collect();
            assert_eq!(rules.len(), 1, "{mode:?}: {args:?}");
            assert_eq!(rules[0], "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE a.test");
            // No certificate relaxation in the controlled capture.
            assert!(!has(&args, "--allow-insecure-localhost"), "{mode:?}");
            assert!(!has(&args, "--ignore-certificate-errors"), "{mode:?}");
        }
    }

    #[test]
    fn ignore_cert_is_the_only_certificate_relaxation_in_open_mode() {
        let args = args_for(NetworkMode::Open, None, false, true, true);
        assert!(has(&args, "--ignore-certificate-errors"));
        assert!(!has(&args, "--allow-insecure-localhost"));
    }

    const SESSION_DIR_FILES: [&str; 3] = ["cdp-events.jsonl", "netlog.json", "session.json"];
    use super::*;

    fn lines(collector: &mut BodyCollector) -> Vec<Value> {
        collector
            .take_lines()
            .iter()
            .map(|line| serde_json::from_str(line).expect("linha JSON"))
            .collect()
    }

    fn will_be_sent(id: &str, method: &str, extra: Value, redirect: bool) -> Value {
        let mut request = json!({ "url": "http://127.0.0.1/x", "method": method, "headers": {} });
        for (key, value) in extra.as_object().unwrap() {
            request[key] = value.clone();
        }
        let mut params = json!({ "requestId": id, "request": request, "timestamp": 10.5 });
        if redirect {
            params["redirectResponse"] = json!({ "status": 302 });
        }
        params
    }

    fn finish_event(id: &str) -> Value {
        json!({ "requestId": id, "timestamp": 11.0 })
    }

    fn test_cdp() -> Cdp {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "scrapelens-setup-test-{}-{}-{}.jsonl",
            std::process::id(),
            unix_nanos(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let file = open_private(&path).unwrap();
        let cdp = Cdp::new(Arc::new(Mutex::new(CaptureStatus::default())), file).unwrap();
        let _ = std::fs::remove_file(&path);
        cdp
    }

    fn sw_target() -> AttachedTarget {
        AttachedTarget {
            session_id: "S1".into(),
            target_id: "T1".into(),
            target_type: "service_worker".into(),
        }
    }

    fn event_methods(cdp: &Cdp) -> Vec<String> {
        cdp.events
            .iter()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v.get("method").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-fs-{tag}-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn open_private_does_not_follow_a_planted_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = scratch_dir("open");
        let outside = dir.join("OUTSIDE.txt");
        std::fs::write(&outside, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("cdp-bodies.jsonl");
        symlink(&outside, &link).unwrap();
        let mut file = open_private(&link).unwrap();
        file.write_all(b"DATA\n").unwrap();
        drop(file);
        // The link's target was not touched and its mode was not changed.
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "ORIGINAL\n");
        assert_eq!(std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777, 0o644);
        // The name became a regular 0600 file with the data.
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file() && !meta.file_type().is_symlink());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "DATA\n");
        // Bare `create_new` refuses an existing name (including a symlink).
        assert!(open_new_private(&link).is_err());
        let dangling = dir.join("pendurado");
        symlink(dir.join("missing"), &dangling).unwrap();
        assert!(open_new_private(&dangling).is_err(), "O_NOFOLLOW/O_EXCL refuses a symlink");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_is_created_new_0700_and_verified_after_open() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = scratch_dir("privdir");
        // New: 0700 since creation.
        let fresh = base.join("new");
        create_private_dir_new(&fresh).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o700);
        // Name already exists (directory): refused, not reused.
        assert!(create_private_dir_new(&fresh).is_err());
        // Symlink planted under the name (even for a real directory): refused.
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        symlink(&real, &link).unwrap();
        assert!(create_private_dir_new(&link).is_err());
        assert!(verify_private_dir(&link).is_err(), "link in the last component");
        // A mode other than 0700 does not pass the check.
        let loose = base.join("solto");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_private_dir(&loose).is_err());
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o700)).unwrap();
        verify_private_dir(&loose).unwrap();
        // A regular file is not a directory.
        let file = base.join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(verify_private_dir(&file).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn read_private_regular_refuses_symlinks_and_non_files() {
        use std::os::unix::fs::symlink;
        let base = scratch_dir("readreg");
        let target = base.join("target");
        std::fs::write(&target, "segredo").unwrap();
        let link = base.join("netlog.json");
        symlink(&target, &link).unwrap();
        assert_eq!(read_private_regular(&target).as_deref(), Some(&b"segredo"[..]));
        assert_eq!(read_private_regular(&link), None, "does not follow symlinks");
        assert_eq!(read_private_regular(&base), None, "a directory is not a file");
        assert_eq!(read_private_regular(&base.join("ausente")), None);
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_replaces_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = scratch_dir("atomic");
        let outside = dir.join("OUTSIDE.txt");
        std::fs::write(&outside, "ORIGINAL\n").unwrap();
        let dest = dir.join("cdp-events.jsonl");
        symlink(&outside, &dest).unwrap();
        write_private(&dest, b"{\"method\":\"x\"}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "ORIGINAL\n");
        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"method\":\"x\"}\n");
        // No temporary file is left over.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_session_dir_that_is_a_symlink_is_refused_before_anything_runs() {
        let dir = scratch_dir("sessiondir");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("session");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (_stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, _ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from("/nothing/runs/here"),
            session_dir: link,
            start_url: String::new(),
            headless: true,
            ignore_cert: false,
            network: NetworkMode::default(),
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let error = run(config, status, stop_rx, ready_tx).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&real).unwrap().next().is_none(), "nothing may have been written");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn initial_target_gate_requires_acked_network_enable_and_auto_attach() {
        let target = |session: &str| AttachedTarget {
            session_id: session.into(),
            target_id: format!("T-{session}"),
            target_type: "page".into(),
        };
        let mut cdp = test_cdp();
        assert!(cdp.initial_target_gate().unwrap_err().contains("not attached"));
        cdp.page_session_id = "P".into();
        assert!(cdp.initial_target_gate().unwrap_err().contains("not been configured"));
        cdp.configured_sessions.insert("P".into());
        assert!(cdp
            .initial_target_gate()
            .unwrap_err()
            .contains("Network.enable not confirmed"));
        // Commands sent, ACK not yet arrived: gate closed.
        cdp.register_setup_command(1, &target("P"), "Network.enable", None);
        cdp.register_setup_command(2, &target("P"), "Target.setAutoAttach", None);
        assert!(cdp.initial_target_gate().unwrap_err().contains("awaiting a response"));
        cdp.on_setup_response(1, &json!({ "id": 1, "result": {} }));
        assert!(cdp.initial_target_gate().is_err(), "falta o setAutoAttach");
        // A pending command from ANOTHER session does not hold the gate.
        cdp.register_setup_command(3, &target("W"), "Network.enable", None);
        cdp.on_setup_response(2, &json!({ "id": 2, "result": {} }));
        assert_eq!(cdp.initial_target_gate(), Ok(()));
    }

    #[test]
    fn initial_target_gate_stays_closed_when_network_enable_fails() {
        let target = AttachedTarget {
            session_id: "P".into(),
            target_id: "T".into(),
            target_type: "page".into(),
        };
        let mut cdp = test_cdp();
        cdp.page_session_id = "P".into();
        cdp.configured_sessions.insert("P".into());
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.register_setup_command(2, &target, "Target.setAutoAttach", None);
        cdp.on_setup_response(1, &json!({ "id": 1, "error": { "message": "boom" } }));
        cdp.on_setup_response(2, &json!({ "id": 2, "result": {} }));
        let reason = cdp.initial_target_gate().unwrap_err();
        assert!(reason.contains("Network.enable not confirmed"), "{reason}");
    }

    #[test]
    fn late_setup_ack_produces_no_warning() {
        let mut cdp = test_cdp();
        cdp.register_setup_command(7, &sw_target(), "Network.enable", None);
        // ACK arrives later (late), before shutdown.
        assert!(cdp.on_setup_response(7, &json!({ "id": 7, "result": {} })));
        cdp.finalize_pending_setups();
        assert!(event_methods(&cdp).is_empty(), "{:?}", event_methods(&cdp));
        // Unknown id is not a setup one.
        assert!(!cdp.on_setup_response(99, &json!({ "id": 99, "result": {} })));
    }

    #[test]
    fn missing_ack_at_shutdown_warns_even_on_primary_session() {
        let mut cdp = test_cdp();
        let target = sw_target();
        cdp.configured_target_primary
            .insert(target.target_id.clone(), target.session_id.clone());
        cdp.register_setup_command(3, &target, "Target.setAutoAttach", Some("ROOT"));
        cdp.register_setup_command(4, &target, "Network.enable", None);
        assert!(cdp.on_setup_response(4, &json!({ "id": 4, "result": {} })));
        cdp.finalize_pending_setups();
        let lines: Vec<Value> = cdp
            .events
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["method"], "Capture.targetSetupTimeout");
        assert_eq!(lines[0]["params"]["command"], "Target.setAutoAttach");
        assert_eq!(lines[0]["params"]["type"], "service_worker");
        assert!(lines[0]["params"]["pendingMs"].is_u64());
        assert_eq!(lines[0]["parentSessionId"], "ROOT");
        assert!(cdp.setup_pending.is_empty());
    }

    #[test]
    fn target_destroyed_before_ack_is_aborted_not_timeout() {
        let mut cdp = test_cdp();
        let target = sw_target();
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.register_setup_command(2, &target, "Runtime.enable", None);
        cdp.on_target_gone(Some("S1"), None);
        cdp.finalize_pending_setups();
        assert_eq!(event_methods(&cdp), vec!["Capture.targetSetupAborted"]);
        let line: Value = serde_json::from_str(&cdp.events[0]).unwrap();
        assert_eq!(
            line["params"]["reason"],
            "target closed during setup"
        );

        let mut cdp = test_cdp();
        cdp.register_setup_command(1, &target, "Network.enable", None);
        cdp.on_target_gone(None, Some("T1"));
        cdp.finalize_pending_setups();
        assert_eq!(event_methods(&cdp), vec!["Capture.targetSetupAborted"]);
    }

    #[test]
    fn setup_command_error_is_not_reported_as_no_response() {
        let mut cdp = test_cdp();
        let target = sw_target();
        // Page.enable unsupported: ignored. Network.enable with a real error: its own event.
        cdp.register_setup_command(1, &target, "Page.enable", None);
        cdp.register_setup_command(2, &target, "Network.enable", None);
        cdp.register_setup_command(3, &target, "Runtime.enable", None);
        assert!(cdp.on_setup_response(1, &json!({ "id": 1, "error": { "message": "'Page.enable' wasn't found" } })));
        assert!(cdp.on_setup_response(2, &json!({ "id": 2, "error": { "message": "boom" } })));
        // Session vanished: abort, not timeout.
        assert!(cdp.on_setup_response(3, &json!({ "id": 3, "error": { "message": "Session with given id not found." } })));
        cdp.finalize_pending_setups();
        assert_eq!(
            event_methods(&cdp),
            vec!["Capture.targetSetupError", "Capture.targetSetupAborted"]
        );
    }

    // --- orphan cleanup ---------------------------------------------------

    fn orphan_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "scrapelens-orphan-test-{tag}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn app_profile(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{PROFILE_PREFIX}test-{tag}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(dir.join("Default")).unwrap();
        dir
    }

    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(!process_exists(pid));
        pid
    }

    fn write_marker(root: &Path, name: &str, owner: u32, chrome: u32, profile: &Path) -> PathBuf {
        let path = root.join(format!("{MARKER_PREFIX}{name}.json"));
        let body = json!({
            "ownerPid": owner,
            "chromePid": chrome,
            "profile": profile.display().to_string(),
            "port": 9999,
        });
        write_private(&path, body.to_string().as_bytes()).unwrap();
        path
    }

    #[test]
    fn orphan_with_dead_pids_is_cleaned() {
        let root = orphan_root("dead");
        let profile = app_profile("dead");
        let marker = write_marker(&root, "a", dead_pid(), dead_pid(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report.markers_removed, 1);
        assert_eq!(report.processes_killed, 0);
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_pid_with_foreign_command_line_is_not_touched() {
        let root = orphan_root("foreign");
        let profile = app_profile("foreign");
        // Live process whose command line does NOT contain the profile (a "reused" PID).
        let mut other = Command::new("sleep").arg("30").spawn().unwrap();
        let marker = write_marker(&root, "b", dead_pid(), other.id(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report.processes_killed, 0);
        assert!(
            other.try_wait().unwrap().is_none(),
            "foreign process was terminated"
        );
        assert!(process_exists(other.id()));
        // The app's profile and marker are cleaned up anyway.
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = other.kill();
        let _ = other.wait();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_pid_using_the_dedicated_profile_is_terminated() {
        let root = orphan_root("ours");
        let profile = app_profile("ours");
        // Chrome stand-in: its command line carries the dedicated profile.
        let mut fake = Command::new("sh")
            .args(["-c", "sleep 30; true", "fake-chrome"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .spawn()
            .unwrap();
        let marker = write_marker(&root, "c", dead_pid(), fake.id(), &profile);
        let report = cleanup_orphans(&root);
        assert!(report.processes_killed >= 1);
        let exited = (0..30).any(|_| {
            if fake.try_wait().unwrap().is_some() {
                return true;
            }
            thread::sleep(Duration::from_millis(100));
            false
        });
        assert!(exited, "the dedicated-profile Chrome should have been terminated");
        assert!(!profile.exists());
        assert!(!marker.exists());
        let _ = fake.kill();
        let _ = fake.wait();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn marker_of_a_live_owner_is_left_alone() {
        let root = orphan_root("alive");
        let profile = app_profile("alive");
        let marker = write_marker(&root, "d", std::process::id(), dead_pid(), &profile);
        let report = cleanup_orphans(&root);
        assert_eq!(report, OrphanCleanup::default());
        assert!(profile.exists());
        assert!(marker.exists());
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn marker_pointing_outside_app_profiles_never_deletes_the_directory() {
        let root = orphan_root("foreign-dir");
        let victim = orphan_root("victim");
        std::fs::write(victim.join("keep.txt"), b"x").unwrap();
        let marker = write_marker(&root, "e", dead_pid(), dead_pid(), &victim);
        cleanup_orphans(&root);
        assert!(victim.join("keep.txt").exists());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&victim);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_marker_is_private_and_removed_on_drop() {
        let root = orphan_root("marker");
        let profile = app_profile("marker");
        let marker = OrphanMarker::create(&root, 4242, &profile, None);
        marker.set_port(Some(9222));
        let path = marker.path.clone().unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["chromePid"], 4242);
        assert_eq!(value["port"], 9222);
        assert_eq!(value["ownerPid"], std::process::id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        drop(marker);
        assert!(!path.exists());
        assert_eq!(port_from_ws_url("ws://127.0.0.1:41234/devtools/browser/abc"), Some(41234));
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn base64_roundtrip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for len in 0..data.len() {
            let encoded = b64_encode(&data[..len]);
            assert_eq!(b64_decode(&encoded).unwrap(), &data[..len]);
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert!(b64_decode("@@@").is_none());
    }

    #[test]
    fn form_post_body_is_captured_verbatim() {
        let mut c = BodyCollector::default();
        let post = "cmd_consultar_placa=1&placa=TST0T00&x=%C3%A9";
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent(
                "1.1",
                "POST",
                json!({ "postData": post, "hasPostData": true }),
                false,
            ),
        );
        assert!(cmds.is_empty(), "postData present, no command needed");
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["kind"], "request");
        assert_eq!(rows[0]["attemptIndex"], 0);
        assert_eq!(rows[0]["encoding"], "utf8");
        assert_eq!(rows[0]["data"], post);
        assert_eq!(rows[0]["capturedSize"], post.len());
        assert_eq!(rows[0]["source"], "requestWillBeSent.postData");
    }

    #[test]
    fn binary_entries_become_base64_with_same_bytes() {
        let mut c = BodyCollector::default();
        let raw = [0xFFu8, 0xC0, 0x00, 0x80, 0x41];
        let params = will_be_sent(
            "2.1",
            "POST",
            json!({ "hasPostData": true, "postDataEntries": [{ "bytes": b64_encode(&raw[..2]) }, { "bytes": b64_encode(&raw[2..]) }] }),
            false,
        );
        assert!(c.on_event("Network.requestWillBeSent", &params).is_empty());
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "base64");
        assert_eq!(b64_decode(rows[0]["data"].as_str().unwrap()).unwrap(), raw);
        assert_eq!(rows[0]["source"], "requestWillBeSent.postDataEntries");

        // With complete entries, the (lossy) postData is ignored.
        let params = will_be_sent(
            "2.2",
            "POST",
            json!({ "postData": "\u{FFFD}\u{FFFD}", "hasPostData": true, "postDataEntries": [{ "bytes": b64_encode(b"a=\xC3\xA9") }] }),
            false,
        );
        c.on_event("Network.requestWillBeSent", &params);
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "utf8");
        assert_eq!(rows[0]["data"], "a=é");
        assert_eq!(rows[0]["source"], "requestWillBeSent.postDataEntries");
    }

    #[test]
    fn has_post_data_without_data_asks_cdp_and_failures_are_unavailable() {
        let mut c = BodyCollector::default();
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("3.1", "POST", json!({ "hasPostData": true }), false),
        );
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].method, "Network.getRequestPostData");
        assert!(lines(&mut c).is_empty());
        c.on_result(
            cmds[0].tag.clone(),
            Err("No data found for resource with given identifier".into()),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "unavailable");
        assert!(rows[0]["reason"]
            .as_str()
            .unwrap()
            .contains("No data found"));
        assert_eq!(rows[0]["source"], "Network.getRequestPostData");

        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("3.2", "POST", json!({ "hasPostData": true }), false),
        );
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "postData": b64_encode(&[0, 1, 2]), "base64Encoded": true })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["encoding"], "base64");
    }

    #[test]
    fn redirect_marks_previous_response_unavailable_and_keeps_each_request_body() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("4.1", "POST", json!({ "postData": "a=1" }), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("4.1", "POST", json!({ "postData": "a=1" }), true),
        );
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            (rows[0]["kind"].as_str(), rows[0]["attemptIndex"].as_u64()),
            (Some("request"), Some(0))
        );
        assert_eq!(
            (rows[1]["kind"].as_str(), rows[1]["attemptIndex"].as_u64()),
            (Some("response"), Some(0))
        );
        assert_eq!(rows[1]["state"], "unavailable");
        assert_eq!(
            rows[1]["reason"],
            "redirect response: CDP does not provide a body"
        );
        assert_eq!(
            (rows[2]["kind"].as_str(), rows[2]["attemptIndex"].as_u64()),
            (Some("request"), Some(1))
        );
        assert_eq!(rows[2]["data"], "a=1");
        let cmds = c.on_event("Network.loadingFinished", &finish_event("4.1"));
        match &cmds[0].tag {
            BodyTag::Response { attempt, .. } => assert_eq!(*attempt, 1),
            other => panic!("unexpected tag: {other:?}"),
        }
        // A repeated loadingFinished does not generate a second command.
        assert!(c
            .on_event("Network.loadingFinished", &finish_event("4.1"))
            .is_empty());
    }

    #[test]
    fn response_over_limit_is_truncated_with_original_size() {
        let mut c = BodyCollector::default();
        let cmds = {
            c.on_event(
                "Network.requestWillBeSent",
                &will_be_sent("5.1", "GET", json!({}), false),
            );
            c.on_event("Network.loadingFinished", &finish_event("5.1"))
        };
        let body = "é".repeat(MAX_BODY_BYTES / 2 + 10); // 2 bytes per char; the cut falls between characters
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": body, "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "truncated");
        assert_eq!(rows[0]["originalSize"], body.len());
        assert_eq!(rows[0]["capturedSize"], MAX_BODY_BYTES);
        assert_eq!(rows[0]["data"].as_str().unwrap().len(), MAX_BODY_BYTES);
        assert!(body.starts_with(rows[0]["data"].as_str().unwrap()));

        // A cut that would land in the middle of a character backs up to the boundary.
        let odd = format!("a{}", "é".repeat(MAX_BODY_BYTES / 2));
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("5.2", "GET", json!({}), false),
        );
        let cmds = c.on_event("Network.loadingFinished", &finish_event("5.2"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": odd, "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["capturedSize"], MAX_BODY_BYTES - 1);

        // Truncated base64 preserves the 5 MiB of decoded bytes.
        let big = vec![7u8; MAX_BODY_BYTES + 3];
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("5.3", "GET", json!({}), false),
        );
        let cmds = c.on_event("Network.loadingFinished", &finish_event("5.3"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": b64_encode(&big), "base64Encoded": true })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "truncated");
        assert_eq!(rows[0]["originalSize"], big.len());
        assert_eq!(
            b64_decode(rows[0]["data"].as_str().unwrap()).unwrap().len(),
            MAX_BODY_BYTES
        );
    }

    #[test]
    fn session_budget_discards_following_bodies() {
        let mut c = BodyCollector {
            used: SESSION_BODY_BUDGET - 4,
            ..BodyCollector::default()
        };
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("6.1", "POST", json!({ "postData": "abcd" }), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("6.2", "POST", json!({ "postData": "e" }), false),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[1]["state"], "discarded");
        assert_eq!(rows[1]["reason"], "session body budget exceeded");
        assert_eq!(rows[1]["originalSize"], 1);
        assert!(rows[1]["data"].is_null());
    }

    #[test]
    fn failure_streaming_and_websocket_are_unavailable_with_reason() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("7.1", "GET", json!({}), false),
        );
        c.on_event("Network.loadingFailed", &json!({ "requestId": "7.1", "timestamp": 1.0, "errorText": "net::ERR_CONNECTION_REFUSED" }));
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("7.2", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "7.2", "type": "EventSource", "response": { "status": 200, "mimeType": "text/event-stream" } }));
        c.on_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "7.3", "url": "ws://127.0.0.1/" }),
        );
        // A loadingFinished after resolution does not generate a command.
        assert!(c
            .on_event("Network.loadingFinished", &finish_event("7.2"))
            .is_empty());
        let rows = lines(&mut c);
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row["state"] == "unavailable" && row["kind"] == "response"));
        assert!(rows[0]["reason"]
            .as_str()
            .unwrap()
            .contains("ERR_CONNECTION_REFUSED"));
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("7.4", "GET", json!({}), false),
        );
        c.on_event("Network.loadingFailed", &json!({ "requestId": "7.4", "timestamp": 1.0, "errorText": "net::ERR_PROXY_CONNECTION_FAILED" }));
        let proxy_rows = lines(&mut c);
        let proxy_reason = proxy_rows.last().unwrap()["reason"].as_str().unwrap();
        assert!(proxy_reason.contains("could not be reached"), "{proxy_reason}");
        assert!(!proxy_reason.contains("loadingFailed"), "{proxy_reason}");
        assert!(rows[1]["reason"].as_str().unwrap().contains("SSE"));
        assert!(rows[2]["reason"].as_str().unwrap().contains("WebSocket"));
    }

    #[test]
    fn empty_requires_evidence() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.1", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.1", "type": "XHR", "response": { "status": 204, "mimeType": "" } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.1"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.2", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.2", "type": "XHR", "response": { "status": 200, "mimeType": "text/plain" } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.2"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("8.3", "GET", json!({}), false),
        );
        c.on_event("Network.responseReceived", &json!({ "requestId": "8.3", "type": "XHR", "response": { "status": 200, "headers": { "Content-Length": "0" } } }));
        let cmds = c.on_event("Network.loadingFinished", &finish_event("8.3"));
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({ "body": "", "base64Encoded": false })),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "empty");
        assert_eq!(rows[1]["state"], "unavailable");
        assert_eq!(rows[2]["state"], "empty");
        assert_eq!(rows[2]["reason"], "Content-Length: 0");
    }

    #[test]
    fn finish_covers_requests_without_loading_finished() {
        let mut c = BodyCollector::default();
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("9.1", "GET", json!({}), false),
        );
        c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("9.2", "POST", json!({}), false),
        );
        c.finish();
        let rows = lines(&mut c);
        // 9.2 also gains the request row with no body reported.
        assert_eq!(
            rows.iter().filter(|row| row["kind"] == "response").count(),
            2
        );
        assert!(rows.iter().all(|row| row["state"] == "unavailable"));
        c.finish();
        assert!(lines(&mut c).is_empty(), "finish is idempotent");
    }

    #[test]
    fn response_text_is_marked_transformed_and_charset_is_named() {
        let mut c = BodyCollector::default();
        for (id, headers, body_b64) in [
            ("t.1", json!({}), false),
            (
                "t.2",
                json!({"Content-Type": "text/html; charset=ISO-8859-1"}),
                false,
            ),
            (
                "t.3",
                json!({"content-type": "text/plain; charset=\"utf-8\""}),
                false,
            ),
            (
                "t.4",
                json!({"Content-Type": "application/octet-stream"}),
                true,
            ),
        ] {
            c.on_event(
                "Network.requestWillBeSent",
                &will_be_sent(id, "GET", json!({}), false),
            );
            c.on_event(
                "Network.responseReceived",
                &json!({"requestId": id, "type": "Fetch", "response": {"status": 200, "headers": headers}}),
            );
            let cmds = c.on_event("Network.loadingFinished", &finish_event(id));
            let body = if body_b64 {
                b64_encode(&[0xFF, 1])
            } else {
                "São".to_string()
            };
            c.on_result(
                cmds[0].tag.clone(),
                Ok(json!({"body": body, "base64Encoded": body_b64})),
            );
        }
        let rows = lines(&mut c);
        assert_eq!(rows[0]["transformed"], json!(["chrome-decoded"]));
        assert_eq!(
            rows[1]["transformed"],
            json!(["chrome-decoded", "charset:iso-8859-1->utf-8"])
        );
        assert_eq!(rows[2]["transformed"], json!(["chrome-decoded"]));
        assert!(rows[3].get("transformed").is_none());
    }

    #[test]
    fn incomplete_entries_try_cdp_then_mark_lossy_fallback() {
        let incomplete = json!({
            "hasPostData": true,
            "postData": "a=\u{FFFD}",
            "postDataEntries": [{"type": "blob"}]
        });
        let mut c = BodyCollector::default();
        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("l.1", "POST", incomplete.clone(), false),
        );
        assert_eq!(cmds.len(), 1);
        assert!(lines(&mut c).is_empty());
        c.on_result(cmds[0].tag.clone(), Err("boom".into()));
        let rows = lines(&mut c);
        assert_eq!(rows[0]["state"], "captured");
        assert_eq!(rows[0]["transformed"], json!(["lossy-postData"]));
        assert_eq!(rows[0]["source"], "requestWillBeSent.postData");

        let cmds = c.on_event(
            "Network.requestWillBeSent",
            &will_be_sent("l.2", "POST", incomplete.clone(), false),
        );
        c.on_result(
            cmds[0].tag.clone(),
            Ok(json!({"postData": b64_encode(&[0xFF, 0]), "base64Encoded": true})),
        );
        let rows = lines(&mut c);
        assert_eq!(rows[0]["encoding"], "base64");
        assert!(rows[0].get("transformed").is_none());

        // Without hasPostData, the lossy postData is written marked, with no command.
        let no_flag = json!({"postData": "x", "postDataEntries": [{"type": "blob"}]});
        assert!(c
            .on_event(
                "Network.requestWillBeSent",
                &will_be_sent("l.3", "POST", no_flag, false)
            )
            .is_empty());
        assert_eq!(lines(&mut c)[0]["transformed"], json!(["lossy-postData"]));
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../experiments/results/h1-page")
            .join(name);
        std::fs::read(path).expect("fixture from experiments/results/h1-page")
    }

    fn quiet_shutdown(exit: ChromeExit) -> ShutdownReport {
        ShutdownReport {
            browser_close: Ok(()),
            exit,
            waited_ms: 1,
            transport_closed: None,
        }
    }

    #[test]
    fn a3_b2_closed_transport_marks_the_session_incomplete_with_an_explicit_reason() {
        let cdp = fixture("cdp-events.jsonl");
        let (netlog, status) = prepare_netlog(Some(&fixture("chrome-netlog.json")));
        assert_eq!(status, NetlogStatus::Complete);
        let mut imported = scrapelens_core::import_capture_with_bodies(
            &cdp,
            &netlog,
            None,
            CorrelationOptions::default(),
        )
        .unwrap();
        let mut shutdown = quiet_shutdown(ChromeExit::Graceful(Some(0)));
        shutdown.transport_closed = Some("frame_too_large".to_string());
        mark_incomplete(&mut imported.bundle.session, &status, &shutdown);
        let session = &imported.bundle.session;
        // Even with a complete NetLog and a graceful Chrome, the reason comes out explicitly.
        assert!(session
            .session
            .completeness
            .reasons
            .iter()
            .any(|r| r.contains("cdp_transport_closed: frame_too_large")), "{:?}", session.session.completeness);
        assert!(session.warnings.iter().any(|w| w.code == "capture.cdp_transport_closed"));
        // Combines with the other reasons, without replacing them.
        let mut both = quiet_shutdown(ChromeExit::Killed);
        both.transport_closed = Some("frame_too_large".to_string());
        mark_incomplete(&mut imported.bundle.session, &status, &both);
        let codes: Vec<&str> = imported.bundle.session.warnings.iter().map(|w| w.code.as_str()).collect();
        assert!(codes.contains(&"capture.chrome_killed"), "{codes:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a4_b5_swapped_session_dir_is_detected_and_nothing_is_written_or_removed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = scratch_dir("a4b5");
        let session_dir = base.join("capture-X");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = verify_private_dir(&session_dir).unwrap();
        recheck_session_dir(&session_dir, identity).expect("intact passes");

        // 1. Swapped for a symlink to OUT, full of links (the Reviewer's PoC).
        let out = base.join("OUT");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = base.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        for name in SESSION_DIR_FILES {
            symlink(&victim, out.join(name)).unwrap();
        }
        let handle = std::fs::File::open(&session_dir).unwrap();
        let moved = base.join("capture-X.orig");
        std::fs::rename(&session_dir, &moved).unwrap();
        symlink(&out, &session_dir).unwrap();
        let err = recheck_session_dir(&session_dir, identity).unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        let cdp = fixture("cdp-events.jsonl");
        let (netlog, _s) = prepare_netlog(Some(&fixture("chrome-netlog.json")));
        let mut imported = import_capture_labeled(
            &cdp,
            &netlog,
            None,
            &["live-capture".to_string()],
            CorrelationOptions::default(),
        )
        .unwrap();
        // A6-B5: the write is relative to the descriptor: ALL of it goes to the original directory
        // (moved), and nothing lands in OUT, even though the name was already swapped.
        write_session_fd(&mut imported.bundle, &handle, &base).expect("writes through the descriptor");
        assert!(moved.join("session.json").is_file(), "the session stayed in the original directory");
        assert!(moved.join("cdp-events.jsonl").is_file());
        // Nothing was written to OUT, and OUT's links were NOT removed.
        for name in SESSION_DIR_FILES {
            let meta = std::fs::symlink_metadata(out.join(name)).unwrap();
            assert!(meta.file_type().is_symlink(), "{name} in OUT was touched");
        }
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 3);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");

        // 2. Swapped for ANOTHER real directory (0700, ours): the identity differs.
        std::fs::remove_file(&session_dir).unwrap();
        std::fs::create_dir(&session_dir).unwrap();
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(recheck_session_dir(&session_dir, identity).unwrap_err().contains("different directory"));
        // 3. Modo afrouxado.
        std::fs::remove_dir(&session_dir).unwrap();
        std::fs::rename(&moved, &session_dir).unwrap();
        recheck_session_dir(&session_dir, identity).expect("the original, swapped back, passes");
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(recheck_session_dir(&session_dir, identity).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn a7_message_after_a_swap_during_the_write_names_the_moved_dir_and_does_not_contradict_itself() {
        use std::os::unix::fs::symlink;
        let base = scratch_dir("a7msg");
        let dir = base.join("capture-X");
        std::fs::create_dir_all(&dir).unwrap();
        let handle = std::fs::File::open(&dir).unwrap();
        let moved = base.join("capture-X.moved");
        std::fs::rename(&dir, &moved).unwrap();
        symlink(base.join("OUT"), &dir).unwrap();
        let message = session_dir_changed_after_write("now a symbolic link".to_string(), &handle);
        let canonical = std::fs::canonicalize(&moved).unwrap();
        assert!(message.contains(&canonical.display().to_string()), "without the moved path: {message}");
        assert!(message.contains("written in full to the ORIGINAL directory"), "{message}");
        // Does not assert the opposite ("nothing was written to it").
        assert!(!message.contains("nothing was written to it"), "{message}");
        // The message from BEFORE the write still says that nothing was written to it.
        assert!(session_dir_changed("x".to_string()).contains("nothing was written to it"));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a5_b3_rescue_keeps_only_the_capture_files_in_a_private_dir_with_a_marker() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("rescue");
        let root = base.join("state");
        let mut bodies = open_private(&base.join("cdp-bodies.jsonl")).unwrap();
        bodies.write_all(b"{\"body\":1}\n").unwrap();
        let dir = rescue_capture_files(&root, b"{\"a\":1}\n", Some(b"{\"constants\":{}}"), &mut bodies, "test reason")
            .unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        // Only the capture files (+ the reason): nothing from the Chrome profile.
        assert_eq!(names, ["cdp-bodies.jsonl", "cdp-events.jsonl", "motivo.txt", "netlog.json"]);
        assert_eq!(std::fs::read(dir.join("cdp-bodies.jsonl")).unwrap(), b"{\"body\":1}\n");
        // Marker in the state root.
        let marker = root.join(format!("{}.json", dir.file_name().unwrap().to_string_lossy()));
        let value: Value = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        assert_eq!(value["kind"], "rescue");
        let _ = std::fs::remove_dir_all(base);
    }

    /// Sets the directory's modification date `days` days into the past.
    fn age_dir(dir: &Path, days: u64) {
        let old = SystemTime::now() - Duration::from_secs(days * 24 * 3600 + 60);
        std::fs::File::open(dir).unwrap().set_modified(old).unwrap();
    }

    #[test]
    fn a5_b3_cleanup_removes_only_expired_rescues_that_the_marker_really_names() {
        let base = scratch_dir("rescue-ttl");
        let root = base.join("state");
        std::fs::create_dir_all(&root).unwrap();
        let mut bodies = open_private(&base.join("b.jsonl")).unwrap();
        let recent = rescue_capture_files(&root, b"x\n", None, &mut bodies, "recent").unwrap();
        // One expired by the DIRECTORY'S AGE (8 days), a tampered marker
        // pointing outside, and a folder that is not a rescue one.
        let old = rescue_capture_files(&root, b"y\n", None, &mut bodies, "expired").unwrap();
        age_dir(&old, 8);
        let outside = base.join("OUTSIDE");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("x"), "x").unwrap();
        age_dir(&outside, 30);
        std::fs::write(
            root.join(format!("{RESCUE_PREFIX}evil.json")),
            json!({"kind":"rescue","ownerPid":1,"dir":"../OUTSIDE"}).to_string(),
        )
        .unwrap();
        let report = cleanup_orphans(&root);
        assert_eq!(report.rescues_removed, 1, "{report:?}");
        assert!(!old.exists(), "the expired one should be gone");
        assert!(recent.exists(), "the recent one stays");
        assert!(outside.join("x").exists(), "tampered marker does not delete outside");
        let _ = std::fs::remove_dir_all(base);
    }

    /// A6-B7: the age comes from the directory, not from the marker. A forged marker
    /// with an old `createdMs` (or with the name of ANOTHER folder) does not delete a rescue
    /// recent.
    #[test]
    fn a6_b7_forged_marker_cannot_delete_a_recent_rescue() {
        let base = scratch_dir("rescue-forged");
        let root = base.join("state");
        std::fs::create_dir_all(&root).unwrap();
        let mut bodies = open_private(&base.join("b.jsonl")).unwrap();
        let recent = rescue_capture_files(&root, b"x\n", None, &mut bodies, "recent").unwrap();
        let recent_name = recent.file_name().unwrap().to_string_lossy().to_string();
        // 1. The Reviewer's PoC: a file with another name, the recent rescue's `dir` and
        //    `createdMs: 0`.
        std::fs::write(
            root.join(format!("{RESCUE_PREFIX}evil.json")),
            json!({"kind":"rescue","ownerPid":1,"dir":recent_name,"createdMs":0}).to_string(),
        )
        .unwrap();
        // 2. Overwrites the true marker with `createdMs: 0`.
        std::fs::write(
            root.join(format!("{recent_name}.json")),
            json!({"kind":"rescue","ownerPid":1,"dir":recent_name,"createdMs":0}).to_string(),
        )
        .unwrap();
        let report = cleanup_orphans(&root);
        assert_eq!(report.rescues_removed, 0, "{report:?}");
        assert!(recent.join("cdp-events.jsonl").is_file(), "the recent rescue was deleted");
        // When the directory really ages, the true marker deletes it.
        age_dir(&recent, 8);
        assert_eq!(cleanup_orphans(&root).rescues_removed, 1);
        assert!(!recent.exists());
        let _ = std::fs::remove_dir_all(base);
    }

    /// A6-B6: if the normal rescue fails, the profile becomes the rescue: without Cookies,
    /// with the CDP events, the marker and the same deadline.
    #[test]
    fn a6_b6_fallback_adopts_the_profile_with_events_and_a_ttl_marker() {
        let base = scratch_dir("rescue-fallback");
        let root = base.join("state");
        let profile = base.join("scrapelens-chrome-1-2");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        for f in ["Default/Cookies", "Default/History", "Local State", "netlog.json"] {
            std::fs::write(profile.join(f), "chrome data").unwrap();
        }
        let mut bodies = open_private(&base.join("b.jsonl")).unwrap();
        bodies.write_all(b"{\"body\":1}\n").unwrap();
        let mut guard = ProfileCleanup { path: profile.clone(), keep: false };
        FORCE_PRIMARY_RESCUE_FAILURE.with(|f| f.set(true));
        let message = rescue_or_adopt("failed", &root, &profile, &mut guard, b"{\"ev\":1}\n", Some(b"{\"constants\":{}}"), &mut bodies);
        FORCE_PRIMARY_RESCUE_FAILURE.with(|f| f.set(false));
        assert!(message.contains("normal rescue failed") && message.contains("7 days"), "{message}");
        drop(guard); // keep() was called: does not delete
        assert!(!profile.exists(), "the profile was moved to the state root");
        let dirs: Vec<PathBuf> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_dir())
            .collect();
        assert_eq!(dirs.len(), 1, "{dirs:?}");
        let rescue = &dirs[0];
        let mut names: Vec<String> = std::fs::read_dir(rescue)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        // Only the capture files: no Cookies/History/Local State/Default.
        assert_eq!(names, ["cdp-bodies.jsonl", "cdp-events.jsonl", "motivo.txt", "netlog.json"]);
        assert_eq!(std::fs::read(rescue.join("cdp-events.jsonl")).unwrap(), b"{\"ev\":1}\n");
        // With a marker: expires on the same deadline.
        let name = rescue.file_name().unwrap().to_string_lossy().to_string();
        assert!(root.join(format!("{name}.json")).is_file());
        age_dir(rescue, 8);
        assert_eq!(cleanup_orphans(&root).rescues_removed, 1);
        assert!(!rescue.exists());
        let _ = std::fs::remove_dir_all(base);
    }

    /// A6-B6, last rung: without a way to move/mark it (unusable state root) the
    /// profile stays in place, already cleaned and with the events, and the message says there is no
    /// automatic deadline.
    #[test]
    fn a6_b6_fallback_keeps_events_in_place_when_it_cannot_be_moved() {
        let base = scratch_dir("rescue-fallback2");
        let root = base.join("state-file");
        std::fs::write(&root, "I am a file, not a directory").unwrap();
        let profile = base.join("scrapelens-chrome-3-4");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        std::fs::write(profile.join("Default/Cookies"), "x").unwrap();
        let mut bodies = open_private(&base.join("b.jsonl")).unwrap();
        let mut guard = ProfileCleanup { path: profile.clone(), keep: false };
        let message = rescue_or_adopt("failed", &root, &profile, &mut guard, b"{\"ev\":1}\n", None, &mut bodies);
        assert!(message.contains("WITHOUT an automatic deadline"), "{message}");
        drop(guard);
        assert!(profile.join("cdp-events.jsonl").is_file(), "the events stay in the kept profile");
        assert!(!profile.join("Default").exists(), "Chrome data removed");
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn a5_b2_remove_stale_tmp_cleans_the_original_dir_even_after_it_was_moved() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("staletmp");
        let dir = base.join("session");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (handle, _id) = verify_private_dir_handle(&dir).unwrap();
        for name in [".session.json.tmp-1-2-0", ".cdp-events.jsonl.tmp-9-9-3", "session.json", ".other.tmp-1", "notes.txt"] {
            std::fs::write(dir.join(name), "x").unwrap();
        }
        // The folder is moved elsewhere (and the name becomes something else): the descriptor
        // keeps pointing to the original.
        let moved = base.join("session.moved");
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(".session.json.tmp-7-7-7"), "from the new one, not ours").unwrap();
        remove_stale_tmp(&handle);
        let list = |p: &Path| {
            let mut v: Vec<String> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(list(&moved), [".other.tmp-1", "notes.txt", "session.json"]);
        assert_eq!(list(&dir), [".session.json.tmp-7-7-7"], "the new directory is not touched");
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn a5_b4_empty_cdp_file_is_not_created_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let base = scratch_dir("a5b4");
        let victim = base.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        let link = base.join("cdp-events.jsonl");
        symlink(&victim, &link).unwrap();
        write_private(&link, b"").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n", "target truncated");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_file());
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn a3_b3_planted_symlinks_after_the_copy_do_not_fail_the_stop() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = scratch_dir("a3b3");
        let victim = dir.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let session_dir = dir.join("session");
        std::fs::create_dir_all(&session_dir).unwrap();
        // The PoC planted netlog.json; the core would also refuse the other two.
        for name in SESSION_DIR_FILES {
            symlink(&victim, session_dir.join(name)).unwrap();
        }
        let cdp = fixture("cdp-events.jsonl");
        let (netlog, _status) = prepare_netlog(Some(&fixture("chrome-netlog.json")));
        let mut imported = import_capture_labeled(
            &cdp,
            &netlog,
            None,
            &["live-capture".to_string()],
            CorrelationOptions::default(),
        )
        .unwrap();
        // Without the fix, the core refuses ("is a symbolic link; refused").
        assert!(store::write_session_dir(&imported.bundle, &session_dir).is_err());
        for name in SESSION_DIR_FILES {
            let _ = std::fs::remove_file(session_dir.join(name));
            symlink(&victim, session_dir.join(name)).unwrap();
        }
        // A4-B3: `attachments` can also be a link to a directory outside.
        let outside_dir = dir.join("DIR-OUTSIDE");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("intact.txt"), "ORIGINAL\n").unwrap();
        let _ = std::fs::remove_dir_all(session_dir.join("attachments"));
        symlink(&outside_dir, session_dir.join("attachments")).unwrap();
        assert!(store::write_session_dir(&imported.bundle, &session_dir).is_err(), "the core refuses an attachments link");
        for name in SESSION_DIR_FILES {
            let _ = std::fs::remove_file(session_dir.join(name));
            symlink(&victim, session_dir.join(name)).unwrap();
        }
        let _ = std::fs::remove_file(session_dir.join("attachments"));
        symlink(&outside_dir, session_dir.join("attachments")).unwrap();
        let handle = std::fs::File::open(&session_dir).unwrap();
        let removed = write_session_fd(&mut imported.bundle, &handle, &dir)
            .expect("stop must not fail because of a planted symlink");
        assert_eq!(removed.len(), 4, "{removed:?}");
        assert!(removed.contains(&"attachments".to_string()));
        assert_eq!(std::fs::read_dir(&outside_dir).unwrap().count(), 1, "outside directory was touched");
        assert_eq!(std::fs::read_to_string(outside_dir.join("intact.txt")).unwrap(), "ORIGINAL\n");
        let att = std::fs::symlink_metadata(session_dir.join("attachments")).unwrap();
        assert!(att.file_type().is_dir(), "attachments should be a real directory");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n", "target touched");
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        for name in SESSION_DIR_FILES {
            let meta = std::fs::symlink_metadata(session_dir.join(name)).unwrap();
            assert!(meta.file_type().is_file(), "{name} should be a regular file");
        }
        assert!(imported
            .bundle
            .session
            .warnings
            .iter()
            .any(|w| w.code == "capture.planted_symlink_removed"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn truncated_netlog_is_repaired_and_still_imports() {
        let full = fixture("chrome-netlog.json");
        let cdp = fixture("cdp-events.jsonl");
        assert_eq!(prepare_netlog(Some(&full)).1, NetlogStatus::Complete);
        let full_events = serde_json::from_slice::<Value>(&full).unwrap()["events"]
            .as_array()
            .unwrap()
            .len();
        // Cuts at varied points: a line break with a comma and mid-line.
        for fraction in [0.3_f64, 0.55, 0.8] {
            let mut cut = (full.len() as f64 * fraction) as usize;
            for variant in 0..2 {
                if variant == 1 {
                    cut += 7;
                }
                let (fixed, status) = prepare_netlog(Some(&full[..cut]));
                assert!(
                    matches!(status, NetlogStatus::Repaired { .. }),
                    "{fraction}/{variant}: {status:?}"
                );
                let events = serde_json::from_slice::<Value>(&fixed).unwrap()["events"]
                    .as_array()
                    .unwrap()
                    .len();
                assert!(events > 0 && events < full_events);
                let imported = scrapelens_core::import_capture_with_bodies(
                    &cdp,
                    &fixed,
                    None,
                    CorrelationOptions::default(),
                );
                assert!(
                    imported.is_ok(),
                    "import of the repaired NetLog: {:?}",
                    imported.err()
                );
            }
        }
    }

    #[test]
    fn unusable_netlog_falls_back_to_cdp_only_import() {
        let cdp = fixture("cdp-events.jsonl");
        for raw in [None, Some(&b"{\"constants\":{\"a\":"[..])] {
            let (netlog, status) = prepare_netlog(raw);
            assert!(matches!(status, NetlogStatus::Unusable { .. }));
            let mut imported = scrapelens_core::import_capture_with_bodies(
                &cdp,
                &netlog,
                None,
                CorrelationOptions::default(),
            )
            .expect("CDP without NetLog still imports");
            mark_incomplete(
                &mut imported.bundle.session,
                &status,
                &quiet_shutdown(ChromeExit::Graceful(Some(0))),
            );
            let session = &imported.bundle.session;
            assert!(session
                .warnings
                .iter()
                .any(|w| w.code == "capture.netlog_unusable"));
            assert!(session
                .session
                .completeness
                .reasons
                .iter()
                .any(|r| r.contains("capture.netlog_unusable")));
            assert!(!session.requests.is_empty());
        }
    }

    #[test]
    fn killed_chrome_adds_a_warning_even_with_valid_netlog() {
        let cdp = fixture("cdp-events.jsonl");
        let full = fixture("chrome-netlog.json");
        let mut imported = scrapelens_core::import_capture_with_bodies(
            &cdp,
            &full,
            None,
            CorrelationOptions::default(),
        )
        .unwrap();
        let before = imported.bundle.session.warnings.len();
        mark_incomplete(
            &mut imported.bundle.session,
            &NetlogStatus::Complete,
            &quiet_shutdown(ChromeExit::Graceful(Some(0))),
        );
        assert_eq!(imported.bundle.session.warnings.len(), before);
        mark_incomplete(
            &mut imported.bundle.session,
            &NetlogStatus::Complete,
            &quiet_shutdown(ChromeExit::Killed),
        );
        assert!(imported
            .bundle
            .session
            .warnings
            .iter()
            .any(|w| w.code == "capture.chrome_killed"));
    }

    #[cfg(unix)]
    #[test]
    fn bodies_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "scrapelens-bodies-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        let file = open_private(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
