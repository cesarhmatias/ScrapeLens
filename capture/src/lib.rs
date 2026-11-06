//! Live capture: external Chrome with a dedicated profile + CDP + NetLog.
//!
//! Regras:
//! - its own temporary profile (never the personal profile), removed at the end;
//! - our client talks to Chrome over a **pipe** (`--remote-debugging-pipe`,
//!   no open port) by default; only with `expose_cdp` (external agent) does
//!   Chrome open the debugging port, **only on 127.0.0.1**, on an ephemeral port
//!   (see `docs/16b-mcp-browser.md` §2.5 for the risk);
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
pub mod chrome;
pub mod cookies;
mod fdio;
pub mod proxy;
pub mod relay;
pub mod transport;

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
    /// `SCRAPELENS_CAPTURE_NETWORK=loopback` turns on loopback-only mode (test suites
    /// that must not touch the network); any other value, or the variable
    /// unset, means open network.
    pub fn from_env() -> NetworkMode {
        Self::parse(std::env::var("SCRAPELENS_CAPTURE_NETWORK").ok().as_deref())
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
            Some(relay::ProxyPlan::prepare(link.clone(), allow).map_err(|e| e.to_string())?)
        }
        None => None,
    };
    let proxy_arg = proxy_plan.as_ref().map(relay::ProxyPlan::chrome_arg);
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
    let mut chrome = ChromeProcess::new(spawn_chrome(config, &launch_args, pipe_ends.as_ref())?);
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
    let proxy_suffix = match proxy_plan.as_ref().map(relay::ProxyPlan::failures) {
        Some(failures) if !failures.is_empty() => {
            format!("; proxy: {}", failures.join("; "))
        }
        _ => String::new(),
    };
    Ok((
        CaptureOutcome {
            session: session_value,
            session_dir: config.session_dir.clone(),
            notice: format!(
                "Session captured and imported: {} CDP+NetLog event(s) used, {} warning(s).{}{}",
                requests, warnings, cookie_suffix, proxy_suffix
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
fn merge_blink_features(args: &mut Vec<String>, features: &[&str]) {
    const PREFIX: &str = "--disable-blink-features=";
    let mut merged: Vec<String> = Vec::new();
    let mut first_index: Option<usize> = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(values) = args[index].strip_prefix(PREFIX) {
            for value in values.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                if !merged.iter().any(|m| m == value) {
                    merged.push(value.to_string());
                }
            }
            if first_index.is_none() {
                first_index = Some(index);
                index += 1;
            } else {
                args.remove(index);
            }
        } else {
            index += 1;
        }
    }
    for feature in features {
        if !merged.iter().any(|m| m == feature) {
            merged.push((*feature).to_string());
        }
    }
    let flag = format!("{PREFIX}{}", merged.join(","));
    match first_index {
        Some(at) => args[at] = flag,
        None => args.insert(args.len().saturating_sub(1), flag),
    }
}

/// Arguments recorded in `session.json` (`capture.chromeArgs`): the same as the
/// launch ones, without the temporary paths (profile and NetLog) and without the
/// initial URL. Whoever reads the session (the `site_profile`) knows the context in which it was
/// captured, including that the automation notice was suppressed.
fn recorded_chrome_args(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|a| *a != "about:blank")
        .map(|a| {
            if a.starts_with("--user-data-dir=") {
                "--user-data-dir=<temporary-profile>".to_string()
            } else if a.starts_with("--log-net-log=") {
                "--log-net-log=<netlog>".to_string()
            } else {
                a.clone()
            }
        })
        .collect()
}

/// Command-line arguments for the capture's Chrome, without running anything
/// (testable). `resolver_rules` is the allowlist of the CONTROLLED capture; when
/// it exists, it applies in place of the network mode, and no certificate relaxation is
/// added.
fn chrome_args(
    config: &CaptureConfig,
    profile: &Path,
    netlog: &Path,
    resolver_rules: Option<&str>,
    use_pipe: bool,
    proxy_arg: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--log-net-log={}", netlog.display()),
        "--net-log-capture-mode=Everything".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-sync".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-extensions".to_string(),
        "--metrics-recording-only".to_string(),
        "--no-service-autorun".to_string(),
        "--no-pings".to_string(),
        "--disable-breakpad".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-component-extensions-with-background-pages".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
        "--disable-search-engine-choice-screen".to_string(),
        "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions"
            .to_string(),
        "--enable-quic".to_string(),
        "--disable-popup-blocking".to_string(),
        "about:blank".to_string(),
    ];
    // D7: the automation notice is ALWAYS suppressed (`navigator.webdriver` goes back to
    // `false` even with CDP), in every mode and transport.
    merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
    if use_pipe {
        // No port at all: Chrome reads commands on fd 3 and writes them on fd 4.
        args.insert(args.len() - 1, "--remote-debugging-pipe".to_string());
    } else {
        // Ephemeral port ONLY on 127.0.0.1. Without `--remote-allow-origins`, CDP clients
        // (us, Playwright, DevTools MCP) do not send an Origin; a web page
        // that tries the WebSocket (Origin present) is refused by Chrome.
        args.insert(args.len() - 1, "--remote-debugging-port=0".to_string());
        args.insert(args.len() - 1, "--remote-debugging-address=127.0.0.1".to_string());
    }
    match (resolver_rules, config.network) {
        // Controlled capture: only the allowlist hosts resolve; no
        // certificate relaxation. Through a proxy, Chrome must still reach the local relay
        // (its address is a literal the rules would deny), so the loopback address is
        // excluded; loopback TARGETS then go through the proxy too (see below), where the
        // relay refuses anything the allowlist does not permit.
        (Some(rules), _) => {
            let rules = match proxy_arg {
                Some(_) => format!("{rules}, EXCLUDE 127.0.0.1"),
                None => rules.to_string(),
            };
            args.insert(args.len() - 1, format!("--host-resolver-rules={rules}"));
        }
        // Common App capture: normal network. No DNS rules.
        (None, NetworkMode::Open) => {}
        // Tests only: nothing beyond loopback resolves.
        (None, NetworkMode::LoopbackOnly) => {
            args.insert(args.len() - 1, "--allow-insecure-localhost".to_string());
            args.insert(
                args.len() - 1,
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
                    .to_string(),
            );
        }
    }
    if let Some(server) = proxy_arg {
        // The value never carries credentials: the relay's address, or the link without
        // them (direct route). WebRTC must not open UDP outside the proxy.
        args.push(format!("--proxy-server={server}"));
        args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string());
        // A controlled capture sends loopback targets through the proxy as well, so the
        // allowlist covers them; the App's common capture keeps Chrome's default bypass.
        if resolver_rules.is_some() || config.test_proxy_bypass_loopback {
            args.push("--proxy-bypass-list=<-loopback>".to_string());
        }
    }
    if config.headless {
        args.push("--headless=new".to_string());
    }
    if config.ignore_cert {
        args.push("--ignore-certificate-errors".to_string());
    }
    args
}

fn spawn_chrome(
    config: &CaptureConfig,
    args: &[String],
    pipe: Option<&transport::PipeEnds>,
) -> Result<Child, String> {
    let mut command = Command::new(&config.chrome);
    command
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        // With pipe: fd 3 (read) and fd 4 (write) belong to the CDP; without pipe, none.
        let ends = pipe.map(|e| (e.child_read.as_raw_fd(), e.child_write.as_raw_fd()));
        // SAFETY: between fork and exec it only calls `dup2`, `fcntl` and `getdtablesize`,
        // all async-signal-safe and without allocating. The pipe's source fds are >= 10,
        // so they do not collide with 3 and 4; `dup2` clears FD_CLOEXEC on the targets.
        // Every other fd >= 3 (R9) gets FD_CLOEXEC and is closed on exec: nothing that the
        // launcher inherited (log, socket, secret) reaches Chrome. Marking instead of closing
        // preserves the internal pipe that std uses to report
        // an exec failure.
        unsafe {
            command.pre_exec(move || {
                let first_other = match ends {
                    Some((read_fd, write_fd)) => {
                        if libc::dup2(read_fd, 3) < 0 || libc::dup2(write_fd, 4) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        5
                    }
                    None => 3,
                };
                mark_fds_cloexec(first_other);
                Ok(())
            });
        }
    }
    command
        .spawn()
        .map_err(|error| {
            format!(
                "Could not open Chrome at {}: {error}. Select Chrome manually.",
                config.chrome.display()
            )
        })
}

/// Ceiling on the descriptor sweep in the child: covers any practical limit
/// (the macOS default `ulimit -n` is 256) without sweeping millions of numbers.
const MAX_FD_SWEEP: libc::c_int = 65_536;

/// Marks FD_CLOEXEC on every open descriptor `>= first` (async-signal-safe;
/// runs in the child between fork and exec). Descriptors above `MAX_FD_SWEEP`
/// are not swept: a gap documented in docs/16b §2.1.
fn mark_fds_cloexec(first: libc::c_int) {
    // Linux 5.11+: `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` marks ALL of them at once
    // (no sweep ceiling). Without the syscall (old kernel, seccomp) it falls back to the loop.
    #[cfg(target_os = "linux")]
    {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
        // SAFETY: direct syscall, async-signal-safe; it only changes descriptor flags.
        let rc = unsafe {
            libc::syscall(libc::SYS_close_range, first as libc::c_uint, libc::c_uint::MAX, CLOSE_RANGE_CLOEXEC)
        };
        if rc == 0 {
            return;
        }
    }
    // SAFETY: `getdtablesize` and `fcntl` only read or change descriptor flags.
    unsafe {
        let limit = libc::getdtablesize().clamp(first, MAX_FD_SWEEP);
        for fd in first..limit {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

fn wait_for_devtools(
    child: &mut Child,
    profile: &Path,
    timeout: Duration,
) -> Result<String, String> {
    let port_file = profile.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                return Err(
                    "Chrome exited before opening debugging. Check whether another instance is using the profile, or select another Chrome.".to_string(),
                );
            }
        }
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                let path = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{path}")
                };
                return Ok(format!("ws://127.0.0.1:{port}{path}"));
            }
        }
        thread::sleep(Duration::from_millis(120));
    }
    Err(
        "Chrome did not expose debugging within 25 s (DevToolsActivePort missing). Nothing was captured."
            .to_string(),
    )
}

#[derive(Debug, Clone)]
enum ChromeExit {
    /// The process exited on its own after `Browser.close`.
    Graceful(#[allow(dead_code)] Option<i32>),
    /// Exceeded the deadline and was killed by this module (the NetLog may be truncated).
    Killed,
    Unknown,
}

#[derive(Debug, Clone)]
struct ShutdownReport {
    browser_close: Result<(), String>,
    exit: ChromeExit,
    waited_ms: u64,
    /// The CDP transport closed for an abnormal reason (e.g. `frame_too_large`):
    /// the capture ended before the stop request, and the session is incomplete.
    transport_closed: Option<String>,
}

/// Safety net: only kills Chrome if `run_inner` exits without `disarm` (error/panic).
struct ChromeProcess(Option<Child>);

impl ChromeProcess {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .expect("ChromeProcess already released after graceful shutdown")
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Orphans: Chrome and the temporary profile left behind by an app SIGKILL.
// ---------------------------------------------------------------------------

const MARKER_PREFIX: &str = "capture-";
const PROFILE_PREFIX: &str = "scrapelens-chrome-";

/// PRIVATE, per-user base for the temporary profile, the NetLog and the state root.
/// - macOS: `temp_dir()` (`$TMPDIR` is a per-user directory, 0700).
/// - Linux: `$TMPDIR` if the user set it; otherwise `$XDG_RUNTIME_DIR` (per user,
///   tmpfs, 0700), if it really exists and belongs to the user with mode 0700; otherwise
///   `/tmp` (shared: names there carry the uid and everything is checked after
///   creation, see [`default_state_root`] and `create_private_dir_new`).
pub fn private_base_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        pick_base_dir(
            std::env::var_os("TMPDIR"),
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::temp_dir(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    std::env::temp_dir()
}

/// Pure choice (testable without touching the environment): a `TMPDIR` that is set and non-empty wins;
/// otherwise the valid `XDG_RUNTIME_DIR`; otherwise the `fallback` (`temp_dir()`).
#[cfg(target_os = "linux")]
fn pick_base_dir(
    tmpdir: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    fallback: PathBuf,
) -> PathBuf {
    if tmpdir.is_some_and(|v| !v.is_empty()) {
        return fallback;
    }
    xdg.and_then(|v| valid_runtime_dir(PathBuf::from(v))).unwrap_or(fallback)
}

/// `dir` if it is a real directory (not a symlink), absolute, owned by the current user, and with no
/// group/other access (the correct `XDG_RUNTIME_DIR` is 0700).
#[cfg(target_os = "linux")]
fn valid_runtime_dir(dir: PathBuf) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if !dir.is_absolute() {
        return None;
    }
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    (meta.is_dir() && meta.uid() == euid && meta.mode() & 0o077 == 0).then_some(dir)
}

/// Root of the capture markers' state (per user). The App calls
/// `cleanup_orphans(&default_state_root())`. On Linux, when the base is the shared `/tmp`,
/// the name carries the uid (`scrapelens-capture-state-<uid>`) so that two
/// users do not contend for the same directory; under `$XDG_RUNTIME_DIR` or on macOS the name
/// is `scrapelens-capture-state`.
pub fn default_state_root() -> PathBuf {
    state_root_in(&private_base_dir())
}

/// Name of the state root inside `base`. Linux: under a valid `XDG_RUNTIME_DIR`
/// (per user) it is `scrapelens-capture-state`; in any other base (for example
/// the shared `/tmp`) it carries the uid. macOS: always `scrapelens-capture-state`.
fn state_root_in(base: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let per_user = std::env::var_os("XDG_RUNTIME_DIR")
            .and_then(|v| valid_runtime_dir(PathBuf::from(v)))
            .is_some_and(|x| x == base);
        if !per_user {
            // SAFETY: `geteuid` has no preconditions.
            let uid = unsafe { libc::geteuid() };
            return base.join(format!("scrapelens-capture-state-{uid}"));
        }
    }
    base.join("scrapelens-capture-state")
}

/// Creates (if missing) the state root and checks, already open, that it is a directory of the
/// user, 0700 and not a link (this matters on `/tmp`, where another user may have
/// created the name first).
fn ensure_private_state_root(root: &Path) -> std::io::Result<()> {
    // A symlink in place of the root is refused BEFORE any chmod (the `set_mode` of the
    // core would follow the link and change the target's mode).
    if std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is a symbolic link; refused", root.display()),
        ));
    }
    store::ensure_private_dir(root).map_err(|e| std::io::Error::other(e.to_string()))?;
    verify_private_dir(root).map(|_| ())
}

fn port_from_ws_url(url: &str) -> Option<u16> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split('/').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// 0600 marker with what is needed to clean up an abandoned capture.
struct OrphanMarker {
    path: Option<PathBuf>,
    chrome_pid: u32,
    profile: PathBuf,
}

impl OrphanMarker {
    fn create(root: &Path, chrome_pid: u32, profile: &Path, port: Option<u16>) -> Self {
        let mut marker = Self {
            path: None,
            chrome_pid,
            profile: profile.to_path_buf(),
        };
        if ensure_private_state_root(root).is_ok() {
            let path = root.join(format!(
                "{MARKER_PREFIX}{}-{}.json",
                std::process::id(),
                unix_nanos()
            ));
            marker.path = Some(path);
            marker.write(port);
        }
        marker
    }

    fn write(&self, port: Option<u16>) {
        let Some(path) = &self.path else { return };
        let body = json!({
            "ownerPid": std::process::id(),
            "chromePid": self.chrome_pid,
            "profile": self.profile.display().to_string(),
            "port": port,
        });
        let _ = write_private(path, body.to_string().as_bytes());
    }

    fn set_port(&self, port: Option<u16>) {
        self.write(port);
    }
}

impl Drop for OrphanMarker {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Command line of the process, or `None` if it does not exist.
#[cfg(not(target_os = "linux"))]
fn process_command(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !text.is_empty()).then_some(text)
}

/// Linux: `/proc/<pid>/cmdline` (NUL-separated arguments), without depending on `ps`.
#[cfg(target_os = "linux")]
fn process_command(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let text = String::from_utf8_lossy(&raw).replace('\0', " ").trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(not(target_os = "linux"))]
fn process_exists(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Linux: `kill(pid, 0)`; `EPERM` also means the process exists.
#[cfg(target_os = "linux")]
fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 only tests existence.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn signal(pid: u32, name: &str) {
    let sig = match name {
        "-KILL" => libc::SIGKILL,
        _ => libc::SIGTERM,
    };
    // SAFETY: sends a signal to the marker's pid (already checked as ours by the caller).
    unsafe { libc::kill(pid as libc::pid_t, sig) };
}

/// Pids whose command line contains exactly `--user-data-dir=<profile>`
/// (the dedicated Chrome and its helpers).
#[cfg(not(target_os = "linux"))]
fn pids_using_profile(profile_flag: &str) -> Vec<u32> {
    let Ok(output) = Command::new("ps").args(["-ww", "-axo", "pid=,command="]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            let pid: u32 = pid.parse().ok()?;
            (command.contains(profile_flag) && pid != std::process::id()).then_some(pid)
        })
        .collect()
}

/// Linux: scans `/proc/<pid>/cmdline`.
#[cfg(target_os = "linux")]
fn pids_using_profile(profile_flag: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let command = process_command(pid)?;
            (command.contains(profile_flag) && pid != std::process::id()).then_some(pid)
        })
        .collect()
}

/// Only deletes profiles that this module creates: inside the private base and with the
/// app's prefix. A tampered marker cannot point to another directory.
fn is_app_profile(profile: &Path) -> bool {
    profile.parent() == Some(private_base_dir().as_path())
        && profile
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(PROFILE_PREFIX))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrphanCleanup {
    /// Markers of abandoned captures that were removed.
    pub markers_removed: usize,
    /// Chrome processes shut down (only those still using the marker's profile).
    pub processes_killed: usize,
    /// Temporary profiles deleted.
    pub profiles_removed: usize,
    /// Rescue folders (sessions that could not be written) that expired and were
    /// deleted, along with their marker.
    pub rescues_removed: usize,
}

/// Cleans up abandoned captures left behind by an app that died without shutting Chrome down.
/// For each marker in `state_root` whose owner process no longer exists:
/// shuts down the marker's Chrome only if the PID's command line still
/// contains the dedicated profile (never a reused PID or the user's own Chrome),
/// deletes the app's temporary profile and the marker. A marker whose owner is
/// still alive (including this process) is not touched.
pub fn cleanup_orphans(state_root: &Path) -> OrphanCleanup {
    let mut report = OrphanCleanup::default();
    let Ok(entries) = std::fs::read_dir(state_root) else {
        return report;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(RESCUE_PREFIX) && n.ends_with(".json"))
        {
            if !path.is_symlink() && cleanup_rescue_marker(state_root, &path) {
                report.rescues_removed += 1;
            }
            continue;
        }
        let is_marker = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(MARKER_PREFIX) && n.ends_with(".json"));
        if !is_marker || path.is_symlink() {
            continue;
        }
        let Some(value) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        let (Some(owner), Some(chrome_pid), Some(profile)) = (
            value.get("ownerPid").and_then(Value::as_u64),
            value.get("chromePid").and_then(Value::as_u64),
            value.get("profile").and_then(Value::as_str),
        ) else {
            continue;
        };
        let (owner, chrome_pid, profile) = (owner as u32, chrome_pid as u32, PathBuf::from(profile));
        if process_exists(owner) {
            continue;
        }
        if !is_app_profile(&profile) {
            // Marker that is not ours: only the marker is removed, nothing else is touched.
            let _ = std::fs::remove_file(&path);
            report.markers_removed += 1;
            continue;
        }
        let profile_flag = format!("--user-data-dir={}", profile.display());
        let ours = |pid: u32| process_command(pid).is_some_and(|c| c.contains(&profile_flag));
        let mut targets: Vec<u32> = Vec::new();
        if ours(chrome_pid) {
            targets.push(chrome_pid);
        }
        // Helpers of the same Chrome (renderers etc.) only join if the main one was ours.
        if !targets.is_empty() {
            for pid in pids_using_profile(&profile_flag) {
                if !targets.contains(&pid) {
                    targets.push(pid);
                }
            }
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-TERM");
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && targets.iter().any(|p| ours(*p)) {
            thread::sleep(Duration::from_millis(100));
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-KILL");
            }
        }
        report.processes_killed += targets.len();
        if profile.exists() && std::fs::remove_dir_all(&profile).is_ok() {
            report.profiles_removed += 1;
        }
        let _ = std::fs::remove_file(&path);
        report.markers_removed += 1;
    }
    report
}

/// Deletes an expired rescue folder (`RESCUE_TTL_DAYS`) and its marker. The age
/// comes from the rescue directory ITSELF (mtime, which changes only when entries are
/// created or removed in it), never from the marker's content (A6-B7): a
/// forged marker does not make a recent rescue look expired. The marker only counts if the
/// file name is `<dir>.json` and `dir` is a direct child of `state_root`, with the
/// rescue prefix and is not a symlink; a tampered marker does not point to
/// anywhere else.
fn cleanup_rescue_marker(state_root: &Path, marker: &Path) -> bool {
    let Some(value) = std::fs::read(marker)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    else {
        return false;
    };
    if value.get("kind").and_then(Value::as_str) != Some("rescue") {
        return false;
    }
    let Some(name) = value.get("dir").and_then(Value::as_str) else {
        return false;
    };
    let name_ok = name.starts_with(RESCUE_PREFIX) && !name.contains('/') && !name.contains("..");
    let bound = marker.file_name().and_then(|n| n.to_str()) == Some(&format!("{name}.json"));
    if !name_ok || !bound {
        return false;
    }
    let dir = state_root.join(name);
    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        // Rescue already deleted: only the marker is left over, so remove only it.
        let _ = std::fs::remove_file(marker);
        return false;
    };
    if !meta.file_type().is_dir() {
        return false;
    }
    let age = meta
        .modified()
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or_default();
    if age < Duration::from_secs(RESCUE_TTL_DAYS * 24 * 3600) {
        return false;
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(marker);
    true
}

fn wait_or_kill(child: &mut Child, timeout: Duration) -> ChromeExit {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ChromeExit::Graceful(status.code()),
            Ok(None) => {}
            Err(_) => return ChromeExit::Unknown,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return ChromeExit::Killed;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

const CDP_TARGET_METHODS: &[&str] = &[
    "Target.attachedToTarget",
    "Target.detachedFromTarget",
    "Target.targetInfoChanged",
    "Target.attachFailed",
    "Capture.sessionSetup",
    "Capture.targetSetupTimeout",
    "Capture.targetSetupAborted",
    "Capture.targetSetupError",
    "Target.targetDestroyed",
];

/// Warning code imported by the core (`cdp.target_setup_timeout`).
const CDP_TARGET_SETUP_TIMEOUT_WARNING: &str = "cdp.target_setup_timeout";

fn cdp_records_method(method: &str) -> bool {
    method.starts_with("Network.") || CDP_TARGET_METHODS.contains(&method)
}

#[derive(Debug, Clone)]
struct AttachedTarget {
    session_id: String,
    target_id: String,
    target_type: String,
}

struct Cdp {
    next_id: u64,
    page_session_id: String,
    events: Vec<String>,
    status: Arc<Mutex<CaptureStatus>>,
    bodies_by_session: HashMap<String, BodyCollector>,
    bodies_file: std::fs::File,
    in_flight: HashMap<u64, (String, BodyTag)>,
    outbox: Vec<(String, String)>,
    setup_done: HashMap<String, AttachedTarget>,
    /// Sessions that already went through `setup_attached_target` (commands sent).
    configured_sessions: std::collections::HashSet<String>,
    configured_target_primary: HashMap<String, String>,
    detached_sessions: std::collections::HashSet<String>,
    wait_for_debugger: bool,
    /// Targets seen via auto-attach (at any time), per session.
    setup_seen: HashMap<String, AttachedTarget>,
    /// Setup commands sent and still without a response, by CDP id. Setup
    /// never blocks: the response is handled by `record` in arrival order,
    /// by whoever is reading the socket.
    setup_pending: HashMap<u64, PendingSetupCommand>,
    /// `Page.loadEventFired` seen in the main page's session.
    page_load_events: u64,
    /// Successful ACKs of setup commands, by (session, method).
    setup_acked: std::collections::HashSet<(String, String)>,
}

/// Target setup command awaiting its ACK.
#[derive(Debug, Clone)]
struct PendingSetupCommand {
    target: AttachedTarget,
    method: String,
    sent_at: Instant,
    parent_session_id: Option<String>,
}

impl Cdp {
    fn new(status: Arc<Mutex<CaptureStatus>>, bodies_file: std::fs::File) -> Result<Self, String> {
        Ok(Self {
            next_id: 0,
            page_session_id: String::new(),
            events: Vec::new(),
            status,
            bodies_by_session: HashMap::new(),
            bodies_file: bodies_file
                .try_clone()
                .map_err(|error| format!("cdp-bodies.jsonl: {error}"))?,
            in_flight: HashMap::new(),
            outbox: Vec::new(),
            setup_done: HashMap::new(),
            configured_sessions: std::collections::HashSet::new(),
            configured_target_primary: HashMap::new(),
            detached_sessions: std::collections::HashSet::new(),
            wait_for_debugger: true,
            setup_seen: HashMap::new(),
            setup_pending: HashMap::new(),
            page_load_events: 0,
            setup_acked: std::collections::HashSet::new(),
        })
    }

    fn auto_attach_params(&self, wait_on_start: bool) -> Value {
        json!({
            "autoAttach": true,
            "flatten": true,
            "waitForDebuggerOnStart": wait_on_start && self.wait_for_debugger,
        })
    }

    fn wire_command(
        &mut self,
        socket: &mut Transport,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send_text(message.to_string())
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        Ok(id)
    }

    fn pump_socket(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) | Ok(Incoming::Other) => break,
                Err(ReadError::WouldBlock) => {}
                Err(_) => break,
            }
        }
    }

    fn bodies_for(&mut self, session_id: &str) -> &mut BodyCollector {
        self.bodies_by_session
            .entry(session_id.to_string())
            .or_default()
    }

    /// Sends a setup command without waiting for the response, and records it as
    /// pending. A late response produces no warning: only what is still without an ACK
    /// at shutdown becomes `Capture.targetSetupTimeout`.
    fn wire_setup_command(
        &mut self,
        socket: &mut Transport,
        target: &AttachedTarget,
        method: &str,
        params: Value,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        let id = self.wire_command(socket, method, params, Some(&target.session_id))?;
        self.register_setup_command(id, target, method, parent_session_id);
        Ok(())
    }

    fn register_setup_command(
        &mut self,
        id: u64,
        target: &AttachedTarget,
        method: &str,
        parent_session_id: Option<&str>,
    ) {
        self.setup_pending.insert(
            id,
            PendingSetupCommand {
                target: target.clone(),
                method: method.to_string(),
                sent_at: Instant::now(),
                parent_session_id: parent_session_id.map(str::to_string),
            },
        );
    }

    /// Handles the ACK of a setup command. Returns `true` if the id was a setup one.
    /// A late ACK only removes the pending entry; an error on an essential command becomes
    /// `Capture.targetSetupError` (as opposed to "no response").
    fn on_setup_response(&mut self, id: u64, value: &Value) -> bool {
        let Some(pending) = self.setup_pending.remove(&id) else {
            return false;
        };
        if value.get("error").is_none() {
            self.setup_acked
                .insert((pending.target.session_id.clone(), pending.method.clone()));
        }
        if let Some(error) = value.get("error") {
            let text = error
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());
            let gone = text.contains("not found") || text.contains("Target closed");
            if gone {
                self.push_target_setup_aborted(&pending.target, pending.parent_session_id.as_deref());
            } else if matches!(
                pending.method.as_str(),
                "Network.enable" | "Target.setAutoAttach" | "Runtime.runIfWaitingForDebugger"
            ) {
                self.push_event_line(
                    &pending.target.session_id,
                    "Capture.targetSetupError",
                    &json!({
                        "targetId": pending.target.target_id,
                        "sessionId": pending.target.session_id,
                        "type": pending.target.target_type,
                        "command": pending.method,
                        "error": text,
                    }),
                    pending.parent_session_id.as_deref(),
                );
            }
        }
        true
    }

    /// Is our client attached to the initial target? (`Network.enable` and
    /// `Target.setAutoAttach` with a successful ACK, no setup command
    /// pending, and the session configured.) Error = what is still missing.
    pub(crate) fn initial_target_gate(&self) -> Result<(), String> {
        let page = &self.page_session_id;
        if page.is_empty() {
            return Err("the initial tab has not attached yet".to_string());
        }
        if !self.configured_sessions.contains(page) {
            return Err("the initial tab has not been configured yet".to_string());
        }
        if let Some(pending) = self.setup_pending.values().find(|p| &p.target.session_id == page) {
            return Err(format!("{} still awaiting a response on the initial tab", pending.method));
        }
        for method in ["Network.enable", "Target.setAutoAttach"] {
            if !self.setup_acked.contains(&(page.clone(), method.to_string())) {
                return Err(format!("{method} not confirmed on the initial tab"));
            }
        }
        Ok(())
    }

    /// Reads the socket until the gate opens or the deadline passes.
    fn wait_initial_target_ready(
        &mut self,
        socket: &mut Transport,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.initial_target_gate() {
                Ok(()) => return Ok(()),
                Err(reason) if Instant::now() >= deadline => return Err(reason),
                Err(_) => self.pump_socket(socket, Duration::from_millis(100)),
            }
        }
    }

    /// Target detached or destroyed: its pending commands do not turn into a timeout.
    fn on_target_gone(&mut self, session_id: Option<&str>, target_id: Option<&str>) {
        let gone: Vec<u64> = self
            .setup_pending
            .iter()
            .filter(|(_, p)| {
                session_id.is_some_and(|s| p.target.session_id == s)
                    || target_id.is_some_and(|t| p.target.target_id == t)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut seen = std::collections::HashSet::new();
        for id in gone {
            if let Some(pending) = self.setup_pending.remove(&id) {
                if seen.insert(pending.target.session_id.clone()) {
                    self.push_target_setup_aborted(
                        &pending.target,
                        pending.parent_session_id.as_deref(),
                    );
                }
            }
        }
    }

    fn push_target_setup_aborted(
        &mut self,
        attached: &AttachedTarget,
        parent_session_id: Option<&str>,
    ) {
        self.push_event_line(
            &attached.session_id,
            "Capture.targetSetupAborted",
            &json!({
                "targetId": attached.target_id,
                "sessionId": attached.session_id,
                "type": attached.target_type,
                "reason": "target closed during setup",
            }),
            parent_session_id,
        );
    }

    /// Shutdown (before `Browser.close`): every setup command still without an
    /// ACK, in any session (including the primary one), becomes a real warning.
    fn finalize_pending_setups(&mut self) {
        let mut pending: Vec<(u64, PendingSetupCommand)> = self.setup_pending.drain().collect();
        pending.sort_by_key(|(id, _)| *id);
        for (_, p) in pending {
            self.push_event_line(
                &p.target.session_id,
                "Capture.targetSetupTimeout",
                &json!({
                    "targetId": p.target.target_id,
                    "sessionId": p.target.session_id,
                    "type": p.target.target_type,
                    "command": p.method,
                    "pendingMs": p.sent_at.elapsed().as_millis() as u64,
                    "warningCode": CDP_TARGET_SETUP_TIMEOUT_WARNING,
                }),
                p.parent_session_id.as_deref(),
            );
        }
    }

    /// Reads the socket until no setup is pending or `window` runs out.
    fn pump_until_setup_settled(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.setup_pending.is_empty() && Instant::now() < deadline {
            self.pump_socket(socket, Duration::from_millis(100));
        }
    }

    fn push_event_line(
        &mut self,
        session_id: &str,
        method: &str,
        params: &Value,
        parent_session_id: Option<&str>,
    ) {
        let mut line = json!({
            "sessionId": session_id,
            "method": method,
            "params": params,
        });
        if let Some(parent) = parent_session_id.filter(|p| !p.is_empty() && *p != session_id) {
            line["parentSessionId"] = json!(parent);
        }
        self.events.push(line.to_string());
        if let Ok(mut guard) = self.status.lock() {
            guard.events = self.events.len();
        }
    }

    fn skip_target_setup(target_type: &str) -> bool {
        matches!(target_type, "browser_ui" | "other")
    }

    fn recurse_auto_attach(target_type: &str) -> bool {
        matches!(
            target_type,
            "page" | "iframe" | "worker" | "service_worker"
        )
    }

    fn setup_duplicate_target_session(
        &mut self,
        socket: &mut Transport,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        // Extra session of the same target: resumes it (if paused) and detaches, without network.
        // The ACKs do not matter: nothing here is capture setup.
        if self.wait_for_debugger && waiting_for_debugger {
            self.wire_command(
                socket,
                "Runtime.runIfWaitingForDebugger",
                json!({}),
                Some(&attached.session_id),
            )?;
        }
        self.wire_command(
            socket,
            "Target.detachFromTarget",
            json!({ "sessionId": attached.session_id }),
            None,
        )?;
        self.detached_sessions.insert(attached.session_id.clone());
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": attached.target_type,
                "waitingForDebugger": waiting_for_debugger,
                "duplicateSession": true,
                "detached": true,
            }),
            parent_session_id,
        );
        Ok(())
    }

    /// Configures an attached target without blocking: sends the commands in a pipeline,
    /// in the same session, and leaves the ACKs for whoever reads the socket (`record`).
    /// Paused target: Network.enable → Page/Runtime.enable → setAutoAttach →
    /// runIfWaitingForDebugger (the network is already on when it resumes, and the
    /// resume does not wait for a response). Unpaused target: the harness order
    /// (setAutoAttach → Network.enable → Page/Runtime.enable).
    fn setup_attached_target(
        &mut self,
        socket: &mut Transport,
        attached: AttachedTarget,
        waiting_for_debugger: bool,
        parent_session_id: Option<&str>,
    ) -> Result<(), String> {
        match self.configured_target_primary.get(&attached.target_id) {
            Some(primary) if primary != &attached.session_id => {
                return self.setup_duplicate_target_session(
                    socket,
                    attached,
                    waiting_for_debugger,
                    parent_session_id,
                );
            }
            None if !Self::skip_target_setup(&attached.target_type) => {
                self.configured_target_primary.insert(
                    attached.target_id.clone(),
                    attached.session_id.clone(),
                );
            }
            _ => {}
        }
        if self.configured_sessions.contains(&attached.session_id) {
            return Ok(());
        }
        // Mark before sending: avoids re-entry if the send fails.
        self.configured_sessions
            .insert(attached.session_id.clone());
        self.setup_seen
            .insert(attached.session_id.clone(), attached.clone());
        let target_type = attached.target_type.clone();
        let resume = self.wait_for_debugger && waiting_for_debugger;
        if Self::skip_target_setup(&target_type) {
            if resume {
                self.wire_command(
                    socket,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    Some(&attached.session_id),
                )?;
            }
            self.setup_done
                .insert(attached.session_id.clone(), attached.clone());
            self.push_event_line(
                &attached.session_id,
                "Capture.sessionSetup",
                &json!({
                    "targetId": attached.target_id,
                    "type": target_type,
                    "waitingForDebugger": waiting_for_debugger,
                    "resumedDebugger": resume,
                    "skippedNetwork": true,
                }),
                parent_session_id,
            );
            return Ok(());
        }
        let network_params = json!({
            "maxTotalBufferSize": 100_000_000,
            "maxResourceBufferSize": 50_000_000,
            "maxPostDataSize": MAX_BODY_BYTES
        });
        let recurse = Self::recurse_auto_attach(&target_type);
        let page_like = target_type == "page" || target_type == "iframe";
        let parent = parent_session_id;
        let auto_attach = self.auto_attach_params(true);
        let mut commands: Vec<(&str, Value)> = Vec::new();
        if resume {
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Runtime.runIfWaitingForDebugger", json!({})));
        } else {
            if recurse {
                commands.push(("Target.setAutoAttach", auto_attach));
            }
            commands.push(("Network.enable", network_params));
            if page_like {
                commands.push(("Page.enable", json!({})));
            }
            commands.push(("Runtime.enable", json!({})));
        }
        for (method, params) in commands {
            self.wire_setup_command(socket, &attached, method, params, parent)?;
        }
        self.setup_done
            .insert(attached.session_id.clone(), attached.clone());
        self.push_event_line(
            &attached.session_id,
            "Capture.sessionSetup",
            &json!({
                "targetId": attached.target_id,
                "type": target_type,
                "waitingForDebugger": waiting_for_debugger,
                "resumedDebugger": resume,
                "pipelinedSetup": true,
                "recursiveAutoAttach": recurse,
            }),
            parent_session_id,
        );
        Ok(())
    }

    fn session_for_recorded_event(
        &self,
        method: &str,
        wire: &Value,
        params: &Value,
    ) -> String {
        if method == "Target.attachedToTarget" {
            return params
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }
        if method == "Target.targetInfoChanged" {
            if let Some(target_id) = params
                .get("targetInfo")
                .and_then(|info| info.get("targetId"))
                .and_then(Value::as_str)
            {
                for attached in self.setup_done.values().chain(self.setup_seen.values()) {
                    if attached.target_id == target_id {
                        return attached.session_id.clone();
                    }
                }
            }
        }
        wire
            .get("sessionId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn handle_incoming_event(
        &mut self,
        socket: &mut Transport,
        value: &Value,
    ) {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return;
        };
        if method == "Target.detachedFromTarget" {
            let session_id = value
                .get("params")
                .and_then(|p| p.get("sessionId"))
                .and_then(Value::as_str);
            self.on_target_gone(session_id, None);
        }
        if method == "Page.loadEventFired"
            && !self.page_session_id.is_empty()
            && value.get("sessionId").and_then(Value::as_str) == Some(self.page_session_id.as_str())
        {
            self.page_load_events += 1;
        }
        if method == "Target.targetDestroyed" {
            let target_id = value
                .get("params")
                .and_then(|p| p.get("targetId"))
                .and_then(Value::as_str);
            self.on_target_gone(None, target_id);
        }
        if method == "Target.attachedToTarget" {
            if let Some(params) = value.get("params").and_then(Value::as_object) {
                let session_id = params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target = params.get("targetInfo").and_then(Value::as_object);
                let target_id = target
                    .and_then(|t| t.get("targetId"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let target_type = target
                    .and_then(|t| t.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let waiting = params
                    .get("waitingForDebugger")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let attached = AttachedTarget {
                    session_id: session_id.clone(),
                    target_id: target_id.clone(),
                    target_type: target_type.clone(),
                };
                if !Self::skip_target_setup(&target_type) {
                    self.configured_target_primary
                        .entry(target_id.clone())
                        .or_insert(session_id.clone());
                }
                let parent_wire = value.get("sessionId").and_then(Value::as_str);
                self.setup_seen
                    .insert(session_id.clone(), attached.clone());
                // Does not block: it only sends the commands. A send failure (socket)
                // shows up as a read error in the capture loop.
                let _ = self.setup_attached_target(socket, attached, waiting, parent_wire);
            }
        }
        if !cdp_records_method(method) {
            return;
        }
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let session_id = self.session_for_recorded_event(method, value, &params);
        if method.starts_with("Network.") && self.detached_sessions.contains(&session_id) {
            return;
        }
        let parent_session_id = if method == "Target.attachedToTarget" {
            value.get("sessionId").and_then(Value::as_str)
        } else {
            None
        };
        self.push_event_line(&session_id, method, &params, parent_session_id);
        if method.starts_with("Network.") {
            for command in self.bodies_for(&session_id).on_event(method, &params) {
                let id = self.next_id;
                self.next_id += 1;
                let message =
                    json!({ "id": id, "method": command.method, "params": command.params });
                self.in_flight
                    .insert(id, (session_id.clone(), command.tag));
                self.outbox
                    .push((session_id.clone(), message.to_string()));
            }
            self.write_body_lines();
        }
    }

    fn setup(
        &mut self,
        socket: &mut Transport,
        start_url: &str,
        cookies: &[cookies::ImportedCookie],
        audit: Option<CookieAudit<'_>>,
    ) -> Result<(), String> {
        let setup_result = self.setup_inner(socket, start_url, cookies, audit);
        if setup_result.is_ok() {
            self.pump_socket(socket, Duration::from_millis(400));
        }
        setup_result
    }

    /// Recipe `cdp_multi_capture.mjs` (da972ef): root auto-attach, a setup queue
    /// per session, recursive `setAutoAttach` on the page before navigating.
    fn setup_inner(
        &mut self,
        socket: &mut Transport,
        start_url: &str,
        cookies: &[cookies::ImportedCookie],
        audit: Option<CookieAudit<'_>>,
    ) -> Result<(), String> {
        self.send(
            socket,
            "Target.setDiscoverTargets",
            json!({ "discover": true }),
            None,
            // Aligned with `wait_for_devtools` and `Target.setAutoAttach`: a cold headful Chrome
            // on macOS can take >10 s to initialize the GPU and the
            // window before draining fd 3 of the pipe (timeout seen by the user).
            Duration::from_secs(25),
        )?;
        self.send(
            socket,
            "Target.setAutoAttach",
            self.auto_attach_params(true),
            None,
            Duration::from_secs(25),
        )?;
        let url = if start_url.trim().is_empty() {
            "about:blank".to_string()
        } else {
            start_url.to_string()
        };
        let created = self.send(
            socket,
            "Target.createTarget",
            json!({ "url": "about:blank" }),
            None,
            Duration::from_secs(15),
        )?;
        let main_target = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP returned no targetId".to_string())?
            .to_string();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(page_session) = self
                .setup_seen
                .values()
                .find(|t| t.target_id == main_target && t.target_type == "page")
                .map(|t| t.session_id.clone())
            {
                self.page_session_id = page_session.clone();
                if !self.configured_sessions.contains(&page_session) {
                    // The handler normally already configured the page on attach;
                    // this branch only covers an attach that the handler did not see.
                    self.setup_attached_target(
                        socket,
                        AttachedTarget {
                            session_id: page_session.clone(),
                            target_id: main_target.clone(),
                            target_type: "page".to_string(),
                        },
                        false,
                        None,
                    )?;
                }
                self.send(
                    socket,
                    "Target.setAutoAttach",
                    self.auto_attach_params(true),
                    Some(&page_session),
                    Duration::from_secs(15),
                )?;
                self.send(
                    socket,
                    "Network.setCacheDisabled",
                    json!({ "cacheDisabled": true }),
                    Some(&page_session),
                    Duration::from_secs(5),
                )?;
                if url != "about:blank" {
                    // Imported cookies are added BEFORE the first navigation: the
                    // initial request already carries the site's session.
                    if !cookies.is_empty() {
                        self.send(
                            socket,
                            "Network.setCookies",
                            json!({ "cookies": cookies::cdp_cookies(cookies) }),
                            Some(&page_session),
                            Duration::from_secs(10),
                        )?;
                    }
                    if let Some(audit) = audit {
                        self.push_event_line(
                            &page_session,
                            "Capture.cookiesImported",
                            &json!({
                                "source": audit.source,
                                "domain": audit.domain,
                                "importedCount": cookies.len(),
                                "skippedCount": audit.skipped,
                                "undecryptableCount": audit.undecryptable,
                                "undecryptableReason": audit.undecryptable_reason,
                            }),
                            None,
                        );
                    }
                    self.send(
                        socket,
                        "Page.navigate",
                        json!({ "url": url }),
                        Some(&page_session),
                        Duration::from_secs(30),
                    )?;
                }
                break;
            }
            self.pump_socket(socket, Duration::from_millis(100));
        }
        if self.page_session_id.is_empty() {
            return Err(
                "The initial page did not attach after createTarget (Target.attachedToTarget)"
                    .to_string(),
            );
        }
        let settle = Instant::now() + Duration::from_secs(5);
        while Instant::now() < settle {
            self.pump_socket(socket, Duration::from_millis(100));
        }
        Ok(())
    }

    fn send(
        &mut self,
        socket: &mut Transport,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        socket
            .send_text(message.to_string())
            .map_err(|error| format!("CDP send {method}: {error}"))?;
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("{} {method}", browser::CDP_TIMEOUT_PREFIX));
            }
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    let value: Value = serde_json::from_str(text.as_str())
                        .map_err(|error| format!("invalid CDP JSON: {error}"))?;
                    if value.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = value.get("error") {
                            return Err(format!("CDP {method}: {error}"));
                        }
                        return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                    }
                    self.record(socket, &value);
                    self.flush_outbox(socket);
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) => return Err(format!("CDP fechou durante {method}")),
                Ok(_) => {}
                Err(ReadError::WouldBlock) => {}
                Err(ReadError::Fatal(error)) => return Err(format!("CDP read {method}: {error}")),
            }
        }
    }

    fn record(
        &mut self,
        socket: &mut Transport,
        value: &Value,
    ) {
        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            if self.on_setup_response(id, value) {
                return;
            }
            if let Some((session_id, tag)) = self.in_flight.remove(&id) {
                let outcome = match value.get("error") {
                    Some(error) => Err(error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| error.to_string())),
                    None => Ok(value.get("result").cloned().unwrap_or(Value::Null)),
                };
                self.bodies_for(&session_id).on_result(tag, outcome);
                self.write_body_lines();
            }
            return;
        }
        self.handle_incoming_event(socket, value);
    }

    /// Sends, without waiting for a response, the body commands queued by
    /// `record`. A send failure becomes `unavailable` immediately.
    fn flush_outbox(&mut self, socket: &mut Transport) {
        for (session_id, message) in std::mem::take(&mut self.outbox) {
            let id = serde_json::from_str::<Value>(&message)
                .ok()
                .and_then(|value| value.get("id").and_then(Value::as_u64));
            let mut payload: Value = serde_json::from_str(&message).unwrap_or(Value::Null);
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("sessionId".to_string(), json!(session_id));
            }
            let wire = payload.to_string();
            if let Err(error) = socket.send_text(wire) {
                if let Some(id) = id {
                    if let Some((sid, tag)) = self.in_flight.remove(&id) {
                        self.bodies_for(&sid).on_result(
                            tag,
                            Err(format!("failed to send command to CDP: {error}")),
                        );
                    }
                }
            }
        }
        self.write_body_lines();
    }

    /// Waits (up to `window`) for the body responses still in flight.
    fn drain_bodies(
        &mut self,
        socket: &mut Transport,
        window: Duration,
    ) {
        let deadline = Instant::now() + window;
        while !self.in_flight.is_empty() && Instant::now() < deadline {
            match socket.read() {
                Ok(Incoming::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(text.as_str()) {
                        self.record(socket, &value);
                        self.flush_outbox(socket);
                    }
                }
                Ok(Incoming::Ping(payload)) => {
                    socket.pong(payload);
                }
                Ok(Incoming::Close) => break,
                Ok(_) => {}
                Err(ReadError::WouldBlock) => {}
                Err(_) => break,
            }
        }
    }

    /// Closes collection: nothing is left without a row.
    fn finish_bodies(&mut self) {
        let leftover: Vec<(String, BodyTag)> =
            self.in_flight.drain().map(|(_, pair)| pair).collect();
        for (session_id, tag) in leftover {
            self.bodies_for(&session_id).on_result(
                tag,
                Err("capture ended before CDP answered the body command".to_string()),
            );
        }
        for collector in self.bodies_by_session.values_mut() {
            collector.finish();
        }
        self.write_body_lines();
        let _ = self.bodies_file.sync_all();
    }

    fn write_body_lines(&mut self) {
        for (session_id, collector) in &mut self.bodies_by_session {
            for line in collector.take_lines() {
                let mut value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                if let Some(map) = value.as_object_mut() {
                    map.insert("sessionId".to_string(), json!(session_id));
                }
                let out = format!("{}\n", value);
                let result = self
                    .bodies_file
                    .write_all(out.as_bytes());
                if let Err(error) = result {
                    if let Ok(mut guard) = self.status.lock() {
                        guard.last_error = Some(format!("cdp-bodies.jsonl: {error}"));
                    }
                }
            }
        }
    }

    fn events_text(&self) -> String {
        if self.events.is_empty() {
            return String::new();
        }
        let mut text = self.events.join("\n");
        text.push('\n');
        text
    }
}

const EMPTY_NETLOG: &[u8] = br#"{"constants":{},"events":[]}"#;

/// NetLog state read from disk after Chrome shut down.
#[derive(Debug, Clone, PartialEq)]
enum NetlogStatus {
    Complete,
    /// Truncated; repaired by cutting at the last complete event.
    Repaired {
        original_bytes: usize,
        kept_bytes: usize,
    },
    /// Missing, empty or unrecoverable: the session continues with CDP only.
    Unusable {
        reason: String,
    },
}

fn is_valid_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
}

/// Chrome writes one event per line in `"events":[`. A truncated file
/// ends with a complete event followed by a comma, or with a partial line: it cuts at the
/// last line break, removes the comma and closes `]}` (the `polledData` is lost).
fn repair_netlog(raw: &[u8]) -> Option<Vec<u8>> {
    let marker = raw
        .windows(10)
        .position(|w| w == b"\"events\":[" || w == b"\"events\": ")?;
    let mut end = raw.len();
    for _ in 0..16 {
        let mut candidate = raw[..end].to_vec();
        while candidate
            .last()
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            candidate.pop();
        }
        candidate.extend_from_slice(b"]}");
        if is_valid_json(&candidate) {
            return Some(candidate);
        }
        // Steps back one line; stops before entering the constants.
        end = raw[..end].iter().rposition(|byte| *byte == b'\n')?;
        if end <= marker {
            return None;
        }
    }
    None
}

fn prepare_netlog(raw: Option<&[u8]>) -> (Vec<u8>, NetlogStatus) {
    let Some(raw) = raw else {
        return (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog missing or empty".to_string(),
            },
        );
    };
    if is_valid_json(raw) {
        return (raw.to_vec(), NetlogStatus::Complete);
    }
    match repair_netlog(raw) {
        Some(fixed) => {
            let kept_bytes = fixed.len();
            (
                fixed,
                NetlogStatus::Repaired {
                    original_bytes: raw.len(),
                    kept_bytes,
                },
            )
        }
        None => (
            EMPTY_NETLOG.to_vec(),
            NetlogStatus::Unusable {
                reason: "NetLog truncated and unrepairable".to_string(),
            },
        ),
    }
}

/// Records in the session everything that made the capture incomplete. Never silently.
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
                let mut reason = format!("loadingFailed: {text}");
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
