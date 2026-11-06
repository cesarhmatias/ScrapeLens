//! Controlled capture for the MCP (`docs/16b-mcp-browser.md` §3–§4).
//!
//! `BrowserCapture` opens stable Chrome with a dedicated profile, CDP + NetLog and
//! a **mandatory allowlist**, accepts `navigate` and shuts down gracefully. The
//! capture thread keeps ownership of the CDP socket; `navigate` is a message
//! on a channel consumed by the recording loop. The user's confirmation
//! (MCP elicitation) happens in the server layer, before calling this API.

use std::path::PathBuf;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use super::transport::{CdpTransport, Transport};

use super::allowlist::{Allowlist, AllowlistError, AllowlistReport, UrlDenied};
use super::chrome::{validate_chrome, ChromeError};
use super::{run_with_options, CaptureConfig, CaptureOutcome, CaptureStatus, Cdp, RunOptions, RunReport};

/// Fixed text that the MCP server shows in the `start_capture` confirmation.
pub const SENSITIVE_NOTICE: &str = "This capture records cookies, authorization headers and request and response bodies (NetLog in Everything mode + CDP). The data stays in the session folder; read tools mask values by default. Do not type credentials into the capture browser.";

/// Chrome debugging address (loopback).
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub http: Option<String>,
    pub browser_ws: String,
    pub chrome_pid: u32,
    pub page_target_id: Option<String>,
    pub product: Option<String>,
    pub user_agent: Option<String>,
}

/// Messages for the recording loop.
pub(crate) enum Control {
    Navigate {
        url: String,
        wait_load: bool,
        timeout: Duration,
        reply: Sender<Result<NavigateResult, NavigateError>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigateResult {
    pub frame_id: Option<String>,
    pub loader_id: Option<String>,
    pub loaded: bool,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BrowserCaptureConfig {
    pub chrome: PathBuf,
    pub session_dir: PathBuf,
    pub start_url: Option<String>,
    pub headless: bool,
    pub allowed_hosts: Vec<String>,
    pub third_party_hosts: Vec<String>,
    pub expose_cdp: bool,
    /// Optional proxy. With the allowlist it always goes through the relay, which checks
    /// every destination before it leaves.
    pub proxy: Option<crate::proxy::ProxyLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    Allowlist(AllowlistError),
    /// The browser is not Google's stable Chrome (`chrome::validate_chrome`).
    BrowserInvalid(ChromeError),
    /// The proxy could not be used (unreachable, certificate rejected, local relay).
    /// The message carries no credentials.
    Proxy(crate::relay::RelayError),
    StartUrlNotAllowed(UrlDenied),
    SessionDir(String),
    BrowserStart(String),
}

impl StartError {
    pub fn code(&self) -> &'static str {
        match self {
            StartError::Allowlist(e) => e.code(),
            StartError::BrowserInvalid(e) => e.code(),
            StartError::Proxy(_) => "proxy_unavailable",
            StartError::StartUrlNotAllowed(_) => "start_url_not_allowed",
            StartError::SessionDir(_) => "session_dir",
            StartError::BrowserStart(_) => "browser_start_failed",
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Allowlist(e) => write!(f, "{e}"),
            StartError::BrowserInvalid(e) => write!(f, "{e}"),
            StartError::StartUrlNotAllowed(e) => write!(f, "start_url: {e}"),
            StartError::SessionDir(e) => write!(f, "session directory: {e}"),
            StartError::BrowserStart(e) => write!(f, "{e}"),
            StartError::Proxy(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpAccess {
    pub http: Option<String>,
    pub browser_ws: String,
    /// The capture tab (the one `navigate` uses): the agent attaches to this one.
    pub page_target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserInfo {
    pub path: String,
    pub version: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistInfo {
    pub allowed_hosts: Vec<String>,
    pub third_party_hosts: Vec<String>,
    pub resolver_rules: String,
}

/// Response of `start_capture`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartInfo {
    pub session_dir: String,
    pub chrome_pid: u32,
    pub browser: BrowserInfo,
    pub allowlist: AllowlistInfo,
    /// Only with `expose_cdp: true`.
    pub cdp: Option<CdpAccess>,
    pub sensitive_notice: &'static str,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigateError {
    UrlNotAllowed(UrlDenied),
    CaptureStopped,
    Failed(String),
    /// The browser did not respond within the `navigate` deadline (stuck or
    /// stopped). The capture keeps running; the agent can retry or stop it.
    TimedOut,
}

impl NavigateError {
    pub fn code(&self) -> &'static str {
        match self {
            NavigateError::UrlNotAllowed(_) => "url_not_allowed",
            NavigateError::CaptureStopped => "capture_stopped",
            NavigateError::Failed(_) => "navigate_failed",
            NavigateError::TimedOut => "navigate_timeout",
        }
    }
}

impl std::fmt::Display for NavigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NavigateError::UrlNotAllowed(e) => write!(f, "{e}"),
            NavigateError::CaptureStopped => write!(f, "the capture has already been stopped"),
            NavigateError::Failed(e) => write!(f, "{e}"),
            NavigateError::TimedOut => write!(
                f,
                "the browser did not respond to navigate within the deadline (stuck or stopped)"
            ),
        }
    }
}

impl std::error::Error for NavigateError {}

/// Response of `stop_capture`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopReport {
    pub session_dir: String,
    pub requests: usize,
    pub netlog: String,
    pub graceful: bool,
    pub waited_ms: u64,
    pub allowlist: AllowlistReport,
    pub warnings: Vec<String>,
    /// Imported session, for the caller (the MCP server registers the handle).
    #[serde(skip)]
    pub outcome: Option<CaptureOutcome>,
}

pub struct BrowserCapture {
    allowlist: Allowlist,
    session_dir: PathBuf,
    control: Sender<Control>,
    stop: Sender<()>,
    join: Option<JoinHandle<Result<(CaptureOutcome, RunReport), String>>>,
    status: Arc<Mutex<CaptureStatus>>,
}

/// Start of the `Cdp::send` message when a response deadline expires.
pub(crate) const CDP_TIMEOUT_PREFIX: &str = "CDP timeout aguardando";

/// Floor for a `navigate` deadline: `Page.navigate` needs time to confirm
/// even when the agent asks for a very short `timeout_ms`.
const MIN_NAVIGATE_BUDGET: Duration = Duration::from_secs(2);
/// Cap for `Page.navigate` (the requested deadline never extends it).
const MAX_PAGE_NAVIGATE: Duration = Duration::from_secs(30);
/// Slack between the loop deadline and the caller's.
const NAVIGATE_REPLY_MARGIN: Duration = Duration::from_secs(5);

/// Total deadline (command + load wait) of a `navigate`.
fn navigate_budget(timeout: Duration) -> Duration {
    timeout.max(MIN_NAVIGATE_BUDGET)
}

impl BrowserCapture {
    /// Opens Chrome. Without a valid allowlist, it opens nothing.
    pub fn start(config: BrowserCaptureConfig) -> Result<(BrowserCapture, StartInfo), StartError> {
        let allowlist = Allowlist::new(&config.allowed_hosts, &config.third_party_hosts)
            .map_err(StartError::Allowlist)?;
        let start_url = match config.start_url.as_deref().filter(|u| !u.trim().is_empty()) {
            Some(url) => {
                allowlist
                    .permits_url(url)
                    .map_err(StartError::StartUrlNotAllowed)?;
                url.to_string()
            }
            None => String::new(),
        };
        // Only Google's stable Chrome, read from the bundle and its signature,
        // without running anything. The validated path (symlinks resolved) is the one that runs.
        let validated = validate_chrome(&config.chrome).map_err(StartError::BrowserInvalid)?;
        // Preflight: an unusable proxy is refused here, before any browser starts. The
        // capture prepares its own relay again when it starts (the first one is dropped).
        if let Some(link) = &config.proxy {
            let al = allowlist.clone();
            let allow: crate::relay::AllowFn =
                Arc::new(move |host: &str, port: u16| al.permits_destination(host, port));
            crate::relay::ProxyPlan::prepare(link.clone(), Some(allow)).map_err(StartError::Proxy)?;
        }
        let capture_config = CaptureConfig {
            chrome: validated.binary.clone(),
            session_dir: config.session_dir.clone(),
            start_url,
            headless: config.headless,
            ignore_cert: false,
            // No effect: the controlled capture always carries the allowlist
            // (`resolver_rules`), which applies in place of the mode. If it were missing,
            // the network would be restricted to loopback (fail closed), never opened.
            network: crate::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: config.proxy.clone(),
            test_proxy_bypass_loopback: false,
        };
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_dir: config.session_dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let (control_tx, control_rx) = channel();
        let endpoint: Arc<Mutex<Option<Endpoint>>> = Arc::new(Mutex::new(None));
        let opts = RunOptions {
            allowlist: Some(allowlist.clone()),
            control: Some(control_rx),
            endpoint: Some(endpoint.clone()),
            require_initial_target_ready: true,
            // With no agent connected, Chrome opens no port at all (pipe); with
            // `expose_cdp`, the port, only on 127.0.0.1, is inherent to the feature.
            transport: if config.expose_cdp {
                CdpTransport::Port
            } else {
                CdpTransport::Pipe
            },
        };
        let thread_status = status.clone();
        let join = thread::spawn(move || {
            run_with_options(capture_config, thread_status, stop_rx, ready_tx, &opts)
        });
        match ready_rx.recv_timeout(Duration::from_secs(90)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = join.join();
                return Err(StartError::BrowserStart(error));
            }
            Err(_) => {
                let _ = stop_tx.send(());
                let _ = join.join();
                return Err(StartError::BrowserStart(
                    "Chrome was not ready within 90 s".to_string(),
                ));
            }
        }
        let endpoint = endpoint
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| StartError::BrowserStart("debugging endpoint missing".to_string()))?;
        let info = StartInfo {
            session_dir: config.session_dir.display().to_string(),
            chrome_pid: endpoint.chrome_pid,
            browser: BrowserInfo {
                path: validated.binary.display().to_string(),
                version: endpoint.product.clone().or(Some(validated.version.clone())),
                user_agent: endpoint.user_agent.clone(),
            },
            allowlist: AllowlistInfo {
                allowed_hosts: allowlist.allowed_hosts(),
                third_party_hosts: allowlist.third_party_hosts(),
                resolver_rules: allowlist.resolver_rules(),
            },
            cdp: config.expose_cdp.then(|| CdpAccess {
                http: endpoint.http.clone(),
                browser_ws: endpoint.browser_ws.clone(),
                page_target_id: endpoint.page_target_id.clone(),
            }),
            sensitive_notice: SENSITIVE_NOTICE,
            warnings: Vec::new(),
        };
        Ok((
            BrowserCapture {
                allowlist,
                session_dir: config.session_dir,
                control: control_tx,
                stop: stop_tx,
                join: Some(join),
                status,
            },
            info,
        ))
    }

    /// Navigates the main tab. The URL is validated before anything is sent.
    pub fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        let allowed = self
            .allowlist
            .permits_url(url)
            .map_err(NavigateError::UrlNotAllowed)?;
        let (reply_tx, reply_rx) = channel();
        self.control
            .send(Control::Navigate {
                url: allowed.url,
                wait_load,
                timeout,
                reply: reply_tx,
            })
            .map_err(|_| NavigateError::CaptureStopped)?;
        // The loop responds within ~250 ms and `navigate_page` honors the whole
        // deadline (R12); the margin covers the delay of a task running in the loop.
        match reply_rx.recv_timeout(navigate_budget(timeout) + NAVIGATE_REPLY_MARGIN) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(NavigateError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => Err(NavigateError::CaptureStopped),
        }
    }

    pub fn status(&self) -> CaptureStatus {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Graceful shutdown (`Browser.close`, wait, NetLog closed) and
    /// session import.
    pub fn stop(mut self) -> Result<StopReport, String> {
        let _ = self.stop.send(());
        let join = self
            .join
            .take()
            .ok_or_else(|| "capture already stopped".to_string())?;
        let (outcome, report) = join
            .join()
            .map_err(|_| "the capture thread failed".to_string())??;
        Ok(StopReport {
            session_dir: self.session_dir.display().to_string(),
            requests: report.requests,
            netlog: report.netlog,
            graceful: report.graceful,
            waited_ms: report.waited_ms,
            allowlist: report.allowlist.unwrap_or_default(),
            warnings: report.warnings,
            outcome: Some(outcome),
        })
    }
}

impl Drop for BrowserCapture {
    fn drop(&mut self) {
        // Without `stop`: shuts down the same way (the loop treats the closed channel
        // as a stop) and waits for the thread, so Chrome is not left running.
        if let Some(join) = self.join.take() {
            let _ = self.stop.send(());
            let _ = join.join();
        }
    }
}

impl Cdp {
    /// Handles a control message inside the recording loop.
    pub(super) fn handle_control(
        &mut self,
        socket: &mut Transport,
        message: Control,
    ) {
        match message {
            Control::Navigate {
                url,
                wait_load,
                timeout,
                reply,
            } => {
                let result = self.navigate_page(socket, &url, wait_load, timeout);
                let _ = reply.send(result);
            }
        }
    }

    fn navigate_page(
        &mut self,
        socket: &mut Transport,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        if self.page_session_id.is_empty() {
            return Err(NavigateError::Failed("the main tab is not ready".to_string()));
        }
        let page = self.page_session_id.clone();
        let before = self.page_load_events;
        // A single deadline for the command and the load wait: with Chrome stuck,
        // `navigate(timeout_ms=3000)` returns in ~3 s, not 30 s.
        let budget = navigate_budget(timeout);
        let started = Instant::now();
        let result = self.send(
            socket,
            "Page.navigate",
            json!({ "url": url }),
            Some(&page),
            budget.min(MAX_PAGE_NAVIGATE),
        )
        .map_err(|error| {
            // An expired deadline (Chrome stopped/stuck) is `navigate_timeout`, not a failure.
            if error.starts_with(CDP_TIMEOUT_PREFIX) {
                NavigateError::TimedOut
            } else {
                NavigateError::Failed(error)
            }
        })?;
        let text = |key: &str| result.get(key).and_then(Value::as_str).map(str::to_string);
        // Chrome's proxy errors become the same sentence the relay uses, so a direct-route
        // failure is not reported as a generic page error.
        let error_text = text("errorText").map(|raw| {
            crate::relay::chrome_proxy_failure(&raw).map(str::to_string).unwrap_or(raw)
        });
        let mut loaded = false;
        if error_text.is_none() && wait_load {
            let deadline = started + budget;
            while Instant::now() < deadline {
                if self.page_load_events > before {
                    loaded = true;
                    break;
                }
                self.pump_socket(socket, Duration::from_millis(100));
                // The channel closed (Chrome exited or a message above the cap): there is
                // no load event left to wait for; without this the loop spins until the deadline.
                if socket.is_closed() && self.page_load_events <= before {
                    let why = socket
                        .abnormal_close_reason()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default();
                    return Err(NavigateError::Failed(format!(
                        "the CDP closed during navigate{why}; the capture ended"
                    )));
                }
            }
            // One last look: the event may have arrived in the last pump.
            loaded = loaded || self.page_load_events > before;
        }
        Ok(NavigateResult {
            frame_id: text("frameId"),
            loader_id: text("loaderId"),
            loaded,
            error_text,
        })
    }
}

#[cfg(test)]
pub(crate) mod testsite {
    //! Minimal HTTP server on loopback for the live tests (std only).
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    pub struct Reply {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Reply {
        pub fn html(body: &str) -> Self {
            Reply {
                status: 200,
                headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
                body: body.to_string(),
            }
        }
        pub fn status(mut self, status: u16) -> Self {
            self.status = status;
            self
        }
        pub fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
    }

    pub struct TestSite {
        pub port: u16,
        /// `"METHOD path"` of each received request, in order.
        pub seen: Arc<Mutex<Vec<String>>>,
    }

    impl TestSite {
        pub fn start<F>(route: F) -> TestSite
        where
            F: Fn(&str, &str) -> Reply + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().unwrap().port();
            let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let route = Arc::new(route);
            let seen_thread = seen.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let route = route.clone();
                    let seen = seen_thread.clone();
                    thread::spawn(move || handle(stream, route, seen));
                }
            });
            TestSite { port, seen }
        }

        pub fn seen_paths(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn handle<F>(mut stream: TcpStream, route: Arc<F>, seen: Arc<Mutex<Vec<String>>>)
    where
        F: Fn(&str, &str) -> Reply,
    {
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0;
        loop {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") || total == buf.len() {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let head = String::from_utf8_lossy(&buf[..total]).to_string();
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("/").to_string();
        seen.lock().unwrap().push(format!("{method} {path}"));
        let reply = route(&method, &path);
        let reason = match reply.status {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            _ => "Status",
        };
        let mut out = format!("HTTP/1.1 {} {}\r\n", reply.status, reason);
        let mut has_len = false;
        for (name, value) in &reply.headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_len = true;
            }
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        if !has_len {
            out.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        }
        out.push_str("Connection: close\r\n\r\n");
        out.push_str(&reply.body);
        let _ = stream.write_all(out.as_bytes());
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::testsite::{Reply, TestSite};
    use super::*;
    use std::path::Path;

    fn config(allowed: &[&str], start_url: Option<&str>) -> BrowserCaptureConfig {
        BrowserCaptureConfig {
            chrome: PathBuf::from("/does/not/exist/chrome"),
            session_dir: std::env::temp_dir().join(format!(
                "scrapelens-bc-test-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            )),
            start_url: start_url.map(str::to_string),
            headless: true,
            allowed_hosts: allowed.iter().map(|s| s.to_string()).collect(),
            third_party_hosts: Vec::new(),
            expose_cdp: false,
            proxy: None,
        }
    }

    #[test]
    fn start_without_allowlist_is_an_error_and_never_spawns() {
        let err = BrowserCapture::start(config(&[], None)).err().expect("error");
        assert_eq!(err.code(), "allowlist_required");
        let err = BrowserCapture::start(config(&["*"], None)).err().expect("error");
        assert_eq!(err.code(), "allowlist_too_broad");
        let err = BrowserCapture::start(config(&["http://example.com"], None))
            .err()
            .expect("error");
        assert_eq!(err.code(), "allowlist_invalid");
    }

    #[test]
    fn start_url_must_pass_the_allowlist() {
        let err = BrowserCapture::start(config(&["a.test"], Some("http://b.test/")))
            .err()
            .expect("error");
        assert_eq!(err.code(), "start_url_not_allowed");
    }

    #[test]
    fn start_refuses_anything_that_is_not_the_stable_chrome() {
        // Nonexistent, system binary and fake script: `browser_invalid`, nothing runs.
        let dir = std::env::temp_dir().join(format!("scrapelens-fakechrome-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("chrome");
        std::fs::write(&script, "#!/bin/sh\ntouch /tmp/sl-start-ran\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for path in [
            PathBuf::from("/does/not/exist/chrome"),
            PathBuf::from("/bin/echo"),
            script.clone(),
        ] {
            let mut cfg = config(&["a.test"], Some("http://a.test/"));
            cfg.chrome = path.clone();
            let err = BrowserCapture::start(cfg).err().expect("error");
            assert_eq!(err.code(), "browser_invalid", "{path:?}: {err}");
        }
        assert!(!Path::new("/tmp/sl-start-ran").exists(), "the fake script must not have run");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn chrome_or_skip() -> PathBuf {
        PathBuf::from(crate::chrome::detect(None).path.expect("Chrome installed"))
    }

    /// `SL_LIVE_HEADED=1` runs the live tests that accept a window (on Linux, under Xvfb).
    fn live_headless() -> bool {
        std::env::var("SL_LIVE_HEADED").as_deref() != Ok("1")
    }

    fn live_config(allowed: Vec<String>, name: &str, expose_cdp: bool) -> BrowserCaptureConfig {
        BrowserCaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: std::env::temp_dir().join(format!(
                "scrapelens-bc-live-{name}-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            )),
            start_url: None,
            headless: live_headless(),
            allowed_hosts: allowed,
            third_party_hosts: Vec::new(),
            expose_cdp,
            proxy: None,
        }
    }

    /// Live cycle on loopback: allowlist on both layers + graceful shutdown. `cargo test --lib live_allowlist_cycle -- --ignored --nocapture`.
    ///
    /// Measured finding (Chrome 156): `MAP * ~NOTFOUND` also denies a literal IP
    /// (`ERR_NAME_NOT_RESOLVED`); what escapes the resolver is the PORT of an
    /// allowed host, and only layer 2 and the report catch that.
    #[test]
    #[ignore]
    fn live_allowlist_cycle() {
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(0);
        static PORT2: AtomicU16 = AtomicU16::new(0);
        let site2 = TestSite::start(|_m, _p| Reply::html("second server"));
        PORT2.store(site2.port, Ordering::SeqCst);
        let site = TestSite::start(|_m, path| match path {
            "/" => {
                let p = PORT.load(Ordering::SeqCst);
                let p2 = PORT2.load(Ordering::SeqCst);
                Reply::html(&format!(
                    "<html><body><h1>ok</h1>\
                     <img src='http://blocked.invalid.test:{p}/b.png'>\
                     <img src='http://127.0.0.1:{p}/ip.png'>\
                     <img src='http://127.1:{p}/ip-short.png'>\
                     <img src='http://2130706433:{p}/ip-decimal.png'>\
                     <img src='http://[::1]:{p}/ip-v6.png'>\
                     <img src='http://localhost:{p2}/other-port.png'></body></html>"
                ))
            }
            _ => Reply::html("x"),
        });
        PORT.store(site.port, Ordering::SeqCst);
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "allowlist", true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        assert!(info.allowlist.resolver_rules.contains("EXCLUDE localhost"));
        let cdp = info.cdp.expect("cdp exposed");
        assert!(cdp.browser_ws.starts_with("ws://127.0.0.1:"));
        assert!(info.browser.version.as_deref().unwrap_or("").contains("Chrome"));

        // Layer 2: refusals before anything is sent.
        for bad in [
            format!("http://127.0.0.1:{port}/"),
            "http://evil.test/".to_string(),
            format!("http://localhost:{}/", port.wrapping_add(1)),
            format!("http://localhost:{port}@evil.test/"),
            "file:///etc/passwd".to_string(),
        ] {
            let err = capture
                .navigate(&bad, true, Duration::from_secs(5))
                .expect_err(&bad);
            assert_eq!(err.code(), "url_not_allowed", "{bad}");
        }
        assert!(site.seen_paths().is_empty(), "nothing may have reached the server");

        let result = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
            .expect("navigate");
        assert!(result.loaded, "{result:?}");
        assert!(result.error_text.is_none());
        thread::sleep(Duration::from_millis(1000));

        let report = capture.stop().expect("stop");
        println!("allowlist: {:#?}", report.allowlist);
        println!("server saw: {:?}; second server saw: {:?}", site.seen_paths(), site2.seen_paths());
        assert!(report.graceful, "encerramento gracioso");
        assert_eq!(report.netlog, "complete");
        assert!(report.requests >= 1);
        let blocked: Vec<&str> = report
            .allowlist
            .blocked_hosts
            .iter()
            .map(|b| b.host.as_str())
            .collect();
        // Layer 1: a name outside the list and a literal IP (any form) do not resolve.
        assert!(blocked.contains(&"blocked.invalid.test"), "{blocked:?}");
        assert!(blocked.contains(&"127.0.0.1"), "{blocked:?}");
        for escaped in ["ip.png", "ip-short.png", "ip-decimal.png", "ip-v6.png", "b.png"] {
            assert!(
                !site.seen_paths().iter().any(|p| p.contains(escaped)),
                "{escaped} reached the server"
            );
        }
        // Measured gap: another PORT of the allowed host goes through the resolver.
        assert!(site2.seen_paths().iter().any(|p| p == "GET /other-port.png"));
        assert!(
            report
                .allowlist
                .violations
                .iter()
                .any(|v| v.url.contains("other-port.png") && v.reason.contains("port")),
            "{:?}",
            report.allowlist
        );
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json"))
                .expect("session.json");
        assert!(session_json.contains("capture.third_party_blocked"));
        assert!(session_json.contains("capture.allowlist_violation"));
    }

    /// Second CDP client (the agent) on the same Chrome, with auto-attach and
    /// `waitForDebuggerOnStart`. Measures whether it coexists with our client
    /// (`docs/16b-mcp-browser.md` §3.5). `cooperative`: resumes the paused
    /// targets; otherwise it never calls `runIfWaitingForDebugger`.
    fn second_cdp_client_scenario(cooperative: bool, name: &str) -> (bool, Vec<String>, String) {
        use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(0);
        let site = TestSite::start(|_m, path| match path {
            "/idle" => Reply::html("<html><body>ocioso</body></html>"),
            "/" => Reply::html(
                "<html><body><h1>agente</h1><script>new Worker('/w.js');</script></body></html>",
            ),
            "/w.js" => Reply {
                status: 200,
                headers: vec![("Content-Type".into(), "application/javascript".into())],
                body: "fetch('/from-worker?m=wk').catch(()=>{});".to_string(),
            },
            _ => Reply::html("x"),
        });
        PORT.store(site.port, Ordering::SeqCst);
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], name, true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        let ws = info.cdp.expect("cdp").browser_ws;

        // The agent connects mid-session: the page is already at a known URL.
        let idle = capture
            .navigate(&format!("http://localhost:{port}/idle"), true, Duration::from_secs(20))
            .expect("navigate idle");
        assert!(idle.loaded);
        let running = Arc::new(AtomicBool::new(true));
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let client_running = running.clone();
        let client_log = log.clone();
        let idle_prefix = format!("http://localhost:{port}/idle");
        let (ready_tx, ready_rx) = channel::<()>();
        let client = thread::spawn(move || {
            let (mut socket, _) = tungstenite::connect(ws.as_str()).expect("second client");
            if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
            }
            let mut next = 0u64;
            let mut send = |socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
                            method: &str,
                            params: Value,
                            session: Option<&str>| {
                next += 1;
                let mut msg = json!({ "id": next, "method": method, "params": params });
                if let Some(s) = session {
                    msg["sessionId"] = json!(s);
                }
                socket
                    .send(tungstenite::Message::Text(msg.to_string().into()))
                    .expect("send");
                next
            };
            // The capture's main page target.
            let id_targets = send(&mut socket, "Target.getTargets", json!({}), None);
            send(&mut socket, "Target.setDiscoverTargets", json!({ "discover": true }), None);
            let mut id_attach = 0u64;
            let mut announced = false;
            while client_running.load(Ordering::SeqCst) {
                let text = match socket.read() {
                    Ok(tungstenite::Message::Text(t)) => t.to_string(),
                    Ok(_) => continue,
                    Err(tungstenite::Error::Io(e))
                        if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
                    {
                        continue
                    }
                    Err(_) => break,
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                if let Some(m) = v.get("method").and_then(Value::as_str) {
                    if m.starts_with("Target.") {
                        client_log.lock().unwrap().push(format!("evento {m} {} {}", v["params"]["targetInfo"]["type"], v["params"]["targetInfo"]["url"]));
                    }
                }
                if v.get("error").is_some() {
                    client_log.lock().unwrap().push(format!("second client: error {}", v["error"]));
                }
                if v.get("id").and_then(Value::as_u64) == Some(id_targets) {
                    let target = v["result"]["targetInfos"]
                        .as_array()
                        .and_then(|a| {
                            a.iter().find(|t| {
                                t["type"] == "page"
                                    && t["url"].as_str().map(|u| u.starts_with(&idle_prefix)).unwrap_or(false)
                            })
                        })
                        .cloned();
                    if let Some(t) = target {
                        id_attach = send(
                            &mut socket,
                            "Target.attachToTarget",
                            json!({ "targetId": t["targetId"], "flatten": true }),
                            None,
                        );
                    }
                } else if v.get("id").and_then(Value::as_u64) == Some(id_attach) && id_attach != 0 {
                    let page_session = v["result"]["sessionId"].as_str().map(str::to_string);
                    if let Some(sid) = &page_session {
                        send(
                            &mut socket,
                            "Target.setAutoAttach",
                            json!({ "autoAttach": true, "flatten": true, "waitForDebuggerOnStart": true }),
                            Some(sid),
                        );
                        send(&mut socket, "Page.enable", json!({}), Some(sid));
                        send(&mut socket, "Network.enable", json!({}), Some(sid));
                        if !announced {
                            announced = true;
                            let _ = ready_tx.send(());
                        }
                    }
                } else if v["method"] == "Target.attachedToTarget" {
                    let kind = v["params"]["targetInfo"]["type"].as_str().unwrap_or("?").to_string();
                    let waiting = v["params"]["waitingForDebugger"].as_bool().unwrap_or(false);
                    client_log
                        .lock()
                        .unwrap()
                        .push(format!("second client: attached {kind} waiting={waiting}"));
                    if waiting && cooperative {
                        if let Some(sid) = v["params"]["sessionId"].as_str() {
                            send(&mut socket, "Runtime.runIfWaitingForDebugger", json!({}), Some(sid));
                        }
                    }
                }
            }
            let _ = socket.close(None);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("second client attached");

        thread::sleep(Duration::from_millis(500));
        let result = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
            .expect("navigate");
        thread::sleep(Duration::from_millis(2500));
        running.store(false, Ordering::SeqCst);
        let _ = client.join();
        let report = capture.stop().expect("stop");
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json"))
                .unwrap_or_default();
        let worker_in_session = session_json.contains("from-worker");
        let worker_hit = site.seen_paths().iter().any(|p| p.contains("/from-worker"));
        let summary = format!(
            "{name}: navigate.loaded={} graceful={} worker_reached_server={} worker_in_session={}",
            result.loaded, report.graceful, worker_hit, worker_in_session
        );
        println!("{summary}");
        let log_lines = log.lock().unwrap().clone();
        for l in &log_lines {
            println!("  {l}");
        }
        (result.loaded && report.graceful && worker_hit && worker_in_session, log_lines, summary)
    }

    /// Scenario A: the agent resumes the targets it paused. Expected: nothing hangs and
    /// the worker is captured by our client.
    #[test]
    #[ignore]
    fn second_cdp_client_cooperative() {
        let (ok, _log, summary) = second_cdp_client_scenario(true, "cooperative");
        assert!(ok, "{summary}");
    }

    /// Scenario B: the agent asks for `waitForDebuggerOnStart` and NEVER resumes. The
    /// result is measured and printed; the only requirement is that the capture does not
    /// hang and shuts down gracefully.
    #[test]
    #[ignore]
    fn second_cdp_client_never_resumes() {
        let (_ok, _log, summary) = second_cdp_client_scenario(false, "never-resumes");
        println!("RESULTADO B: {summary}");
    }

    /// Generates three real sessions (headless Chrome against loopback servers that
    /// IMITATE documented signals) for the end-to-end test of the `recon` crate:
    /// `plain`, `unsolved`, `solved`. Run by `recon/scripts/live_e2e.sh`.
    /// Variable: `SL_RECON_E2E_DIR`.
    #[test]
    #[ignore]
    fn live_recon_scenarios() {
        let root = PathBuf::from(
            std::env::var("SL_RECON_E2E_DIR").expect("SL_RECON_E2E_DIR (output directory)"),
        );
        std::fs::create_dir_all(&root).unwrap();
        for scenario in ["plain", "unsolved", "solved"] {
            let site = TestSite::start(move |_m, path| {
                let route = path.split('?').next().unwrap_or("/");
                match (scenario, route, path.contains("r=1")) {
                    ("plain", "/", _) => Reply::html(
                        "<html><body><h1>ok</h1><script>fetch('/api/list').then(r=>r.text());</script></body></html>",
                    )
                    .header("cf-ray", "8abc123def456-GRU")
                    .header("Set-Cookie", "__cf_bm=SEGREDO-BM-1; Path=/; HttpOnly"),
                    ("plain", "/api/list", _) => Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: "{\"itens\":[1,2,3]}".to_string(),
                    },
                    ("unsolved", "/", _) => Reply::html(
                        "<html><body>Verifying…<script src='https://turnstile.blocked.invalid.test/api.js'></script></body></html>",
                    )
                    .status(403)
                    .header("cf-mitigated", "challenge")
                    .header("cf-ray", "8abc123def456-GRU")
                    .header("Set-Cookie", "cf_chl_rc_ni=1; Path=/"),
                    ("solved", "/", false) => Reply::html(
                        "<html><body>Verifying…<script>setTimeout(()=>location.replace('/?r=1'),50)</script></body></html>",
                    )
                    .status(403)
                    .header("cf-mitigated", "challenge")
                    .header("cf-ray", "8abc123def456-GRU"),
                    ("solved", "/", true) => Reply::html(
                        "<html><body><h1>liberado</h1><script>fetch('/api/data').then(r=>r.text());</script></body></html>",
                    )
                    .header("cf-ray", "8abc123def457-GRU")
                    .header("Set-Cookie", "cf_clearance=SEGREDO-CLEARANCE-9; Path=/; HttpOnly"),
                    ("solved", "/api/data", _) => Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: "{\"ok\":true}".to_string(),
                    },
                    _ => Reply::html("x").status(404),
                }
            });
            let port = site.port;
            let mut config = live_config(vec![format!("localhost:{port}")], scenario, false);
            config.session_dir = root.join(scenario);
            let (capture, _info) = BrowserCapture::start(config).expect("start");
            let result = capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(20))
                .expect("navigate");
            println!("{scenario}: loaded={}", result.loaded);
            thread::sleep(Duration::from_millis(1800));
            let report = capture.stop().expect("stop");
            assert!(report.graceful, "{scenario}");
            println!("{scenario}: {} requests; server saw {:?}", report.requests, site.seen_paths());
        }
    }

    /// The CDP address is only handed out with our client attached to the initial target:
    /// the FIRST action of an external agent (attach to the capture tab and navigate,
    /// without waiting for anything) is already seen by our capture, with the `Network.*`
    /// events of that same tab. Requirement from the lead, derived from finding 5 of
    /// `docs/16b-mcp-browser.md` §3.5.
    #[test]
    #[ignore]
    fn agent_first_action_is_captured() {
        let site = TestSite::start(|_m, path| {
            if path.starts_with("/first") {
                Reply::html("<html><body><img src='/sub.png?m=agent-sub'></body></html>")
            } else {
                Reply::html("x")
            }
        });
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "agent-first", true);
        let (capture, info) = BrowserCapture::start(config).expect("start");
        let access = info.cdp.expect("cdp exposed");
        let target_id = access.page_target_id.clone().expect("capture tab");

        // Agent's immediate action: attaches to the capture tab and navigates.
        let (mut socket, _) = tungstenite::connect(access.browser_ws.as_str()).expect("agent");
        let mut call = |method: &str, params: Value, session: Option<&str>| -> Value {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let mut msg = json!({ "id": id, "method": method, "params": params });
            if let Some(s) = session {
                msg["sessionId"] = json!(s);
            }
            socket.send(tungstenite::Message::Text(msg.to_string().into())).expect("send");
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if let Ok(tungstenite::Message::Text(t)) = socket.read() {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        if v["id"].as_u64() == Some(id) {
                            return v;
                        }
                    }
                }
            }
            panic!("no response to {method}");
        };
        let attached = call(
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
            None,
        );
        let session = attached["result"]["sessionId"].as_str().expect("agent session").to_string();
        let nav = call(
            "Page.navigate",
            json!({ "url": format!("http://localhost:{port}/first?m=agent-first") }),
            Some(&session),
        );
        assert!(nav["result"]["errorText"].is_null(), "{nav}");
        thread::sleep(Duration::from_millis(2000));
        drop(socket);

        let report = capture.stop().expect("stop");
        assert!(report.graceful);
        let cdp_events = std::fs::read_to_string(
            std::path::Path::new(&report.session_dir).join("cdp-events.jsonl"),
        )
        .expect("cdp-events.jsonl");
        let seen_in_cdp = |needle: &str| {
            cdp_events
                .lines()
                .any(|l| l.contains("\"Network.requestWillBeSent\"") && l.contains(needle))
        };
        assert!(seen_in_cdp("m=agent-first"), "the agent's navigation is not in the capture's CDP");
        assert!(seen_in_cdp("m=agent-sub"), "the subresource is not in the capture's CDP");
        println!("server saw: {:?}", site.seen_paths());
    }

    /// The 8 paths of the review PoC (`/tmp/rev25/poc-allow`): with
    /// `localhost:P1` approved, the page reaches `localhost:P2` via a top-level 302,
    /// `location=`, meta refresh, `window.open`, iframe, fetch, WebSocket and an
    /// uppercase host. Official semantics (docs/16b §2.2): the browser enforces the
    /// HOST; the port is only reported. Each of the 8 must appear in
    /// `allowlist.violations`.
    #[test]
    #[ignore]
    fn live_port_gap_is_reported_on_all_paths() {
        use std::sync::atomic::{AtomicU16, Ordering};
        static P2: AtomicU16 = AtomicU16::new(0);
        let site2 = TestSite::start(|_m, _p| Reply::html("other port"));
        P2.store(site2.port, Ordering::SeqCst);
        let site = TestSite::start(|_m, path| {
            let p2 = P2.load(Ordering::SeqCst);
            match path {
                "/" => Reply::html(&format!(
                    "<html><body>ok\
                     <img src='http://LOCALHOST:{p2}/upper.png'>\
                     <iframe src='http://localhost:{p2}/iframe-other-port'></iframe>\
                     <script>try{{new WebSocket('ws://localhost:{p2}/ws-other-port')}}catch(e){{}}\
                     fetch('http://localhost:{p2}/fetch-other-port',{{mode:'no-cors'}});\
                     window.open('http://localhost:{p2}/popup-other-port');</script></body></html>"
                )),
                "/redir" => Reply::html("x")
                    .status(302)
                    .header("Location", &format!("http://localhost:{p2}/redirected-top-level")),
                "/jsloc" => Reply::html(&format!(
                    "<script>location='http://localhost:{p2}/js-location'</script>"
                )),
                "/meta" => Reply::html(&format!(
                    "<meta http-equiv=refresh content='0;url=http://localhost:{p2}/meta-refresh'>"
                )),
                _ => Reply::html("x"),
            }
        });
        let p1 = site.port;
        let config = live_config(vec![format!("localhost:{p1}")], "port-gap", false);
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        for path in ["/", "/redir", "/jsloc", "/meta"] {
            let _ = capture.navigate(&format!("http://localhost:{p1}{path}"), true, Duration::from_secs(10));
            thread::sleep(Duration::from_millis(1500));
        }
        let report = capture.stop().expect("stop");
        let p2 = site2.port;
        println!("P2 saw: {:?}", site2.seen_paths());
        println!("violations: {:#?}", report.allowlist.violations.iter().map(|v| (&v.url, &v.reason)).collect::<Vec<_>>());
        let urls: Vec<String> = report.allowlist.violations.iter().map(|v| v.url.clone()).collect();
        for path in [
            "redirected-top-level",
            "js-location",
            "meta-refresh",
            "popup-other-port",
            "iframe-other-port",
            "fetch-other-port",
            "ws-other-port",
            "upper.png",
        ] {
            let scheme = if path == "ws-other-port" { "ws" } else { "http" };
            let expected = format!("{scheme}://localhost:{p2}/{path}");
            assert!(urls.contains(&expected), "path {path} was not reported: {urls:?}");
            let v = report.allowlist.violations.iter().find(|v| v.url == expected).unwrap();
            assert!(v.reason.contains(&format!("port {p2}")), "{}", v.reason);
        }
        // The gap is real and documented: the browser let it through (host allowed).
        for path in ["/redirected-top-level", "/js-location", "/meta-refresh", "/fetch-other-port", "/upper.png"] {
            assert!(
                site2.seen_paths().iter().any(|p| p == &format!("GET {path}")),
                "the PoC expected {path} to reach P2: {:?}",
                site2.seen_paths()
            );
        }
        // What is on the approved port is not a violation; session warnings do not leak queries.
        assert!(!urls.iter().any(|u| u.contains(&format!("localhost:{p1}"))));
        assert!(report.warnings.iter().all(|w| !w.contains('?') || w.contains("?…")));
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
        assert!(session_json.contains("capture.allowlist_violation"));
    }

    /// Review PoC (`/tmp/rev25/poc-fs/poc_capture_symlink.py`): symlinks
    /// planted in the session folder, before (`netlog.json`, `cdp-bodies.jsonl`) and
    /// during the capture (`cdp-events.jsonl`), pointing to files outside it.
    /// No target may receive data or change mode.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_planted_symlinks_are_not_followed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let mut config = live_config(vec![format!("localhost:{port}")], "symlinks", false);
        let dir = config.session_dir.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("scrapelens-symlink-poc-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let targets: Vec<PathBuf> = ["netlog", "bodies", "events"].iter().map(|n| outside.join(n)).collect();
        for t in &targets {
            std::fs::write(t, "ORIGINAL\n").unwrap();
            std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        symlink(&targets[0], dir.join("netlog.json")).unwrap();
        symlink(&targets[1], dir.join("cdp-bodies.jsonl")).unwrap();
        config.session_dir = dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        // During the capture: the final file does not exist yet, plant the link.
        symlink(&targets[2], dir.join("cdp-events.jsonl")).unwrap();
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        thread::sleep(Duration::from_millis(500));
        let report = capture.stop().expect("stop");
        for t in &targets {
            assert_eq!(std::fs::read_to_string(t).unwrap(), "ORIGINAL\n", "{t:?} received data");
            assert_eq!(std::fs::metadata(t).unwrap().permissions().mode() & 0o777, 0o644, "{t:?}");
        }
        for name in ["netlog.json", "cdp-bodies.jsonl", "cdp-events.jsonl"] {
            let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
            assert!(meta.file_type().is_file(), "{name} should be a regular file");
        }
        let events = std::fs::read_to_string(dir.join("cdp-events.jsonl")).unwrap();
        assert!(events.contains("Network.requestWillBeSent"));
        assert!(std::fs::metadata(dir.join("netlog.json")).unwrap().len() > 1000);
        assert!(report.requests >= 1);
        let _ = std::fs::remove_dir_all(outside);
    }

    /// Review PoC (`poc_netlog_race.py`, R3): a process of the same user
    /// swaps `netlog.json` in the session folder for a symlink during the capture.
    /// Chrome now writes the NetLog to the private profile, so the link target cannot
    /// receive any byte, and the final `netlog.json` is a regular file.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_netlog_swap_race_does_not_write_through_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "netlog-race", false);
        let dir = config.session_dir.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("scrapelens-netlog-race-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let swaps = Arc::new(AtomicUsize::new(0));
        let attacker = {
            let (dir, victim, done, swaps) = (dir.clone(), victim.clone(), done.clone(), swaps.clone());
            thread::spawn(move || {
                let path = dir.join("netlog.json");
                while !done.load(Ordering::SeqCst) {
                    // The PoC's attack, in both forms: the file exists and is not a
                    // link -> swap; the name is free -> plant the link (a Chrome that
                    // opened that path would write to the target).
                    match std::fs::symlink_metadata(&path) {
                        Ok(m) if !m.file_type().is_symlink() => {
                            if std::fs::remove_file(&path).is_ok() && symlink(&victim, &path).is_ok() {
                                swaps.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::NotFound
                                && symlink(&victim, &path).is_ok() =>
                        {
                            swaps.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            })
        };
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        thread::sleep(Duration::from_millis(800));
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL\n",
            "the NetLog leaked to the link target DURING the capture"
        );
        // The attacker acts during the capture (like the PoC); after `stop` it could
        // only make the final write fail (link refusal), never leak.
        done.store(true, Ordering::SeqCst);
        attacker.join().unwrap();
        let report = capture.stop().expect("stop");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n", "target altered");
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        let meta = std::fs::symlink_metadata(dir.join("netlog.json")).unwrap();
        assert!(meta.file_type().is_file(), "final netlog.json must be a regular file");
        assert!(meta.len() > 1000, "the NetLog reached the session ({} bytes)", meta.len());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(report.requests >= 1);
        eprintln!("swaps attempted by the attacker: {}", swaps.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(outside);
    }

    /// First path that exists (`lsof` lives in /usr/sbin on macOS and in /usr/bin on Linux).
    fn tool_path(candidates: &[&'static str]) -> &'static str {
        candidates.iter().copied().find(|p| std::path::Path::new(p).exists()).unwrap_or(candidates[0])
    }

    fn lsof_listen(pid: u32) -> String {
        let out = std::process::Command::new(tool_path(&["/usr/sbin/lsof", "/usr/bin/lsof"]))
            .args(["-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-p", &pid.to_string()])
            .output()
            .expect("lsof");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn process_args(pid: u32) -> String {
        let out = std::process::Command::new(tool_path(&["/bin/ps", "/usr/bin/ps"]))
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Review item 5: without `expose_cdp` Chrome opens no port at all
    /// (`--remote-debugging-pipe`); with `expose_cdp` the port listens ONLY on
    /// 127.0.0.1 and refuses WebSocket from a web page (Origin present).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_pipe_opens_no_port_and_exposed_port_is_loopback_only() {
        use std::io::{Read, Write};
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        // 1. Pipe: no port, no --remote-debugging-port.
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "pipe", false)).expect("start");
        assert!(info.cdp.is_none());
        let args = process_args(info.chrome_pid);
        assert!(args.contains("--remote-debugging-pipe"), "{args}");
        assert!(!args.contains("--remote-debugging-port"), "{args}");
        assert!(lsof_listen(info.chrome_pid).trim().is_empty(), "Chrome opened a port: {}", lsof_listen(info.chrome_pid));
        let nav = capture
            .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10))
            .expect("navigate");
        assert!(nav.loaded);
        let report = capture.stop().expect("stop");
        assert!(report.graceful && report.netlog == "complete");
        // 2. Exposed port: only 127.0.0.1, without --remote-allow-origins.
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "port", true)).expect("start");
        let access = info.cdp.clone().expect("cdp exposed");
        let args = process_args(info.chrome_pid);
        assert!(args.contains("--remote-debugging-address=127.0.0.1"), "{args}");
        assert!(!args.contains("--remote-allow-origins"), "{args}");
        assert!(!args.contains("--remote-debugging-pipe"), "{args}");
        let listen = lsof_listen(info.chrome_pid);
        println!("lsof:\n{listen}");
        let names: Vec<&str> = listen.lines().skip(1).filter_map(|l| l.split_whitespace().nth(8)).collect();
        assert!(!names.is_empty(), "expected a debugging port: {listen}");
        for n in &names {
            assert!(n.starts_with("127.0.0.1:"), "listening outside the loopback: {n}");
        }
        // WebSocket from a web page (Origin) is refused; without Origin it is accepted.
        let ws_path = access.browser_ws.split_once("127.0.0.1:").unwrap().1;
        let (port_s, path) = ws_path.split_once('/').unwrap();
        let handshake = |origin: Option<&str>| -> String {
            let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port_s}")).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let origin_line = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
            write!(
                s,
                "GET /{path} HTTP/1.1\r\nHost: 127.0.0.1:{port_s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{origin_line}\r\n"
            )
            .unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string()
        };
        let evil = handshake(Some("https://evil.example"));
        let plain = handshake(None);
        println!("with Origin: {evil:?}; without Origin: {plain:?}");
        assert!(!evil.contains("101"), "web page got the WebSocket: {evil}");
        assert!(plain.contains("101"), "client without Origin should connect: {plain}");
        let _ = capture.stop().expect("stop");
    }

    /// R9: a descriptor inherited from the launcher, WITHOUT CLOEXEC, must not reach
    /// Chrome (neither the main process nor the helpers), with pipe or with port;
    /// in pipe mode, only fds 3 and 4 of the CDP exist.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_inherited_fds_do_not_leak_into_chrome() {
        use std::ffi::CString;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let secret = std::env::temp_dir().join(format!("launcher-secret-{}.log", std::process::id()));
        let c_path = CString::new(secret.to_str().unwrap()).unwrap();
        // SAFETY: plain `open`, without O_CLOEXEC: reproduces the PoC's fd 7.
        let leaked = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600) };
        assert!(leaked >= 0);
        // High number and without CLOEXEC (F_DUPFD), far from the pipe's 3 and 4.
        // SAFETY: `fcntl`/`close` on the freshly opened fd.
        let leaked = unsafe {
            let high = libc::fcntl(leaked, libc::F_DUPFD, 20);
            libc::close(leaked);
            high
        };
        assert!(leaked >= 20);
        let children = |expose: bool, tag: &str| {
            let (capture, info) =
                BrowserCapture::start(live_config(vec![format!("localhost:{port}")], tag, expose)).expect("start");
            let nav = capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10))
                .expect("navigate");
            assert!(nav.loaded);
            // Main process and descendants (helpers).
            let ps = std::process::Command::new(tool_path(&["/bin/ps", "/usr/bin/ps"])).args(["-axo", "pid=,ppid="]).output().unwrap();
            let ps = String::from_utf8_lossy(&ps.stdout).to_string();
            let mut pids = vec![info.chrome_pid];
            for line in ps.lines() {
                let mut it = line.split_whitespace().map(|v| v.parse::<u32>().unwrap_or(0));
                if let (Some(pid), Some(ppid)) = (it.next(), it.next()) {
                    if ppid == info.chrome_pid {
                        pids.push(pid);
                    }
                }
            }
            for pid in &pids {
                let out = std::process::Command::new(tool_path(&["/usr/sbin/lsof", "/usr/bin/lsof"])).args(["-n", "-P", "-p", &pid.to_string()]).output().unwrap();
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                assert!(!text.contains("launcher-secret"), "fd leaked to pid {pid} ({tag}):\n{text}");
            }
            let _ = capture.stop().expect("stop");
        };
        children(false, "fds-pipe");
        children(true, "fds-port");
        // SAFETY: closes the fd opened above.
        unsafe { libc::close(leaked) };
        let _ = std::fs::remove_file(secret);
    }

    #[test]
    fn r12_navigate_budget_has_a_floor_and_never_adds_the_old_40_seconds() {
        assert_eq!(navigate_budget(Duration::from_millis(100)), MIN_NAVIGATE_BUDGET);
        assert_eq!(navigate_budget(Duration::from_secs(3)), Duration::from_secs(3));
        assert!(
            navigate_budget(Duration::from_secs(3)) + NAVIGATE_REPLY_MARGIN < Duration::from_secs(10),
            "the PoC took 30.4 s with timeout_ms=3000"
        );
        assert_eq!(NavigateError::TimedOut.code(), "navigate_timeout");
    }

    /// R12 (PoC `poc_sigstop`): with Chrome STOPPED (SIGSTOP), `navigate` with
    /// `timeout_ms=3000` returned in 30.4 s. Now it honors the deadline.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_navigate_honours_its_timeout_when_chrome_is_frozen() {
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let (capture, info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], "sigstop", false)).expect("start");
        let pid = info.chrome_pid as i32;
        // SAFETY: signals to the process we started ourselves.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let started = Instant::now();
        let result = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_millis(3000));
        let elapsed = started.elapsed();
        // SAFETY: same; resume before any assertion so Chrome can exit.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        println!("navigate with Chrome stopped: {result:?} in {elapsed:?}");
        assert!(
            matches!(result, Err(NavigateError::TimedOut)),
            "with the deadline expired the code is navigate_timeout: {result:?}"
        );
        assert!(elapsed < Duration::from_secs(9), "took {elapsed:?}; the deadline was 3 s + slack");
        let _ = capture.stop();
    }

    /// A3-B2 (PoC `r12_cap.py`): an allowed page does a `console.log` of 140 MB.
    /// The message exceeds the pipe cap: the capture must come out INCOMPLETE with an
    /// explicit reason, and `navigate` must not wait for the whole deadline.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_oversized_pipe_message_marks_the_capture_incomplete() {
        oversized_message_marks_the_capture_incomplete(false, "oversize");
    }

    /// A4-B2: the same in port mode (`expose_cdp`, WebSocket).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_oversized_websocket_message_marks_the_capture_incomplete() {
        oversized_message_marks_the_capture_incomplete(true, "oversize-ws");
    }

    #[cfg(unix)]
    fn oversized_message_marks_the_capture_incomplete(expose: bool, tag: &str) {
        let site = TestSite::start(|_m, path| {
            if path == "/favicon.ico" {
                return Reply::html("").status(404);
            }
            Reply::html("<html><body><script>console.log('x'.repeat(140e6))</script>ok</body></html>")
        });
        let port = site.port;
        let (capture, _info) =
            BrowserCapture::start(live_config(vec![format!("localhost:{port}")], tag, expose)).expect("start");
        let started = Instant::now();
        let nav = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(45));
        let elapsed = started.elapsed();
        println!("navigate: {nav:?} em {elapsed:?}");
        assert!(elapsed < Duration::from_secs(40), "waited the whole deadline: {elapsed:?}");
        let report = capture.stop().expect("stop");
        println!("stop: graceful={} netlog={} warnings={:?}", report.graceful, report.netlog, report.warnings);
        assert!(!report.graceful);
        assert!(
            report.warnings.iter().any(|w| w.contains("cdp_transport_closed: frame_too_large")),
            "{:?}",
            report.warnings
        );
        let session_json =
            std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
        assert!(session_json.contains("cdp_transport_closed: frame_too_large"));
        let doc: serde_json::Value = serde_json::from_str(&session_json).unwrap();
        let state = doc["session"]["completeness"]["state"].as_str().unwrap_or("?").to_string();
        println!("completeness.state = {state}");
        assert_ne!(state, "complete", "the session must not come out complete");
    }

    /// A4-B5 (PoC `n_newsurface.py`, dirswap): the session folder is swapped for a
    /// symlink to OUT during the capture. Stop fails with a clear error, nothing is
    /// written to OUT, OUT's links are not removed and the data stays in the
    /// temporary profile.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_swapped_session_dir_fails_the_stop_without_touching_outside() {
        use std::os::unix::fs::symlink;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "dirswap", false);
        let dir = config.session_dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        // Swap the folder for a link to OUT (which contains links to a target).
        let out = std::env::temp_dir().join(format!("scrapelens-dirswap-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let victim = out.join("VICTIM.txt");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        for name in ["netlog.json", "session.json"] {
            symlink(&victim, out.join(name)).unwrap();
        }
        let moved = dir.with_file_name(format!("{}-orig", dir.file_name().unwrap().to_string_lossy()));
        std::fs::rename(&dir, &moved).unwrap();
        symlink(&out, &dir).unwrap();
        let result = capture.stop();
        let error = result.expect_err("stop should fail with the folder swapped");
        println!("error: {error}");
        assert!(error.contains("The session directory was swapped"), "{error}");
        assert!(error.contains("now a symbolic link"), "{error}");
        assert!(error.contains("rescue folder"), "{error}");
        // OUT intact: same 3 names, links not removed, target unchanged.
        let mut names: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["VICTIM.txt", "netlog.json", "session.json"]);
        for name in ["netlog.json", "session.json"] {
            assert!(std::fs::symlink_metadata(out.join(name)).unwrap().file_type().is_symlink(), "{name} mexido");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "ORIGINAL\n");
        // The data stayed in the rescue folder named in the error: only the capture
        // files, nothing from the Chrome profile.
        let rescue = rescue_dir_from(&error);
        assert!(rescue.join("cdp-events.jsonl").is_file(), "no cdp-events in {}", rescue.display());
        assert!(rescue.join("netlog.json").is_file());
        assert_no_chrome_profile_data(&rescue);
        let _ = std::fs::remove_dir_all(&rescue);
        let _ = std::fs::remove_file(rescue.with_extension("json"));
        let _ = std::fs::remove_dir_all(out);
        let _ = std::fs::remove_dir_all(moved);
        let _ = std::fs::remove_file(dir);
    }

    /// Rescue folder named in the stop error.
    fn rescue_dir_from(error: &str) -> PathBuf {
        let after = error.split("rescue folder ").nth(1).expect("error cites the rescue folder");
        PathBuf::from(after.split(" (0700").next().unwrap().trim())
    }

    /// The rescue has only the capture files: no Chrome profile data.
    fn assert_no_chrome_profile_data(dir: &std::path::Path) {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for name in &names {
            assert!(
                ["cdp-bodies.jsonl", "cdp-events.jsonl", "motivo.txt", "netlog.json"].contains(&name.as_str()),
                "unexpected file in the rescue: {name} (all: {names:?})"
            );
        }
        for forbidden in ["Cookies", "Login Data", "History", "Default", "Local State"] {
            assert!(!names.iter().any(|n| n == forbidden), "{forbidden} in the rescue");
        }
    }

    /// A5-B2: a write failure with the folder still ours (here, a DIRECTORY named
    /// `session.json`, which the core refuses) also rescues the data, does not delete
    /// the profile first, and leaves no `.tmp-*` in the session folder.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_any_write_failure_rescues_the_capture_files() {
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>ok</body></html>"));
        let port = site.port;
        let config = live_config(vec![format!("localhost:{port}")], "writefail", false);
        let dir = config.session_dir.clone();
        let (capture, _info) = BrowserCapture::start(config).expect("start");
        let _ = capture.navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(10));
        std::fs::create_dir(dir.join("session.json")).unwrap();
        let error = capture.stop().expect_err("the core refuses a directory in place of session.json");
        println!("error: {error}");
        assert!(error.contains("rescue folder"), "{error}");
        let rescue = rescue_dir_from(&error);
        assert!(rescue.join("cdp-events.jsonl").is_file());
        assert!(rescue.join("netlog.json").is_file());
        assert!(rescue.join("cdp-bodies.jsonl").is_file(), "the bodies are also rescued");
        assert!(rescue.join("motivo.txt").is_file());
        assert_no_chrome_profile_data(&rescue);
        // No stray `.tmp-*` left in the session folder.
        let strays: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp-"))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
        // Rescue marker exists in the state root.
        let marker = rescue.with_extension("json");
        assert!(marker.is_file(), "no marker {}", marker.display());
        let _ = std::fs::remove_dir_all(&rescue);
        let _ = std::fs::remove_file(marker);
    }

    /// COMMON capture (`crate::run`) against a local server accessed by a NAME that
    /// is neither `127.0.0.1` nor `localhost` (`<name>.localhost`, which Chrome resolves
    /// to loopback on its own). Returns `(site requests seen by the server,
    /// statuses of the session's requests for the name)`.
    #[cfg(unix)]
    fn run_common_capture(mode: crate::NetworkMode, tag: &str) -> (usize, Vec<u64>) {
        use std::sync::mpsc::channel;
        let site = TestSite::start(|_m, _p| Reply::html("<html><body>aberto</body></html>"));
        let port = site.port;
        let name = "sl-open-mode.localhost";
        let dir = std::env::temp_dir().join(format!(
            "scrapelens-open-{tag}-{}-{}",
            std::process::id(),
            super::super::unix_millis()
        ));
        let config = crate::CaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: dir.clone(),
            start_url: format!("http://{name}:{port}/"),
            headless: true,
            ignore_cert: false,
            network: mode,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let join = thread::spawn(move || crate::run(config, status, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(40))
            .expect("capture ready")
            .expect("capture started");
        // Waits for the server to see the request (open mode) or gives a deadline (loopback).
        let deadline = Instant::now() + Duration::from_secs(8);
        while site.seen_paths().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }
        thread::sleep(Duration::from_millis(800));
        let _ = stop_tx.send(());
        let outcome = join.join().expect("thread").expect("capture ended");
        let statuses = outcome.session["requests"]
            .as_array()
            .map(|requests| {
                requests
                    .iter()
                    .filter(|r| r["url"].as_str().is_some_and(|u| u.contains(name)))
                    .filter_map(|r| r["status"].as_u64())
                    .collect()
            })
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(dir);
        (site.seen_paths().len(), statuses)
    }

    /// User-reported bug: `Start session` with `https://google.com.br` opened Chrome
    /// with `DNS_PROBE_FINISHED_NXDOMAIN`, because the common capture passed
    /// `--host-resolver-rules=MAP * ~NOTFOUND…`. Without touching a real site: a local name
    /// resolved by Chrome itself loads in open mode and NOT in `LoopbackOnly`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_open_mode_resolves_a_local_name_and_loopback_only_does_not() {
        let (seen_open, statuses_open) = run_common_capture(crate::NetworkMode::Open, "open");
        println!("Open: server saw {seen_open}, status {statuses_open:?}");
        assert!(seen_open >= 1, "open mode should reach the server by the local name");
        assert!(statuses_open.contains(&200), "{statuses_open:?}");

        let (seen_lo, statuses_lo) = run_common_capture(crate::NetworkMode::LoopbackOnly, "loopback");
        println!("LoopbackOnly: server saw {seen_lo}, status {statuses_lo:?}");
        assert_eq!(seen_lo, 0, "the local name must not resolve in LoopbackOnly");
        assert!(!statuses_lo.contains(&200), "{statuses_lo:?}");
    }

    /// Local probe page: records `navigator.webdriver` on the server (`/wd?webdriver=…`).
    #[cfg(unix)]
    fn webdriver_probe_site() -> TestSite {
        TestSite::start(|_m, path| {
            if path.starts_with("/wd") || path == "/favicon.ico" {
                return Reply::html("").status(204);
            }
            Reply::html(
                "<html><body><script>fetch('/wd?webdriver='+navigator.webdriver)</script>sonda</body></html>",
            )
        })
    }

    #[cfg(unix)]
    fn webdriver_seen(site: &TestSite) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen: Vec<String> = site
                .seen_paths()
                .into_iter()
                .filter_map(|p| p.split("/wd?webdriver=").nth(1).map(str::to_string))
                .collect();
            if !seen.is_empty() || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// D7, FULL COMMON capture (`run`/`run_with_options`) on both transports: the
    /// page reads `navigator.webdriver === false` (without the flag it would be `true` with
    /// CDP on) and the session records the flag in `capture.chromeArgs`/`notes`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_full_capture_hides_navigator_webdriver_on_both_transports() {
        use std::sync::mpsc::channel;
        for (transport, tag) in [(crate::transport::CdpTransport::Pipe, "pipe"), (crate::transport::CdpTransport::Port, "port")] {
            let site = webdriver_probe_site();
            let dir = std::env::temp_dir().join(format!(
                "scrapelens-d7-{tag}-{}-{}",
                std::process::id(),
                super::super::unix_millis()
            ));
            let config = crate::CaptureConfig {
                chrome: chrome_or_skip(),
                session_dir: dir.clone(),
                start_url: format!("http://127.0.0.1:{}/", site.port),
                headless: live_headless(),
                ignore_cert: false,
                network: crate::NetworkMode::LoopbackOnly,
                cookie_source: None,
                initial_cookies: Vec::new(),
                proxy: None,
                test_proxy_bypass_loopback: false,
            };
            let status = Arc::new(Mutex::new(CaptureStatus::default()));
            let (stop_tx, stop_rx) = channel();
            let (ready_tx, ready_rx) = channel();
            let opts = crate::RunOptions { transport, ..crate::RunOptions::default() };
            let join = thread::spawn(move || crate::run_with_options(config, status, stop_rx, ready_tx, &opts));
            ready_rx.recv_timeout(Duration::from_secs(40)).expect("ready").expect("started");
            let seen = webdriver_seen(&site);
            println!("{tag}: navigator.webdriver seen by the page = {seen:?}");
            assert_eq!(seen, ["false"], "{tag}: the full capture should hide navigator.webdriver");
            let _ = stop_tx.send(());
            let (outcome, _) = join.join().expect("thread").expect("ended");
            let capture = &outcome.session["session"]["capture"];
            let args: Vec<&str> = capture["chromeArgs"].as_array().expect("chromeArgs").iter().filter_map(|v| v.as_str()).collect();
            assert!(args.contains(&"--disable-blink-features=AutomationControlled"), "{tag}: {args:?}");
            assert_eq!(args.contains(&"--remote-debugging-pipe"), tag == "pipe", "{tag}: {args:?}");
            assert!(capture["notes"].as_str().unwrap_or("").contains("AutomationControlled"), "{capture}");
            // The record does not leak temporary paths.
            assert!(args.iter().all(|a| !a.contains(&*dir.display().to_string())), "{args:?}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Imported cookies (`CaptureConfig.initial_cookies`) reach the FIRST request
    /// of the initial navigation, and the audit event enters the CDP stream
    /// without the values. Loopback, headless per `SL_LIVE_HEADED`.
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_imported_cookies_are_sent_with_the_first_navigation() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc::channel;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let heads_thread = heads.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = vec![0u8; 16 * 1024];
                let mut total = 0;
                while total < buf.len() {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                heads_thread
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..total]).to_string());
                let body = b"ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });

        let dir = std::env::temp_dir().join(format!(
            "scrapelens-cookies-live-{}-{}",
            std::process::id(),
            super::super::unix_millis()
        ));
        let cookie = crate::cookies::ImportedCookie {
            name: "sid".to_string(),
            value: "abc123".to_string(),
            domain: "127.0.0.1".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: Some("Lax".to_string()),
            expires: None,
        };
        let config = crate::CaptureConfig {
            chrome: chrome_or_skip(),
            session_dir: dir.clone(),
            start_url: format!("http://127.0.0.1:{port}/"),
            headless: live_headless(),
            ignore_cert: false,
            network: crate::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: vec![cookie],
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let status = Arc::new(Mutex::new(CaptureStatus::default()));
        let (stop_tx, stop_rx) = channel();
        let (ready_tx, ready_rx) = channel();
        let join = thread::spawn(move || crate::run(config, status, stop_rx, ready_tx));
        ready_rx.recv_timeout(Duration::from_secs(40)).expect("ready").expect("started");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_cookie = false;
        while Instant::now() < deadline && !saw_cookie {
            saw_cookie = heads
                .lock()
                .unwrap()
                .iter()
                .any(|head| head.lines().any(|line| line.eq_ignore_ascii_case("cookie: sid=abc123")));
            thread::sleep(Duration::from_millis(100));
        }
        assert!(saw_cookie, "the first request should carry the imported cookie: {:?}", heads.lock().unwrap());
        let _ = stop_tx.send(());
        let outcome = join.join().expect("thread").expect("ended");
        assert!(outcome.notice.contains("cookie(s) imported"), "{}", outcome.notice);
        let events = std::fs::read_to_string(dir.join("cdp-events.jsonl")).unwrap();
        assert!(events.contains("Capture.cookiesImported"), "the audit event is missing");
        assert!(events.contains("\"importedCount\":1"), "{events}");
        let audit = events
            .lines()
            .find(|line| line.contains("Capture.cookiesImported"))
            .expect("linha de auditoria");
        assert!(!audit.contains("abc123"), "the audit event must not record the value: {audit}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// D7, MCP CONTROLLED capture (allowlist), pipe and `expose_cdp` (port).
    #[cfg(unix)]
    #[test]
    #[ignore]
    fn live_controlled_capture_hides_navigator_webdriver_on_both_transports() {
        for (expose, tag) in [(false, "pipe"), (true, "port")] {
            let site = webdriver_probe_site();
            let port = site.port;
            let (capture, _info) =
                BrowserCapture::start(live_config(vec![format!("localhost:{port}")], &format!("d7-{tag}"), expose)).expect("start");
            capture
                .navigate(&format!("http://localhost:{port}/"), true, Duration::from_secs(15))
                .expect("navigate");
            let seen = webdriver_seen(&site);
            println!("controlled {tag}: navigator.webdriver = {seen:?}");
            assert_eq!(seen, ["false"], "controlled/{tag}");
            let report = capture.stop().expect("stop");
            let session_json = std::fs::read_to_string(std::path::Path::new(&report.session_dir).join("session.json")).unwrap();
            assert!(session_json.contains("--disable-blink-features=AutomationControlled"), "{tag}");
        }
    }

    #[test]
    fn test_site_serves_and_records() {
        let site = TestSite::start(|_m, path| Reply::html(&format!("<p>{path}</p>")).header("X-T", "1"));
        let mut s = std::net::TcpStream::connect(("127.0.0.1", site.port)).unwrap();
        use std::io::{Read, Write};
        s.write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK"));
        assert!(out.contains("X-T: 1"));
        assert_eq!(site.seen_paths(), vec!["GET /a"]);
    }
}
