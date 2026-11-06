//! Live captures controlled by the server: the `capture_id` → capture map,
//! request validation, the confirmation decision and the masked output.
//!
//! The browser sits behind [`CaptureBackend`]/[`LiveCapture`]: the product uses
//! `scrapelens-capture` ([`RealBackend`]); the tests use a fake browser.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use schemars::JsonSchema;
use scrapelens_capture::allowlist::Allowlist;
use scrapelens_capture::browser::{
    BrowserCapture, BrowserCaptureConfig, NavigateError, NavigateResult, StartError, StartInfo,
    StopReport, SENSITIVE_NOTICE,
};
use scrapelens_capture::CaptureStatus;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::valid_name;
use crate::error::ToolError;
use crate::registry::Ctx;

pub const DEFAULT_NAVIGATE_TIMEOUT_MS: u64 = 15_000;
pub const MAX_NAVIGATE_TIMEOUT_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// browser behind a trait
// ---------------------------------------------------------------------------

pub trait LiveCapture: Send {
    fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError>;
    fn status(&self) -> CaptureStatus;
    /// Graceful shutdown; writes the session to `session_dir`.
    fn stop(self: Box<Self>) -> Result<StopReport, String>;
}

pub trait CaptureBackend: Send + Sync {
    /// Called once when the server starts (cleans up orphaned captures left by
    /// earlier runs that died without closing Chrome).
    fn startup(&self) {}

    /// Chrome that would be used (explicit `binary_path` or detection).
    fn resolve_chrome(&self, binary_path: Option<&str>) -> Result<PathBuf, ToolError>;
    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError>;
}

pub struct RealBackend;

impl LiveCapture for BrowserCapture {
    fn navigate(
        &self,
        url: &str,
        wait_load: bool,
        timeout: Duration,
    ) -> Result<NavigateResult, NavigateError> {
        BrowserCapture::navigate(self, url, wait_load, timeout)
    }

    fn status(&self) -> CaptureStatus {
        BrowserCapture::status(self)
    }

    fn stop(self: Box<Self>) -> Result<StopReport, String> {
        BrowserCapture::stop(*self)
    }
}

impl CaptureBackend for RealBackend {
    fn startup(&self) {
        let report = scrapelens_capture::cleanup_orphans(&scrapelens_capture::default_state_root());
        if report.processes_killed + report.profiles_removed + report.markers_removed > 0 {
            eprintln!(
                "scrapelens-mcp: orphans from earlier runs cleaned up (processes {}, profiles {}, markers {})",
                report.processes_killed, report.profiles_removed, report.markers_removed
            );
        }
    }

    fn resolve_chrome(&self, binary_path: Option<&str>) -> Result<PathBuf, ToolError> {
        // Only stable Chrome (bundle, version and Google signature): any
        // `binary_path` (`/bin/echo`, a script) is refused.
        let explicit = binary_path
            .filter(|path| !path.trim().is_empty())
            .map(std::path::Path::new);
        scrapelens_capture::chrome::resolve_stable_chrome(explicit)
            .map(|chrome| chrome.binary)
            .map_err(|error| ToolError::new(error.code(), error.to_string()))
    }

    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError> {
        let (capture, info) = BrowserCapture::start(config)?;
        Ok((Box::new(capture), info))
    }
}

// ---------------------------------------------------------------------------
// parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartCaptureParams {
    /// Hosts the agent may navigate to (required, at least one). Exact name,
    /// `*.domain` or explicit IP literal; optional port (`host:8080`).
    pub allowed_hosts: Vec<String>,
    /// Additional hosts the page must load (CDN, challenges).
    pub third_party_hosts: Option<Vec<String>>,
    /// Start URL (must pass the allowlist).
    pub start_url: Option<String>,
    /// Chrome path; default: automatic detection.
    pub binary_path: Option<String>,
    /// Chrome without a window (default false).
    pub headless: Option<bool>,
    /// Passes the loopback CDP address to the agent (default false).
    pub expose_cdp: Option<bool>,
    /// Optional proxy: `http://`, `https://`, `socks5://`, `socks5h://`, `host:port`, or
    /// `host:port:user:pass`. `"env"` reads the link from the server's
    /// `SCRAPELENS_PROXY_URL`, so a password never passes through the model. Recommended
    /// whenever the proxy has credentials. The confirmation shows only the address.
    pub proxy: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NavigateParams {
    pub capture_id: String,
    /// http(s) URL of an allowed host.
    pub url: String,
    /// `load` (default) or `none`.
    pub wait: Option<String>,
    /// Timeout in ms (default 15000, maximum 60000).
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CaptureIdParams {
    pub capture_id: String,
}

/// Elicitation form: the user explicitly ticks the box.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConfirmStart {
    /// Tick to authorize opening Chrome and capturing the described traffic.
    pub confirmo: bool,
}
rmcp::elicit_safe!(ConfirmStart);

// ---------------------------------------------------------------------------
// confirmation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    Accepted,
    Declined(String),
    Cancelled,
    /// The client does not support (or failed to perform) the elicitation.
    Unavailable(String),
}

/// Resolves the `proxy` parameter. Only `"env"` reads the server's environment, and only
/// when asked. A refusal never includes the link: the link is where the password is.
pub fn resolve_proxy(
    requested: Option<&str>,
) -> Result<Option<scrapelens_capture::proxy::ProxyLink>, ToolError> {
    use scrapelens_capture::proxy::ProxyLink;
    let requested = match requested.map(str::trim).filter(|v| !v.is_empty()) {
        None => return Ok(None),
        Some(value) => value,
    };
    let raw = if requested == "env" {
        std::env::var("SCRAPELENS_PROXY_URL").map_err(|_| {
            ToolError::new(
                "proxy_env_missing",
                "proxy \"env\" was requested, but SCRAPELENS_PROXY_URL is not set on the server",
            )
        })?
    } else {
        requested.to_string()
    };
    ProxyLink::parse(&raw)
        .map(Some)
        .map_err(|e| ToolError::new("proxy_invalid", e.to_string()))
}

/// Applies the policy: without explicit acceptance nothing opens; without
/// elicitation it passes only with `--allow-unconfirmed-capture`. Returns how it was confirmed.
pub fn decide(
    confirmation: &Confirmation,
    allow_unconfirmed: bool,
) -> Result<&'static str, ToolError> {
    match confirmation {
        Confirmation::Accepted => Ok("elicited"),
        Confirmation::Declined(why) => Err(ToolError::new(
            "confirmation_denied",
            format!("the user did not confirm: {why}. Nothing was opened."),
        )),
        Confirmation::Cancelled => Err(ToolError::new(
            "confirmation_denied",
            "the confirmation was cancelled or expired. Nothing was opened.",
        )),
        Confirmation::Unavailable(why) if allow_unconfirmed => {
            let _ = why;
            Ok("unconfirmed-flag")
        }
        Confirmation::Unavailable(why) => Err(ToolError::new(
            "confirmation_unavailable",
            format!(
                "the MCP client does not allow asking for confirmation ({why}); start_capture is refused by default. Nothing was opened. The operator can start the server with --allow-unconfirmed-capture."
            ),
        )),
    }
}

/// Same policy as [`decide`], for a full export. A refusal writes nothing, even
/// when `--allow-sensitive-export` is set. That flag applies only when the
/// client cannot ask.
pub fn decide_sensitive_export(
    confirmation: &Confirmation,
    allow_sensitive_export: bool,
) -> Result<&'static str, ToolError> {
    match confirmation {
        Confirmation::Accepted => Ok("elicited"),
        Confirmation::Declined(why) => Err(ToolError::new(
            "confirmation_denied",
            format!("the user did not confirm: {why}. Nothing was written."),
        )),
        Confirmation::Cancelled => Err(ToolError::new(
            "confirmation_denied",
            "the confirmation was cancelled or expired. Nothing was written.",
        )),
        Confirmation::Unavailable(why) if allow_sensitive_export => {
            let _ = why;
            Ok("unconfirmed-flag")
        }
        Confirmation::Unavailable(why) => Err(ToolError::new(
            "confirmation_unavailable",
            format!(
                "the MCP client does not allow asking for confirmation ({why}); include_sensitive is refused by default. Nothing was written. The operator can start the server with --allow-sensitive-export."
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// mapa de capturas
// ---------------------------------------------------------------------------

struct Running {
    cap: Mutex<Option<Box<dyn LiveCapture>>>,
    /// Session directory name (handle used by the read tools).
    session_handle: String,
}

enum Slot {
    /// Reserved: validation done, waiting for the user's confirmation.
    Starting,
    /// The browser is starting (`backend.start` in progress). `abandoned`:
    /// the caller gave up (cancellation, deadline, disconnect); a capture that
    /// becomes ready is stopped instead of registered.
    Opening {
        abandoned: bool,
    },
    Running(Arc<Running>),
}

pub struct Prepared {
    pub capture_id: String,
    pub session_handle: String,
    pub config: BrowserCaptureConfig,
    pub message: String,
}

pub struct Manager {
    backend: Arc<dyn CaptureBackend>,
    slots: Mutex<HashMap<String, Slot>>,
    /// The server is shutting down: nothing new opens, and whatever is still
    /// starting is closed as soon as the browser responds.
    shutting_down: AtomicBool,
    /// `backend.start` in progress (Chrome may exist before the capture
    /// is registered).
    starts_in_flight: AtomicUsize,
    stops_in_flight: AtomicUsize,
}

fn new_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    format!("cap-{:016x}", hasher.finish())
}

fn strip_path_fields(object: &mut Map<String, Value>) {
    object.remove("sessionDir");
}

impl Manager {
    pub fn new(backend: Arc<dyn CaptureBackend>) -> Self {
        Self {
            backend,
            slots: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            starts_in_flight: AtomicUsize::new(0),
            stops_in_flight: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Validates the request, reserves the single slot and builds the confirmation text.
    /// Nothing is opened here.
    pub fn prepare(&self, ctx: &Ctx, params: StartCaptureParams) -> Result<Prepared, ToolError> {
        let third = params.third_party_hosts.clone().unwrap_or_default();
        let allowlist = Allowlist::new(&params.allowed_hosts, &third)
            .map_err(|e| ToolError::new(e.code(), e.to_string()))?;
        let start_url = params.start_url.clone().filter(|u| !u.trim().is_empty());
        if let Some(url) = &start_url {
            allowlist
                .permits_url(url)
                .map_err(|e| ToolError::new("start_url_not_allowed", format!("start_url: {e}")))?;
        }
        let chrome = self.backend.resolve_chrome(params.binary_path.as_deref())?;
        let headless = params.headless.unwrap_or(false);
        let expose_cdp = params.expose_cdp.unwrap_or(false);
        let proxy = resolve_proxy(params.proxy.as_deref())?;

        let mut slots = self.lock();
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ToolError::new(
                "shutting_down",
                "the server is shutting down",
            ));
        }
        if !slots.is_empty() {
            return Err(ToolError::new(
                "capture_already_running",
                "a capture is already active (or starting); stop it with stop_capture before starting another",
            ));
        }
        let capture_id = new_id();
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let session_handle = format!("capture-{millis}");
        debug_assert!(valid_name(&session_handle));
        let session_dir = ctx.cfg.sessions_dir.join(&session_handle);
        if session_dir.exists() {
            return Err(ToolError::new(
                "exists",
                "session directory already exists; try again",
            ));
        }
        slots.insert(capture_id.clone(), Slot::Starting);

        let list = |hosts: Vec<String>| {
            if hosts.is_empty() {
                "(none)".to_string()
            } else {
                hosts.join(", ")
            }
        };
        let list = |hosts: Vec<String>| escape_display(&list(hosts));
        let message = format!(
            "An agent asked to open Chrome and capture network traffic.\n\
             Allowed hosts (navigate and act): {}\n\
             Third-party hosts allowed: {}\n\
             Start URL: {}\n\
             CDP handed to the agent (browser control): {}\n\
             Mode: {}\n\
             Chrome binary: {}\n\
             Proxy: {}\n\n\
             WARNING about ports: the browser enforces the HOST on all ports; the PORT is only enforced when the agent uses navigate. Approving a host with a port (e.g. localhost:8080) approves, for the page, that host on ANY port (local Redis, admin panels, other services). List only hosts for which this is acceptable.\n\n\
             {}\n\n\
             Tick \"confirmo\" to authorize. Without it nothing is opened.",
            list(allowlist.allowed_hosts()),
            list(allowlist.third_party_hosts()),
            escape_display(
                &start_url
                    .as_deref()
                    .map(strip_query)
                    .unwrap_or_else(|| "(none)".to_string())
            ),
            if expose_cdp {
                "YES — WARNING: the CDP port has no authentication; any local process can control the whole Chrome (all tabs, cookies, open sessions)"
            } else {
                "no"
            },
            if headless {
                "without a window (headless)"
            } else {
                "with a window"
            },
            escape_display(&chrome.display().to_string()),
            match &proxy {
                Some(link) => format!(
                    "{} (credentials: {})",
                    escape_display(&link.server_url()),
                    if link.authenticated() { "yes, not shown" } else { "no" }
                ),
                None => "none".to_string(),
            },
            SENSITIVE_NOTICE
        );
        Ok(Prepared {
            capture_id,
            session_handle,
            config: BrowserCaptureConfig {
                chrome,
                session_dir,
                start_url,
                headless,
                allowed_hosts: params.allowed_hosts,
                third_party_hosts: third,
                expose_cdp,
                proxy,
            },
            message,
        })
    }

    /// The `start_capture` call ended without delivering the `capture_id` to the
    /// client (cancellation, deadline, giving up, refusal): any late acceptance
    /// is ignored and the slot is always released. If the browser is already
    /// starting or has started, it is stopped.
    pub fn abandon(&self, capture_id: &str) {
        let mut slots = self.lock();
        match slots.get_mut(capture_id) {
            Some(Slot::Starting) => {
                slots.remove(capture_id);
            }
            Some(Slot::Opening { abandoned }) => *abandoned = true,
            Some(Slot::Running(_)) => {
                if let Some(Slot::Running(running)) = slots.remove(capture_id) {
                    drop(slots);
                    let cap = running.cap.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(cap) = cap {
                        // In another thread: stopping waits for Chrome to exit.
                        std::thread::spawn(move || {
                            if let Err(error) = cap.stop() {
                                eprintln!(
                                    "scrapelens-mcp: while stopping an abandoned capture: {error}"
                                );
                            }
                        });
                    }
                }
            }
            None => {}
        }
    }

    /// Releases the slot reserved by `prepare` (confirmation denied or failure).
    pub fn release(&self, capture_id: &str) {
        self.lock().remove(capture_id);
    }

    /// Opens the browser (blocking) and registers the capture. If the server
    /// starts shutting down while Chrome is starting, the capture is closed right
    /// here (Chrome is never left orphaned).
    pub fn start(&self, prepared: Prepared, how: &'static str) -> Result<Value, ToolError> {
        let Prepared {
            capture_id,
            session_handle,
            config,
            ..
        } = prepared;
        self.starts_in_flight.fetch_add(1, Ordering::SeqCst);
        // Only opens the browser if the slot still belongs to this call: a cancellation or
        // abandonment before this point has already released it and nothing opens.
        let reserved = {
            let mut slots = self.lock();
            match slots.get_mut(&capture_id) {
                Some(slot @ Slot::Starting) => {
                    *slot = Slot::Opening { abandoned: false };
                    true
                }
                _ => false,
            }
        };
        let result = if reserved {
            self.start_inner(&capture_id, &session_handle, config, how)
        } else {
            Err(ToolError::new(
                "capture_cancelled",
                "the call was cancelled or abandoned before the browser opened; nothing was opened",
            ))
        };
        self.starts_in_flight.fetch_sub(1, Ordering::SeqCst);
        if result.is_err() {
            self.release(&capture_id);
        }
        result
    }

    fn start_inner(
        &self,
        capture_id: &str,
        session_handle: &str,
        config: BrowserCaptureConfig,
        how: &'static str,
    ) -> Result<Value, ToolError> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ToolError::new(
                "shutting_down",
                "the server is shutting down",
            ));
        }
        match self.backend.start(config) {
            Ok((cap, info)) => {
                let mut slots = self.lock();
                let abandoned = matches!(
                    slots.get(capture_id),
                    Some(Slot::Opening { abandoned: true }) | None
                );
                if self.shutting_down.load(Ordering::SeqCst) || abandoned {
                    drop(slots);
                    // Started after the server began shutting down or after the caller gave up:
                    // stop it now, with the session recorded.
                    match cap.stop() {
                        Ok(_) => eprintln!(
                            "scrapelens-mcp: the capture that was starting during shutdown was stopped"
                        ),
                        Err(error) => {
                            eprintln!("scrapelens-mcp: while stopping the capture that was starting: {error}")
                        }
                    }
                    return Err(ToolError::new(
                        if abandoned { "capture_cancelled" } else { "shutting_down" },
                        "the capture was stopped because the request was cancelled or the server shut down during startup",
                    ));
                }
                let running = Arc::new(Running {
                    cap: Mutex::new(Some(cap)),
                    session_handle: session_handle.to_string(),
                });
                slots.insert(capture_id.to_string(), Slot::Running(running));
                drop(slots);
                let mut object = match serde_json::to_value(&info) {
                    Ok(Value::Object(map)) => map,
                    _ => Map::new(),
                };
                strip_path_fields(&mut object);
                object.insert("captureId".into(), json!(capture_id));
                object.insert("sessionId".into(), json!(session_handle));
                object.insert("confirmation".into(), json!(how));
                Ok(Value::Object(object))
            }
            Err(error) => Err(ToolError::new(error.code(), error.to_string())),
        }
    }

    fn running(&self, capture_id: &str) -> Result<Arc<Running>, ToolError> {
        match self.lock().get(capture_id) {
            Some(Slot::Running(running)) => Ok(running.clone()),
            Some(Slot::Starting | Slot::Opening { .. }) => Err(ToolError::new(
                "capture_not_ready",
                "the capture is still starting",
            )),
            None => Err(ToolError::new(
                "capture_not_found",
                format!("capture {capture_id:?} does not exist (stopped or invalid id)"),
            )),
        }
    }

    pub fn navigate(&self, params: &NavigateParams) -> Result<Value, ToolError> {
        let wait_load = match params.wait.as_deref().unwrap_or("load") {
            "load" => true,
            "none" => false,
            other => {
                return Err(ToolError::invalid(format!(
                    "invalid wait: {other:?} (load|none)"
                )))
            }
        };
        let timeout_ms = params.timeout_ms.unwrap_or(DEFAULT_NAVIGATE_TIMEOUT_MS);
        if timeout_ms == 0 || timeout_ms > MAX_NAVIGATE_TIMEOUT_MS {
            return Err(ToolError::invalid(format!(
                "timeout_ms must be between 1 and {MAX_NAVIGATE_TIMEOUT_MS}"
            )));
        }
        let running = self.running(&params.capture_id)?;
        let guard = running.cap.lock().unwrap_or_else(|e| e.into_inner());
        let cap = guard.as_ref().ok_or_else(|| {
            ToolError::new("capture_stopped", "the capture has already been stopped")
        })?;
        let result = cap
            .navigate(&params.url, wait_load, Duration::from_millis(timeout_ms))
            .map_err(|e| ToolError::new(e.code(), e.to_string()))?;
        let mut object = match serde_json::to_value(&result) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        object.insert("captureId".into(), json!(params.capture_id));
        Ok(Value::Object(object))
    }

    pub fn status(&self, capture_id: &str) -> Result<Value, ToolError> {
        let running = self.running(capture_id)?;
        let guard = running.cap.lock().unwrap_or_else(|e| e.into_inner());
        let cap = guard.as_ref().ok_or_else(|| {
            ToolError::new("capture_stopped", "the capture has already been stopped")
        })?;
        let mut object = match serde_json::to_value(cap.status()) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        strip_path_fields(&mut object);
        object.insert("captureId".into(), json!(capture_id));
        object.insert("sessionId".into(), json!(running.session_handle));
        let mut value = Value::Object(object);
        mask_urls(&mut value);
        Ok(value)
    }

    /// Stops the capture (graceful), writes the session and returns the masked
    /// report. The capture leaves the map in any case.
    pub fn stop(&self, ctx: &Ctx, capture_id: &str) -> Result<Value, ToolError> {
        // Counts the stop BEFORE the capture leaves the map: server shutdown
        // waits for this stop to finish and record the session (R10).
        let _in_flight = InFlight::new(&self.stops_in_flight);
        let running = self.running(capture_id)?;
        self.lock().remove(capture_id);
        let cap = running
            .cap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| {
                ToolError::new("capture_stopped", "the capture has already been stopped")
            })?;
        let report = cap.stop().map_err(|e| {
            ToolError::new("stop_failed", format!("failed to stop the capture: {e}"))
        })?;
        let mut object = match serde_json::to_value(&report) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        strip_path_fields(&mut object);
        object.insert("captureId".into(), json!(capture_id));
        object.insert("sessionId".into(), json!(running.session_handle));
        object.insert(
            "readable".into(),
            json!(ctx.open(&running.session_handle).is_ok()),
        );
        let mut value = Value::Object(object);
        mask_urls(&mut value);
        Ok(value)
    }

    /// Stops all captures (server shutdown) and waits for those still starting,
    /// which close on their own once ready. Returns how many were stopped.
    /// Blocking.
    pub fn stop_all(&self, ctx: &Ctx) -> usize {
        self.shutting_down.store(true, Ordering::SeqCst);
        let ids: Vec<String> = self
            .lock()
            .iter()
            .filter(|(_, slot)| matches!(slot, Slot::Running(_)))
            .map(|(id, _)| id.clone())
            .collect();
        let mut stopped = 0;
        for id in ids {
            match self.stop(ctx, &id) {
                Ok(_) => stopped += 1,
                Err(error) => eprintln!("scrapelens-mcp: while stopping {id}: {error}"),
            }
        }
        // Chrome that is still starting: `start` closes it when it finishes. The limit is
        // the capture's own startup deadline (90 s) plus some margin.
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while (self.starts_in_flight.load(Ordering::SeqCst) > 0
            || self.stops_in_flight.load(Ordering::SeqCst) > 0)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.stops_in_flight.load(Ordering::SeqCst) > 0 {
            eprintln!("scrapelens-mcp: a stop_capture did not finish in time; the session may not have been recorded");
        }
        if self.starts_in_flight.load(Ordering::SeqCst) > 0 {
            eprintln!("scrapelens-mcp: a capture start did not finish in time; Chrome may have stayed active");
        }
        stopped
    }

    /// Called by the server on startup.
    pub fn startup(&self) {
        self.backend.startup();
    }

    pub fn active(&self) -> usize {
        self.lock().len()
    }
}

/// Counter of operations in progress, decremented when it goes out of scope.
struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Character that must not appear raw in text shown to the user: control
/// (Cc), non-spacing and enclosing marks (Mn, Me: they stack on the previous one),
/// format (Cf: bidi, zero width, variation selectors, tags), separators
/// except the plain space (Zs, Zl, Zp), private use (Co) and unassigned (Cn),
/// plus some "fillers" that are letters/symbols but render as blank.
fn is_hidden_char(ch: char) -> bool {
    use icu_properties::props::GeneralCategory as Gc;
    if ch == ' ' {
        return false;
    }
    if matches!(
        ch as u32,
        0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x2800 | 0x3164 | 0xFFA0 | 0xFFFC | 0xE0100..=0xE01EF
    ) {
        return true;
    }
    matches!(
        icu_properties::CodePointMapData::<Gc>::new().get(ch),
        Gc::Control
            | Gc::NonspacingMark
            | Gc::EnclosingMark
            | Gc::Format
            | Gc::SpaceSeparator
            | Gc::LineSeparator
            | Gc::ParagraphSeparator
            | Gc::PrivateUse
            | Gc::Unassigned
            | Gc::Surrogate
    )
}

/// Text shown in the confirmation and error messages: invisible characters or
/// ones that reorder/stack (see [`is_hidden_char`]) become a literal `\u{XXXX}`, so
/// that a value controlled by the agent cannot inject fake lines or disguise the text.
pub fn escape_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_hidden_char(ch) {
            out.push_str(&format!("\\u{{{:04X}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// URL without query or fragment (replaced by `?…`): in capture outputs there
/// is no way to know which parameters are secrets, so none is shown.
pub fn strip_query(url: &str) -> String {
    match url.find(['?', '#']) {
        Some(at) => format!("{}?…", &url[..at]),
        None => url.to_string(),
    }
}

/// Free text without query or fragment: after redacting what Core
/// recognizes as a credential, every `?…` and `#…` up to a terminator becomes `?…`/`#…`.
pub fn strip_text(text: &str) -> String {
    let text = scrapelens_core::export::sanitize::sanitize_text(
        text,
        &scrapelens_core::export::sanitize::SanitizeOptions::default(),
    );
    let is_end = |ch: char| {
        ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | '(' | ')' | ',' | '\\')
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let end = rest.find(is_end).unwrap_or(rest.len());
        if end == 0 {
            let ch = rest.chars().next().unwrap();
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        }
        let (token, after) = rest.split_at(end);
        // URL-like or path-like token: cut at the first `?`, `#` or `;`
        // (query, fragment, matrix parameter); only the path remains.
        let urlish = token.contains("://") || token.starts_with('/');
        match token.find(['?', '#', ';']).filter(|_| urlish) {
            Some(at) => {
                out.push_str(&token[..at]);
                out.push('…');
            }
            None => out.push_str(token),
        }
        rest = after;
    }
    out
}

/// In capture outputs no string keeps a query or fragment (URL fields,
/// warnings and error messages).
fn mask_urls(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(mask_urls),
        Value::Array(list) => list.iter_mut().for_each(mask_urls),
        Value::String(text) if text.contains(['?', '#', '=']) || text.contains("://") => {
            *text = strip_text(text);
        }
        _ => {}
    }
}
