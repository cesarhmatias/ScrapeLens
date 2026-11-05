//! Confirmation policy and capture map, without a browser (counted backend).

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use scrapelens_capture::browser::{
    AllowlistInfo, BrowserCaptureConfig, BrowserInfo, NavigateError, NavigateResult, StartError,
    StartInfo, StopReport, SENSITIVE_NOTICE,
};
use scrapelens_capture::CaptureStatus;
use scrapelens_mcp::error::ToolError;
use scrapelens_mcp::live::{decide, CaptureBackend, Confirmation, LiveCapture, Manager};
use serde_json::json;

#[derive(Default)]
struct Counting {
    starts: AtomicUsize,
    fail_start: bool,
}

struct Noop;

impl LiveCapture for Noop {
    fn navigate(&self, _: &str, _: bool, _: Duration) -> Result<NavigateResult, NavigateError> {
        Err(NavigateError::CaptureStopped)
    }
    fn status(&self) -> CaptureStatus {
        CaptureStatus::default()
    }
    fn stop(self: Box<Self>) -> Result<StopReport, String> {
        Ok(StopReport {
            session_dir: "x".into(),
            requests: 0,
            netlog: "complete".into(),
            graceful: true,
            waited_ms: 0,
            allowlist: Default::default(),
            warnings: vec![],
            outcome: None,
        })
    }
}

struct Backend(Arc<Counting>);

impl CaptureBackend for Backend {
    fn resolve_chrome(&self, _: Option<&str>) -> Result<PathBuf, ToolError> {
        Ok(PathBuf::from("/fake/chrome"))
    }
    fn start(
        &self,
        config: BrowserCaptureConfig,
    ) -> Result<(Box<dyn LiveCapture>, StartInfo), StartError> {
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_start {
            return Err(StartError::BrowserStart("falhou".into()));
        }
        Ok((
            Box::new(Noop),
            StartInfo {
                session_dir: config.session_dir.display().to_string(),
                chrome_pid: 1,
                browser: BrowserInfo {
                    path: "x".into(),
                    version: None,
                    user_agent: None,
                },
                allowlist: AllowlistInfo {
                    allowed_hosts: vec![],
                    third_party_hosts: vec![],
                    resolver_rules: String::new(),
                },
                cdp: None,
                sensitive_notice: SENSITIVE_NOTICE,
                warnings: vec![],
            },
        ))
    }
}

fn params(v: serde_json::Value) -> scrapelens_mcp::live::StartCaptureParams {
    p(v)
}

#[test]
fn decide_requires_explicit_acceptance() {
    use Confirmation::*;
    assert_eq!(decide(&Accepted, false).unwrap(), "elicited");
    for flag in [false, true] {
        // Refusal or cancellation always applies, with or without the flag.
        for c in [Declined("no".into()), Cancelled] {
            assert_eq!(
                decide(&c, flag).unwrap_err().code,
                "confirmation_denied",
                "{c:?} flag={flag}"
            );
        }
    }
    // Without elicitation: only with the operator's flag.
    let unavailable = Unavailable("client without support".into());
    assert_eq!(
        decide(&unavailable, false).unwrap_err().code,
        "confirmation_unavailable"
    );
    assert_eq!(decide(&unavailable, true).unwrap(), "unconfirmed-flag");
}

#[test]
fn manager_allows_one_capture_and_releases_the_slot() {
    let env = Env::new(false);
    let backend = Arc::new(Counting::default());
    let manager = Manager::new(Arc::new(Backend(backend.clone())));
    let args = || params(json!({"allowed_hosts": ["site.invalid.test"]}));

    let first = manager.prepare(&env.ctx, args()).unwrap();
    // The slot is already reserved during confirmation.
    assert_eq!(
        manager.prepare(&env.ctx, args()).err().unwrap().code,
        "capture_already_running"
    );
    // Confirmation denied: the slot is released and the browser was never opened.
    manager.release(&first.capture_id);
    assert_eq!(backend.starts.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active(), 0);

    let second = manager.prepare(&env.ctx, args()).unwrap();
    let started = manager.start(second, "elicited").unwrap();
    assert_eq!(backend.starts.load(Ordering::SeqCst), 1);
    let id = started["captureId"].as_str().unwrap().to_string();
    assert_eq!(
        manager.prepare(&env.ctx, args()).err().unwrap().code,
        "capture_already_running"
    );
    assert_eq!(manager.stop_all(&env.ctx), 1);
    assert_eq!(manager.active(), 0);
    assert_eq!(manager.status(&id).unwrap_err().code, "capture_not_found");
}

#[test]
fn failed_start_releases_the_slot() {
    let env = Env::new(false);
    let backend = Arc::new(Counting {
        fail_start: true,
        ..Counting::default()
    });
    let manager = Manager::new(Arc::new(Backend(backend)));
    let prepared = manager
        .prepare(
            &env.ctx,
            params(json!({"allowed_hosts": ["site.invalid.test"]})),
        )
        .unwrap();
    assert_eq!(
        manager.start(prepared, "elicited").unwrap_err().code,
        "browser_start_failed"
    );
    assert_eq!(manager.active(), 0);
}

#[test]
fn prepare_validates_before_reserving_or_asking() {
    let env = Env::new(false);
    let manager = Manager::new(Arc::new(Backend(Arc::new(Counting::default()))));
    for (args, code) in [
        (json!({"allowed_hosts": []}), "allowlist_required"),
        (json!({"allowed_hosts": ["*"]}), "allowlist_too_broad"),
        (json!({"allowed_hosts": ["http://x"]}), "allowlist_invalid"),
        (
            json!({"allowed_hosts": ["a.test"], "start_url": "http://evil.test/"}),
            "start_url_not_allowed",
        ),
    ] {
        assert_eq!(
            manager
                .prepare(&env.ctx, params(args.clone()))
                .err()
                .unwrap()
                .code,
            code,
            "{args}"
        );
        assert_eq!(manager.active(), 0, "nothing reserved: {args}");
    }
}

#[test]
fn confirmation_text_lists_what_the_user_is_authorizing() {
    let env = Env::new(false);
    let manager = Manager::new(Arc::new(Backend(Arc::new(Counting::default()))));
    let prepared = manager
        .prepare(
            &env.ctx,
            params(json!({"allowed_hosts": ["A.Site.Test:8080"], "third_party_hosts": ["cdn.test"], "expose_cdp": true, "start_url": "http://a.site.test:8080/"})),
        )
        .unwrap();
    let message = &prepared.message;
    for needle in [
        "a.site.test:8080",
        "cdn.test",
        "YES",
        "/fake/chrome",
        "with a window",
        SENSITIVE_NOTICE,
        "confirmo",
    ] {
        assert!(message.contains(needle), "missing {needle:?}: {message}");
    }
    // The capture id is opaque and the directory stays inside --sessions-dir.
    assert!(prepared.capture_id.starts_with("cap-"));
    assert!(prepared
        .config
        .session_dir
        .starts_with(&env.ctx.cfg.sessions_dir));
    assert!(
        !prepared.config.session_dir.exists(),
        "nothing created before confirmation"
    );
}
