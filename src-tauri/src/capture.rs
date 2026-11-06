//! Thin adapter between the App (Tauri) and the `scrapelens-capture` crate.
//!
//! All capture (Chrome with a dedicated profile, CDP + NetLog, allowlist, controlled
//! capture, orphan cleanup) lives in `capture/` (crate without Tauri). Only what
//! belongs to the App stays here: `SessionPayload` (command responses) and
//! `CaptureSession` (the handle the App keeps). `run()` and `CaptureConfig` behave
//! as they did before.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

pub use scrapelens_capture::{
    cleanup_orphans, default_state_root, CaptureConfig, CaptureStatus, OrphanCleanup,
};

use crate::commands::SessionPayload;

pub struct CaptureSession {
    pub id: String,
    pub dir: PathBuf,
    pub started_at: String,
    pub stop: Sender<()>,
    pub join: thread::JoinHandle<Result<SessionPayload, String>>,
    pub status: Arc<Mutex<CaptureStatus>>,
}

/// Runs the capture and delivers the session in the format the commands return.
pub fn run(
    config: CaptureConfig,
    status: Arc<Mutex<CaptureStatus>>,
    stop: Receiver<()>,
    ready: Sender<Result<(), String>>,
) -> Result<SessionPayload, String> {
    let outcome = scrapelens_capture::run(config, status, stop, ready)?;
    // P5: drop the capture's `Value` and return only the header (paginated list).
    let notice = outcome.notice;
    let dir = outcome.session_dir;
    drop(outcome.session);
    let mut payload = crate::commands::header_payload(&dir, |_, _| notice)?;
    payload.synthetic = false;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Manual test of the real cycle: requires Chrome installed and the h1 testserver on
    /// 127.0.0.1:8781. Run with:
    ///   cargo test live_capture_cycle -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_capture_cycle() {
        let chrome = crate::chrome::detect(None)
            .path
            .expect("Chrome installed for the capture test");
        let dir = std::env::temp_dir().join(format!("scrapelens-live-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)));
        std::fs::create_dir_all(&dir).unwrap();
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_id: "live-test".to_string(),
            session_dir: dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from(chrome),
            session_dir: dir.clone(),
            start_url: "http://127.0.0.1:8781/page".to_string(),
            headless: true,
            ignore_cert: false,
            // Live tests: loopback only, nothing leaves the machine.
            network: scrapelens_capture::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let status_thread = status.clone();
        let join = thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("capture ready")
            .expect("capture started");
        thread::sleep(Duration::from_secs(6));
        let _ = stop_tx.send(());
        let payload = join
            .join()
            .expect("capture thread")
            .expect("capture imported");
        let requests = payload.session["requests"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        println!(
            "live capture: {} requests, session_dir={:?}, notice={:?}",
            requests, payload.session_dir, payload.notice
        );
        assert!(requests > 0, "the capture must contain real requests");
        assert!(!payload.synthetic);
        println!("session.json: {}", dir.join("session.json").display());
    }

    /// Real cycle driven by `experiments/bodies/run_bodies.py` (requires Chrome and
    /// the local h1 testserver). Variables: `SL_LIVE_START_URL`,
    /// `SL_LIVE_SESSION_DIR`, `SL_LIVE_STOP_FILE` (the capture stops once the file
    /// exists).
    #[test]
    #[ignore]
    fn live_bodies_cycle() {
        let start_url = std::env::var("SL_LIVE_START_URL").expect("SL_LIVE_START_URL");
        let dir = PathBuf::from(std::env::var("SL_LIVE_SESSION_DIR").expect("SL_LIVE_SESSION_DIR"));
        let stop_file =
            PathBuf::from(std::env::var("SL_LIVE_STOP_FILE").expect("SL_LIVE_STOP_FILE"));
        let chrome = crate::chrome::detect(None).path.expect("Chrome installed");
        let status = Arc::new(Mutex::new(CaptureStatus {
            recording: true,
            session_id: "live-bodies".to_string(),
            session_dir: dir.display().to_string(),
            ..CaptureStatus::default()
        }));
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let config = CaptureConfig {
            chrome: PathBuf::from(chrome),
            session_dir: dir,
            start_url,
            headless: true,
            ignore_cert: false,
            // Live tests: loopback only, nothing leaves the machine.
            network: scrapelens_capture::NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: Vec::new(),
            proxy: None,
            test_proxy_bypass_loopback: false,
        };
        let status_thread = status.clone();
        let join = thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("capture ready")
            .expect("capture started");
        let deadline = Instant::now() + Duration::from_secs(180);
        while !stop_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }
        let _ = stop_tx.send(());
        let payload = join
            .join()
            .expect("capture thread")
            .expect("capture imported");
        println!("live bodies: notice={:?}", payload.notice);
    }
}
