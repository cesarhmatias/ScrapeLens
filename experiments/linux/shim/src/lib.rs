//! Stand-in for `src-tauri` in the Linux container (docs/21-linux.md §6). The
//! `check_multi_target.py` drives `cargo test live_bodies_cycle` inside `src-tauri`;
//! on Linux Tauri (webkit2gtk) is not built in this round, so the container swaps
//! `src-tauri` for this crate, whose test does EXACTLY what the one in `src-tauri/src/capture.rs`
//! does (`scrapelens_capture::run`, headless, loopback only), without the window.
#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use scrapelens_capture::{run, CaptureConfig, CaptureStatus, NetworkMode};

    #[test]
    #[ignore]
    fn live_bodies_cycle() {
        let start_url = std::env::var("SL_LIVE_START_URL").expect("SL_LIVE_START_URL");
        let dir = PathBuf::from(std::env::var("SL_LIVE_SESSION_DIR").expect("SL_LIVE_SESSION_DIR"));
        let stop_file = PathBuf::from(std::env::var("SL_LIVE_STOP_FILE").expect("SL_LIVE_STOP_FILE"));
        let chrome = scrapelens_capture::chrome::detect(None).path.expect("Chrome or Chromium installed");
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
            network: NetworkMode::LoopbackOnly,
            cookie_source: None,
            initial_cookies: Vec::new(),
        };
        let status_thread = status.clone();
        let join = std::thread::spawn(move || run(config, status_thread, stop_rx, ready_tx));
        ready_rx.recv_timeout(Duration::from_secs(30)).expect("capture ready").expect("capture started");
        let deadline = Instant::now() + Duration::from_secs(180);
        while !stop_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = stop_tx.send(());
        let outcome = join.join().expect("capture thread").expect("capture imported");
        println!("live bodies: notice={:?}", outcome.notice);
    }
}
