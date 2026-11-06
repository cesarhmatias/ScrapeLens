//! Baseline driver for the no-proxy regression check (revision f69e9dc, before the proxy
//! link existed). Same `common` capture path as `main.rs`, without the proxy fields.
//! Copied over `main.rs` by run_acceptance.py only inside the baseline build folder.

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scrapelens_capture::{run, CaptureConfig, CaptureStatus, NetworkMode};
use scrapelens_capture::chrome::resolve_stable_chrome;

fn main() {
    // argv (without the program name): <session_dir> <start_url> [seconds]
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let session_dir = PathBuf::from(&argv[0]);
    let start_url = argv[1].clone();
    let seconds: u64 = argv.get(2).and_then(|s| s.parse().ok()).unwrap_or(6);
    let chrome = resolve_stable_chrome(None).expect("stable Chrome").binary;
    let config = CaptureConfig {
        chrome,
        session_dir: session_dir.clone(),
        start_url,
        headless: true,
        ignore_cert: true,
        network: NetworkMode::Open,
        cookie_source: None,
        initial_cookies: Vec::new(),
    };
    let status = Arc::new(Mutex::new(CaptureStatus::default()));
    let (stop_tx, stop_rx) = channel();
    let (ready_tx, ready_rx) = channel();
    let handle = std::thread::spawn(move || run(config, status, stop_rx, ready_tx));
    let result = match ready_rx.recv() {
        Ok(Ok(())) => {
            std::thread::sleep(Duration::from_secs(seconds));
            let _ = stop_tx.send(());
            match handle.join() {
                Ok(Ok(outcome)) => serde_json::json!({"mode":"common","ok":true,
                    "session_dir": outcome.session_dir.display().to_string(), "notice": outcome.notice}),
                Ok(Err(e)) => serde_json::json!({"mode":"common","ok":false,"error":e}),
                Err(_) => serde_json::json!({"mode":"common","ok":false,"error":"thread failed"}),
            }
        }
        Ok(Err(e)) => {
            let _ = handle.join();
            serde_json::json!({"mode":"common","ok":false,"error":e})
        }
        Err(_) => serde_json::json!({"mode":"common","ok":false,"error":"no ready signal"}),
    };
    println!("{result}");
}
