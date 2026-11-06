//! Real capture through the COMMON (App) path, imported by the current core, for one
//! proxy route. Test only: loopback origin and test proxies; `ignore_cert` is set so that
//! the synthetic HTTPS origin and the HTTPS test proxy (fixture CA) are accepted.
//!
//! Usage: `[SCRAPELENS_PROXY_URL=...] cargo run --example proxy_import -- <session-folder> <start-url> <seconds>`
//! Prints the session folder on stdout and the notice on stderr.

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scrapelens_capture::chrome::resolve_stable_chrome;
use scrapelens_capture::proxy::ProxyLink;
use scrapelens_capture::{run, CaptureConfig, CaptureStatus, NetworkMode};

fn main() {
    let mut args = std::env::args().skip(1);
    let session_dir = PathBuf::from(args.next().expect("session folder"));
    let start_url = args.next().expect("start url");
    let seconds: u64 = args.next().unwrap_or_else(|| "8".into()).parse().expect("seconds");
    let proxy = std::env::var("SCRAPELENS_PROXY_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|raw| ProxyLink::parse(&raw).expect("valid proxy link"));
    eprintln!("route: {}", proxy.as_ref().map(|p| format!("{p:?}")).unwrap_or_else(|| "none".into()));
    let config = CaptureConfig {
        chrome: resolve_stable_chrome(None).expect("stable Chrome").binary,
        session_dir,
        start_url,
        headless: true,
        ignore_cert: true,
        network: NetworkMode::Open,
        cookie_source: None,
        initial_cookies: Vec::new(),
        proxy,
        test_proxy_bypass_loopback: true,
    };
    let status = Arc::new(Mutex::new(CaptureStatus::default()));
    let (stop_tx, stop_rx) = channel();
    let (ready_tx, ready_rx) = channel();
    let handle = std::thread::spawn(move || run(config, status, stop_rx, ready_tx));
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            eprintln!("start failed: {message}");
            let _ = handle.join();
            std::process::exit(3);
        }
        Err(_) => std::process::exit(4),
    }
    std::thread::sleep(Duration::from_secs(seconds));
    let _ = stop_tx.send(());
    match handle.join() {
        Ok(Ok(outcome)) => {
            eprintln!("notice: {}", outcome.notice);
            println!("{}", outcome.session_dir.display());
        }
        Ok(Err(message)) => {
            eprintln!("capture failed: {message}");
            std::process::exit(5);
        }
        Err(_) => std::process::exit(6),
    }
}
