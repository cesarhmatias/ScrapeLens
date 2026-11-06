//! Acceptance driver for the proxy link (v0.1.2). Test only.
//!
//! Runs the REAL capture paths, without the App window and without the MCP
//! confirmation dialog:
//!   * `common`:     `scrapelens_capture::run` — the App's capture path.
//!   * `controlled`: `BrowserCapture::start` + `navigate` — the controlled path the MCP
//!                   `start_capture` tool uses after the user confirms (allowlist, relay).
//!   * `parse`:      `ProxyLink::parse` — the invalid-link refusal.
//!
//! Every mode prints one JSON line on stdout. The link is never printed: the Debug form
//! of `ProxyLink` shows only the scheme, host, port and whether it is authenticated.
//!
//! Usage:
//!   proxy-acceptance-driver common <session_dir> <start_url> <seconds> [--link URL]
//!   proxy-acceptance-driver controlled <session_dir> <start_url> [--allow HOST:PORT]... [--nav URL]... [--link URL]
//!   proxy-acceptance-driver parse <link>
//! The link may also come from SCRAPELENS_PROXY_URL when `--link` is absent in `common`.

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scrapelens_capture::browser::{BrowserCapture, BrowserCaptureConfig};
use scrapelens_capture::chrome::resolve_stable_chrome;
use scrapelens_capture::proxy::ProxyLink;
use scrapelens_capture::{CaptureConfig, CaptureStatus, NetworkMode, run};
use serde_json::{Value, json};

fn parse_link(raw: &str) -> Result<ProxyLink, String> {
    ProxyLink::parse(raw).map_err(|e| e.to_string())
}

fn take_link(args: &[String]) -> Result<Option<ProxyLink>, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--link" {
            let v = args.get(i + 1).ok_or("--link needs a value")?;
            return parse_link(v).map(Some);
        }
        i += 1;
    }
    Ok(None)
}

fn values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn common(args: &[String]) -> Value {
    let session_dir = PathBuf::from(&args[0]);
    let start_url = args[1].clone();
    let seconds: u64 = args[2].parse().unwrap_or(6);
    let link = match take_link(&args[3..]) {
        Ok(l) => l,
        Err(e) => return json!({"mode":"common","ok":false,"stage":"link","error":e}),
    };
    let route = link.as_ref().map(|l| format!("{:?}", l)).unwrap_or_else(|| "none".into());
    let chrome = match resolve_stable_chrome(None) {
        Ok(c) => c.binary,
        Err(e) => return json!({"mode":"common","ok":false,"stage":"chrome","error":e.to_string()}),
    };
    let config = CaptureConfig {
        chrome,
        session_dir: session_dir.clone(),
        start_url,
        headless: true,
        ignore_cert: true,
        network: NetworkMode::Open,
        cookie_source: None,
        initial_cookies: Vec::new(),
        proxy: link,
        test_proxy_bypass_loopback: true,
    };
    let status = Arc::new(Mutex::new(CaptureStatus::default()));
    let (stop_tx, stop_rx) = channel();
    let (ready_tx, ready_rx) = channel();
    let handle = std::thread::spawn(move || run(config, status, stop_rx, ready_tx));
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            let _ = handle.join();
            return json!({"mode":"common","ok":false,"stage":"start","route":route,"error":message});
        }
        Err(_) => {
            let _ = handle.join();
            return json!({"mode":"common","ok":false,"stage":"start","route":route,"error":"capture thread ended before ready"});
        }
    }
    std::thread::sleep(Duration::from_secs(seconds));
    let _ = stop_tx.send(());
    match handle.join() {
        Ok(Ok(outcome)) => json!({"mode":"common","ok":true,"route":route,
            "session_dir": outcome.session_dir.display().to_string(), "notice": outcome.notice}),
        Ok(Err(message)) => json!({"mode":"common","ok":false,"stage":"stop","route":route,"error":message}),
        Err(_) => json!({"mode":"common","ok":false,"stage":"stop","route":route,"error":"capture thread failed"}),
    }
}

fn controlled(args: &[String]) -> Value {
    let session_dir = PathBuf::from(&args[0]);
    let start_url = args[1].clone();
    let allow = values(&args[2..], "--allow");
    let navs = values(&args[2..], "--nav");
    let link = match take_link(&args[2..]) {
        Ok(l) => l,
        Err(e) => return json!({"mode":"controlled","ok":false,"stage":"link","error":e}),
    };
    let route = link.as_ref().map(|l| format!("{:?}", l)).unwrap_or_else(|| "none".into());
    let chrome = match resolve_stable_chrome(None) {
        Ok(c) => c.binary,
        Err(e) => return json!({"mode":"controlled","ok":false,"stage":"chrome","error":e.to_string()}),
    };
    let config = BrowserCaptureConfig {
        chrome,
        session_dir,
        start_url: Some(start_url),
        headless: true,
        allowed_hosts: allow,
        third_party_hosts: Vec::new(),
        expose_cdp: false,
        proxy: link,
    };
    let (capture, info) = match BrowserCapture::start(config) {
        Ok(v) => v,
        Err(e) => return json!({"mode":"controlled","ok":false,"stage":"start","route":route,"error":format!("{e:?}")}),
    };
    let mut nav_results = Vec::new();
    for url in &navs {
        let r = capture.navigate(url, true, Duration::from_secs(30));
        nav_results.push(match r {
            Ok(res) => json!({"url":url,"ok":true,"loaded":res.loaded,"error_text":res.error_text}),
            Err(e) => json!({"url":url,"ok":false,"code":e.code(),"error":e.to_string()}),
        });
        std::thread::sleep(Duration::from_secs(2));
    }
    std::thread::sleep(Duration::from_secs(4));
    let warnings = info.warnings.clone();
    match capture.stop() {
        Ok(report) => json!({"mode":"controlled","ok":true,"route":route,"start_warnings":warnings,
            "session_dir": report.session_dir, "requests": report.requests, "graceful": report.graceful,
            "navigations": nav_results}),
        Err(e) => json!({"mode":"controlled","ok":false,"stage":"stop","route":route,"error":e,"navigations":nav_results}),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match argv.split_first() {
        Some((c, r)) => (c.as_str(), r.to_vec()),
        None => {
            eprintln!("usage: proxy-acceptance-driver common|controlled|parse ...");
            std::process::exit(2);
        }
    };
    let out = match cmd {
        "common" => common(&rest),
        "controlled" => controlled(&rest),
        "parse" => match rest.first().map(|r| parse_link(r)) {
            Some(Ok(link)) => json!({"mode":"parse","ok":true,"link":format!("{:?}", link)}),
            Some(Err(e)) => json!({"mode":"parse","ok":false,"error":e}),
            None => json!({"mode":"parse","ok":false,"error":"missing link"}),
        },
        other => json!({"mode":"unknown","ok":false,"error":other}),
    };
    println!("{out}");
}
