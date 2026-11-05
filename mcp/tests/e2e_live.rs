//! Live E2E: the real product binary, with real Chrome (headless) and an HTTP
//! server on loopback from the test itself. No real site is accessed.
//!
//! Run with: `cargo test --test e2e_live -- --ignored --nocapture`

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::client::{Client, Elicit};
use serde_json::json;

/// Minimal server: `/` with invented Cloudflare signals (cf-ray and cookie),
/// `/area` with 403 and `cf-mitigated: challenge`. Keeps the paths seen.
fn serve() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_thread = seen.clone();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let seen = seen_thread.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                seen.lock().unwrap().push(path.clone());
                let (status, extra, body) = if path.starts_with("/area") {
                    (
                        "403 Forbidden",
                        "cf-mitigated: challenge\r\n",
                        "<html><body>challenge</body></html>",
                    )
                } else {
                    (
                        "200 OK",
                        "cf-ray: 0000-TST\r\nSet-Cookie: __cf_bm=SEGREDO-LIVE-1; Path=/; HttpOnly\r\n",
                        "<html><body><h1>ok</h1></body></html>",
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    (port, seen)
}

#[test]
#[ignore = "uses real Chrome (headless) and a loopback server"]
fn live_cycle_with_real_chrome() {
    let (port, seen) = serve();
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let program = std::path::PathBuf::from(env!("CARGO_BIN_EXE_scrapelens-mcp"));
    let mut client = Client::start(
        &program,
        &["--sessions-dir", sessions.to_str().unwrap()],
        Elicit::Accept,
    );
    client.handshake();

    let host = format!("localhost:{port}");
    let (is_error, started) = client.tool(
        "start_capture",
        json!({"allowed_hosts": [host], "headless": true, "start_url": format!("http://localhost:{port}/")}),
    );
    assert!(!is_error, "{started}");
    let id = started["captureId"].as_str().unwrap().to_string();
    assert!(
        started["browser"]["version"]
            .as_str()
            .unwrap_or("")
            .contains("Chrome"),
        "{started}"
    );
    assert_eq!(client.elicitations.len(), 1);

    // Outside the allowlist: refused before sending; the server sees nothing.
    let before = seen.lock().unwrap().len();
    for bad in [
        format!("http://127.0.0.1:{port}/x"),
        "http://evil.test/".to_string(),
    ] {
        let (is_error, denied) = client.tool("navigate", json!({"capture_id": id, "url": bad}));
        assert!(is_error);
        assert_eq!(denied["error"]["code"], "url_not_allowed");
    }
    assert_eq!(seen.lock().unwrap().len(), before);

    let (is_error, nav) = client.tool(
        "navigate",
        json!({"capture_id": id, "url": format!("http://localhost:{port}/area?x=1"), "timeout_ms": 20000}),
    );
    assert!(!is_error, "{nav}");
    assert_eq!(nav["loaded"], true, "{nav}");
    thread::sleep(Duration::from_millis(800));

    let (_, status) = client.tool("capture_status", json!({"capture_id": id}));
    assert_eq!(status["recording"], true);
    assert!(
        !status.to_string().contains("x=1"),
        "query doesn't leave: {status}"
    );

    let (is_error, stopped) = client.tool("stop_capture", json!({"capture_id": id}));
    assert!(!is_error, "{stopped}");
    assert_eq!(stopped["graceful"], true, "{stopped}");
    assert_eq!(stopped["netlog"], "complete", "{stopped}");
    assert_eq!(stopped["readable"], true);
    let session_id = stopped["sessionId"].as_str().unwrap().to_string();

    // The recorded session is readable by the read tools, with header order.
    let (is_error, requests) = client.tool(
        "list_requests",
        json!({"session_id": session_id, "host": host}),
    );
    assert!(!is_error, "{requests}");
    assert!(requests["total"].as_u64().unwrap() >= 2, "{requests}");
    let area = requests["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["url"].as_str().unwrap().contains("/area"))
        .expect("/area in the session");
    assert_eq!(area["status"], 403);
    let (_, detail) = client.tool(
        "get_request",
        json!({"session_id": session_id, "request_id": area["requestId"]}),
    );
    assert!(detail["response"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h[0].as_str().unwrap().eq_ignore_ascii_case("cf-mitigated")));
    // The cookie value never leaves without reveal.
    let root = client
        .tool(
            "get_request",
            json!({"session_id": session_id, "request_id": requests["items"][0]["requestId"]}),
        )
        .1;
    assert!(!root.to_string().contains("SEGREDO-LIVE-1"), "{root}");

    // site_profile recognizes the challenge and the recommendation.
    let (is_error, profile) = client.tool("site_profile", json!({"session_id": session_id}));
    assert!(!is_error, "{profile}");
    let signatures: Vec<&str> = profile["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["signatureId"].as_str())
        .collect();
    assert!(signatures.contains(&"cf-005"), "{signatures:?}");
    assert!(!profile.to_string().contains("SEGREDO-LIVE-1"));
    println!("recommendation: {}", profile["recommendation"]["value"]);

    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
}

fn chrome_left_for(server_pid: u32) -> (usize, Vec<String>) {
    let pattern = format!("scrapelens-chrome-{server_pid}-");
    let procs = std::process::Command::new("pgrep")
        .args(["-f", &pattern])
        .output()
        .unwrap();
    let count = String::from_utf8_lossy(&procs.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let profiles = std::fs::read_dir(std::env::temp_dir())
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n.starts_with(&pattern))
                .collect()
        })
        .unwrap_or_default();
    (count, profiles)
}

fn end_during_start(sigterm: bool) {
    let work = tempfile::tempdir().unwrap();
    let sessions = work.path().join("sessions");
    let program = std::path::PathBuf::from(env!("CARGO_BIN_EXE_scrapelens-mcp"));
    let mut client = Client::start(
        &program,
        &["--sessions-dir", sessions.to_str().unwrap()],
        Elicit::Accept,
    );
    client.handshake();
    let pid = client.child.id();
    client.call_nowait(
        "start_capture",
        json!({"allowed_hosts": ["localhost:9"], "headless": true}),
    );
    client.answer_next_elicitation();
    // The confirmation was given and Chrome is starting up: shut the server down now.
    if sigterm {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let exit = client.child.wait().unwrap();
        assert!(exit.success(), "{exit:?}");
    } else {
        client.close_stdin();
        let (ok, stderr) = client.finish();
        assert!(ok, "{stderr}");
        // Proof that the test caught the window: Chrome was starting up and was stopped by the server.
        assert!(
            stderr.contains("the capture that was starting during shutdown was stopped"),
            "{stderr}"
        );
    }
    let (procs, profiles) = chrome_left_for(pid);
    assert_eq!(procs, 0, "orphaned Chrome after shutting down during startup");
    assert!(profiles.is_empty(), "leftover profile: {profiles:?}");
}

#[test]
#[ignore = "uses real Chrome (headless)"]
fn live_eof_during_start_leaves_no_chrome_or_profile() {
    end_during_start(false);
}

#[test]
#[ignore = "uses real Chrome (headless)"]
fn live_sigterm_during_start_leaves_no_chrome_or_profile() {
    end_during_start(true);
}
