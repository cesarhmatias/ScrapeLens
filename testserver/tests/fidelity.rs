//! Integration tests for the reference servers.
//!
//! Each test starts a real server on an ephemeral port, sends a deliberately
//! ordered request and checks the two things the fidelity work depends on:
//! the header list kept by the server (JSONL evidence) and the list echoed back
//! to the client. Duplicates and order must survive both.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use scrapelens_testserver::cert::{self, TlsFiles};
use scrapelens_testserver::evidence::Evidence;
use scrapelens_testserver::{h1, h2cli, h2srv, h3cli, h3srv};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

fn tls() -> TlsFiles {
    cert::init_crypto();
    cert::ensure(&fixtures_dir().join("tls"), false).expect("fixture cert")
}

fn evidence_dir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "scrapelens-ts-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ))
}

fn read_evidence(dir: &Path, file: &str) -> Vec<Value> {
    let path = dir.join(file);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid evidence JSONL line"))
        .collect()
}

fn start_h1(tag: &str) -> (SocketAddr, PathBuf) {
    let dir = evidence_dir(tag);
    let ev = Arc::new(Evidence::open(&dir, "http/1.1").unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let _ = h1::serve_on(listener, ev);
    });
    (addr, dir)
}

fn start_h2(tag: &str) -> (SocketAddr, PathBuf) {
    let dir = evidence_dir(tag);
    let ev = Arc::new(Evidence::open(&dir, "h2").unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = cert::rustls_server_config(&tls()).unwrap();
    thread::spawn(move || {
        let _ = h2srv::serve_on(listener, ev, cfg, None);
    });
    (addr, dir)
}

fn start_h3(tag: &str) -> (SocketAddr, PathBuf) {
    let dir = evidence_dir(tag);
    let ev = Arc::new(Evidence::open(&dir, "h3").unwrap());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let tls_files = tls();
    thread::spawn(move || {
        let _ = h3srv::serve_on(socket, ev, &tls_files, 0);
    });
    (addr, dir)
}

struct Http1Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Send raw request bytes and parse one HTTP/1.1 response (keep-alive safe).
fn h1_request(addr: SocketAddr, raw: &[u8]) -> Http1Response {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line: {line:?}"));

    let mut headers = Vec::new();
    loop {
        let mut hline = String::new();
        let n = reader.read_line(&mut hline).unwrap();
        assert!(n > 0, "unexpected eof in headers");
        let t = hline.trim_end_matches(['\r', '\n']);
        if t.is_empty() {
            break;
        }
        let (name, value) = t.split_once(':').expect("header with colon");
        headers.push((name.to_string(), value.trim_start().to_string()));
    }
    let len: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).unwrap();
    Http1Response {
        status,
        headers,
        body,
    }
}

fn header_pairs(v: &Value) -> Vec<(String, String)> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|pair| {
            let p = pair.as_array().expect("pair array");
            (
                p[0].as_str().unwrap().to_string(),
                p[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn h1_keeps_exact_order_casing_and_duplicates() {
    let (addr, dir) = start_h1("h1-order");
    thread::sleep(Duration::from_millis(100));

    let raw = b"GET /echo-order?probe=h1 HTTP/1.1\r\n\
                X-Zeta: 1\r\n\
                x-alpha: a\r\n\
                X-Zeta: 2\r\n\
                Cookie: a=1\r\n\
                Cookie: b=2\r\n\
                Host: example.test\r\n\
                Connection: close\r\n\r\n";
    let resp = h1_request(addr, raw);
    assert_eq!(resp.status, 200);

    let json: Value = serde_json::from_slice(&resp.body).unwrap();
    let echoed = header_pairs(&json["headers"]);
    let expected = vec![
        ("X-Zeta".to_string(), "1".to_string()),
        ("x-alpha".to_string(), "a".to_string()),
        ("X-Zeta".to_string(), "2".to_string()),
        ("Cookie".to_string(), "a=1".to_string()),
        ("Cookie".to_string(), "b=2".to_string()),
        ("Host".to_string(), "example.test".to_string()),
        ("Connection".to_string(), "close".to_string()),
    ];
    assert_eq!(
        echoed, expected,
        "echoed header list must keep order/case/dups"
    );
    assert_eq!(json["header_count"], 7);

    let rows = read_evidence(&dir, "h1.jsonl");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["proto"], "http/1.1");
    assert_eq!(
        rows[0]["decode_point"]
            .as_str()
            .unwrap()
            .contains("raw socket"),
        true
    );
    assert_eq!(header_pairs(&rows[0]["headers"]), expected);
    // The exact request head bytes must be recoverable from the evidence.
    use base64::Engine as _;
    let raw_b64 = rows[0]["raw_head_b64"].as_str().unwrap();
    let raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .unwrap();
    assert_eq!(raw_bytes, raw, "raw head bytes must be byte-identical");
}

#[test]
fn h1_setcookie_keeps_response_order() {
    let (addr, dir) = start_h1("h1-setcookie");
    thread::sleep(Duration::from_millis(100));

    let resp = h1_request(
        addr,
        b"GET /setcookie HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(resp.status, 200);
    let cookies: Vec<&str> = resp
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        cookies,
        vec![
            "sc_a=alpha; Path=/; SameSite=Lax",
            "sc_b=beta; Path=/; SameSite=Lax",
            "sc_dup=one; Path=/; SameSite=Lax",
            "sc_dup=two; Path=/; SameSite=Lax",
        ]
    );
    let markers: Vec<&str> = resp
        .headers
        .iter()
        .filter(|(n, _)| n == "x-scrapelens-order")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        markers,
        vec!["0", "1", "2", "3", "4"],
        "Set-Cookie order preserved with markers"
    );

    let rows = read_evidence(&dir, "h1.jsonl");
    assert_eq!(rows.len(), 1);
    assert_eq!(header_pairs(&rows[0]["response"]["headers"]), resp.headers);
}

#[test]
fn h1_echo_returns_exact_body_bytes() {
    let (addr, _dir) = start_h1("h1-echo");
    thread::sleep(Duration::from_millis(100));

    let body: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let mut raw = format!(
        "POST /echo HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);

    let resp = h1_request(addr, &raw);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, body, "echo must be byte-identical");
}

#[test]
fn h1_chunked_body_is_dechunked_and_echoed() {
    let (addr, dir) = start_h1("h1-chunked");
    thread::sleep(Duration::from_millis(100));

    let raw = b"POST /echo HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let resp = h1_request(addr, raw);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello world");
    let rows = read_evidence(&dir, "h1.jsonl");
    assert_eq!(rows[0]["body_framing"], "chunked");
}

#[test]
fn h1_redirect_chain_is_recorded_per_hop() {
    let (addr, dir) = start_h1("h1-redirect");
    thread::sleep(Duration::from_millis(100));

    let mut target = "/redirect?n=2".to_string();
    let mut hops = 0;
    loop {
        let raw =
            format!("GET {target} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
        let resp = h1_request(addr, raw.as_bytes());
        hops += 1;
        if resp.status == 302 {
            target = resp
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .expect("location header");
            continue;
        }
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"redirect chain end\n");
        break;
    }
    assert_eq!(hops, 3);
    let rows = read_evidence(&dir, "h1.jsonl");
    assert_eq!(rows.len(), 3, "each hop is its own request/record");
    assert_eq!(rows[0]["response"]["status"], 302);
    assert_eq!(rows[2]["target"], "/redirect?n=0");
}

#[test]
fn h2_preserves_decoded_order_and_duplicates() {
    let (addr, dir) = start_h2("h2-order");
    thread::sleep(Duration::from_millis(150));

    let extras = vec![
        ("x-order".to_string(), "first".to_string()),
        ("x-dup".to_string(), "same".to_string()),
        ("x-order".to_string(), "second".to_string()),
        ("x-dup".to_string(), "same".to_string()),
        ("cookie".to_string(), "a=1".to_string()),
        ("cookie".to_string(), "b=2".to_string()),
    ];
    let resp = h2cli::get(addr, "/echo-order?probe=h2", &extras, &tls()).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.alpn, "h2");

    let json: Value = serde_json::from_slice(&resp.body).unwrap();
    let echoed = header_pairs(&json["headers"]);
    let mut expected = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), addr.to_string()),
        (":path".to_string(), "/echo-order?probe=h2".to_string()),
        (
            "user-agent".to_string(),
            "scrapelens-testserver-client/0.1".to_string(),
        ),
    ];
    expected.extend(extras.clone());
    assert_eq!(
        echoed, expected,
        "h2 decoded order must match what was sent"
    );

    let rows = read_evidence(&dir, "h2.jsonl");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["proto"], "h2");
    assert_eq!(rows[0]["stream"], 1);
    assert_eq!(header_pairs(&rows[0]["headers"]), expected);
    assert_eq!(
        rows[0]["decode_point"]
            .as_str()
            .unwrap()
            .contains("HPACK decoded field list"),
        true
    );
    // Raw HPACK bytes are kept next to the decoded list, for cross-checking.
    assert!(rows[0]["header_block_b64"].is_string());
    assert_eq!(header_pairs(&rows[0]["pseudoheaders"]).len(), 4);
}

#[test]
fn h3_preserves_decoded_order_and_duplicates() {
    let (addr, dir) = start_h3("h3-order");
    thread::sleep(Duration::from_millis(200));

    let extras = vec![
        ("x-order".to_string(), "first".to_string()),
        ("x-order".to_string(), "second".to_string()),
        ("x-dup".to_string(), "same".to_string()),
        ("cookie".to_string(), "a=1".to_string()),
        ("cookie".to_string(), "b=2".to_string()),
    ];
    let tls_files = tls();
    let resp = h3cli::get(addr, "/echo-order?probe=h3", &extras, &tls_files, false).unwrap();
    assert_eq!(resp.status, 200);

    let json: Value = serde_json::from_slice(&resp.body).unwrap();
    let echoed = header_pairs(&json["headers"]);
    let mut expected = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), addr.to_string()),
        (":path".to_string(), "/echo-order?probe=h3".to_string()),
        (
            "user-agent".to_string(),
            "scrapelens-testserver-client/0.1".to_string(),
        ),
    ];
    expected.extend(extras);
    assert_eq!(echoed, expected);

    let rows = read_evidence(&dir, "h3.jsonl");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["proto"], "h3");
    assert_eq!(header_pairs(&rows[0]["headers"]), expected);
    assert!(
        rows[0]["decode_point"]
            .as_str()
            .unwrap()
            .contains("QPACK decoded field list")
    );
}

#[test]
fn evidence_lines_are_versioned_and_complete() {
    let (addr, dir) = start_h1("h1-schema");
    thread::sleep(Duration::from_millis(100));
    let _ = h1_request(
        addr,
        b"GET /healthz HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    let rows = read_evidence(&dir, "h1.jsonl");
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r["schema"], "scrapelens.testserver.evidence/1");
    assert_eq!(r["ts_unix_ms"].as_u64().unwrap() > 1_700_000_000_000, true);
    assert!(r["ts_rfc3339"].as_str().unwrap().ends_with('Z'));
    assert!(r["headers"].is_array());
    assert_eq!(r["response"]["status"], 200);
    assert!(r["response"]["headers"].is_array());
    assert_eq!(r["body_len"], 0);
    // Each header entry is a two-element array, never an object.
    for pair in r["headers"].as_array().unwrap() {
        assert_eq!(pair.as_array().unwrap().len(), 2);
    }
}

#[test]
fn h1_body_routes_serve_expected_bytes_and_sink_writes_file() {
    let dir = std::env::temp_dir().join(format!("sl-bodies-{}", std::process::id()));
    scrapelens_testserver::endpoints::set_body_dir(dir.clone());
    let (addr, _ev) = start_h1("h1-bodies");
    thread::sleep(Duration::from_millis(100));
    let get = |path: &str| h1_request(addr, format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes());

    assert_eq!(get("/binary").body, scrapelens_testserver::endpoints::binary_bytes());
    assert!(std::str::from_utf8(&get("/binary").body).is_err());
    assert_eq!(get("/big").body.len(), 6 * 1024 * 1024);
    assert_eq!(get("/json").status, 200);
    assert_eq!(get("/redirect302").status, 302);
    assert_eq!(get("/empty").status, 204);
    let gz = get("/gzip");
    assert_eq!(&gz.body[..2], &[0x1f, 0x8b]);
    assert!(gz.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("content-encoding") && v == "gzip"));
    assert_eq!(&gz.body[gz.body.len() - 4..], &(scrapelens_testserver::endpoints::GZIP_TEXT.len() as u32).to_le_bytes());

    let payload: Vec<u8> = (0..=255u8).chain([0xFF, 0x00]).collect();
    let mut raw = format!("POST /redirect307 HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).into_bytes();
    raw.extend_from_slice(&payload);
    assert_eq!(h1_request(addr, &raw).status, 307);
    let mut raw = format!("POST /sink HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).into_bytes();
    raw.extend_from_slice(&payload);
    let r = h1_request(addr, &raw);
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    let file = v["file"].as_str().expect("sink file");
    assert_eq!(std::fs::read(file).unwrap(), payload);
}

/// Round 10 (docs/14-capture-multi-target.md): `/multi/` fires one request per
/// target kind, each with a unique `?m=` marker, and the server keeps the
/// marker in the normal evidence plus the compact `multi.jsonl` log.
#[test]
fn multi_target_page_marks_every_request_kind() {
    let dir = evidence_dir("multi");
    scrapelens_testserver::evidence::set_multi_log(&dir);
    let (addr, evdir) = start_h1("multi-h1");
    thread::sleep(Duration::from_millis(100));

    let page = h1_request(
        addr,
        b"GET /multi/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let html = String::from_utf8_lossy(&page.body);
    assert_eq!(page.status, 200);
    for needle in [
        "window.open('/multi/popup.html?m=popup-1'",
        "blank.html?m=blank-1",
        "iframe.html?m=oopif-1",
        "new Worker('/multi/worker.js')",
        "serviceWorker.register('/multi/sw.js'",
        "/multi/sw-fetch?m=sw-intercept-1",
    ] {
        assert!(html.contains(needle), "page without {needle}");
    }

    let js = h1_request(
        addr,
        b"GET /multi/worker.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(js.status, 200);
    assert!(js
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.starts_with("text/javascript")));
    assert!(String::from_utf8_lossy(&js.body).contains("worker-post-body-1"));

    let sw = h1_request(
        addr,
        b"GET /multi/sw.js HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let sw_js = String::from_utf8_lossy(&sw.body);
    assert!(sw_js.contains("sw-own-1") && sw_js.contains("sw-intercept-1"));

    let beacon = h1_request(
        addr,
        b"GET /multi/beacon?m=main-1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let v: Value = serde_json::from_slice(&beacon.body).unwrap();
    assert_eq!(v["marker"], "main-1");
    assert_eq!(v["method"], "GET");
    assert_eq!(v["schema"], "scrapelens.testserver.multi/1");

    let post_body = "main-post-body-1";
    let raw = format!(
        "POST /multi/ping?m=main-post-1 HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{post_body}",
        post_body.len()
    );
    let ping = h1_request(addr, raw.as_bytes());
    let v: Value = serde_json::from_slice(&ping.body).unwrap();
    assert_eq!(v["marker"], "main-post-1");
    assert_eq!(v["method"], "POST");
    assert_eq!(v["body_text"], post_body);
    assert_eq!(
        v["body_sha256"],
        "2a2c9f0adee25a25831065088dd4062b838a3c01d89c2b94d53da89a9ed9b572"
    );

    // Evidence keeps the marker; the compact multi.jsonl has it first.
    let rows = read_evidence(&evdir, "h1.jsonl");
    let marked: Vec<&Value> = rows.iter().filter(|r| r["marker"] == "main-post-1").collect();
    assert_eq!(marked.len(), 1, "marker in the evidence JSONL");
    assert_eq!(marked[0]["method"], "POST");
    let multi = read_evidence(&dir, "multi.jsonl");
    assert!(multi.iter().any(|r| r["marker"] == "main-post-1" && r["body_text"] == post_body));
    assert!(multi.iter().any(|r| r["marker"] == "main-1"));
    // Page/asset requests have no marker but are still logged.
    assert!(multi.iter().any(|r| r["target"] == "/multi/" && r["marker"].is_null()));
}
