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
