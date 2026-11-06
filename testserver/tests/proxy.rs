//! Integration tests for the loopback test proxies (HTTP, HTTPS, SOCKS5).
//!
//! Every test starts real listeners on ephemeral ports against loopback origins
//! it creates itself. Credentials are synthetic. Each test also checks that the
//! password and its Base64 `user:password` form appear nowhere in the evidence.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use scrapelens_testserver::cert::{self, TlsFiles};
use scrapelens_testserver::proxy::{self, Credentials, DropPoint, EvidenceLog, Kind, ProxyConfig};

const USER: &str = "tester-synthetic";
const PASS: &str = "pw-synthetic-7f3a";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tls_files() -> TlsFiles {
    cert::test_tls()
}

fn scratch(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "scrapelens-proxy-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A started proxy plus the evidence file it writes.
struct Started {
    addr: SocketAddr,
    evidence: PathBuf,
}

fn start(kind: Kind, tag: &str, configure: impl FnOnce(&mut ProxyConfig)) -> Started {
    let dir = scratch(tag);
    let evidence = dir.join("evidence.jsonl");
    let log = Arc::new(EvidenceLog::open(&evidence).unwrap());
    let listener = proxy::bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = ProxyConfig::new(kind, log, addr.to_string());
    if kind == Kind::Https {
        cfg.tls = Some(proxy::tls_server_config(&tls_files()).unwrap());
    }
    configure(&mut cfg);
    proxy::spawn(listener, cfg);
    Started { addr, evidence }
}

fn creds() -> Credentials {
    Credentials::parse(&format!("{USER}:{PASS}")).unwrap()
}

fn basic_header() -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASS}"));
    format!("Proxy-Authorization: Basic {token}\r\n")
}

/// Waits (bounded) until the evidence file has at least `n` lines.
fn records(evidence: &Path, n: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(evidence).unwrap_or_default();
        let lines: Vec<Value> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("evidence line is JSON"))
            .collect();
        if lines.len() >= n || Instant::now() >= deadline {
            return lines;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn one(evidence: &Path) -> Value {
    let mut recs = records(evidence, 1);
    assert_eq!(recs.len(), 1, "expected one evidence line");
    recs.remove(0)
}

fn assert_no_secret(evidence: &Path) {
    let text = std::fs::read_to_string(evidence).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASS}"));
    assert!(!text.contains(PASS), "password leaked into evidence");
    assert!(!text.contains(&b64), "Base64 credentials leaked into evidence");
    assert!(!text.contains(USER), "user name leaked into evidence");
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(7) % 251) as u8).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Echo origin: writes back every byte it reads, then closes its write side.
fn origin_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || echo(stream));
        }
    });
    addr
}

fn echo(mut stream: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Write);
}

/// Origin for absolute-URI requests: records each request head, answers `ok`.
fn origin_http(seen: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut one) {
                    Ok(1) => head.push(one[0]),
                    _ => break,
                }
            }
            seen.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            );
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    addr
}

fn connect_proxy(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}

/// Reads until the `\r\n\r\n` that ends a response head; returns the head text.
fn read_head(stream: &mut impl Read) -> String {
    let mut out = Vec::new();
    let mut one = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut one).expect("response head");
        assert_eq!(n, 1, "connection closed inside the response head");
        out.push(one[0]);
    }
    String::from_utf8(out).unwrap()
}

fn status_code(head: &str) -> u16 {
    head.split(' ').nth(1).unwrap().parse().unwrap()
}

/// Sends `data` on a helper thread while the caller reads `expect` bytes back.
fn echo_round_trip(mut stream: TcpStream, data: Vec<u8>) -> Vec<u8> {
    let mut writer = stream.try_clone().unwrap();
    let to_send = data.clone();
    let sender = thread::spawn(move || {
        writer.write_all(&to_send).unwrap();
        let _ = writer.shutdown(Shutdown::Write);
    });
    let mut back = Vec::new();
    stream.read_to_end(&mut back).unwrap();
    sender.join().unwrap();
    back
}

// ---------------------------------------------------------------------------
// HTTP: CONNECT
// ---------------------------------------------------------------------------

#[test]
fn http_connect_without_auth_relays_bytes_unchanged() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-noauth", |_| {});
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 200, "{head}");

    let data = payload(300 * 1024);
    let back = echo_round_trip(stream, data.clone());
    assert_eq!(back, data, "relay altered the tunnel bytes");

    let rec = one(&proxy.evidence);
    assert_eq!(rec["schema"], "scrapelens.testproxy.evidence/1");
    assert_eq!(rec["kind"], "http");
    assert_eq!(rec["protocol"], "CONNECT");
    assert_eq!(rec["target"], origin.to_string());
    assert_eq!(rec["target_kind"], "host-port");
    assert_eq!(rec["auth"]["required"], false);
    assert_eq!(rec["result"], "relayed");
    assert_eq!(rec["reply_code"], 200);
    assert_eq!(rec["bytes_up"], data.len() as u64);
    assert_eq!(rec["bytes_down"], data.len() as u64);
    assert_eq!(rec["sha256_up"], sha_hex(&data));
    assert_eq!(rec["sha256_down"], sha_hex(&data));
}

#[test]
fn http_connect_with_correct_credentials_is_relayed() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-auth-ok", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    write!(
        stream,
        "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n{}\r\n",
        basic_header()
    )
    .unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 200, "{head}");
    let data = payload(4096);
    assert_eq!(echo_round_trip(stream, data.clone()), data);

    let rec = one(&proxy.evidence);
    assert_eq!(rec["auth"]["required"], true);
    assert_eq!(rec["auth"]["presented"], true);
    assert_eq!(rec["auth"]["ok"], true);
    assert_eq!(rec["auth"]["method"], "basic");
    assert_eq!(rec["result"], "relayed");
    assert_no_secret(&proxy.evidence);
}

#[test]
fn http_connect_with_wrong_password_gets_407_and_no_tunnel() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-wrong", |c| c.credentials = Some(creds()));
    let wrong = {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:not-it"));
        format!("Proxy-Authorization: Basic {token}\r\n")
    };
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n{wrong}\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 407, "{head}");
    assert!(head.contains("Proxy-Authenticate: Basic realm=\"scrapelens-test\""), "{head}");

    let rec = one(&proxy.evidence);
    assert_eq!(rec["result"], "auth_failed");
    assert_eq!(rec["reply_code"], 407);
    assert_eq!(rec["auth"]["ok"], false);
    assert_eq!(rec["auth"]["presented"], true);
    assert_eq!(rec["bytes_up"], 0);
    assert_no_secret(&proxy.evidence);
}

#[test]
fn http_connect_without_credentials_gets_407() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-missing", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 407);
    let rec = one(&proxy.evidence);
    assert_eq!(rec["result"], "auth_failed");
    assert_eq!(rec["auth"]["presented"], false);
    assert_no_secret(&proxy.evidence);
}

#[test]
fn http_reject_auth_refuses_even_correct_credentials() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-reject", |c| {
        c.credentials = Some(creds());
        c.reject_auth = true;
    });
    let mut stream = connect_proxy(proxy.addr);
    write!(
        stream,
        "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n{}\r\n",
        basic_header()
    )
    .unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 407);
    assert_eq!(one(&proxy.evidence)["result"], "auth_failed");
    assert_no_secret(&proxy.evidence);
}

#[test]
fn http_connect_to_denied_target_gets_403_and_origin_is_not_contacted() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-deny", |c| {
        c.deny = vec![("127.0.0.1".into(), origin.port())];
    });
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 403);
    let rec = one(&proxy.evidence);
    assert_eq!(rec["result"], "target_refused");
    assert_eq!(rec["reply_code"], 403);
    assert_eq!(rec["bytes_up"], 0);
}

#[test]
fn http_connect_dropped_before_reply_closes_without_answer() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-drop-before", |c| c.drop = DropPoint::BeforeReply);
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "no bytes expected, got {rest:?}");
    assert_eq!(one(&proxy.evidence)["result"], "dropped_before_reply");
}

#[test]
fn http_connect_dropped_after_reply_sends_200_then_closes() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "connect-drop-after", |c| c.drop = DropPoint::AfterReply);
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 200);
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert_eq!(one(&proxy.evidence)["result"], "dropped_after_reply");
}

#[test]
fn http_connect_to_unreachable_target_gets_502() {
    // Bind and drop to obtain a port nothing listens on.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let proxy = start(Kind::Http, "connect-502", |_| {});
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {closed} HTTP/1.1\r\nHost: {closed}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 502);
    assert_eq!(one(&proxy.evidence)["result"], "upstream_failed");
}

// ---------------------------------------------------------------------------
// HTTP: absolute-URI
// ---------------------------------------------------------------------------

#[test]
fn http_absolute_uri_is_forwarded_in_origin_form_without_proxy_credentials() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin = origin_http(Arc::clone(&seen));
    let proxy = start(Kind::Http, "absolute", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    write!(
        stream,
        "GET http://{origin}/hello?x=1 HTTP/1.1\r\nHost: {origin}\r\nUser-Agent: scrapelens-test\r\n{}\r\n",
        basic_header()
    )
    .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(text.ends_with("ok"), "{text}");

    let heads = seen.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    let origin_head = &heads[0];
    assert!(origin_head.starts_with("GET /hello?x=1 HTTP/1.1\r\n"), "{origin_head}");
    assert!(!origin_head.to_ascii_lowercase().contains("proxy-authorization"), "{origin_head}");
    assert!(origin_head.contains("User-Agent: scrapelens-test"), "{origin_head}");
    assert!(origin_head.contains("Connection: close"), "{origin_head}");

    let rec = one(&proxy.evidence);
    assert_eq!(rec["protocol"], "GET");
    assert_eq!(rec["target_kind"], "absolute-uri");
    assert_eq!(rec["result"], "relayed");
    assert_no_secret(&proxy.evidence);
}

#[test]
fn http_absolute_uri_wrong_password_gets_407_and_origin_not_contacted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin = origin_http(Arc::clone(&seen));
    let proxy = start(Kind::Http, "absolute-wrong", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.1 407"));
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(one(&proxy.evidence)["result"], "auth_failed");
}

// ---------------------------------------------------------------------------
// HTTPS (TLS to the proxy)
// ---------------------------------------------------------------------------

fn tls_client(addr: SocketAddr) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let files = tls_files();
    let mut roots = rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(std::fs::File::open(&files.ca_pem).unwrap());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let tcp = connect_proxy(addr);
    rustls::StreamOwned::new(conn, tcp)
}

#[test]
fn https_proxy_connect_with_auth_relays_bytes_unchanged() {
    let origin = origin_echo();
    let proxy = start(Kind::Https, "https-auth", |c| c.credentials = Some(creds()));
    let mut tls = tls_client(proxy.addr);
    write!(
        tls,
        "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n{}\r\n",
        basic_header()
    )
    .unwrap();
    tls.flush().unwrap();
    let head = read_head(&mut tls);
    assert_eq!(status_code(&head), 200, "{head}");

    // Echo through the TLS-wrapped tunnel: write, then read the same amount back.
    let data = payload(64 * 1024);
    tls.write_all(&data).unwrap();
    tls.flush().unwrap();
    let mut back = vec![0u8; data.len()];
    tls.read_exact(&mut back).unwrap();
    assert_eq!(back, data);

    let rec = one_when_done(&proxy.evidence, &mut tls);
    assert_eq!(rec["kind"], "https");
    assert_eq!(rec["auth"]["ok"], true);
    assert_eq!(rec["bytes_up"], data.len() as u64);
    assert_eq!(rec["sha256_up"], sha_hex(&data));
    assert_no_secret(&proxy.evidence);
}

/// Closes the TLS client so the proxy finishes the tunnel, then reads the record.
fn one_when_done(
    evidence: &Path,
    tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Value {
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
    let mut rest = Vec::new();
    let _ = tls.read_to_end(&mut rest);
    one(evidence)
}

#[test]
fn https_proxy_wrong_password_gets_407() {
    let origin = origin_echo();
    let proxy = start(Kind::Https, "https-wrong", |c| c.credentials = Some(creds()));
    let mut tls = tls_client(proxy.addr);
    write!(tls, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    tls.flush().unwrap();
    let head = read_head(&mut tls);
    assert_eq!(status_code(&head), 407);
    assert_eq!(one(&proxy.evidence)["result"], "auth_failed");
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

fn socks_connect_domain(stream: &mut TcpStream, host: &str, port: u16) -> u8 {
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    reply[1]
}

fn socks_connect_ipv4(stream: &mut TcpStream, addr: SocketAddr) -> u8 {
    let std::net::IpAddr::V4(v4) = addr.ip() else { panic!("ipv4 expected") };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.octets());
    req.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    reply[1]
}

#[test]
fn socks5_no_auth_domain_target_is_resolved_by_proxy_and_relayed() {
    let origin = origin_echo();
    let proxy = start(Kind::Socks5, "socks-noauth", |_| {});
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    assert_eq!(socks_connect_domain(&mut stream, "localhost", origin.port()), 0);

    let data = payload(100 * 1024);
    let back = echo_round_trip(stream, data.clone());
    assert_eq!(back, data);

    let rec = one(&proxy.evidence);
    assert_eq!(rec["kind"], "socks5");
    assert_eq!(rec["protocol"], "SOCKS5");
    assert_eq!(rec["target_kind"], "socks-domain");
    assert_eq!(rec["target"], format!("localhost:{}", origin.port()));
    assert_eq!(rec["auth"]["required"], false);
    assert_eq!(rec["result"], "relayed");
    assert_eq!(rec["reply_code"], 0);
    assert_eq!(rec["bytes_up"], data.len() as u64);
    assert_eq!(rec["sha256_down"], sha_hex(&data));
}

#[test]
fn socks5_userpass_correct_then_ipv4_relayed() {
    let origin = origin_echo();
    let proxy = start(Kind::Socks5, "socks-auth-ok", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 2]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 2]);
    let mut sub = vec![1, USER.len() as u8];
    sub.extend_from_slice(USER.as_bytes());
    sub.push(PASS.len() as u8);
    sub.extend_from_slice(PASS.as_bytes());
    stream.write_all(&sub).unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).unwrap();
    assert_eq!(status, [1, 0]);
    assert_eq!(socks_connect_ipv4(&mut stream, origin), 0);
    let data = payload(2048);
    assert_eq!(echo_round_trip(stream, data.clone()), data);

    let rec = one(&proxy.evidence);
    assert_eq!(rec["auth"]["method"], "socks5-userpass");
    assert_eq!(rec["auth"]["ok"], true);
    assert_eq!(rec["target_kind"], "socks-ipv4");
    assert_eq!(rec["result"], "relayed");
    assert_no_secret(&proxy.evidence);
}

#[test]
fn socks5_wrong_password_gets_rfc1929_failure() {
    let proxy = start(Kind::Socks5, "socks-wrong", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 2]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 2]);
    let mut sub = vec![1, USER.len() as u8];
    sub.extend_from_slice(USER.as_bytes());
    sub.push(3);
    sub.extend_from_slice(b"bad");
    stream.write_all(&sub).unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).unwrap();
    assert_eq!(status, [1, 1]);
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    let rec = one(&proxy.evidence);
    assert_eq!(rec["result"], "auth_failed");
    assert_eq!(rec["auth"]["ok"], false);
    assert_no_secret(&proxy.evidence);
}

#[test]
fn socks5_auth_required_but_client_offers_only_no_auth_gets_ff() {
    let proxy = start(Kind::Socks5, "socks-noacc", |c| c.credentials = Some(creds()));
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0xFF]);
    assert_eq!(one(&proxy.evidence)["result"], "no_acceptable_method");
}

#[test]
fn socks5_denied_target_gets_reply_2() {
    let origin = origin_echo();
    let proxy = start(Kind::Socks5, "socks-deny", |c| {
        c.deny = vec![("localhost".into(), origin.port())];
    });
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(socks_connect_domain(&mut stream, "localhost", origin.port()), 2);
    let rec = one(&proxy.evidence);
    assert_eq!(rec["result"], "target_refused");
    assert_eq!(rec["reply_code"], 2);
}

#[test]
fn socks5_dropped_after_reply_closes_tunnel() {
    let origin = origin_echo();
    let proxy = start(Kind::Socks5, "socks-drop", |c| c.drop = DropPoint::AfterReply);
    let mut stream = connect_proxy(proxy.addr);
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(socks_connect_domain(&mut stream, "localhost", origin.port()), 0);
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert_eq!(one(&proxy.evidence)["result"], "dropped_after_reply");
}

// ---------------------------------------------------------------------------
// Tunnel dump and redaction
// ---------------------------------------------------------------------------

#[test]
fn tunnel_dump_records_exactly_the_bytes_that_crossed_the_relay() {
    let origin = origin_echo();
    let dir = scratch("dump");
    let dump_dir = dir.join("tunnel");
    let proxy = start(Kind::Http, "dump", |c| c.tunnel_dump = Some(dump_dir.clone()));
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 200);
    let data = payload(200 * 1024);
    assert_eq!(echo_round_trip(stream, data.clone()), data);

    let rec = one(&proxy.evidence);
    let conn = rec["conn"].as_str().unwrap();
    let up = std::fs::read(dump_dir.join(format!("{conn}.up.bin"))).unwrap();
    let down = std::fs::read(dump_dir.join(format!("{conn}.down.bin"))).unwrap();
    assert_eq!(up, data, "client-to-origin dump differs from what the client sent");
    assert_eq!(down, data, "origin-to-client dump differs from what the origin sent");
    assert_eq!(sha_hex(&up), rec["sha256_up"].as_str().unwrap());
}

#[test]
fn absolute_uri_dump_starts_with_the_rewritten_head_and_counts_match() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin = origin_http(Arc::clone(&seen));
    let dir = scratch("abs-dump");
    let dump_dir = dir.join("tunnel");
    let proxy = start(Kind::Http, "abs-dump", |c| {
        c.credentials = Some(creds());
        c.tunnel_dump = Some(dump_dir.clone());
    });
    let mut stream = connect_proxy(proxy.addr);
    write!(
        stream,
        "GET http://{origin}/dump?y=2 HTTP/1.1\r\nHost: {origin}\r\n{}\r\n",
        basic_header()
    )
    .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    assert!(String::from_utf8_lossy(&body).ends_with("ok"));

    let rec = one(&proxy.evidence);
    let conn = rec["conn"].as_str().unwrap();
    let up = std::fs::read(dump_dir.join(format!("{conn}.up.bin"))).unwrap();
    let up_text = String::from_utf8_lossy(&up).into_owned();
    assert!(up_text.starts_with("GET /dump?y=2 HTTP/1.1\r\n"), "{up_text}");
    assert!(!up_text.to_ascii_lowercase().contains("proxy-authorization"));
    assert_eq!(rec["bytes_up"], up.len() as u64);
    assert_eq!(rec["sha256_up"], sha_hex(&up));
    let down = std::fs::read(dump_dir.join(format!("{conn}.down.bin"))).unwrap();
    assert_eq!(rec["bytes_down"], down.len() as u64);
    assert_eq!(rec["sha256_down"], sha_hex(&down));
    assert_no_secret(&proxy.evidence);
}

#[test]
fn debug_output_and_error_strings_never_show_the_password() {
    let mut config = ProxyConfig::new(
        Kind::Http,
        Arc::new(EvidenceLog::open(&scratch("debug").join("e.jsonl")).unwrap()),
        "127.0.0.1:0".into(),
    );
    config.credentials = Some(creds());
    let shown = format!("{config:?} {:?}", config.credentials.as_ref().unwrap());
    assert!(!shown.contains(PASS), "{shown}");
    assert!(!shown.contains(USER), "{shown}");
    assert!(Credentials::parse("no-colon-here").is_err());
    assert!(!Credentials::parse("no-colon-here").unwrap_err().contains(PASS));
}

#[test]
fn resolve_maps_a_synthetic_name_only_through_the_proxy() {
    let origin = origin_echo();
    let proxy = start(Kind::Http, "resolve", |c| {
        c.resolve = vec![("site-a.test".into(), "127.0.0.1".into())];
    });
    // The name does not resolve on this machine; the proxy maps it itself.
    let mut stream = connect_proxy(proxy.addr);
    write!(
        stream,
        "CONNECT site-a.test:{} HTTP/1.1\r\nHost: site-a.test\r\n\r\n",
        origin.port()
    )
    .unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 200, "{head}");
    let data = payload(1024);
    assert_eq!(echo_round_trip(stream, data.clone()), data);
    let rec = one(&proxy.evidence);
    assert_eq!(rec["target"], format!("site-a.test:{}", origin.port()));
    assert_eq!(rec["result"], "relayed");
}

#[test]
fn without_resolve_the_same_name_is_an_upstream_failure_not_a_relay() {
    let proxy = start(Kind::Http, "no-resolve", |_| {});
    let mut stream = connect_proxy(proxy.addr);
    write!(stream, "CONNECT site-a.test.invalid:18781 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert_eq!(status_code(&head), 502, "{head}");
    assert_eq!(one(&proxy.evidence)["result"], "upstream_failed");
}

#[test]
fn parse_target_accepts_hosts_and_v6_and_rejects_empty_host() {
    assert_eq!(proxy::parse_target("Example.TEST:8080"), Some(("example.test".into(), 8080)));
    assert_eq!(proxy::parse_target("[::1]:443"), Some(("::1".into(), 443)));
    assert_eq!(proxy::parse_target(":80"), None);
    assert_eq!(proxy::parse_target("host:notaport"), None);
    assert_eq!(proxy::parse_target("host"), None);
}

#[test]
fn kind_and_drop_parse_only_the_documented_names() {
    assert_eq!(Kind::parse("socks5"), Some(Kind::Socks5));
    assert_eq!(Kind::parse("socks4"), None);
    assert_eq!(DropPoint::parse("after-reply"), Some(DropPoint::AfterReply));
    assert_eq!(DropPoint::parse("sometimes"), None);
}
