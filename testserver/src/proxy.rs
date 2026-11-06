//! Local test proxies for the ScrapeLens proxy-link contract.
//!
//! Three kinds, all bound to loopback, all synthetic:
//!
//! * `http`   — plain HTTP proxy: `CONNECT host:port` tunnels and absolute-URI
//!   requests (`GET http://host:port/path`). Optional `Basic` authentication.
//! * `https`  — the same HTTP proxy, reached over TLS (test certificate from
//!   `fixtures/tls/`, trusted through the fixture CA).
//! * `socks5` — SOCKS5 `CONNECT` with no authentication, or RFC 1929
//!   username/password. Domain names are resolved by the proxy (remote DNS).
//!
//! Each connection appends one JSON line to an evidence file (see
//! [`EvidenceLog`]). Credentials are never written anywhere: not in the
//! evidence, not in notes, not in `Debug` output. The relay forwards bytes
//! unchanged; the evidence keeps byte counts and SHA-256 per direction.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cert::TlsFiles;
use crate::util::{ConnIds, now_ms, note};

/// Schema tag of every evidence line.
pub const PROXY_SCHEMA: &str = "scrapelens.testproxy.evidence/1";
/// Realm sent in `Proxy-Authenticate` (no credentials in it).
pub const REALM: &str = "scrapelens-test";
pub const DEFAULT_PORT_HTTP: u16 = 8791;
pub const DEFAULT_PORT_HTTPS: u16 = 8792;
pub const DEFAULT_PORT_SOCKS5: u16 = 8793;

const HEAD_LIMIT: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Read timeout on every socket: the relay alternates directions every few ms.
const POLL: Duration = Duration::from_millis(5);
/// A tunnel with no traffic in either direction for this long is closed.
const IDLE: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Proxy protocol served by one listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Http,
    Https,
    Socks5,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "socks5" => Some(Self::Socks5),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks5 => "socks5",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => DEFAULT_PORT_HTTP,
            Self::Https => DEFAULT_PORT_HTTPS,
            Self::Socks5 => DEFAULT_PORT_SOCKS5,
        }
    }
}

/// Forced failure point for a connection (test-only behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropPoint {
    /// Normal behavior.
    Never,
    /// Close the client socket after reading the request, before any reply.
    BeforeReply,
    /// Send the success reply (`200` or SOCKS `00`), then close both sides.
    AfterReply,
}

impl DropPoint {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "never" => Some(Self::Never),
            "before-reply" => Some(Self::BeforeReply),
            "after-reply" => Some(Self::AfterReply),
            _ => None,
        }
    }
}

/// `user:password` for the proxy. The `Debug` output is redacted.
#[derive(Clone)]
pub struct Credentials {
    user: String,
    password: String,
}

impl Credentials {
    /// Splits at the first colon. Errors never echo the value.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let (user, password) = s
            .split_once(':')
            .ok_or("credentials must be user:password")?;
        if user.is_empty() {
            return Err("credentials need a non-empty user");
        }
        Ok(Self {
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    fn basic_token(&self) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.user, self.password))
    }

    /// `Proxy-Authorization` value check: scheme `Basic`, case-insensitive.
    fn matches_basic(&self, header: &str) -> bool {
        let mut parts = header.trim().splitn(2, ' ');
        let scheme = parts.next().unwrap_or("");
        let token = parts.next().unwrap_or("").trim();
        scheme.eq_ignore_ascii_case("basic") && token == self.basic_token()
    }

    /// RFC 1929 username/password check.
    fn matches_socks(&self, user: &[u8], password: &[u8]) -> bool {
        user == self.user.as_bytes() && password == self.password.as_bytes()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials(<redacted>)")
    }
}

/// Append-only JSONL evidence file, one line per connection.
pub struct EvidenceLog {
    file: Mutex<File>,
    seq: AtomicU64,
    conns: ConnIds,
}

impl EvidenceLog {
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            seq: AtomicU64::new(0),
            conns: ConnIds::default(),
        })
    }

    fn next_conn(&self) -> String {
        self.conns.next()
    }

    fn write(&self, rec: Value) {
        let Value::Object(mut map) = rec else { return };
        map.insert("schema".into(), json!(PROXY_SCHEMA));
        map.insert("seq".into(), json!(self.seq.fetch_add(1, Ordering::SeqCst)));
        map.insert(
            "ts_rfc3339".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        map.insert("ts_unix_ms".into(), json!(now_ms() as u64));
        let mut line = serde_json::to_string(&Value::Object(map)).unwrap_or_default();
        line.push('\n');
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

/// Everything one listener needs. Build with [`ProxyConfig::new`] and set fields.
pub struct ProxyConfig {
    pub kind: Kind,
    /// `127.0.0.1:port` as bound; written into every evidence line.
    pub listen: String,
    pub credentials: Option<Credentials>,
    /// Refuse every client with `407` / SOCKS `01` even when credentials are right.
    pub reject_auth: bool,
    /// Destinations refused with `403` / SOCKS `02` (lowercase host, port).
    pub deny: Vec<(String, u16)>,
    pub drop: DropPoint,
    /// When set, tunnel bytes are written to `<dir>/<conn>.up.bin` and `.down.bin`.
    pub tunnel_dump: Option<PathBuf>,
    /// Server TLS config for `Kind::Https` (see [`tls_server_config`]).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub log: Arc<EvidenceLog>,
}

impl ProxyConfig {
    pub fn new(kind: Kind, log: Arc<EvidenceLog>, listen: String) -> Self {
        Self {
            kind,
            listen,
            credentials: None,
            reject_auth: false,
            deny: Vec::new(),
            drop: DropPoint::Never,
            tunnel_dump: None,
            tls: None,
            log,
        }
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("kind", &self.kind)
            .field("listen", &self.listen)
            .field("credentials", &self.credentials)
            .field("reject_auth", &self.reject_auth)
            .field("deny", &self.deny)
            .field("drop", &self.drop)
            .field("tunnel_dump", &self.tunnel_dump)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

/// Parses `host:port`, `[v6]:port`; the host is lowercased.
pub fn parse_target(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        (h, after.strip_prefix(':')?)
    } else {
        s.rsplit_once(':')?
    };
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some((host.to_ascii_lowercase(), port))
}

/// Binds a loopback listener. Port 0 picks an ephemeral port.
pub fn bind(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}

/// Accepts connections until the listener fails. One thread per connection.
pub fn serve(listener: TcpListener, cfg: Arc<ProxyConfig>) -> io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || handle(stream, &cfg));
            }
            Err(e) => note("proxy", format!("accept failed: {:?}", e.kind())),
        }
    }
    Ok(())
}

/// Runs [`serve`] on a background thread (for tests and embedding).
pub fn spawn(listener: TcpListener, cfg: ProxyConfig) -> SocketAddr {
    let addr = listener.local_addr().expect("listener address");
    let cfg = Arc::new(cfg);
    thread::spawn(move || {
        let _ = serve(listener, cfg);
    });
    addr
}

/// Server TLS config for the `https` kind: the fixture leaf, no ALPN.
pub fn tls_server_config(
    files: &TlsFiles,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let mut cert_reader = BufReader::new(File::open(&files.cert_pem)?);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    let mut key_reader = BufReader::new(File::open(&files.key_pem)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("no private key in key PEM")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Per-connection record
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Tally {
    bytes: u64,
    sha256: Option<String>,
}

struct Hash {
    sha: Sha256,
    bytes: u64,
}

impl Hash {
    fn new() -> Self {
        Self {
            sha: Sha256::new(),
            bytes: 0,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.sha.update(bytes);
        self.bytes += bytes.len() as u64;
    }

    fn finish(self) -> Tally {
        let digest: String = self
            .sha
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Tally {
            bytes: self.bytes,
            sha256: Some(digest),
        }
    }
}

struct Attempt {
    conn: String,
    kind: Kind,
    listen: String,
    started: Instant,
    protocol: String,
    target: String,
    target_kind: &'static str,
    auth_required: bool,
    auth_presented: bool,
    auth_ok: Option<bool>,
    auth_method: &'static str,
    result: &'static str,
    reply_code: Option<u16>,
    up: Tally,
    down: Tally,
    notes: Vec<String>,
}

impl Attempt {
    fn new(cfg: &ProxyConfig) -> Self {
        Self {
            conn: cfg.log.next_conn(),
            kind: cfg.kind,
            listen: cfg.listen.clone(),
            started: Instant::now(),
            protocol: String::new(),
            target: String::new(),
            target_kind: "none",
            auth_required: false,
            auth_presented: false,
            auth_ok: None,
            auth_method: "none",
            // Overwritten on every path that is reached; "io_error" means the
            // connection failed before the proxy could classify it.
            result: "io_error",
            reply_code: None,
            up: Tally::default(),
            down: Tally::default(),
            notes: Vec::new(),
        }
    }

    /// Notes are fixed strings or I/O error kinds only: never credentials.
    fn add_note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    fn finish(self, log: &EvidenceLog) {
        log.write(json!({
            "conn": self.conn,
            "kind": self.kind.as_str(),
            "listen": self.listen,
            "protocol": self.protocol,
            "target": self.target,
            "target_kind": self.target_kind,
            "auth": {
                "required": self.auth_required,
                "presented": self.auth_presented,
                "method": self.auth_method,
                "ok": self.auth_ok,
            },
            "result": self.result,
            "reply_code": self.reply_code,
            "bytes_up": self.up.bytes,
            "bytes_down": self.down.bytes,
            "sha256_up": self.up.sha256,
            "sha256_down": self.down.sha256,
            "duration_ms": self.started.elapsed().as_millis() as u64,
            "notes": self.notes,
        }));
    }
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

fn handle(mut stream: TcpStream, cfg: &ProxyConfig) {
    let mut at = Attempt::new(cfg);
    let _ = stream.set_nodelay(true);
    if stream.set_read_timeout(Some(POLL)).is_err() {
        at.result = "io_error";
        at.add_note("set_read_timeout failed");
        at.finish(&cfg.log);
        return;
    }
    match cfg.kind {
        Kind::Http => serve_http(&mut stream, cfg, &mut at),
        Kind::Https => match cfg.tls.as_ref() {
            Some(tls) => match rustls::ServerConnection::new(Arc::clone(tls)) {
                Ok(conn) => {
                    let mut tls_stream = rustls::StreamOwned::new(conn, stream);
                    serve_http(&mut tls_stream, cfg, &mut at);
                }
                Err(_) => at.add_note("tls connection setup failed"),
            },
            None => at.add_note("https kind without a TLS config"),
        },
        Kind::Socks5 => {
            if let Err(e) = serve_socks(&mut stream, cfg, &mut at) {
                if at.result == "io_error" {
                    at.result = "client_error";
                }
                at.add_note(format!("socks5: {:?}", e.kind()));
            }
        }
    }
    at.finish(&cfg.log);
}

fn is_wait(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn read_head<C: Read>(client: &mut C) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut out = Vec::with_capacity(512);
    let mut one = [0u8; 1];
    loop {
        match client.read(&mut one) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "closed before end of request head",
                ));
            }
            Ok(_) => {
                out.push(one[0]);
                if out.ends_with(b"\r\n\r\n") {
                    return Ok(out);
                }
                if out.len() > HEAD_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request head too large",
                    ));
                }
            }
            Err(e) if is_wait(&e) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for request head",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

fn read_bytes<C: Read>(client: &mut C, n: usize) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match client.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed early",
                ));
            }
            Ok(k) => filled += k,
            Err(e) if is_wait(&e) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "client too slow"));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn respond<C: Write>(client: &mut C, status: &str, extra: &[String]) {
    let mut head = format!("HTTP/1.1 {status}\r\n");
    for line in extra {
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = client.write_all(head.as_bytes());
    let _ = client.flush();
}

fn http_fail<C: Write>(
    client: &mut C,
    at: &mut Attempt,
    status: &str,
    code: u16,
    result: &'static str,
    why: &str,
) {
    respond(client, status, &[]);
    at.reply_code = Some(code);
    at.result = result;
    at.add_note(why);
}

fn denied(cfg: &ProxyConfig, host: &str, port: u16) -> bool {
    cfg.deny
        .iter()
        .any(|(h, p)| *p == port && h.eq_ignore_ascii_case(host))
}

fn connect_upstream(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(POLL))?;
                return Ok(stream);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for host")))
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

struct Dest {
    host: String,
    port: u16,
    path: String,
}

impl Dest {
    fn display(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("http://{host}:{}{}", self.port, self.path)
    }
}

/// `http://host[:port][/path]`. Userinfo is dropped and never recorded.
fn parse_absolute(target: &str) -> Option<Dest> {
    let rest = strip_prefix_ci(target, "http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match parse_target(authority) {
        Some(hp) => hp,
        None => (
            authority
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase(),
            80,
        ),
    };
    if host.is_empty() {
        return None;
    }
    Some(Dest {
        host,
        port,
        path: path.to_string(),
    })
}

fn serve_http<C: Read + Write>(client: &mut C, cfg: &ProxyConfig, at: &mut Attempt) {
    let head = match read_head(client) {
        Ok(head) => head,
        Err(e) => {
            at.result = "client_error";
            at.add_note(format!("request head: {:?}", e.kind()));
            return;
        }
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").trim().to_string();
    // Recorded before the authentication decision so refused requests keep their method.
    at.protocol = method.clone();
    at.target = target.clone();

    // Authentication decision first; nothing is written before it is known.
    let presented = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.as_str());
    let required = cfg.credentials.is_some() || cfg.reject_auth;
    let authorized = !cfg.reject_auth
        && match (&cfg.credentials, presented) {
            (Some(creds), Some(value)) => creds.matches_basic(value),
            _ => false,
        };
    at.auth_required = required;
    at.auth_presented = presented.is_some();
    at.auth_method = if required { "basic" } else { "none" };
    if required {
        at.auth_ok = Some(authorized);
    }

    if cfg.drop == DropPoint::BeforeReply {
        at.result = "dropped_before_reply";
        return;
    }
    if required && !authorized {
        let challenge = format!("Proxy-Authenticate: Basic realm=\"{REALM}\"");
        respond(client, "407 Proxy Authentication Required", &[challenge]);
        at.reply_code = Some(407);
        at.result = "auth_failed";
        return;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = parse_target(&target) else {
            http_fail(client, at, "400 Bad Request", 400, "bad_request", "CONNECT target is not host:port");
            return;
        };
        at.target = format!("{host}:{port}");
        at.target_kind = "host-port";
        if denied(cfg, &host, port) {
            http_fail(client, at, "403 Forbidden", 403, "target_refused", "destination refused by proxy");
            return;
        }
        let mut upstream = match connect_upstream(&host, port) {
            Ok(stream) => stream,
            Err(e) => {
                let why = format!("upstream connect: {:?}", e.kind());
                http_fail(client, at, "502 Bad Gateway", 502, "upstream_failed", &why);
                return;
            }
        };
        let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
        let _ = client.flush();
        at.reply_code = Some(200);
        if cfg.drop == DropPoint::AfterReply {
            at.result = "dropped_after_reply";
            return;
        }
        tunnel(client, &mut upstream, cfg, at, false, &[]);
    } else {
        let Some(dest) = parse_absolute(&target) else {
            http_fail(
                client,
                at,
                "400 Bad Request",
                400,
                "bad_request",
                "only CONNECT and absolute http:// requests are supported",
            );
            return;
        };
        at.target = dest.display();
        at.target_kind = "absolute-uri";
        if denied(cfg, &dest.host, dest.port) {
            http_fail(client, at, "403 Forbidden", 403, "target_refused", "destination refused by proxy");
            return;
        }
        let mut upstream = match connect_upstream(&dest.host, dest.port) {
            Ok(stream) => stream,
            Err(e) => {
                let why = format!("upstream connect: {:?}", e.kind());
                http_fail(client, at, "502 Bad Gateway", 502, "upstream_failed", &why);
                return;
            }
        };
        // Origin form towards the origin. Proxy credentials are removed; the
        // connection is closed after the response so the relay ends cleanly.
        let mut forwarded = format!("{method} {} {version}\r\n", dest.path);
        for (name, value) in &headers {
            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "proxy-authorization" | "proxy-connection" | "connection") {
                continue;
            }
            forwarded.push_str(&format!("{name}: {value}\r\n"));
        }
        forwarded.push_str("Connection: close\r\n\r\n");
        at.add_note("forwarded in origin form; Proxy-Authorization removed; Connection: close added");
        // The rewritten head is the first client-to-origin bytes: it goes through the
        // relay so the byte counts, hashes and dump include it.
        tunnel(
            client,
            &mut upstream,
            cfg,
            at,
            cfg.drop == DropPoint::AfterReply,
            forwarded.as_bytes(),
        );
    }
}

fn socks_reply<C: Write>(client: &mut C, rep: u8) {
    let _ = client.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]);
    let _ = client.flush();
}

fn serve_socks<C: Read + Write>(client: &mut C, cfg: &ProxyConfig, at: &mut Attempt) -> io::Result<()> {
    at.protocol = "SOCKS5".into();
    let greeting = read_bytes(client, 2)?;
    if greeting[0] != 5 {
        at.result = "bad_request";
        at.add_note("not SOCKS5");
        return Ok(());
    }
    let methods = read_bytes(client, greeting[1] as usize)?;

    let required = cfg.credentials.is_some() || cfg.reject_auth;
    let chosen: u8 = if required { 0x02 } else { 0x00 };
    at.auth_required = required;
    at.auth_method = if required { "socks5-userpass" } else { "none" };
    at.auth_presented = methods.contains(&0x02);

    if cfg.drop == DropPoint::BeforeReply {
        at.result = "dropped_before_reply";
        return Ok(());
    }
    if !methods.contains(&chosen) {
        let _ = client.write_all(&[5, 0xFF]);
        at.result = "no_acceptable_method";
        at.reply_code = Some(0xFF);
        return Ok(());
    }
    client.write_all(&[5, chosen])?;

    if chosen == 0x02 {
        let version = read_bytes(client, 1)?;
        if version[0] != 1 {
            at.result = "bad_request";
            at.add_note("username/password subnegotiation version");
            return Ok(());
        }
        let user_len = read_bytes(client, 1)?[0] as usize;
        let user = read_bytes(client, user_len)?;
        let pass_len = read_bytes(client, 1)?[0] as usize;
        let password = read_bytes(client, pass_len)?;
        let ok = !cfg.reject_auth
            && cfg
                .credentials
                .as_ref()
                .is_some_and(|c| c.matches_socks(&user, &password));
        at.auth_ok = Some(ok);
        if !ok {
            client.write_all(&[1, 1])?;
            at.result = "auth_failed";
            at.add_note("RFC 1929 status 1");
            return Ok(());
        }
        client.write_all(&[1, 0])?;
    }

    let head = read_bytes(client, 4)?;
    if head[0] != 5 {
        at.result = "bad_request";
        at.add_note("request version");
        return Ok(());
    }
    if head[1] != 1 {
        socks_reply(client, 0x07);
        at.result = "unsupported";
        at.reply_code = Some(0x07);
        at.add_note("only CONNECT is supported");
        return Ok(());
    }
    let (host, kind) = match head[3] {
        1 => {
            let b = read_bytes(client, 4)?;
            (Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(), "socks-ipv4")
        }
        3 => {
            let len = read_bytes(client, 1)?[0] as usize;
            let name = read_bytes(client, len)?;
            (String::from_utf8_lossy(&name).into_owned(), "socks-domain")
        }
        4 => {
            let b = read_bytes(client, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b);
            (Ipv6Addr::from(octets).to_string(), "socks-ipv6")
        }
        _ => {
            socks_reply(client, 0x08);
            at.result = "unsupported";
            at.reply_code = Some(0x08);
            at.add_note("address type not supported");
            return Ok(());
        }
    };
    let port_bytes = read_bytes(client, 2)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    at.target = if kind == "socks-ipv6" {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    at.target_kind = kind;

    if denied(cfg, &host.to_ascii_lowercase(), port) {
        socks_reply(client, 0x02);
        at.result = "target_refused";
        at.reply_code = Some(0x02);
        return Ok(());
    }
    let mut upstream = match connect_upstream(&host, port) {
        Ok(stream) => stream,
        Err(e) => {
            let rep = if e.kind() == io::ErrorKind::ConnectionRefused { 0x05 } else { 0x01 };
            socks_reply(client, rep);
            at.result = "upstream_failed";
            at.reply_code = Some(rep as u16);
            at.add_note(format!("upstream connect: {:?}", e.kind()));
            return Ok(());
        }
    };
    socks_reply(client, 0x00);
    at.reply_code = Some(0);
    if cfg.drop == DropPoint::AfterReply {
        at.result = "dropped_after_reply";
        return Ok(());
    }
    tunnel(client, &mut upstream, cfg, at, false, &[]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

enum RelayEnd {
    /// The origin closed its side after the response.
    Closed,
    /// The first reply was forwarded and the relay stopped on purpose.
    Cut,
    Failed(String),
}

fn open_dump(cfg: &ProxyConfig, conn: &str, at: &mut Attempt) -> Option<(File, File)> {
    let dir = cfg.tunnel_dump.as_ref()?;
    let made = (|| -> io::Result<(File, File)> {
        fs::create_dir_all(dir)?;
        Ok((
            File::create(dir.join(format!("{conn}.up.bin")))?,
            File::create(dir.join(format!("{conn}.down.bin")))?,
        ))
    })();
    match made {
        Ok(files) => Some(files),
        Err(e) => {
            at.add_note(format!("tunnel dump: {:?}", e.kind()));
            None
        }
    }
}

/// Two-direction relay. The client-to-origin direction is written by a helper
/// thread, so neither direction can stall the other (no write-write deadlock).
/// The client side may be TLS: its reads are bounded by the socket timeout.
fn relay<C: Read + Write>(
    client: &mut C,
    upstream: &mut TcpStream,
    dump: &mut Option<(File, File)>,
    cut_after_first_reply: bool,
    prefix_up: &[u8],
) -> (Hash, Hash, RelayEnd) {
    let mut up = Hash::new();
    let mut down = Hash::new();
    let mut writer_sock = match upstream.try_clone() {
        Ok(sock) => sock,
        Err(e) => {
            return (up, down, RelayEnd::Failed(format!("clone upstream: {:?}", e.kind())));
        }
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let writer = thread::spawn(move || {
        for chunk in rx {
            if writer_sock.write_all(&chunk).is_err() {
                return;
            }
        }
        let _ = writer_sock.shutdown(Shutdown::Write);
    });
    let mut tx = Some(tx);
    if !prefix_up.is_empty() {
        up.feed(prefix_up);
        if let Some((up_file, _)) = dump.as_mut() {
            let _ = up_file.write_all(prefix_up);
        }
        if let Some(sender) = tx.as_ref() {
            let _ = sender.send(prefix_up.to_vec());
        }
    }
    let mut buf = vec![0u8; 16 * 1024];
    let mut last_activity = Instant::now();
    let end = loop {
        if last_activity.elapsed() > IDLE {
            break RelayEnd::Failed("idle timeout".into());
        }
        let mut active = false;
        if tx.is_some() {
            match client.read(&mut buf) {
                Ok(0) => {
                    tx = None; // the writer half-closes the origin side
                    active = true;
                }
                Ok(n) => {
                    up.feed(&buf[..n]);
                    if let Some((up_file, _)) = dump.as_mut() {
                        let _ = up_file.write_all(&buf[..n]);
                    }
                    let sent = tx
                        .as_ref()
                        .is_some_and(|sender| sender.send(buf[..n].to_vec()).is_ok());
                    if !sent {
                        break RelayEnd::Failed("upstream write failed".into());
                    }
                    active = true;
                }
                Err(e) if is_wait(&e) => {}
                Err(e) => break RelayEnd::Failed(format!("client read: {:?}", e.kind())),
            }
        }
        match upstream.read(&mut buf) {
            Ok(0) => break RelayEnd::Closed,
            Ok(n) => {
                down.feed(&buf[..n]);
                if let Some((_, down_file)) = dump.as_mut() {
                    let _ = down_file.write_all(&buf[..n]);
                }
                if let Err(e) = client.write_all(&buf[..n]).and_then(|()| client.flush()) {
                    break RelayEnd::Failed(format!("client write: {:?}", e.kind()));
                }
                active = true;
                if cut_after_first_reply {
                    break RelayEnd::Cut;
                }
            }
            Err(e) if is_wait(&e) => {}
            Err(e) => break RelayEnd::Failed(format!("upstream read: {:?}", e.kind())),
        }
        if active {
            last_activity = Instant::now();
        }
    };
    let _ = upstream.shutdown(Shutdown::Both);
    drop(tx);
    let _ = writer.join();
    (up, down, end)
}

fn tunnel<C: Read + Write>(
    client: &mut C,
    upstream: &mut TcpStream,
    cfg: &ProxyConfig,
    at: &mut Attempt,
    cut_after_first_reply: bool,
    prefix_up: &[u8],
) {
    let conn = at.conn.clone();
    let mut dump = open_dump(cfg, &conn, at);
    let (up, down, end) = relay(client, upstream, &mut dump, cut_after_first_reply, prefix_up);
    at.up = up.finish();
    at.down = down.finish();
    at.result = match end {
        RelayEnd::Closed => "relayed",
        RelayEnd::Cut => "dropped_after_reply",
        RelayEnd::Failed(why) => {
            at.add_note(why);
            "relay_error"
        }
    };
}
