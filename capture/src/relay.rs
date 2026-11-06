//! Local relay for a proxy link that has credentials or an allowlist.
//!
//! Chrome gets `socks5://127.0.0.1:<random port>` with no authentication. For each
//! connection the relay checks the destination against the allowlist (before anything
//! reaches the upstream), then opens a tunnel through the upstream proxy, adding its
//! credentials: SOCKS5 user/pass, or HTTP `CONNECT` with `Proxy-Authorization`. An
//! `https://` proxy is reached over TLS first (system trust store, plus a test-only extra
//! CA); the `CONNECT` then goes inside that TLS session. The relay copies bytes; it never
//! parses or changes the application's request.
//!
//! The password lives in this process only. Failures are recorded as text with no
//! credentials, for the capture to report. The relay stops when it is dropped, including
//! on an error path of the capture.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::proxy::{ProxyLink, ProxyScheme};

/// Decides whether a destination (host, port) may be reached through the relay.
pub type AllowFn = Arc<dyn Fn(&str, u16) -> bool + Send + Sync>;

/// How Chrome reaches the proxy for one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRoute {
    /// Chrome gets the proxy address itself (no credentials, no allowlist).
    Direct,
    /// Chrome talks to the local relay, which adds the credentials and the allowlist.
    Relay,
}

/// The proxy of one capture, prepared before Chrome starts. Dropping it stops the relay,
/// so every error path of the capture cleans it up.
pub struct ProxyPlan {
    link: ProxyLink,
    route: ProxyRoute,
    relay: Option<Relay>,
}

impl ProxyPlan {
    /// The direct route when the link has no credentials and there is no allowlist; the
    /// relay otherwise. With an allowlist the relay is always used, so every connection
    /// is checked before it leaves (`--host-resolver-rules` does not restrict targets once
    /// DNS happens at the proxy).
    pub fn prepare(link: ProxyLink, allow: Option<AllowFn>) -> Result<ProxyPlan, RelayError> {
        if allow.is_none() && !link.authenticated() {
            return Ok(ProxyPlan { link, route: ProxyRoute::Direct, relay: None });
        }
        let relay = Relay::start(&link, allow)?;
        Ok(ProxyPlan { link, route: ProxyRoute::Relay, relay: Some(relay) })
    }

    /// The value for Chrome's `--proxy-server`. Never contains credentials.
    pub fn chrome_arg(&self) -> String {
        match &self.relay {
            Some(relay) => format!("socks5://127.0.0.1:{}", relay.port()),
            None => self.link.chrome_server_arg(),
        }
    }

    pub fn route(&self) -> ProxyRoute {
        self.route
    }

    /// The link (scheme, host, port, whether it is authenticated). No credentials leave
    /// through this type's output.
    pub fn link(&self) -> &ProxyLink {
        &self.link
    }

    /// Failures the relay recorded, in order, without credentials.
    pub fn failures(&self) -> Vec<String> {
        self.relay.as_ref().map(Relay::failures).unwrap_or_default()
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// Why the relay could not start. Messages carry `scheme://host:port` at most, never
/// credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The upstream proxy could not be reached (DNS failure, refused, timeout).
    UpstreamUnreachable { server: String },
    /// TLS to an `https://` proxy failed. The message is already complete.
    Tls { message: String },
    /// The local listener could not be opened.
    Listen(String),
    /// The test-only extra CA could not be used. Certificate checks stay on.
    TestCa(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::UpstreamUnreachable { server } => write!(
                f,
                "the proxy {server} could not be reached: check the host name, the port and the network, then try again"
            ),
            RelayError::Tls { message } | RelayError::TestCa(message) => f.write_str(message),
            RelayError::Listen(detail) => write!(f, "the local proxy relay could not start: {detail}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// A running relay. Dropping it stops the listener and closes every open tunnel.
pub struct Relay {
    port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    failures: Arc<Mutex<Vec<String>>>,
    sockets: Arc<Mutex<Vec<TcpStream>>>,
}

impl Relay {
    /// Starts the relay for `link`. `allow` of `None` means no allowlist: any destination.
    /// An `https://` link reads `SCRAPELENS_TEST_PROXY_CA` (a PEM path) when it is set, and
    /// adds that root next to the system trust store. The variable is test-only: it is not
    /// an MCP or App option, and it never turns certificate checks off.
    pub fn start(link: &ProxyLink, allow: Option<AllowFn>) -> Result<Relay, RelayError> {
        let extra = if link.scheme() == ProxyScheme::Https {
            test_extra_ca_from_env()?
        } else {
            Vec::new()
        };
        Self::start_with_extra_ca(link, allow, &extra)
    }

    /// Same as [`Relay::start`], with the extra test CA passed in (PEM bytes, or empty).
    pub(crate) fn start_with_extra_ca(
        link: &ProxyLink,
        allow: Option<AllowFn>,
        extra_pem: &[u8],
    ) -> Result<Relay, RelayError> {
        let server = link.server_url();
        // Preflight: an unreachable upstream, or a certificate the system does not trust,
        // is reported now, not as a page timeout later.
        let tls = if link.scheme() == ProxyScheme::Https {
            let config = build_tls_config(extra_pem, &server)?;
            match tls_connect(link, &config) {
                Ok(_) => Some(config),
                Err(DialFail::Unreachable) => {
                    return Err(RelayError::UpstreamUnreachable { server });
                }
                Err(DialFail::Tls(message)) => return Err(RelayError::Tls { message }),
            }
        } else {
            let upstream = connect_upstream(link).ok();
            if upstream.is_none() {
                return Err(RelayError::UpstreamUnreachable { server });
            }
            None
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| RelayError::Listen(e.kind().to_string()))?;
        listener.set_nonblocking(true).map_err(|e| RelayError::Listen(e.kind().to_string()))?;
        let port = listener.local_addr().map_err(|e| RelayError::Listen(e.kind().to_string()))?.port();

        let shared = Shared {
            link: Arc::new(link.clone()),
            allow,
            tls,
            failures: Arc::new(Mutex::new(Vec::new())),
            sockets: Arc::new(Mutex::new(Vec::new())),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let stop = Arc::clone(&stop);
            let shared = shared.clone();
            thread::spawn(move || accept_loop(listener, stop, shared))
        };
        Ok(Relay {
            port,
            stop,
            accept: Some(accept),
            failures: shared.failures,
            sockets: shared.sockets,
        })
    }

    /// The loopback port Chrome must use: `socks5://127.0.0.1:<port>`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Reasons the relay refused or lost a connection, in order. No credentials.
    pub fn failures(&self) -> Vec<String> {
        self.failures.lock().map(|f| f.clone()).unwrap_or_default()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(sockets) = self.sockets.lock() {
            for socket in sockets.iter() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone)]
struct Shared {
    link: Arc<ProxyLink>,
    allow: Option<AllowFn>,
    tls: Option<Arc<ClientConfig>>,
    failures: Arc<Mutex<Vec<String>>>,
    sockets: Arc<Mutex<Vec<TcpStream>>>,
}

impl Shared {
    fn fail(&self, reason: String) {
        if let Ok(mut f) = self.failures.lock() {
            f.push(reason);
        }
    }

    fn track(&self, socket: &TcpStream) {
        if let (Ok(clone), Ok(mut list)) = (socket.try_clone(), self.sockets.lock()) {
            list.push(clone);
        }
    }
}

fn accept_loop(listener: TcpListener, stop: Arc<AtomicBool>, shared: Shared) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, _)) => {
                let _ = client.set_nonblocking(false);
                shared.track(&client);
                let shared = shared.clone();
                thread::spawn(move || handle_client(client, shared));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

/// One Chrome connection: SOCKS5 (no auth) from Chrome, then the tunnel.
fn handle_client(mut client: TcpStream, shared: Shared) {
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let target = match socks_request(&mut client) {
        Ok(target) => target,
        Err(_) => return,
    };
    let (host, port) = target;
    if let Some(allow) = &shared.allow {
        if !allow(&host, port) {
            shared.fail(format!("destination not allowed by the capture allowlist: {host}:{port}"));
            let _ = client.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
    }
    let upstream = match dial_through(&shared.link, shared.tls.as_ref(), &host, port) {
        Ok(stream) => stream,
        Err((reply, reason)) => {
            shared.fail(reason);
            let _ = client.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return;
    }
    let _ = client.set_read_timeout(None);
    match upstream {
        Upstream::Plain(stream) => {
            let _ = stream.set_read_timeout(None);
            shared.track(&stream);
            pipe(client, stream);
        }
        Upstream::Tls(stream) => {
            let stream = *stream;
            let _ = stream.sock.set_read_timeout(None);
            shared.track(&stream.sock);
            pipe_tls(client, stream);
        }
    }
}

/// Reads the SOCKS5 greeting and CONNECT request from Chrome. Only no-auth and CONNECT.
fn socks_request(client: &mut TcpStream) -> io::Result<(String, u16)> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no supported method"));
    }
    client.write_all(&[5, 0])?;
    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    if req[1] != 1 {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "only CONNECT"));
    }
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b)?;
            Ipv4Addr::from(b).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name)?;
            String::from_utf8(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "name"))?
        }
        4 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b)?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "address type")),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

/// The tunnel to the upstream proxy, after authentication. Plain TCP, or TLS for `https://`.
enum Upstream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

enum DialFail {
    Unreachable,
    Tls(String),
}

/// Opens the tunnel to `host:port` through the upstream proxy. The error is the SOCKS5
/// reply code for Chrome and a reason without credentials.
fn dial_through(
    link: &ProxyLink,
    tls: Option<&Arc<ClientConfig>>,
    host: &str,
    port: u16,
) -> Result<Upstream, (u8, String)> {
    let server = link.server_url();
    match link.scheme() {
        ProxyScheme::Https => {
            let config = tls.ok_or_else(|| {
                (1, format!("the proxy {server} needs TLS, and the relay has no certificate config"))
            })?;
            let mut stream = match tls_connect(link, config) {
                Ok(stream) => stream,
                Err(DialFail::Unreachable) => {
                    return Err((5, format!("the proxy {server} could not be reached")));
                }
                Err(DialFail::Tls(message)) => return Err((1, message)),
            };
            http_connect(&mut stream, link, host, port, &server)?;
            Ok(Upstream::Tls(Box::new(stream)))
        }
        ProxyScheme::Http | ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
            let mut stream = connect_upstream(link).map_err(|_| {
                (5u8, format!("the proxy {server} could not be reached"))
            })?;
            stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
            stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
            match link.scheme() {
                ProxyScheme::Http => http_connect(&mut stream, link, host, port, &server)?,
                _ => socks5_connect(&mut stream, link, host, port, &server)?,
            }
            Ok(Upstream::Plain(stream))
        }
    }
}

fn connect_upstream(link: &ProxyLink) -> io::Result<TcpStream> {
    let addr: SocketAddr = (link.host(), link.port())
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
}

/// `SCRAPELENS_TEST_PROXY_CA` is a PEM file of extra roots for the relay's TLS check.
/// Unset means system roots only. A set but unreadable file is an error: checks stay on.
fn test_extra_ca_from_env() -> Result<Vec<u8>, RelayError> {
    match std::env::var("SCRAPELENS_TEST_PROXY_CA") {
        Err(_) => Ok(Vec::new()),
        Ok(path) if path.trim().is_empty() => Ok(Vec::new()),
        Ok(path) => std::fs::read(path.trim()).map_err(|_| {
            RelayError::TestCa(
                "the test proxy CA file could not be read (SCRAPELENS_TEST_PROXY_CA). Certificate checks stay on"
                    .to_string(),
            )
        }),
    }
}

fn install_ring() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// System trust store, plus `extra_pem` when a test passed a CA. Never an empty store
/// and never a verifier that skips checks.
fn build_tls_config(extra_pem: &[u8], server: &str) -> Result<Arc<ClientConfig>, RelayError> {
    install_ring();
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if !extra_pem.is_empty() {
        let mut reader = std::io::Cursor::new(extra_pem);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                RelayError::TestCa(
                    "the test proxy CA is not a valid PEM certificate. Certificate checks stay on"
                        .to_string(),
                )
            })?;
        if certs.is_empty() {
            return Err(RelayError::TestCa(
                "the test proxy CA PEM contained no certificate. Certificate checks stay on".to_string(),
            ));
        }
        for cert in certs {
            roots.add(cert).map_err(|_| {
                RelayError::TestCa(
                    "the test proxy CA could not be added. Certificate checks stay on".to_string(),
                )
            })?;
        }
    }
    if roots.is_empty() {
        return Err(RelayError::Tls {
            message: format!(
                "the proxy {server} cannot be checked: no system trust roots were found. Install the system CA bundle, then try again"
            ),
        });
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn server_name(host: &str) -> Result<ServerName<'static>, ()> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_string()).map_err(|_| ())
    }
}

fn tls_connect(link: &ProxyLink, config: &Arc<ClientConfig>) -> Result<StreamOwned<ClientConnection, TcpStream>, DialFail> {
    let server = link.server_url();
    let mut sock = connect_upstream(link).map_err(|_| DialFail::Unreachable)?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
    sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
    let name = server_name(link.host()).map_err(|_| {
        DialFail::Tls(format!(
            "the proxy {server} host is not a DNS name or an IP address, so its certificate cannot be checked"
        ))
    })?;
    let mut conn = ClientConnection::new(Arc::clone(config), name).map_err(|error| {
        DialFail::Tls(tls_message(&server, &error))
    })?;
    while conn.is_handshaking() {
        if let Err(error) = conn.complete_io(&mut sock) {
            if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::ConnectionRefused {
                return Err(DialFail::Unreachable);
            }
            return Err(DialFail::Tls(tls_message(&server, &error)));
        }
    }
    Ok(StreamOwned::new(conn, sock))
}

/// A certificate or handshake failure. The text is rustls's own, trimmed, and it does
/// not contain the proxy credentials (those never enter the TLS stack).
fn tls_message(server: &str, error: &dyn fmt::Display) -> String {
    let detail: String = error.to_string().chars().take(180).collect();
    let lower = detail.to_ascii_lowercase();
    if lower.contains("certificate") || lower.contains("cert") || lower.contains("unknownissuer") || lower.contains("invalid peer") {
        format!(
            "the proxy {server} presented a certificate the system does not trust ({detail}). Install the proxy CA in the system trust store, or check the host name"
        )
    } else {
        format!("the proxy {server} could not complete TLS ({detail}). Check the host name and the port")
    }
}

/// Chrome's `net::ERR_*` proxy failures, as the same kind of sentence the relay records.
/// `None` when the text is an ordinary page or network failure.
pub(crate) fn chrome_proxy_failure(error_text: &str) -> Option<&'static str> {
    const MAP: &[(&str, &str)] = &[
        (
            "ERR_PROXY_CONNECTION_FAILED",
            "the proxy could not be reached: check the host name, the port and the network, then try again",
        ),
        (
            "ERR_MANDATORY_PROXY_CONFIGURATION_FAILED",
            "the proxy could not be reached: check the host name, the port and the network, then try again",
        ),
        (
            "ERR_SOCKS_CONNECTION_FAILED",
            "the proxy could not be reached: check the host name, the port and the network, then try again",
        ),
        (
            "ERR_PROXY_AUTH_REQUESTED",
            "the proxy refused the credentials (it asked for authentication). Give a link with the username and password, or check them",
        ),
        (
            "ERR_PROXY_AUTH_UNSUPPORTED",
            "the proxy asked for an authentication this capture cannot answer on the direct route. Give a link with the username and password so the local relay can authenticate",
        ),
        (
            "ERR_TUNNEL_CONNECTION_FAILED",
            "the proxy could not open the tunnel to the target. Check that the proxy allows that destination",
        ),
        (
            "ERR_SOCKS_CONNECTION_HOST_UNREACHABLE",
            "the proxy could not reach the target host",
        ),
        (
            "ERR_PROXY_CERTIFICATE_INVALID",
            "the proxy presented a certificate the system does not trust. Install the proxy CA in the system trust store, or check the host name",
        ),
        (
            "ERR_HTTPS_PROXY_TUNNEL_RESPONSE_REDIRECT",
            "the proxy answered the tunnel with a redirect instead of opening it",
        ),
        (
            "ERR_NO_SUPPORTED_PROXIES",
            "the proxy could not be used for this request",
        ),
    ];
    MAP.iter().find(|(code, _)| error_text.contains(code)).map(|(_, message)| *message)
}

/// Distinct proxy failures found in a CDP JSONL (`Network.loadingFailed`).
pub(crate) fn proxy_failures_from_cdp(events: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in events.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("method").and_then(|m| m.as_str()) != Some("Network.loadingFailed") {
            continue;
        }
        let Some(text) = value.pointer("/params/errorText").and_then(|t| t.as_str()) else {
            continue;
        };
        if let Some(message) = chrome_proxy_failure(text) {
            if !out.iter().any(|have| have == message) {
                out.push(message.to_string());
            }
        }
    }
    out
}

fn http_connect(
    stream: &mut (impl Read + Write),
    link: &ProxyLink,
    host: &str,
    port: u16,
    server: &str,
) -> Result<(), (u8, String)> {
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let (Some(user), Some(password)) = (link.user(), link.password()) {
        let token = base64(format!("{}:{}", user.expose(), password.expose()).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| (5, format!("the proxy {server} closed the connection")))?;
    let head = read_head(stream).map_err(|_| (5, format!("the proxy {server} closed the connection")))?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    match status {
        200 => Ok(()),
        407 => Err((2, format!("the proxy {server} refused the credentials (HTTP 407)"))),
        code => Err((5, format!("the proxy {server} refused {host}:{port} (HTTP {code})"))),
    }
}

fn socks5_connect(
    stream: &mut (impl Read + Write),
    link: &ProxyLink,
    host: &str,
    port: u16,
    server: &str,
) -> Result<(), (u8, String)> {
    let io_err = |_: io::Error| (5u8, format!("the proxy {server} closed the connection"));
    let with_auth = link.user().is_some() || link.password().is_some();
    stream
        .write_all(if with_auth { &[5, 1, 2] } else { &[5, 1, 0] })
        .map_err(io_err)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).map_err(io_err)?;
    match choice[1] {
        0 => {}
        2 => {
            let user = link.user().map(|u| u.expose().as_bytes().to_vec()).unwrap_or_default();
            let password = link.password().map(|p| p.expose().as_bytes().to_vec()).unwrap_or_default();
            if user.len() > 255 || password.len() > 255 {
                return Err((1, "the proxy credentials are too long for SOCKS5".to_string()));
            }
            let mut auth = vec![1, user.len() as u8];
            auth.extend_from_slice(&user);
            auth.push(password.len() as u8);
            auth.extend_from_slice(&password);
            stream.write_all(&auth).map_err(io_err)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).map_err(io_err)?;
            if status[1] != 0 {
                return Err((2, format!("the proxy {server} refused the credentials (SOCKS5 auth)")));
            }
        }
        _ => return Err((1, format!("the proxy {server} offered no usable SOCKS5 method"))),
    }
    let name = host.as_bytes();
    if name.len() > 255 {
        return Err((1, format!("the destination name is too long for SOCKS5: {host}")));
    }
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(io_err)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(io_err)?;
    // Consume the bound address so the tunnel starts at the application's first byte.
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(io_err)?;
            len[0] as usize + 2
        }
        _ => return Err((1, format!("the proxy {server} sent an unknown reply"))),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).map_err(io_err)?;
    match head[1] {
        0 => Ok(()),
        5 => Err((5, format!("the proxy {server} refused {host}:{port}"))),
        4 => Err((4, format!("the proxy {server} could not reach {host}:{port}"))),
        _ => Err((1, format!("the proxy {server} failed to open {host}:{port}"))),
    }
}

/// Reads an HTTP response head (up to the blank line), one byte at a time so that no
/// tunnel byte is consumed.
fn read_head(stream: &mut impl Read) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Copies bytes both ways across a TLS session. One thread: a `rustls` connection cannot
/// be split, and a short read timeout wakes the loop so neither direction stalls the other.
fn pipe_tls<C, D>(mut client: TcpStream, mut tls: StreamOwned<C, TcpStream>)
where
    C: std::ops::DerefMut + std::ops::Deref<Target = rustls::ConnectionCommon<D>>,
    D: rustls::SideData,
{
    let tick = Some(Duration::from_millis(50));
    let _ = client.set_read_timeout(tick);
    let _ = client.set_write_timeout(None);
    let _ = tls.sock.set_read_timeout(tick);
    let _ = tls.sock.set_write_timeout(None);
    let mut buf = [0u8; 16384];
    let mut client_open = true;
    let mut tls_open = true;
    while client_open || tls_open {
        if client_open {
            match client.read(&mut buf) {
                Ok(0) => {
                    client_open = false;
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                Ok(n) => {
                    if tls.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if timed_out(&e) => {}
                Err(_) => break,
            }
        }
        if tls_open {
            match tls.read(&mut buf) {
                Ok(0) => {
                    tls_open = false;
                    let _ = client.shutdown(Shutdown::Write);
                }
                Ok(n) => {
                    if client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if timed_out(&e) => {}
                Err(_) => break,
            }
        }
    }
}

fn timed_out(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

fn pipe(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut client_r), Ok(mut upstream_r)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let (mut client_w, mut upstream_w) = (client, upstream);
    let forward = thread::spawn(move || {
        let _ = io::copy(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = forward.join();
}

/// Standard Base64 with padding (RFC 4648). Used for `Proxy-Authorization: Basic`.
pub(crate) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn an_unreachable_upstream_is_reported_without_credentials() {
        let link = ProxyLink::parse("http://exp-user:Pw-Relay-9@127.0.0.1:1").unwrap();
        let err = Relay::start(&link, None).err().expect("refused");
        let shown = format!("{err:?} {err}");
        assert!(matches!(err, RelayError::UpstreamUnreachable { .. }), "{shown}");
        assert!(!shown.contains("exp-user") && !shown.contains("Pw-Relay-9"), "{shown}");
    }

    #[test]
    fn an_unreachable_https_upstream_is_reported_without_credentials() {
        let link = ProxyLink::parse("https://exp-user:Pw-Relay-9@127.0.0.1:1").unwrap();
        let err = Relay::start_with_extra_ca(&link, None, b"").err().expect("refused");
        let shown = format!("{err:?} {err}");
        assert!(matches!(err, RelayError::UpstreamUnreachable { .. }), "{shown}");
        assert!(!shown.contains("exp-user") && !shown.contains("Pw-Relay-9"), "{shown}");
    }

    #[test]
    fn chrome_proxy_errors_become_the_relay_sentences_and_page_errors_do_not() {
        assert!(chrome_proxy_failure("net::ERR_PROXY_CONNECTION_FAILED")
            .unwrap()
            .contains("could not be reached"));
        assert!(chrome_proxy_failure("net::ERR_TUNNEL_CONNECTION_FAILED")
            .unwrap()
            .contains("tunnel"));
        assert!(chrome_proxy_failure("net::ERR_PROXY_AUTH_REQUESTED")
            .unwrap()
            .contains("credentials"));
        assert!(chrome_proxy_failure("net::ERR_CONNECTION_REFUSED").is_none());
        let events = concat!(
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_PROXY_CONNECTION_FAILED"}}"#,
            "\n",
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_PROXY_CONNECTION_FAILED"}}"#,
            "\n",
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_TIMED_OUT"}}"#,
            "\n",
        );
        let found = proxy_failures_from_cdp(events);
        assert_eq!(found.len(), 1, "{found:?}");
    }
}

#[cfg(test)]
mod wire_tests {
    //! Real sockets: a fake upstream proxy (SOCKS5 user/pass or HTTP CONNECT with Basic),
    //! the relay, and a SOCKS5 client standing in for Chrome.
    use super::*;
    use std::net::TcpListener;

    const USER: &str = "exp-user";
    const PASSWORD: &str = "Pw-Relay-9";

    fn echo_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = conn.read(&mut buf) {
                        if n == 0 || conn.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// What the fake upstream saw: "auth-ok", "auth-refused", "CONNECT host:port".
    type Seen = Arc<Mutex<Vec<String>>>;

    fn socks_upstream(user: &'static str, password: &'static str) -> (u16, Seen) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    let mut c = conn;
                    let mut head = [0u8; 2];
                    if c.read_exact(&mut head).is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; head[1] as usize];
                    let _ = c.read_exact(&mut methods);
                    if !methods.contains(&2) {
                        return;
                    }
                    let _ = c.write_all(&[5, 2]);
                    let mut ulen = [0u8; 2];
                    let _ = c.read_exact(&mut ulen);
                    let mut got_user = vec![0u8; ulen[1] as usize];
                    let _ = c.read_exact(&mut got_user);
                    let mut plen = [0u8; 1];
                    let _ = c.read_exact(&mut plen);
                    let mut got_pass = vec![0u8; plen[0] as usize];
                    let _ = c.read_exact(&mut got_pass);
                    let ok = got_user == user.as_bytes() && got_pass == password.as_bytes();
                    let _ = c.write_all(&[1, if ok { 0 } else { 1 }]);
                    if !ok {
                        log.lock().unwrap().push("auth-refused".to_string());
                        return;
                    }
                    log.lock().unwrap().push("auth-ok".to_string());
                    let mut req = [0u8; 4];
                    let _ = c.read_exact(&mut req);
                    let mut len = [0u8; 1];
                    let _ = c.read_exact(&mut len);
                    let mut name = vec![0u8; len[0] as usize];
                    let _ = c.read_exact(&mut name);
                    let mut port_b = [0u8; 2];
                    let _ = c.read_exact(&mut port_b);
                    let target_port = u16::from_be_bytes(port_b);
                    let host = String::from_utf8_lossy(&name).into_owned();
                    log.lock().unwrap().push(format!("CONNECT {host}:{target_port}"));
                    match TcpStream::connect((host.as_str(), target_port)) {
                        Ok(target) => {
                            let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                            pipe(c, target);
                        }
                        Err(_) => {
                            let _ = c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    fn http_upstream(user: &'static str, password: &'static str) -> (u16, Seen) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let expected = format!("Basic {}", base64(format!("{user}:{password}").as_bytes()));
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                let expected = expected.clone();
                thread::spawn(move || {
                    let mut c = conn;
                    let head = match read_head(&mut c) {
                        Ok(h) => h,
                        Err(_) => return,
                    };
                    let auth_ok = head.lines().any(|l| l.eq_ignore_ascii_case(&format!("Proxy-Authorization: {expected}")));
                    if !auth_ok {
                        log.lock().unwrap().push("auth-refused".to_string());
                        let _ = c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    log.lock().unwrap().push("auth-ok".to_string());
                    let target_line = head.lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_string();
                    log.lock().unwrap().push(format!("CONNECT {target_line}"));
                    let (h, p) = target_line.rsplit_once(':').unwrap();
                    match TcpStream::connect((h, p.parse::<u16>().unwrap())) {
                        Ok(target) => {
                            let _ = c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                            pipe(c, target);
                        }
                        Err(_) => {
                            let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    /// HTTPS proxy: the fixture leaf (127.0.0.1) over TLS, then the same CONNECT as `http_upstream`.
    fn https_upstream(user: &'static str, password: &'static str) -> (u16, Seen) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let expected = format!("Basic {}", base64(format!("{user}:{password}").as_bytes()));
        let tls_config = fixture_server_config();
        thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                let expected = expected.clone();
                let tls_config = Arc::clone(&tls_config);
                thread::spawn(move || {
                    let Ok(server) = rustls::ServerConnection::new(tls_config) else {
                        return;
                    };
                    let mut tls = rustls::StreamOwned::new(server, conn);
                    let head = match read_head(&mut tls) {
                        Ok(h) => h,
                        Err(_) => return,
                    };
                    let auth_ok = head.lines().any(|l| l.eq_ignore_ascii_case(&format!("Proxy-Authorization: {expected}")));
                    if !auth_ok {
                        log.lock().unwrap().push("auth-refused".to_string());
                        let _ = tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    log.lock().unwrap().push("auth-ok".to_string());
                    let target_line = head.lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_string();
                    log.lock().unwrap().push(format!("CONNECT {target_line}"));
                    let Some((h, p)) = target_line.rsplit_once(':') else { return };
                    let Ok(target_port) = p.parse::<u16>() else { return };
                    match TcpStream::connect((h, target_port)) {
                        Ok(target) => {
                            let _ = tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                            pipe_tls(target, tls);
                        }
                        Err(_) => {
                            let _ = tls.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/tls")
    }

    fn fixture_server_config() -> Arc<rustls::ServerConfig> {
        install_ring();
        let dir = fixture_dir();
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("scrapelens-test-localhost.crt.pem")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("scrapelens-test-localhost.key.pem")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    fn fixture_ca_pem() -> Vec<u8> {
        std::fs::read(fixture_dir().join("scrapelens-test-ca.crt.pem")).unwrap()
    }

    /// A SOCKS5 client (Chrome's side): returns the reply code and the connected socket.
    fn chrome_connect(relay_port: u16, target_port: u16) -> (u8, TcpStream) {
        let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut choice = [0u8; 2];
        c.read_exact(&mut choice).unwrap();
        assert_eq!(choice, [5, 0]);
        let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&target_port.to_be_bytes());
        c.write_all(&req).unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap();
        (reply[1], c)
    }

    fn start(link: &str, allow: Option<AllowFn>) -> Relay {
        let link = ProxyLink::parse(link).unwrap();
        Relay::start(&link, allow).expect("relay starts")
    }

    #[test]
    fn socks_upstream_with_credentials_tunnels_bytes_unchanged() {
        let echo = echo_server();
        let (up, seen) = socks_upstream(USER, PASSWORD);
        let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), None);
        let (code, mut tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 0);
        tunnel.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut back = [0u8; 18];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"GET / HTTP/1.1\r\n\r\n");
        let log = seen.lock().unwrap().clone();
        assert_eq!(log[0], "auth-ok");
        assert_eq!(log[1], format!("CONNECT 127.0.0.1:{echo}"));
        assert!(relay.failures().is_empty());
    }

    #[test]
    fn https_upstream_without_the_test_ca_is_refused_and_shows_no_secret() {
        let (up, _seen) = https_upstream(USER, PASSWORD);
        let link = ProxyLink::parse(&format!("https://{USER}:{PASSWORD}@127.0.0.1:{up}")).unwrap();
        let err = match Relay::start_with_extra_ca(&link, None, b"") {
            Err(err) => err,
            Ok(_) => panic!("a fixture certificate must not be trusted without the test CA"),
        };
        let shown = format!("{err} {err:?}");
        assert!(matches!(err, RelayError::Tls { .. }), "{shown}");
        assert!(shown.contains("certificate") || shown.contains("trust"), "{shown}");
        assert!(!shown.contains(PASSWORD) && !shown.contains(USER), "{shown}");
    }

    #[test]
    fn https_upstream_with_the_test_ca_tunnels_bytes_and_checks_the_certificate() {
        let echo = echo_server();
        let (up, seen) = https_upstream(USER, PASSWORD);
        let link = ProxyLink::parse(&format!("https://{USER}:{PASSWORD}@127.0.0.1:{up}")).unwrap();
        let relay = Relay::start_with_extra_ca(&link, None, &fixture_ca_pem()).expect("trusted");
        let (code, mut tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 0);
        tunnel.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        assert_eq!(seen.lock().unwrap()[0], "auth-ok");
        assert!(relay.failures().is_empty(), "{:?}", relay.failures());
    }

    #[test]
    fn http_connect_upstream_gets_the_basic_credentials_and_tunnels() {
        let echo = echo_server();
        let (up, seen) = http_upstream(USER, PASSWORD);
        let relay = start(&format!("http://{USER}:{PASSWORD}@127.0.0.1:{up}"), None);
        let (code, mut tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 0);
        tunnel.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        tunnel.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        assert_eq!(seen.lock().unwrap()[0], "auth-ok");
    }

    #[test]
    fn a_destination_outside_the_allowlist_never_reaches_the_upstream() {
        let echo = echo_server();
        let (up, seen) = socks_upstream(USER, PASSWORD);
        let allow: AllowFn = Arc::new(|host: &str, _port: u16| host == "allowed.example");
        let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), Some(allow));
        let (code, _tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 2, "not allowed");
        let log = seen.lock().unwrap().clone();
        assert!(log.iter().all(|l| !l.starts_with("CONNECT")), "upstream saw {log:?}");
        assert!(relay.failures().iter().any(|f| f.contains("not allowed") && f.contains("127.0.0.1")));
    }

    #[test]
    fn refused_credentials_are_reported_without_the_password() {
        let echo = echo_server();
        let (up, _seen) = socks_upstream(USER, PASSWORD);
        let relay = start(&format!("socks5://{USER}:wrong-{PASSWORD}@127.0.0.1:{up}"), None);
        let (code, _tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 2);
        let failures = relay.failures();
        assert!(failures.iter().any(|f| f.contains("refused the credentials")), "{failures:?}");
        for f in &failures {
            assert!(!f.contains(PASSWORD) && !f.contains("wrong-") && !f.contains(USER), "{f}");
        }
    }

    #[test]
    fn dropping_the_relay_stops_listening() {
        let (up, _seen) = socks_upstream(USER, PASSWORD);
        let port = {
            let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), None);
            relay.port()
        };
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }

    #[test]
    fn the_direct_route_is_used_only_without_credentials_or_allowlist() {
        let plain = ProxyPlan::prepare(ProxyLink::parse("http://127.0.0.1:3128").unwrap(), None).unwrap();
        assert_eq!(plain.route(), ProxyRoute::Direct);
        assert_eq!(plain.chrome_arg(), "http://127.0.0.1:3128");
        assert!(plain.failures().is_empty());

        let socks_h = ProxyPlan::prepare(ProxyLink::parse("socks5h://127.0.0.1:1080").unwrap(), None).unwrap();
        assert_eq!(socks_h.chrome_arg(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn an_allowlist_forces_the_relay_and_the_relay_port_is_what_chrome_gets() {
        // The upstream only has to accept the preflight connection; the allowlist refuses
        // every destination, so nothing is ever tunnelled.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let up = listener.local_addr().unwrap().port();
        let allow: AllowFn = Arc::new(|_: &str, _: u16| false);
        let plan = ProxyPlan::prepare(
            ProxyLink::parse(&format!("socks5://exp-user:Pw-Plan-3@127.0.0.1:{up}")).unwrap(),
            Some(allow),
        )
        .unwrap();
        assert_eq!(plan.route(), ProxyRoute::Relay);
        assert!(plan.chrome_arg().starts_with("socks5://127.0.0.1:"));
        assert!(!plan.chrome_arg().contains("Pw-Plan-3") && !plan.chrome_arg().contains("exp-user"));
        drop(listener);
    }
}
