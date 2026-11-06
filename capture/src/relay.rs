//! Local relay for a proxy link that has credentials or an allowlist.
//!
//! Chrome gets `socks5://127.0.0.1:<random port>` with no authentication. For each
//! connection the relay checks the destination against the allowlist (before anything
//! reaches the upstream), then opens a tunnel through the upstream proxy, adding its
//! credentials: SOCKS5 user/pass, or HTTP `CONNECT` with `Proxy-Authorization`. The
//! relay copies bytes; it never parses or changes the application's request.
//!
//! The password lives in this process only. Failures are recorded as text with no
//! credentials, for the capture to report. The relay stops when it is dropped, including
//! on an error path of the capture.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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

/// Why the relay could not start. Messages carry `scheme://host:port` at most.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The upstream proxy could not be reached (DNS failure, refused, timeout).
    UpstreamUnreachable { server: String },
    /// An `https://` proxy on the relay path needs TLS to the proxy, which the relay does
    /// not have. Without credentials or an allowlist, Chrome reaches it directly instead.
    HttpsUpstreamUnsupported,
    /// The local listener could not be opened.
    Listen(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::UpstreamUnreachable { server } => write!(
                f,
                "the proxy {server} could not be reached: check the host name, the port and the network, then try again"
            ),
            RelayError::HttpsUpstreamUnsupported => f.write_str(
                "an https:// proxy cannot be used with credentials or an allowlist yet: use http:// or socks5:// for that, or a link without credentials",
            ),
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
    pub fn start(link: &ProxyLink, allow: Option<AllowFn>) -> Result<Relay, RelayError> {
        if link.scheme() == ProxyScheme::Https {
            return Err(RelayError::HttpsUpstreamUnsupported);
        }
        let server = link.server_url();
        // Preflight: an unreachable upstream is reported now, not as a page timeout later.
        let upstream = (link.host(), link.port())
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .and_then(|addr| TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).ok());
        if upstream.is_none() {
            return Err(RelayError::UpstreamUnreachable { server });
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| RelayError::Listen(e.kind().to_string()))?;
        listener.set_nonblocking(true).map_err(|e| RelayError::Listen(e.kind().to_string()))?;
        let port = listener.local_addr().map_err(|e| RelayError::Listen(e.kind().to_string()))?.port();

        let shared = Shared {
            link: Arc::new(link.clone()),
            allow,
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
    let upstream = match dial_through(&shared.link, &host, port) {
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
    let _ = upstream.set_read_timeout(None);
    pipe(client, upstream);
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

/// Opens the tunnel to `host:port` through the upstream proxy. The error is the SOCKS5
/// reply code for Chrome and a reason without credentials.
fn dial_through(link: &ProxyLink, host: &str, port: u16) -> Result<TcpStream, (u8, String)> {
    let server = link.server_url();
    let mut stream = connect_upstream(link).map_err(|_| {
        (5, format!("the proxy {server} could not be reached"))
    })?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
    match link.scheme() {
        ProxyScheme::Http => http_connect(&mut stream, link, host, port, &server),
        ProxyScheme::Socks5 | ProxyScheme::Socks5h => socks5_connect(&mut stream, link, host, port, &server),
        ProxyScheme::Https => return Err((1, format!("the proxy {server} needs TLS, which the relay does not have"))),
    }?;
    Ok(stream)
}

fn connect_upstream(link: &ProxyLink) -> io::Result<TcpStream> {
    let addr: SocketAddr = (link.host(), link.port())
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
}

fn http_connect(
    stream: &mut TcpStream,
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
    stream: &mut TcpStream,
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
fn read_head(stream: &mut TcpStream) -> io::Result<String> {
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
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
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
    fn an_https_upstream_is_refused_on_the_relay_path_until_tls_exists() {
        let link = ProxyLink::parse("https://exp-user:Pw-Relay-9@127.0.0.1:443").unwrap();
        assert_eq!(Relay::start(&link, None).err(), Some(RelayError::HttpsUpstreamUnsupported));
        let no_creds = ProxyLink::parse("https://127.0.0.1:443").unwrap();
        assert_eq!(Relay::start(&no_creds, None).err(), Some(RelayError::HttpsUpstreamUnsupported));
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
