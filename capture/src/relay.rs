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
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::proxy::{ProxyLink, ProxyScheme};

#[path = "relay_peer.rs"]
mod peer;

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

    /// Publishes the browser pid. Until this runs, the relay refuses every connection.
    /// Called after the browser is stopped and before it is continued, so nothing connects first.
    pub fn set_chrome_pid(&self, pid: u32) {
        if let Some(relay) = &self.relay {
            relay.set_owner_pid(pid);
        }
    }

    pub(crate) fn peer_check(&self) -> PeerCheck {
        self.relay.as_ref().map(Relay::peer_check).unwrap_or_default()
    }
}

/// How long the process check took, and how many connections it refused.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PeerCheck {
    pub checks: u64,
    pub refused: u64,
    pub max_nanos: u64,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
/// Enough for a real Chrome (page, workers, service worker, utility and network service)
/// without letting a local process open tunnels without bound.
const MAX_CLIENTS: usize = 512;
const MAX_FAILURES: usize = 32;

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
    failures: Arc<Mutex<Vec<(String, u32)>>>,
    sockets: Arc<Mutex<Vec<(u64, TcpStream)>>>,
    #[cfg(test)]
    client_limit: Arc<AtomicUsize>,
    owner: Arc<AtomicU32>,
    peer_checks: Arc<AtomicU64>,
    peer_refused: Arc<AtomicU64>,
    peer_max_nanos: Arc<AtomicU64>,
}

impl Relay {
    /// Starts the relay for `link`. `allow` of `None` means no allowlist: any destination.
    /// An `https://` link reads the test-only CA path when the `test-hooks` feature
    /// (or `cfg(test)`) is on, and adds that root next to the system trust store.
    /// It is not an MCP or App option, and it never turns certificate checks off.
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

        let client_limit = Arc::new(AtomicUsize::new(MAX_CLIENTS));
        let owner = Arc::new(AtomicU32::new(0));
        let peer_checks = Arc::new(AtomicU64::new(0));
        let peer_refused = Arc::new(AtomicU64::new(0));
        let peer_max_nanos = Arc::new(AtomicU64::new(0));
        let shared = Shared {
            link: Arc::new(link.clone()),
            allow,
            tls,
            failures: Arc::new(Mutex::new(Vec::new())),
            sockets: Arc::new(Mutex::new(Vec::new())),
            next_socket: Arc::new(AtomicU64::new(1)),
            clients: Arc::new(AtomicUsize::new(0)),
            client_limit: Arc::clone(&client_limit),
            owner: Arc::clone(&owner),
            listen_port: port,
            peer_checks: Arc::clone(&peer_checks),
            peer_refused: Arc::clone(&peer_refused),
            peer_max_nanos: Arc::clone(&peer_max_nanos),
        };
        #[cfg(not(test))]
        drop(client_limit);
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
            #[cfg(test)]
            client_limit,
            owner,
            peer_checks,
            peer_refused,
            peer_max_nanos,
        })
    }

    /// The only process, with its descendants, allowed to open a tunnel.
    /// Until this is called the relay refuses every connection and does not dial upstream.
    /// A capture passes the Chrome pid. Tests pass the process that stands in for it.
    pub fn set_owner_pid(&self, pid: u32) {
        self.owner.store(pid, Ordering::SeqCst);
    }

    pub(crate) fn peer_check(&self) -> PeerCheck {
        PeerCheck {
            checks: self.peer_checks.load(Ordering::Relaxed),
            refused: self.peer_refused.load(Ordering::Relaxed),
            max_nanos: self.peer_max_nanos.load(Ordering::Relaxed),
        }
    }

    /// Test-only ceiling, lower than [`MAX_CLIENTS`], so the cap can be observed
    /// without hundreds of sockets.
    #[cfg(test)]
    fn set_connection_limit(&self, limit: usize) {
        self.client_limit.store(limit.max(1), Ordering::SeqCst);
    }

    #[cfg(test)]
    fn tracked_sockets(&self) -> usize {
        self.sockets.lock().map(|list| list.len()).unwrap_or(0)
    }

    /// The loopback port Chrome must use: `socks5://127.0.0.1:<port>`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Reasons the relay refused or lost a connection, in order. The same reason is
    /// one entry; a repeat carries its count. No credentials.
    pub fn failures(&self) -> Vec<String> {
        self.failures
            .lock()
            .map(|failures| failures.iter().map(|(reason, count)| show_failure(reason, *count)).collect())
            .unwrap_or_default()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(sockets) = self.sockets.lock() {
            for (_, socket) in sockets.iter() {
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
    failures: Arc<Mutex<Vec<(String, u32)>>>,
    sockets: Arc<Mutex<Vec<(u64, TcpStream)>>>,
    next_socket: Arc<AtomicU64>,
    clients: Arc<AtomicUsize>,
    client_limit: Arc<AtomicUsize>,
    owner: Arc<AtomicU32>,
    listen_port: u16,
    peer_checks: Arc<AtomicU64>,
    peer_refused: Arc<AtomicU64>,
    peer_max_nanos: Arc<AtomicU64>,
}

/// One warning per reason. A repeat says how many times, and does not add a second warning.
fn show_failure(reason: &str, count: u32) -> String {
    if count <= 1 {
        reason.to_string()
    } else {
        format!("{reason} ({count} times)")
    }
}

/// Removes one tracked socket when the handler that owns it returns.
struct TrackedSocket {
    shared: Shared,
    id: u64,
}

impl Drop for TrackedSocket {
    fn drop(&mut self) {
        if let Ok(mut list) = self.shared.sockets.lock() {
            list.retain(|(id, _)| *id != self.id);
        }
    }
}

/// Releases one client slot when the handler returns, including on panic.
struct ClientSlot(Shared);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.clients.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Shared {
    fn fail(&self, reason: String) {
        if let Ok(mut failures) = self.failures.lock() {
            if let Some((_, count)) = failures.iter_mut().find(|(have, _)| have == &reason) {
                *count = count.saturating_add(1);
                return;
            }
            if failures.len() >= MAX_FAILURES {
                let extra = failures.len() + 1 - MAX_FAILURES;
                failures.drain(0..extra);
            }
            failures.push((reason, 1));
        }
    }

    fn track(&self, socket: &TcpStream) -> Option<TrackedSocket> {
        let clone = socket.try_clone().ok()?;
        let id = self.next_socket.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut list) = self.sockets.lock() {
            list.push((id, clone));
        }
        Some(TrackedSocket { shared: self.clone(), id })
    }

    fn try_acquire(&self) -> bool {
        let limit = self.client_limit.load(Ordering::SeqCst).max(1);
        let mut current = self.clients.load(Ordering::SeqCst);
        loop {
            if current >= limit {
                return false;
            }
            match self.clients.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
    }

    /// Positive admission is the only way into `handle_client`. A failed check never
    /// becomes success. An empty cancel is not shown to the user. Neither is a socket
    /// that no process still holds: that peer cannot read a tunnel. Unread bytes from
    /// a process that is still there, including after FIN, are a refusal.
    fn admit(&self, client: &TcpStream) -> Admission {
        let owner = self.owner.load(Ordering::SeqCst);
        let peer_port = match client.peer_addr() {
            Ok(addr) => addr.port(),
            Err(_) => {
                return if quiet_cancel(client) {
                    Admission::QuietClose
                } else {
                    self.peer_refused.fetch_add(1, Ordering::Relaxed);
                    Admission::Refused("the client process could not be confirmed")
                };
            }
        };
        let started = std::time::Instant::now();
        let verdict = peer::admit(peer_port, self.listen_port, owner);
        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.peer_checks.fetch_add(1, Ordering::Relaxed);
        let mut current = self.peer_max_nanos.load(Ordering::Relaxed);
        while nanos > current {
            match self.peer_max_nanos.compare_exchange(current, nanos, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        match verdict {
            // The browser already half-closed. Do not dial upstream for a dead request.
            Ok(()) if peer_sent_fin(client) => Admission::QuietClose,
            Ok(()) => Admission::Admitted,
            Err(_) if quiet_cancel(client) => Admission::QuietClose,
            Err(peer::ALREADY_CLOSED) => Admission::QuietClose,
            Err(reason) => {
                self.peer_refused.fetch_add(1, Ordering::Relaxed);
                Admission::Refused(reason)
            }
        }
    }
}

enum Admission {
    Admitted,
    QuietClose,
    Refused(&'static str),
}

/// True when the peer has closed and the receive buffer is empty.
/// FIN with a greeting or CONNECT still buffered is not an empty cancel.
fn quiet_cancel(stream: &TcpStream) -> bool {
    let previous = stream.read_timeout().ok().flatten();
    if stream.set_read_timeout(Some(Duration::from_millis(5))).is_err() {
        return false;
    }
    let mut buf = [0u8; 1];
    let quiet = match stream.peek(&mut buf) {
        Ok(0) => true,
        Err(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::NotConnected
        ),
        Ok(_) => false,
    };
    let _ = stream.set_read_timeout(previous);
    quiet
}

fn peer_sent_fin(stream: &TcpStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut buf = [0u8; 256];
    let mut len = buf.len() as libc::socklen_t;
    #[cfg(target_os = "macos")]
    let name = libc::TCP_CONNECTION_INFO;
    #[cfg(target_os = "linux")]
    let name = libc::TCP_INFO;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (stream, &mut buf, &mut len);
        return false;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // SAFETY: `buf` is writable for `len` bytes. The call only writes the TCP info.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                name,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 || len == 0 {
            return false;
        }
        // `tcpi_state` is the first byte. macOS uses the BSD `TCPS_*` numbers
        // (CLOSE_WAIT is 5). Linux uses its own (CLOSE_WAIT is 8).
        let state = buf[0];
        #[cfg(target_os = "macos")]
        return matches!(state, 0 | 5 | 7 | 8 | 10);
        #[cfg(target_os = "linux")]
        return matches!(state, 6 | 7 | 8 | 9 | 11);
    }
}

fn accept_loop(listener: TcpListener, stop: Arc<AtomicBool>, shared: Shared) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, _)) => {
                let _ = client.set_nonblocking(false);
                if !shared.try_acquire() {
                    shared.fail("too many connections".to_string());
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
                let shared = shared.clone();
                thread::spawn(move || {
                    let _slot = ClientSlot(shared.clone());
                    let _tracked_client = shared.track(&client);
                    match shared.admit(&client) {
                        Admission::Admitted => handle_client(client, shared),
                        Admission::QuietClose => {
                            let _ = client.shutdown(Shutdown::Both);
                        }
                        Admission::Refused(reason) => {
                            shared.fail(reason.to_string());
                            let _ = client.shutdown(Shutdown::Both);
                        }
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

/// One admitted Chrome connection: SOCKS5 (no auth) from Chrome, then the tunnel.
/// The accept thread calls this only after `Admission::Admitted`.
fn handle_client(mut client: TcpStream, shared: Shared) {
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let target = match socks_request(&mut client) {
        Ok(target) => target,
        Err(_) => return,
    };
    let host = target.host();
    if let Some(allow) = &shared.allow {
        if !allow(&host, target.port) {
            shared.fail(format!(
                "destination not allowed by the capture allowlist: {}",
                target.authority()
            ));
            let _ = write_all_retry(&mut client, &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
    }
    let upstream = match dial_through(&shared.link, shared.tls.as_ref(), &target) {
        Ok(stream) => stream,
        Err((reply, reason)) => {
            shared.fail(reason);
            let _ = write_all_retry(&mut client, &[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    // Both ends are tracked before the success reply, so a caller that has
    // read the reply can rely on stop() shutting the upstream down too.
    let _ = client.set_read_timeout(None);
    let reply = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    match upstream {
        Upstream::Plain(stream) => {
            let _ = stream.set_read_timeout(None);
            let _tracked_upstream = shared.track(&stream);
            if write_all_retry(&mut client, &reply).is_err() {
                return;
            }
            pipe(client, stream);
        }
        Upstream::Tls(stream) => {
            let stream = *stream;
            let _ = stream.sock.set_read_timeout(None);
            let _tracked_upstream = shared.track(&stream.sock);
            if write_all_retry(&mut client, &reply).is_err() {
                return;
            }
            pipe_tls(client, stream);
        }
    }
}

/// Where Chrome asked to connect. The SOCKS address type is kept: an IP is not rewritten
/// as a domain name on the way to the upstream.
#[derive(Clone, Debug)]
enum HostAddr {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(String),
}

#[derive(Clone, Debug)]
struct Destination {
    host: HostAddr,
    port: u16,
}

impl Destination {
    /// Host as the allowlist sees it. An IPv6 literal has no brackets.
    fn host(&self) -> String {
        match &self.host {
            HostAddr::V4(octets) => Ipv4Addr::from(*octets).to_string(),
            HostAddr::V6(octets) => Ipv6Addr::from(*octets).to_string(),
            HostAddr::Name(name) => name.clone(),
        }
    }

    /// `host:port`, or `[ipv6]:port` when the host is an IPv6 literal (including a domain
    /// whose text is an IPv6 address). This is the HTTP CONNECT authority.
    fn authority(&self) -> String {
        let host = self.host();
        if matches!(self.host, HostAddr::V6(_)) || host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Reads the SOCKS5 greeting and CONNECT request from Chrome. Only no-auth and CONNECT.
fn socks_request(client: &mut (impl Read + Write)) -> io::Result<Destination> {
    let mut head = [0u8; 2];
    read_exact_retry(client, &mut head)?;
    if head[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    read_exact_retry(client, &mut methods)?;
    if !methods.contains(&0) {
        write_all_retry(client, &[5, 0xff])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no supported method"));
    }
    write_all_retry(client, &[5, 0])?;
    let mut req = [0u8; 4];
    read_exact_retry(client, &mut req)?;
    if req[1] != 1 {
        write_all_retry(client, &[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "only CONNECT"));
    }
    let host = match req[3] {
        1 => {
            let mut octets = [0u8; 4];
            read_exact_retry(client, &mut octets)?;
            HostAddr::V4(octets)
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact_retry(client, &mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            read_exact_retry(client, &mut name)?;
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "name"))?;
            HostAddr::Name(name)
        }
        4 => {
            let mut octets = [0u8; 16];
            read_exact_retry(client, &mut octets)?;
            HostAddr::V6(octets)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "address type")),
    };
    let mut port = [0u8; 2];
    read_exact_retry(client, &mut port)?;
    Ok(Destination { host, port: u16::from_be_bytes(port) })
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
    dest: &Destination,
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
            http_connect(&mut stream, link, dest, &server)?;
            Ok(Upstream::Tls(Box::new(stream)))
        }
        ProxyScheme::Http | ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
            let mut stream = connect_upstream(link).map_err(|_| {
                (5u8, format!("the proxy {server} could not be reached"))
            })?;
            stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
            stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
            match link.scheme() {
                ProxyScheme::Http => http_connect(&mut stream, link, dest, &server)?,
                _ => socks5_connect(&mut stream, link, dest, &server)?,
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
    // A signal (a child stopping, or the emulator returning EINTR) is not a dead proxy.
    loop {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Err(error) if interrupted(&error) => continue,
            other => return other,
        }
    }
}

/// Extra roots for the relay's TLS check. Release builds never read the test
/// hook and use system roots only. A set but unreadable file is an error when
/// the hook is on: checks stay on.
fn test_extra_ca_from_env() -> Result<Vec<u8>, RelayError> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        match std::env::var("SCRAPELENS_TEST_PROXY_CA") {
            Err(_) => Ok(Vec::new()),
            Ok(path) if path.trim().is_empty() => Ok(Vec::new()),
            Ok(path) => std::fs::read(path.trim()).map_err(|_| {
                RelayError::TestCa(
                    "the test proxy CA file could not be read. Certificate checks stay on"
                        .to_string(),
                )
            }),
        }
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    {
        Ok(Vec::new())
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
            if interrupted(&error) {
                continue;
            }
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

const AUTH_ERROR: &str = "ERR_INVALID_AUTH_CREDENTIALS";
const STATUS_ERROR: &str = "ERR_HTTP_RESPONSE_CODE_FAILURE";
const AUTH_SURE: &str =
    "the proxy asked for credentials or refused them; add them to the proxy link";
const AUTH_MAYBE: &str =
    "the proxy may be asking for credentials or refusing them; add them to the proxy link";
const DEST_SURE: &str =
    "the proxy refused the destination. Check that the proxy allows that destination";
const DEST_MAYBE: &str =
    "the proxy may be refusing the destination. Check that the proxy allows that destination";

/// Direct-route failures. `ERR_PROXY_*` is mapped as before. The two codes that
/// also happen with no proxy are a proxy failure only when `has_proxy` is set.
/// A tunnel response of 407 or another 4xx (`HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS`)
/// confirms it. Without that evidence the sentence says "may be", and with no
/// proxy the codes stay ordinary page errors.
pub(crate) fn direct_route_proxy_failures(has_proxy: bool, events: &str, netlog: &[u8]) -> Vec<String> {
    let mut out = proxy_failures_from_cdp(events);
    if !has_proxy {
        return out;
    }
    let tunnel = tunnel_refusal(netlog);
    let texts = loading_failed_texts(events);
    if tunnel.auth {
        push_new(&mut out, AUTH_SURE);
    } else if texts.iter().any(|text| text.contains(AUTH_ERROR)) {
        push_new(&mut out, AUTH_MAYBE);
    }
    if tunnel.destination {
        push_new(&mut out, DEST_SURE);
    } else if texts.iter().any(|text| text.contains(STATUS_ERROR)) {
        push_new(&mut out, DEST_MAYBE);
    }
    out
}

fn push_new(out: &mut Vec<String>, message: &str) {
    if !out.iter().any(|have| have == message) {
        out.push(message.to_string());
    }
}

fn loading_failed_texts(events: &str) -> Vec<String> {
    let mut texts = Vec::new();
    for line in events.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("method").and_then(|m| m.as_str()) != Some("Network.loadingFailed") {
            continue;
        }
        if let Some(text) = value.pointer("/params/errorText").and_then(|t| t.as_str()) {
            texts.push(text.to_string());
        }
    }
    texts
}

struct TunnelRefusal {
    auth: bool,
    destination: bool,
}

/// 407, or another 4xx, on the proxy tunnel. Header text is not copied out.
fn tunnel_refusal(netlog: &[u8]) -> TunnelRefusal {
    let mut found = TunnelRefusal { auth: false, destination: false };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(netlog) else {
        return found;
    };
    let Some(type_id) = value
        .pointer("/constants/logEventTypes/HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS")
        .and_then(|id| id.as_u64())
    else {
        return found;
    };
    let Some(events) = value.get("events").and_then(|events| events.as_array()) else {
        return found;
    };
    for event in events {
        if event.get("type").and_then(|ty| ty.as_u64()) != Some(type_id) {
            continue;
        }
        let Some(params) = event.get("params") else { continue };
        for code in header_statuses(params) {
            if code == 407 {
                found.auth = true;
            } else if (400..500).contains(&code) {
                found.destination = true;
            }
        }
    }
    found
}

fn header_statuses(params: &serde_json::Value) -> Vec<u16> {
    let mut codes = Vec::new();
    if let Some(line) = params.get("line").and_then(|line| line.as_str()) {
        if let Some(code) = status_from_line(line) {
            codes.push(code);
        }
    }
    match params.get("headers") {
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                if let Some(code) = status_from_header(item) {
                    codes.push(code);
                }
            }
        }
        Some(serde_json::Value::String(text)) => {
            for line in text.lines() {
                if let Some(code) = status_from_line(line) {
                    codes.push(code);
                }
            }
        }
        _ => {}
    }
    codes
}

fn status_from_header(item: &serde_json::Value) -> Option<u16> {
    if let Some(line) = item.as_str() {
        return status_from_line(line);
    }
    let name = item.get("name").and_then(|name| name.as_str()).unwrap_or("");
    let value = item.get("value").and_then(|value| value.as_str()).unwrap_or("");
    if name.eq_ignore_ascii_case(":status") {
        return value.trim().parse().ok();
    }
    status_from_line(name).or_else(|| status_from_line(&format!("{name}: {value}")))
}

fn status_from_line(line: &str) -> Option<u16> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("HTTP/") {
        let mut parts = rest.split_whitespace();
        let _version = parts.next()?;
        return parts.next()?.parse().ok();
    }
    let lower = line.to_ascii_lowercase();
    let rest = lower.strip_prefix(":status")?;
    let rest = rest.trim_start_matches([':', ' ']);
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
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
    dest: &Destination,
    server: &str,
) -> Result<(), (u8, String)> {
    let authority = dest.authority();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let (Some(user), Some(password)) = (link.user(), link.password()) {
        let token = base64(format!("{}:{}", user.expose(), password.expose()).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    write_all_retry(stream, request.as_bytes())
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
        code => Err((5, format!("the proxy {server} refused {authority} (HTTP {code})"))),
    }
}

fn socks5_connect(
    stream: &mut (impl Read + Write),
    link: &ProxyLink,
    dest: &Destination,
    server: &str,
) -> Result<(), (u8, String)> {
    let io_err = |_: io::Error| (5u8, format!("the proxy {server} closed the connection"));
    let with_auth = link.user().is_some() || link.password().is_some();
    write_all_retry(stream, if with_auth { &[5, 1, 2] } else { &[5, 1, 0] }).map_err(io_err)?;
    let mut choice = [0u8; 2];
    read_exact_retry(stream, &mut choice).map_err(io_err)?;
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
            write_all_retry(stream, &auth).map_err(io_err)?;
            let mut status = [0u8; 2];
            read_exact_retry(stream, &mut status).map_err(io_err)?;
            if status[1] != 0 {
                return Err((2, format!("the proxy {server} refused the credentials (SOCKS5 auth)")));
            }
        }
        _ => return Err((1, format!("the proxy {server} offered no usable SOCKS5 method"))),
    }
    let mut request = vec![5, 1, 0];
    match &dest.host {
        HostAddr::V4(octets) => {
            request.push(1);
            request.extend_from_slice(octets);
        }
        HostAddr::V6(octets) => {
            request.push(4);
            request.extend_from_slice(octets);
        }
        HostAddr::Name(name) => {
            let bytes = name.as_bytes();
            if bytes.len() > 255 {
                return Err((1, format!("the destination name is too long for SOCKS5: {name}")));
            }
            request.push(3);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    request.extend_from_slice(&dest.port.to_be_bytes());
    write_all_retry(stream, &request).map_err(io_err)?;
    let mut head = [0u8; 4];
    read_exact_retry(stream, &mut head).map_err(io_err)?;
    // Consume the bound address so the tunnel starts at the application's first byte.
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            read_exact_retry(stream, &mut len).map_err(io_err)?;
            len[0] as usize + 2
        }
        _ => return Err((1, format!("the proxy {server} sent an unknown reply"))),
    };
    let mut bound = vec![0u8; rest];
    read_exact_retry(stream, &mut bound).map_err(io_err)?;
    let authority = dest.authority();
    match head[1] {
        0 => Ok(()),
        5 => Err((5, format!("the proxy {server} refused {authority}"))),
        4 => Err((4, format!("the proxy {server} could not reach {authority}"))),
        _ => Err((1, format!("the proxy {server} failed to open {authority}"))),
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
        match read_retry(stream, &mut byte) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            Ok(_) => {}
            Err(error) => return Err(error),
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
            match read_retry(&mut client, &mut buf) {
                Ok(0) => {
                    client_open = false;
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                Ok(n) => {
                    if write_all_retry(&mut tls, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if timed_out(&e) => {}
                Err(_) => break,
            }
        }
        if tls_open {
            match read_retry(&mut tls, &mut buf) {
                Ok(0) => {
                    tls_open = false;
                    let _ = client.shutdown(Shutdown::Write);
                }
                Ok(n) => {
                    if write_all_retry(&mut client, &buf[..n]).is_err() {
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

/// `EINTR` is a signal, not a closed socket. qemu-user also returns it spuriously.
fn interrupted(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted
}

fn read_retry(stream: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match stream.read(buf) {
            Err(error) if interrupted(&error) => continue,
            other => return other,
        }
    }
}

fn read_exact_retry(stream: &mut impl Read, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match read_retry(stream, buf)? {
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            n => buf = &mut buf[n..],
        }
    }
    Ok(())
}

fn write_all_retry(stream: &mut impl Write, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")),
            Ok(n) => buf = &buf[n..],
            Err(error) if interrupted(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn copy_retry(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<u64> {
    let mut buf = [0u8; 16384];
    let mut total = 0u64;
    loop {
        match read_retry(reader, &mut buf)? {
            0 => return Ok(total),
            n => {
                write_all_retry(writer, &buf[..n])?;
                total += n as u64;
            }
        }
    }
}

fn pipe(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut client_r), Ok(mut upstream_r)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let (mut client_w, mut upstream_w) = (client, upstream);
    let forward = thread::spawn(move || {
        let _ = copy_retry(&mut client_r, &mut upstream_w);
        let _ = upstream_w.shutdown(Shutdown::Write);
    });
    let _ = copy_retry(&mut upstream_r, &mut client_w);
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
    fn the_test_ca_hook_is_empty_until_set_and_refuses_a_missing_file() {
        // SAFETY: test process only. Removed before return.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::remove_var("SCRAPELENS_TEST_PROXY_CA") };
        assert!(test_extra_ca_from_env().unwrap().is_empty());
        unsafe { std::env::set_var("SCRAPELENS_TEST_PROXY_CA", "   ") };
        assert!(test_extra_ca_from_env().unwrap().is_empty());
        unsafe {
            std::env::set_var(
                "SCRAPELENS_TEST_PROXY_CA",
                "/no/such/scrapelens-test-ca.pem",
            )
        };
        let err = test_extra_ca_from_env().unwrap_err();
        assert!(matches!(err, RelayError::TestCa(_)), "{err}");
        assert!(!err.to_string().contains("no/such"), "{err}");
        unsafe { std::env::remove_var("SCRAPELENS_TEST_PROXY_CA") };
    }

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
        // These two also happen with no proxy, so the code alone is not a proxy failure.
        assert!(chrome_proxy_failure("net::ERR_INVALID_AUTH_CREDENTIALS").is_none());
        assert!(chrome_proxy_failure("net::ERR_HTTP_RESPONSE_CODE_FAILURE").is_none());
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

    fn ambiguous_cdp() -> &'static str {
        concat!(
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_INVALID_AUTH_CREDENTIALS"}}"#,
            "\n",
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_HTTP_RESPONSE_CODE_FAILURE"}}"#,
            "\n",
        )
    }

    fn netlog(event: &str, headers: &str) -> String {
        format!(
            r#"{{"constants":{{"logEventTypes":{{"{event}":7}}}},"events":[{{"type":7,"params":{{"headers":[{headers}]}}}}]}}"#
        )
    }

    #[test]
    fn ambiguous_proxy_codes_need_a_proxy_and_a_tunnel_status() {
        let events = ambiguous_cdp();
        let tunnel_403 = netlog(
            "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS",
            r#""HTTP/1.1 403 Forbidden","Proxy-Authorization: Basic c2VjcmV0","Host: site-a.test:18781""#,
        );
        // A page that fails with these codes, even if a tunnel header is in the file, is not a
        // proxy failure when the capture has no proxy.
        let page = direct_route_proxy_failures(false, events, tunnel_403.as_bytes());
        assert!(page.is_empty(), "{page:?}");

        // An origin 403 uses the response-header event, not the tunnel. That is "may be".
        let origin = netlog(
            "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
            r#""HTTP/1.1 403 Forbidden","Host: site-a.test:18781""#,
        );
        let maybe = direct_route_proxy_failures(true, events, origin.as_bytes());
        assert!(maybe.iter().all(|line| line.contains("may be")), "{maybe:?}");
        assert_eq!(maybe.len(), 2, "{maybe:?}");
        for line in &maybe {
            assert!(!line.contains("c2VjcmV0") && !line.contains("site-a.test"), "{line}");
        }

        let auth = netlog(
            "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS",
            r#""HTTP/1.1 407 Proxy Authentication Required","Proxy-Authenticate: Basic realm=\"secret-user\"""#,
        );
        let sure_auth = direct_route_proxy_failures(
            true,
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_INVALID_AUTH_CREDENTIALS"}}"#,
            auth.as_bytes(),
        );
        assert_eq!(
            sure_auth,
            vec!["the proxy asked for credentials or refused them; add them to the proxy link".to_string()]
        );
        assert!(!sure_auth[0].contains("may be"));
        assert!(!sure_auth[0].contains("secret-user") && !sure_auth[0].contains("site-a.test"));

        let denied = netlog(
            "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS",
            r#"{"name":":status","value":"403"}"#,
        );
        let sure_dest = direct_route_proxy_failures(
            true,
            r#"{"method":"Network.loadingFailed","params":{"errorText":"net::ERR_HTTP_RESPONSE_CODE_FAILURE"}}"#,
            denied.as_bytes(),
        );
        assert_eq!(sure_dest.len(), 1, "{sure_dest:?}");
        assert!(sure_dest[0].contains("refused the destination"), "{sure_dest:?}");
        assert!(!sure_dest[0].contains("may be") && !sure_dest[0].contains("site-a.test"));
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
                    if c.read_exact(&mut req).is_err() {
                        return;
                    }
                    let (atyp, connect_host, shown) = match req[3] {
                        1 => {
                            let mut octets = [0u8; 4];
                            if c.read_exact(&mut octets).is_err() {
                                return;
                            }
                            let ip = Ipv4Addr::from(octets).to_string();
                            (1u8, ip.clone(), ip)
                        }
                        4 => {
                            let mut octets = [0u8; 16];
                            if c.read_exact(&mut octets).is_err() {
                                return;
                            }
                            let ip = Ipv6Addr::from(octets).to_string();
                            (4u8, ip.clone(), format!("[{ip}]"))
                        }
                        3 => {
                            let mut len = [0u8; 1];
                            if c.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut name = vec![0u8; len[0] as usize];
                            if c.read_exact(&mut name).is_err() {
                                return;
                            }
                            let host = String::from_utf8_lossy(&name).into_owned();
                            (3u8, host.clone(), host)
                        }
                        _ => return,
                    };
                    let mut port_b = [0u8; 2];
                    if c.read_exact(&mut port_b).is_err() {
                        return;
                    }
                    let target_port = u16::from_be_bytes(port_b);
                    log.lock().unwrap().push(format!("ATYP {atyp} {shown}:{target_port}"));
                    match TcpStream::connect((connect_host.as_str(), target_port)) {
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
                        // The relay's reachability check connects and drops. That is not a failure.
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return,
                        Err(error) => {
                            log.lock().unwrap().push(format!("read-head-err {}", error.kind()));
                            return;
                        }
                    };
                    let auth_ok = head.lines().any(|l| l.eq_ignore_ascii_case(&format!("Proxy-Authorization: {expected}")));
                    if !auth_ok {
                        log.lock().unwrap().push("auth-refused".to_string());
                        let _ = c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    let target_line = head.lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_string();
                    let host_header = head
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                        .unwrap_or("")
                        .to_string();
                    // One critical section so a reader cannot observe auth without the request line.
                    log.lock().unwrap().extend([
                        "auth-ok".to_string(),
                        format!("LINE {target_line}"),
                        format!("HOST {host_header}"),
                    ]);
                    let Some((h, p)) = split_connect_authority(&target_line) else {
                        return;
                    };
                    match TcpStream::connect((h.as_str(), p)) {
                        Ok(target) => {
                            let _ = write_all_retry(&mut c, b"HTTP/1.1 200 Connection established\r\n\r\n");
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
                    let host_header = head
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                        .unwrap_or("")
                        .to_string();
                    log.lock().unwrap().push(format!("LINE {target_line}"));
                    log.lock().unwrap().push(format!("HOST {host_header}"));
                    let Some((h, target_port)) = split_connect_authority(&target_line) else { return };
                    match TcpStream::connect((h.as_str(), target_port)) {
                        Ok(target) => {
                            let _ = write_all_retry(&mut tls, b"HTTP/1.1 200 Connection established\r\n\r\n");
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

    struct GeneratedTls {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        ca_pem: Vec<u8>,
    }

    /// Synthetic CA and leaf, once per test process. The leaf is valid for
    /// 127.0.0.1, which is the proxy address the relay checks. Nothing is read
    /// from `fixtures/tls` and nothing is written into the repository.
    fn generated_tls() -> &'static GeneratedTls {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, SanType,
        };
        static TLS: std::sync::OnceLock<GeneratedTls> = std::sync::OnceLock::new();
        TLS.get_or_init(|| {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "ScrapeLens local test CA (synthetic)");
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            ca_params.not_before = rcgen::date_time_ymd(2026, 1, 1);
            ca_params.not_after = rcgen::date_time_ymd(2036, 1, 1);
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();

            let leaf_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, "ScrapeLens local test server");
            params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
            params.subject_alt_names.push(SanType::IpAddress("::1".parse().unwrap()));
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.not_before = rcgen::date_time_ymd(2026, 1, 1);
            params.not_after = rcgen::date_time_ymd(2036, 1, 1);
            let leaf = params.signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key)).unwrap();
            GeneratedTls {
                cert_pem: leaf.pem().into_bytes(),
                key_pem: leaf_key.serialize_pem().into_bytes(),
                ca_pem: ca_cert.pem().into_bytes(),
            }
        })
    }

    fn fixture_server_config() -> Arc<rustls::ServerConfig> {
        install_ring();
        let files = generated_tls();
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(files.cert_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(files.key_pem.as_slice()))
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
        generated_tls().ca_pem.clone()
    }

    /// `host:port` or `[ipv6]:port` from a CONNECT request line.
    fn split_connect_authority(authority: &str) -> Option<(String, u16)> {
        if let Some(rest) = authority.strip_prefix('[') {
            let (host, port) = rest.split_once("]:")?;
            return Some((host.to_string(), port.parse().ok()?));
        }
        let (host, port) = authority.rsplit_once(':')?;
        Some((host.to_string(), port.parse().ok()?))
    }

    /// A SOCKS5 client (Chrome's side): returns the reply code and the connected socket.
    fn chrome_connect(relay_port: u16, target_port: u16) -> (u8, TcpStream) {
        chrome_request(relay_port, 1, &[127, 0, 0, 1], target_port).unwrap()
    }

    /// Sends one CONNECT. `0xfe` means the relay closed the socket before a reply.
    fn chrome_request(relay_port: u16, atyp: u8, addr: &[u8], port: u16) -> io::Result<(u8, TcpStream)> {
        let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port))?;
        c.set_read_timeout(Some(Duration::from_secs(10)))?;
        if write_all_retry(&mut c, &[5, 1, 0]).is_err() {
            return Ok((0xfe, c));
        }
        let mut choice = [0u8; 2];
        if read_exact_retry(&mut c, &mut choice).is_err() {
            return Ok((0xfe, c));
        }
        if choice != [5, 0] {
            return Ok((0xff, c));
        }
        let mut req = vec![5, 1, 0, atyp];
        if atyp == 3 {
            req.push(addr.len() as u8);
        }
        req.extend_from_slice(addr);
        req.extend_from_slice(&port.to_be_bytes());
        if write_all_retry(&mut c, &req).is_err() {
            return Ok((0xfe, c));
        }
        let mut reply = [0u8; 10];
        if read_exact_retry(&mut c, &mut reply).is_err() {
            return Ok((0xfe, c));
        }
        Ok((reply[1], c))
    }

    fn start(link: &str, allow: Option<AllowFn>) -> Relay {
        let link = ProxyLink::parse(link).unwrap();
        let relay = Relay::start(&link, allow).expect("relay starts");
        // The suite stands in for Chrome: this process, and a child it spawns, may connect.
        relay.set_owner_pid(std::process::id());
        relay
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
        assert_eq!(log[1], format!("ATYP 1 127.0.0.1:{echo}"));
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
        relay.set_owner_pid(std::process::id());
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
        assert_eq!(code, 0, "{:?}", relay.failures());
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
        assert_eq!(code, 2, "not allowed; failures={:?}", relay.failures());
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

    /// IPv4 (ATYP 1), domain (ATYP 3) and IPv6 (ATYP 4) stay in that form on both upstreams.
    /// A domain whose text is an IPv6 literal is bracketed for HTTP and is not turned into ATYP 4.
    #[test]
    fn address_types_keep_their_form_on_http_and_socks5() {
        let cases = [
            (1u8, &[127, 0, 0, 1][..], "127.0.0.1:443", "ATYP 1 127.0.0.1:443"),
            (3, b"example.test".as_slice(), "example.test:443", "ATYP 3 example.test:443"),
            (4, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..], "[::1]:443", "ATYP 4 [::1]:443"),
            (3, b"::1".as_slice(), "[::1]:443", "ATYP 3 ::1:443"),
        ];
        for (atyp, addr, http_authority, socks_line) in cases {
            let (http_port, http_seen) = http_upstream(USER, PASSWORD);
            let http = start(&format!("http://{USER}:{PASSWORD}@127.0.0.1:{http_port}"), None);
            let _ = chrome_request(http.port(), atyp, addr, 443).unwrap();
            let http_log = http_seen.lock().unwrap().clone();
            assert!(http_log.iter().any(|line| line == &format!("LINE {http_authority}")), "{http_log:?}");
            assert!(
                http_log.iter().any(|line| line == &format!("HOST Host: {http_authority}")),
                "{http_log:?}"
            );

            let (socks_port, socks_seen) = socks_upstream(USER, PASSWORD);
            let socks = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{socks_port}"), None);
            let _ = chrome_request(socks.port(), atyp, addr, 443).unwrap();
            let socks_log = socks_seen.lock().unwrap().clone();
            assert!(socks_log.iter().any(|line| line == socks_line), "{socks_log:?}");
        }
    }

    #[test]
    fn finished_tunnels_are_removed_from_the_socket_list() {
        let echo = echo_server();
        let (up, _seen) = socks_upstream(USER, PASSWORD);
        let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), None);
        let (code, tunnel) = chrome_connect(relay.port(), echo);
        assert_eq!(code, 0);
        let tracked = relay.tracked_sockets();
        assert!(tracked >= 2, "client and upstream stay tracked while open, saw {tracked}");
        drop(tunnel);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while relay.tracked_sockets() != 0 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(relay.tracked_sockets(), 0);
    }

    #[test]
    fn the_failure_list_and_the_connection_count_stay_bounded() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let up = listener.local_addr().unwrap().port();
        let allow: AllowFn = Arc::new(|_: &str, _: u16| false);
        let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), Some(allow));
        for port in 1..=u16::try_from(MAX_FAILURES + 8).unwrap() {
            let _ = chrome_connect(relay.port(), port);
        }
        let failures = relay.failures();
        assert_eq!(failures.len(), MAX_FAILURES, "{failures:?}");
        assert!(failures.iter().all(|line| line.contains("not allowed")));
        assert!(
            failures.iter().all(|line| !line.ends_with("127.0.0.1:1")),
            "the oldest distinct reason was kept: {failures:?}"
        );
        let newest = format!("127.0.0.1:{}", MAX_FAILURES + 8);
        assert!(failures.iter().any(|line| line.ends_with(&newest)), "{failures:?}");

        relay.set_connection_limit(2);
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port())).unwrap());
        }
        thread::sleep(Duration::from_millis(80));
        let mut extra = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port())).unwrap();
        extra.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut buf = [0u8; 1];
        let read = extra.read(&mut buf);
        let closed = match read {
            Ok(0) => true,
            Err(ref error) => !matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            Ok(_) => false,
        };
        assert!(closed, "a connection past the cap must be closed, read={read:?}");
        assert!(relay.failures().iter().any(|line| line == "too many connections"));
        drop(held);
        drop(listener);
    }

    /// The same proxy refusal must not become one session warning per connection.
    /// A different reason stays, and neither line carries credentials.
    #[test]
    fn repeated_relay_failures_collapse_by_reason() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let up = listener.local_addr().unwrap().port();
        let allow: AllowFn = Arc::new(|_: &str, _: u16| false);
        let relay = start(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}"), Some(allow));
        let _ = chrome_connect(relay.port(), 9);
        let _ = chrome_connect(relay.port(), 9);
        let _ = chrome_connect(relay.port(), 10);
        let failures = relay.failures();
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(
            failures.iter().any(|line| line.contains("127.0.0.1:9") && line.contains("(2 times)")),
            "{failures:?}"
        );
        assert!(
            failures.iter().any(|line| line.ends_with("127.0.0.1:10")),
            "{failures:?}"
        );
        for line in &failures {
            assert!(!line.contains(PASSWORD) && !line.contains(USER) && !line.contains("wrong-"), "{line}");
        }
    }

    /// Runs only when spawned by `a_stranger_is_refused_and_a_child_of_the_owner_is_admitted`.
    /// The probe name stays in this test only: a release library does not contain it,
    /// with or without the `test-hooks` feature.
    #[test]
    fn relay_peer_probe() {
        let Ok(port) = std::env::var("SCRAPELENS_RELAY_PEER_PROBE") else {
            return;
        };
        let port: u16 = port.parse().expect("port");
        let (code, _socket) = chrome_request(port, 1, &[127, 0, 0, 1], 9).unwrap();
        assert_ne!(code, 0xfe, "the relay closed the connection");
        assert_ne!(code, 0xff, "the relay rejected the greeting");
    }

    #[test]
    fn a_stranger_is_refused_and_a_child_of_the_owner_is_admitted() {
        let (up, seen) = socks_upstream(USER, PASSWORD);
        let link = ProxyLink::parse(&format!("socks5://{USER}:{PASSWORD}@127.0.0.1:{up}")).unwrap();
        let relay = Relay::start(&link, None).unwrap();

        let (code, _) = chrome_request(relay.port(), 1, &[127, 0, 0, 1], 9).unwrap();
        assert_eq!(code, 0xfe, "no browser pid yet");
        assert!(relay.failures().iter().any(|line| line == "the capture browser is not running yet"));
        assert!(
            seen.lock().unwrap().iter().all(|line| !line.starts_with("ATYP") && line != "auth-ok"),
            "upstream was dialed: {:?}",
            seen.lock().unwrap()
        );

        let sleeper = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        struct StopSleep(Option<std::process::Child>);
        impl Drop for StopSleep {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let sleeper = StopSleep(Some(sleeper));
        relay.set_owner_pid(sleeper.0.as_ref().unwrap().id());
        let (code, _) = chrome_request(relay.port(), 1, &[127, 0, 0, 1], 9).unwrap();
        assert_eq!(code, 0xfe, "the test process is not in the sleeper's tree");
        assert!(relay.failures().iter().any(|line| line == "the client process is not the capture browser"));
        assert!(
            seen.lock().unwrap().iter().all(|line| !line.starts_with("ATYP") && line != "auth-ok"),
            "upstream was dialed for a stranger: {:?}",
            seen.lock().unwrap()
        );
        drop(sleeper);

        relay.set_owner_pid(std::process::id());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relay::wire_tests::relay_peer_probe", "--test-threads", "1"])
            .env("SCRAPELENS_RELAY_PEER_PROBE", relay.port().to_string())
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "status {:?} stderr {}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        );
        let log = seen.lock().unwrap().clone();
        assert!(
            log.iter().any(|line| line.starts_with("ATYP 1") || line == "auth-ok"),
            "the child was not admitted: {log:?}"
        );
        let stats = relay.peer_check();
        eprintln!(
            "peer checks={} refused={} max_us={}",
            stats.checks,
            stats.refused,
            stats.max_nanos / 1000
        );
        assert!(stats.checks >= 3, "{stats:?}");
        assert_eq!(stats.refused, 2, "only the two stranger attempts are refused");
        // A miss may use the confirmation budget. A hit does not, and this cap
        // is only there so a stuck check cannot pass.
        assert!(stats.max_nanos < 1_500_000_000, "peer check max {} ns", stats.max_nanos);
    }

    /// The reviewer's case: a stranger writes the SOCKS request, half-closes, and keeps
    /// reading. Unread bytes must not turn a failed process check into a tunnel.
    #[test]
    fn fin_with_a_pending_request_is_refused_and_an_empty_cancel_is_quiet() {
        let (up, seen) = http_upstream(USER, PASSWORD);
        let link = ProxyLink::parse(&format!("http://{USER}:{PASSWORD}@127.0.0.1:{up}")).unwrap();
        let relay = Relay::start(&link, None).expect("relay starts");
        let sleeper = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        struct StopSleep(Option<std::process::Child>);
        impl Drop for StopSleep {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let sleeper = StopSleep(Some(sleeper));
        relay.set_owner_pid(sleeper.0.as_ref().unwrap().id());
        let before = seen.lock().unwrap().len();

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port())).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = [0u8; 12];
        let read = client.read(&mut response);
        thread::sleep(Duration::from_millis(150));
        let log = seen.lock().unwrap().clone();
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "half-closed stranger got a reply: {read:?} {response:?}"
        );
        assert!(
            log[before..].iter().all(|line| line != "auth-ok" && !line.starts_with("LINE ")),
            "upstream saw the stranger: {log:?}"
        );
        let failures = relay.failures();
        assert!(
            failures.iter().any(|line| line == "the client process is not the capture browser"),
            "{failures:?}"
        );
        assert!(failures.iter().all(|line| !line.contains(PASSWORD) && !line.contains(USER)));
        let refused_after_attack = relay.peer_check().refused;

        let mut open = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port())).unwrap();
        open.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        open.write_all(&request).unwrap();
        let mut open_response = [0u8; 12];
        let open_read = open.read(&mut open_response);
        thread::sleep(Duration::from_millis(100));
        let log = seen.lock().unwrap().clone();
        assert!(matches!(open_read, Ok(0) | Err(_)), "{open_read:?} {open_response:?}");
        assert!(
            log.iter().all(|line| line != "auth-ok" && !line.starts_with("LINE ")),
            "open stranger reached the upstream: {log:?}"
        );
        assert!(relay.peer_check().refused > refused_after_attack);

        let failure_count = relay.failures().len();
        let refused = relay.peer_check().refused;
        let cancelled = TcpStream::connect((Ipv4Addr::LOCALHOST, relay.port())).unwrap();
        cancelled.shutdown(Shutdown::Both).unwrap();
        drop(cancelled);
        // The check retries a socket that has already gone. Wait out that
        // budget before deciding the cancel stayed quiet.
        thread::sleep(Duration::from_millis(1200));
        assert_eq!(
            relay.failures().len(),
            failure_count,
            "an empty cancel was reported: {:?}",
            relay.failures()
        );
        assert_eq!(relay.peer_check().refused, refused, "an empty cancel counted as a refusal");
        let log = seen.lock().unwrap().clone();
        assert!(log.iter().all(|line| line != "auth-ok"));
    }

    #[test]
    fn fin_with_unread_bytes_is_not_a_quiet_cancel() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        assert!(!super::quiet_cancel(&server), "a pending greeting is not an empty cancel");
        client.shutdown(Shutdown::Write).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(
            !super::quiet_cancel(&server),
            "FIN with an unread greeting is still a request"
        );

        let empty = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (empty_server, _) = listener.accept().unwrap();
        empty.shutdown(Shutdown::Both).unwrap();
        drop(empty);
        let started = std::time::Instant::now();
        while !super::quiet_cancel(&empty_server) && started.elapsed() < Duration::from_secs(1) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(super::quiet_cancel(&empty_server), "a close with nothing to read is quiet");
    }

    /// Chrome cancels by closing the socket after writing. The bytes can still be
    /// buffered here, but no process holds the socket, so the check must not call
    /// that client a stranger. The relay maps this to a quiet close.
    #[test]
    fn a_closed_socket_with_unread_bytes_is_not_a_stranger() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 9]).unwrap();
        }
        let server = listener.accept().unwrap().0;
        let mut pending = [0u8; 1];
        assert!(server.peek(&mut pending).unwrap() > 0, "the closed client left bytes to read");
        let sleeper = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        struct StopSleep(Option<std::process::Child>);
        impl Drop for StopSleep {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let sleeper = StopSleep(Some(sleeper));
        let verdict = super::peer::admit(server.peer_addr().unwrap().port(), port, sleeper.0.as_ref().unwrap().id());
        assert_eq!(verdict, Err(super::peer::ALREADY_CLOSED), "{verdict:?}");
    }
}
