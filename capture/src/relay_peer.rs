//! Decides whether the process that connected to the relay may use it.
//!
//! Chrome does not authenticate to the local SOCKS5 listener, so the relay admits a
//! connection only when the socket belongs to the capture browser or one of its
//! descendants. Anything else, including another user of this machine, is refused.
//! A process of the same user that can already drive that Chrome is outside this check.
//! If the owner cannot be confirmed, the connection is refused. A socket that no
//! process still holds cannot read a tunnel; that result is [`ALREADY_CLOSED`].
//!
//! A socket is identified by its whole connection: the client's address and port as the
//! relay sees them, and the relay's own address and port. Matching the port alone let a
//! process on another local address reuse the browser's port and be taken for it.
//!
//! The owner tree is read once per generation, not once per connection. A connection is
//! admitted when a generation that started after it arrived lists its whole connection
//! under the owner. The cost of a flood is therefore the number of generations, not the
//! number of connections, and a miss ends after [`GENERATIONS`] of them.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// No process still has this socket. The relay closes it without admitting it and
/// without showing a failure. A client that is still reading keeps the socket and
/// is refused instead.
pub(crate) const ALREADY_CLOSED: &str = "the client closed before its process could be checked";

/// A check that reads the process table found no permit at once. The connection is
/// refused: a check that cannot run is never a pass.
pub(crate) const BUSY: &str = "too many connections are being checked at once";

/// The owner tree was read, and it does not hold this connection.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const NOT_BROWSER: &str = "the client process is not the capture browser";

/// The owner tree could not be read in full, so no admission can be made.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const UNCONFIRMED: &str = "the client process could not be confirmed";

/// The fast-path bound the tests use for a hit that a generation has already listed. The
/// production wait is the whole [`CHECK_WINDOW`], so this constant only exists for tests.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) const CONFIRM_BUDGET: Duration = Duration::from_millis(400);

/// The whole verification window of one connection: its generation wait, its scans and its
/// direct look, together. When it ends the check fails, and the connection is refused as a
/// real refusal (counted, not quiet). Under load a scan can run past the budget above; the
/// window bounds that wait, so a stranger never holds its slot indefinitely.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const CHECK_WINDOW: Duration = Duration::from_secs(3);

/// Tree generations one connection may wait for before its miss is final. One complete
/// generation that starts after the connection arrived decides it. More generations only
/// repeat the same scan under a flood: measured on Chrome, a second one costs pages (review-013
/// M1), and a stranger that a complete scan does not list is not in the tree.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const GENERATIONS: usize = 1;

/// Bounds the connections or scans that run at the same time. A permit is held for as long as
/// the work it counts.
pub(crate) struct Gate {
    limit: usize,
    used: Mutex<usize>,
    freed: Condvar,
}

/// One permit. It holds the gate, so it can outlive the scope that took it (a connection's
/// waiting slot moves into its thread). The permit is returned when it drops.
pub(crate) struct GatePermit(Arc<Gate>);

impl Gate {
    pub(crate) fn new(limit: usize) -> Arc<Gate> {
        Arc::new(Gate { limit: limit.max(1), used: Mutex::new(0), freed: Condvar::new() })
    }

    /// Waits up to `wait` for a permit. `None` when none frees up in time.
    pub(crate) fn acquire(gate: &Arc<Gate>, wait: Duration) -> Option<GatePermit> {
        let deadline = Instant::now() + wait;
        let mut used = gate.used.lock().ok()?;
        loop {
            if *used < gate.limit {
                *used += 1;
                return Some(GatePermit(Arc::clone(gate)));
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = gate.freed.wait_timeout(used, deadline - now).ok()?;
            used = guard;
        }
    }

    /// A permit now, or `None`.
    pub(crate) fn try_acquire(gate: &Arc<Gate>) -> Option<GatePermit> {
        Gate::acquire(gate, Duration::ZERO)
    }
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        if let Ok(mut used) = self.0.used.lock() {
            *used = used.saturating_sub(1);
        }
        self.0.freed.notify_one();
    }
}

/// A connection of the owner tree: its local and its remote address, both canonical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) type Tuple = (SocketAddr, SocketAddr);

/// One scan of the owner tree. `tuples` is `None` when the scan could not read every
/// process of the tree, so nothing in it can be trusted.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct View {
    owner: u32,
    tuples: Option<HashSet<Tuple>>,
}

/// The scan bookkeeping. Scan `n` is the n-th one started; `finished == started` when idle.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct Tree {
    started: u64,
    finished: u64,
    running: bool,
    view: Option<Arc<View>>,
}

/// One connection waiting for its check. `cancelled` is set when a newer arrival needs its slot.
pub(crate) struct Ticket {
    pub(crate) cancelled: AtomicBool,
}

/// The connections that wait for their check, oldest first, bounded by `limit`. At the limit the
/// oldest waiter is cancelled and its slot taken: the newest arrival is the one a flood cannot
/// have held out longer than the others. A cancelled waiter refuses itself on its next wakeup.
pub(crate) struct Pending {
    limit: usize,
    order: Mutex<VecDeque<Arc<Ticket>>>,
}

impl Pending {
    pub(crate) fn new(limit: usize) -> Arc<Pending> {
        Arc::new(Pending { limit: limit.max(1), order: Mutex::new(VecDeque::new()) })
    }

    /// Takes a slot for a new waiter. Returns its ticket, and whether the oldest waiter was
    /// cancelled to make room.
    pub(crate) fn enter(&self) -> (Arc<Ticket>, bool) {
        let mut order = self.order.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut evicted = false;
        if order.len() >= self.limit {
            if let Some(oldest) = order.pop_front() {
                oldest.cancelled.store(true, Ordering::SeqCst);
                evicted = true;
            }
        }
        let ticket = Arc::new(Ticket { cancelled: AtomicBool::new(false) });
        order.push_back(Arc::clone(&ticket));
        (ticket, evicted)
    }

    /// Frees the slot of a waiter that has finished. A waiter that was already cancelled has no
    /// slot left, and nothing is removed.
    pub(crate) fn leave(&self, ticket: &Arc<Ticket>) {
        let mut order = self.order.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(at) = order.iter().position(|waiting| Arc::ptr_eq(waiting, ticket)) {
            order.remove(at);
        }
    }
}

/// The part of the window that the generation wait leaves to the direct look. Without it, a
/// wait that runs to the window leaves the direct look nothing to read with.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DIRECT_RESERVE: Duration = Duration::from_secs(1);

/// How often a waiting connection looks at its cancel flag. Short enough that a cancelled waiter
/// is refused within a few milliseconds, long enough that a waiter does not spin.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CANCEL_SLICE: Duration = Duration::from_millis(20);

/// The state every connection of one relay shares: the owner-tree view, and the bound on
/// the checks that read the process table one connection at a time (after a miss).
pub(crate) struct Peers {
    /// A permit is taken without waiting; a connection without one is refused as [`BUSY`].
    pub(super) post_miss: Arc<Gate>,
    /// Connections that missed the owner tree and entered the retry path. A hit never does.
    misses: std::sync::atomic::AtomicU64,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    tree: Mutex<Tree>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    moved: Condvar,
}

impl Peers {
    pub(crate) fn new(post_miss_limit: usize) -> Arc<Peers> {
        Arc::new(Peers {
            post_miss: Gate::new(post_miss_limit),
            misses: std::sync::atomic::AtomicU64::new(0),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            tree: Mutex::new(Tree::default()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            moved: Condvar::new(),
        })
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// How many connections entered the retry path. Used by tests to prove a hit skips it.
    #[cfg(test)]
    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The view of the first scan that starts after this call. A scan that is already
    /// running started before the call, so it does not count. The caller that finds no scan
    /// running starts the next one; the others wait for it. `None` when no such scan
    /// finishes before `deadline`, or when the state is unavailable.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fresh(
        &self,
        owner: u32,
        deadline: Instant,
        window: Instant,
        scan: fn(u32, Instant) -> Result<HashSet<Tuple>, ()>,
        cancel: &AtomicBool,
    ) -> Option<Arc<View>> {
        let mut tree = self.tree.lock().ok()?;
        let need = tree.started + 1;
        loop {
            if tree.finished >= need {
                return tree.view.clone();
            }
            if !tree.running && tree.started < need {
                tree.started += 1;
                tree.running = true;
                let number = tree.started;
                drop(tree);
                let tuples = scan(owner, window).ok();
                tree = self.tree.lock().ok()?;
                tree.view = Some(Arc::new(View { owner, tuples }));
                tree.finished = number;
                tree.running = false;
                self.moved.notify_all();
                continue;
            }
            let now = Instant::now();
            if now >= deadline || cancel.load(Ordering::SeqCst) {
                return None;
            }
            tree = self.moved.wait_timeout(tree, (deadline - now).min(CANCEL_SLICE)).ok()?.0;
        }
    }
}

/// `owner` is the browser pid published by the capture. Zero means it is not known yet.
/// `client` is the address the relay sees for the connection, `listen` the relay's own.
pub(crate) fn admit_cancellable(
    client: SocketAddr,
    listen: SocketAddr,
    owner: u32,
    peers: &Arc<Peers>,
    cancel: &AtomicBool,
) -> Result<(), &'static str> {
    if owner == 0 {
        return Err("the capture browser is not running yet");
    }
    #[cfg(target_os = "linux")]
    {
        linux::admit(client, listen, owner, peers, cancel)
    }
    #[cfg(target_os = "macos")]
    {
        macos::admit(client, listen, owner, peers, cancel)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (client, listen, owner, peers, cancel);
        Err("the client process could not be confirmed")
    }
}

/// A check that nobody cancels. Tests use it; the relay passes its waiter's flag.
#[cfg(test)]
pub(crate) fn admit(
    client: SocketAddr,
    listen: SocketAddr,
    owner: u32,
    peers: &Arc<Peers>,
) -> Result<(), &'static str> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    admit_cancellable(client, listen, owner, peers, &NEVER)
}

/// Checks one connection against the owner tree. A hit returns on the first generation that
/// lists the connection. A miss is final after [`GENERATIONS`] generations, or when the budget
/// is spent. A generation that could not be read in full is never a hit. When no generation
/// finishes in time, one direct look at the tree answers this connection, so a busy process
/// table cannot starve the browser's own connection.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn in_tree(
    client: SocketAddr,
    listen: SocketAddr,
    owner: u32,
    peers: &Peers,
    scan: fn(u32, Instant) -> Result<HashSet<Tuple>, ()>,
    direct: fn(u32, SocketAddr, SocketAddr, Instant) -> Result<bool, ()>,
    cancel: &AtomicBool,
) -> Result<(), &'static str> {
    let wanted: Tuple = (
        SocketAddr::new(canonical(client.ip()), client.port()),
        SocketAddr::new(canonical(listen.ip()), listen.port()),
    );
    // One window for the whole check. The generation wait ends at the budget or the window,
    // whichever is first; every scan and the direct look stop when the window ends.
    let window = Instant::now() + CHECK_WINDOW;
    // The generation wait runs to the window. A scan serves every connection that waits for it,
    // so a flood costs one scan per generation instead of one direct look per connection.
    let deadline = window.checked_sub(DIRECT_RESERVE).unwrap_or(window);
    let mut last = UNCONFIRMED;
    for _ in 0..GENERATIONS {
        if cancel.load(Ordering::SeqCst) {
            return Err(UNCONFIRMED);
        }
        let Some(view) = peers.fresh(owner, deadline, window, scan, cancel) else {
            if cancel.load(Ordering::SeqCst) {
                return Err(UNCONFIRMED);
            }
            // No generation finished in time: one direct look at the owner tree answers
            // this connection instead of another wait.
            return match direct(owner, client, listen, window) {
                Ok(true) => Ok(()),
                Ok(false) => Err(last),
                Err(()) => Err(UNCONFIRMED),
            };
        };
        match view.tuples.as_ref() {
            Some(tuples) if view.owner == owner => {
                if tuples.contains(&wanted) {
                    return Ok(());
                }
                last = NOT_BROWSER;
            }
            _ => last = UNCONFIRMED,
        }
    }
    if last == UNCONFIRMED {
        // No complete generation was read. One direct look can still answer this
        // connection, instead of refusing it on a view that could not be trusted.
        return match direct(owner, client, listen, window) {
            Ok(true) => Ok(()),
            Ok(false) | Err(()) => Err(UNCONFIRMED),
        };
    }
    Err(last)
}

/// One process check that reads the process table. It runs only under a permit of `checks`
/// taken now; without one the connection is refused as [`BUSY`], and it does not wait.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn checked(checks: &Arc<Gate>, once: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
    match Gate::try_acquire(checks) {
        Some(_permit) => once(),
        None => Err(BUSY),
    }
}

/// The address as the pair the relay compares: an IPv4-mapped IPv6 address is its IPv4 form,
/// so `::ffff:127.0.0.1` and `127.0.0.1` are the same client.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::{canonical, checked, in_tree, Gate, Peers, Tuple, UNCONFIRMED};

    pub(crate) fn admit(
        client: SocketAddr,
        listen: SocketAddr,
        owner: u32,
        peers: &Arc<Peers>,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        let last = match in_tree(client, listen, owner, peers, tree_tuples, direct_tree_has, cancel) {
            Ok(()) => return Ok(()),
            Err(reason) => reason,
        };
        // A waiter cancelled for a newer arrival has no slot to keep: it is refused here.
        if cancel.load(Ordering::SeqCst) {
            return Err(UNCONFIRMED);
        }
        // The browser tree does not list this socket. A row that is gone, or whose inode
        // column is zero, has no owner: the kernel keeps such a row only after the last
        // process released the socket, so nobody can read a tunnel reply and the connection
        // is closed quietly. A row with an inode has an owner outside the browser tree: that
        // is a stranger, and it stays refused. The kernel's inode column is the whole answer;
        // this does not read other processes' descriptor tables, which an ordinary user cannot.
        peers.record_miss();
        released_or(client, listen, last, &peers.post_miss)
    }

    /// `held` is the refusal when the kernel still lists an owner for the socket.
    fn released_or(
        client: SocketAddr,
        listen: SocketAddr,
        held: &'static str,
        checks: &Arc<Gate>,
    ) -> Result<(), &'static str> {
        checked(checks, || match client_once(client, listen) {
            Ok(None) => Err(super::ALREADY_CLOSED),
            Err(()) => Err(UNCONFIRMED),
            // No owner (inode 0): nobody can read the tunnel, so this is a cancel.
            Ok(Some(row)) if row.inode == 0 => Err(super::ALREADY_CLOSED),
            // An owner exists and it is not in the browser tree: refuse the stranger.
            Ok(Some(_)) => Err(held),
        })
    }

    /// Every connection the owner tree holds right now: the sockets of the owner and its
    /// descendants, joined with the established TCP rows. An unreadable process fails the scan.
    pub(super) fn tree_tuples(owner: u32, window: Instant) -> Result<HashSet<Tuple>, ()> {
        let mut inodes = HashSet::new();
        let mut seen = HashSet::new();
        let mut stack = vec![owner];
        while let Some(pid) = stack.pop() {
            if Instant::now() >= window {
                return Err(());
            }
            if !seen.insert(pid) {
                continue;
            }
            if seen.len() > 4096 {
                return Err(());
            }
            socket_inodes(pid, &mut inodes, window)?;
            stack.extend(children(pid)?);
        }
        Ok(tcp_rows()?
            .into_iter()
            .filter(|row| inodes.contains(&row.inode))
            .map(|row| (row.local, row.remote))
            .collect())
    }

    /// One direct look at the owner tree for this connection, used when no generation
    /// finished in time. `Ok(true)` when the owner tree holds its inode; an unreadable
    /// process of the tree fails the look, so it never admits on a partial view.
    fn direct_tree_has(owner: u32, client: SocketAddr, listen: SocketAddr, window: Instant) -> Result<bool, ()> {
        let inode = match client_once(client, listen) {
            Ok(Some(row)) if row.inode != 0 => row.inode,
            Ok(_) => return Ok(false),
            Err(()) => return Err(()),
        };
        let mut stack = vec![owner];
        let mut seen = Vec::new();
        while let Some(pid) = stack.pop() {
            if Instant::now() >= window {
                return Err(());
            }
            if seen.contains(&pid) {
                continue;
            }
            seen.push(pid);
            if seen.len() > 4096 {
                return Err(());
            }
            if process_has_inode(pid, inode, window)? {
                return Ok(true);
            }
            stack.extend(children(pid)?);
        }
        Ok(false)
    }

    fn process_has_inode(pid: u32, inode: u64, window: Instant) -> Result<bool, ()> {
        let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(()),
        };
        let needle = format!("socket:[{inode}]");
        for entry in entries {
            if Instant::now() >= window {
                return Err(());
            }
            let entry = entry.map_err(|_| ())?;
            match std::fs::read_link(entry.path()) {
                Ok(target) if target.to_string_lossy() == needle => return Ok(true),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(()),
            }
        }
        Ok(false)
    }

    /// One established TCP connection, from `/proc/net/tcp` or `/proc/net/tcp6`.
    #[derive(Clone, Copy)]
    struct Row {
        local: SocketAddr,
        remote: SocketAddr,
        uid: u32,
        inode: u64,
    }

    /// The established rows of both tables. A row with a field that does not parse is skipped.
    /// ESTABLISHED, or FIN_WAIT after the client half-closes and keeps reading. TIME_WAIT has no
    /// process and is not listed.
    fn tcp_rows() -> Result<Vec<Row>, ()> {
        let mut rows = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(()),
            };
            for line in text.lines().skip(1) {
                let mut cols = line.split_whitespace();
                let _index = cols.next();
                let (Some(local), Some(remote), Some(state)) = (cols.next(), cols.next(), cols.next()) else {
                    continue;
                };
                if !matches!(state, "01" | "04" | "05") {
                    continue;
                }
                let (Some(local), Some(remote)) = (socket_addr(local), socket_addr(remote)) else {
                    continue;
                };
                // tx_queue:rx_queue, tr:tm, retrnsmt, uid, timeout, inode.
                let Some(uid) = cols.nth(3).and_then(|text| text.parse::<u32>().ok()) else { continue };
                let Some(inode) = cols.nth(1).and_then(|text| text.parse::<u64>().ok()) else { continue };
                rows.push(Row { local, remote, uid, inode });
            }
        }
        Ok(rows)
    }

    /// `address:port` in `/proc/net/tcp` form.
    fn socket_addr(text: &str) -> Option<SocketAddr> {
        let (addr, port) = text.rsplit_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        Some(SocketAddr::new(parse_addr(addr)?, port))
    }

    /// The socket inodes that `pid` holds, added to `inodes`.
    fn socket_inodes(pid: u32, inodes: &mut HashSet<u64>, window: Instant) -> Result<(), ()> {
        let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(()),
        };
        for entry in entries {
            if Instant::now() >= window {
                return Err(());
            }
            let entry = entry.map_err(|_| ())?;
            match std::fs::read_link(entry.path()) {
                Ok(target) => {
                    let inode = target
                        .to_str()
                        .and_then(|text| text.strip_prefix("socket:["))
                        .and_then(|text| text.strip_suffix(']'))
                        .and_then(|text| text.parse::<u64>().ok());
                    if let Some(inode) = inode {
                        inodes.insert(inode);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(()),
            }
        }
        Ok(())
    }

    /// The client socket is the established row whose local side is the client's address
    /// and port, and whose remote side is the relay's. A row must match the whole connection.
    fn client_once(client: SocketAddr, listen: SocketAddr) -> Result<Option<ClientSocket>, ()> {
        let local = SocketAddr::new(canonical(client.ip()), client.port());
        let remote = SocketAddr::new(canonical(listen.ip()), listen.port());
        let mut found: Option<ClientSocket> = None;
        for row in tcp_rows()? {
            if row.local != local || row.remote != remote {
                continue;
            }
            // A torn or shifting snapshot can repeat one socket. The same inode is one match.
            // Two inodes, or two uids, on one connection means the table moved.
            match found {
                Some(previous) if previous.inode != row.inode || previous.uid != row.uid => return Err(()),
                Some(_) => {}
                None => found = Some(ClientSocket { inode: row.inode, uid: row.uid }),
            }
        }
        Ok(found)
    }

    #[derive(Clone, Copy)]
    struct ClientSocket {
        inode: u64,
        uid: u32,
    }

    /// One `/proc/net/tcp` address: 8 hex digits (IPv4) or 32 (IPv6). Each 32-bit word
    /// is printed in host order, which is little-endian here.
    fn parse_addr(hex: &str) -> Option<IpAddr> {
        match hex.len() {
            8 => {
                let word = u32::from_str_radix(hex, 16).ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())).to_canonical())
            }
            32 => {
                let mut bytes = [0u8; 16];
                for (index, chunk) in hex.as_bytes().chunks(8).enumerate() {
                    let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                Some(IpAddr::V6(Ipv6Addr::from(bytes)).to_canonical())
            }
            _ => None,
        }
    }

    fn children(pid: u32) -> Result<Vec<u32>, ()> {
        let entries = match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
        };
        let mut kids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let text = match std::fs::read_to_string(entry.path().join("children")) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(()),
            };
            for token in text.split_whitespace() {
                if let Ok(child) = token.parse::<u32>() {
                    kids.push(child);
                }
            }
        }
        Ok(kids)
    }

    #[cfg(test)]
    mod tests {
        use std::net::{TcpListener, TcpStream};
        use std::process::Command;
        use std::thread;
        use std::time::Duration;

        use super::super::{Gate, Peers, ALREADY_CLOSED, NOT_BROWSER};
        use super::{admit, client_once, released_or, UNCONFIRMED};

        /// The kernel releases a closed socket's inode once its last file reference is gone.
        /// A concurrent fork in the same process briefly holds a copy of every descriptor, so
        /// the row can keep its inode for a short time under load. Poll for the release.
        fn wait_until_orphaned(client: std::net::SocketAddr, listen: std::net::SocketAddr) -> Result<Option<super::ClientSocket>, ()> {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                match client_once(client, listen) {
                    Ok(Some(row)) if row.inode != 0 && std::time::Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    other => return other,
                }
            }
        }

        #[test]
        fn a_live_socket_lists_an_inode_and_a_closed_one_has_none() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).unwrap();
            let accepted = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            let row = client_once(client_addr, listen).unwrap().expect("client row");
            assert_ne!(row.inode, 0, "a socket a process holds has an inode");
            drop(client);
            drop(accepted);
            match wait_until_orphaned(client_addr, listen) {
                // TIME_WAIT has no process and is not listed.
                Ok(None) => {}
                // A lingering half-closed row has no owner, which is what closes it quietly.
                Ok(Some(row)) => assert_eq!(row.inode, 0, "an orphan socket has no inode"),
                Err(()) => panic!("the table could not be read"),
            }
        }

        #[test]
        fn a_dropped_socket_is_quiet_and_a_live_one_stays_refused() {
            let gate = Gate::new(8);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            assert_eq!(released_or(client_addr, listen, UNCONFIRMED, &gate), Err(UNCONFIRMED));
            assert_eq!(released_or(client_addr, listen, NOT_BROWSER, &gate), Err(NOT_BROWSER));

            drop(client);
            drop(accepted);
            wait_until_orphaned(client_addr, listen).expect("the table could not be read");
            assert_eq!(released_or(client_addr, listen, UNCONFIRMED, &gate), Err(ALREADY_CLOSED));
            assert_eq!(released_or(client_addr, listen, NOT_BROWSER, &gate), Err(ALREADY_CLOSED));

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).unwrap();
            let _accepted = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let never = std::sync::atomic::AtomicBool::new(false);
            let verdict = admit(client_addr, listen, sleeper.id(), &Peers::new(8), &never);
            let _ = sleeper.kill();
            let _ = sleeper.wait();
            // A live stranger is refused. Under load its check can end at the window, which gives the
            // honest reason "could not be confirmed"; either refusal is correct, an admission is not.
            assert!(matches!(verdict, Err(NOT_BROWSER) | Err(UNCONFIRMED)), "{verdict:?}");
            drop(client);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::{canonical, checked, in_tree, Peers, Tuple, NOT_BROWSER, UNCONFIRMED};

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;
    /// `sizeof(struct socket_fdinfo)` on this SDK. A short read is treated as unconfirmed.
    const SOCKET_FDINFO_SIZE: usize = 792;
    /// `soi_kind` inside `socket_fdinfo` (`proc_fileinfo` is 24 bytes, then `socket_info`).
    const OFF_SOI_KIND: usize = 256;
    /// `insi_fport` / `insi_lport` of the `in_sockinfo` at the start of `soi_proto`.
    /// TCP stores that struct at offset 0 of `tcp_sockinfo`, so both kinds share it.
    const OFF_FPORT: usize = 264;
    const OFF_LPORT: usize = 268;
    /// `insi_vflag` (IPv4 / IPv6 flags), then the foreign and local addresses. Each address
    /// is 16 bytes: an IPv4 address sits in its last four bytes, an IPv6 address in all sixteen.
    const OFF_VFLAG: usize = 288;
    const OFF_FADDR: usize = 296;
    const OFF_LADDR: usize = 312;
    const INI_IPV4: u8 = 0x1;
    const BSDINFO_SIZE: usize = 136;
    const OFF_PPID: usize = 16;

    #[link(name = "proc")]
    extern "C" {
        fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_listchildpids(ppid: i32, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut c_void, buffersize: i32) -> i32;
    }

    pub(crate) fn admit(
        client: SocketAddr,
        listen: SocketAddr,
        owner: u32,
        peers: &Arc<Peers>,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        let last = match in_tree(client, listen, owner, peers, tree_tuples, direct_tree_has, cancel) {
            Ok(()) => return Ok(()),
            Err(reason) => reason,
        };
        // A waiter cancelled for a newer arrival has no slot to keep: it is refused here.
        if cancel.load(Ordering::SeqCst) {
            return Err(UNCONFIRMED);
        }
        // The owner tree does not list this socket. A stranger that is still reading has
        // it open somewhere else. A Chrome cancel has already dropped the descriptor, so
        // nobody can read a tunnel reply.
        peers.record_miss();
        if last == NOT_BROWSER {
            return checked(&peers.post_miss, || match socket_holder(client, listen) {
                Ok(Some(pid)) => {
                    if descends_from(pid, owner)? { Ok(()) } else { Err(NOT_BROWSER) }
                }
                Ok(None) => Err(super::ALREADY_CLOSED),
                Err(()) => Err(UNCONFIRMED),
            });
        }
        // The owner tree could not be read fully. A finished scan that finds
        // nobody still holding the socket is a cancel, not a user-facing failure.
        // A process that still has it stays unconfirmed: this does not admit it.
        checked(&peers.post_miss, || match socket_holder(client, listen) {
            Ok(None) => Err(super::ALREADY_CLOSED),
            Ok(Some(_)) | Err(()) => Err(UNCONFIRMED),
        })
    }

    /// Every connection the owner tree holds right now: the sockets of the owner and its
    /// descendants. An unreadable process fails the scan.
    pub(super) fn tree_tuples(owner: u32, window: Instant) -> Result<HashSet<Tuple>, ()> {
        let mut tuples = HashSet::new();
        let mut seen = HashSet::new();
        let mut stack = vec![owner];
        while let Some(pid) = stack.pop() {
            if Instant::now() >= window {
                return Err(());
            }
            if !seen.insert(pid) {
                continue;
            }
            if seen.len() > 4096 {
                return Err(());
            }
            tuples.extend(socket_tuples(pid, Some(window))?);
            stack.extend(children(pid)?);
        }
        Ok(tuples)
    }

    /// One direct look at the owner tree for this connection, used when no generation
    /// finished in time. An unreadable process of the tree fails the look, so it never
    /// admits on a partial view.
    fn direct_tree_has(owner: u32, client: SocketAddr, listen: SocketAddr, window: Instant) -> Result<bool, ()> {
        let mut seen = Vec::new();
        let mut stack = vec![owner];
        while let Some(pid) = stack.pop() {
            if Instant::now() >= window {
                return Err(());
            }
            if seen.contains(&pid) {
                continue;
            }
            seen.push(pid);
            if seen.len() > 4096 {
                return Err(());
            }
            if sockets_match(pid, client, listen, Some(window))? {
                return Ok(true);
            }
            stack.extend(children(pid)?);
        }
        Ok(false)
    }

    /// `Ok(Some)` is the process that still has the client socket. `Ok(None)` means
    /// the scan finished and no process has it. `Err` means the scan was incomplete.
    fn socket_holder(client: SocketAddr, listen: SocketAddr) -> Result<Option<u32>, ()> {
        let pids = all_pids()?;
        let mut incomplete = false;
        for pid in pids {
            match sockets_match(pid, client, listen, None) {
                Ok(true) => return Ok(Some(pid)),
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(()) } else { Ok(None) }
    }

    /// The return of a libproc call that fails with -1 or with zero and errno set. errno is cleared
    /// first, so a zero with errno clear is an answer (an empty list), not a failure.
    /// `Err` carries the errno of the failure.
    fn libproc_return(call: impl FnOnce() -> i32) -> Result<i32, i32> {
        // SAFETY: `__error` returns this thread's errno location, which is valid to write.
        unsafe {
            *libc::__error() = 0;
        }
        let got = call();
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if got < 0 || (got == 0 && errno != 0) {
            return Err(if errno != 0 { errno } else { libc::EIO });
        }
        Ok(got)
    }

    pub(super) fn all_pids() -> Result<Vec<u32>, ()> {
        let mut cap = 256usize;
        for _ in 0..6 {
            let mut buf = vec![0i32; cap];
            // proc_listallpids returns the number of pids it wrote, not a byte count. A full
            // buffer may hide more processes, so the buffer grows and the list is read again.
            let count = libproc_return(|| {
                // SAFETY: `buf` is writable for `buf.len() * 4` bytes. The call only fills that buffer.
                unsafe { proc_listallpids(buf.as_mut_ptr().cast::<c_void>(), (buf.len() * 4) as i32) }
            })
            .map_err(|_| ())?;
            // Zero processes is not an answer: launchd always runs, so an empty list is a failed read.
            if count == 0 {
                return Err(());
            }
            let count = count as usize;
            if count >= buf.len() {
                cap = cap.saturating_mul(2);
                continue;
            }
            return Ok(buf
                .into_iter()
                .take(count)
                .filter(|pid| *pid > 0)
                .map(|pid| pid as u32)
                .collect());
        }
        Err(())
    }

    fn children(pid: u32) -> Result<Vec<u32>, ()> {
        let mut buf = vec![0i32; 256];
        // SAFETY: `buf` is writable for `buf.len() * 4` bytes. The call only fills that buffer.
        let count = unsafe {
            proc_listchildpids(pid as i32, buf.as_mut_ptr().cast::<c_void>(), (buf.len() * 4) as i32)
        };
        if count < 0 || count as usize >= buf.len() {
            return Err(());
        }
        Ok(buf.into_iter().take(count as usize).filter(|pid| *pid > 0).map(|pid| pid as u32).collect())
    }

    /// The TCP and generic Internet sockets of `pid`, as canonical (local, remote) pairs.
    fn socket_tuples(pid: u32, window: Option<Instant>) -> Result<HashSet<Tuple>, ()> {
        // A process with more descriptors than the buffer holds is read again with a larger one:
        // a full buffer may hide the rest, and a short list would miss the connection it holds.
        let mut capacity = 4096usize * 8;
        let (list, got) = loop {
            let mut list = vec![0u8; capacity];
            let got = match libproc_return(|| {
                // SAFETY: `list` is writable for its length. The kernel writes at most that many bytes.
                unsafe { proc_pidinfo(pid as i32, PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast::<c_void>(), list.len() as i32) }
            }) {
                Ok(got) => got as usize,
                // Another user's process cannot be read, and it is not the owner's descendant: it
                // adds nothing the owner tree or the post-miss holder check could admit. A process
                // that exited after the listing holds no socket. Neither is a failed scan. Any other
                // error still fails the scan.
                Err(libc::EPERM | libc::ESRCH) => return Ok(HashSet::new()),
                Err(_) => return Err(()),
            };
            if got >= list.len() {
                capacity = capacity.checked_mul(2).filter(|next| *next <= 1 << 22).ok_or(())?;
                continue;
            }
            break (list, got);
        };
        if got % 8 != 0 {
            return Err(());
        }
        let fds = got / 8;
        let mut tuples = HashSet::new();
        for index in 0..fds {
            if window.is_some_and(|until| Instant::now() >= until) {
                return Err(());
            }
            let base = index * 8;
            let fd = i32::from_le_bytes(list[base..base + 4].try_into().unwrap());
            let kind = u32::from_le_bytes(list[base + 4..base + 8].try_into().unwrap());
            if kind != PROX_FDTYPE_SOCKET {
                continue;
            }
            if let Some(tuple) = socket_tuple(pid, fd)? {
                tuples.insert(tuple);
            }
        }
        Ok(tuples)
    }

    /// Whether `pid` holds the connection `client` to `listen`, both canonical.
    fn sockets_match(pid: u32, client: SocketAddr, listen: SocketAddr, window: Option<Instant>) -> Result<bool, ()> {
        let wanted = (
            SocketAddr::new(canonical(client.ip()), client.port()),
            SocketAddr::new(canonical(listen.ip()), listen.port()),
        );
        Ok(socket_tuples(pid, window)?.contains(&wanted))
    }

    /// The (local, remote) pair of one socket descriptor, or `None` for a descriptor that is
    /// not TCP or Internet, or that vanished since the list was read.
    fn socket_tuple(pid: u32, fd: i32) -> Result<Option<Tuple>, ()> {
        let mut info = vec![0u8; SOCKET_FDINFO_SIZE];
        let got = match libproc_return(|| {
            // SAFETY: `info` is exactly `sizeof(struct socket_fdinfo)` and is writable.
            unsafe {
                proc_pidfdinfo(
                    pid as i32,
                    fd,
                    PROC_PIDFDSOCKETINFO,
                    info.as_mut_ptr().cast::<c_void>(),
                    info.len() as i32,
                )
            }
        }) {
            Ok(got) => got,
            // The descriptor or its process can vanish between the list and this call. Then it
            // holds no socket any more, which is not a failed scan.
            Err(libc::ENOENT | libc::EBADF | libc::ESRCH) => return Ok(None),
            Err(_) => return Err(()),
        };
        if got == 0 {
            return Ok(None);
        }
        if got < SOCKET_FDINFO_SIZE as i32 {
            return Err(());
        }
        let kind = i32::from_le_bytes(info[OFF_SOI_KIND..OFF_SOI_KIND + 4].try_into().unwrap());
        if kind != SOCKINFO_TCP && kind != SOCKINFO_IN {
            return Ok(None);
        }
        let local_port = i32::from_le_bytes(info[OFF_LPORT..OFF_LPORT + 4].try_into().unwrap());
        let foreign_port = i32::from_le_bytes(info[OFF_FPORT..OFF_FPORT + 4].try_into().unwrap());
        let flags = info[OFF_VFLAG];
        let local = SocketAddr::new(socket_ip(&info, OFF_LADDR, flags), u16::from_be(local_port as u16));
        let remote = SocketAddr::new(socket_ip(&info, OFF_FADDR, flags), u16::from_be(foreign_port as u16));
        Ok(Some((local, remote)))
    }

    /// One `in_sockinfo` address. IPv4 sockets keep their address in the last four bytes.
    fn socket_ip(info: &[u8], offset: usize, flags: u8) -> IpAddr {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&info[offset..offset + 16]);
        if flags & INI_IPV4 != 0 {
            IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]))
        } else {
            IpAddr::V6(Ipv6Addr::from(raw)).to_canonical()
        }
    }

    fn descends_from(pid: u32, owner: u32) -> Result<bool, &'static str> {
        if pid == owner {
            return Ok(true);
        }
        if pid == 0 || pid == 1 {
            return Ok(false);
        }
        let mut current = pid;
        for _ in 0..64 {
            let parent = ppid(current).map_err(|_| UNCONFIRMED)?;
            if parent == owner {
                return Ok(true);
            }
            // launchd is pid 1, and its own parent is not readable. Reaching it
            // without the owner means this process is outside the browser tree.
            if parent == 0 || parent == 1 || parent == current {
                return Ok(false);
            }
            current = parent;
        }
        Ok(false)
    }

    fn ppid(pid: u32) -> Result<u32, ()> {
        let mut info = vec![0u8; BSDINFO_SIZE];
        // SAFETY: `info` is `sizeof(struct proc_bsdinfo)` and is writable.
        let got = unsafe {
            proc_pidinfo(pid as i32, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast::<c_void>(), info.len() as i32)
        };
        if got < BSDINFO_SIZE as i32 {
            return Err(());
        }
        Ok(u32::from_le_bytes(info[OFF_PPID..OFF_PPID + 4].try_into().unwrap()))
    }
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn the_process_list_is_every_process_not_the_newest_64() {
    // proc_listallpids returns a count. The reader that treated it as bytes saw only the newest 64
    // processes, so a real owner that was not among them could never be found.
    let pids = macos::all_pids().expect("the process list reads");
    assert!(pids.contains(&std::process::id()), "this process is listed");
    assert!(pids.len() > 64, "only {} processes listed", pids.len());
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{admit, Peers, ALREADY_CLOSED, CHECK_WINDOW, CONFIRM_BUDGET};

    fn loopback_pair() -> (TcpStream, TcpStream, SocketAddr, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let client_addr = client.local_addr().unwrap();
        (client, accepted, client_addr, listen)
    }

    struct StopSleep(Option<std::process::Child>);

    impl Drop for StopSleep {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    struct Burners {
        stop: Arc<AtomicBool>,
        joins: Vec<thread::JoinHandle<()>>,
    }

    impl Drop for Burners {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for handle in self.joins.drain(..) {
                let _ = handle.join();
            }
        }
    }

    impl Burners {
        fn start() -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let n = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
            let mut joins = Vec::with_capacity(n);
            for _ in 0..n {
                let stop = Arc::clone(&stop);
                joins.push(thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let mut x = 0x1234_5678_9abc_def0u64;
                        for _ in 0..50_000 {
                            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                        }
                        std::hint::black_box(x);
                    }
                }));
            }
            thread::sleep(Duration::from_millis(20));
            Self { stop, joins }
        }
    }

    fn refused_while_held(verdict: Result<(), &'static str>) -> bool {
        match verdict {
            Ok(()) => false,
            Err(ALREADY_CLOSED) => false,
            Err(_) => true,
        }
    }

    #[test]
    fn a_confirmed_owner_returns_before_the_retry_budget() {
        let peers = Peers::new(64);
        let mut worst = Duration::ZERO;
        for _ in 0..20 {
            let (client, accepted, peer, listen) = loopback_pair();
            let started = Instant::now();
            let verdict = admit(peer, listen, std::process::id(), &peers);
            let elapsed = started.elapsed();
            assert_eq!(verdict, Ok(()), "{verdict:?} after {elapsed:?}");
            worst = worst.max(elapsed);
            drop(client);
            drop(accepted);
        }
        eprintln!("confirmed owner worst={worst:?} budget={CONFIRM_BUDGET:?}");
        // The claim is structural: an admission that the owner tree confirms never enters the
        // retry path, whatever the clock says. Wall-clock time under a loaded suite is not
        // the claim, so it is not asserted here.
        assert_eq!(peers.misses(), 0, "a confirmed owner entered the retry path");
    }

    #[test]
    fn twenty_held_sockets_are_admitted_while_the_cpu_is_busy() {
        let peers = Peers::new(64);
        let _burn = Burners::start();
        let mut worst = Duration::ZERO;
        let mut refused = 0u32;
        for i in 0..20 {
            let (client, accepted, peer, listen) = loopback_pair();
            let started = Instant::now();
            let verdict = admit(peer, listen, std::process::id(), &peers);
            let elapsed = started.elapsed();
            if verdict.is_err() {
                refused += 1;
                eprintln!("load admit {i} {verdict:?} after {elapsed:?}");
            }
            worst = worst.max(elapsed);
            drop(client);
            drop(accepted);
        }
        let (open_client, open_accepted, open_peer, open_listen) = loopback_pair();
        let sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let sleeper = StopSleep(Some(sleeper));
        let owner = sleeper.0.as_ref().unwrap().id();
        // A stranger's owner is another process, so its view is kept apart from the browser's.
        let open = admit(open_peer, open_listen, owner, &Peers::new(64));
        let (fin_client, fin_accepted, fin_peer, fin_listen) = loopback_pair();
        fin_client.shutdown(Shutdown::Write).unwrap();
        let fin_started = Instant::now();
        let fin = admit(fin_peer, fin_listen, owner, &Peers::new(64));
        let fin_elapsed = fin_started.elapsed();
        eprintln!(
            "load admits worst={worst:?} refused={refused} open={open:?} fin={fin:?} fin_elapsed={fin_elapsed:?}"
        );
        assert_eq!(refused, 0, "a socket this process holds was refused under load");
        assert!(refused_while_held(open), "an open stranger was not refused: {open:?}");
        assert!(refused_while_held(fin), "a half-closed stranger was not refused: {fin:?}");
        assert!(
            fin_elapsed < CHECK_WINDOW + Duration::from_secs(2),
            "a stranger check did not stop: {fin_elapsed:?}"
        );
        drop(open_client);
        drop(open_accepted);
        drop(fin_client);
        drop(fin_accepted);
    }

    #[test]
    fn a_stranger_miss_does_not_hold_up_a_browser_connection() {
        // A relay has one owner, so each owner keeps its own view. The stranger's owner is
        // another process, so its connection is a miss; the browser connection hits in the
        // test process's own tree while the stranger's misses run.
        let browser_peers = Peers::new(64);
        let stranger_peers = Peers::new(64);
        let sleeper = StopSleep(Some(Command::new("/bin/sleep").arg("30").spawn().unwrap()));
        let sleeper_pid = sleeper.0.as_ref().unwrap().id();
        let (stranger_client, stranger_accepted, stranger_peer, stranger_listen) = loopback_pair();
        let slow = thread::spawn(move || {
            let started = Instant::now();
            let verdict = admit(stranger_peer, stranger_listen, sleeper_pid, &stranger_peers);
            (verdict, started.elapsed(), Instant::now())
        });
        thread::sleep(Duration::from_millis(5));
        let (client, accepted, peer, listen) = loopback_pair();
        let fast_started = Instant::now();
        let fast = admit(peer, listen, std::process::id(), &browser_peers);
        let fast_elapsed = fast_started.elapsed();
        let (slow_verdict, slow_elapsed, slow_finished) = slow.join().unwrap();
        eprintln!("overlap fast={fast_elapsed:?} slow={slow_elapsed:?} {slow_verdict:?}");
        assert_eq!(fast, Ok(()), "{fast:?}");
        // The claim: a stranger's miss never makes the browser connection wait past the window.
        // Whether the miss is still running when the browser is answered depends on scheduling,
        // so only the browser's own bound is asserted here.
        assert!(
            fast_elapsed < CHECK_WINDOW,
            "the browser connection waited past the window: browser {fast_elapsed:?}, miss {slow_elapsed:?}"
        );
        let _ = slow_finished;
        assert!(refused_while_held(slow_verdict), "{slow_verdict:?}");
        assert!(slow_elapsed < CHECK_WINDOW + Duration::from_secs(2), "{slow_elapsed:?}");
        drop(client);
        drop(accepted);
        drop(stranger_client);
        drop(stranger_accepted);
        drop(sleeper);
    }
}

/// Regression for HIGH 1 (review-013, scenario S4). A browser-like socket of the owner
/// holds source port P towards the relay. A stranger on another local address of the
/// same host binds the same port P and connects to the same relay. Matching only the
/// port pair takes the owner's socket for the stranger and admits it; the stranger must
/// be refused. Runs on Linux and macOS; the stranger uses 127.0.0.2, which is loopback too.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod same_port_tests {
    use std::io::{BufRead, BufReader};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::FromRawFd;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::{admit, Peers};

    /// The child that owns the browser-like socket. Runs only when spawned by the test.
    #[test]
    fn same_port_browser_hold_probe() {
        let Ok(listen) = std::env::var("SCRAPELENS_PEER_HOLD") else {
            return;
        };
        let stream = TcpStream::connect(("127.0.0.1", listen.parse::<u16>().unwrap())).unwrap();
        println!("PORT {}", stream.local_addr().unwrap().port());
        thread::sleep(Duration::from_secs(25));
        drop(stream);
    }

    struct Child25(Child);

    impl Drop for Child25 {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `socket`, `bind` to `local`, `connect` to `remote`. Std cannot bind before connect.
    fn connect_from(local: SocketAddrV4, remote: SocketAddrV4) -> std::io::Result<TcpStream> {
        fn sockaddr(addr: SocketAddrV4) -> libc::sockaddr_in {
            // SAFETY: an all-zero `sockaddr_in` is a valid value; the fields set below are the ones used.
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = addr.port().to_be();
            raw.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(addr.ip().octets()) };
            #[cfg(target_os = "macos")]
            {
                raw.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            raw
        }
        // SAFETY: the descriptor is closed on every error path below, and the sockaddr
        // structs live for the calls that read them.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let bound = sockaddr(local);
            if libc::bind(
                fd,
                (&bound as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
                let error = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let target = sockaddr(remote);
            if libc::connect(
                fd,
                (&target as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
                let error = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            Ok(TcpStream::from_raw_fd(fd))
        }
    }

    /// A local IPv4 address other than 127.0.0.1 that this host sends from: 127.0.0.2 where the
    /// loopback range is configured (Linux), else the source the default route uses (macOS,
    /// which does not configure 127.0.0.2). No packet is sent: a UDP `connect` only picks the route.
    fn other_local_address() -> Option<Ipv4Addr> {
        if TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).is_ok() {
            return Some(Ipv4Addr::new(127, 0, 0, 2));
        }
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        udp.connect((Ipv4Addr::new(203, 0, 113, 1), 9)).ok()?;
        match udp.local_addr().ok()?.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
            _ => None,
        }
    }

    #[test]
    fn a_stranger_on_another_address_with_the_browser_port_is_refused() {
        let other = other_local_address().expect("this host has a second local IPv4 address to send from");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relay::peer::same_port_tests::same_port_browser_hold_probe", "--nocapture", "--test-threads", "1"])
            .env("SCRAPELENS_PEER_HOLD", listen.port().to_string())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            // The harness writes its own "name ... " before the probe's line, so the marker
            // is searched for, not matched at the start.
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(at) = line.find("PORT ") {
                    let digits = line[at + 5..].split_whitespace().next().unwrap_or("");
                    if let Ok(port) = digits.parse::<u16>() {
                        let _ = tx.send(port);
                        return;
                    }
                }
            }
        });
        let browser_port = rx.recv_timeout(Duration::from_secs(20)).expect("the browser-like socket was not reported");
        let _browser = Child25(child);
        let (_browser_side, _) = listener.accept().unwrap();
        let owner = _browser.0.id();

        // The owner's own socket, on the loopback address the relay sees, is admitted.
        let owner_addr = SocketAddr::from(([127, 0, 0, 1], browser_port));
        assert_eq!(admit(owner_addr, listen, owner, &Peers::new(64)), Ok(()), "the owner's socket must stay admitted");

        // The stranger: same source port, another loopback address, held open towards the relay.
        let stranger = connect_from(SocketAddrV4::new(other, browser_port), SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen.port()))
            .expect("the second local address can send to the relay");
        let (_stranger_side, _) = listener.accept().unwrap();
        let stranger_addr = SocketAddr::new(IpAddr::V4(other), browser_port);
        let verdict = admit(stranger_addr, listen, owner, &Peers::new(64));
        drop(stranger);
        assert!(verdict.is_err(), "a stranger with the browser's port was admitted: {verdict:?}");
    }
}

#[cfg(test)]
mod pending_tests {
    use std::sync::atomic::Ordering;

    use super::Pending;

    /// At the limit the oldest waiter is cancelled, never the newest arrival.
    #[test]
    fn the_oldest_waiter_is_cancelled_at_the_limit() {
        let pending = Pending::new(2);
        let (first, evicted) = pending.enter();
        assert!(!evicted);
        let (second, evicted) = pending.enter();
        assert!(!evicted);
        let (third, evicted) = pending.enter();
        assert!(evicted, "the third arrival takes a slot from the oldest");
        assert!(first.cancelled.load(Ordering::SeqCst), "the oldest waiter is cancelled");
        assert!(!second.cancelled.load(Ordering::SeqCst), "a newer waiter is kept");
        assert!(!third.cancelled.load(Ordering::SeqCst), "the newest arrival is kept");
    }

    /// A finished waiter frees its slot, so nothing is evicted for it.
    #[test]
    fn a_finished_waiter_frees_its_slot() {
        let pending = Pending::new(2);
        let (first, _) = pending.enter();
        let (_second, _) = pending.enter();
        pending.leave(&first);
        let (_third, evicted) = pending.enter();
        assert!(!evicted, "a freed slot is taken without an eviction");
    }
}
