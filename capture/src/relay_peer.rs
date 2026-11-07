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

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// No process still has this socket. The relay closes it without admitting it and
/// without showing a failure. A client that is still reading keeps the socket and
/// is refused instead.
pub(crate) const ALREADY_CLOSED: &str = "the client closed before its process could be checked";

/// The process scans in progress are at their limit, or a scan waited out its budget.
/// The connection is refused: a check that cannot run is never a pass.
pub(crate) const BUSY: &str = "too many connections are being checked at once";

/// Bounds the connections or scans that run at the same time. A permit is held for as long as
/// the work it counts; a pause between two confirmation attempts holds none.
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

/// `owner` is the browser pid published by the capture. Zero means it is not known yet.
/// `client` is the address the relay sees for the connection, `listen` the relay's own.
pub(crate) fn admit(
    client: SocketAddr,
    listen: SocketAddr,
    owner: u32,
    checks: &Arc<Gate>,
) -> Result<(), &'static str> {
    if owner == 0 {
        return Err("the capture browser is not running yet");
    }
    #[cfg(target_os = "linux")]
    {
        linux::admit(client, listen, owner, checks)
    }
    #[cfg(target_os = "macos")]
    {
        macos::admit(client, listen, owner, checks)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (client, listen, owner, checks);
        Err("the client process could not be confirmed")
    }
}

/// How long a miss may be retried. A hit returns on the first look.
/// 400 ms sits inside the 250–500 ms cap: long enough for a busy process
/// table or a descriptor that appears just after accept, and short enough
/// that one connection cannot sit forever.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const CONFIRM_BUDGET: std::time::Duration = std::time::Duration::from_millis(400);

/// Retries `once` with backoff until [`CONFIRM_BUDGET`] is spent.
/// The sleep stays on this thread, and holds no check permit. The accept loop admits each
/// connection on its own thread, so one slow check does not hold the next.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn retry_for(mut once: impl FnMut() -> Result<(), &'static str>) -> Result<(), &'static str> {
    let started = std::time::Instant::now();
    let mut delay = std::time::Duration::from_millis(1);
    let cap = std::time::Duration::from_millis(32);
    let mut last;
    loop {
        match once() {
            Ok(()) => return Ok(()),
            Err(reason) => last = reason,
        }
        let elapsed = started.elapsed();
        if elapsed >= CONFIRM_BUDGET {
            return Err(last);
        }
        let pause = delay.min(CONFIRM_BUDGET - elapsed);
        if pause.is_zero() {
            return Err(last);
        }
        std::thread::sleep(pause);
        delay = delay.saturating_mul(2).min(cap);
    }
}

/// One process scan under a permit of `checks`. Without a permit within the budget the scan
/// does not run, and the connection is refused like any other failed check.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scan(checks: &Arc<Gate>, once: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
    match Gate::acquire(checks, CONFIRM_BUDGET) {
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use std::sync::Arc;

    use super::{canonical, scan, Gate};

    const NOT_BROWSER: &str = "the client process is not the capture browser";
    const UNCONFIRMED: &str = "the client process could not be confirmed";

    pub(crate) fn admit(client: SocketAddr, listen: SocketAddr, owner: u32, checks: &Arc<Gate>) -> Result<(), &'static str> {
        // The socket can show up in /proc a moment after accept, and a busy
        // /proc read can fail or list one row twice. Spread the misses across
        // the budget, then fail closed. A hit does not sleep.
        let last = match super::retry_for(|| scan(checks, || admit_once(client, listen, owner))) {
            Ok(()) => return Ok(()),
            Err(reason) => reason,
        };
        // The browser tree missed this socket. A row that is gone, or that no
        // process of the socket's uid still holds, cannot read a tunnel. An
        // unreadable process of another uid is not that holder. A same-uid
        // process that still has it stays refused, and is not admitted here.
        if last == NOT_BROWSER || last == UNCONFIRMED {
            return released_or(client, listen, last, checks);
        }
        Err(last)
    }

    /// `held` is the refusal when a process of the socket uid still has the inode.
    fn released_or(
        client: SocketAddr,
        listen: SocketAddr,
        held: &'static str,
        checks: &Arc<Gate>,
    ) -> Result<(), &'static str> {
        scan(checks, || match client_once(client, listen) {
            Ok(None) => Err(super::ALREADY_CLOSED),
            Err(()) => Err(UNCONFIRMED),
            // No owner (inode 0): the kernel has no process for this socket, so it is closed.
            Ok(Some(row)) if row.inode == 0 => Err(super::ALREADY_CLOSED),
            Ok(Some(row)) => match uid_holds_inode(row.inode, row.uid) {
                Ok(false) => Err(super::ALREADY_CLOSED),
                Ok(true) => Err(held),
                Err(()) => Err(UNCONFIRMED),
            },
        })
    }

    fn admit_once(client: SocketAddr, listen: SocketAddr, owner: u32) -> Result<(), &'static str> {
        let inode = find_client_inode(client, listen)?;
        let mut incomplete = false;
        let mut stack = vec![owner];
        let mut seen = Vec::new();
        while let Some(pid) = stack.pop() {
            if seen.contains(&pid) {
                continue;
            }
            seen.push(pid);
            if seen.len() > 4096 {
                return Err(UNCONFIRMED);
            }
            match process_has_inode(pid, inode) {
                Ok(true) => return if descends_from(pid, owner)? { Ok(()) } else { Err(NOT_BROWSER) },
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
            match children(pid) {
                Ok(kids) => stack.extend(kids),
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(UNCONFIRMED) } else { Err(NOT_BROWSER) }
    }

    fn find_client_inode(client: SocketAddr, listen: SocketAddr) -> Result<u64, &'static str> {
        match client_once(client, listen) {
            Ok(Some(row)) if row.inode != 0 => Ok(row.inode),
            // No owner (inode 0): the kernel has no process for this socket, so it is closed,
            // not a stranger (LOW 5). A non-root process cannot read the other owners' tables.
            Ok(Some(_)) => Err(super::ALREADY_CLOSED),
            // TIME_WAIT and a socket that has already disappeared have no process.
            // A client that is still reading stays ESTABLISHED or FIN_WAIT and is listed.
            Ok(None) => Err(super::ALREADY_CLOSED),
            Err(()) => Err(UNCONFIRMED),
        }
    }

    /// The client socket is the established row whose local side is the client's address
    /// and port, and whose remote side is the relay's. `/proc/net/tcp` addresses are
    /// little-endian; a row must match the whole connection, not only the port pair.
    fn client_once(client: SocketAddr, listen: SocketAddr) -> Result<Option<ClientSocket>, ()> {
        let mut found: Option<ClientSocket> = None;
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(()),
            };
            for line in text.lines().skip(1) {
                let mut cols = line.split_whitespace();
                let _index = cols.next();
                let Some(local) = cols.next() else { continue };
                let Some(remote) = cols.next() else { continue };
                let Some(state) = cols.next() else { continue };
                // ESTABLISHED, or FIN_WAIT after the client half-closes and keeps reading.
                // TIME_WAIT has no process and must not count as that client.
                if !matches!(state, "01" | "04" | "05") {
                    continue;
                }
                let Some((local_addr, local_port)) = local.rsplit_once(':') else { continue };
                let Some((remote_addr, remote_port)) = remote.rsplit_once(':') else { continue };
                let Ok(local_port) = u16::from_str_radix(local_port, 16) else { continue };
                let Ok(remote_port) = u16::from_str_radix(remote_port, 16) else { continue };
                if local_port != client.port() || remote_port != listen.port() {
                    continue;
                }
                if parse_addr(local_addr) != Some(canonical(client.ip()))
                    || parse_addr(remote_addr) != Some(canonical(listen.ip()))
                {
                    continue;
                }
                // tx_queue:rx_queue, tr:tm, retrnsmt, uid, timeout, inode.
                // A torn or shifting snapshot can repeat one socket. The same inode is
                // one match. Two inodes, or two uids, on one port pair means the table moved.
                let Some(uid) = cols.nth(3) else { continue };
                let Ok(uid) = uid.parse::<u32>() else { continue };
                let Some(inode) = cols.nth(1) else { continue };
                let Ok(inode) = inode.parse::<u64>() else { continue };
                let row = ClientSocket { inode, uid };
                if let Some(previous) = found {
                    if previous.inode != inode || previous.uid != uid {
                        return Err(());
                    }
                    continue;
                }
                found = Some(row);
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

    fn process_has_inode(pid: u32, inode: u64) -> Result<bool, ()> {
        let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(()),
        };
        let needle = format!("socket:[{inode}]");
        for entry in entries {
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

    /// `Ok(true)` when a process of `uid` has the inode. `Ok(false)` when every
    /// process of that uid was readable and none has it. Another uid is ignored,
    /// including one whose descriptor table cannot be read. `Err` when a process
    /// of this uid, or a process whose uid cannot be read, was skipped.
    fn uid_holds_inode(inode: u64, uid: u32) -> Result<bool, ()> {
        let entries = std::fs::read_dir("/proc").map_err(|_| ())?;
        let mut incomplete = false;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
                continue;
            };
            match process_uid(pid) {
                Ok(Some(process)) if process == uid => {}
                Ok(_) => continue,
                Err(()) => {
                    incomplete = true;
                    continue;
                }
            }
            match process_has_inode(pid, inode) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(()) } else { Ok(false) }
    }

    /// `Ok(None)` is a pid that has already exited. An unreadable status hides
    /// the uid, so the caller keeps the check fail-closed.
    fn process_uid(pid: u32) -> Result<Option<u32>, ()> {
        let text = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("Uid:") else { continue };
            let Some(uid) = rest.split_whitespace().next() else { return Err(()) };
            return uid.parse().map(Some).map_err(|_| ());
        }
        Err(())
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
            // Init is the root. Reaching it without the owner means this process is outside.
            if parent == 0 || parent == 1 || parent == current {
                return Ok(false);
            }
            current = parent;
        }
        Ok(false)
    }

    fn ppid(pid: u32) -> Result<u32, ()> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| ())?;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                return rest.trim().parse().map_err(|_| ());
            }
        }
        Err(())
    }

    #[cfg(test)]
    mod tests {
        use std::net::{TcpListener, TcpStream};
        use std::process::Command;
        use std::thread;
        use std::time::Duration;

        use super::super::{Gate, ALREADY_CLOSED};
        use super::{admit, client_once, released_or, uid_holds_inode, NOT_BROWSER, UNCONFIRMED};

        #[test]
        fn the_socket_uid_scan_sees_a_live_descriptor_and_not_a_closed_one() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).unwrap();
            let accepted = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            let row = client_once(client_addr, listen).unwrap().expect("client row");
            assert_eq!(uid_holds_inode(row.inode, row.uid), Ok(true));
            drop(client);
            drop(accepted);
            thread::sleep(Duration::from_millis(50));
            assert_eq!(uid_holds_inode(row.inode, row.uid), Ok(false));
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
            thread::sleep(Duration::from_millis(50));
            assert_eq!(released_or(client_addr, listen, UNCONFIRMED, &gate), Err(ALREADY_CLOSED));
            assert_eq!(released_or(client_addr, listen, NOT_BROWSER, &gate), Err(ALREADY_CLOSED));

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).unwrap();
            let _accepted = listener.accept().unwrap();
            let client_addr = client.local_addr().unwrap();
            let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let verdict = admit(client_addr, listen, sleeper.id(), &gate);
            let _ = sleeper.kill();
            let _ = sleeper.wait();
            assert_eq!(verdict, Err(NOT_BROWSER), "{verdict:?}");
            drop(client);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::raw::c_void;

    use std::sync::Arc;

    use super::{canonical, scan, Gate};

    const NOT_BROWSER: &str = "the client process is not the capture browser";
    const UNCONFIRMED: &str = "the client process could not be confirmed";
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

    pub(crate) fn admit(client: SocketAddr, listen: SocketAddr, owner: u32, checks: &Arc<Gate>) -> Result<(), &'static str> {
        // A helper can connect in the same instant it appears in the process tree.
        // Spread the misses across the same budget as Linux, then still fail closed.
        // A hit does not sleep.
        let last = match super::retry_for(|| scan(checks, || admit_once(client, listen, owner))) {
            Ok(()) => return Ok(()),
            Err(reason) => reason,
        };
        // The owner tree does not have this socket. A stranger that is still
        // reading has it open somewhere else. A Chrome cancel has already dropped
        // the descriptor, so nobody can read a tunnel reply.
        if last == NOT_BROWSER {
            return scan(checks, || match socket_holder(client, listen) {
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
        if last == UNCONFIRMED {
            return scan(checks, || match socket_holder(client, listen) {
                Ok(None) => Err(super::ALREADY_CLOSED),
                Ok(Some(_)) | Err(()) => Err(UNCONFIRMED),
            });
        }
        Err(last)
    }

    fn admit_once(client: SocketAddr, listen: SocketAddr, owner: u32) -> Result<(), &'static str> {
        let mut incomplete = false;
        let mut stack = vec![owner];
        let mut seen = Vec::new();
        while let Some(pid) = stack.pop() {
            if seen.contains(&pid) {
                continue;
            }
            seen.push(pid);
            if seen.len() > 4096 {
                return Err(UNCONFIRMED);
            }
            match sockets_match(pid, client, listen) {
                Ok(true) => return if descends_from(pid, owner)? { Ok(()) } else { Err(NOT_BROWSER) },
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
            match children(pid) {
                Ok(kids) => stack.extend(kids),
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(UNCONFIRMED) } else { Err(NOT_BROWSER) }
    }

    /// `Ok(Some)` is the process that still has the client socket. `Ok(None)` means
    /// the scan finished and no process has it. `Err` means the scan was incomplete.
    fn socket_holder(client: SocketAddr, listen: SocketAddr) -> Result<Option<u32>, ()> {
        let pids = all_pids()?;
        let mut incomplete = false;
        for pid in pids {
            match sockets_match(pid, client, listen) {
                Ok(true) => return Ok(Some(pid)),
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(()) } else { Ok(None) }
    }

    fn all_pids() -> Result<Vec<u32>, ()> {
        let mut cap = 256usize;
        for _ in 0..6 {
            let mut buf = vec![0i32; cap];
            // SAFETY: `buf` is writable for `buf.len() * 4` bytes. The call only fills that buffer.
            let got = unsafe {
                proc_listallpids(buf.as_mut_ptr().cast::<c_void>(), (buf.len() * 4) as i32)
            };
            if got < 0 {
                return Err(());
            }
            let bytes = got as usize;
            if bytes >= buf.len() * 4 {
                cap = cap.saturating_mul(2);
                continue;
            }
            let count = bytes / 4;
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

    fn sockets_match(pid: u32, client: SocketAddr, listen: SocketAddr) -> Result<bool, ()> {
        let mut list = vec![0u8; 4096 * 8];
        // SAFETY: `list` is writable for its length. The kernel writes at most that many bytes.
        let got = unsafe {
            proc_pidinfo(pid as i32, PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast::<c_void>(), list.len() as i32)
        };
        if got < 0 || got as usize >= list.len() || got as usize % 8 != 0 {
            return Err(());
        }
        let fds = got as usize / 8;
        for index in 0..fds {
            let base = index * 8;
            let fd = i32::from_le_bytes(list[base..base + 4].try_into().unwrap());
            let kind = u32::from_le_bytes(list[base + 4..base + 8].try_into().unwrap());
            if kind != PROX_FDTYPE_SOCKET {
                continue;
            }
            if socket_is_client(pid, fd, client, listen)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn socket_is_client(pid: u32, fd: i32, client: SocketAddr, listen: SocketAddr) -> Result<bool, ()> {
        let mut info = vec![0u8; SOCKET_FDINFO_SIZE];
        // SAFETY: `info` is exactly `sizeof(struct socket_fdinfo)` and is writable.
        let got = unsafe {
            proc_pidfdinfo(
                pid as i32,
                fd,
                PROC_PIDFDSOCKETINFO,
                info.as_mut_ptr().cast::<c_void>(),
                info.len() as i32,
            )
        };
        if got == 0 {
            // The descriptor can vanish between the list and this call.
            return Ok(false);
        }
        if got < SOCKET_FDINFO_SIZE as i32 {
            return Err(());
        }
        let kind = i32::from_le_bytes(info[OFF_SOI_KIND..OFF_SOI_KIND + 4].try_into().unwrap());
        if kind != SOCKINFO_TCP && kind != SOCKINFO_IN {
            return Ok(false);
        }
        let local = i32::from_le_bytes(info[OFF_LPORT..OFF_LPORT + 4].try_into().unwrap());
        let foreign = i32::from_le_bytes(info[OFF_FPORT..OFF_FPORT + 4].try_into().unwrap());
        let local = u16::from_be(local as u16);
        let foreign = u16::from_be(foreign as u16);
        if local != client.port() || foreign != listen.port() {
            return Ok(false);
        }
        // The whole connection: the client's address on the local side, the relay's on the foreign.
        let flags = info[OFF_VFLAG];
        let local_ip = socket_ip(&info, OFF_LADDR, flags);
        let foreign_ip = socket_ip(&info, OFF_FADDR, flags);
        Ok(local_ip == canonical(client.ip()) && foreign_ip == canonical(listen.ip()))
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{admit, Gate, ALREADY_CLOSED, CONFIRM_BUDGET};

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
        let gate = Gate::new(64);
        let mut worst = Duration::ZERO;
        for _ in 0..20 {
            let (client, accepted, peer, listen) = loopback_pair();
            let started = Instant::now();
            let verdict = admit(peer, listen, std::process::id(), &gate);
            let elapsed = started.elapsed();
            assert_eq!(verdict, Ok(()), "{verdict:?} after {elapsed:?}");
            worst = worst.max(elapsed);
            drop(client);
            drop(accepted);
        }
        eprintln!("confirmed owner worst={worst:?} budget={CONFIRM_BUDGET:?}");
        assert!(
            worst < CONFIRM_BUDGET / 2,
            "a hit waited {worst:?}; only a miss may use {CONFIRM_BUDGET:?}"
        );
    }

    #[test]
    fn twenty_held_sockets_are_admitted_while_the_cpu_is_busy() {
        let gate = Gate::new(64);
        let _burn = Burners::start();
        let mut worst = Duration::ZERO;
        let mut refused = 0u32;
        for i in 0..20 {
            let (client, accepted, peer, listen) = loopback_pair();
            let started = Instant::now();
            let verdict = admit(peer, listen, std::process::id(), &gate);
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
        let open = admit(open_peer, open_listen, owner, &gate);
        let (fin_client, fin_accepted, fin_peer, fin_listen) = loopback_pair();
        fin_client.shutdown(Shutdown::Write).unwrap();
        let fin_started = Instant::now();
        let fin = admit(fin_peer, fin_listen, owner, &gate);
        let fin_elapsed = fin_started.elapsed();
        eprintln!(
            "load admits worst={worst:?} refused={refused} open={open:?} fin={fin:?} fin_elapsed={fin_elapsed:?}"
        );
        assert_eq!(refused, 0, "a socket this process holds was refused under load");
        assert!(refused_while_held(open), "an open stranger was not refused: {open:?}");
        assert!(refused_while_held(fin), "a half-closed stranger was not refused: {fin:?}");
        assert!(
            fin_elapsed >= Duration::from_millis(250),
            "a stranger was refused before the budget: {fin_elapsed:?}"
        );
        assert!(
            fin_elapsed < CONFIRM_BUDGET + Duration::from_secs(2),
            "a stranger check did not stop: {fin_elapsed:?}"
        );
        drop(open_client);
        drop(open_accepted);
        drop(fin_client);
        drop(fin_accepted);
    }

    #[test]
    fn a_slow_miss_does_not_hold_up_another_connection() {
        let gate = Gate::new(64);
        let (stranger_client, stranger_accepted, stranger_peer, stranger_listen) = loopback_pair();
        let sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let sleeper = StopSleep(Some(sleeper));
        let owner = sleeper.0.as_ref().unwrap().id();
        let started = Instant::now();
        let slow_gate = gate;
        let slow_gate_thread = Arc::clone(&slow_gate);
        let slow = thread::spawn(move || {
            let verdict = admit(stranger_peer, stranger_listen, owner, &slow_gate_thread);
            (verdict, started.elapsed())
        });
        thread::sleep(Duration::from_millis(30));
        let (client, accepted, peer, listen) = loopback_pair();
        let fast_started = Instant::now();
        let fast = admit(peer, listen, std::process::id(), &slow_gate);
        let fast_elapsed = fast_started.elapsed();
        let (slow_verdict, slow_elapsed) = slow.join().unwrap();
        eprintln!("overlap fast={fast_elapsed:?} slow={slow_elapsed:?} {slow_verdict:?}");
        assert_eq!(fast, Ok(()), "{fast:?}");
        assert!(
            fast_elapsed < CONFIRM_BUDGET / 2,
            "another connection waited out the miss: {fast_elapsed:?}"
        );
        assert!(refused_while_held(slow_verdict), "{slow_verdict:?}");
        assert!(slow_elapsed >= Duration::from_millis(250), "{slow_elapsed:?}");
        drop(client);
        drop(accepted);
        drop(stranger_client);
        drop(stranger_accepted);
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

    use super::{admit, Gate};

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
        assert_eq!(admit(owner_addr, listen, owner, &Gate::new(64)), Ok(()), "the owner's socket must stay admitted");

        // The stranger: same source port, another loopback address, held open towards the relay.
        let stranger = connect_from(SocketAddrV4::new(other, browser_port), SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen.port()))
            .expect("the second local address can send to the relay");
        let (_stranger_side, _) = listener.accept().unwrap();
        let stranger_addr = SocketAddr::new(IpAddr::V4(other), browser_port);
        let verdict = admit(stranger_addr, listen, owner, &Gate::new(64));
        drop(stranger);
        assert!(verdict.is_err(), "a stranger with the browser's port was admitted: {verdict:?}");
    }
}
