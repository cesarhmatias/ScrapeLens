//! Decides whether the process that connected to the relay may use it.
//!
//! Chrome does not authenticate to the local SOCKS5 listener, so the relay admits a
//! connection only when the socket belongs to the capture browser or one of its
//! descendants. Anything else, including another user of this machine, is refused.
//! A process of the same user that can already drive that Chrome is outside this check.
//! If the owner cannot be confirmed, the connection is refused. A socket that no
//! process still holds cannot read a tunnel; that result is [`ALREADY_CLOSED`].

/// No process still has this socket. The relay closes it without admitting it and
/// without showing a failure. A client that is still reading keeps the socket and
/// is refused instead.
pub(crate) const ALREADY_CLOSED: &str = "the client closed before its process could be checked";

/// `owner` is the browser pid published by the capture. Zero means it is not known yet.
pub(crate) fn admit(peer_port: u16, listen_port: u16, owner: u32) -> Result<(), &'static str> {
    if owner == 0 {
        return Err("the capture browser is not running yet");
    }
    #[cfg(target_os = "linux")]
    {
        linux::admit(peer_port, listen_port, owner)
    }
    #[cfg(target_os = "macos")]
    {
        macos::admit(peer_port, listen_port, owner)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (peer_port, listen_port, owner);
        Err("the client process could not be confirmed")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    const NOT_BROWSER: &str = "the client process is not the capture browser";
    const UNCONFIRMED: &str = "the client process could not be confirmed";

    pub(crate) fn admit(peer_port: u16, listen_port: u16, owner: u32) -> Result<(), &'static str> {
        // The socket can show up in /proc a moment after accept, and a busy
        // /proc/net/tcp read can list one row twice. Retry a miss, then fail closed.
        let mut last = UNCONFIRMED;
        for attempt in 0..5 {
            match admit_once(peer_port, listen_port, owner) {
                Ok(()) => return Ok(()),
                Err(reason) => {
                    last = reason;
                    if attempt + 1 < 5 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        // Not in the browser tree. A FIN_WAIT row can outlive the process that
        // closed it. Only a process that still has the inode can read a tunnel.
        if last == NOT_BROWSER {
            return match inode_once(peer_port, listen_port) {
                Ok(Some(inode)) => match any_process_has_inode(inode) {
                    Ok(true) => Err(NOT_BROWSER),
                    Ok(false) => Err(super::ALREADY_CLOSED),
                    Err(()) => Err(UNCONFIRMED),
                },
                Ok(None) => Err(super::ALREADY_CLOSED),
                Err(()) => Err(UNCONFIRMED),
            };
        }
        Err(last)
    }

    fn admit_once(peer_port: u16, listen_port: u16, owner: u32) -> Result<(), &'static str> {
        let inode = find_client_inode(peer_port, listen_port)?;
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

    fn find_client_inode(peer_port: u16, listen_port: u16) -> Result<u64, &'static str> {
        match inode_once(peer_port, listen_port) {
            Ok(Some(inode)) => Ok(inode),
            // TIME_WAIT and a socket that has already disappeared have no process.
            // A client that is still reading stays ESTABLISHED or FIN_WAIT and is listed.
            Ok(None) => Err(super::ALREADY_CLOSED),
            Err(()) => Err(UNCONFIRMED),
        }
    }

    /// The client socket is the established row whose local port is the ephemeral port
    /// and whose remote port is the relay. `/proc/net/tcp` addresses are little-endian.
    fn inode_once(peer_port: u16, listen_port: u16) -> Result<Option<u64>, ()> {
        let mut found = None;
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
                if local_port != peer_port || remote_port != listen_port {
                    continue;
                }
                if !is_loopback(local_addr) || !is_loopback(remote_addr) {
                    continue;
                }
                // tx_queue:rx_queue, tr:tm, retrnsmt, uid, timeout, inode.
                // A torn or shifting snapshot can repeat one socket. The same inode is
                // one match. Two inodes on one port pair means the table moved.
                let Some(inode) = cols.nth(5) else { continue };
                let Ok(inode) = inode.parse::<u64>() else { continue };
                if let Some(previous) = found {
                    if previous != inode {
                        return Err(());
                    }
                    continue;
                }
                found = Some(inode);
            }
        }
        Ok(found)
    }

    fn is_loopback(addr: &str) -> bool {
        addr.eq_ignore_ascii_case("0100007F")
            || addr.eq_ignore_ascii_case("00000000000000000000000001000000")
            || addr.eq_ignore_ascii_case("0000000000000000FFFF00000100007F")
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

    fn any_process_has_inode(inode: u64) -> Result<bool, ()> {
        let entries = std::fs::read_dir("/proc").map_err(|_| ())?;
        let mut incomplete = false;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
                continue;
            };
            match process_has_inode(pid, inode) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(()) => incomplete = true,
            }
        }
        if incomplete { Err(()) } else { Ok(false) }
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
}

#[cfg(target_os = "macos")]
mod macos {
    use std::os::raw::c_void;

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
    const BSDINFO_SIZE: usize = 136;
    const OFF_PPID: usize = 16;

    #[link(name = "proc")]
    extern "C" {
        fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_listchildpids(ppid: i32, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut c_void, buffersize: i32) -> i32;
    }

    pub(crate) fn admit(peer_port: u16, listen_port: u16, owner: u32) -> Result<(), &'static str> {
        // A helper can connect in the same instant it appears in the process tree.
        // Retry a miss the way the Linux inode lookup does, then still fail closed.
        let mut last = NOT_BROWSER;
        for attempt in 0..5 {
            match admit_once(peer_port, listen_port, owner) {
                Ok(()) => return Ok(()),
                Err(reason) => {
                    last = reason;
                    if attempt + 1 < 5 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                }
            }
        }
        // The owner tree does not have this socket. A stranger that is still
        // reading has it open somewhere else. A Chrome cancel has already dropped
        // the descriptor, so nobody can read a tunnel reply.
        if last == NOT_BROWSER {
            match socket_holder(peer_port, listen_port) {
                Ok(Some(pid)) => {
                    return if descends_from(pid, owner)? { Ok(()) } else { Err(NOT_BROWSER) };
                }
                Ok(None) => return Err(super::ALREADY_CLOSED),
                Err(()) => return Err(UNCONFIRMED),
            }
        }
        Err(last)
    }

    fn admit_once(peer_port: u16, listen_port: u16, owner: u32) -> Result<(), &'static str> {
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
            match sockets_match(pid, peer_port, listen_port) {
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
    fn socket_holder(peer_port: u16, listen_port: u16) -> Result<Option<u32>, ()> {
        let pids = all_pids()?;
        let mut incomplete = false;
        for pid in pids {
            match sockets_match(pid, peer_port, listen_port) {
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

    fn sockets_match(pid: u32, peer_port: u16, listen_port: u16) -> Result<bool, ()> {
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
            if socket_is_client(pid, fd, peer_port, listen_port)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn socket_is_client(pid: u32, fd: i32, peer_port: u16, listen_port: u16) -> Result<bool, ()> {
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
        Ok(local == peer_port && foreign == listen_port)
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
