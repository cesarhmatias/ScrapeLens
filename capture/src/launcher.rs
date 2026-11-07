//! launcher module for the capture crate; moved from lib.rs by T29.

use super::*;

pub(crate) fn merge_blink_features(args: &mut Vec<String>, features: &[&str]) {
    const PREFIX: &str = "--disable-blink-features=";
    let mut merged: Vec<String> = Vec::new();
    let mut first_index: Option<usize> = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(values) = args[index].strip_prefix(PREFIX) {
            for value in values.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                if !merged.iter().any(|m| m == value) {
                    merged.push(value.to_string());
                }
            }
            if first_index.is_none() {
                first_index = Some(index);
                index += 1;
            } else {
                args.remove(index);
            }
        } else {
            index += 1;
        }
    }
    for feature in features {
        if !merged.iter().any(|m| m == feature) {
            merged.push((*feature).to_string());
        }
    }
    let flag = format!("{PREFIX}{}", merged.join(","));
    match first_index {
        Some(at) => args[at] = flag,
        None => args.insert(args.len().saturating_sub(1), flag),
    }
}

/// Arguments recorded in `session.json` (`capture.chromeArgs`): the same as the
/// launch ones, without the temporary paths (profile and NetLog) and without the
/// initial URL. Whoever reads the session (the `site_profile`) knows the context in which it was
/// captured, including that the automation notice was suppressed.
pub(crate) fn recorded_chrome_args(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|a| *a != "about:blank")
        .map(|a| {
            if a.starts_with("--user-data-dir=") {
                "--user-data-dir=<temporary-profile>".to_string()
            } else if a.starts_with("--log-net-log=") {
                "--log-net-log=<netlog>".to_string()
            } else {
                a.clone()
            }
        })
        .collect()
}

/// Command-line arguments for the capture's Chrome, without running anything
/// (testable). `resolver_rules` is the allowlist of the CONTROLLED capture; when
/// it exists, it applies in place of the network mode, and no certificate relaxation is
/// added.
pub(crate) fn chrome_args(
    config: &CaptureConfig,
    profile: &Path,
    netlog: &Path,
    resolver_rules: Option<&str>,
    use_pipe: bool,
    proxy_arg: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--log-net-log={}", netlog.display()),
        "--net-log-capture-mode=Everything".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-sync".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-extensions".to_string(),
        "--metrics-recording-only".to_string(),
        "--no-service-autorun".to_string(),
        "--no-pings".to_string(),
        "--disable-breakpad".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-component-extensions-with-background-pages".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
        "--disable-search-engine-choice-screen".to_string(),
        "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions"
            .to_string(),
        "--enable-quic".to_string(),
        "--disable-popup-blocking".to_string(),
        "about:blank".to_string(),
    ];
    // D7: the automation notice is ALWAYS suppressed (`navigator.webdriver` goes back to
    // `false` even with CDP), in every mode and transport.
    merge_blink_features(&mut args, &[AUTOMATION_FEATURE]);
    if use_pipe {
        // No port at all: Chrome reads commands on fd 3 and writes them on fd 4.
        args.insert(args.len() - 1, "--remote-debugging-pipe".to_string());
    } else {
        // Ephemeral port ONLY on 127.0.0.1, and only when the transport is the port
        // (`SCRAPELENS_CDP_TRANSPORT=port`). `expose_cdp` does not use it: the agent
        // gets the mode-0600 socket in front of the pipe. Without
        // `--remote-allow-origins`, a client that sends no Origin is accepted; a
        // web page that tries the WebSocket (Origin present) is refused by Chrome.
        args.insert(args.len() - 1, "--remote-debugging-port=0".to_string());
        args.insert(args.len() - 1, "--remote-debugging-address=127.0.0.1".to_string());
    }
    // Fail closed through a proxy: Chrome resolves nothing itself, so a name that would
    // leave by a direct route (a lookup, a connection) is refused instead. Loopback stays
    // local, and the proxy's own address is excluded so that Chrome can reach it.
    let proxy_rules = match (resolver_rules, proxy_arg) {
        (None, Some(server)) => Some(fail_closed_rules(server)),
        _ => None,
    };
    match (resolver_rules, config.network) {
        // Controlled capture: only the allowlist hosts resolve; no
        // certificate relaxation. Through a proxy, Chrome must still reach the local relay
        // (its address is a literal the rules would deny), so the loopback address is
        // excluded; loopback TARGETS then go through the proxy too (see below), where the
        // relay refuses anything the allowlist does not permit.
        (Some(rules), _) => {
            let rules = match proxy_arg {
                Some(_) => format!("{rules}, EXCLUDE 127.0.0.1"),
                None => rules.to_string(),
            };
            args.insert(args.len() - 1, format!("--host-resolver-rules={rules}"));
        }
        // Common App capture with a proxy: the fail-closed rules above.
        (None, mode) if proxy_rules.is_some() => {
            if mode == NetworkMode::LoopbackOnly {
                args.insert(args.len() - 1, "--allow-insecure-localhost".to_string());
            }
            if let Some(rules) = proxy_rules {
                args.insert(args.len() - 1, format!("--host-resolver-rules={rules}"));
            }
        }
        // Common App capture: normal network. No DNS rules.
        (None, NetworkMode::Open) => {}
        // Tests only: nothing beyond loopback resolves.
        (None, NetworkMode::LoopbackOnly) => {
            args.insert(args.len() - 1, "--allow-insecure-localhost".to_string());
            args.insert(
                args.len() - 1,
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
                    .to_string(),
            );
        }
    }
    if let Some(server) = proxy_arg {
        // The value never carries credentials: the relay's address, or the link without
        // them (direct route). WebRTC must not open UDP outside the proxy.
        args.push(format!("--proxy-server={server}"));
        args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string());
        // A controlled capture sends loopback targets through the proxy as well, so the
        // allowlist covers them; the App's common capture keeps Chrome's default bypass.
        if resolver_rules.is_some() || config.test_proxy_bypass_loopback {
            args.push("--proxy-bypass-list=<-loopback>".to_string());
        }
    }
    if config.headless {
        args.push("--headless=new".to_string());
    }
    if config.ignore_cert {
        args.push("--ignore-certificate-errors".to_string());
    }
    args
}

/// Writes `Local State` (secure DNS off) and `Default/Preferences` (WebRTC policy) into
/// the temporary profile. Files are created with `create_new`, so nothing follows a link.
pub(crate) fn write_proxy_profile_prefs(profile: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    let write_new = |path: &Path, body: &str| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(body.as_bytes())
    };
    write_new(
        &profile.join("Local State"),
        r#"{"dns_over_https":{"mode":"off"}}"#,
    )?;
    let default_dir = profile.join("Default");
    if !default_dir.exists() {
        std::fs::create_dir(&default_dir)?;
    }
    let prefs = default_dir.join("Preferences");
    if prefs.exists() {
        return Ok(());
    }
    write_new(
        &prefs,
        r#"{"webrtc":{"ip_handling_policy":"disable_non_proxied_udp","multiple_routes_enabled":false,"nonproxied_udp_enabled":false}}"#,
    )
}

/// The host-resolver rule of a proxied capture without an allowlist. `server` is the
/// `scheme://host:port` Chrome is given (the relay's address, or the link's own address).
pub(crate) fn fail_closed_rules(server: &str) -> String {
    let authority = server.split_once("://").map(|(_, rest)| rest).unwrap_or(server);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("").to_string()
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority).to_string()
    };
    let mut rules = String::from("MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost");
    if !host.is_empty() && host != "127.0.0.1" && host != "localhost" {
        rules.push_str(&format!(", EXCLUDE {host}"));
    }
    rules
}

pub(crate) fn spawn_chrome(
    config: &CaptureConfig,
    args: &[String],
    pipe: Option<&transport::PipeEnds>,
    hold_for_relay: bool,
) -> Result<Child, String> {
    // A SIGSTOP inside `pre_exec` never returns, so `Command::spawn` would wait forever.
    // The shell stops after spawn has returned; `exec` then keeps this pid for Chrome.
    let mut command = if hold_for_relay {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("kill -STOP $$; exec \"$0\" \"$@\"")
            .arg(&config.chrome);
        command
    } else {
        Command::new(&config.chrome)
    };
    command
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        // With pipe: fd 3 (read) and fd 4 (write) belong to the CDP; without pipe, none.
        let ends = pipe.map(|e| (e.child_read.as_raw_fd(), e.child_write.as_raw_fd()));
        // SAFETY: between fork and exec it only calls `dup2`, `fcntl` and `getdtablesize`,
        // all async-signal-safe and without allocating. The pipe's source fds are >= 10,
        // so they do not collide with 3 and 4; `dup2` clears FD_CLOEXEC on the targets.
        // Every other fd >= 3 (R9) gets FD_CLOEXEC and is closed on exec: nothing that the
        // launcher inherited (log, socket, secret) reaches Chrome. Marking instead of closing
        // preserves the internal pipe that std uses to report
        // an exec failure.
        unsafe {
            command.pre_exec(move || {
                let first_other = match ends {
                    Some((read_fd, write_fd)) => {
                        if libc::dup2(read_fd, 3) < 0 || libc::dup2(write_fd, 4) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        5
                    }
                    None => 3,
                };
                mark_fds_cloexec(first_other);
                Ok(())
            });
        }
    }
    command
        .spawn()
        .map_err(|error| {
            format!(
                "Could not open Chrome at {}: {error}. Select Chrome manually.",
                config.chrome.display()
            )
        })
}

/// Waits until `pid` is stopped, without reaping it. A later `Child::wait` still works.
pub(crate) fn wait_until_stopped(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: `status` is a writable int. WUNTRACED reports a stop and does not reap it.
        let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        if rc == pid as libc::pid_t && libc::WIFSTOPPED(status) {
            return true;
        }
        if rc < 0 || (rc == pid as libc::pid_t && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))) {
            return false;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Ceiling on the descriptor sweep in the child: covers any practical limit
/// (the macOS default `ulimit -n` is 256) without sweeping millions of numbers.
pub(crate) const MAX_FD_SWEEP: libc::c_int = 65_536;

/// Marks FD_CLOEXEC on every open descriptor `>= first` (async-signal-safe;
/// runs in the child between fork and exec). Descriptors above `MAX_FD_SWEEP`
/// are not swept: a gap documented in docs/16b §2.1.
pub(crate) fn mark_fds_cloexec(first: libc::c_int) {
    // Linux 5.11+: `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` marks ALL of them at once
    // (no sweep ceiling). Without the syscall (old kernel, seccomp) it falls back to the loop.
    #[cfg(target_os = "linux")]
    {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
        // SAFETY: direct syscall, async-signal-safe; it only changes descriptor flags.
        let rc = unsafe {
            libc::syscall(libc::SYS_close_range, first as libc::c_uint, libc::c_uint::MAX, CLOSE_RANGE_CLOEXEC)
        };
        if rc == 0 {
            return;
        }
    }
    // SAFETY: `getdtablesize` and `fcntl` only read or change descriptor flags.
    unsafe {
        let limit = libc::getdtablesize().clamp(first, MAX_FD_SWEEP);
        for fd in first..limit {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

pub(crate) fn wait_for_devtools(
    child: &mut Child,
    profile: &Path,
    timeout: Duration,
) -> Result<String, String> {
    let port_file = profile.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(status) = child.try_wait() {
            if status.is_some() {
                return Err(
                    "Chrome exited before opening debugging. Check whether another instance is using the profile, or select another Chrome.".to_string(),
                );
            }
        }
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                let path = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{path}")
                };
                return Ok(format!("ws://127.0.0.1:{port}{path}"));
            }
        }
        thread::sleep(Duration::from_millis(120));
    }
    Err(
        "Chrome did not expose debugging within 25 s (DevToolsActivePort missing). Nothing was captured."
            .to_string(),
    )
}

#[derive(Debug, Clone)]
pub(crate) enum ChromeExit {
    /// The process exited on its own after `Browser.close`.
    Graceful(#[allow(dead_code)] Option<i32>),
    /// Exceeded the deadline and was killed by this module (the NetLog may be truncated).
    Killed,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct ShutdownReport {
    pub(crate) browser_close: Result<(), String>,
    pub(crate) exit: ChromeExit,
    pub(crate) waited_ms: u64,
    /// The CDP transport closed for an abnormal reason (e.g. `frame_too_large`):
    /// the capture ended before the stop request, and the session is incomplete.
    pub(crate) transport_closed: Option<String>,
}

/// Safety net: only kills Chrome if `run_inner` exits without `disarm` (error/panic).
pub(crate) struct ChromeProcess(Option<Child>);

impl ChromeProcess {
    pub(crate) fn new(child: Child) -> Self {
        Self(Some(child))
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .expect("ChromeProcess already released after graceful shutdown")
    }

    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Orphans: Chrome and the temporary profile left behind by an app SIGKILL.
// ---------------------------------------------------------------------------

pub(crate) const MARKER_PREFIX: &str = "capture-";
pub(crate) const PROFILE_PREFIX: &str = "scrapelens-chrome-";

/// PRIVATE, per-user base for the temporary profile, the NetLog and the state root.
/// - macOS: `temp_dir()` (`$TMPDIR` is a per-user directory, 0700).
/// - Linux: `$TMPDIR` if the user set it; otherwise `$XDG_RUNTIME_DIR` (per user,
///   tmpfs, 0700), if it really exists and belongs to the user with mode 0700; otherwise
///   `/tmp` (shared: names there carry the uid and everything is checked after
///   creation, see [`default_state_root`] and `create_private_dir_new`).
pub fn private_base_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        pick_base_dir(
            std::env::var_os("TMPDIR"),
            std::env::var_os("XDG_RUNTIME_DIR"),
            std::env::temp_dir(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    std::env::temp_dir()
}

/// Pure choice (testable without touching the environment): a `TMPDIR` that is set and non-empty wins;
/// otherwise the valid `XDG_RUNTIME_DIR`; otherwise the `fallback` (`temp_dir()`).
#[cfg(target_os = "linux")]
pub(crate) fn pick_base_dir(
    tmpdir: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    fallback: PathBuf,
) -> PathBuf {
    if tmpdir.is_some_and(|v| !v.is_empty()) {
        return fallback;
    }
    xdg.and_then(|v| valid_runtime_dir(PathBuf::from(v))).unwrap_or(fallback)
}

/// `dir` if it is a real directory (not a symlink), absolute, owned by the current user, and with no
/// group/other access (the correct `XDG_RUNTIME_DIR` is 0700).
#[cfg(target_os = "linux")]
pub(crate) fn valid_runtime_dir(dir: PathBuf) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if !dir.is_absolute() {
        return None;
    }
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    (meta.is_dir() && meta.uid() == euid && meta.mode() & 0o077 == 0).then_some(dir)
}

/// Root of the capture markers' state (per user). The App calls
/// `cleanup_orphans(&default_state_root())`. On Linux, when the base is the shared `/tmp`,
/// the name carries the uid (`scrapelens-capture-state-<uid>`) so that two
/// users do not contend for the same directory; under `$XDG_RUNTIME_DIR` or on macOS the name
/// is `scrapelens-capture-state`.
pub fn default_state_root() -> PathBuf {
    state_root_in(&private_base_dir())
}

/// Name of the state root inside `base`. Linux: under a valid `XDG_RUNTIME_DIR`
/// (per user) it is `scrapelens-capture-state`; in any other base (for example
/// the shared `/tmp`) it carries the uid. macOS: always `scrapelens-capture-state`.
pub(crate) fn state_root_in(base: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let per_user = std::env::var_os("XDG_RUNTIME_DIR")
            .and_then(|v| valid_runtime_dir(PathBuf::from(v)))
            .is_some_and(|x| x == base);
        if !per_user {
            // SAFETY: `geteuid` has no preconditions.
            let uid = unsafe { libc::geteuid() };
            return base.join(format!("scrapelens-capture-state-{uid}"));
        }
    }
    base.join("scrapelens-capture-state")
}

/// Creates (if missing) the state root and checks, already open, that it is a directory of the
/// user, 0700 and not a link (this matters on `/tmp`, where another user may have
/// created the name first).
pub(crate) fn ensure_private_state_root(root: &Path) -> std::io::Result<()> {
    // A symlink in place of the root is refused BEFORE any chmod (the `set_mode` of the
    // core would follow the link and change the target's mode).
    if std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is a symbolic link; refused", root.display()),
        ));
    }
    store::ensure_private_dir(root).map_err(|e| std::io::Error::other(e.to_string()))?;
    verify_private_dir(root).map(|_| ())
}

pub(crate) fn port_from_ws_url(url: &str) -> Option<u16> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split('/').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// 0600 marker with what is needed to clean up an abandoned capture.
pub(crate) struct OrphanMarker {
    pub(crate) path: Option<PathBuf>,
    pub(crate) chrome_pid: u32,
    pub(crate) profile: PathBuf,
}

impl OrphanMarker {
    pub(crate) fn create(root: &Path, chrome_pid: u32, profile: &Path, port: Option<u16>) -> Self {
        let mut marker = Self {
            path: None,
            chrome_pid,
            profile: profile.to_path_buf(),
        };
        if ensure_private_state_root(root).is_ok() {
            let path = root.join(format!(
                "{MARKER_PREFIX}{}-{}.json",
                std::process::id(),
                unix_nanos()
            ));
            marker.path = Some(path);
            marker.write(port);
        }
        marker
    }

    pub(crate) fn write(&self, port: Option<u16>) {
        let Some(path) = &self.path else { return };
        let body = json!({
            "ownerPid": std::process::id(),
            "chromePid": self.chrome_pid,
            "profile": self.profile.display().to_string(),
            "port": port,
        });
        let _ = write_private(path, body.to_string().as_bytes());
    }

    pub(crate) fn set_port(&self, port: Option<u16>) {
        self.write(port);
    }
}

impl Drop for OrphanMarker {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Command line of the process, or `None` if it does not exist.
#[cfg(not(target_os = "linux"))]
pub(crate) fn process_command(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !text.is_empty()).then_some(text)
}

/// Linux: `/proc/<pid>/cmdline` (NUL-separated arguments), without depending on `ps`.
#[cfg(target_os = "linux")]
pub(crate) fn process_command(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let text = String::from_utf8_lossy(&raw).replace('\0', " ").trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn process_exists(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Linux: `kill(pid, 0)`; `EPERM` also means the process exists.
#[cfg(target_os = "linux")]
pub(crate) fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 only tests existence.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(crate) fn signal(pid: u32, name: &str) {
    let sig = match name {
        "-KILL" => libc::SIGKILL,
        _ => libc::SIGTERM,
    };
    // SAFETY: sends a signal to the marker's pid (already checked as ours by the caller).
    unsafe { libc::kill(pid as libc::pid_t, sig) };
}

/// Pids whose command line contains exactly `--user-data-dir=<profile>`
/// (the dedicated Chrome and its helpers).
#[cfg(not(target_os = "linux"))]
pub(crate) fn pids_using_profile(profile_flag: &str) -> Vec<u32> {
    let Ok(output) = Command::new("ps").args(["-ww", "-axo", "pid=,command="]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            let pid: u32 = pid.parse().ok()?;
            (command.contains(profile_flag) && pid != std::process::id()).then_some(pid)
        })
        .collect()
}

/// Linux: scans `/proc/<pid>/cmdline`.
#[cfg(target_os = "linux")]
pub(crate) fn pids_using_profile(profile_flag: &str) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let command = process_command(pid)?;
            (command.contains(profile_flag) && pid != std::process::id()).then_some(pid)
        })
        .collect()
}

/// Only deletes profiles that this module creates: inside the private base and with the
/// app's prefix. A tampered marker cannot point to another directory.
pub(crate) fn is_app_profile(profile: &Path) -> bool {
    profile.parent() == Some(private_base_dir().as_path())
        && profile
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(PROFILE_PREFIX))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrphanCleanup {
    /// Markers of abandoned captures that were removed.
    pub markers_removed: usize,
    /// Chrome processes shut down (only those still using the marker's profile).
    pub processes_killed: usize,
    /// Temporary profiles deleted.
    pub profiles_removed: usize,
    /// Rescue folders (sessions that could not be written) that expired and were
    /// deleted, along with their marker.
    pub rescues_removed: usize,
}

/// Cleans up abandoned captures left behind by an app that died without shutting Chrome down.
/// For each marker in `state_root` whose owner process no longer exists:
/// shuts down the marker's Chrome only if the PID's command line still
/// contains the dedicated profile (never a reused PID or the user's own Chrome),
/// deletes the app's temporary profile and the marker. A marker whose owner is
/// still alive (including this process) is not touched.
pub fn cleanup_orphans(state_root: &Path) -> OrphanCleanup {
    let mut report = OrphanCleanup::default();
    let Ok(entries) = std::fs::read_dir(state_root) else {
        return report;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(RESCUE_PREFIX) && n.ends_with(".json"))
        {
            if !path.is_symlink() && cleanup_rescue_marker(state_root, &path) {
                report.rescues_removed += 1;
            }
            continue;
        }
        let is_marker = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(MARKER_PREFIX) && n.ends_with(".json"));
        if !is_marker || path.is_symlink() {
            continue;
        }
        let Some(value) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        let (Some(owner), Some(chrome_pid), Some(profile)) = (
            value.get("ownerPid").and_then(Value::as_u64),
            value.get("chromePid").and_then(Value::as_u64),
            value.get("profile").and_then(Value::as_str),
        ) else {
            continue;
        };
        let (owner, chrome_pid, profile) = (owner as u32, chrome_pid as u32, PathBuf::from(profile));
        if process_exists(owner) {
            continue;
        }
        if !is_app_profile(&profile) {
            // Marker that is not ours: only the marker is removed, nothing else is touched.
            let _ = std::fs::remove_file(&path);
            report.markers_removed += 1;
            continue;
        }
        let profile_flag = format!("--user-data-dir={}", profile.display());
        let ours = |pid: u32| process_command(pid).is_some_and(|c| c.contains(&profile_flag));
        let mut targets: Vec<u32> = Vec::new();
        if ours(chrome_pid) {
            targets.push(chrome_pid);
        }
        // Helpers of the same Chrome (renderers etc.) only join if the main one was ours.
        if !targets.is_empty() {
            for pid in pids_using_profile(&profile_flag) {
                if !targets.contains(&pid) {
                    targets.push(pid);
                }
            }
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-TERM");
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && targets.iter().any(|p| ours(*p)) {
            thread::sleep(Duration::from_millis(100));
        }
        for pid in &targets {
            if ours(*pid) {
                signal(*pid, "-KILL");
            }
        }
        report.processes_killed += targets.len();
        if profile.exists() && std::fs::remove_dir_all(&profile).is_ok() {
            report.profiles_removed += 1;
        }
        let _ = std::fs::remove_file(&path);
        report.markers_removed += 1;
    }
    report
}

/// Deletes an expired rescue folder (`RESCUE_TTL_DAYS`) and its marker. The age
/// comes from the rescue directory ITSELF (mtime, which changes only when entries are
/// created or removed in it), never from the marker's content (A6-B7): a
/// forged marker does not make a recent rescue look expired. The marker only counts if the
/// file name is `<dir>.json` and `dir` is a direct child of `state_root`, with the
/// rescue prefix and is not a symlink; a tampered marker does not point to
/// anywhere else.
pub(crate) fn cleanup_rescue_marker(state_root: &Path, marker: &Path) -> bool {
    let Some(value) = std::fs::read(marker)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    else {
        return false;
    };
    if value.get("kind").and_then(Value::as_str) != Some("rescue") {
        return false;
    }
    let Some(name) = value.get("dir").and_then(Value::as_str) else {
        return false;
    };
    let name_ok = name.starts_with(RESCUE_PREFIX) && !name.contains('/') && !name.contains("..");
    let bound = marker.file_name().and_then(|n| n.to_str()) == Some(&format!("{name}.json"));
    if !name_ok || !bound {
        return false;
    }
    let dir = state_root.join(name);
    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        // Rescue already deleted: only the marker is left over, so remove only it.
        let _ = std::fs::remove_file(marker);
        return false;
    };
    if !meta.file_type().is_dir() {
        return false;
    }
    let age = meta
        .modified()
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or_default();
    if age < Duration::from_secs(RESCUE_TTL_DAYS * 24 * 3600) {
        return false;
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(marker);
    true
}

pub(crate) fn wait_or_kill(child: &mut Child, timeout: Duration) -> ChromeExit {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ChromeExit::Graceful(status.code()),
            Ok(None) => {}
            Err(_) => return ChromeExit::Unknown,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return ChromeExit::Killed;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

