//! persist module for the capture crate; moved from lib.rs by T29.

use super::*;

pub(crate) fn mark_incomplete(
    document: &mut scrapelens_core::model::SessionV1,
    netlog: &NetlogStatus,
    shutdown: &ShutdownReport,
) {
    let detail = json!({
        "browserClose": shutdown.browser_close.clone().err(),
        "chromeExit": format!("{:?}", shutdown.exit),
        "waitedMs": shutdown.waited_ms,
        "netlog": format!("{netlog:?}"),
        "transportClosed": shutdown.transport_closed,
    });
    let killed = matches!(shutdown.exit, ChromeExit::Killed);
    let mut entries: Vec<(&str, String)> = Vec::new();
    // A3-B2: the CDP closed on its own (message above the ceiling). Chrome exits
    // afterwards gracefully and the NetLog looks complete, but the capture stopped
    // before the stop request: the explicit reason comes first.
    if let Some(reason) = &shutdown.transport_closed {
        entries.push((
            "capture.cdp_transport_closed",
            format!(
                "cdp_transport_closed: {reason}: the CDP channel closed before the stop request; events after that point were not captured."
            ),
        ));
    }
    match netlog {
        NetlogStatus::Complete if !killed => {}
        NetlogStatus::Complete => entries.push((
            "capture.chrome_killed",
            "Chrome did not exit within the deadline and was force-killed; the NetLog may not reflect the end of the capture.".to_string(),
        )),
        NetlogStatus::Repaired { original_bytes, kept_bytes } => entries.push((
            "capture.netlog_incomplete",
            format!("The Chrome NetLog was truncated ({original_bytes} bytes); the session uses only the complete events ({kept_bytes} bytes). The original is in netlog.original.json."),
        )),
        NetlogStatus::Unusable { reason } => entries.push((
            "capture.netlog_unusable",
            format!("{reason}: the session was imported with CDP and bodies only, without NetLog evidence. The original (if it exists) is in netlog.original.json."),
        )),
    }
    for (code, message) in entries {
        document
            .session
            .completeness
            .add_reason(format!("{code}: {message}"));
        document
            .warnings
            .push(scrapelens_core::model::Warning::new(code, message).with_detail(detail.clone()));
    }
}

/// Names that the session writes (files) or creates (`attachments`) in the session
/// directory, which a planted symlink could occupy.
pub(crate) const SESSION_DIR_LINK_NAMES: [&str; 4] =
    ["cdp-events.jsonl", "netlog.json", "session.json", "attachments"];

/// Writes the session (A3-B3, A4-B3, A6-B5) WITHOUT resolving the session directory's path
/// at any point:
/// 1. warns (in the document) which names were symlinks, through the descriptor;
/// 2. the core writes the bundle into a new 0700 staging directory inside
///    `stage_parent` (the temporary profile, ours and out of the attacker's reach);
/// 3. each item is moved into the session directory with `renameat` relative to the
///    descriptor (`session.json` last), replacing the name, including a
///    symlink, without writing to its target. Between different filesystems, it copies.
///
/// Re-planting links in a loop (A4-B4) no longer matters: `renameat` is atomic.
/// Returns the names that were symlinks and were replaced.
pub(crate) fn write_session_fd(
    bundle: &mut scrapelens_core::SessionBundle,
    session: &std::fs::File,
    stage_parent: &Path,
) -> Result<Vec<String>, String> {
    let fail = |what: &str, error: &dyn std::fmt::Display| {
        format!("Could not write the session: {what}: {error}")
    };
    for name in SESSION_DIR_LINK_NAMES {
        if fdio::kind_of(session, name).ok().flatten() == Some(fdio::EntryKind::Symlink) {
            bundle.session.add_warning(scrapelens_core::model::Warning::new(
                "capture.planted_symlink_removed",
                format!("{name} was a symbolic link in the session directory; the link was replaced and the target was not touched."),
            ));
        }
    }
    let stage = stage_parent.join(format!("stage-{}", unix_nanos()));
    create_private_dir_new(&stage).map_err(|e| fail("staging directory", &e))?;
    let result = (|| -> Result<Vec<String>, String> {
        store::write_session_dir(bundle, &stage).map_err(|e| fail("preparo", &e))?;
        let (stage_handle, _) =
            verify_private_dir_handle(&stage).map_err(|e| fail("staging directory", &e))?;
        let mut replaced: Vec<String> = Vec::new();
        // `session.json` last: it never points to files that do not exist yet.
        let mut order: Vec<String> = fdio::list(&stage_handle)
            .map_err(|e| fail("preparo", &e))?
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| name != "session.json")
            .collect();
        order.sort();
        order.push("session.json".to_string());
        for name in order {
            replaced.extend(
                fdio::move_entry(&stage_handle, session, &name).map_err(|e| fail(&name, &e))?,
            );
        }
        Ok(replaced)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result
}

/// Reads everything from the descriptor (from position 0). For the bodies: re-reads through the descriptor, not
/// through the path.
pub(crate) fn read_all_from(file: &mut std::fs::File) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Error message when the session directory stopped being trustworthy (A4-B5).
pub(crate) fn session_dir_changed(why: String) -> String {
    format!(
        "The session directory was swapped or stopped being ours during the capture ({why}); nothing was written to it and nothing outside it was deleted."
    )
}

/// Message when the directory was swapped DURING the write (A7): the session was
/// written in full to the ORIGINAL directory (the descriptor opened at the start), which the
/// system now finds at another path (`F_GETPATH`); nothing was written to the directory
/// that took its place. It does not repeat "nothing was written to it", which would be false.
pub(crate) fn session_dir_changed_after_write(why: String, original: &std::fs::File) -> String {
    let moved = descriptor_path(original)
        .map(|p| format!("now at {}", p.display()))
        .unwrap_or_else(|| "that we could not locate".to_string());
    format!(
        "The session directory was swapped during the write ({why}). The session was written in full to the ORIGINAL directory, {moved}; nothing was written to the directory that took its place, and nothing outside the original directory was deleted."
    )
}

/// CURRENT path of the directory that the descriptor represents, even if the name has
/// been moved (macOS: `F_GETPATH`; Linux: `/proc/self/fd/N`).
#[cfg(target_os = "macos")]
pub(crate) fn descriptor_path(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes at most PATH_MAX bytes into the buffer.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
    if result < 0 {
        return None;
    }
    let len = buffer.iter().position(|&b| b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..len])))
}

/// Linux: `readlink /proc/self/fd/N` (the directory's current path; the kernel appends
/// ` (deleted)` if it was deleted).
#[cfg(target_os = "linux")]
pub(crate) fn descriptor_path(file: &std::fs::File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn descriptor_path(_file: &std::fs::File) -> Option<PathBuf> {
    None
}

pub(crate) const RESCUE_PREFIX: &str = "rescue-";
/// Age from which `cleanup_orphans` deletes a rescue folder.
pub(crate) const RESCUE_TTL_DAYS: u64 = 7;

/// Rescue (A5-B2, A5-B3): when the session could not be written, it keeps ONLY the
/// capture files (CDP events, bodies and NetLog) in a new 0700 folder inside
/// `state_root`, with a marker so that `cleanup_orphans` deletes it later, after
/// `RESCUE_TTL_DAYS`. The rest of the Chrome profile (Cookies, Login Data, History)
/// is never kept. Returns the folder.
pub(crate) fn rescue_capture_files(
    state_root: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> Result<PathBuf, String> {
    #[cfg(test)]
    if FORCE_PRIMARY_RESCUE_FAILURE.with(std::cell::Cell::get) {
        return Err("forced failure (test)".to_string());
    }
    ensure_private_state_root(state_root).map_err(|e| format!("state folder: {e}"))?;
    let name = format!("{RESCUE_PREFIX}{}-{}", std::process::id(), unix_nanos());
    let dir = state_root.join(&name);
    create_private_dir_new(&dir).map_err(|e| format!("rescue folder: {e}"))?;
    let result = fill_rescue_dir(&dir, cdp, netlog, bodies, reason)
        .and_then(|()| write_rescue_marker(state_root, &name));
    match result {
        Ok(()) => Ok(dir),
        Err(error) => {
            // A half-done rescue is no good: the caller tries plan B.
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_file(state_root.join(format!("{name}.json")));
            Err(error.to_string())
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test: makes the normal rescue fail on THIS thread (plan B kicks in).
    pub(crate) static FORCE_PRIMARY_RESCUE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Writes the capture files (and the reason) into a rescue folder.
pub(crate) fn fill_rescue_dir(
    dir: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    if !cdp.is_empty() {
        write_private(&dir.join("cdp-events.jsonl"), cdp)?;
    }
    if let Some(raw) = netlog {
        write_private(&dir.join("netlog.json"), raw)?;
    }
    let mut body_bytes = Vec::new();
    if bodies.seek(SeekFrom::Start(0)).is_ok()
        && bodies.read_to_end(&mut body_bytes).is_ok()
        && !body_bytes.is_empty()
    {
        write_private(&dir.join("cdp-bodies.jsonl"), &body_bytes)?;
    }
    write_private(&dir.join("motivo.txt"), reason.as_bytes())
}

/// Marker `<name>.json` next to the rescue folder. Its age does NOT come from it.
pub(crate) fn write_rescue_marker(state_root: &Path, name: &str) -> std::io::Result<()> {
    let marker = json!({
        "kind": "rescue",
        "ownerPid": std::process::id(),
        "dir": name,
    });
    write_private(
        &state_root.join(format!("{name}.json")),
        marker.to_string().as_bytes(),
    )
}

/// Plan B of the rescue (A6-B6), used when the normal rescue folder could not be
/// created (e.g. ENOSPC): the temporary profile ITSELF becomes the rescue. It deletes everything
/// that is not part of the capture (Cookies, Login Data, History..., which also frees
/// space), writes the CDP events, the bodies and the reason into it, and moves it to
/// `state_root` with a marker, under the same 7-day deadline. If it cannot
/// move or mark it, it stays where it is, already cleaned and holding the events, and the
/// return says there is no automatic deadline.
pub(crate) struct AdoptedProfile {
    dir: PathBuf,
    has_ttl: bool,
}

pub(crate) fn adopt_profile_as_rescue(
    state_root: &Path,
    profile: &Path,
    cdp: &[u8],
    netlog: Option<&[u8]>,
    bodies: &mut std::fs::File,
    reason: &str,
) -> Result<AdoptedProfile, String> {
    // 1. Only the capture files survive in the profile.
    let keep_netlog = netlog.is_none() && profile.join("netlog.json").is_file();
    for entry in std::fs::read_dir(profile).map_err(|e| format!("profile: {e}"))?.flatten() {
        let path = entry.path();
        if keep_netlog && entry.file_name() == "netlog.json" {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let _ = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
    // 2. The events, the bodies and the reason.
    fill_rescue_dir(profile, cdp, netlog, bodies, reason).map_err(|e| format!("profile: {e}"))?;
    // 3. Move to the state root and mark it (same deadline).
    let name = format!("{RESCUE_PREFIX}{}-{}", std::process::id(), unix_nanos());
    let target = state_root.join(&name);
    let moved = ensure_private_state_root(state_root)
        .ok()
        .and_then(|()| std::fs::rename(profile, &target).ok());
    if moved.is_some() && write_rescue_marker(state_root, &name).is_ok() {
        return Ok(AdoptedProfile { dir: target, has_ttl: true });
    }
    Ok(AdoptedProfile {
        dir: if moved.is_some() { target } else { profile.to_path_buf() },
        has_ttl: false,
    })
}

/// Rescues the capture files after a write failure and returns the
/// final error for `stop_capture`: normal rescue folder; if that fails, plan B
/// (the profile becomes the rescue); if everything fails, the profile is kept.
pub(crate) fn rescue_or_adopt(
    message: &str,
    state_root: &Path,
    profile: &Path,
    profile_guard: &mut ProfileCleanup,
    cdp_bytes: &[u8],
    netlog_raw: Option<&[u8]>,
    bodies: &mut std::fs::File,
) -> String {
    match rescue_capture_files(state_root, cdp_bytes, netlog_raw, bodies, message) {
        Ok(dir) => format!(
            "{message} The capture files (CDP events, bodies and NetLog) were kept in the rescue folder {} (0700; automatically deleted after {} days).",
            dir.display(),
            RESCUE_TTL_DAYS
        ),
        Err(why) => {
            // Plan B: the profile becomes the rescue (cleaned, with the events and, if
            // possible, with a marker and deadline). Never lose the data.
            profile_guard.keep();
            match adopt_profile_as_rescue(state_root, profile, cdp_bytes, netlog_raw, bodies, message) {
                Ok(adopted) if adopted.has_ttl => format!(
                    "{message} The normal rescue failed ({why}); the capture files (CDP events, bodies and NetLog) were kept in {} (0700; automatically deleted after {} days).",
                    adopted.dir.display(),
                    RESCUE_TTL_DAYS
                ),
                Ok(adopted) => format!(
                    "{message} The normal rescue failed ({why}); the capture files (CDP events, bodies and NetLog) were kept in {}, WITHOUT an automatic deadline (it could not be marked): delete them when you recover.",
                    adopted.dir.display()
                ),
                Err(second) => format!(
                    "{message} The rescue failed ({why}) and so did plan B ({second}); the temporary profile {} was kept and may be incomplete (it contains Chrome data; delete it when you recover).",
                    profile.display()
                ),
            }
        }
    }
}

/// Removes the `.tmp-*` files that `write_atomic` (core) and `write_private` leave in the
/// session directory when the `rename` fails. It works through the directory's DESCRIPTOR (opened
/// at the start): it applies to the original directory even if the name was swapped or
/// moved, and never follows a path. Only files with the exact name of those
/// we write (`.<file>.tmp-…`).
pub(crate) fn remove_stale_tmp(dir: &std::fs::File) {
    use std::ffi::{CStr, CString};
    use std::os::fd::AsRawFd;
    const NAMES: [&str; 5] = [
        "cdp-events.jsonl",
        "netlog.json",
        "netlog.original.json",
        "session.json",
        "cdp-bodies.jsonl",
    ];
    // SAFETY: `dup` of the open descriptor; `fdopendir` takes over the copy and `closedir`
    // closes it; `readdir` returns valid entries until NULL; `unlinkat` only removes
    // the name (it never follows a symlink: without AT_REMOVEDIR it removes the link itself).
    unsafe {
        let copy = libc::dup(dir.as_raw_fd());
        if copy < 0 {
            return;
        }
        let stream = libc::fdopendir(copy);
        if stream.is_null() {
            libc::close(copy);
            return;
        }
        libc::rewinddir(stream);
        let mut found: Vec<CString> = Vec::new();
        loop {
            let entry = libc::readdir(stream);
            if entry.is_null() {
                break;
            }
            let name = CStr::from_ptr((*entry).d_name.as_ptr());
            let text = name.to_string_lossy();
            let regular = (*entry).d_type == libc::DT_REG;
            if regular && NAMES.iter().any(|n| text.starts_with(&format!(".{n}.tmp-"))) {
                found.push(name.to_owned());
            }
        }
        libc::closedir(stream);
        for name in found {
            libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
        }
    }
}

/// Atomic, symlink-safe write: writes into a new file with a unique name
/// (`create_new` + `O_NOFOLLOW`, 0600) in the same directory, and swaps the destination with
/// `rename`, which replaces the symlink itself (it never writes to its target).
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp = path.with_file_name(format!(".{name}.tmp-{}-{}", std::process::id(), unix_nanos()));
    let result = (|| {
        let mut file = open_new_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Identity of a directory (device + inode) read from the open descriptor.
/// Used by `stop` to recognize that the session directory is the SAME one as at the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirIdentity {
    dev: u64,
    ino: u64,
}

/// Rechecks the session directory on `stop` (A4-B5): opened without following links, ours,
/// 0700 and with the identity (dev+inode) from the start. Swapping the directory for a symlink,
/// or for another directory, makes stop fail without writing anything to it.
pub(crate) fn recheck_session_dir(dir: &Path, expected: DirIdentity) -> Result<(), String> {
    match verify_private_dir(dir) {
        Ok(found) if found == expected => Ok(()),
        Ok(_) => Err("it is a different directory from the one at the start of the capture".to_string()),
        Err(error) => {
            let is_link = std::fs::symlink_metadata(dir)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            Err(if is_link {
                "now a symbolic link".to_string()
            } else {
                error.to_string()
            })
        }
    }
}

/// Deletes the temporary profile on exit, unless `keep()` was called
/// (the session was left there because the destination directory was not trustworthy).
pub(crate) struct ProfileCleanup {
    pub(crate) path: PathBuf,
    pub(crate) keep: bool,
}

impl ProfileCleanup {
    pub(crate) fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Creates a NEW 0700 directory (fails if the name exists, including as a
/// symlink) and checks, while open, that it is ours, not a link, 0700.
pub(crate) fn create_private_dir_new(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(false).mode(0o700).create(path)?;
        verify_private_dir(path).map(|_| ())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

/// Opens the directory without following the final link, and checks through the open descriptor:
/// it is a directory, it belongs to our user, and the mode is exactly 0700.
#[cfg(unix)]
pub(crate) fn verify_private_dir(path: &Path) -> std::io::Result<DirIdentity> {
    verify_private_dir_handle(path).map(|(_, identity)| identity)
}

/// Like `verify_private_dir`, but also returns the open descriptor of the directory:
/// it keeps pointing to the SAME directory even if the name is swapped, and
/// is used to clean up the `.tmp-*` that the write left in it.
#[cfg(unix)]
pub(crate) fn verify_private_dir_handle(path: &Path) -> std::io::Result<(std::fs::File, DirIdentity)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let meta = dir.metadata()?;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o777 != 0o700 {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is not a 0700 directory of ours (mode {:o}, owner {})",
                path.display(),
                meta.mode() & 0o7777,
                meta.uid()
            ),
        ));
    }
    Ok((
        dir,
        DirIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        },
    ))
}

/// Reads a file without following symlinks: it only accepts a regular file of our
/// user (checked through the open descriptor). `None` if it is missing or refused.
pub(crate) fn read_private_regular(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return None;
        }
    }
    if !meta.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

pub(crate) fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Creates a NEW 0600 file without following symlinks: `create_new` (O_EXCL) and
/// `O_NOFOLLOW`. Fails if the name already exists (including as a symlink).
pub(crate) fn open_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    // `read` too: the rescue re-reads the bodies through its own descriptor.
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(test)]
/// Opens the file for writing as NEW, without following symlinks. If the name already
/// exists (old file or planted symlink), it REMOVES the name (the link, never the
/// target) and creates it again; a race in which someone re-plants the name makes the
/// `create_new` fail instead of writing outside.
pub(crate) fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    match open_new_private(path) {
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            open_new_private(path)
        }
        other => other,
    }
}

