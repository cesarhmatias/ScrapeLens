use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::model::SessionBundle;

pub const SESSION_FILE: &str = "session.json";
pub const CDP_EVENTS_FILE: &str = "cdp-events.jsonl";
pub const NETLOG_FILE: &str = "netlog.json";
pub const ATTACHMENTS_DIR: &str = "attachments";

/// Small sessions keep an fsync per attachment (durability); large captures
/// use a single directory fsync, because the per-file cost dominates.
const ATTACHMENT_SYNC_LIMIT: usize = 256;

/// Accepted attachment name: relative, without `..`, without a directory
/// separator and without a null byte. Blocks traversal before any read/write.
pub fn validate_attachment_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    let invalid = name.is_empty()
        || name.len() > 255
        || name.contains('\0')
        || name.contains('\\')
        || path.is_absolute()
        || path.components().count() != 1
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)));

    if invalid {
        return Err(CoreError::InvalidAttachmentPath {
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| CoreError::io(path, error))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// A symlink may be traversed only as part of the system layout: the link and
/// its containing directory belong to root, and the directory is not writable
/// by group or other. This covers macOS `/tmp`, `/var` and `/etc` and Linux
/// layouts such as `/home -> var/home` without a fixed name list. A dotfile
/// symlink in the user's home is owned by the user (or lives in a user-owned
/// parent) and is refused. Symlink permissions are not meaningful on Linux, so
/// the writability rule is applied to the containing directory.
#[cfg(unix)]
fn trusted_system_link(link_uid: u32, parent_uid: u32, parent_mode: u32) -> bool {
    link_uid == 0 && parent_uid == 0 && parent_mode & 0o022 == 0
}

#[cfg(unix)]
pub fn is_trusted_symlink_ancestor(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = path.parent() else {
        return false;
    };
    let (Ok(link), Ok(parent_meta)) = (fs::symlink_metadata(path), fs::metadata(parent)) else {
        return false;
    };
    trusted_system_link(link.uid(), parent_meta.uid(), parent_meta.mode())
}

#[cfg(not(unix))]
pub fn is_trusted_symlink_ancestor(_path: &Path) -> bool {
    false
}

/// First ancestor of `path` (including `path`) that is a symlink and is not a
/// trusted system link. `None` means the chain is safe to traverse.
pub fn first_symlink_ancestor(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            fs::symlink_metadata(ancestor)
                .map(|meta| meta.file_type().is_symlink() && !is_trusted_symlink_ancestor(ancestor))
                .unwrap_or(false)
        })
        .map(Path::to_path_buf)
}

/// Creates (if needed) the session directory with permission 0700.
///
/// The whole chain is checked component by component before a component is
/// created: a symlink ancestor not owned by root (except a trusted system
/// link), `..`, a file or a foreign-owned destination is refused before any
/// chmod or write. Missing components are created with mode 0700 from the
/// start, one at a time, and each one is inspected again right after creation.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) => {
                    return Err(CoreError::LimitExceeded {
                        message: format!("{} has an unsupported prefix; refused", path.display()),
                    });
                }
                Component::RootDir => {
                    current.push(Path::new("/"));
                    continue;
                }
                Component::CurDir => continue,
                Component::ParentDir => {
                    return Err(CoreError::LimitExceeded {
                        message: format!("{} contains '..'; refused", path.display()),
                    });
                }
                Component::Normal(part) => current.push(part),
            }
            match fs::symlink_metadata(&current) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        if is_trusted_symlink_ancestor(&current) {
                            continue;
                        }
                        return Err(CoreError::LimitExceeded {
                            message: format!(
                                "{} is a symbolic link; refused (ancestor of the destination); indicate a real folder for the session",
                                current.display()
                            ),
                        });
                    }
                    if !meta.is_dir() {
                        return Err(CoreError::LimitExceeded {
                            message: format!(
                                "{} exists and is not a directory; refused",
                                current.display()
                            ),
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Another thread may create the same component between the
                    // lstat and create. On EEXIST, inspect the component again
                    // with the same rules; a symlink planted in the window is
                    // still refused, and a directory created by the peer is
                    // accepted only after that re-check.
                    let mut ready = false;
                    for _ in 0..8 {
                        if component_ready(&current)? {
                            ready = true;
                            break;
                        }
                        match fs::DirBuilder::new()
                            .recursive(false)
                            .mode(0o700)
                            .create(&current)
                        {
                            Ok(()) => continue,
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                                continue;
                            }
                            Err(error) => return Err(CoreError::io(&current, error)),
                        }
                    }
                    if !ready || !component_ready(&current)? {
                        return Err(CoreError::LimitExceeded {
                            message: format!(
                                "{} changed repeatedly while it was being created; refused",
                                current.display()
                            ),
                        });
                    }
                }
                Err(error) => return Err(CoreError::io(&current, error)),
            }
        }
        set_private_mode(path)?;
    }
    #[cfg(not(unix))]
    {
        if !path.exists() {
            fs::create_dir_all(path).map_err(|error| CoreError::io(path, error))?;
        }
        set_mode(path, 0o700)?;
    }
    Ok(())
}

/// Same rules as a component of `ensure_private_dir`: a missing component is
/// false, an accepted symlink or a real directory is true.
#[cfg(unix)]
fn component_ready(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if is_trusted_symlink_ancestor(path) {
                Ok(true)
            } else {
                Err(CoreError::LimitExceeded {
                    message: format!(
                        "{} is a symbolic link; refused (ancestor of the destination); indicate a real folder for the session",
                        path.display()
                    ),
                })
            }
        }
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(CoreError::LimitExceeded {
            message: format!("{} exists and is not a directory; refused", path.display()),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CoreError::io(path, error)),
    }
}

/// Opens the directory and changes its mode through the opened file descriptor.
/// The path and the opened inode are compared before the chmod, so a path
/// swapped to a symlink after the check cannot redirect the chmod.
#[cfg(unix)]
fn set_private_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let file = File::open(path).map_err(|error| CoreError::io(path, error))?;
    let meta = fs::symlink_metadata(path).map_err(|error| CoreError::io(path, error))?;
    if meta.file_type().is_symlink() {
        return Err(CoreError::LimitExceeded {
            message: format!("{} is a symbolic link; refused", path.display()),
        });
    }
    let opened = file
        .metadata()
        .map_err(|error| CoreError::io(path, error))?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "{} changed while it was being opened; refused",
                path.display()
            ),
        });
    }
    check_private_dir(path, &meta)?;
    file.set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|error| CoreError::io(path, error))?;
    let after = fs::symlink_metadata(path).map_err(|error| CoreError::io(path, error))?;
    check_private_dir(path, &after)
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn check_private_dir(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if meta.file_type().is_symlink() {
        return Err(CoreError::LimitExceeded {
            message: format!("{} is a symbolic link; refused", path.display()),
        });
    }
    if !meta.is_dir() {
        return Err(CoreError::LimitExceeded {
            message: format!("{} exists and is not a directory; refused", path.display()),
        });
    }
    check_private_owner(path, meta.uid(), effective_uid())
}

#[cfg(unix)]
fn check_private_owner(path: &Path, owner: u32, expected: u32) -> Result<()> {
    if owner == expected {
        return Ok(());
    }
    Err(CoreError::LimitExceeded {
        message: format!(
            "{} is owned by uid {owner}, not {expected}; refused",
            path.display()
        ),
    })
}

/// Refuses a symlink (and anything that is not a regular file) at the destination.
fn refuse_non_regular_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::LimitExceeded {
            message: format!("{} is a symbolic link; refused", path.display()),
        }),
        Ok(meta) if !meta.is_file() => Err(CoreError::LimitExceeded {
            message: format!(
                "{} exists and is not a regular file; refused",
                path.display()
            ),
        }),
        _ => Ok(()),
    }
}

fn write_atomic(path: &Path, bytes: &[u8], sync_data: bool) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::InvalidAttachmentPath {
            name: path.to_string_lossy().to_string(),
        })?;
    // The destination must never be a symlink (the write would leave the directory).
    refuse_non_regular_destination(path)?;
    // Temporary with an unpredictable name, created with O_EXCL (`create_new`): if the
    // name exists, even as a symlink, the open fails instead of following the link.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|error| CoreError::io(&tmp, error))?;
    let written = file
        .write_all(bytes)
        .map_err(|error| CoreError::io(&tmp, error))
        .and_then(|()| {
            if sync_data {
                file.sync_all().map_err(|error| CoreError::io(&tmp, error))
            } else {
                file.flush().map_err(|error| CoreError::io(&tmp, error))
            }
        });
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }

    set_mode(&tmp, 0o600)?;
    // Check again right before the rename: the destination may have become a symlink.
    if let Err(error) = refuse_non_regular_destination(path) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    fs::rename(&tmp, path).map_err(|error| {
        let _ = fs::remove_file(&tmp);
        CoreError::io(path, error)
    })?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    let dir = File::open(path).map_err(|error| CoreError::io(path, error))?;
    dir.sync_all().map_err(|error| CoreError::io(path, error))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// Above this size (indented JSON) `session.json` is written compact (docs/18 P6):
/// ~−43 % in the file and in memory for whoever reads it whole; below it, it stays readable.
pub const COMPACT_SESSION_BYTES: usize = 50 * 1024 * 1024;

/// Byte counter that stores nothing: measures the indented size without allocating it.
struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bytes of `session.json`: indented if they fit in `threshold`, compact if not. The
/// measure is taken without building the indented text (which, for huge sessions, costs ~1.7x the compact one).
fn session_json_bytes(session: &crate::model::SessionV1, threshold: usize) -> Result<Vec<u8>> {
    let mut counter = CountingWriter(0);
    serde_json::to_writer_pretty(&mut counter, session)
        .map_err(|error| CoreError::json("session.json", error))?;
    if counter.0 > threshold {
        serde_json::to_vec(session).map_err(|error| CoreError::json("session.json", error))
    } else {
        serde_json::to_vec_pretty(session).map_err(|error| CoreError::json("session.json", error))
    }
}

/// Writes a complete session in the v1 layout with restricted permissions:
/// directory 0700, `session.json`/attachments 0600, atomic write per file.
///
/// Attachments do not get an individual `fsync`: each file is closed and renamed
/// atomically, and the directory is synchronized once at the end of the batch. In
/// captures with tens of thousands of small bodies, one `fsync` per attachment
/// dominated the import time (128 s for 20 thousand attachments in the acceptance
/// run); `session.json` is still synchronized. The batch preserves the order
/// "artifacts/attachments before the document" so as not to leave a broken reference.
pub fn write_session_dir(bundle: &SessionBundle, dir: &Path) -> Result<()> {
    ensure_private_dir(dir)?;
    // From here on everything is written under the canonicalized directory: no
    // component of the path may be swapped for a symlink in the middle of the write.
    let dir = &dir
        .canonicalize()
        .map_err(|error| CoreError::io(dir, error))?;
    let attachments_dir = dir.join(ATTACHMENTS_DIR);
    // `attachments/` is created by us inside the session: a symlink there is refused
    // before any mkdir/chmod.
    if let Ok(meta) = fs::symlink_metadata(&attachments_dir) {
        if meta.file_type().is_symlink() {
            return Err(CoreError::LimitExceeded {
                message: format!("{} is a symbolic link; refused", attachments_dir.display()),
            });
        }
    }
    ensure_private_dir(&attachments_dir)?;
    let canonical_attachments = attachments_dir
        .canonicalize()
        .map_err(|error| CoreError::io(&attachments_dir, error))?;
    if canonical_attachments.parent() != Some(dir.as_path()) {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "{} resolves outside the session; refused",
                attachments_dir.display()
            ),
        });
    }

    // Artifacts/attachments first; session.json last, so that a document never
    // points to files that do not exist yet.
    if let Some(bytes) = &bundle.cdp_events_jsonl {
        write_atomic(&dir.join(CDP_EVENTS_FILE), bytes, true)?;
    }
    if let Some(bytes) = &bundle.netlog_json {
        write_atomic(&dir.join(NETLOG_FILE), bytes, true)?;
    }

    // Batch: in small sessions each attachment is durable; in large captures the
    // fsync is a single one per directory at the end, not one per file.
    let sync_each = bundle.attachments.len() <= ATTACHMENT_SYNC_LIMIT;
    for (name, bytes) in &bundle.attachments {
        validate_attachment_name(name)?;
        write_atomic(&attachments_dir.join(name), bytes, sync_each)?;
    }
    if !bundle.attachments.is_empty() {
        sync_dir(&attachments_dir)?;
    }

    // A proxied capture gets its remote endpoints and notes made explicit before it is
    // written; direct captures are written as they are.
    let json = if bundle
        .session
        .session
        .capture
        .as_ref()
        .and_then(|capture| capture.proxy.as_ref())
        .is_some()
    {
        let mut session = bundle.session.clone();
        crate::model::apply_proxy_facts(&mut session);
        session_json_bytes(&session, COMPACT_SESSION_BYTES)?
    } else {
        session_json_bytes(&bundle.session, COMPACT_SESSION_BYTES)?
    };
    write_atomic(&dir.join(SESSION_FILE), &json, true)?;
    sync_dir(dir)?;
    Ok(())
}

/// Opens an attachment for reading, refusing symlinks (in the folder and in the
/// file) and anything that is not a regular file; checks that the opened file is
/// the same one that was inspected (TOCTOU). Returns the file and its size.
pub fn open_regular_attachment(dir: &Path, name: &str) -> Result<(File, u64)> {
    validate_attachment_name(name)?;
    let refused = |message: String| CoreError::LimitExceeded { message };
    let root = dir.join(ATTACHMENTS_DIR);
    let root_meta = fs::symlink_metadata(&root).map_err(|error| CoreError::io(&root, error))?;
    if root_meta.file_type().is_symlink() {
        return Err(refused(
            "the attachments folder is a symbolic link; refused".into(),
        ));
    }
    let target = root.join(name);
    let before = fs::symlink_metadata(&target).map_err(|error| CoreError::io(&target, error))?;
    if before.file_type().is_symlink() {
        return Err(refused(format!(
            "attachment {name} is a symbolic link; refused"
        )));
    }
    let file = File::open(&target).map_err(|error| CoreError::io(&target, error))?;
    let opened = file
        .metadata()
        .map_err(|error| CoreError::io(&target, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != before.ino() || opened.dev() != before.dev() {
            return Err(refused(format!(
                "attachment {name} changed while being opened; refused"
            )));
        }
    }
    if !opened.is_file() {
        return Err(refused(format!("attachment {name} is not a regular file")));
    }
    Ok((file, opened.len()))
}

/// Reads at most `limit` bytes of an attachment (see [`open_regular_attachment`]).
/// The second value is `true` when the file is larger than the limit.
pub fn read_attachment_limited(dir: &Path, name: &str, limit: u64) -> Result<(Vec<u8>, bool)> {
    use std::io::Read;
    let (file, size) = open_regular_attachment(dir, name)?;
    let mut bytes = Vec::with_capacity(size.min(limit) as usize);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| CoreError::io(dir.join(ATTACHMENTS_DIR).join(name), error))?;
    Ok((bytes, size > limit))
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| CoreError::io(path, error))
}

pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let bytes = read_file(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CoreError::json(path.display().to_string(), error))
}

/// Permission check to warn (not fix) about imported sessions that are
/// readable by group/others.
#[cfg(unix)]
pub fn is_private(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    Ok(mode & 0o077 == 0)
}

#[cfg(not(unix))]
pub fn is_private(_path: &Path) -> std::io::Result<bool> {
    Ok(true)
}

/// Path of an attachment inside a session, validated against traversal.
pub fn attachment_path(dir: &Path, name: &str) -> Result<PathBuf> {
    validate_attachment_name(name)?;
    Ok(dir.join(ATTACHMENTS_DIR).join(name))
}

/// Closes the file after the flush and ensures the rename leaves no temporary behind.
pub fn cleanup_temp_files(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|error| CoreError::io(dir, error))? {
        let entry = entry.map_err(|error| CoreError::io(dir, error))?;
        let name = entry.file_name();
        if name.to_string_lossy().contains(".tmp-") {
            let path = entry.path();
            fs::remove_file(&path).map_err(|error| CoreError::io(&path, error))?;
        }
    }
    Ok(())
}

/// Reads bytes from a freshly opened `File` without depending on the declared
/// size. Used by the permission tests.
pub fn read_existing(path: &Path) -> Result<(File, u64)> {
    let file = File::open(path).map_err(|error| CoreError::io(path, error))?;
    let len = file
        .metadata()
        .map_err(|error| CoreError::io(path, error))?
        .len();
    Ok((file, len))
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_json_is_pretty_below_the_threshold_and_compact_above_it() {
        let har = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/har-minimal.json"),
        )
        .unwrap();
        let session = crate::import_har(&har).unwrap().bundle.session;
        let pretty = session_json_bytes(&session, usize::MAX).unwrap();
        let compact = session_json_bytes(&session, 0).unwrap();
        assert!(pretty.contains(&b'\n') && pretty.windows(2).any(|w| w == b"  "));
        assert!(!compact.contains(&b'\n'));
        assert!(compact.len() < pretty.len());
        let a: serde_json::Value = serde_json::from_slice(&pretty).unwrap();
        let b: serde_json::Value = serde_json::from_slice(&compact).unwrap();
        assert_eq!(a, b);
        // The limit applies to the indented size: exactly at the limit it is still indented.
        let exact = session_json_bytes(&session, pretty.len()).unwrap();
        assert_eq!(exact, pretty);
        let below = session_json_bytes(&session, pretty.len() - 1).unwrap();
        assert_eq!(below, compact);
    }

    use super::*;
    use crate::model::{BrowserInfo, SessionMeta, SessionV1, SCHEMA_VERSION};

    #[test]
    fn rejects_path_traversal() {
        for name in ["../x", "a/b", "/abs", "a\\b", "", "..", "."] {
            assert!(validate_attachment_name(name).is_err(), "{name:?}");
        }
        assert!(validate_attachment_name("req-1.request.bin").is_ok());
        assert!(validate_attachment_name("a b.bin").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_creates_nested_0700_and_refuses_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a").join("session");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let error = ensure_private_dir(&link).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(
            error.to_string().contains("indicate a real folder"),
            "{error}"
        );
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        let error = ensure_private_dir(&file).unwrap_err();
        assert!(error.to_string().contains("not a directory"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn system_symlink_exception_is_owner_and_mode_based() {
        // Injected owners keep the accepted case testable without root.
        assert!(trusted_system_link(0, 0, 0o755), "root link + root parent");
        assert!(
            trusted_system_link(0, 0, 0o555),
            "root parent, not writable"
        );
        assert!(!trusted_system_link(501, 0, 0o755), "user-owned link");
        assert!(!trusted_system_link(0, 501, 0o755), "user-owned parent");
        assert!(!trusted_system_link(0, 0, 0o775), "group-writable parent");
        assert!(!trusted_system_link(0, 0, 0o757), "other-writable parent");
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn root_owned_home_symlink_is_accepted_when_running_as_root() {
        use std::os::unix::fs::PermissionsExt;
        if effective_uid() != 0 {
            eprintln!("skipping: needs root to own the simulated /home layout");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let real = root.path().join("var").join("home");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(real.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&real, &home).unwrap();
        let destination = home.join("user").join("session");
        ensure_private_dir(&destination).unwrap();
        assert!(destination.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_fixes_permissions_and_refuses_a_foreign_owner() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // The owner check is exercised with the real metadata and a different
        // expected uid: no chmod of a foreign directory is attempted.
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(&dir).unwrap();
        let error = check_private_owner(&dir, meta.uid(), meta.uid().wrapping_add(1)).unwrap_err();
        assert!(error.to_string().contains("owned by uid"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn check_private_dir_refuses_real_foreign_metadata() {
        use std::os::unix::fs::MetadataExt;
        // Metadata only: a foreign directory is refused before any chmod, so
        // this never changes a system directory.
        for path in ["/private/tmp", "/tmp"] {
            let Ok(meta) = fs::symlink_metadata(path) else {
                continue;
            };
            if !meta.is_dir() || meta.uid() == effective_uid() {
                continue;
            }
            let error = check_private_dir(Path::new(path), &meta).unwrap_err();
            assert!(error.to_string().contains("owned by uid"), "{error}");
            return;
        }
        eprintln!("skipping: no foreign-owned directory available");
    }

    #[cfg(unix)]
    #[test]
    fn writes_private_permissions_and_reads_back() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        bundle.insert_attachment("req-1.request.bin", b"hello".to_vec());

        write_session_dir(&bundle, &dir).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(SESSION_FILE)), 0o600);
        assert_eq!(mode(&dir.join(ATTACHMENTS_DIR)), 0o700);
        assert_eq!(
            mode(&dir.join(ATTACHMENTS_DIR).join("req-1.request.bin")),
            0o600
        );

        let json = fs::read(dir.join(SESSION_FILE)).unwrap();
        let parsed: SessionV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(
            fs::read(dir.join(ATTACHMENTS_DIR).join("req-1.request.bin")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn writes_many_attachments_in_one_batch() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-many",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        for index in 0..128 {
            bundle.insert_attachment(format!("a-{index:03}.bin"), vec![b'x'; 20]);
        }
        write_session_dir(&bundle, &dir).unwrap();
        assert_eq!(
            fs::read_dir(dir.join(ATTACHMENTS_DIR)).unwrap().count(),
            128
        );
        assert_eq!(
            fs::read(dir.join(ATTACHMENTS_DIR).join("a-127.bin")).unwrap(),
            vec![b'x'; 20]
        );
        let leftovers: Vec<_> = fs::read_dir(dir.join(ATTACHMENTS_DIR))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    #[ignore = "manual benchmark: cargo test --release -- --ignored writes_20k_small_attachments"]
    fn writes_20k_small_attachments_quickly() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("session");
        let session = SessionV1::new(SessionMeta::new(
            "s-many",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        for index in 0..20_000 {
            bundle.insert_attachment(format!("a-{index:05}.bin"), vec![b'x'; 20]);
        }
        let started = std::time::Instant::now();
        write_session_dir(&bundle, &dir).unwrap();
        let elapsed = started.elapsed();
        println!("20k attachments: {elapsed:?}");
        assert_eq!(
            std::fs::read_dir(dir.join(ATTACHMENTS_DIR))
                .unwrap()
                .count(),
            20_000
        );
        assert_eq!(
            std::fs::read(dir.join(ATTACHMENTS_DIR).join("a-19999.bin")).unwrap(),
            vec![b'x'; 20]
        );
    }

    #[test]
    fn write_is_atomic_over_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("s");
        let session = SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            BrowserInfo::default(),
        ));
        let mut bundle = SessionBundle::new(session);
        write_session_dir(&bundle, &dir).unwrap();
        bundle.session.session.id = "s-2".to_string();
        write_session_dir(&bundle, &dir).unwrap();
        let parsed: SessionV1 =
            serde_json::from_slice(&fs::read(dir.join(SESSION_FILE)).unwrap()).unwrap();
        assert_eq!(parsed.session.id, "s-2");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
