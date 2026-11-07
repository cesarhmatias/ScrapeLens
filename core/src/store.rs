#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
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
fn trusted_system_link(link_uid: u32, parent_uid: u32, parent_mode: u64) -> bool {
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
    trusted_system_link(link.uid(), parent_meta.uid(), u64::from(parent_meta.mode()))
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
/// The whole chain is walked through directory descriptors opened with `O_NOFOLLOW`:
/// a symlink ancestor not owned by root (except a trusted system link), `..`, a
/// file or a foreign-owned destination is refused before any chmod or write.
/// Missing components are created with `mkdirat` (mode 0700) relative to the
/// parent descriptor, and the destination is opened, checked and chmodded
/// through its own descriptor. Nothing is resolved from the path again, so a
/// name swapped for a symlink after a check can only make the call fail, never
/// redirect a mkdir or a chmod to another directory.
#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    open_private_dir(path).map(|_| ())
}

#[cfg(not(unix))]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|error| CoreError::io(path, error))?;
    }
    set_mode(path, 0o700)
}

/// Opens (creating missing components) the private destination and returns the
/// descriptor of the FINAL directory. Every later operation must be relative to it.
#[cfg(unix)]
fn open_private_dir(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags};

    if path.as_os_str().is_empty() {
        return Err(CoreError::LimitExceeded {
            message: "empty destination path; refused".to_string(),
        });
    }
    let absolute = path.is_absolute();
    let mut components = path.components();
    let mut current = if absolute {
        // Consume `RootDir`; the descriptor starts at the filesystem root.
        components.next();
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    let root_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let mut dir: File =
        rustix::fs::open(if absolute { "/" } else { "." }, root_flags, Mode::empty())
            .map(File::from)
            .map_err(|error| CoreError::io(path, errno_io(error)))?;
    let mut remaining = components.peekable();
    while let Some(component) = remaining.next() {
        let is_final = remaining.peek().is_none();
        let part = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err(CoreError::LimitExceeded {
                    message: format!("{} contains '..'; refused", path.display()),
                });
            }
            Component::Prefix(_) => {
                return Err(CoreError::LimitExceeded {
                    message: format!("{} has an unsupported prefix; refused", path.display()),
                });
            }
            Component::Normal(part) => part,
        };
        current.push(part);
        dir = enter_private_component(&dir, part, &current, !is_final)?;
    }
    verify_private_fd(&dir, path)?;
    Ok(dir)
}

/// One component of the walk: a real directory is opened without following its
/// final link; a missing one is created with `mkdirat` and reopened; only a
/// trusted system symlink in an ANCESTOR position is followed. Errors carry the
/// full path for the caller.
#[cfg(unix)]
fn enter_private_component(
    dir: &File,
    part: &std::ffi::OsStr,
    current: &Path,
    allow_system_link: bool,
) -> Result<File> {
    use rustix::fs::{AtFlags, FileType, Mode};

    match rustix::fs::statat(dir, part, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let kind = FileType::from_raw_mode(stat.st_mode as _);
            if kind == FileType::Symlink {
                let parent = rustix::fs::fstat(dir)
                    .map_err(|error| CoreError::io(current, errno_io(error)))?;
                if allow_system_link
                    && trusted_system_link(stat.st_uid, parent.st_uid, u64::from(parent.st_mode))
                {
                    return open_component(dir, part, current, true);
                }
                return Err(symlink_refused(current));
            }
            if !kind.is_dir() {
                return Err(not_a_directory(current));
            }
            open_component(dir, part, current, false)
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            for _ in 0..8 {
                match rustix::fs::mkdirat(dir, part, Mode::from(0o700)) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(CoreError::io(current, errno_io(error))),
                }
                match open_component(dir, part, current, false) {
                    Ok(opened) => return Ok(opened),
                    Err(CoreError::Io { source, .. })
                        if source.raw_os_error()
                            == Some(rustix::io::Errno::NOENT.raw_os_error()) =>
                    {
                        continue;
                    }
                    Err(CoreError::Io { source, .. })
                        if source.raw_os_error()
                            == Some(rustix::io::Errno::LOOP.raw_os_error()) =>
                    {
                        return Err(symlink_refused(current));
                    }
                    Err(CoreError::Io { source, .. })
                        if source.raw_os_error()
                            == Some(rustix::io::Errno::NOTDIR.raw_os_error()) =>
                    {
                        return Err(not_a_directory(current));
                    }
                    Err(other) => return Err(other),
                }
            }
            Err(CoreError::LimitExceeded {
                message: format!(
                    "{} changed repeatedly while it was being created; refused",
                    current.display()
                ),
            })
        }
        Err(error) => Err(CoreError::io(current, errno_io(error))),
    }
}

#[cfg(unix)]
fn open_component(
    dir: &File,
    part: &std::ffi::OsStr,
    current: &Path,
    follow: bool,
) -> Result<File> {
    use rustix::fs::{Mode, OFlags};
    let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    if !follow {
        flags |= OFlags::NOFOLLOW;
    }
    rustix::fs::openat(dir, part, flags, Mode::empty())
        .map(File::from)
        .map_err(|error| CoreError::io(current, errno_io(error)))
}

#[cfg(unix)]
fn symlink_refused(path: &Path) -> CoreError {
    CoreError::LimitExceeded {
        message: format!(
            "{} is a symbolic link; refused (ancestor of the destination); indicate a real folder for the session",
            path.display()
        ),
    }
}

#[cfg(unix)]
fn not_a_directory(path: &Path) -> CoreError {
    CoreError::LimitExceeded {
        message: format!("{} exists and is not a directory; refused", path.display()),
    }
}

#[cfg(unix)]
fn errno_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

/// Checks through the descriptor that it is a directory of ours, then sets 0700
/// with `fchmod` on that same descriptor (a swapped name cannot redirect either).
#[cfg(unix)]
fn verify_private_fd(dir: &File, path: &Path) -> Result<()> {
    use rustix::fs::{FileType, Mode};

    let before = rustix::fs::fstat(dir).map_err(|error| CoreError::io(path, errno_io(error)))?;
    if !FileType::from_raw_mode(before.st_mode as _).is_dir() {
        return Err(not_a_directory(path));
    }
    check_private_owner(path, before.st_uid, effective_uid())?;
    rustix::fs::fchmod(dir, Mode::from(0o700))
        .map_err(|error| CoreError::io(path, errno_io(error)))?;
    let after = rustix::fs::fstat(dir).map_err(|error| CoreError::io(path, errno_io(error)))?;
    check_private_owner(path, after.st_uid, effective_uid())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(all(unix, test))]
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

#[cfg(not(unix))]
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

#[cfg(unix)]
/// Refuses a symlink or a non-regular entry at the destination name, relative to
/// the open session directory (never by resolving the full path again).
fn refuse_destination_at(dir: &File, name: &str, path: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, FileType};
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let kind = FileType::from_raw_mode(stat.st_mode as _);
            if kind == FileType::Symlink {
                Err(CoreError::LimitExceeded {
                    message: format!("{} is a symbolic link; refused", path.display()),
                })
            } else if !kind.is_file() {
                Err(CoreError::LimitExceeded {
                    message: format!(
                        "{} exists and is not a regular file; refused",
                        path.display()
                    ),
                })
            } else {
                Ok(())
            }
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(CoreError::io(path, errno_io(error))),
    }
}

#[cfg(unix)]
/// Writes `bytes` to `<dir>/<name>` atomically and relative to the descriptor
/// (A4-B4/A6-B5): a new temporary file with `O_EXCL|O_NOFOLLOW` in the same
/// directory, then `renameat` over the name. A symlink planted at the name is
/// replaced as a NAME; its target is never opened for writing. No path is
/// resolved again after the descriptor was opened.
fn write_private_at(
    dir: &File,
    name: &str,
    path: &Path,
    bytes: &[u8],
    sync_data: bool,
) -> Result<()> {
    write_private_at_impl(dir, name, path, bytes, sync_data, true)
}

/// Same atomic descriptor-relative write, but a symlink or file already at the
/// name is replaced as a NAME (renameat), never followed. Used by spill files,
/// where replacing the entry is the documented behaviour.
#[cfg(unix)]
fn write_private_replacing_at(
    dir: &File,
    name: &str,
    path: &Path,
    bytes: &[u8],
    sync_data: bool,
) -> Result<()> {
    write_private_at_impl(dir, name, path, bytes, sync_data, false)
}

#[cfg(unix)]
fn write_private_at_impl(
    dir: &File,
    name: &str,
    path: &Path,
    bytes: &[u8],
    sync_data: bool,
    refuse_existing: bool,
) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{Mode, OFlags};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    validate_attachment_name(name)?;
    if refuse_existing {
        refuse_destination_at(dir, name, path)?;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!(
        ".{name}.tmp-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = rustix::fs::openat(dir, tmp.as_str(), flags, Mode::from(0o600))
        .map(File::from)
        .map_err(|error| CoreError::io(path, errno_io(error)))?;
    let written = file
        .write_all(bytes)
        .map_err(|error| CoreError::io(path, error))
        .and_then(|()| {
            if sync_data {
                file.sync_all().map_err(|error| CoreError::io(path, error))
            } else {
                file.flush().map_err(|error| CoreError::io(path, error))
            }
        });
    if let Err(error) = written {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), rustix::fs::AtFlags::empty());
        return Err(error);
    }
    rustix::fs::fchmod(&file, Mode::from(0o600))
        .map_err(|error| CoreError::io(path, errno_io(error)))?;
    drop(file);
    rustix::fs::renameat(dir, tmp.as_str(), dir, name).map_err(|error| {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), rustix::fs::AtFlags::empty());
        CoreError::io(path, errno_io(error))
    })
}

#[cfg(not(unix))]
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
    refuse_non_regular_destination(path)?;
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

/// Opens (creating and chmodding) a private subdirectory of an already-open
/// private directory, relative to its descriptor. A symlink is always refused
/// here: the system-symlink exception belongs to the ancestor walk only.
#[cfg(unix)]
fn open_private_subdir(parent: &File, name: &str, path: &Path) -> Result<File> {
    let dir = enter_private_component(parent, std::ffi::OsStr::new(name), path, false)?;
    verify_private_fd(&dir, path)?;
    Ok(dir)
}

/// An open private (0700, ours) directory. Every write through it is relative to
/// the descriptor taken at [`PrivateDir::open`], so a name swapped for a symlink
/// later can only make the operation fail, never redirect it outside.
#[cfg(unix)]
pub struct PrivateDir {
    dir: File,
    path: PathBuf,
}

#[cfg(unix)]
impl PrivateDir {
    /// Opens an existing private directory with the full ancestor walk.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            dir: open_private_dir(path)?,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes one private file (0600) atomically, replacing a planted symlink name
    /// without touching its target.
    pub fn write(&self, name: &str, bytes: &[u8], sync_data: bool) -> Result<()> {
        write_private_at(&self.dir, name, &self.path.join(name), bytes, sync_data)
    }

    /// Like [`PrivateDir::write`], but an entry already at the name (including a
    /// symlink) is replaced without touching the link target.
    pub fn write_replacing(&self, name: &str, bytes: &[u8], sync_data: bool) -> Result<()> {
        write_private_replacing_at(&self.dir, name, &self.path.join(name), bytes, sync_data)
    }

    /// Copies a regular file into the directory without following links at the
    /// source or at the destination name.
    pub fn copy_from(&self, name: &str, source: &Path) -> Result<()> {
        use rustix::fs::{Mode, OFlags};

        validate_attachment_name(name)?;
        refuse_destination_at(&self.dir, name, &self.path.join(name))?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut input = rustix::fs::open(source, flags, Mode::empty())
            .map(File::from)
            .map_err(|error| CoreError::io(source, errno_io(error)))?;
        let meta = input
            .metadata()
            .map_err(|error| CoreError::io(source, error))?;
        if !meta.is_file() {
            return Err(CoreError::LimitExceeded {
                message: format!("{} is not a regular file; refused", source.display()),
            });
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = format!(".{name}.tmp-{nanos}");
        let target = self.path.join(name);
        let create =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut output = rustix::fs::openat(&self.dir, tmp.as_str(), create, Mode::from(0o600))
            .map(File::from)
            .map_err(|error| CoreError::io(&target, errno_io(error)))?;
        let copied = std::io::copy(&mut input, &mut output)
            .and_then(|_| output.sync_all())
            .map_err(|error| CoreError::io(&target, error));
        if let Err(error) = copied {
            let _ = rustix::fs::unlinkat(&self.dir, tmp.as_str(), rustix::fs::AtFlags::empty());
            return Err(error);
        }
        rustix::fs::fchmod(&output, Mode::from(0o600))
            .map_err(|error| CoreError::io(&target, errno_io(error)))?;
        drop(output);
        rustix::fs::renameat(&self.dir, tmp.as_str(), &self.dir, name).map_err(|error| {
            let _ = rustix::fs::unlinkat(&self.dir, tmp.as_str(), rustix::fs::AtFlags::empty());
            CoreError::io(&target, errno_io(error))
        })
    }
}

#[cfg(not(unix))]
pub struct PrivateDir {
    path: PathBuf,
}

#[cfg(not(unix))]
impl PrivateDir {
    pub fn open(path: &Path) -> Result<Self> {
        ensure_private_dir(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self, name: &str, bytes: &[u8], sync_data: bool) -> Result<()> {
        validate_attachment_name(name)?;
        write_atomic(&self.path.join(name), bytes, sync_data)
    }

    pub fn write_replacing(&self, name: &str, bytes: &[u8], sync_data: bool) -> Result<()> {
        self.write(name, bytes, sync_data)
    }

    pub fn copy_from(&self, name: &str, source: &Path) -> Result<()> {
        validate_attachment_name(name)?;
        let bytes = fs::read(source).map_err(|error| CoreError::io(source, error))?;
        self.write(name, &bytes, true)
    }
}

/// Writes a complete session in the v1 layout with restricted permissions:
/// directory 0700, `session.json`/attachments 0600, atomic write per file.
///
/// The destination is opened once (see [`open_private_dir`]) and every mkdir,
/// chmod and write from then on is relative to that descriptor (`mkdirat`,
/// `fchmod`, `openat`, `renameat`). A name swapped for a symlink after the
/// checks can only make the call fail; it can never redirect `session.json` or
/// an attachment to another directory.
///
/// Attachments do not get an individual `fsync`: each file is closed and renamed
/// atomically, and the directory is synchronized once at the end of the batch. In
/// captures with tens of thousands of small bodies, one `fsync` per attachment
/// dominated the import time (128 s for 20 thousand attachments in the acceptance
/// run); `session.json` is still synchronized. The batch preserves the order
/// "artifacts/attachments before the document" so as not to leave a broken reference.
pub fn write_session_dir(bundle: &SessionBundle, dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let session = open_private_dir(dir)?;
        let attachments_path = dir.join(ATTACHMENTS_DIR);
        let attachments = open_private_subdir(&session, ATTACHMENTS_DIR, &attachments_path)?;

        // Artifacts/attachments first; session.json last, so that a document never
        // points to files that do not exist yet.
        if let Some(bytes) = &bundle.cdp_events_jsonl {
            write_private_at(
                &session,
                CDP_EVENTS_FILE,
                &dir.join(CDP_EVENTS_FILE),
                bytes,
                true,
            )?;
        }
        if let Some(bytes) = &bundle.netlog_json {
            write_private_at(&session, NETLOG_FILE, &dir.join(NETLOG_FILE), bytes, true)?;
        }

        // Batch: in small sessions each attachment is durable; in large captures the
        // fsync is a single one per directory at the end, not one per file.
        let sync_each = bundle.attachments.len() <= ATTACHMENT_SYNC_LIMIT;
        for (name, bytes) in &bundle.attachments {
            write_private_at(
                &attachments,
                name,
                &attachments_path.join(name),
                bytes,
                sync_each,
            )?;
        }
        if !bundle.attachments.is_empty() {
            attachments
                .sync_all()
                .map_err(|error| CoreError::io(&attachments_path, error))?;
        }

        let json = session_document(bundle)?;
        write_private_at(&session, SESSION_FILE, &dir.join(SESSION_FILE), &json, true)?;
        session
            .sync_all()
            .map_err(|error| CoreError::io(dir, error))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        ensure_private_dir(dir)?;
        let dir = &dir
            .canonicalize()
            .map_err(|error| CoreError::io(dir, error))?;
        let attachments_dir = dir.join(ATTACHMENTS_DIR);
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
        if let Some(bytes) = &bundle.cdp_events_jsonl {
            write_atomic(&dir.join(CDP_EVENTS_FILE), bytes, true)?;
        }
        if let Some(bytes) = &bundle.netlog_json {
            write_atomic(&dir.join(NETLOG_FILE), bytes, true)?;
        }
        let sync_each = bundle.attachments.len() <= ATTACHMENT_SYNC_LIMIT;
        for (name, bytes) in &bundle.attachments {
            validate_attachment_name(name)?;
            write_atomic(&attachments_dir.join(name), bytes, sync_each)?;
        }
        if !bundle.attachments.is_empty() {
            sync_dir(&attachments_dir)?;
        }
        let json = session_document(bundle)?;
        write_atomic(&dir.join(SESSION_FILE), &json, true)?;
        sync_dir(dir)?;
        Ok(())
    }
}

/// The bytes of `session.json`, applying the proxy facts first when needed.
fn session_document(bundle: &SessionBundle) -> Result<Vec<u8>> {
    if bundle
        .session
        .session
        .capture
        .as_ref()
        .and_then(|capture| capture.proxy.as_ref())
        .is_some()
    {
        let mut session = bundle.session.clone();
        crate::model::apply_proxy_facts(&mut session);
        session_json_bytes(&session, COMPACT_SESSION_BYTES)
    } else {
        session_json_bytes(&bundle.session, COMPACT_SESSION_BYTES)
    }
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
