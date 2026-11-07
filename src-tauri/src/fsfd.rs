//! Descriptor-relative file operations for the places the App writes outside its own folders.
//!
//! A path is resolved once, component by component with `O_NOFOLLOW`, into a descriptor. Every
//! later operation (create, copy, remove) is relative to a descriptor, so a name that is swapped
//! for a symbolic link after that point can only make the operation fail. It cannot redirect it.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

const DIR_FLAGS: OFlags = OFlags::DIRECTORY.union(OFlags::RDONLY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// Opens the absolute `path` as a directory. Every component is opened relative to its parent
/// without following links, so a name swapped for a link before or during the walk fails the
/// walk: the path is never canonicalized, because canonicalizing is what a swapped name exploits.
/// The one exception is the macOS system alias `/tmp`, `/var` or `/etc`, which lives under
/// `/private`: a first component that is such an alias is entered through `/private`.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the path must be absolute"));
    }
    let mut fd = rustix::fs::open("/", DIR_FLAGS, Mode::empty())?;
    let mut first = true;
    for component in path.components() {
        let Component::Normal(name) = component else { continue };
        let alias = first && matches!(name.to_str(), Some("tmp" | "var" | "etc"));
        first = false;
        fd = match rustix::fs::openat(&fd, name, DIR_FLAGS, Mode::empty()) {
            Ok(next) => next,
            // macOS: the alias is a link, and O_DIRECTORY reports it as ENOTDIR; elsewhere it is ELOOP.
            Err(error) if alias && (error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR) => {
                let private = rustix::fs::openat(&fd, "private", DIR_FLAGS, Mode::empty())?;
                rustix::fs::openat(&private, name, DIR_FLAGS, Mode::empty())?
            }
            Err(error) => return Err(io::Error::from(error)),
        };
    }
    Ok(fd)
}

/// Creates a directory (mode 0700) inside `dir`. Fails with `AlreadyExists` when the name is taken.
pub fn create_dir_at(dir: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o700))?;
    rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()).map_err(io::Error::from)
}

/// Creates a new private file (mode 0600) inside `dir`. Fails with `AlreadyExists` when the name is taken.
pub fn create_file_at(dir: &OwnedFd, name: &OsStr) -> io::Result<File> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(dir, name, flags, Mode::from_raw_mode(0o600))
        .map(File::from)
        .map_err(io::Error::from)
}

/// Copies the tree under `src` into `dst`, regular files and folders only. A link or any other
/// kind of entry is refused, and nothing is followed.
pub fn copy_tree_at(src: &OwnedFd, dst: &OwnedFd) -> io::Result<()> {
    for entry in rustix::fs::Dir::read_from(src)? {
        let entry = entry?;
        let Some(name) = entry_name(entry.file_name().to_bytes()) else { continue };
        let kind = match entry.file_type() {
            FileType::Unknown => {
                FileType::from_raw_mode(rustix::fs::statat(src, name, AtFlags::SYMLINK_NOFOLLOW)?.st_mode)
            }
            other => other,
        };
        match kind {
            FileType::Directory => {
                let child_dst = create_dir_at(dst, name)?;
                let child_src = rustix::fs::openat(src, name, DIR_FLAGS, Mode::empty())?;
                copy_tree_at(&child_src, &child_dst)?;
            }
            FileType::RegularFile => {
                let input_fd = rustix::fs::openat(
                    src,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let mut input = File::from(input_fd);
                let mut output = create_file_at(dst, name)?;
                io::copy(&mut input, &mut output)?;
                output.sync_all()?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a regular file or folder; refused", String::from_utf8_lossy(name.as_bytes())),
                ));
            }
        }
    }
    Ok(())
}

/// Removes the entry `name` inside `dir`, and everything under it when it is a folder. Links are
/// removed as links, never followed.
pub fn remove_entry_at(dir: &OwnedFd, name: &OsStr) -> io::Result<()> {
    match rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()) {
        Ok(child) => {
            for entry in rustix::fs::Dir::read_from(&child)? {
                let entry = entry?;
                if let Some(inner) = entry_name(entry.file_name().to_bytes()) {
                    remove_entry_at(&child, inner)?;
                }
            }
            rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(io::Error::from)
        }
        // Not a folder, or a link (O_NOFOLLOW refuses it as ELOOP): remove the entry itself.
        Err(error) if error == rustix::io::Errno::NOTDIR || error == rustix::io::Errno::LOOP => {
            rustix::fs::unlinkat(dir, name, AtFlags::empty()).map_err(io::Error::from)
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

/// Removes the entry at `path`, relative to its parent's descriptor.
pub fn remove_path(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent folder"))?;
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = open_dir_nofollow(parent)?;
    remove_entry_at(&dir, name)
}

fn entry_name(bytes: &[u8]) -> Option<&OsStr> {
    if bytes == b"." || bytes == b".." {
        return None;
    }
    Some(OsStr::from_bytes(bytes))
}

/// Sets the open-files soft limit to the hard limit, up to what macOS and Linux accept for it.
/// A macOS app started from Finder inherits launchd's soft limit, which a real browser exceeds
/// during a session. Returns the soft limit in effect afterwards.
pub fn raise_open_files_limit() -> u64 {
    #[cfg(target_os = "macos")]
    const CEILING: u64 = 10_240;
    #[cfg(not(target_os = "macos"))]
    const CEILING: u64 = 65_536;
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid rlimit for getrlimit to write into.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return 0;
    }
    let target = limit.rlim_max.min(CEILING);
    if target > limit.rlim_cur {
        let raised = libc::rlimit { rlim_cur: target, rlim_max: limit.rlim_max };
        // SAFETY: `raised` is a valid rlimit whose soft limit is not above its hard limit.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }
    }
    let mut now = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut now) } == 0 {
        now.rlim_cur
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_alias_path_opens_without_canonicalizing() {
        // The temporary folder is /var/folders/... on macOS, a link into /private. The walk enters it
        // through /private and the folder is the same one a canonical path names.
        let dir = std::env::temp_dir().join(format!("sl-fsfd-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fd = open_dir_nofollow(&dir).expect("the alias path opens");
        create_file_at(&fd, OsStr::new("probe.txt")).unwrap();
        assert!(dir.join("probe.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_open_files_limit_is_raised_to_a_usable_value() {
        let soft = raise_open_files_limit();
        assert!(soft >= 1024, "soft limit {soft}");
    }

    #[test]
    fn a_link_in_the_path_is_refused() {
        let base = std::env::temp_dir().join(format!("sl-fsfd-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        assert!(open_dir_nofollow(&base.join("link")).is_err(), "a link in the path is refused");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
