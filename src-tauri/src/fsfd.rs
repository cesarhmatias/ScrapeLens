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

use rustix::fs::{AtFlags, Mode, OFlags};

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
        // `..` is taken from the held descriptor: the directory above is the one the walk stands in,
        // which is the lexical parent here, since every component so far was a real directory.
        let name = match component {
            Component::Normal(name) => name,
            Component::ParentDir => {
                fd = rustix::fs::openat(&fd, "..", DIR_FLAGS, Mode::empty()).map_err(io::Error::from)?;
                first = false;
                continue;
            }
            _ => continue,
        };
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

/// Creates an empty directory (mode 0700) inside `dir`. Fails with `AlreadyExists` when the name is taken.
pub fn create_dir_at(dir: &OwnedFd, name: &OsStr) -> io::Result<()> {
    rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o700)).map_err(io::Error::from)
}

/// Creates a new private file (mode 0600) inside `dir`. Fails with `AlreadyExists` when the name is taken.
pub fn create_file_at(dir: &OwnedFd, name: &OsStr) -> io::Result<File> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(dir, name, flags, Mode::from_raw_mode(0o600))
        .map(File::from)
        .map_err(io::Error::from)
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

fn entry_name(bytes: &[u8]) -> Option<&OsStr> {
    if bytes == b"." || bytes == b".." {
        return None;
    }
    Some(OsStr::from_bytes(bytes))
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
    fn a_link_in_the_path_is_refused() {
        let base = std::env::temp_dir().join(format!("sl-fsfd-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        assert!(open_dir_nofollow(&base.join("link")).is_err(), "a link in the path is refused");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_dotdot_path_opens_the_folder_it_names() {
        let base = std::env::temp_dir().join(format!("sl-fsfd-dotdot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        std::fs::create_dir_all(base.join("real")).unwrap();
        let fd = open_dir_nofollow(&base.join("a/b/../../real")).expect("the .. path opens");
        create_file_at(&fd, OsStr::new("probe.txt")).unwrap();
        assert!(base.join("real/probe.txt").exists(), "the .. path must name real/, not a/b/real");
        assert!(!base.join("a/b/real").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
