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
use std::path::{Component, Path, PathBuf};

use scrapelens_core::store;

use rustix::fs::{AtFlags, Mode, OFlags};

const DIR_FLAGS: OFlags = OFlags::DIRECTORY.union(OFlags::RDONLY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// Opens the absolute `path` as a directory. Every component is opened relative to the descriptor
/// of its parent without following links, so a name swapped for a link during the walk fails it.
/// `..` is taken from the descriptor. A symbolic link is followed only as a system link in an
/// ancestor position: the rule is core's `store::is_trusted_symlink_ancestor` (root-owned link, root-owned
/// parent, not writable by group or others), and the same rule is checked again on the held parent
/// descriptor, so the name cannot be swapped by a user between the check and the follow.
/// A user's link is refused.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the path must be absolute"));
    }
    let parts: Vec<Component> = path.components().collect();
    let last = parts.iter().rposition(|part| matches!(part, Component::Normal(_) | Component::ParentDir));
    let mut fd = rustix::fs::open("/", DIR_FLAGS, Mode::empty())?;
    let mut prefix = PathBuf::from("/");
    for (index, part) in parts.iter().enumerate() {
        match part {
            Component::Normal(name) => {
                prefix.push(name);
                fd = open_step(&fd, name, &prefix, Some(index) == last)?;
            }
            Component::ParentDir => {
                prefix.pop();
                fd = rustix::fs::openat(&fd, "..", DIR_FLAGS, Mode::empty()).map_err(io::Error::from)?;
            }
            _ => {}
        }
    }
    Ok(fd)
}

/// One component of the walk. `prefix` is its path, for the rule and for the error.
fn open_step(dir: &OwnedFd, name: &OsStr, prefix: &Path, is_final: bool) -> io::Result<OwnedFd> {
    match rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()) {
        Ok(next) => Ok(next),
        // A symbolic link: O_DIRECTORY reports it as ENOTDIR on macOS, and O_NOFOLLOW as ELOOP elsewhere.
        Err(error) if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR => {
            let refused = || {
                io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is a symbolic link; refused", prefix.display()))
            };
            if is_final || !store::is_trusted_symlink_ancestor(prefix) {
                return Err(refused());
            }
            let parent = rustix::fs::fstat(dir).map_err(io::Error::from)?;
            let link = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
            if link.st_uid != 0 || parent.st_uid != 0 || parent.st_mode & 0o022 != 0 {
                return Err(refused());
            }
            rustix::fs::openat(dir, name, OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
                .map_err(io::Error::from)
        }
        Err(error) => Err(io::Error::from(error)),
    }
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

    /// A link a user made, in an ancestor position, is refused: only a root-owned system link is followed.
    #[test]
    fn a_user_link_in_an_ancestor_position_is_refused() {
        let base = std::env::temp_dir().join(format!("sl-fsfd-userlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        assert!(open_dir_nofollow(&base.join("link/sub")).is_err(), "a user's link is refused as an ancestor");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A root-owned system link is followed when it is an ancestor, as core does: a folder inside
    /// `/tmp` (a macOS link into `/private`) or `/lib` (a usrmerge link) opens and is the folder the
    /// link leads to. Skipped where no such link exists or it cannot be written.
    #[test]
    fn a_root_owned_system_link_is_followed_as_an_ancestor() {
        use std::os::unix::fs::MetadataExt;
        let candidate = ["/tmp", "/lib", "/var", "/etc", "/home"].into_iter().find(|path| {
            std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink() && m.uid() == 0).unwrap_or(false)
        });
        let Some(link) = candidate else {
            eprintln!("no root-owned system link on this host; the test is skipped");
            return;
        };
        let probe = Path::new(link).join(format!("sl-fsfd-sys-{}", std::process::id()));
        if std::fs::create_dir(&probe).is_err() {
            eprintln!("{link} is not writable here; the test is skipped");
            return;
        }
        let through_link = open_dir_nofollow(&probe).expect("a folder under a root-owned system link opens");
        let direct = open_dir_nofollow(&std::fs::canonicalize(&probe).unwrap()).expect("the resolved folder opens");
        assert_eq!(
            rustix::fs::fstat(&through_link).unwrap().st_ino,
            rustix::fs::fstat(&direct).unwrap().st_ino,
            "the link leads to the folder it points to"
        );
        let _ = std::fs::remove_dir(&probe);
    }
}
