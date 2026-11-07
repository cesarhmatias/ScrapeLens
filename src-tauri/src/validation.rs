//! Trace sessions for execution validation: private temporary folder (0700), deleted when closing the
//! validation screen, on app start and on app exit. "Keep this run" copies to a new folder
//! chosen by the user and only then deletes the temporary one.

use std::fs;
use std::path::{Path, PathBuf};

use scrapelens_core::store;

use crate::fsfd;

/// Size limit for the trace file accepted by validation.
pub const TRACE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Temporary root (inside the app data, private).
pub fn tmp_root(app_data: &Path) -> Result<PathBuf, String> {
    let root = app_data.join("validate-tmp");
    store::ensure_private_dir(&root).map_err(|error| format!("could not create {}: {error}", root.display()))?;
    Ok(root)
}

/// App start: deletes runs that were left without `discard_validation` (crash, kill, forced exit).
/// Only immediate children of the root; symlinks are removed as links, never followed.
pub fn cleanup_on_start(app_data: &Path) {
    if let Ok(root) = tmp_root(app_data) {
        cleanup_all(&root);
    }
}

/// Deletes everything left in the temporary root (app start, shutdown).
pub fn cleanup_all(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = fs::symlink_metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
        let _ = if is_dir { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
    }
}

/// `dir` must be a folder directly inside `root` (never a symlink).
fn inside_root(root: &Path, dir: &Path) -> Result<PathBuf, String> {
    let meta = fs::symlink_metadata(dir).map_err(|error| format!("temporary run inaccessible ({}): {error}", dir.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(format!("{} is not a temporary run folder", dir.display()));
    }
    let root_abs = fs::canonicalize(root).map_err(|error| format!("temporary root inaccessible: {error}"))?;
    let dir_abs = fs::canonicalize(dir).map_err(|error| format!("temporary run inaccessible: {error}"))?;
    if dir_abs.parent() != Some(root_abs.as_path()) {
        return Err(format!("{} does not belong to the app's temporary runs; refused", dir.display()));
    }
    Ok(dir_abs)
}

/// Discards the temporary run; refuses any folder outside the root.
pub fn discard(root: &Path, dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    let dir_abs = inside_root(root, dir)?;
    fs::remove_dir_all(&dir_abs).map_err(|error| format!("could not delete {}: {error}", dir_abs.display()))
}

/// Copies the temporary run to `destination` (new folder, outside the root) and deletes the temporary one.
/// Returns the final path. On error, removes the partial copy and keeps the temporary one.
///
/// The destination's parent is opened once, without following links, and the new folder, the copy
/// and the removal of the temporary run all happen relative to descriptors. A name swapped for a
/// link while the copy runs makes the copy fail; it cannot send the files somewhere else.
pub fn keep(root: &Path, dir: &Path, destination: &Path) -> Result<PathBuf, String> {
    let src = inside_root(root, dir)?;
    let name = destination.file_name().ok_or_else(|| format!("destination has no folder name: {}", destination.display()))?;
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    // parent folder (and ancestors) without symlinks, as in sanitization
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() || ancestor == Path::new("/var") || ancestor == Path::new("/tmp") || ancestor == Path::new("/etc") {
            continue;
        }
        if fs::symlink_metadata(ancestor).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            return Err(format!("the chosen folder goes through a symbolic link ({}); choose a real path", ancestor.display()));
        }
    }
    // Only for the checks below: the copy itself walks the path it was given, never this canonical one.
    let parent_checked = fs::canonicalize(parent).map_err(|error| format!("invalid destination folder ({}): {error}", parent.display()))?;
    let root_abs = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if parent_checked.join(name).starts_with(&root_abs) {
        return Err("the destination is inside the app's temporary folder; choose another folder".to_string());
    }
    let dest = destination.to_path_buf();
    if fs::symlink_metadata(&dest).is_ok() {
        return Err(format!("the destination already exists ({}); choose a new folder", dest.display()));
    }

    // The parent is walked without following links, and the new folder is created inside that
    // descriptor: a name swapped for a link cannot send the folder (or anything in it) elsewhere.
    let parent_abs = absolute(parent)?;
    let parent_fd = fsfd::open_dir_nofollow(&parent_abs)
        .map_err(|error| format!("invalid destination folder ({}): {error}", parent.display()))?;
    match fsfd::create_dir_at(&parent_fd, name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!("the destination already exists ({}); choose a new folder", dest.display()));
        }
        Err(error) => return Err(format!("could not create {}: {error}", dest.display())),
    }
    // The new folder is ours: core opens it as a private directory and copies the run into it
    // through that descriptor (symlinks and special files refused).
    let dest_abs = parent_abs.join(name);
    let copied = store::PrivateDir::open(&dest_abs)
        .and_then(|private| private.copy_tree_from(&src))
        .map_err(|error| format!("could not copy the run to {}: {error}", dest.display()));
    if let Err(error) = copied {
        remove_partial(&dest_abs, &parent_fd, name);
        return Err(error);
    }

    let src_name = src.file_name().ok_or_else(|| format!("temporary run has no name: {}", src.display()))?;
    let root_private = store::PrivateDir::open(&root_abs).map_err(|error| error.to_string())?;
    let src_name = src_name.to_str().ok_or_else(|| format!("temporary run has no UTF-8 name: {}", src.display()))?;
    root_private
        .remove_all(src_name)
        .map_err(|error| format!("run kept in {}, but the temporary one was not deleted: {error}", dest.display()))?;
    Ok(dest)
}

/// Removes a folder that `keep` created and then failed to fill: its entries through core's
/// private descriptor, then the empty folder through the parent's descriptor.
fn remove_partial(dest: &Path, parent: &std::os::fd::OwnedFd, name: &std::ffi::OsStr) {
    if let Ok(private) = store::PrivateDir::open(dest) {
        if let Ok(entries) = fs::read_dir(dest) {
            for entry in entries.flatten() {
                if let Some(entry_name) = entry.file_name().to_str() {
                    let _ = private.remove_all(entry_name);
                }
            }
        }
    }
    let _ = fsfd::remove_entry_at(parent, name);
}

/// The absolute form of `path`: as given when it is absolute, otherwise relative to the working directory.
fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir().map(|cwd| cwd.join(path)).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sl-validation-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    fn make_exec(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("session.json"), "{}").unwrap();
        fs::write(dir.join("attachments/a.bin"), "run data").unwrap();
        dir
    }

    #[test]
    fn startup_removes_executions_left_without_discard() {
        let base = tmp("startup");
        // "previous session" ended without discard_validation: folders, a loose file and a symlink pointing outside
        let root = tmp_root(&base).unwrap();
        make_exec(&root, "har-aaaa");
        make_exec(&root, "har-bbbb");
        fs::write(root.join("loose.json"), "x").unwrap();
        let outside = make_exec(&base, "user-data");
        std::os::unix::fs::symlink(&outside, root.join("link-outside")).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4);
        // new start
        cleanup_on_start(&base);
        assert!(root.is_dir(), "the root still exists");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0, "every child of the root was deleted");
        assert!(outside.join("session.json").exists(), "the symlink target was not touched");
        // no root yet: a clean start creates the private root
        let fresh = tmp("startup-fresh");
        cleanup_on_start(&fresh);
        assert_eq!(fs::metadata(fresh.join("validate-tmp")).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&fresh);
    }

    #[test]
    fn discard_cleanup_and_keep() {
        let base = tmp("flow");
        let root = tmp_root(&base).unwrap();
        // discarding deletes the folder; repeating is harmless
        let a = make_exec(&root, "a");
        discard(&root, &a).unwrap();
        assert!(!a.exists());
        discard(&root, &a).unwrap();
        // refuses a folder outside the root and a symlink pointing outside
        let outside = make_exec(&base, "outside");
        assert!(discard(&root, &outside).unwrap_err().contains("does not belong"));
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(discard(&root, &root.join("link")).is_err());
        assert!(outside.join("session.json").exists(), "the symlink target must not be deleted");
        // full cleanup (app start/shutdown)
        make_exec(&root, "b");
        make_exec(&root, "c");
        cleanup_all(&root);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        assert!(outside.exists());
        // keep: copies (0700/0600) and deletes the temporary one
        let d = make_exec(&root, "d");
        let dest = base.join("kept");
        let kept = keep(&root, &d, &dest).unwrap();
        assert_eq!(kept, dest);
        assert!(!d.exists());
        assert_eq!(fs::read_to_string(dest.join("attachments/a.bin")).unwrap(), "run data");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dest.join("session.json")).unwrap().permissions().mode() & 0o777, 0o600);
        // an existing destination, a destination inside the root, and a source outside the root are refused; the temporary one stays
        let e = make_exec(&root, "e");
        assert!(keep(&root, &e, &dest).unwrap_err().contains("already exists"));
        assert!(keep(&root, &e, &root.join("x")).unwrap_err().contains("inside the app's temporary folder"));
        assert!(keep(&root, &outside, &base.join("y")).is_err());
        assert!(e.exists() && !base.join("y").exists());
        let _ = fs::remove_dir_all(&base);
    }

    /// Swaps `parent` between a real folder and a link to `outside` while copies run. A copy may
    /// fail; no run may land in `outside`.
    #[test]
    fn keep_never_writes_outside_when_the_parent_is_swapped_for_a_link() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let base = tmp("swap");
        let root = tmp_root(&base).unwrap();
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let parent = base.join("picked");
        fs::create_dir_all(&parent).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let stop = Arc::clone(&running);
        let (flip_parent, flip_outside) = (parent.clone(), outside.clone());
        let aside = base.join("aside");
        let flipper = std::thread::spawn(move || {
            while stop.load(Ordering::SeqCst) {
                let _ = fs::rename(&flip_parent, &aside);
                let _ = std::os::unix::fs::symlink(&flip_outside, &flip_parent);
                std::thread::yield_now();
                let _ = fs::remove_file(&flip_parent);
                let _ = fs::rename(&aside, &flip_parent);
            }
        });
        for i in 0..150 {
            let run = make_exec(&root, &format!("har-{i:04}"));
            let _ = keep(&root, &run, &parent.join(format!("kept-{i}")));
        }
        running.store(false, Ordering::SeqCst);
        flipper.join().unwrap();

        let landed: Vec<_> = fs::read_dir(&outside).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(landed.is_empty(), "runs landed outside the chosen folder: {landed:?}");
    }

    /// Removing a run never follows a link out of it: core's `remove_all` unlinks the link.
    #[test]
    fn removing_a_run_never_follows_a_link_out_of_it() {
        let base = tmp("link-remove");
        let private = base.join("private");
        store::ensure_private_dir(&private).unwrap();
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "x").unwrap();
        let run = private.join("run");
        fs::create_dir_all(&run).unwrap();
        std::os::unix::fs::symlink(&outside, run.join("link")).unwrap();
        store::PrivateDir::open(&private).unwrap().remove_all("run").unwrap();
        assert!(!run.exists(), "the run is removed");
        assert!(outside.join("keep.txt").exists(), "the link's target survives");
    }
}
