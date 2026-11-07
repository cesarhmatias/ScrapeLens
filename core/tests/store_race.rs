//! Regression (review 013, HIGH 2): a directory name swapped for a symlink while
//! `ensure_private_dir` / `write_session_dir` is running must never send a mkdir,
//! a chmod, `session.json` or an attachment to the link target. The two scenarios
//! are the harness's R2 and R5, with the outside directory asserted empty during
//! and after every iteration.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use scrapelens_core::store::{ensure_private_dir, write_session_dir};

/// Toggles `name` between a real directory (ours) and a symlink to `target`.
/// If a call recreates `name` while it is parked, that intruder is discarded and
/// the toggle continues; the directory ends real at `name`.
fn swapper(stop: Arc<AtomicBool>, name: PathBuf, target: PathBuf) -> thread::JoinHandle<u64> {
    thread::spawn(move || {
        let hold = name.with_extension("hold");
        let mut swaps = 0u64;
        let mut real_at_name = true;
        while !stop.load(Ordering::Relaxed) {
            if real_at_name {
                if fs::rename(&name, &hold).is_ok() {
                    if symlink(&target, &name).is_ok() {
                        real_at_name = false;
                        swaps += 1;
                    } else {
                        let _ = fs::remove_dir_all(&name);
                        let _ = fs::rename(&hold, &name);
                    }
                }
            } else {
                let _ = fs::remove_file(&name);
                let _ = fs::remove_dir_all(&name);
                if fs::rename(&hold, &name).is_ok() {
                    real_at_name = true;
                }
            }
            std::hint::spin_loop();
        }
        if !real_at_name {
            let _ = fs::remove_file(&name);
            let _ = fs::remove_dir_all(&name);
            let _ = fs::rename(&hold, &name);
        }
        swaps
    })
}

fn outside_entries(outside: &Path) -> Vec<String> {
    fs::read_dir(outside)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn bundle() -> scrapelens_core::SessionBundle {
    let har = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/acceptance/sanitize/secret.har"),
    )
    .unwrap();
    let imported = scrapelens_core::import_har(&har).unwrap();
    assert!(
        !imported.bundle.attachments.is_empty(),
        "precondition: the session has attachments"
    );
    imported.bundle
}

/// R2: an ancestor already checked is renamed to a symlink while missing
/// components are being created. Every `mkdir` must follow the descriptor of
/// the original directory; nothing may appear in the link target.
#[test]
fn r2_mkdir_through_a_swapped_ancestor_never_lands_outside() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("r2/a");
    let outside = root.path().join("r2/outside");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let handle = swapper(stop.clone(), base.clone(), outside.clone());
    let started = Instant::now();
    let (mut ok, mut errors) = (0u64, 0u64);
    let mut index = 0u64;
    while started.elapsed() < Duration::from_millis(1200) {
        index += 1;
        let destination = base.join(format!("c{index}/d/e/f/session"));
        match ensure_private_dir(&destination) {
            Ok(()) => ok += 1,
            Err(_) => errors += 1,
        }
        assert_eq!(
            outside_entries(&outside),
            Vec::<String>::new(),
            "a mkdir/chmod escaped to the symlink target"
        );
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = handle.join().unwrap();
    assert_eq!(outside_entries(&outside), Vec::<String>::new());
    assert!(
        ok > 0,
        "the race never produced a successful creation (errors={errors})"
    );
    assert!(swaps > 0, "the swapper never swapped the ancestor");
    let _ = fs::remove_dir_all(root.path());
}

/// R5: the final session directory is swapped for a symlink between the
/// creation/check and the write. `session.json` and the attachments must go to
/// the directory the descriptor holds, never to the link target.
#[test]
fn r5_session_write_through_a_swapped_destination_never_leaks() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("r5");
    let outside = root.path().join("r5out");
    fs::create_dir_all(&parent).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let destination = parent.join("session");
    fs::create_dir_all(&destination).unwrap();
    let bundle = bundle();

    let stop = Arc::new(AtomicBool::new(false));
    let handle = swapper(stop.clone(), destination.clone(), outside.clone());
    let started = Instant::now();
    let (mut ok, mut errors) = (0u64, 0u64);
    while started.elapsed() < Duration::from_millis(3000) {
        match write_session_dir(&bundle, &destination) {
            Ok(()) => ok += 1,
            Err(_) => errors += 1,
        }
        assert_eq!(
            outside_entries(&outside),
            Vec::<String>::new(),
            "session files escaped to the symlink target"
        );
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = handle.join().unwrap();
    assert_eq!(
        outside_entries(&outside),
        Vec::<String>::new(),
        "the symlink target received session files"
    );
    assert!(
        ok > 0,
        "the race never produced a successful write (errors={errors})"
    );
    assert!(swaps > 0, "the swapper never swapped the destination");
    let _ = fs::remove_dir_all(root.path());
}
