//! Regression (review 013, HIGH 2): a directory name swapped for a symlink while
//! `ensure_private_dir` / `write_session_dir` is running must never send a mkdir,
//! a chmod, `session.json` or an attachment to the link target. The two scenarios
//! are the harness's R2 and R5, with the outside directory asserted empty during
//! and after every iteration.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use scrapelens_core::store::{ensure_private_dir, write_session_dir, PrivateDir};

/// Minimum real swaps before a test may pass. Under load the fixed 1200 ms/3000 ms
/// loop sometimes ended with zero swaps and proved nothing; the loop now runs
/// until this many swaps (and one success) or the time cap, whichever comes first.
const MIN_SWAPS: u64 = 20;
const RACE_CAP: Duration = Duration::from_secs(10);

/// Toggles `name` between a real directory (ours) and a symlink to `target`.
/// If a call recreates `name` while it is parked, that intruder is discarded and
/// the toggle continues; the directory ends real at `name`. Every planted link
/// increments `swaps`, so a test cannot pass without a real swap.
fn swapper(
    stop: Arc<AtomicBool>,
    name: PathBuf,
    target: PathBuf,
    swaps: Arc<AtomicU64>,
) -> thread::JoinHandle<u64> {
    thread::spawn(move || {
        let hold = name.with_extension("hold");
        let mut planted = 0u64;
        let mut real_at_name = true;
        while !stop.load(Ordering::Relaxed) {
            if real_at_name {
                // A stale hold can be left by a lost restore; drop it first.
                let _ = fs::remove_dir_all(&hold);
                if fs::rename(&name, &hold).is_ok() {
                    if symlink(&target, &name).is_ok() {
                        real_at_name = false;
                        planted += 1;
                        swaps.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let _ = fs::remove_dir_all(&name);
                        let _ = fs::rename(&hold, &name);
                    }
                }
            } else {
                let _ = fs::remove_file(&name);
                let _ = fs::remove_dir_all(&name);
                // `ensure_private_dir` may recreate the name between the removal
                // and the rename; retry a few times instead of getting stuck.
                for _ in 0..8 {
                    if fs::rename(&hold, &name).is_ok() {
                        real_at_name = true;
                        break;
                    }
                    let _ = fs::remove_file(&name);
                    let _ = fs::remove_dir_all(&name);
                }
            }
            std::hint::spin_loop();
        }
        if !real_at_name {
            let _ = fs::remove_file(&name);
            let _ = fs::remove_dir_all(&name);
            let _ = fs::rename(&hold, &name);
        }
        planted
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
///
/// Each round uses a fresh, small ancestor and its own swapper. The test runs
/// rounds until [`MIN_SWAPS`] real swaps happened (or the cap), so a loaded
/// machine cannot end it with zero swaps and prove nothing.
#[test]
fn r2_mkdir_through_a_swapped_ancestor_never_lands_outside() {
    let root = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let (mut ok, mut swaps, mut index) = (0u64, 0u64, 0u64);
    while (swaps < MIN_SWAPS || ok == 0) && started.elapsed() < RACE_CAP {
        index += 1;
        let base = root.path().join(format!("a{index}"));
        let outside = root.path().join(format!("out{index}"));
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let planted = Arc::new(AtomicU64::new(0));
        let handle = swapper(stop.clone(), base.clone(), outside.clone(), planted.clone());
        let round = Instant::now();
        let mut calls = 0u64;
        // At least two calls, and keep going until the swapper really swapped.
        while (planted.load(Ordering::Relaxed) == 0 || calls < 2)
            && round.elapsed() < Duration::from_secs(3)
        {
            calls += 1;
            let destination = base.join(format!("c{calls}/d/e/f/session"));
            if ensure_private_dir(&destination).is_ok() {
                ok += 1;
            }
            assert_eq!(
                outside_entries(&outside),
                Vec::<String>::new(),
                "a mkdir/chmod escaped to the symlink target"
            );
        }
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join().unwrap();
        swaps += planted.load(Ordering::Relaxed);
        assert_eq!(outside_entries(&outside), Vec::<String>::new());
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&outside);
    }
    assert!(
        swaps >= MIN_SWAPS,
        "the race ended without {MIN_SWAPS} real swaps ({swaps} in {:?})",
        started.elapsed()
    );
    assert!(ok > 0, "the race never produced a successful creation");
    let _ = fs::remove_dir_all(root.path());
}

/// R5: the final session directory is swapped for a symlink between the
/// creation/check and the write. `session.json` and the attachments must go to
/// the directory the descriptor holds, never to the link target. Fresh
/// destination and swapper per round; runs until [`MIN_SWAPS`] real swaps.
#[test]
fn r5_session_write_through_a_swapped_destination_never_leaks() {
    let root = tempfile::tempdir().unwrap();
    let bundle = bundle();
    let started = Instant::now();
    let (mut ok, mut swaps, mut index) = (0u64, 0u64, 0u64);
    while (swaps < MIN_SWAPS || ok == 0) && started.elapsed() < RACE_CAP {
        index += 1;
        let parent = root.path().join(format!("p{index}"));
        let outside = root.path().join(format!("out{index}"));
        fs::create_dir_all(&parent).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let destination = parent.join("session");
        fs::create_dir_all(&destination).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let planted = Arc::new(AtomicU64::new(0));
        let handle = swapper(
            stop.clone(),
            destination.clone(),
            outside.clone(),
            planted.clone(),
        );
        let round = Instant::now();
        let mut calls = 0u64;
        while (planted.load(Ordering::Relaxed) == 0 || calls < 2)
            && round.elapsed() < Duration::from_secs(3)
        {
            calls += 1;
            if write_session_dir(&bundle, &destination).is_ok() {
                ok += 1;
            }
            assert_eq!(
                outside_entries(&outside),
                Vec::<String>::new(),
                "session files escaped to the symlink target"
            );
        }
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join().unwrap();
        swaps += planted.load(Ordering::Relaxed);
        assert_eq!(
            outside_entries(&outside),
            Vec::<String>::new(),
            "the symlink target received session files"
        );
        let _ = fs::remove_dir_all(&parent);
        let _ = fs::remove_dir_all(&outside);
    }
    assert!(
        swaps >= MIN_SWAPS,
        "the race ended without {MIN_SWAPS} real swaps ({swaps} in {:?})",
        started.elapsed()
    );
    assert!(ok > 0, "the race never produced a successful write");
    let _ = fs::remove_dir_all(root.path());
}

/// L2: cleanup must act on the descriptor, not on the path again. A directory
/// swapped for a symlink after it was opened may lose the entry inside the
/// ORIGINAL directory, never the link target.
#[test]
fn remove_all_through_a_swapped_directory_never_deletes_outside() {
    let root = tempfile::tempdir().unwrap();
    let inside = root.path().join("session");
    let outside = root.path().join("outside");
    fs::create_dir(&inside).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(inside.join("cdp-events.jsonl"), b"ours").unwrap();
    fs::write(outside.join("cdp-events.jsonl"), b"KEEP").unwrap();

    let private = PrivateDir::open(&inside).unwrap();
    let moved = root.path().join("session.moved");
    fs::rename(&inside, &moved).unwrap();
    symlink(&outside, &inside).unwrap();
    private.remove_all("cdp-events.jsonl").unwrap();

    assert_eq!(
        fs::read(outside.join("cdp-events.jsonl")).unwrap(),
        b"KEEP",
        "cleanup followed the link to the outside directory"
    );
    assert!(!moved.join("cdp-events.jsonl").exists());

    fs::remove_file(&inside).unwrap();
    fs::rename(&moved, &inside).unwrap();
    let _ = fs::remove_dir_all(root.path());
}
