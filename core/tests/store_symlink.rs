//! Regression: `write_session_dir` never writes outside the session directory
//! because of a planted symlink (destination, predictable temporary, `attachments/`).

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use scrapelens_core::store::write_session_dir;

fn bundle() -> scrapelens_core::SessionBundle {
    let har = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/acceptance/sanitize/secret.har"),
    )
    .unwrap();
    let imported = scrapelens_core::import_har(&har).unwrap();
    assert!(
        !imported.bundle.attachments.is_empty(),
        "precondition: there are attachments"
    );
    imported.bundle
}

fn outside(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, "ORIGINAL\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    path
}

fn intact(path: &Path) {
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "ORIGINAL\n",
        "{path:?} was overwritten"
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644,
        "{path:?} changed mode"
    );
}

#[test]
fn ancestor_symlinks_are_refused_before_creating_the_session() {
    let root = tempfile::tempdir().unwrap();
    let allowed = root.path().join("allowed");
    let outside = root.path().join("outside");
    fs::create_dir(&allowed).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();

    // Absolute ancestor symlink: allowed/link -> outside.
    symlink(&outside, allowed.join("link")).unwrap();
    let destination = allowed.join("link").join("session");
    let error = write_session_dir(&bundle(), &destination).unwrap_err();
    assert!(
        error.to_string().contains("symbolic link"),
        "absolute ancestor: {error}"
    );
    assert!(!outside.join("session").exists());
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing may be written outside"
    );
    assert!(!destination.exists());

    // Relative ancestor symlink: allowed/linkrel -> ../outside.
    symlink(Path::new("../outside"), allowed.join("linkrel")).unwrap();
    let destination = allowed.join("linkrel").join("session");
    let error = write_session_dir(&bundle(), &destination).unwrap_err();
    assert!(
        error.to_string().contains("symbolic link"),
        "relative ancestor: {error}"
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert!(!destination.exists());

    // The control without a symlink writes normally.
    let control = root.path().join("control").join("session");
    write_session_dir(&bundle(), &control).unwrap();
    assert!(control.join("session.json").is_file());
    assert!(control.join("attachments").is_dir());
}

#[test]
fn an_ancestor_without_the_read_bit_is_walked_with_search_rights() {
    // L4 regression: ancestors are only used as `*at` dirfds, so a mode 0311
    // folder (write+execute, no read) must not fail with EACCES.
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let locked = root.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o311)).unwrap();

    let destination = locked.join("session");
    scrapelens_core::store::ensure_private_dir(&destination).unwrap();
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o700
    );
    write_session_dir(&bundle(), &destination).unwrap();
    assert!(destination.join("session.json").is_file());

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn copy_from_refuses_a_fifo_without_blocking_on_it() {
    // L5 regression: opening a FIFO read-only blocks until a writer appears.
    use std::sync::mpsc;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("dest");
    let private = scrapelens_core::store::PrivateDir::open(&destination).unwrap();
    let fifo = root.path().join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = private
            .copy_from("body.bin", &fifo)
            .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("copy_from blocked on a FIFO");
    let error = result.expect_err("a FIFO must be refused");
    assert!(error.contains("not a regular file"), "{error}");
    assert!(!destination.join("body.bin").exists());
}

#[test]
fn symlinked_destinations_are_refused_and_targets_stay_intact() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("session");
    fs::create_dir(&dir).unwrap();
    let target = outside(root.path(), "target-session.txt");
    symlink(&target, dir.join("session.json")).unwrap();
    let error = write_session_dir(&bundle(), &dir).unwrap_err();
    assert!(error.to_string().contains("symbolic link"), "{error}");
    intact(&target);

    let mut with_raw = bundle();
    with_raw.cdp_events_jsonl = Some(b"{}\n".to_vec());
    let dir2 = root.path().join("session2");
    fs::create_dir(&dir2).unwrap();
    let target2 = outside(root.path(), "target-cdp.txt");
    symlink(&target2, dir2.join("cdp-events.jsonl")).unwrap();
    assert!(write_session_dir(&with_raw, &dir2).is_err());
    intact(&target2);
}

#[test]
fn predictable_temp_name_symlink_is_never_followed() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("session");
    fs::create_dir(&dir).unwrap();
    let target = outside(root.path(), "target-tmp.txt");
    for name in [
        format!(".session.json.tmp-{}", std::process::id()),
        ".session.json.tmp-1".to_string(),
    ] {
        symlink(&target, dir.join(name)).unwrap();
    }
    write_session_dir(&bundle(), &dir).unwrap();
    intact(&target);
    let meta = fs::symlink_metadata(dir.join("session.json")).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[test]
fn symlinked_attachments_dir_and_files_are_refused() {
    let root = tempfile::tempdir().unwrap();
    // attachments/ -> directory from outside
    let dir = root.path().join("session");
    fs::create_dir(&dir).unwrap();
    let ext = root.path().join("outside");
    fs::create_dir(&ext).unwrap();
    fs::set_permissions(&ext, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&ext, dir.join("attachments")).unwrap();
    assert!(write_session_dir(&bundle(), &dir).is_err());
    assert_eq!(
        fs::read_dir(&ext).unwrap().count(),
        0,
        "nothing may be written outside"
    );
    assert_eq!(
        fs::metadata(&ext).unwrap().permissions().mode() & 0o777,
        0o755,
        "no chmod on the target"
    );

    // an attachment that already exists as a symlink
    let dir2 = root.path().join("session2");
    fs::create_dir_all(dir2.join("attachments")).unwrap();
    let target = outside(root.path(), "target-attachment.txt");
    let b = bundle();
    let name = b.attachments.keys().next().unwrap().clone();
    symlink(&target, dir2.join("attachments").join(&name)).unwrap();
    assert!(write_session_dir(&b, &dir2).is_err());
    intact(&target);
}

#[test]
fn parallel_creation_of_the_same_chain_is_idempotent() {
    use std::sync::{Arc, Barrier};
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("a").join("b").join("session");
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let destination = destination.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let mut failures = Vec::new();
            for _ in 0..300 {
                if let Err(error) = scrapelens_core::store::ensure_private_dir(&destination) {
                    failures.push(error.to_string());
                }
            }
            failures
        }));
    }
    let failures: Vec<String> = threads
        .into_iter()
        .flat_map(|thread| thread.join().unwrap())
        .collect();
    assert!(
        failures.is_empty(),
        "concurrent creation failed: {failures:?}"
    );
    let meta = fs::symlink_metadata(&destination).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

#[test]
fn racing_symlink_and_creation_never_escapes_or_masks_the_link() {
    use std::sync::{Arc, Barrier};
    for _ in 0..100 {
        let root = tempfile::tempdir().unwrap();
        let allowed = root.path().join("allowed");
        let outside = root.path().join("outside");
        fs::create_dir(&allowed).unwrap();
        fs::create_dir(&outside).unwrap();
        let destination = allowed.join("session");
        let barrier = Arc::new(Barrier::new(2));

        let creator = {
            let destination = destination.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                scrapelens_core::store::ensure_private_dir(&destination)
            })
        };
        let planter = {
            let destination = destination.clone();
            let outside = outside.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let _ = symlink(&outside, &destination);
            })
        };

        let created = creator.join().unwrap();
        planter.join().unwrap();
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            0,
            "nothing may be written outside"
        );
        let meta = fs::symlink_metadata(&destination).unwrap();
        if created.is_ok() {
            assert!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "a successful creation must be a real directory"
            );
        } else {
            assert!(
                meta.file_type().is_symlink(),
                "a refusal must be caused by the planted symlink"
            );
        }
    }
}
