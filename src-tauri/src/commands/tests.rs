//! Tests of the commands. Moved from commands.rs unchanged; they reach the commands through the
//! module re-exports in mod.rs.

use super::*;

#[test]
fn reveal_dir_uses_parent_for_files() {
    let dir = std::env::temp_dir().join(format!("sl-reveal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.txt");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(super::reveal_dir(&file), dir);
    assert_eq!(super::reveal_dir(&dir), dir);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn import_read_uses_fd_refusing_symlink_fifo_and_dir() {
    use std::os::unix::fs::symlink;
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "scrapelens-fdread-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("a.har");
    std::fs::write(&file, b"{\"log\":{}}").unwrap();
    assert_eq!(
        read_import_file_max(file.to_str().unwrap(), "HAR", 1024).unwrap(),
        b"{\"log\":{}}"
    );
    assert!(read_import_file_max(file.to_str().unwrap(), "HAR", 3)
        .unwrap_err()
        .contains("larger"));
    let link = root.join("l.har");
    symlink(&file, &link).unwrap();
    assert!(read_import_file_max(link.to_str().unwrap(), "HAR", 1024).is_err());
    let fifo = root.join("p.har");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    // FIFO with no writer: O_NONBLOCK does not block; fstat refuses it for not being regular.
    assert!(read_import_file_max(fifo.to_str().unwrap(), "HAR", 1024)
        .unwrap_err()
        .contains("regular"));
    assert!(read_import_file_max(root.to_str().unwrap(), "HAR", 1024)
        .unwrap_err()
        .contains("directory"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_open_fails_when_parent_is_swapped_for_symlink() {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "scrapelens-openat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::create_dir_all(root.join("other")).unwrap();
    std::fs::write(root.join("dir/a.har"), b"good").unwrap();
    std::fs::write(root.join("other/a.har"), b"evil").unwrap();
    let path = root.join("dir/a.har");
    crate::cli::validate_absolute_regular_file(&path).unwrap();
    assert_eq!(
        read_import_file_max(path.to_str().unwrap(), "HAR", 64).unwrap(),
        b"good"
    );
    // swap the parent for a symlink after validation
    std::fs::rename(root.join("dir"), root.join("dir-old")).unwrap();
    std::os::unix::fs::symlink(root.join("other"), root.join("dir")).unwrap();
    assert!(read_import_file_max(path.to_str().unwrap(), "HAR", 64).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn second_open_is_refused_while_one_is_loading() {
    let flag = std::sync::atomic::AtomicBool::new(false);
    let first = FlagGuard::acquire(&flag).expect("first open");
    assert!(
        FlagGuard::acquire(&flag).is_none(),
        "a second parallel open must be refused"
    );
    drop(first);
    assert!(
        FlagGuard::acquire(&flag).is_some(),
        "released when finished"
    );
    let result = std::panic::catch_unwind(|| {
        let _g = FlagGuard::acquire(&flag).unwrap();
        panic!("open failed");
    });
    assert!(result.is_err());
    assert!(
        !flag.load(std::sync::atomic::Ordering::SeqCst),
        "a panic also releases it"
    );
}

#[test]
fn starting_state_disables_menu_and_reenables_on_failure() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let flag = AtomicBool::new(false);
    let calls = std::cell::RefCell::new(Vec::new());
    {
        let _g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
        assert!(flag.load(Ordering::SeqCst));
        assert!(crate::menu::blocked_while_recording("start-session", &flag));
        // start fails (exits without commit)
    }
    assert!(!flag.load(Ordering::SeqCst));
    assert_eq!(*calls.borrow(), vec![true, false]);
    calls.borrow_mut().clear();
    {
        let mut g = StartingGuard::begin(&flag, |r| calls.borrow_mut().push(r));
        g.commit();
    }
    assert!(
        flag.load(Ordering::SeqCst),
        "a successful start keeps recording"
    );
    assert_eq!(*calls.borrow(), vec![true]);
}

#[test]
fn opens_session_file_with_any_name_but_not_symlink() {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "scrapelens-anyname-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("my-capture.json");
    std::fs::write(&file, MINIMAL_SESSION).unwrap();
    let payload = read_session_payload(file.to_str().unwrap()).unwrap();
    assert_eq!(payload.session["requestCount"], 0);
    assert_eq!(
        payload.session.pointer("/session/id").unwrap(),
        "test-session"
    );
    assert_eq!(payload.session_dir.as_deref(), file.to_str());
    let page = crate::listing::list_page(
        &cached_session(&file).unwrap().session,
        0,
        10,
        &Default::default(),
    );
    assert_eq!(page.total, 0);

    let link = root.join("shortcut.json");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(read_session_payload(link.to_str().unwrap())
        .unwrap_err()
        .contains("symlink"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn imports_are_refused_while_recording() {
    assert!(ensure_not_recording(true)
        .unwrap_err()
        .contains("Stop the recording"));
    assert!(ensure_not_recording(false).is_ok());
    assert_eq!(
        crate::menu::RECORDING_DISABLED_IDS,
        ["import-har", "import-netlog", "start-session"]
    );
}

#[test]
fn menu_guard_never_waits_on_capture_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let state = crate::AppState::default();
    // start_session holds the lock (up to 35 s); the menu must respond right away.
    let _held = state.capture.lock().unwrap();
    let started = std::time::Instant::now();
    assert!(!crate::menu::blocked_while_recording(
        "start-session",
        &state.recording
    ));
    state.recording.store(true, Ordering::SeqCst);
    assert!(crate::menu::blocked_while_recording(
        "start-session",
        &state.recording
    ));
    assert!(crate::menu::blocked_while_recording(
        "import-har",
        &state.recording
    ));
    assert!(!crate::menu::blocked_while_recording(
        "stop-session",
        &state.recording
    ));
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
    let _ = AtomicBool::new(false);
}

static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn temp_session_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "scrapelens-test-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(dir.join("attachments")).unwrap();
    dir
}

const MINIMAL_SESSION: &str = r#"{
  "schemaVersion": 1,
  "session": {
    "id": "test-session",
    "startedAt": "2026-10-26T20:00:00Z",
    "labels": ["synthetic-fixture"],
    "completeness": { "state": "partial", "reasons": ["test fixture"] }
  },
  "requests": []
}"#;

#[test]
fn opens_a_v1_session_directory_and_flags_synthetic() {
    let dir = temp_session_dir("ok");
    fs::write(dir.join("session.json"), MINIMAL_SESSION).unwrap();
    let payload = read_session_payload(dir.to_str().unwrap()).unwrap();
    assert!(payload.synthetic);
    assert_eq!(payload.session["schemaVersion"], 1);
    assert_eq!(payload.session["requestCount"], 0);
    assert_eq!(payload.session["requests"], serde_json::json!([]));
    assert_eq!(
        payload.session.pointer("/session/id").unwrap(),
        "test-session"
    );
    assert!(payload.session_dir.is_some());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn rejects_unknown_schema_version() {
    let dir = temp_session_dir("version");
    fs::write(
        dir.join("session.json"),
        MINIMAL_SESSION.replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
    )
    .unwrap();
    let error = read_session_payload(dir.to_str().unwrap()).unwrap_err();
    assert!(error.contains("schemaVersion 2"), "{error}");
    fs::remove_dir_all(dir).ok();
}

#[test]
fn rejects_missing_session_file() {
    let error = read_session_payload("/path/that/does/not/exist/scrapelens").unwrap_err();
    assert!(error.contains("not found"), "{error}");
}

#[test]
fn attachment_preview_is_text_inside_attachments() {
    let dir = temp_session_dir("attachment");
    fs::write(dir.join("attachments/req.bin"), b"hello").unwrap();
    let payload = read_attachment(session_token(&dir), "req.bin".to_string()).unwrap();
    assert_eq!(payload.kind, "text");
    assert_eq!(payload.text.as_deref(), Some("hello"));
    assert!(read_attachment(session_token(&dir), "../escape".to_string()).is_err());
    fs::remove_dir_all(dir).ok();
}

fn detran_session(name: &str) -> PathBuf {
    fixture_session(name, "detran-pb", "detran-pb")
}

fn fixture_session(name: &str, folder: &str, stem: &str) -> PathBuf {
    use scrapelens_core::correlate::CorrelationOptions;
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(folder);
    let read = |file: String| fs::read(fixtures.join(file)).unwrap();
    let imported = scrapelens_core::parse::import_capture_with_bodies(
        &read(format!("{stem}.cdp.jsonl")),
        &read(format!("{stem}.netlog.json")),
        Some(&read(format!("{stem}.cdp-bodies.jsonl"))),
        CorrelationOptions::default(),
    )
    .unwrap();
    let dir = temp_session_dir(name);
    fs::remove_dir_all(&dir).ok();
    store::write_session_dir(&imported.bundle, &dir).unwrap();
    dir
}

#[test]
fn search_session_finds_body_only_and_reports_partial() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = detran_session("search");
    let found = run_search(
        dir.to_str().unwrap(),
        "cmd_consultar_placa",
        &[],
        false,
        None,
    )
    .unwrap();
    assert_eq!(found.matches.len(), 2);
    assert!(found
        .matches
        .iter()
        .all(|m| m.decoded && m.scope == scrapelens_core::search::Scope::RequestBody));
    assert!(found.partial && !found.partial_attempts.is_empty());
    let url_only = run_search(
        dir.to_str().unwrap(),
        "cmd_consultar_placa",
        &["url".into()],
        false,
        None,
    )
    .unwrap();
    assert!(url_only.matches.is_empty());
    let capped = run_search(
        dir.to_str().unwrap(),
        "cmd_consultar_placa",
        &[],
        false,
        Some(1),
    )
    .unwrap();
    assert_eq!(capped.matches.len(), 1);
    assert!(capped.limit_reached);
    assert!(run_search(dir.to_str().unwrap(), "x", &["nope".into()], false, None).is_err());
    assert!(run_search(dir.to_str().unwrap(), "", &[], false, None).is_err());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn read_body_text_binary_and_cut() {
    let dir = temp_session_dir("body");
    let att = dir.join("attachments");
    // Non-ASCII UTF-8 text (multi-byte characters), so the cut must respect character boundaries.
    fs::write(att.join("t.bin"), "áéíóú".repeat(100)).unwrap();
    fs::write(att.join("b.bin"), [0u8, 159, 146, 150, 255]).unwrap();
    let d = dir.to_str().unwrap();
    let text = read_body_blocking(d, "t.bin", 1000).unwrap();
    assert_eq!(text.kind, "text");
    assert!(!text.cut);
    let cut = read_body_blocking(d, "t.bin", 101).unwrap();
    assert!(cut.cut && cut.kind == "text" && cut.shown_bytes < 101);
    let bin = read_body_blocking(d, "b.bin", 1000).unwrap();
    assert_eq!(bin.kind, "binary");
    assert_eq!(bin.hex.as_deref(), Some("00 9f 92 96 ff"));
    assert!(bin.text.is_none());
    assert!(read_body_blocking(d, "../x", 10).is_err());
    fs::remove_dir_all(dir).ok();
}

#[test]
fn bundle_cache_reuses_and_invalidates() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = detran_session("cache");
    let first = cached_session(&dir).unwrap();
    let second = cached_session(&dir).unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "the second search must reuse the bundle"
    );
    // file changed (size/mtime) → reload
    let session_file = dir.join("session.json");
    let mut text = fs::read_to_string(&session_file).unwrap();
    text.push('\n');
    fs::write(&session_file, text).unwrap();
    let third = cached_session(&dir).unwrap();
    assert!(!Arc::ptr_eq(&first, &third));
    // another session replaces the previous one
    let other = detran_session("cache-other");
    let fourth = cached_session(&other).unwrap();
    assert!(!Arc::ptr_eq(&third, &fourth));
    fs::remove_dir_all(dir).ok();
    fs::remove_dir_all(other).ok();
}

#[cfg(unix)]
#[test]
fn attachments_refuse_symlinks() {
    let dir = temp_session_dir("symlink");
    let outside = temp_session_dir("symlink-outside");
    fs::write(outside.join("secret.txt"), "secret").unwrap();
    let att = dir.join("attachments");
    std::os::unix::fs::symlink(outside.join("secret.txt"), att.join("link.bin")).unwrap();
    fs::write(att.join("ok.bin"), "ok").unwrap();
    let d = dir.to_str().unwrap();
    assert!(read_body_blocking(d, "link.bin", 100)
        .unwrap_err()
        .contains("symbolic link"));
    assert!(
        read_attachment(session_token(Path::new(d)), "link.bin".to_string())
            .unwrap_err()
            .contains("symbolic link")
    );
    assert_eq!(read_body_blocking(d, "ok.bin", 100).unwrap().kind, "text");
    // attachments/ folder as a link
    let dir2 = temp_session_dir("symlink2");
    fs::remove_dir_all(dir2.join("attachments")).unwrap();
    std::os::unix::fs::symlink(&att, dir2.join("attachments")).unwrap();
    assert!(read_body_blocking(dir2.to_str().unwrap(), "ok.bin", 100)
        .unwrap_err()
        .contains("symbolic link"));
    // directory in place of a file
    fs::create_dir(att.join("sub")).unwrap();
    assert!(read_body_blocking(d, "sub", 100).is_err());
    for d in [dir, dir2, outside] {
        fs::remove_dir_all(d).ok();
    }
}

/// Manual measurement: `SL_LARGE_DIR=<session> cargo test --release -- --ignored large_search --nocapture`.
#[test]
#[ignore]
fn large_search_timing() {
    let dir = std::env::var("SL_LARGE_DIR").expect("set SL_LARGE_DIR");
    for round in 1..=3 {
        let start = std::time::Instant::now();
        let found = run_search(&dir, "zzzz", &[], false, None).unwrap();
        eprintln!(
            "search {round}: {:?}, {} matches, loads={}, current_rss={}",
            start.elapsed(),
            found.matches.len(),
            SESSION_LOADS.load(std::sync::atomic::Ordering::SeqCst),
            String::from_utf8_lossy(
                &std::process::Command::new("ps")
                    .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                    .output()
                    .unwrap()
                    .stdout
            )
            .trim()
        );
    }
}

#[test]
fn origins_chain_and_compare_on_detran_fixtures() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let a = detran_session("flow-a");
    let b = fixture_session("flow-b", "detran-pb-b", "detran-pb-b");
    let lazy = cached_session(&a).unwrap();
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let options = scrapelens_core::flow::FlowOptions::default();
    let origins =
        scrapelens_core::flow::value_origins(&lazy.session, &source, "cdp-r0011", &options)
            .unwrap();
    assert!(origins.values.iter().any(|v| v.field == "JSESSIONID"));
    let chain =
        scrapelens_core::flow::priming_chain(&lazy.session, &source, "cdp-r0011", &options)
            .unwrap();
    assert!(!chain.steps.is_empty() && !chain.protection.is_empty());
    let cmp = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
    assert!(cmp.counts.dynamic > 0 && cmp.pairs > 0);
    let page = comparison_page(cmp.handle, 0, 5, true).unwrap();
    assert!(page.total <= cmp.pairs && page.items.len() <= 5 && !page.items.is_empty());
    let all = comparison_page(cmp.handle, 0, 500, false).unwrap();
    assert_eq!(all.total, cmp.pairs);
    let fields = stored_comparison(cmp.handle).unwrap().pairs[page.items[0].index]
        .fields
        .len();
    assert_eq!(fields, page.items[0].field_count);
    assert!(comparison_page(cmp.handle + 99, 0, 5, false).is_err());
    // the same session through different paths (./, symlink) is refused
    let same = a.to_str().unwrap().to_string();
    assert!(open_comparison(
        &same,
        &format!("{same}/../{}", a.file_name().unwrap().to_str().unwrap())
    )
    .unwrap_err()
    .contains("same session"));
    let link = std::env::temp_dir().join(format!("sl-link-{}", std::process::id()));
    std::os::unix::fs::symlink(&a, &link).unwrap();
    assert!(open_comparison(&same, link.to_str().unwrap())
        .unwrap_err()
        .contains("same session"));
    fs::remove_file(&link).ok();
    // both sessions stay cached at the same time
    let again = cached_session(&a).unwrap();
    assert!(Arc::ptr_eq(&lazy, &again));
    fs::remove_dir_all(a).ok();
    fs::remove_dir_all(b).ok();
}

#[test]
fn assess_marks_blocked_responses_on_detran_fixture() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = detran_session("assess");
    let result = assess_blocking(&dir).unwrap();
    assert_eq!(result["schema"], "scrapelens.assess/1");
    let outcomes = result["outcomes"].as_array().unwrap();
    assert!(!outcomes.is_empty());
    assert!(outcomes.iter().any(|o| o["verdictKind"] == "app-ok"));
    // the keys of `counts` are the same as `verdictKind` (kebab-case)
    let counts = result["counts"].as_object().unwrap();
    assert!(!counts.is_empty());
    for (key, value) in counts {
        assert_eq!(
            value.as_u64().unwrap() as usize,
            outcomes
                .iter()
                .filter(|o| o["verdictKind"] == key.as_str())
                .count(),
            "key {key} outside the schema"
        );
        // `undetermined` is the canonical verdict; `indeterminado` is the legacy value, still accepted.
        assert!(
            [
                "app-ok",
                "app-error",
                "blocked",
                "undetermined",
                "indeterminado",
                "not-assessed"
            ]
            .contains(&key.as_str()),
            "unexpected key: {key}"
        );
    }
    // invalid rules become an actionable error
    fs::write(dir.join("assess-rules.json"), "{\"schema\":\"x\"}").unwrap();
    assert!(assess_blocking(&dir).unwrap_err().contains("fix or remove"));
    // the parse error does not echo the file's content
    fs::write(dir.join("assess-rules.json"), "SECRET-IN-FILE").unwrap();
    assert!(!assess_blocking(&dir).unwrap_err().contains("SECRET"));
    // a large file is refused
    fs::write(dir.join("assess-rules.json"), vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(assess_blocking(&dir).unwrap_err().contains("256 KiB"));
    // a symlink is refused, without reading the target
    let outside = dir.join("outside.json");
    fs::write(&outside, "{\"schema\":\"scrapelens.assess-rules/1\"}").unwrap();
    fs::remove_file(dir.join("assess-rules.json")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("assess-rules.json")).unwrap();
    assert!(assess_blocking(&dir).unwrap_err().contains("symbolic link"));
    fs::remove_file(dir.join("assess-rules.json")).unwrap();
    // without rules or with sound rules, no warnings; rules that distort return the core's warnings
    fs::remove_file(dir.join("assess-rules.json")).ok();
    assert_eq!(result["warnings"].as_array().unwrap().len(), 0);
    fs::write(
        dir.join("assess-rules.json"),
        "{\"schema\":\"scrapelens.assess-rules/1\",\"protectionPaths\":[\"/\"]}",
    )
    .unwrap();
    let warned = assess_blocking(&dir).unwrap();
    let warnings = warned["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("protectionPaths")),
        "{warnings:?}"
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn annotated_export_adds_only_comments_on_detran() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = detran_session("annot");
    let d = Path::new(&dir);
    let plain = export_preview(d, "cdp-r0011", "curl", false, false).unwrap();
    let noted = export_preview(d, "cdp-r0011", "curl", true, false).unwrap();
    let strip = |text: &str| {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(strip(&plain.text), strip(&noted.text));
    assert!(
        noted.text.len() > plain.text.len(),
        "there must be origin comments"
    );
    assert!(noted
        .warnings
        .iter()
        .all(|w| w.code != "export.origins_unavailable"));
    fs::remove_dir_all(dir).ok();
}

/// Generates the real previews (with and without origins) for the UI harness:
/// `SL_SESSION=<folder> SL_REQUEST=<id> SL_DUMP=<file.json> cargo test -- --ignored dump_export_previews`.
#[test]
#[ignore]
fn dump_export_previews() {
    let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
    let request = std::env::var("SL_REQUEST").expect("SL_REQUEST");
    let out = std::env::var("SL_DUMP").expect("SL_DUMP");
    let mut all = serde_json::Map::new();
    for format in ["curl", "python"] {
        for annotate in [false, true] {
            let preview =
                export_preview(Path::new(&dir), &request, format, annotate, false).unwrap();
            all.insert(
                format!("{format}-{annotate}"),
                serde_json::to_value(&preview).unwrap(),
            );
        }
    }
    fs::write(out, serde_json::to_string_pretty(&all).unwrap()).unwrap();
}

/// Manual measurement: `SL_LARGE_A=<session> SL_LARGE_B=<copy> cargo test --release -- --ignored large_compare --nocapture`.
#[test]
#[ignore]
fn large_compare_timing() {
    let rss = || {
        String::from_utf8_lossy(
            &std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string()
    };
    let a = std::env::var("SL_LARGE_A").expect("SL_LARGE_A");
    let b = std::env::var("SL_LARGE_B").expect("SL_LARGE_B");
    let start = std::time::Instant::now();
    let summary = open_comparison(&a, &b).unwrap();
    let opened = start.elapsed();
    let filtered = comparison_page(summary.handle, 0, 50, summary.pairs > 500).unwrap();
    let first = start.elapsed();
    eprintln!(
        "1st page with the default filter (only dynamic if >500 pairs): {} item(s) of {}",
        filtered.items.len(),
        filtered.total
    );
    let page = comparison_page(summary.handle, 0, 50, false).unwrap();
    let fields = stored_comparison(summary.handle).unwrap().pairs[page.items[0].index]
        .fields
        .len();
    eprintln!(
        "pairs={} dynamic={} summary_json={}B page50_json={}B fields_of_1st_pair={} open={:?} 1st_page={:?} rss_kb={}",
        summary.pairs,
        summary.dynamic_pairs,
        serde_json::to_string(&summary).unwrap().len(),
        serde_json::to_string(&page).unwrap().len(),
        fields,
        opened,
        first,
        rss()
    );
    let full = scrapelens_core::compare::compare_sessions(
        &cached_session(Path::new(&a)).unwrap().session,
        &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&a)).unwrap()),
        &cached_session(Path::new(&b)).unwrap().session,
        &scrapelens_core::search::LazyBodies(&cached_session(Path::new(&b)).unwrap()),
        &scrapelens_core::compare::CompareOptions::default(),
    );
    eprintln!(
        "full_json_old={}B",
        serde_json::to_string(&full).unwrap().len()
    );
}

#[test]
fn compare_summary_carries_reordered_leftovers() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let a = detran_session("reorder-a");
    let b = fixture_session("reorder-b", "detran-pb-b", "detran-pb-b");
    // B with the 4th request moved to the end: a leftover of the same model on both sides.
    let file = b.join("session.json");
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let requests = doc["requests"].as_array_mut().unwrap();
    let moved = requests.remove(3);
    requests.push(moved);
    fs::write(&file, serde_json::to_vec(&doc).unwrap()).unwrap();
    let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
    assert_eq!(summary.reordered_total, 1);
    assert_eq!(summary.reordered[0].a.request_id, "cdp-r0004");
    assert!(summary
        .only_in_a
        .iter()
        .any(|r| r.request_id == "cdp-r0004"));
    assert!(summary
        .only_in_b
        .iter()
        .any(|r| r.request_id == "cdp-r0004"));
    fs::remove_dir_all(a).ok();
    fs::remove_dir_all(b).ok();
}

#[test]
fn compare_options_parse_ranges_and_reject_garbage() {
    let ok = compare_options(true, Some("2:9"), Some(" ")).unwrap();
    assert!(ok.include_all && ok.a_range.is_some() && ok.b_range.is_none());
    assert!(compare_options(false, Some("norange"), None).is_err());
}

#[test]
fn real_shape_compare_reports_rounds_and_groups() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let har = |name: &str| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/detran-pb-real-shape")
            .join(name);
        let imported = scrapelens_core::import_har(&fs::read(path).unwrap()).unwrap();
        let dir = temp_session_dir(&format!("rs-{name}"));
        fs::remove_dir_all(&dir).ok();
        store::write_session_dir(&imported.bundle, &dir).unwrap();
        dir
    };
    let a = har("real-shape-1round.har");
    let b = har("real-shape-2rounds.har");
    let summary = open_comparison(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
    assert!(!summary.rounds.is_empty());
    assert!(
        !summary.unpaired_rounds.is_empty(),
        "B's 2nd round is left without a pair"
    );
    assert!(summary.groups.iter().any(|g| g.kind == "protection"));
    let all = open_comparison_with(
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        compare_options(true, None, None).unwrap(),
    )
    .unwrap();
    assert!(all.include_all && all.groups.is_empty());
    fs::remove_dir_all(a).ok();
    fs::remove_dir_all(b).ok();
}

fn real_shape_session(name: &str) -> PathBuf {
    let har = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/detran-pb-real-shape/real-shape-1round.har"),
    )
    .unwrap();
    let imported = scrapelens_core::parse::import_har(&har).unwrap();
    let dir = temp_session_dir(name);
    fs::remove_dir_all(&dir).ok();
    store::write_session_dir(&imported.bundle, &dir).unwrap();
    dir
}

#[test]
fn natural_adapter_names_view_and_priming_encoder() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = real_shape_session("natural");
    let d = dir.to_str().unwrap();
    let lazy = cached_session(&dir).unwrap();
    // origins use the adapter's internal names
    let origins = scrapelens_core::flow::value_origins(
        &lazy.session,
        &scrapelens_core::search::LazyBodies(&lazy),
        "har-0026",
        &crate::adapters::flow_options(),
    )
    .unwrap();
    let json = serde_json::to_string(&origins).unwrap();
    assert!(
        json.contains("XML.delta") || json.contains("XML.p."),
        "no internal adapter names"
    );
    // structured view: raw + named parts
    let request = lazy
        .session
        .requests
        .iter()
        .find(|r| r.id == "har-0026")
        .unwrap();
    let view = crate::adapters::view(&lazy, request, "request").unwrap();
    assert!(!view.fields.is_empty() && view.fields[0].error.is_none());
    assert!(view.fields[0]
        .parts
        .iter()
        .any(|p| p.name == "delta" || p.name.starts_with("p.")));
    assert!(!view.fields[0].raw.is_empty());
    assert!(crate::adapters::view(&lazy, request, "invalid-side").is_err());
    // the priming script uses the adapter's encoder and the preview says so
    let preview = export_preview(&dir, "har-0026", "priming", false, false).unwrap();
    assert_eq!(preview.format, "priming");
    assert_eq!(preview.adapter.as_deref(), Some("natural-ajax"));
    // `--lenient-parts` is an advanced option: off by default; when on, it generates the script without error (in this fixture the text comes out the same as strict)
    let lenient = export_preview(&dir, "har-0026", "priming", false, true).unwrap();
    assert_eq!(lenient.adapter.as_deref(), Some("natural-ajax"));
    let _ = d;
    fs::remove_dir_all(dir).ok();
}

#[test]
fn adapter_view_refuses_oversized_field_and_keeps_raw() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = real_shape_session("natural-big");
    let name = {
        let session: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("session.json")).unwrap()).unwrap();
        let req = session["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "har-0026")
            .unwrap();
        req["requestBody"]["attachment"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let big = format!("XML=v{}", "0".repeat(crate::adapters::MAX_FIELD_BYTES + 10));
    fs::write(dir.join("attachments").join(&name), big).unwrap();
    let lazy = cached_session(&dir).unwrap();
    let request = lazy
        .session
        .requests
        .iter()
        .find(|r| r.id == "har-0026")
        .unwrap();
    let view = crate::adapters::view(&lazy, request, "request").unwrap();
    assert_eq!(view.fields.len(), 1);
    let field = &view.fields[0];
    // needle must match `TOO_BIG_MESSAGE` in src-tauri/src/adapters.rs (not owned by this file)
    assert!(field
        .error
        .as_deref()
        .unwrap()
        .contains("field too large for the adapter view"));
    assert!(field.parts.is_empty());
    assert!(
        field.raw.starts_with("v000") && field.raw.len() < 70 * 1024,
        "raw cut, not whole"
    );
    fs::remove_dir_all(dir).ok();
}

fn sim_trace(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/bodies-search")
        .join(name)
        .display()
        .to_string()
}

#[test]
fn timeline_and_validate_execution_on_real_shape_with_sim_traces() {
    let _guard = CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let capture = real_shape_session("timeline-cap");
    // timeline: application events with the adapter label and collapsed groups
    let rt = tauri::async_runtime::block_on(session_timeline(session_token(&capture))).unwrap();
    assert!(rt.counts.events > 0 && rt.counts.protection > 0);
    let json = serde_json::to_value(&rt).unwrap();
    assert!(json["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["type"] == "group" && i["kind"] == "protection"));
    assert!(
        json["items"].as_array().unwrap().iter().any(|i| i["label"]
            .as_str()
            .is_some_and(|l| l.contains("cmd_consultar_placa"))),
        "event label from the adapter"
    );
    // validation: trace ok = equivalent; 403 = diverges; trace in a new 0700 folder
    let root = temp_session_dir("timeline-root");
    fs::remove_dir_all(&root).ok();
    fs::create_dir_all(&root).unwrap();
    let ok =
        validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-ok.json"), None)
            .unwrap();
    assert!(
        ok.validation
            .summary
            .starts_with("execution equivalent to capture"),
        "{}",
        ok.validation.summary
    );
    assert!(ok.validation.summary.contains("[mapped origin:"));
    // faithful trace (plan.version 2): no parameter or plan warning; only the mapped-origin one
    assert!(
        ok.validation
            .warnings
            .iter()
            .all(|w| w.starts_with("different application origins")),
        "a faithful trace must not generate warnings beyond the mapped-origin one: {:?}",
        ok.validation.warnings
    );
    assert!(
        // English and legacy Portuguese reason text (legacy matcher kept for old sessions).
        !ok.validation
            .warnings
            .iter()
            .any(|w| w.contains("parameter")
                || w.contains("plan")
                || w.contains("parâmetro")
                || w.contains("plano")),
        "spurious parameter/plan warnings: {:?}",
        ok.validation.warnings
    );
    assert!(
        // legacy Portuguese reason kept for old sessions
        ok.validation
            .steps
            .iter()
            .flat_map(|st| &st.expected)
            .any(|n| n.reason.contains("user parameter")
                || n.reason.contains("parâmetro do usuário")),
        "plate/CPF provided become expected (user parameter)"
    );
    let bad =
        validate_execution_blocking(&root, &capture, &sim_trace("trace-sim-403.json"), None)
            .unwrap();
    assert!(
        bad.validation.summary.starts_with("diverges at step 3"),
        "{}",
        bad.validation.summary
    );
    let down = validate_execution_blocking(
        &root,
        &capture,
        &sim_trace("trace-sim-incomplete.json"),
        None,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(down.validation.verdict).unwrap(),
        "incomplete"
    );
    assert!(
        down.validation
            .summary
            .starts_with("incomplete: stopped at step 1"),
        "{}",
        down.validation.summary
    );
    assert_ne!(ok.trace_dir, bad.trace_dir);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&bad.trace_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // actionable errors
    let invalid = root.join("not-a-trace.json");
    fs::write(&invalid, "{\"schema\":\"x\"}").unwrap();
    assert!(
        validate_execution_blocking(&root, &capture, invalid.to_str().unwrap(), None)
            .unwrap_err()
            .contains("invalid trace")
    );
    assert!(validate_execution_blocking(
        &root,
        &capture,
        &sim_trace("trace-sim-ok.json"),
        Some("no-equals-sign")
    )
    .unwrap_err()
    .contains("invalid origin mapping"));
    assert!(
        validate_execution_blocking(&root, &capture, "/does/not/exist.json", None).is_err()
    );
    // trace above 64 MiB: actionable error, without reading or creating a session
    let huge = root.join("huge.json");
    fs::File::create(&huge)
        .unwrap()
        .set_len(crate::validation::TRACE_MAX_BYTES + 1)
        .unwrap();
    let before = fs::read_dir(&root).unwrap().count();
    let err =
        validate_execution_blocking(&root, &capture, huge.to_str().unwrap(), None).unwrap_err();
    assert!(err.contains("larger than 64 MiB"), "{err}");
    assert_eq!(fs::read_dir(&root).unwrap().count(), before);
    fs::remove_dir_all(capture).ok();
    fs::remove_dir_all(root).ok();
}

/// Real Round 9 data for the UI harness:
/// `SL_SESSION=<folder> SL_TRACES=<a.json,b.json> SL_DUMP=<dir> cargo test -- --ignored dump_round9_evidence`.
#[test]
#[ignore]
fn dump_round9_evidence() {
    let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
    let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
    fs::create_dir_all(&out).unwrap();
    let t = tauri::async_runtime::block_on(session_timeline(session_token(Path::new(&dir))))
        .unwrap();
    fs::write(
        out.join("timeline.json"),
        serde_json::to_string(&t).unwrap(),
    )
    .unwrap();
    let root = out.join("traces");
    fs::create_dir_all(&root).unwrap();
    for (n, trace) in std::env::var("SL_TRACES")
        .expect("SL_TRACES")
        .split(',')
        .enumerate()
    {
        let r = validate_execution_blocking(&root, Path::new(&dir), trace, None).unwrap();
        fs::write(
            out.join(format!("validate-{n}.json")),
            serde_json::to_string(&r).unwrap(),
        )
        .unwrap();
    }
}

/// Real data (Natural adapter registered) for the UI harness:
/// `SL_SESSION=<folder> SL_DUMP=<dir> cargo test -- --ignored dump_adapter_evidence`.
#[test]
#[ignore]
fn dump_adapter_evidence() {
    let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
    let out = PathBuf::from(std::env::var("SL_DUMP").expect("SL_DUMP"));
    fs::create_dir_all(&out).unwrap();
    let lazy = cached_session(Path::new(&dir)).unwrap();
    let source = scrapelens_core::search::LazyBodies(&lazy);
    let opts = crate::adapters::flow_options();
    for request in &lazy.session.requests {
        let id = &request.id;
        let write = |name: &str, value: serde_json::Value| {
            fs::write(
                out.join(format!("{id}.{name}.json")),
                serde_json::to_string(&value).unwrap(),
            )
            .unwrap()
        };
        if let Ok(o) = scrapelens_core::flow::value_origins(&lazy.session, &source, id, &opts) {
            write("origins", serde_json::to_value(o).unwrap());
        }
        if let Ok(c) = scrapelens_core::flow::priming_chain(&lazy.session, &source, id, &opts) {
            write("chain", serde_json::to_value(c).unwrap());
        }
        for side in ["request", "response"] {
            if let Ok(v) = crate::adapters::view(&lazy, request, side) {
                if !v.fields.is_empty() {
                    write(side, serde_json::to_value(v).unwrap());
                }
            }
        }
    }
    for id in ["har-0026"] {
        if let Ok(p) = priming_preview(Path::new(&dir), id, false) {
            fs::write(
                out.join(format!("{id}.priming.json")),
                serde_json::to_string(&p).unwrap(),
            )
            .unwrap();
        }
    }
}

/// Real sanitization preview for the UI harness:
/// `SL_SESSION=<folder> SL_DUMP=<file.json> cargo test -- --ignored dump_sanitize_preview`.
#[test]
#[ignore]
fn dump_sanitize_preview() {
    let dir = std::env::var("SL_SESSION").expect("SL_SESSION");
    let out = std::env::var("SL_DUMP").expect("SL_DUMP");
    let preview = crate::export::sanitize_preview(Path::new(&dir)).unwrap();
    fs::write(out, serde_json::to_string_pretty(&preview).unwrap()).unwrap();
}

#[cfg(all(test, not(feature = "test-hooks")))]
mod test_switch_tests {
    use super::*;

    /// Release builds (no `test-hooks`) start captures with the normal settings, whatever
    /// the environment says: nothing here reads a test variable.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_capture_switches_are_the_normal_settings() {
        let switches = capture_test_switches();
        assert!(!switches.headless);
        assert!(!switches.ignore_cert);
        assert!(!switches.proxy_bypass_loopback);
        assert_eq!(switches.network, scrapelens_capture::NetworkMode::Open);
    }

    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_has_no_test_start_url_suggestion() {
        assert_eq!(test_capture_url(), "");
    }
}

#[cfg(test)]
mod proxy_command_tests {
    use super::*;
    use scrapelens_capture::proxy::ProxyLink;
    use std::sync::Mutex;

    #[test]
    fn a_valid_link_is_kept_in_memory_and_only_its_address_is_returned() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        let link =
            parse_and_store(&slot, "http://reader:Hunter2-secret@proxy.example:8080").unwrap();
        assert_eq!(link.server_url(), "http://proxy.example:8080");
        let info = serde_json::to_string(&crate::capture_proxy::ProxyInfo::of(&link)).unwrap();
        assert!(!info.contains("Hunter2"), "{info}");
        assert!(!info.contains("reader"), "{info}");
        // The memory copy keeps the credentials for the relay.
        assert!(slot.lock().unwrap().as_ref().unwrap().authenticated());
    }

    #[test]
    fn an_invalid_link_is_refused_and_its_text_is_never_echoed() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        for input in [
            "socks4://reader:Hunter2-secret@proxy.example:1080",
            "http://reader:Hunter2-secret@proxy.example:99999",
            "http://reader:Hunter2-secret@proxy.example:8080/path",
            "http://reader:Hunter2-secret@proxy.example:8080\u{7}",
        ] {
            let error = parse_and_store(&slot, input).unwrap_err();
            assert!(!error.contains("Hunter2"), "{error}");
            assert!(!error.contains("reader"), "{error}");
            assert!(
                !error.contains("proxy.example"),
                "the input is not repeated: {error}"
            );
        }
        assert!(
            slot.lock().unwrap().is_none(),
            "a refused link replaces nothing"
        );
    }

    #[test]
    fn changing_or_clearing_the_proxy_is_refused_while_recording() {
        assert!(ensure_proxy_editable(false).is_ok());
        let err = ensure_proxy_editable(true).unwrap_err();
        assert!(err.contains("Stop the capture"), "{err}");
    }

    #[test]
    fn socks4_gets_its_own_message() {
        let slot: Mutex<Option<ProxyLink>> = Mutex::new(None);
        let error = parse_and_store(&slot, "socks4://proxy.example:1080").unwrap_err();
        assert!(error.contains("socks4 is not supported"), "{error}");
    }
}

#[cfg(test)]
mod capture_start_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    fn temp_session_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("sl-start-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn startup_error_from_the_capture_thread_is_shown_not_the_timeout() {
        let dir = temp_session_dir("early-error");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, _stop_rx) = mpsc::channel::<()>();
        let message =
            "cookies could not be read: the profile database is locked; close Chrome and try again";
        let join = thread::spawn(move || {
            // Same as `capture::run` returning early with `?` before signalling readiness.
            drop(ready_tx);
            Err::<(), String>(message.to_string())
        });
        let started = Instant::now();
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, CAPTURE_READY_TIMEOUT)
            .err()
            .unwrap();
        assert_eq!(error, message);
        assert!(!error.contains("not ready within"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must not wait for the 35 s timeout"
        );
        assert!(
            !dir.exists(),
            "the session folder of a failed start is removed"
        );
    }

    #[test]
    fn silent_thread_still_times_out_and_is_stopped() {
        let dir = temp_session_dir("silent");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            // Keeps the channel open and only ends when the caller asks it to stop.
            let _keep = ready_tx;
            let _ = stop_rx.recv();
            Err::<(), String>("stopped".to_string())
        });
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, Duration::from_millis(50))
            .err()
            .unwrap();
        assert!(error.contains("not ready within"), "{error}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while dir.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !dir.exists(),
            "the reaper removes the folder after the thread ends"
        );
    }

    #[test]
    fn stuck_capture_thread_never_blocks_the_start_and_is_reaped_later() {
        // The thread ignores the stop request until something external releases it, like a
        // keyring unlock prompt that never completes. The start must still return promptly.
        let dir = temp_session_dir("stuck");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_in_thread = stopped.clone();
        let join = thread::spawn(move || {
            let _keep = ready_tx;
            let _ = release_rx.recv(); // blocked "in the keyring"; does not read `stop` yet
            if stop_rx.try_recv().is_ok() {
                stopped_in_thread.store(true, Ordering::SeqCst);
            }
            Err::<(), String>("cookie key lookup was abandoned".to_string())
        });

        let started = Instant::now();
        let error = await_capture_ready(&ready_rx, &stop_tx, join, &dir, Duration::from_millis(50))
            .err()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the start must not wait for the stuck thread"
        );
        assert!(error.contains("not ready within"), "{error}");
        assert!(
            dir.exists(),
            "the folder stays until the thread really ends"
        );

        // The thread ends later: the reaper removes its folder and the stop request was sent.
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while dir.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !dir.exists(),
            "the reaper removes the folder once the thread ends"
        );
        assert!(
            stopped.load(Ordering::SeqCst),
            "the stop request reached the thread"
        );
    }

    #[test]
    fn ready_signal_returns_the_running_capture() {
        let dir = temp_session_dir("ready");
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            let _ = ready_tx.send(Ok(()));
            let _ = stop_rx.recv();
            Ok::<(), String>(())
        });
        let join = await_capture_ready(&ready_rx, &stop_tx, join, &dir, CAPTURE_READY_TIMEOUT)
            .expect("ready");
        let _ = stop_tx.send(());
        assert!(join.join().unwrap().is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod cookie_source_tests {
    use super::*;

    #[test]
    fn validates_sources_without_exposing_database_path() {
        let sources = vec![CookieSourceDto::from(
            scrapelens_capture::BrowserCookieSource {
                id: "chrome:Default".into(),
                browser: "Google Chrome".into(),
                profile: "Default".into(),
                label: "Google Chrome — Default".into(),
                kind: scrapelens_capture::BrowserKind::Chromium,
                db_path: PathBuf::from("/private/cookie-database"),
            },
        )];
        assert!(resolve_cookie_source(None, &sources).unwrap().is_none());
        assert!(resolve_cookie_source(Some(""), &sources).unwrap().is_none());
        assert!(resolve_cookie_source(Some("chrome:deleted"), &sources).is_err());
        assert_eq!(
            resolve_cookie_source(Some("chrome:Default"), &sources)
                .unwrap()
                .unwrap()
                .id,
            "chrome:Default"
        );
        let json = serde_json::to_string(&sources).unwrap();
        assert!(!json.contains("dbPath") && !json.contains("cookie-database"));
    }
}

/// A session token for a folder a test created (what the backend issues for a session it opened).
#[cfg(test)]
fn session_token(dir: &Path) -> String {
    grants::issue(grants::Kind::Session, dir).expect("token for the test folder")
}

/// T17: the webview gets paths back only as tokens the backend issued.
#[cfg(test)]
mod grant_tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("sl-grant-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn read_body_refuses_a_path_and_takes_a_session_token() {
        let dir = scratch("body");
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("attachments").join("t.txt"), b"hello").unwrap();
        let token = grants::issue(grants::Kind::Session, &dir).unwrap();
        // Without a token, a path is refused: the webview cannot name a folder.
        assert!(session_dir_for_token(&dir.display().to_string()).is_err());
        assert!(session_dir_for_token("not-a-token").is_err());
        // Normal flow: the token gives the folder, and the body is read from it.
        let folder = session_dir_for_token(&token).unwrap();
        let body = read_body_blocking(&folder, "t.txt", 1000).unwrap();
        assert_eq!(body.kind, "text");
        assert_eq!(body.text.as_deref(), Some("hello"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_token_does_not_read_a_session_body() {
        let dir = scratch("kind");
        let file = dir.join("export.sh");
        let saved = finish_save(&file, "#!/bin/sh\n").unwrap();
        assert!(session_dir_for_token(&saved.token).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reveal_refuses_a_path_and_an_unknown_token_and_accepts_granted_ones() {
        let dir = scratch("reveal");
        let file = dir.join("a.txt");
        // A path is refused before any program would be started.
        assert!(reveal_target(&file.display().to_string()).is_err());
        assert!(reveal_target(&dir.display().to_string()).is_err());
        assert!(reveal_target("0123456789abcdef0123456789abcdef").is_err());
        // Granted tokens resolve to the path, for the kind that is allowed.
        let session = grants::issue(grants::Kind::Session, &dir).unwrap();
        assert_eq!(reveal_target(&session).unwrap(), dir);
        let saved = finish_save(&file, "x").unwrap();
        assert_eq!(reveal_target(&saved.token).unwrap(), file);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn import_files_and_sessions_do_not_stand_in_for_each_other() {
        let dir = scratch("kinds");
        let file = dir.join("capture.har");
        fs::write(&file, b"{}").unwrap();
        let import = grants::issue(grants::Kind::ImportFile, &file).unwrap();
        let session = session_token(&dir);
        // A path is refused for an import, and an import token is refused for a session folder.
        assert!(import_path_for_token(&file.display().to_string()).is_err());
        assert!(session_dir_for_token(&import).is_err());
        assert!(import_path_for_token(&session).is_err());
        // The normal flow: each token gives its own path.
        assert_eq!(
            import_path_for_token(&import).unwrap(),
            file.display().to_string()
        );
        assert_eq!(
            session_dir_for_token(&session).unwrap(),
            dir.display().to_string()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_saved_export_is_granted_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("save");
        let target = dir.join("export.sh");
        let saved = finish_save(&target, "#!/bin/sh\n").unwrap();
        assert_eq!(saved.bytes, 10);
        assert_eq!(reveal_target(&saved.token).unwrap(), target);
        assert!(
            finish_save(&target, "again").is_err(),
            "an existing file is not overwritten"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(&dir).ok();
    }
}
