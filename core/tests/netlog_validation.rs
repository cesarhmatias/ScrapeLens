//! P1 (docs/18): `netlog.json` is validated with `IgnoredAny` (without building the DOM). The verdict
//! must be the same as `Value`'s, and the import keeps warning only when the file is invalid.

use scrapelens_core::store::write_session_dir;
use serde_json::Value;

fn bundle() -> scrapelens_core::SessionBundle {
    let har = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/acceptance/sanitize/secret.har"),
    )
    .unwrap();
    scrapelens_core::import_har(&har).unwrap().bundle
}

fn samples() -> Vec<Vec<u8>> {
    let deep_ok = format!("{}{}", "[".repeat(100), "]".repeat(100));
    let deep_bad = format!("{}{}", "[".repeat(300), "]".repeat(300));
    vec![
        br#"{"constants":{},"events":[]}"#.to_vec(),
        br#"[1,2,3]"#.to_vec(),
        // non-ASCII input inside a JSON string: the verdict must not depend on it
        "  {\"events\":[{\"a\":\"é\"}]}  ".as_bytes().to_vec(),
        br#"{"events":["#.to_vec(),
        br#"{} x"#.to_vec(),
        br#"{"a":1,"a":2}"#.to_vec(),
        b"".to_vec(),
        b"\xff\xfe".to_vec(),
        br#"{"events":[1,2,,3]}"#.to_vec(),
        deep_ok.into_bytes(),
        deep_bad.into_bytes(),
        br#"nul"#.to_vec(),
    ]
}

#[test]
fn stream_validator_gives_the_same_verdict_as_value_including_the_recursion_limit() {
    // `IgnoredAny` would accept 300 levels (it skips the recursion limit); the core's validator does not.
    let deep = format!("{}{}", "[".repeat(300), "]".repeat(300));
    assert!(serde_json::from_slice::<serde::de::IgnoredAny>(deep.as_bytes()).is_ok());
    assert!(serde_json::from_slice::<Value>(deep.as_bytes()).is_err());
    for bytes in samples() {
        let by_value = serde_json::from_slice::<Value>(&bytes).is_ok();
        let warned = import_with_netlog(&bytes);
        assert_eq!(
            !by_value,
            warned,
            "{:?}",
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(40)
                .collect::<String>()
        );
    }
    // At the limit boundary (127 passes, 128 does not), like `Value`.
    for n in [126usize, 127, 128, 129] {
        let s = format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(
            !serde_json::from_slice::<Value>(s.as_bytes()).is_ok(),
            import_with_netlog(s.as_bytes()),
            "depth {n}"
        );
    }
}

fn import_with_netlog(bytes: &[u8]) -> bool {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("s");
    write_session_dir(&bundle(), &dir).unwrap();
    std::fs::write(dir.join("netlog.json"), bytes).unwrap();
    let imported = scrapelens_core::import_session_dir(&dir).unwrap();
    imported
        .bundle
        .session
        .warnings
        .iter()
        .any(|w| w.code == "session.netlog_invalid")
        || imported
            .report
            .warnings
            .iter()
            .any(|w| w.code == "session.netlog_invalid")
}

#[test]
fn import_warns_about_invalid_netlog_only() {
    let root = tempfile::tempdir().unwrap();
    for (i, bytes) in samples().into_iter().enumerate() {
        let dir = root.path().join(format!("s{i}"));
        write_session_dir(&bundle(), &dir).unwrap();
        std::fs::write(dir.join("netlog.json"), &bytes).unwrap();
        let imported = scrapelens_core::import_session_dir(&dir).unwrap();
        let warned = imported
            .bundle
            .session
            .warnings
            .iter()
            .any(|w| w.code == "session.netlog_invalid")
            || imported
                .report
                .warnings
                .iter()
                .any(|w| w.code == "session.netlog_invalid");
        let valid = serde_json::from_slice::<Value>(&bytes).is_ok();
        assert_eq!(warned, !valid, "{:?}", String::from_utf8_lossy(&bytes));
    }
}
