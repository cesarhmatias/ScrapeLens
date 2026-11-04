//! Lazy bundle: same search as the eager one, without retaining bytes, with refusals.

use scrapelens_core::lazy::BODY_READ_LIMIT;
use scrapelens_core::search::{search, search_lazy, SearchQuery};
use scrapelens_core::{import_session_dir, open_session_dir_lazy, store, SessionBundle};
use serde_json::json;

fn write_session(dir: &std::path::Path) -> SessionBundle {
    let events: Vec<String> = [
        ("1.1", "POST", "cmd=cmd_consultar_placa&placa=ABC1D23"),
        ("1.2", "POST", "cmd=cmd_nova&placa=ZZZ9Z99"),
    ]
    .iter()
    .enumerate()
    .map(|(i, (id, method, body))| {
        json!({"method": "Network.requestWillBeSent", "params": {
            "requestId": id, "loaderId": "L", "timestamp": 1.0 + i as f64, "wallTime": 1793046001.0 + i as f64,
            "request": {"url": "https://example.test/connector", "method": method,
                "headers": {"content-type": "application/x-www-form-urlencoded"}, "postData": body, "hasPostData": true},
            "type": "XHR", "frameId": "F"}})
        .to_string()
    })
    .collect();
    let bodies: Vec<String> = [("1.1", "cmd=cmd_consultar_placa&placa=ABC1D23"), ("1.2", "cmd=cmd_nova&placa=ZZZ9Z99")]
        .iter()
        .map(|(id, data)| {
            json!({"v":1,"requestId":id,"attemptIndex":0,"kind":"request","state":"captured","encoding":"utf8",
                "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":1.0})
            .to_string()
        })
        .collect();
    let capture =
        scrapelens_core::parse::cdp::parse_cdp_jsonl((events.join("\n") + "\n").as_bytes())
            .unwrap();
    let (mut session, _) = scrapelens_core::parse::cdp::build_cdp_session(&capture);
    let mut attachments = Default::default();
    scrapelens_core::parse::cdp_bodies::apply_cdp_bodies(
        &mut session,
        &mut attachments,
        (bodies.join("\n") + "\n").as_bytes(),
    );
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    store::write_session_dir(&bundle, dir).unwrap();
    bundle
}

#[test]
fn lazy_search_equals_eager_and_retains_no_bytes() {
    let dir = tempfile::tempdir().unwrap();
    write_session(dir.path());
    let eager = import_session_dir(dir.path()).unwrap().bundle;
    let (lazy, report) = open_session_dir_lazy(dir.path()).unwrap();
    assert_eq!(
        report.attachments_loaded, 0,
        "no attachment read on open"
    );
    for text in [
        "cmd_consultar_placa",
        "ABC1D23",
        "cmd_nova",
        "connector",
        "zzzz",
    ] {
        let q = SearchQuery::new(text);
        let (a, b) = (search(&eager, &q), search_lazy(&lazy, &q));
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap(),
            "{text}"
        );
    }
    assert_eq!(lazy.session.requests.len(), 2);
    let bundle = lazy.into_bundle().unwrap();
    assert_eq!(bundle.attachments.len(), 2);
}

#[cfg(unix)]
#[test]
fn lazy_refuses_symlinks_and_reports_missing() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = write_session(dir.path());
    let name = bundle.attachments.keys().next().unwrap().clone();
    let target = dir.path().join("attachments").join(&name);
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, "cmd_consultar_placa segredo").unwrap();
    std::fs::remove_file(&target).unwrap();
    std::os::unix::fs::symlink(&outside, &target).unwrap();
    let other = bundle.attachments.keys().nth(1).unwrap().clone();
    std::fs::remove_file(dir.path().join("attachments").join(&other)).unwrap();

    let (lazy, report) = open_session_dir_lazy(dir.path()).unwrap();
    let codes: Vec<_> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"attachment.unsafe"), "{codes:?}");
    assert!(codes.contains(&"attachment.missing"), "{codes:?}");
    assert!(lazy.read_attachment(&name, 100).is_err());
    let found = search_lazy(&lazy, &SearchQuery::new("segredo"));
    assert!(
        found.matches.is_empty(),
        "content outside the session must not be readable"
    );
}

#[test]
fn lazy_read_is_capped_and_marks_search_partial() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = write_session(dir.path());
    let name = bundle.attachments.keys().next().unwrap().clone();
    let big = vec![b'a'; BODY_READ_LIMIT as usize + 10];
    std::fs::write(dir.path().join("attachments").join(&name), &big).unwrap();
    let (lazy, _) = open_session_dir_lazy(dir.path()).unwrap();
    let (bytes, cut) = lazy.read_attachment(&name, BODY_READ_LIMIT).unwrap();
    assert_eq!(bytes.len() as u64, BODY_READ_LIMIT);
    assert!(cut);
    let found = search_lazy(&lazy, &SearchQuery::new("zzzz"));
    assert!(found.partial);
}

#[test]
fn eager_import_reports_invalid_json_and_missing_schema() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("session.json"), "{\"requests\": []}").unwrap();
    assert!(matches!(
        import_session_dir(dir.path()),
        Err(scrapelens_core::CoreError::MissingField { .. })
    ));
    std::fs::write(dir.path().join("session.json"), "{\"schemaVersion\": 1, ").unwrap();
    assert!(matches!(
        import_session_dir(dir.path()),
        Err(scrapelens_core::CoreError::Json { .. })
    ));
    std::fs::write(dir.path().join("session.json"), "{\"schemaVersion\": 99}").unwrap();
    assert!(matches!(
        import_session_dir(dir.path()),
        Err(scrapelens_core::CoreError::UnsupportedSchema { .. })
    ));
}
