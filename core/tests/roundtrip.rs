//! Round-trip of the v1 format and sanitized export to disk.

use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::model::Body;
use scrapelens_core::parse::import_har;
use scrapelens_core::store;

fn har() -> Vec<u8> {
    include_bytes!("fixtures/har-minimal.json").to_vec()
}

#[test]
fn session_roundtrip_keeps_original_order_and_attachments() {
    let imported = import_har(&har()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("session");
    store::write_session_dir(&imported.bundle, &dir).unwrap();

    let again = scrapelens_core::import_session_dir(&dir).unwrap();
    assert_eq!(again.bundle.session.requests.len(), 1);
    let request = &again.bundle.session.requests[0];
    assert_eq!(
        request
            .request_headers
            .get_all("x-rep")
            .iter()
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert_eq!(
        again
            .bundle
            .attachment("har-entry-0000.request.bin")
            .unwrap(),
        b"hello=world"
    );
    assert_eq!(again.bundle.session.schema_version, 1);
    assert_eq!(
        again.bundle.session.requests[0].url,
        "https://api.demo.invalid/v1/items?page=2"
    );
    let counts = &again.bundle.session.session.completeness.counts;
    assert_eq!(counts.source_events, 1);
    assert_eq!(counts.source_events_used, 1);
    assert_eq!(counts.source_events_unknown, 0);
}

#[test]
fn netlog_counts_survive_roundtrip() {
    let imported =
        scrapelens_core::import_netlog(include_bytes!("fixtures/netlog-h2.json")).unwrap();
    let counts = &imported.bundle.session.session.completeness.counts;
    assert_eq!(counts.source_events, 8);
    assert_eq!(counts.source_events_used, 7);
    assert_eq!(counts.source_events_unknown, 1);

    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("netlog-session");
    store::write_session_dir(&imported.bundle, &dir).unwrap();
    let again = scrapelens_core::import_session_dir(&dir).unwrap();
    let counts = &again.bundle.session.session.completeness.counts;
    assert_eq!(counts.source_events, 8);
    assert_eq!(counts.source_events_used, 7);
    assert_eq!(counts.source_events_unknown, 1);
    assert_eq!(again.bundle.session.requests.len(), 1);
}

#[test]
fn sanitized_session_writes_only_sanitized_attachments_and_no_raw_events() {
    let mut imported = import_har(&har()).unwrap();
    imported.bundle.cdp_events_jsonl = Some(b"{\"method\":\"Network.x\"}".to_vec());
    imported.bundle.netlog_json = Some(b"{}".to_vec());
    // Add a sensitive header to prove redaction on disk.
    let request = &mut imported.bundle.session.requests[0];
    let provenance = request.request_headers.headers[0].provenance.clone();
    request
        .request_headers
        .add("Authorization", "Bearer top-secret", &provenance);
    request.url = "https://api.demo.invalid/v1/items?page=2&token=secret".to_string();
    request.request_body = Body::captured("har-entry-0000.request.bin", 11, &provenance)
        .with_content_type("text/plain");

    let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sanitized");
    export.write_to(&dir).unwrap();

    let reimported = scrapelens_core::import_session_dir(&dir).unwrap();
    let session = &reimported.bundle.session;
    assert!(session.requests[0]
        .request_headers
        .first_value("authorization")
        .unwrap()
        .contains("REDACTED"));
    assert!(session.requests[0].url.contains("token=%5BREDACTED%5D"));
    assert!(session.requests[0].url.contains("page=2"));
    assert!(!session.requests[0].url.contains("secret"));
    assert!(reimported.bundle.cdp_events_jsonl.is_none());
    assert!(reimported.bundle.netlog_json.is_none());
    assert!(session
        .session
        .labels
        .iter()
        .any(|label| label == "sanitized"));
    // No original attachment is copied; unstructured text/plain body is omitted.
    assert!(!reimported
        .bundle
        .attachments
        .keys()
        .any(|name| name == "har-entry-0000.request.bin"));
    assert!(export
        .warnings
        .iter()
        .any(|warning| warning.code == "sanitize.attachment_omitted"));
}

#[test]
fn sanitize_refuses_to_overwrite_an_existing_session_dir() {
    let imported = import_har(&har()).unwrap();
    let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sanitized");
    export.write_to(&dir).unwrap();
    let error = export.write_to(&dir).unwrap_err();
    assert!(error.to_string().contains("already contains a session"));
}

#[test]
fn stored_permissions_are_private_after_sanitize_write() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let imported = import_har(&har()).unwrap();
        let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("sanitized");
        export.write_to(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let mode = std::fs::metadata(dir.join("session.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
