//! Regression: `target.url` and `initiator.url` (incl. the stack top) are also
//! sanitized on export (synthetic session, fake values).

use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::model::entities::{Initiator, InitiatorFrame};
use scrapelens_core::model::{TargetKind, TargetProvenance};

#[test]
fn target_and_initiator_urls_are_sanitized() {
    let har = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/aceite/sanitize/secret.har"),
    )
    .unwrap();
    let mut imported = scrapelens_core::import_har(&har).unwrap();
    let request = &mut imported.bundle.session.requests[0];
    request.target = Some(TargetProvenance {
        target_id: Some("T1".into()),
        kind: TargetKind::Page,
        url: Some("https://x.invalid/p?token=SECRET-TARGET-TOKEN&page=2#SECRET-TARGET-FRAG".into()),
        ..TargetProvenance::default()
    });
    request.attempts[0].initiator = Some(Initiator {
        kind: "script".into(),
        url: Some("https://x.invalid/a.js?access_token=SECRET-INIT-TOKEN".into()),
        line_number: Some(3),
        stack_top: Some(InitiatorFrame {
            url: Some("https://x.invalid/b.js?api_key=SECRET-FRAME-KEY".into()),
            function: Some("f".into()),
            line_number: Some(9),
        }),
    });

    let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let json = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(!json.contains("SECRET-"), "leaked: {json}");
    let sanitized = &export.bundle.session.requests[0];
    let target_url = sanitized.target.as_ref().unwrap().url.as_ref().unwrap();
    assert!(
        target_url.starts_with("https://x.invalid/p?"),
        "{target_url}"
    );
    assert!(
        target_url.contains("page=2"),
        "non-sensitive parameters are kept: {target_url}"
    );
    let initiator = sanitized.attempts[0].initiator.as_ref().unwrap();
    assert!(initiator
        .url
        .as_ref()
        .unwrap()
        .starts_with("https://x.invalid/a.js"));
    assert!(initiator
        .stack_top
        .as_ref()
        .unwrap()
        .url
        .as_ref()
        .unwrap()
        .starts_with("https://x.invalid/b.js"));
    // Function and line (not sensitive) are preserved.
    assert_eq!(
        initiator.stack_top.as_ref().unwrap().function.as_deref(),
        Some("f")
    );
}
