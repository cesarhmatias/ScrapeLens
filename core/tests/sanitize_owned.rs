//! P7 (docs/18): `sanitize_bundle_owned` consome o bundle e sanitiza no lugar; o resultado
//! tem de ser idêntico ao de `sanitize_bundle` (por referência, sobre uma cópia).

use scrapelens_core::export::sanitize::{sanitize_bundle, sanitize_bundle_owned, SanitizeOptions};

fn repo(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(path)
}

fn bundles() -> Vec<(String, scrapelens_core::SessionBundle)> {
    let mut out = Vec::new();
    let har = std::fs::read(repo("fixtures/aceite/sanitize/secret.har")).unwrap();
    out.push((
        "secret.har".into(),
        scrapelens_core::import_har(&har).unwrap().bundle,
    ));
    for dir in ["h1-page", "h2-page", "h3-page", "contract-h1"] {
        let base = repo("experiments/results").join(dir);
        let (Ok(cdp), Ok(netlog)) = (
            std::fs::read(base.join("cdp-events.jsonl")),
            std::fs::read(base.join("chrome-netlog.json")),
        ) else {
            continue;
        };
        let imported = scrapelens_core::parse::import_capture(
            &cdp,
            &netlog,
            scrapelens_core::correlate::CorrelationOptions::default(),
        )
        .unwrap();
        out.push((dir.into(), imported.bundle));
    }
    out
}

#[test]
fn owned_and_borrowed_sanitization_give_identical_exports() {
    let mut compared = 0;
    for keep_raw in [false, true] {
        let options = SanitizeOptions {
            keep_raw_events: keep_raw,
            omit_unstructured_bodies: false,
            ..SanitizeOptions::default()
        };
        for (name, bundle) in bundles() {
            let by_ref = sanitize_bundle(&bundle, &options);
            let owned = sanitize_bundle_owned(bundle, &options);
            assert_eq!(
                serde_json::to_vec(&by_ref.bundle.session).unwrap(),
                serde_json::to_vec(&owned.bundle.session).unwrap(),
                "{name}: sessão"
            );
            assert_eq!(
                by_ref.bundle.attachments, owned.bundle.attachments,
                "{name}: anexos"
            );
            assert_eq!(
                by_ref.bundle.cdp_events_jsonl, owned.bundle.cdp_events_jsonl,
                "{name}"
            );
            assert_eq!(
                by_ref.bundle.netlog_json, owned.bundle.netlog_json,
                "{name}"
            );
            assert_eq!(by_ref.redactions, owned.redactions, "{name}: contadores");
            assert_eq!(
                by_ref.omitted_attachments, owned.omitted_attachments,
                "{name}"
            );
            assert_eq!(
                serde_json::to_vec(&by_ref.warnings).unwrap(),
                serde_json::to_vec(&owned.warnings).unwrap(),
                "{name}: avisos"
            );
            compared += 1;
        }
    }
    assert!(compared >= 4, "{compared}");
}
