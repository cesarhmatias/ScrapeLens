//! P7 (docs/18): `sanitize_bundle_owned` consumes the bundle and sanitizes it in place; the
//! result must be identical to that of `sanitize_bundle` (by reference, over a copy).
//!
//! Round 15: comparing the two functions only proves that `.clone()` does not change the
//! result (`sanitize_bundle` delegates to `_owned`), with no independent oracle. So the test
//! also pins FNV-1a hashes of the WHOLE sanitized output (session, attachments, raw events,
//! redaction counters, omitted attachments and warnings) of the bundles from `bundles()`.
//!
//! Regenerate (only if the OUTPUT changes on purpose): `PRINT_SANITIZE_GOLDEN=1 cargo test
//! --test sanitize_owned -- --nocapture` and paste the table.

use std::collections::BTreeMap;

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

fn fnv1a(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// Deterministic fingerprint, independent of the whole sanitized output.
fn fingerprint(export: &scrapelens_core::export::sanitize::SanitizedExport) -> (u64, usize) {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut len = 0usize;
    let mut feed = |bytes: &[u8]| {
        fnv1a(&mut hash, bytes);
        len += bytes.len();
    };
    let session = serde_json::to_vec(&export.bundle.session).unwrap();
    feed(b"session\0");
    feed(&session);
    for (name, bytes) in &export.bundle.attachments {
        feed(b"attachment\0");
        feed(name.as_bytes());
        feed(b"\0");
        feed(bytes);
    }
    match &export.bundle.cdp_events_jsonl {
        Some(bytes) => {
            feed(b"cdp\0");
            feed(bytes);
        }
        None => feed(b"cdp-none\0"),
    }
    match &export.bundle.netlog_json {
        Some(bytes) => {
            feed(b"netlog\0");
            feed(bytes);
        }
        None => feed(b"netlog-none\0"),
    }
    for (key, count) in &export.redactions {
        feed(b"redaction\0");
        feed(key.as_bytes());
        feed(&count.to_le_bytes());
    }
    for name in &export.omitted_attachments {
        feed(b"omitted\0");
        feed(name.as_bytes());
    }
    let warnings = serde_json::to_vec(&export.warnings).unwrap();
    feed(b"warnings\0");
    feed(&warnings);
    (hash, len)
}

#[test]
fn owned_and_borrowed_sanitization_give_identical_exports() {
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
                "{name}: session"
            );
            assert_eq!(
                by_ref.bundle.attachments, owned.bundle.attachments,
                "{name}: attachments"
            );
            assert_eq!(
                by_ref.bundle.cdp_events_jsonl, owned.bundle.cdp_events_jsonl,
                "{name}"
            );
            assert_eq!(
                by_ref.bundle.netlog_json, owned.bundle.netlog_json,
                "{name}"
            );
            assert_eq!(by_ref.redactions, owned.redactions, "{name}: counters");
            assert_eq!(
                by_ref.omitted_attachments, owned.omitted_attachments,
                "{name}"
            );
            assert_eq!(
                serde_json::to_vec(&by_ref.warnings).unwrap(),
                serde_json::to_vec(&owned.warnings).unwrap(),
                "{name}: warnings"
            );
        }
    }
}

#[test]
fn sanitized_output_is_pinned_by_independent_hashes() {
    if std::env::var("PRINT_SANITIZE_GOLDEN").is_ok() {
        for keep_raw in [false, true] {
            let options = SanitizeOptions {
                keep_raw_events: keep_raw,
                omit_unstructured_bodies: false,
                ..SanitizeOptions::default()
            };
            for (name, bundle) in bundles() {
                let (hash, len) = fingerprint(&sanitize_bundle(&bundle, &options));
                println!("GOLDEN (\"{name}\", {keep_raw}, 0x{hash:016x}, {len}),");
            }
        }
        return;
    }
    let golden: BTreeMap<(&str, bool), (u64, usize)> = GOLDEN
        .iter()
        .map(|(name, keep_raw, hash, len)| ((*name, *keep_raw), (*hash, *len)))
        .collect();
    let mut compared = 0;
    for keep_raw in [false, true] {
        let options = SanitizeOptions {
            keep_raw_events: keep_raw,
            omit_unstructured_bodies: false,
            ..SanitizeOptions::default()
        };
        for (name, bundle) in bundles() {
            let key = (name.as_str(), keep_raw);
            let (expected_hash, expected_len) = golden
                .get(&key)
                .unwrap_or_else(|| panic!("no hash for {name} keep_raw={keep_raw}"));
            let (hash, len) = fingerprint(&sanitize_bundle(&bundle, &options));
            assert_eq!(
                (hash, len),
                (*expected_hash, *expected_len),
                "{name} keep_raw={keep_raw}: the sanitized output changed"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, GOLDEN.len(), "each bundle must have a hash");
}

/// (bundle, keep_raw, FNV-1a hash, total size) of the sanitized output.
const GOLDEN: &[(&str, bool, u64, usize)] = &[
    ("secret.har", false, 0x269832bf48cd1ac6, 13915),
    ("h1-page", false, 0xc57671997d22a007, 427769),
    ("h2-page", false, 0xeb5d697dd868ae2d, 539616),
    ("h3-page", false, 0xd00bb0e4df83955c, 546464),
    ("contract-h1", false, 0x54a596836bd829da, 522343),
    ("secret.har", true, 0x269832bf48cd1ac6, 13915),
    ("h1-page", true, 0xa5ecb3c1dede4920, 858881),
    ("h2-page", true, 0x909f004e9fd22aac, 1109522),
    ("h3-page", true, 0x72f02bf288656cf1, 1144111),
    ("contract-h1", true, 0xfb21dd9b55f9379e, 1912663),
];
