//! P3 (docs/18): the CDP×NetLog correlation uses an index by (method, canonical URL)
//! instead of scanning every pair. The output must be IDENTICAL. This test imports all the
//! real captures and versioned fixtures (`import_capture_with_bodies`) and checks, byte by
//! byte, the serialized `session.json` (indented JSON) and the attachments against the hash
//! recorded BEFORE the change (FNV-1a 64 bits + size).
//!
//! Round 15: the 6 `multi-target-*` entries (raw data in `experiments/.gitignore`) are
//! optional and checked only when present; the 23 versioned ones are required.
//!
//! Regenerate (only if the OUTPUT changes on purpose): `PRINT_GOLDEN=1 cargo test --test
//! correlation_identity -- --nocapture` and paste the table.

use std::path::Path;

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::parse::import_capture_with_bodies;

/// (directory relative to the repository root, NetLog file name)
const INPUTS: &[(&str, &str)] = &[
    ("experiments/results/contract-h1", "chrome-netlog.json"),
    ("experiments/results/contract-h2", "chrome-netlog.json"),
    ("experiments/results/contract-h3", "chrome-netlog.json"),
    ("experiments/results/h1-cookieprobe", "chrome-netlog.json"),
    ("experiments/results/h1-ordered", "chrome-netlog.json"),
    ("experiments/results/h1-page", "chrome-netlog.json"),
    ("experiments/results/h1-plain", "chrome-netlog.json"),
    ("experiments/results/h1-set3", "chrome-netlog.json"),
    ("experiments/results/h2-cookieprobe", "chrome-netlog.json"),
    ("experiments/results/h2-ordered", "chrome-netlog.json"),
    ("experiments/results/h2-page", "chrome-netlog.json"),
    ("experiments/results/h2-plain", "chrome-netlog.json"),
    ("experiments/results/h2-set3", "chrome-netlog.json"),
    ("experiments/results/h3-cookieprobe", "chrome-netlog.json"),
    ("experiments/results/h3-ordered", "chrome-netlog.json"),
    ("experiments/results/h3-page", "chrome-netlog.json"),
    ("experiments/results/h3-plain", "chrome-netlog.json"),
    ("experiments/results/h3-set3", "chrome-netlog.json"),
    (
        "experiments/results/multi-target-attach-probe/headful",
        "chrome-netlog.json",
    ),
    (
        "experiments/results/multi-target-attach-probe/headless",
        "chrome-netlog.json",
    ),
    (
        "experiments/results/multi-target-official/no-wait",
        "chrome-netlog.json",
    ),
    (
        "experiments/results/multi-target-official/with-wait",
        "chrome-netlog.json",
    ),
    (
        "experiments/results/multi-target-smoke/no-wait",
        "chrome-netlog.json",
    ),
    (
        "experiments/results/multi-target-smoke/with-wait",
        "chrome-netlog.json",
    ),
    ("fixtures/acceptance/sanitize/session", "netlog.json"),
    (
        "src-tauri/evidence/bodies-search/multi-target-session",
        "netlog.json",
    ),
    (
        "adapters/natural-ajax/tests/fixtures/previous-round-producer",
        "netlog.json",
    ),
    (
        "adapters/natural-ajax/tests/fixtures/pruned-producer",
        "netlog.json",
    ),
    (
        "adapters/natural-ajax/tests/fixtures/same-round-producer",
        "netlog.json",
    ),
];

fn fnv1a(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// (hash, tamanho total) do session.json pretty + anexos (nome e bytes, em ordem).
fn fingerprint(dir: &str, netlog: &str) -> Option<(u64, usize)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(dir);
    let cdp = std::fs::read(root.join("cdp-events.jsonl")).ok()?;
    let netlog = std::fs::read(root.join(netlog)).ok()?;
    let bodies = std::fs::read(root.join("cdp-bodies.jsonl")).ok();
    let imported = match import_capture_with_bodies(
        &cdp,
        &netlog,
        bodies.as_deref(),
        CorrelationOptions::default(),
    ) {
        Ok(imported) => imported,
        // Rejected input (e.g. empty NetLog): the error message is also stable.
        Err(error) => {
            let text = format!("ERRO: {error}");
            let mut hash = 0xcbf2_9ce4_8422_2325u64;
            fnv1a(&mut hash, text.as_bytes());
            return Some((hash, text.len()));
        }
    };
    let session = serde_json::to_vec_pretty(&imported.bundle.session).unwrap();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut total = session.len();
    fnv1a(&mut hash, &session);
    for (name, bytes) in &imported.bundle.attachments {
        fnv1a(&mut hash, name.as_bytes());
        fnv1a(&mut hash, bytes);
        total += name.len() + bytes.len();
    }
    Some((hash, total))
}

#[test]
fn correlated_sessions_are_byte_identical_to_the_brute_force_baseline() {
    if std::env::var("PRINT_GOLDEN").is_ok() {
        for (dir, netlog) in INPUTS {
            match fingerprint(dir, netlog) {
                Some((hash, len)) => println!("GOLDEN (\"{dir}\", 0x{hash:016x}, {len}),"),
                None => println!("GOLDEN-MISSING {dir}"),
            }
        }
        return;
    }

    // Round 15: the 6 `multi-target-*` entries are in `experiments/.gitignore`
    // (only `analysis`/`summary` are versioned). In a clean `git clone` the raw data does not
    // exist, so they are checked only when present. The 23 versioned ones
    // must ALWAYS exist: absence is a failure, not a skip.
    let mut checked = 0;
    for (dir, expected_hash, expected_len) in VERSIONED {
        let netlog = netlog_for(dir);
        let (hash, len) =
            fingerprint(dir, netlog).unwrap_or_else(|| panic!("entrada versionada ausente: {dir}"));
        assert_eq!(
            (hash, len),
            (*expected_hash, *expected_len),
            "{dir}: the correlation output changed"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        VERSIONED.len(),
        "cada entrada versionada tem de ter um hash"
    );

    let mut local_checked = 0;
    let mut local_present = 0;
    for (dir, expected_hash, expected_len) in LOCAL_OPTIONAL {
        let netlog = netlog_for(dir);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(dir);
        if !root.join("cdp-events.jsonl").exists() || !root.join(netlog).exists() {
            continue;
        }
        local_present += 1;
        let (hash, len) = fingerprint(dir, netlog).expect("entrada local presente");
        assert_eq!(
            (hash, len),
            (*expected_hash, *expected_len),
            "{dir}: the correlation output changed"
        );
        local_checked += 1;
    }
    assert_eq!(local_checked, local_present);
}

fn netlog_for(dir: &str) -> &'static str {
    INPUTS
        .iter()
        .find(|(candidate, _)| *candidate == dir)
        .unwrap_or_else(|| panic!("entrada sem NetLog em INPUTS: {dir}"))
        .1
}

/// 23 versioned entries (`contract-*`, `h1-*`, `h2-*`, `h3-*`, fixtures and
/// App/adapters evidence). Hashes generated BEFORE the index.
const VERSIONED: &[(&str, u64, usize)] = &[
    (
        "experiments/results/contract-h1",
        0x7ced74d89bbedf35,
        949811,
    ),
    (
        "experiments/results/contract-h2",
        0x57425b16b7c09b9c,
        1164451,
    ),
    (
        "experiments/results/contract-h3",
        0x31539c7102a92085,
        183240,
    ),
    (
        "experiments/results/h1-cookieprobe",
        0x5b3843fca6bfb4cf,
        124226,
    ),
    ("experiments/results/h1-ordered", 0x68155d6bdb771e19, 112891),
    ("experiments/results/h1-page", 0xcbcaf870e812cefd, 780222),
    ("experiments/results/h1-plain", 0xb7e2f5c8dee89f00, 118442),
    ("experiments/results/h1-set3", 0x5f5c8ceabea88974, 132921),
    (
        "experiments/results/h2-cookieprobe",
        0x7fe13ad22119693b,
        155066,
    ),
    ("experiments/results/h2-ordered", 0x13de0b51570b04da, 142885),
    ("experiments/results/h2-page", 0xf918f3a4d17924b6, 974822),
    ("experiments/results/h2-plain", 0x11352b47cdef5d69, 148744),
    ("experiments/results/h2-set3", 0x02716ac77df31e69, 164635),
    (
        "experiments/results/h3-cookieprobe",
        0xb7ced12a9184c53d,
        156220,
    ),
    ("experiments/results/h3-ordered", 0x449c246ad3b9df1b, 143907),
    ("experiments/results/h3-page", 0x3070ef7837553b64, 981863),
    ("experiments/results/h3-plain", 0xfcc91782a91e955c, 149932),
    ("experiments/results/h3-set3", 0x8d827d4e71deeada, 165964),
    (
        "fixtures/acceptance/sanitize/session",
        0x4969b4ef50ddbb95,
        15159,
    ),
    (
        "src-tauri/evidence/bodies-search/multi-target-session",
        0x8e251f85855a93ff,
        1619435,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/previous-round-producer",
        0x97c0f7b42176a865,
        45865,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/pruned-producer",
        0xf6cfaf415db24135,
        31865,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/same-round-producer",
        0x1951890a5ad08af0,
        24880,
    ),
];

/// 6 optional local entries (`multi-target-*`), ignored by git. They are
/// checked against the expected hash when the raw data is in the tree.
const LOCAL_OPTIONAL: &[(&str, u64, usize)] = &[
    (
        "experiments/results/multi-target-attach-probe/headful",
        0xe02bc13d96b45653,
        74,
    ),
    (
        "experiments/results/multi-target-attach-probe/headless",
        0x5cda548a4521563a,
        77,
    ),
    (
        "experiments/results/multi-target-official/no-wait",
        0xf02ff1a6735754d7,
        351317,
    ),
    (
        "experiments/results/multi-target-official/with-wait",
        0x3115692162f19a4d,
        760546,
    ),
    (
        "experiments/results/multi-target-smoke/no-wait",
        0x857210ed975f7317,
        110683,
    ),
    (
        "experiments/results/multi-target-smoke/with-wait",
        0x7258166ed9a4f985,
        409218,
    ),
];
