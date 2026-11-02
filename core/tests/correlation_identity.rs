//! P3 (docs/18): a correlação CDP×NetLog passou a usar um índice por (método, URL canônica)
//! em vez de varrer todos os pares. A saída tem de ser IDÊNTICA. Este teste importa todas as
//! capturas reais e fixtures versionadas (`import_capture_with_bodies`) e confere, byte a
//! byte, o `session.json` serializado (JSON identado) e os anexos contra o hash gravado
//! ANTES da mudança (FNV-1a 64 bits + tamanho).
//!
//! Regenerar (só se a SAÍDA muda de propósito): `PRINT_GOLDEN=1 cargo test --test
//! correlation_identity -- --nocapture` e colar a tabela.

use std::path::Path;

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::parse::import_capture_with_bodies;

/// (diretório a partir da raiz do repositório, nome do NetLog)
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
    ("fixtures/aceite/sanitize/session", "netlog.json"),
    (
        "src-tauri/evidence/busca-corpos/multi-alvo-session",
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
        // Entrada recusada (ex.: NetLog vazio): a mensagem de erro também é estável.
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
    let mut checked = 0;
    for (dir, expected_hash, expected_len) in GOLDEN {
        let netlog = INPUTS.iter().find(|(d, _)| d == dir).unwrap().1;
        let (hash, len) = fingerprint(dir, netlog)
            .unwrap_or_else(|| panic!("entrada ausente: {dir} (os arquivos são versionados)"));
        assert_eq!(
            (hash, len),
            (*expected_hash, *expected_len),
            "{dir}: a saída da correlação mudou"
        );
        checked += 1;
    }
    assert_eq!(checked, INPUTS.len(), "cada entrada tem de ter um hash");
}

/// Hashes gerados ANTES do índice (varredura de todos os pares).
const GOLDEN: &[(&str, u64, usize)] = &[
    (
        "experiments/results/contract-h1",
        0x1c8ff1cbb2f421e0,
        949825,
    ),
    (
        "experiments/results/contract-h2",
        0xab20660c9f608687,
        1164778,
    ),
    (
        "experiments/results/contract-h3",
        0x612308500f0eadf5,
        183395,
    ),
    (
        "experiments/results/h1-cookieprobe",
        0xb96ad6a7a326780b,
        124264,
    ),
    ("experiments/results/h1-ordered", 0xf3df855c914afa53, 112939),
    ("experiments/results/h1-page", 0x6da3931c410cba47, 780242),
    ("experiments/results/h1-plain", 0xa6d8a02d2738c73e, 118490),
    ("experiments/results/h1-set3", 0x2a5fb20754f28d63, 132961),
    (
        "experiments/results/h2-cookieprobe",
        0x57860e2eebb075c3,
        155136,
    ),
    ("experiments/results/h2-ordered", 0xb73881d634fc70ac, 142945),
    ("experiments/results/h2-page", 0x03e3d7a54d826a96, 975133),
    ("experiments/results/h2-plain", 0x0d9d9b38a43508bb, 148804),
    ("experiments/results/h2-set3", 0xf1995b6a5fc7c0f0, 164705),
    (
        "experiments/results/h3-cookieprobe",
        0x41bd183aabfdd237,
        156290,
    ),
    ("experiments/results/h3-ordered", 0x7a0f6073deeb236f, 143967),
    ("experiments/results/h3-page", 0x1c85ee8799dce002, 982174),
    ("experiments/results/h3-plain", 0x834a5310965c95c6, 149992),
    ("experiments/results/h3-set3", 0xb3772f1d847d70e2, 166036),
    (
        "experiments/results/multi-target-attach-probe/headful",
        0x6604a3eadd577f4c,
        76,
    ),
    (
        "experiments/results/multi-target-attach-probe/headless",
        0x874a44442834ff47,
        79,
    ),
    (
        "experiments/results/multi-target-official/no-wait",
        0x48106b95b6c80c72,
        351362,
    ),
    (
        "experiments/results/multi-target-official/with-wait",
        0xeb690267624145c2,
        760570,
    ),
    (
        "experiments/results/multi-target-smoke/no-wait",
        0x144e7cd20727697e,
        110682,
    ),
    (
        "experiments/results/multi-target-smoke/with-wait",
        0x20424e48f1f7d68b,
        409259,
    ),
    (
        "fixtures/aceite/sanitize/session",
        0x508f2021c0a643fd,
        15192,
    ),
    (
        "src-tauri/evidence/busca-corpos/multi-alvo-session",
        0x063620acf1ccd5c8,
        1619857,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/previous-round-producer",
        0xfbfbd168130d7346,
        45779,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/pruned-producer",
        0xa903a7677f7a8096,
        31821,
    ),
    (
        "adapters/natural-ajax/tests/fixtures/same-round-producer",
        0xaf4e2f907f75cfb3,
        24857,
    ),
];
