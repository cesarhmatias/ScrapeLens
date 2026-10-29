//! Round-trip exato: `encode(decode(x)) == x` nos XML das fixtures e (agregado)
//! dos HARs reais. Nada de valores no relatório.

mod common;

use std::path::{Path, PathBuf};

use scrapelens_core::adapter::{AdapterContext, ProtocolAdapter};
use scrapelens_natural_ajax::{grammar, NaturalAjax};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn har_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["detran-pb", "detran-pb-b", "detran-pb-real-shape"] {
        if let Ok(read) = std::fs::read_dir(fixtures_root().join(dir)) {
            for entry in read.flatten() {
                if entry.path().extension().is_some_and(|e| e == "har") {
                    out.push(entry.path());
                }
            }
        }
    }
    out.sort();
    out
}

#[derive(Default, Debug)]
struct Tally {
    fields: usize,
    claimed: usize,
    divergences: usize,
    unclaimed: usize,
}

fn check(xml: &str, tally: &mut Tally) {
    let adapter = NaturalAjax;
    tally.fields += 1;
    let ctx = AdapterContext {
        url: "http://h.test/Connector",
        method: "POST",
        request: true,
        media: None,
    };
    if !adapter.detect("XML", xml, &ctx) {
        tally.unclaimed += 1;
        return;
    }
    tally.claimed += 1;
    let ok = adapter
        .decode(xml)
        .and_then(|decoded| adapter.encode(&decoded))
        .is_ok_and(|encoded| encoded == xml);
    let grammar_ok = grammar::parse(xml)
        .and_then(|items| {
            let ops: Vec<_> = items.into_iter().map(|i| i.op).collect();
            grammar::serialize(&ops)
        })
        .is_ok_and(|encoded| encoded == xml);
    if !(ok && grammar_ok) {
        tally.divergences += 1;
    }
}

#[test]
fn fixtures_round_trip_exactly() {
    let mut tally = Tally::default();
    let mut files = 0;
    for path in har_files() {
        let Some((requests, responses)) = common::har_xml(&path) else {
            continue;
        };
        files += 1;
        for xml in requests.iter().chain(&responses) {
            check(xml, &mut tally);
        }
    }
    println!("fixtures: {files} HAR, {tally:?}");
    assert!(tally.fields > 0, "nenhum XML encontrado nas fixtures");
    assert_eq!(tally.divergences, 0, "{tally:?}");
    assert_eq!(tally.unclaimed, 0, "{tally:?}");
}

#[test]
fn real_hars_round_trip_exactly_aggregate() {
    let paths = [
        "/Users/cesar/Projects/scripts/detran_scraper/detran_paraiba/inputs/sem_captcha.har",
        "/Users/cesar/Downloads/wsdetran.pb.gov.br.har.txt.har",
        "/Users/cesar/Downloads/wsdetran.fluxo.captcha.solve.pgEvy4.har.txt.har",
    ];
    let mut tally = Tally::default();
    let mut seen = 0;
    for path in paths {
        let Some((requests, responses)) = common::har_xml(Path::new(path)) else {
            continue;
        };
        seen += 1;
        for xml in requests.iter().chain(&responses) {
            check(xml, &mut tally);
        }
    }
    // Só agregados, sem valores.
    println!("hars reais: {seen}/3, {tally:?}");
    if seen == 0 {
        return;
    }
    assert_eq!(tally.divergences, 0, "{tally:?}");
    // Controles `XML` que não são Natural (marcação ou JS) ficam sem
    // reivindicação; nenhum campo reivindicado diverge.
    assert!(tally.claimed > 0, "{tally:?}");
}

#[test]
fn hostile_inputs_are_errors_never_panics() {
    let adapter = NaturalAjax;
    let big = "p99".to_string() + &"9".repeat(100_000);
    let cases: Vec<String> = vec![
        String::new(),
        "v".into(),
        "v9999999999999999999999999999".into(),
        "pXX00005".into(),
        "p0200005ab".into(),
        "q0100001kv".into(),
        "c".into(),
        "b02ab".into(),
        "x99short".into(),
        "s9".into(),
        "\u{1F600}".into(),
        "p0200002a\u{1F600}".into(),
        "p0200001a\u{1F600}".into(),
        big,
        "z02".to_string() + &"9".repeat(10) + "ab",
    ];
    for case in cases {
        let _ = grammar::parse(&case);
        let _ = adapter.decode(&case);
    }
}

#[test]
fn parse_cost_is_linear() {
    let mut text = String::from("l");
    let n = 20_000;
    for i in 0..n {
        let name = format!("campo{i:05}");
        let value = "é😀x".repeat(3);
        text.push_str(&format!(
            "p{:02}{:05}{}{}",
            grammar::jslen(&name),
            grammar::jslen(&value),
            name,
            value
        ));
    }
    text.push_str("x02ok");
    let start = std::time::Instant::now();
    let items = grammar::parse(&text).expect("parse");
    let ops: Vec<_> = items.iter().map(|i| i.op.clone()).collect();
    assert_eq!(grammar::serialize(&ops).unwrap(), text);
    assert!(start.elapsed().as_secs_f64() < 2.0, "{:?}", start.elapsed());
}
