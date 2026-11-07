//! Exact round-trip: `encode(decode(x)) == x` on the XML of the fixtures and (aggregated)
//! of the real HARs. No values in the report.

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
    assert!(tally.fields > 0, "no XML found in the fixtures");
    assert_eq!(tally.divergences, 0, "{tally:?}");
    assert_eq!(tally.unclaimed, 0, "{tally:?}");
}

#[test]
fn real_hars_round_trip_exactly_aggregate() {
    // Real HARs are not in the repository: pass a path-separated list in
    // SCRAPELENS_REAL_HARS. Without it the test skips explicitly instead of
    // silently passing.
    let Some(raw) = std::env::var_os("SCRAPELENS_REAL_HARS") else {
        eprintln!(
            "skipping real_hars_round_trip_exactly_aggregate: set SCRAPELENS_REAL_HARS to a \
             path-separated list of real HAR files to run it"
        );
        return;
    };
    let paths: Vec<PathBuf> = std::env::split_paths(&raw)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    if paths.is_empty() {
        eprintln!(
            "skipping real_hars_round_trip_exactly_aggregate: SCRAPELENS_REAL_HARS is empty"
        );
        return;
    }
    let total = paths.len();
    let mut tally = Tally::default();
    let mut seen = 0;
    for path in &paths {
        let Some((requests, responses)) = common::har_xml(path) else {
            eprintln!("skipping unreadable real HAR: {}", path.display());
            continue;
        };
        seen += 1;
        for xml in requests.iter().chain(&responses) {
            check(xml, &mut tally);
        }
    }
    // Aggregates only, no values.
    println!("hars reais: {seen}/{total}, {tally:?}");
    if seen == 0 {
        eprintln!(
            "skipping real_hars_round_trip_exactly_aggregate: no readable HAR in \
             SCRAPELENS_REAL_HARS"
        );
        return;
    }
    assert_eq!(tally.divergences, 0, "{tally:?}");
    // `XML` controls that are not Natural (markup or JS) stay unclaimed;
    // no claimed field diverges.
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

/// Allowed growth beyond linear. 20,000 fields must cost at most `LINEAR_SLACK` times ten parses
/// of 2,000 fields. Linear work gives a ratio of about 1 (measured idle in debug); a quadratic
/// parse gives about 10, which the bound catches.
const LINEAR_SLACK: f64 = 3.0;

/// Multiple of the reference (one parse of MAX_OPS operations) that a refused 8 MiB input may
/// cost. Measured in debug: with the limit, parse and decode cost about 11× the reference (the
/// 8 MiB pass plus MAX_OPS operations). With the limit removed, the same input costs about 47×
/// for parse and 73× for decode (8,388,608 operations). 25 lies between, so a missing limit fails.
const LIMIT_FACTOR: f64 = 25.0;

fn fields_text(n: usize) -> String {
    let mut text = String::from("l");
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
    text
}

#[test]
fn parse_cost_is_linear() {
    // Growth, not absolute time: 10× the fields must cost about 10× the work, not 100×. Both
    // sizes are timed in this process, so host load scales both measurements alike.
    let small = fields_text(2_000);
    let large = fields_text(20_000);
    let parse_all = |text: &str| {
        let items = grammar::parse(text).expect("parse");
        let ops: Vec<_> = items.iter().map(|i| i.op.clone()).collect();
        assert_eq!(grammar::serialize(&ops).unwrap(), text);
    };
    // The reference is a block of ten parses, so its duration (about 70 ms) is not a short
    // denominator; the large input is the min of three runs.
    let small_block = min_cpu(3, || {
        for _ in 0..10 {
            parse_all(&small);
        }
    });
    let t_large = min_cpu(3, || parse_all(&large));
    assert_cost_within(
        "parse of 20,000 fields against 10 × 2,000",
        t_large,
        small_block.mul_f64(LINEAR_SLACK),
    );
}

/// CPU time spent by this thread. The cost bounds below measure work, not the wall clock: a
/// loaded host or other tests running in parallel must not turn a bounded parse into a failure.
fn thread_cpu() -> std::time::Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec; CLOCK_THREAD_CPUTIME_ID is supported on Linux and macOS.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
    std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Smallest thread CPU time over `runs` executions of `f`. Host load only adds time, so the
/// minimum is the least disturbed run.
fn min_cpu(runs: usize, mut f: impl FnMut()) -> std::time::Duration {
    (0..runs)
        .map(|_| {
            let start = thread_cpu();
            f();
            thread_cpu() - start
        })
        .min()
        .expect("at least one run")
}

fn assert_cost_within(what: &str, cost: std::time::Duration, bound: std::time::Duration) {
    // Shown with `--nocapture` (or on failure): the measured cost against its bound.
    eprintln!("{what}: CPU time {cost:?}, bound {bound:?}");
    assert!(
        cost <= bound,
        "{what}: CPU time {cost:?} exceeds the bound {bound:?}"
    );
}

fn rss_mb() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .unwrap_or(0.0)
        / 1024.0
}

#[test]
fn operation_limit_bounds_time_and_memory() {
    // `l`×8 MiB: refused by the operation limit, without exhausting memory.
    let text = "l".repeat(8 * 1024 * 1024);
    assert!(grammar::parse(&text).is_err());
    assert!(NaturalAjax.decode(&text).is_err());
    // Process RSS (shared with the other tests of this binary): a loose ceiling. It is read
    // before the timed runs below, which add to the peak.
    eprintln!("operation limit: RSS {:.0} MB", rss_mb());
    assert!(rss_mb() < 500.0, "{} MB", rss_mb());
    // Time: a bound relative to the work the limit lets through (MAX_OPS operations), timed in
    // this process. The reference is the average of a block of ten parses, so its duration is
    // not a short denominator. See LIMIT_FACTOR for the measured ratios.
    let ok = "l".repeat(grammar::MAX_OPS);
    let block = min_cpu(3, || {
        for _ in 0..10 {
            assert_eq!(grammar::parse(&ok).unwrap().len(), grammar::MAX_OPS);
        }
    });
    let bound = (block / 10).mul_f64(LIMIT_FACTOR);
    let parse = min_cpu(3, || {
        let _ = grammar::parse(&text);
    });
    let decode = min_cpu(3, || {
        let _ = NaturalAjax.decode(&text);
    });
    assert_cost_within("parse of an 8 MiB input over the limit", parse, bound);
    assert_cost_within("decode of an 8 MiB input over the limit", decode, bound);
    // Just below the limit it still works, and one more operation is refused.
    assert!(grammar::parse(&format!("{ok}l")).is_err());
}

#[test]
fn label_hint_marks_only_the_init_operation() {
    let head = |init: bool| grammar::Op::Head {
        init,
        fields: [
            "S".into(),
            "P".into(),
            String::new(),
            "M".into(),
            "dummy".into(),
            "PAGE".into(),
            "cmd_x".into(),
            "false".into(),
        ],
    };
    let adapter = NaturalAjax;
    let decode =
        |ops: Vec<grammar::Op>| adapter.decode(&grammar::serialize(&ops).unwrap()).unwrap();
    assert_eq!(
        adapter.label_hint(&decode(vec![head(true), grammar::Op::Delta("dd".into())])),
        Some("init".to_string())
    );
    assert_eq!(
        adapter.label_hint(&decode(vec![head(false), grammar::Op::Delta("dd".into())])),
        None
    );
    // Response (no header): no hint.
    assert_eq!(
        adapter.label_hint(&decode(vec![
            grammar::Op::Clear,
            grammar::Op::Delta("dd".into())
        ])),
        None
    );
}
