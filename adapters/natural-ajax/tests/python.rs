//! The generated Python encoder is equivalent to the Rust `encode`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use scrapelens_core::adapter::{AdapterPart, Decoded, PartRole, ProtocolAdapter};
use scrapelens_natural_ajax::{NaturalAjax, PYTHON_ENCODER, PYTHON_FUNCTION};

/// CPU time spent by this thread. The cost bounds below measure work, not the wall clock: a
/// loaded host or other tests running in parallel must not turn a bounded parse into a failure.
fn thread_cpu() -> std::time::Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec; CLOCK_THREAD_CPUTIME_ID is supported on Linux and macOS.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
    std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn role_code(role: &PartRole) -> &'static str {
    match role {
        PartRole::Structure => "S",
        PartRole::Name => "N",
        PartRole::Value => "V",
        PartRole::Delta => "D",
        PartRole::Other(_) => "O",
    }
}

fn corpus() -> Vec<String> {
    let mut out = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    for dir in ["detran-pb", "detran-pb-real-shape"] {
        let Ok(read) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for entry in read.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().is_some_and(|e| e == "har") {
                if let Some((req, res)) = common::har_xml(&path) {
                    out.extend(req.into_iter().chain(res));
                }
            }
        }
    }
    out.retain(|x| NaturalAjax.decode(x).is_ok());
    out
}

fn mutate(decoded: &Decoded, text: &str) -> Decoded {
    let mut copy = decoded.clone();
    for p in copy.parts.iter_mut() {
        if matches!(p.role, PartRole::Value | PartRole::Delta | PartRole::Name)
            && !p.value.is_empty()
        {
            p.value = format!("{}{text}", p.value);
        }
    }
    copy
}

fn json_parts(parts: &[AdapterPart]) -> serde_json::Value {
    serde_json::Value::Array(
        parts
            .iter()
            .map(|p| serde_json::json!([p.name, role_code(&p.role), p.value]))
            .collect(),
    )
}

#[test]
fn python_encoder_matches_rust_encode() {
    let adapter = NaturalAjax;
    let mut cases = Vec::new();
    let mut expected = Vec::new();
    for xml in corpus().iter().take(60) {
        let decoded = adapter.decode(xml).unwrap();
        for text in ["", "ZZ", "é😀 \u{202e} ' \" \\ \n"] {
            let m = mutate(&decoded, text);
            // Some examples exceed the width: error on both sides.
            let rust = adapter.encode(&m).ok();
            cases.push(json_parts(&m.parts));
            expected.push(rust);
        }
    }
    assert!(cases.len() > 20, "few cases: {}", cases.len());
    let dir = tempfile::tempdir().unwrap();
    let driver = format!(
        r#"
import json, sys
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
cases = json.load(open(sys.argv[1], encoding='utf-8'))
out = []
for parts in cases:
    try:
        out.append({PYTHON_FUNCTION}([tuple(p) for p in parts]))
    except SystemExit:
        out.append(None)
json.dump(out, open(sys.argv[2], 'w', encoding='utf-8'))
"#
    );
    let (script, input, output) = (
        dir.path().join("d.py"),
        dir.path().join("in.json"),
        dir.path().join("out.json"),
    );
    std::fs::write(&script, driver).unwrap();
    std::fs::write(&input, serde_json::Value::Array(cases).to_string()).unwrap();
    let status = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .status()
        .expect("python3");
    assert!(status.success());
    let got: Vec<Option<String>> =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(got.len(), expected.len());
    let mut compared = 0;
    for (python, rust) in got.iter().zip(&expected) {
        assert_eq!(python, rust, "Python and Rust diverge");
        compared += 1;
    }
    assert!(compared > 20);
    // Without mutation, Python reproduces the original byte for byte.
    for xml in corpus().iter().take(30) {
        let decoded = adapter.decode(xml).unwrap();
        assert_eq!(adapter.encode(&decoded).unwrap(), *xml);
    }
}

#[test]
fn python_encoder_survives_hostile_names_and_values() {
    // Names/values with quotes, breaks, bidi and surrogates: the result is
    // data, never code; nothing runs beyond the function.
    let adapter = NaturalAjax;
    let decoded = Decoded {
        parts: vec![
            AdapterPart {
                name: "op".into(),
                value: "p'\"\\\n\u{202e}x".into(),
                offset: 0,
                len: 0,
                role: PartRole::Structure,
            },
            AdapterPart {
                name: "p.x".into(),
                value: "'''; __import__('os').system('true') #\u{1F600}".into(),
                offset: 0,
                len: 0,
                role: PartRole::Value,
            },
            AdapterPart {
                name: "delta".into(),
                value: "\\".into(),
                offset: 0,
                len: 0,
                role: PartRole::Delta,
            },
        ],
    };
    let rust = adapter.encode(&decoded).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("d.py");
    let driver = format!(
        r#"
import json, sys
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
parts = json.loads(sys.argv[1])
print(json.dumps({PYTHON_FUNCTION}([tuple(p) for p in parts])))
"#
    );
    std::fs::write(&script, driver).unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(json_parts(&decoded.parts).to_string())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let python: String = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(python, rust);
}

#[test]
fn python_decoder_matches_rust_decode() {
    use scrapelens_natural_ajax::PYTHON_DECODER;
    let adapter = NaturalAjax;
    let corpus: Vec<String> = corpus().into_iter().take(80).collect();
    assert!(corpus.len() > 20);
    let dir = tempfile::tempdir().unwrap();
    let driver = format!(
        r#"
import json, sys
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
texts = json.load(open(sys.argv[1], encoding='utf-8'))
out = []
for text in texts:
    try:
        out.append([list(p) for p in {PYTHON_DECODER}(text)])
    except SystemExit:
        out.append(None)
json.dump(out, open(sys.argv[2], 'w', encoding='utf-8'))
"#
    );
    let (script, input, output) = (
        dir.path().join("d.py"),
        dir.path().join("in.json"),
        dir.path().join("out.json"),
    );
    std::fs::write(&script, driver).unwrap();
    // Extra cases: emoji, scopes and dictionary.
    let mut texts = corpus.clone();
    texts.push("lb02ab".to_string() + "s1" + "02" + "kk" + "xx" + "q0100005kvalue" + "c" + "x02ok");
    texts.push("p0200003a\u{1F600}b".to_string() + "x01z");
    std::fs::write(&input, serde_json::to_string(&texts).unwrap()).unwrap();
    let status = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let got: Vec<Option<Vec<Vec<String>>>> =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    for (text, python) in texts.iter().zip(got) {
        let rust = adapter.decode(text).ok().map(|d| {
            d.parts
                .iter()
                .map(|p| {
                    vec![
                        p.name.clone(),
                        role_code(&p.role).to_string(),
                        p.value.clone(),
                    ]
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(python, rust, "decoders diverge");
    }
}

fn py_driver_decode(texts: &[String]) -> Vec<Option<Vec<Vec<String>>>> {
    use scrapelens_natural_ajax::PYTHON_DECODER;
    let dir = tempfile::tempdir().unwrap();
    let driver = format!(
        r#"
import json, sys
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
texts = json.load(open(sys.argv[1], encoding='utf-8'))
out = []
for text in texts:
    try:
        out.append([list(p) for p in {PYTHON_DECODER}(text)])
    except SystemExit:
        out.append(None)
json.dump(out, open(sys.argv[2], 'w', encoding='utf-8'))
"#
    );
    let (script, input, output) = (
        dir.path().join("d.py"),
        dir.path().join("in.json"),
        dir.path().join("out.json"),
    );
    std::fs::write(&script, driver).unwrap();
    std::fs::write(&input, serde_json::to_string(texts).unwrap()).unwrap();
    let status = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(&input)
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap()
}

/// Deterministic LCG (no dependency).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
        items[(self.next() as usize) % items.len()]
    }
}

#[test]
fn python_decoder_is_as_strict_as_rust_on_random_inputs() {
    use scrapelens_natural_ajax::grammar::{self, Op};
    let adapter = NaturalAjax;
    let mut rng = Rng(42);
    let atoms = ["a", "b", "é", "😀", "x", "9", "0", ".", " "];
    let word =
        |rng: &mut Rng| -> String { (0..(rng.next() % 5)).map(|_| rng.pick(&atoms)).collect() };
    let mut texts: Vec<String> = Vec::new();
    for _ in 0..3000 {
        // Valid messages built from operations, then corrupted.
        let mut ops = Vec::new();
        for _ in 0..(rng.next() % 8) {
            ops.push(match rng.next() % 7 {
                0 => Op::Begin(word(&mut rng)),
                1 => Op::End,
                2 => Op::Clear,
                3 => Op::Dict {
                    key: "k".into(),
                    name: word(&mut rng),
                },
                4 => Op::Ref {
                    op: 'q',
                    key: "k".into(),
                    value: word(&mut rng),
                },
                5 => Op::Delete(word(&mut rng)),
                _ => Op::Lit {
                    op: 'p',
                    key: word(&mut rng),
                    value: word(&mut rng),
                },
            });
        }
        ops.push(Op::Delta(word(&mut rng)));
        let mut text = grammar::serialize(&ops).unwrap_or_default();
        texts.push(text.clone());
        // Corrupts: swaps a digit, cuts, or inserts an emoji (surrogate pair).
        let chars: Vec<char> = text.chars().collect();
        if !chars.is_empty() {
            let at = (rng.next() as usize) % chars.len();
            match rng.next() % 3 {
                0 => {
                    let mut c = chars.clone();
                    c[at] = char::from_digit((rng.next() % 10) as u32, 10).unwrap();
                    text = c.into_iter().collect();
                }
                1 => text = chars[..at].iter().collect(),
                _ => {
                    let mut c = chars.clone();
                    c.insert(at, '😀');
                    text = c.into_iter().collect();
                }
            }
            texts.push(text);
        }
    }
    for _ in 0..2000 {
        // Pure noise over the protocol alphabet.
        let alphabet = [
            "p", "q", "z", "w", "b", "c", "s", "l", "k", "x", "v", "i", "0", "1", "2", "5", "9",
            "a", "😀", "é",
        ];
        let text: String = (0..(rng.next() % 24))
            .map(|_| rng.pick(&alphabet))
            .collect();
        texts.push(text);
    }
    assert!(texts.len() >= 5000, "{}", texts.len());
    let python = py_driver_decode(&texts);
    let (mut ok, mut err) = (0, 0);
    for (text, py) in texts.iter().zip(python) {
        let rust = adapter.decode(text).ok().map(|d| {
            d.parts
                .iter()
                .map(|p| {
                    vec![
                        p.name.clone(),
                        role_code(&p.role).to_string(),
                        p.value.clone(),
                    ]
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(
            py,
            rust,
            "decoders diverge on {:?}",
            text.chars().take(40).collect::<String>()
        );
        if rust.is_some() {
            ok += 1
        } else {
            err += 1
        }
    }
    println!(
        "random: {} inputs, {ok} valid, {err} refused",
        texts.len()
    );
    assert!(ok > 200 && err > 200);
}

/// Multiple of the Rust reference: the same input with its first byte replaced by `!`, which is
/// not an operation, so the decoder fails right after the byte pass that every input of this
/// size pays. Measured in debug (see the commit message).
const PASS_FACTOR: f64 = 2.0;

/// Multiple of the Python reference, timed in the same Python process: the work each limit lets
/// through (32 scopes, 10,000 keys).
const PY_FACTOR: f64 = 3.0;

/// Smallest thread CPU time over `runs` executions of `f`.
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
    eprintln!("{what}: CPU time {cost:?}, bound {bound:?}");
    assert!(
        cost <= bound,
        "{what}: CPU time {cost:?} exceeds the bound {bound:?}"
    );
}

#[test]
fn deep_scopes_and_big_dictionaries_are_refused_fast_in_rust_and_python() {
    use scrapelens_natural_ajax::grammar;
    let deep = "b01a".repeat(40_000) + &"p0100001ab".repeat(40_000);
    // Valid dictionary entries (`s`, key length 6, name length 0) with distinct keys: the 10,001st
    // is refused.
    let mut dict = String::new();
    for i in 0..100_000 {
        dict.push_str(&format!("s600{:06}", i));
    }
    let mut dict_limit = String::new();
    for i in 0..10_000 {
        dict_limit.push_str(&format!("s600{:06}", i));
    }
    let depth_limit = "b01a".repeat(33);
    let ok_depth = "b01a".repeat(32) + "p0100001ab" + &"c".repeat(32) + "x02ok";

    // Rust reference (see PASS_FACTOR).
    let deep_pass = format!("!{}", &deep[1..]);
    let dict_pass = format!("!{}", &dict[1..]);
    // Each measurement is a block of five runs: a single run is too short to average out load.
    let deep_ref = min_cpu(3, || {
        for _ in 0..5 {
            assert!(grammar::parse(&deep_pass).is_err());
        }
    });
    let dict_ref = min_cpu(3, || {
        for _ in 0..5 {
            assert!(grammar::parse(&dict_pass).is_err());
        }
    });
    let parse_deep = min_cpu(3, || {
        for _ in 0..5 {
            let _ = grammar::parse(&deep);
        }
    });
    let decode_deep = min_cpu(3, || {
        for _ in 0..5 {
            let _ = NaturalAjax.decode(&deep);
        }
    });
    let parse_dict = min_cpu(3, || {
        for _ in 0..5 {
            let _ = grammar::parse(&dict);
        }
    });
    assert_cost_within("parse of the deep scopes", parse_deep, deep_ref.mul_f64(PASS_FACTOR));
    assert_cost_within("decode of the deep scopes", decode_deep, deep_ref.mul_f64(PASS_FACTOR));
    assert_cost_within("parse of the big dictionary", parse_dict, dict_ref.mul_f64(PASS_FACTOR));
    // The refusals are the limits themselves, not some other error.
    let deep_err = grammar::parse(&deep).unwrap_err().to_string();
    assert!(deep_err.contains("nested too deeply"), "{deep_err}");
    let dict_err = grammar::parse(&dict).unwrap_err().to_string();
    assert!(dict_err.contains("too many dictionary keys"), "{dict_err}");
    assert!(NaturalAjax.decode(&deep).is_err());
    // Depth and dictionary within the limit keep working.
    assert!(grammar::parse(&ok_depth).is_ok());
    assert!(grammar::parse(&depth_limit).is_err());
    assert!(grammar::parse(&dict_limit).is_ok());

    // Python: same verdicts, timed in this process against the work each limit lets through.
    let python = {
        use scrapelens_natural_ajax::PYTHON_DECODER;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("d.py");
        let input = dir.path().join("in.json");
        std::fs::write(
            &script,
            format!(
                r#"
import json, sys, time, resource
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
def run(text):
    try:
        {PYTHON_DECODER}(text)
        return True
    except SystemExit as error:
        return str(error)
def timed(text, reps):
    best = None
    for _ in range(3):
        start = time.process_time()
        for _ in range(reps):
            run(text)
        spent = time.process_time() - start
        best = spent if best is None or spent < best else best
    return best
texts = json.load(open(sys.argv[1], encoding='utf-8'))
deep, dictionary, ok_depth, dict_limit, depth_limit = texts
res = [run(text) for text in (deep, dictionary, ok_depth)]
# Reference: the work the limits allow (32 scopes, 10,000 keys), with blocks long enough to
# average out host load.
times = dict(
    deep=[timed(deep, 1000), timed(depth_limit, 1000)],
    dict=[timed(dictionary, 5), timed(dict_limit, 5)],
)
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps(dict(ok=res, times=times, rss_mb=rss / (1024 * 1024 if sys.platform == 'darwin' else 1024))))
"#
            ),
        )
        .unwrap();
        std::fs::write(
            &input,
            serde_json::to_string(&[&deep, &dict, &ok_depth, &dict_limit, &depth_limit]).unwrap(),
        )
        .unwrap();
        let out = Command::new("python3")
            .arg("-I")
            .arg(&script)
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let verdicts = python["ok"].as_array().unwrap();
    assert!(verdicts[0].as_str().unwrap().contains("nested too deeply"), "{python}");
    assert!(verdicts[1].as_str().unwrap().contains("too many dictionary keys"), "{python}");
    assert_eq!(verdicts[2], serde_json::json!(true), "{python}");
    for (name, pair) in [("deep", "deep"), ("dict", "dict")] {
        let subject = python["times"][pair][0].as_f64().unwrap();
        let reference = python["times"][pair][1].as_f64().unwrap();
        eprintln!("python {name}: {subject:.4}s, reference {reference:.4}s");
        assert!(
            subject <= reference * PY_FACTOR,
            "python {name}: {subject}s exceeds {PY_FACTOR} times the reference {reference}s"
        );
    }
    assert!(python["rss_mb"].as_f64().unwrap() < 100.0, "{python}");
}

#[test]
fn python_decoder_refuses_too_many_operations_within_memory() {
    use scrapelens_natural_ajax::PYTHON_DECODER;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("d.py");
    let input = dir.path().join("in.json");
    std::fs::write(
        &script,
        format!(
            r#"
import json, sys, time, resource
def fail(message):
    raise SystemExit('priming: ' + message)
{PYTHON_ENCODER}
texts = json.load(open(sys.argv[1], encoding='utf-8'))
res = []
t = time.process_time()
for text in texts:
    try:
        {PYTHON_DECODER}(text); res.append(True)
    except SystemExit:
        res.append(False)
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({{'ok': res, 'secs': time.process_time() - t, 'rss_mb': rss / (1024 * 1024 if sys.platform == 'darwin' else 1024)}}))
"#
        ),
    )
    .unwrap();
    let big = "l".repeat(8 * 1024 * 1024);
    let ok = "l".repeat(200_000 - 1);
    std::fs::write(&input, serde_json::to_string(&[big, ok]).unwrap()).unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["ok"], serde_json::json!([false, true]));
    assert!(j["rss_mb"].as_f64().unwrap() < 500.0, "{j}");
}
