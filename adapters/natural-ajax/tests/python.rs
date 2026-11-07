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

#[test]
fn deep_scopes_and_big_dictionaries_are_refused_fast_in_rust_and_python() {
    use scrapelens_natural_ajax::grammar;
    let deep = "b01a".repeat(40_000) + &"p0100001ab".repeat(40_000);
    let mut dict = String::new();
    for i in 0..100_000 {
        dict.push_str(&format!("s8{:02}{:08}{:02}", 2, i, 10));
        dict.push_str("ab");
    }
    let start = thread_cpu();
    assert!(grammar::parse(&deep).is_err());
    assert!(grammar::parse(&dict).is_err());
    assert!(NaturalAjax.decode(&deep).is_err());
    let spent = thread_cpu() - start;
    assert!(spent.as_secs_f64() < 1.0, "CPU time {spent:?}");
    // Depth and dictionary within the limit keep working.
    let ok_depth = "b01a".repeat(32) + "p0100001ab" + &"c".repeat(32) + "x02ok";
    assert!(grammar::parse(&ok_depth).is_ok());
    assert!(grammar::parse(&("b01a".repeat(33))).is_err());

    // Python: same verdict, fast and with low memory.
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
texts = json.load(open(sys.argv[1], encoding='utf-8'))
t = time.process_time()
res = []
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
        std::fs::write(
            &input,
            serde_json::to_string(&[deep, dict, ok_depth]).unwrap(),
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
    assert_eq!(python["ok"], serde_json::json!([false, false, true]));
    assert!(python["secs"].as_f64().unwrap() < 1.0, "{python}");
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
