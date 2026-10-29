//! O codificador Python gerado é equivalente ao `encode` em Rust.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use scrapelens_core::adapter::{AdapterPart, Decoded, PartRole, ProtocolAdapter};
use scrapelens_natural_ajax::{NaturalAjax, PYTHON_ENCODER, PYTHON_FUNCTION};

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
            // Alguns exemplos ultrapassam a largura: erro nos dois lados.
            let rust = adapter.encode(&m).ok();
            cases.push(json_parts(&m.parts));
            expected.push(rust);
        }
    }
    assert!(cases.len() > 20, "poucos casos: {}", cases.len());
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
        assert_eq!(python, rust, "Python e Rust divergem");
        compared += 1;
    }
    assert!(compared > 20);
    // Sem mutação, o Python reproduz o original byte a byte.
    for xml in corpus().iter().take(30) {
        let decoded = adapter.decode(xml).unwrap();
        assert_eq!(adapter.encode(&decoded).unwrap(), *xml);
    }
}

#[test]
fn python_encoder_survives_hostile_names_and_values() {
    // Nomes/valores com aspas, quebras, bidi e substitutos: o resultado é
    // dado, nunca código; nada é executado além da função.
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
    // Casos extras: emoji, escopos e dicionário.
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
        assert_eq!(python, rust, "decoders divergem");
    }
}
