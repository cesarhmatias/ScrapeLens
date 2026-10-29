//! Integração do adaptador no priming: o campo XML é montado por partes e
//! recodificado com os comprimentos recalculados.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use scrapelens_core::adapter::AdapterRegistry;
use scrapelens_core::export::priming::{to_python, AdapterEncoder, PrimingOptions};
use scrapelens_core::{import_har, SessionBundle};
use scrapelens_natural_ajax::{
    grammar, NaturalAjax, ADAPTER_ID, PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION,
};

fn options() -> PrimingOptions {
    let mut options = PrimingOptions::default();
    options.flow.adapters = AdapterRegistry::new().with(Arc::new(NaturalAjax));
    options.adapter_encoders.push(AdapterEncoder {
        adapter_id: ADAPTER_ID.to_string(),
        function: PYTHON_FUNCTION.to_string(),
        decoder: PYTHON_DECODER.to_string(),
        source: PYTHON_ENCODER.to_string(),
    });
    options
}

fn fixture(name: &str) -> SessionBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/detran-pb-real-shape")
        .join(name);
    import_har(&std::fs::read(&path).unwrap())
        .expect("HAR")
        .bundle
}

fn first_placa_request(bundle: &SessionBundle) -> String {
    bundle
        .session
        .requests
        .iter()
        .find(|r| r.method == "POST" && r.url.contains("Connector"))
        .map(|r| r.id.clone())
        .expect("POST do Connector")
}

fn python_ast_ok(script: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.py");
    std::fs::write(&path, script).unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .args([
            "-c",
            "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn real_shape_xml_is_built_by_parts_and_recomputes_prefixes() {
    let bundle = fixture("real-shape-1round.har");
    let target = bundle
        .session
        .requests
        .iter()
        .rev()
        .find(|r| r.method == "POST" && r.url.contains("Connector"))
        .map(|r| r.id.clone())
        .unwrap();
    let out = to_python(&bundle.session, &bundle, &target, &options()).expect("gera");
    let script = out.text;
    python_ast_ok(&script);
    assert!(script.contains("natural_ajax_encode(["), "{script}");
    assert!(
        script.contains("def natural_ajax_decode"),
        "decodificador incluso"
    );
    assert!(
        script.contains("adapter_get("),
        "partes extraídas pelo nome"
    );
    // Sem adaptador (controle), o mesmo alvo usa trechos.
    let control = to_python(
        &bundle.session,
        &bundle,
        &target,
        &PrimingOptions::default(),
    )
    .unwrap()
    .text;
    assert!(!control.contains("natural_ajax_encode"));
    assert!(control.contains("ctx_extract("));
    // Placa e cpf seguem parâmetros obrigatórios, sem valor capturado.
    assert!(script.contains("('placa', None,"), "{script}");
    assert!(!script.contains("TST0T10"));
}

#[test]
fn script_xml_matches_the_captured_one_when_nothing_changes() {
    // Com as mesmas entradas, o XML recodificado reproduz o capturado: a
    // gramática do script é a do adaptador.
    let bundle = fixture("real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let request = bundle.session.find_request(&id).unwrap();
    let body = request.request_body.attachment.as_deref().unwrap();
    let loaded = scrapelens_core::search::BodySource::load(&bundle, body).unwrap();
    let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
    let xml = text
        .split('&')
        .find_map(|p| p.strip_prefix("XML="))
        .map(|v| {
            let mut out = Vec::new();
            let b = v.as_bytes();
            let mut i = 0;
            while i < b.len() {
                match b[i] {
                    b'+' => out.push(b' '),
                    b'%' if i + 2 < b.len() => {
                        out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
                        i += 2;
                    }
                    c => out.push(c),
                }
                i += 1;
            }
            String::from_utf8(out).unwrap()
        })
        .expect("campo XML");
    let items = grammar::parse(&xml).expect("gramática");
    let ops: Vec<_> = items.into_iter().map(|i| i.op).collect();
    assert_eq!(grammar::serialize(&ops).unwrap(), xml);
}

fn hostile_bundle() -> SessionBundle {
    // Nomes e valores hostis dentro da estrutura (aspas, quebra de linha,
    // bidi, ESC e código Python), com prefixos corretos.
    let name = "n'\"\\\n\u{202e}x\u{1b}[31m";
    let value = "'''; __import__('os').system('true') #\u{1F600}";
    let delta = "d\\";
    let xml = grammar::serialize(&[
        grammar::Op::Head {
            init: false,
            fields: [
                "SID1".into(),
                "PID1".into(),
                String::new(),
                "MODEL".into(),
                "dummy".into(),
                "PAGE".into(),
                "ev".into(),
                "false".into(),
            ],
        },
        grammar::Op::Lit {
            op: 'p',
            key: name.into(),
            value: value.into(),
        },
        grammar::Op::Delta(delta.into()),
    ])
    .unwrap();
    let encoded: String = xml
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    let body = format!("SESSIONID=SID1&STAMP=INIT&XML={encoded}");
    let har = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
    "entries": [{
        "startedDateTime": "2026-10-27T12:00:00.000Z", "time": 1,
        "request": {"method": "POST", "url": "https://h.example.test/Connector",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": body.len(),
            "postData": {"mimeType": "application/x-www-form-urlencoded", "text": body}},
        "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [],
            "cookies": [], "headersSize": -1, "bodySize": 2, "redirectURL": "",
            "content": {"size": 2, "mimeType": "text/html", "text": "ok"}},
        "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
    }]}});
    import_har(har.to_string().as_bytes()).unwrap().bundle
}

#[test]
fn hostile_names_and_values_inside_the_structure_stay_data() {
    let bundle = hostile_bundle();
    let out = to_python(&bundle.session, &bundle, "har-0001", &options()).expect("gera");
    let script = out.text;
    python_ast_ok(&script);
    assert!(script.contains("natural_ajax_encode(["), "{script}");
    // Nada cru: sem ESC, bidi nem quebra de linha dentro do código gerado.
    for bad in ['\u{1b}', '\u{202e}'] {
        assert!(!script.contains(bad), "{bad:?} cru no script");
    }
    // O valor hostil é dado: o AST não ganha nenhuma chamada a `__import__`/`system`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.py");
    std::fs::write(&path, &script).unwrap();
    let probe = r#"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
print('__import__' in names, 'system' in names)
"#;
    let result = Command::new("python3")
        .arg("-I")
        .args(["-c", probe])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&result.stdout).trim(),
        "False False"
    );
}

#[test]
fn pii_inside_the_structure_goes_through_the_final_filter() {
    // E-mail num valor de propriedade: não existe parâmetro mapeável (sem nome
    // de negócio) e o filtro final recusa, sem repetir o valor.
    let xml = grammar::serialize(&[
        grammar::Op::Head {
            init: false,
            fields: [
                "SID1".into(),
                "PID1".into(),
                String::new(),
                "MODEL".into(),
                "dummy".into(),
                "PAGE".into(),
                "ev".into(),
                "false".into(),
            ],
        },
        grammar::Op::Lit {
            op: 'p',
            key: "v_contato".into(),
            value: "maria.silva@example.test".into(),
        },
        grammar::Op::Delta("dd".into()),
    ])
    .unwrap();
    let encoded: String = xml
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let body = format!("SESSIONID=SID1&STAMP=INIT&XML={encoded}");
    let har = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
    "entries": [{
        "startedDateTime": "2026-10-27T12:00:00.000Z", "time": 1,
        "request": {"method": "POST", "url": "https://h.example.test/Connector",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": body.len(),
            "postData": {"mimeType": "application/x-www-form-urlencoded", "text": body}},
        "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [],
            "cookies": [], "headersSize": -1, "bodySize": 2, "redirectURL": "",
            "content": {"size": 2, "mimeType": "text/html", "text": "ok"}},
        "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
    }]}});
    let bundle = import_har(har.to_string().as_bytes()).unwrap().bundle;
    match to_python(&bundle.session, &bundle, "har-0001", &options()) {
        Ok(out) => assert!(!out.text.contains("maria.silva@example.test")),
        Err(e) => {
            let message = e.to_string();
            assert!(message.contains("dado pessoal"), "{message}");
            assert!(!message.contains("maria.silva"));
        }
    }
    let _ = Path::new("");
}
