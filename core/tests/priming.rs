//! Script de priming em Python (docs/11-priming-sucesso.md §1, aceite 1 e 4).

use std::path::PathBuf;
use std::process::Command;

use scrapelens_core::export::priming::{to_python, PrimingOptions};
use scrapelens_core::{import_har, SessionBundle};

fn fixture(dir: &str, name: &str) -> SessionBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(dir)
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    import_har(&bytes).expect("importa HAR").bundle
}

fn generate(bundle: &SessionBundle, id: &str) -> String {
    to_python(&bundle.session, bundle, id, &PrimingOptions::default())
        .expect("gera o script")
        .text
}

fn python(args: &[&str], file: &std::path::Path) -> std::process::Output {
    Command::new("python3")
        .arg("-I")
        .args(args)
        .arg(file)
        .output()
        .expect("python3 disponível")
}

/// `ast.parse` + lista dos nomes chamados em todo o módulo.
const AST_CHECK: &str = r#"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
calls = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        f = node.func
        calls.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else '?')
print(','.join(sorted(calls)))
"#;

fn ast_calls(script: &str, dir: &tempfile::TempDir) -> Vec<String> {
    let path = dir.path().join("priming.py");
    std::fs::write(&path, script).unwrap();
    let out = python(&["-c", AST_CHECK], &path);
    assert!(
        out.status.success(),
        "ast.parse falhou: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split(',')
        .map(str::to_string)
        .collect()
}

fn first_placa_request(bundle: &SessionBundle) -> String {
    bundle
        .session
        .requests
        .iter()
        .find(|r| {
            r.request_body
                .attachment
                .as_deref()
                .and_then(|a| bundle.attachment(a))
                .is_some_and(|b| String::from_utf8_lossy(b).contains("cmd_consultar_placa"))
        })
        .map(|r| r.id.clone())
        .expect("cmd_consultar_placa")
}

#[test]
fn real_shape_script_has_app_steps_extractions_and_parameters() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let script = generate(&bundle, &id);
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);

    // Só passos da aplicação: nada de /TSPD/ nem de scripts estáticos.
    assert!(!script.contains("/TSPD/"), "proteção fora do script");
    assert!(!script.contains("jquery-ui"));
    assert!(!script.contains("CIS_V1_SYNTH.js"));
    // Cabeçalho.
    assert!(script.contains("Reprodução semântica"));
    assert!(script.contains("NÃO são garantidas"));
    assert!(script.contains("Não executado pelo ScrapeLens"));
    assert!(script.contains("--confirmar"));
    // STAMP pelo controle HTML; delta pelo trecho da textarea (contexto).
    assert!(script.contains("('STAMP', html_control(R["));
    assert!(script.contains("html_control(R['har-0024'], 'XML', 0") || script.contains("'XML', 0"));
    assert!(
        script.contains("checked(ctx_extract(html_control("),
        "delta pelo trecho da textarea"
    );
    // SESSIONID: prefixo extraído + comentário de composição parcial.
    assert!(script.contains("montado no cliente: complete aqui"));
    assert!(script.contains("P['sessionid_cliente']"));
    // Placa e CPF: parâmetros obrigatórios, sem o valor capturado.
    assert!(script.contains("P['placa']"));
    assert!(script.contains("('placa', None,"));
    assert!(
        !script.contains("TST0T10"),
        "placa capturada não pode ficar no script"
    );
    assert!(
        !script.contains("00000000191"),
        "CPF capturado não pode ficar no script"
    );
    // Valores dinâmicos capturados não aparecem como literais.
    assert!(!script.contains("'4105'"), "STAMP capturado");
    assert!(!script.contains("DLTC0005"), "delta capturado");
    assert!(!script.contains("CSAN00011"), "prefixo de sessão capturado");
    assert!(
        !script.contains("SYNTHPID000000000000000000000011"),
        "processId capturado"
    );
}

#[test]
fn without_confirm_only_prints_plan_and_exits() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let script = generate(&bundle, &first_placa_request(&bundle));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    // Sem --confirmar: roda sem `requests`, imprime o plano e sai com 0.
    let out = python(&[], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Plano de priming"), "{stdout}");
    assert!(stdout.contains("(altera estado)"));
    assert!(stdout.contains("Nada foi enviado"));
    assert!(!stdout.contains("HTTP 200"), "nenhuma requisição enviada");
    // Com --confirmar e sem parâmetros obrigatórios: recusa antes de enviar.
    let out = Command::new("python3")
        .args(["-I"])
        .arg(&path)
        .arg("--confirmar")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("parâmetros obrigatórios ausentes"));
}

#[test]
fn plain_get_chain_does_not_require_confirm() {
    // Um alvo GET sem passos que alteram estado roda sem a flag (plano + execução).
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = bundle
        .session
        .requests
        .iter()
        .find(|r| r.method == "GET" && r.url.contains("easynat-app"))
        .unwrap()
        .id
        .clone();
    let script = generate(&bundle, &id);
    assert!(script.contains("HAS_STATE_CHANGE = False"));
}

/// HAR com nomes/valores hostis num POST que consome o STAMP de uma página.
fn hostile_bundle() -> SessionBundle {
    let hostile_name = "a\nb'''c\"\"\"d\\e\u{202e}f__import__('os').system('x')";
    let hostile_val = "v\nw'''x\"\"\"y\\z\u{202e}\u{2066}\u{0}";
    let page =
        "<html><form><input type=\"hidden\" name=\"STAMP\" value=\"S1234567\"></form></html>";
    let body = format!(
        "STAMP=S1234567&{}={}",
        urlenc(hostile_name),
        urlenc(hostile_val)
    );
    let entries = serde_json::json!([
        {
            "startedDateTime": "2026-10-26T23:00:00.000Z", "time": 1,
            "request": {"method": "GET", "url": "https://h.example.test/p?q=%27%27%27%0Aq&r=%5C%E2%80%AE", "httpVersion": "HTTP/1.1",
                "headers": [{"name": "X-Bad", "value": "ok"}], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [],
                "cookies": [], "headersSize": -1, "bodySize": page.len(), "redirectURL": "",
                "content": {"size": page.len(), "mimeType": "text/html", "text": page}},
            "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
        },
        {
            "startedDateTime": "2026-10-26T23:00:05.000Z", "time": 1,
            "request": {"method": "POST", "url": "https://h.example.test/post", "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                            {"name": "X-Evil", "value": "a\u{202e}b'''\\"}],
                "queryString": [], "cookies": [], "headersSize": -1, "bodySize": body.len(),
                "postData": {"mimeType": "application/x-www-form-urlencoded", "text": body}},
            "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [],
                "cookies": [], "headersSize": -1, "bodySize": 2, "redirectURL": "",
                "content": {"size": 2, "mimeType": "text/html", "text": "ok"}},
            "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
        }
    ]);
    let har = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}});
    import_har(har.to_string().as_bytes())
        .expect("HAR hostil")
        .bundle
}

fn urlenc(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

#[test]
fn hostile_names_and_values_stay_inside_literals() {
    let bundle = hostile_bundle();
    let script = generate(&bundle, "har-0002");
    let dir = tempfile::tempdir().unwrap();
    let calls = ast_calls(&script, &dir);
    // Nenhuma chamada além das conhecidas do script gerado.
    let allowed = [
        "ArgumentParser",
        "HTMLParser",
        "Session",
        "_Controls",
        "__init__",
        "add_argument",
        "append",
        "checked",
        "close",
        "ctx_extract",
        "dict",
        "dumps",
        "enumerate",
        "escape",
        "extend",
        "fail",
        "feed",
        "get",
        "get_cookie",
        "get_header",
        "getattr",
        "group",
        "html_control",
        "isinstance",
        "items",
        "len",
        "lower",
        "loads",
        "main",
        "max",
        "min",
        "parse_args",
        "parse_qs",
        "pop",
        "print",
        "rebase",
        "request",
        "required",
        "rstrip",
        "search",
        "step_1",
        "step_2",
        "str",
        "strip",
        "startswith",
        "super",
        "urlencode",
        "values",
        "write",
        "zip",
        "re",
        "replace",
        "body_field",
        "exit",
        "ImportError",
        "SystemExit",
        "step",
        "handle_starttag",
        "any",
        "format",
        "stripped",
        "join",
        "sorted",
        "set",
        "int",
        "list",
        "tuple",
        "index",
        "sys",
    ];
    for call in &calls {
        assert!(
            allowed.contains(&call.as_str()),
            "chamada inesperada no script gerado: {call}\n{script}"
        );
    }
    // O payload só pode existir em comentários (inertes, feitos por `comment`)
    // ou dentro de literais escapados; nunca cru no código.
    let code: String = script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!code.contains("__import__('os')"), "payload cru no código");
    assert!(!script.contains('\u{202e}'), "bidi cru no código");
    assert!(!script.contains('\u{0}'));
    // Sentinela hostil não vira instrução: ast só vê constantes.
    let probe = r#"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
bad = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in ('os', '__import__')]
print(len(bad))
"#;
    let path = dir.path().join("priming.py");
    let out = python(&["-c", probe], &path);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
    // Sem --confirmar imprime o plano e sai.
    let out = python(&[], &path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nada foi enviado"));
}

#[test]
fn comments_carry_no_raw_hostile_text() {
    let bundle = hostile_bundle();
    let script = generate(&bundle, "har-0002");
    for line in script.lines().filter(|l| l.trim_start().starts_with('#')) {
        assert!(
            !line.contains('\u{202e}') && !line.contains('\u{2066}'),
            "{line}"
        );
        assert!(!line.contains('\0'));
    }
}
