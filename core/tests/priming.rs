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
fn each_step_checks_its_own_response_before_the_next_request() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let script = generate(&bundle, &id);
    // Um `step_N` por passo do plano; cada um checa status e ERRORMESSAGE
    // DENTRO da função, antes de devolver a resposta para o próximo pedido.
    let steps = script
        .match_indices("\ndef step_")
        .filter(|(i, _)| {
            script[i + "\ndef step_".len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert!(steps >= 9, "passos esperados para o alvo:\n{script}");
    assert_eq!(
        script
            .matches("if not (200 <= resp.status_code < 400):")
            .count(),
        steps
    );
    assert_eq!(script.matches("\n    step_error(resp, ").count(), steps);
    assert_eq!(script.matches("except UnicodeEncodeError").count(), steps);
    // A ausência de ERRORMESSAGE não pode virar erro engolido: nenhum
    // `except SystemExit` no script e a checagem só falha se houver valor.
    assert!(!script.contains("except SystemExit"), "{script}");
    assert!(!script.contains("erro = ''"), "{script}");
    assert!(script.contains("if value is not None and value.strip():"));
    // Todo passo que produz controle para outro tem a checagem na própria
    // função, antes do `return resp`; nunca no laço do main.
    for chunk in script.split("\ndef step_").skip(1) {
        let name: String = chunk.chars().take_while(|c| c.is_ascii_digit()).collect();
        if name.is_empty() {
            continue;
        }
        let body = chunk;
        let request_at = body.find("resp = S.request(").unwrap();
        let status_at = body
            .find("if not (200 <= resp.status_code < 400):")
            .unwrap();
        let error_at = body.find("step_error(").unwrap();
        let return_at = body.find("return resp").unwrap();
        assert!(request_at < status_at && status_at < error_at && error_at < return_at);
        if let Some(expected_at) = body.find("step_expected(") {
            assert!(
                status_at < expected_at && expected_at < error_at,
                "checagem de campos fora de ordem no passo {name}:\n{body}"
            );
        }
    }
    // O XML que o passo produtor entrega aos seguintes é checado nele.
    let producer = script
        .split("\ndef step_")
        .find(|chunk| chunk.contains("('control', 'XML', 0)"))
        .expect("nenhum passo checa o XML que produz");
    assert!(
        producer.contains("step_expected(resp, S,"),
        "passo produtor sem checagem do XML:\n{producer}"
    );
}

/// HAR mínimo com um header cujo valor não cabe em latin-1.
fn header_outside_latin1_bundle() -> SessionBundle {
    let entries = serde_json::json!([{
        "startedDateTime": "2026-10-27T12:00:00.000Z", "time": 1,
        "request": {
            "method": "GET", "url": "https://h.example.test/p", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "X-Bad", "value": "a\u{202e}b"}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0
        },
        "response": {
            "status": 200, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [],
            "cookies": [], "headersSize": -1, "bodySize": 2, "redirectURL": "",
            "content": {"size": 2, "mimeType": "text/html", "text": "ok"}
        },
        "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
    }]);
    let har = serde_json::json!({
        "log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}
    });
    import_har(har.to_string().as_bytes())
        .expect("HAR com header fora de latin-1")
        .bundle
}

#[test]
fn header_outside_latin1_fails_with_a_clear_priming_message() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    // O `requests` codifica headers em latin-1. O driver simula a exceção no
    // passo (sem rede e sem depender do pacote `requests`).
    let driver = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[1])
class S:
    def request(self, *a, **k):
        raise UnicodeEncodeError('latin-1', 'a', 0, 1, 'ordinal not in range(256)')
try:
    mod['step_1'](S(), {}, {}, None)
except SystemExit as exc:
    sys.stderr.write(str(exc))
"#;
    let out = python(&["-c", driver], &path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("priming:"),
        "mensagem sem prefixo:\n{stderr}"
    );
    assert!(
        stderr.contains("fora de latin-1"),
        "mensagem deveria apontar o header fora de latin-1:\n{stderr}"
    );
    assert!(
        !stderr.contains("UnicodeEncodeError"),
        "o erro cru não pode vazar:\n{stderr}"
    );
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
    // F1: a parte montada no cliente é obrigatória, sem valor capturado.
    assert!(
        script.contains("('sessionid_cliente', None, 'montado no cliente')"),
        "sufixo de composição parcial não pode ter padrão capturado"
    );
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
    // F1: navegação sem origem observada também é obrigatória (sem padrão).
    assert!(script.contains("('op', None, 'sem origem observada')"));
    assert!(script.contains("('page', None, 'sem origem observada')"));
}

/// HAR mínimo com `entries` (method, url, corpo de requisição, texto da resposta).
/// `None` no texto da resposta = resposta sem corpo observável (`unavailable`).
fn mini_bundle(entries: Vec<(&str, &str, Option<&str>, Option<&str>)>) -> SessionBundle {
    let entries: Vec<serde_json::Value> = entries
        .into_iter()
        .enumerate()
        .map(|(i, (method, url, body, response))| {
            let mut request = serde_json::json!({
                "method": method, "url": url, "httpVersion": "HTTP/1.1",
                "headers": [], "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": 0
            });
            if let Some(body) = body {
                request["headers"] = serde_json::json!([
                    {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                ]);
                request["bodySize"] = serde_json::json!(body.len());
                request["postData"] =
                    serde_json::json!({"mimeType": "application/x-www-form-urlencoded", "text": body});
            }
            let content = match response {
                Some(text) => serde_json::json!({
                    "size": text.len(), "mimeType": "text/html", "text": text
                }),
                // Tamanho > 0 sem texto = `unavailable` (não `empty`).
                None => serde_json::json!({"size": 1, "mimeType": "text/html"}),
            };
            serde_json::json!({
                "startedDateTime": format!("2026-10-27T12:00:{i:02}.000Z"),
                "time": 1,
                "request": request,
                "response": {
                    "status": 200, "statusText": "", "httpVersion": "HTTP/1.1",
                    "headers": [], "cookies": [], "headersSize": -1,
                    "bodySize": response.map_or(1, str::len), "redirectURL": "",
                    "content": content
                },
                "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
            })
        })
        .collect();
    let har = serde_json::json!({
        "log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}
    });
    import_har(har.to_string().as_bytes())
        .expect("HAR mínimo")
        .bundle
}

#[test]
fn value_without_origin_is_a_default_only_with_constancy_proof() {
    // Mesmo (campo, valor) em duas requisições e fora de qualquer resposta:
    // constante do protocolo, pode virar padrão.
    let bundle = mini_bundle(vec![
        (
            "POST",
            "https://mini.example.test/init",
            Some("mode=CONST_MODE&x=1"),
            Some("ok"),
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("mode=CONST_MODE&y=2"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(
        script.contains("('mode', 'CONST_MODE', 'constante do protocolo')"),
        "constância comprovada deveria permitir o padrão:\n{script}"
    );

    // Uma única ocorrência: parâmetro obrigatório, sem o valor capturado.
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/page",
            None,
            Some("<html>ok</html>"),
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("mode=ONLY_ONCE_XYZ&x=2"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(
        script.contains("('mode', None, 'sem origem observada')"),
        "valor sem prova de constância deve ser obrigatório:\n{script}"
    );
    assert!(
        !script.contains("ONLY_ONCE_XYZ"),
        "valor capturado não pode aparecer no script"
    );
}

#[test]
fn stamp_without_producer_is_required_and_never_a_captured_literal() {
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/page",
            None,
            Some("<html>sem STAMP nesta página</html>"),
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("STAMP=STAMP_UNIQUE_42&x=3"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(
        script.contains("('stamp', None, 'sem origem observada')"),
        "STAMP sem produtor tem de ser obrigatório:\n{script}"
    );
    assert!(
        !script.contains("STAMP_UNIQUE_42"),
        "STAMP capturado não pode ficar em código nem em comentário:\n{script}"
    );
    for line in script.lines() {
        assert!(!line.contains("STAMP_UNIQUE_42"), "{line}");
    }
}

#[test]
fn partial_composition_suffix_is_required_without_a_captured_default() {
    let page = "<html><script>m_currentSessionId = \"HEAD12345\";</script></html>";
    let bundle = mini_bundle(vec![
        ("GET", "https://mini.example.test/page", None, Some(page)),
        (
            "POST",
            "https://mini.example.test/target",
            Some("SESSIONID=HEAD12345_999999999999&head=HEAD12345&x=4"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(
        script.contains("montado no cliente"),
        "composição parcial deveria ser reconhecida:\n{script}"
    );
    assert!(
        script.contains("('sessionid_cliente', None, 'montado no cliente')"),
        "sufixo montado no cliente deve ser obrigatório:\n{script}"
    );
    assert!(
        !script.contains("999999999999"),
        "sufixo capturado não pode ficar em código nem em comentário:\n{script}"
    );
}

#[test]
fn incomplete_chain_is_refused_and_allow_incomplete_emits_explicit_fail() {
    // A primeira resposta não tem corpo; o alvo consome um valor que só
    // poderia ter vindo dela. A terceira é a ocorrência equivalente completa.
    let bundle = mini_bundle(vec![
        (
            "POST",
            "https://mini.example.test/step",
            Some("field=UNIQUE_A_111"),
            None,
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("field=UNIQUE_B_222"),
            Some("ok"),
        ),
        (
            "POST",
            "https://mini.example.test/step",
            Some("field=UNIQUE_C_333"),
            Some("ok"),
        ),
    ]);
    let err = to_python(
        &bundle.session,
        &bundle,
        "har-0002",
        &PrimingOptions::default(),
    )
    .expect_err("cadeia incompleta deve ser recusada");
    let message = err.to_string();
    assert!(message.contains("cadeia incompleta"), "{message}");
    assert!(message.contains("har-0002 [field]"), "{message}");
    assert!(message.contains("har-0001 (unavailable)"), "{message}");
    assert!(message.contains("har-0003"), "sugestão ausente: {message}");
    assert!(
        message.contains("Nenhum valor capturado é usado no lugar"),
        "{message}"
    );
    assert!(message.contains("--allow-incomplete"), "{message}");

    let opts = PrimingOptions {
        allow_incomplete: true,
        ..PrimingOptions::default()
    };
    let output = to_python(&bundle.session, &bundle, "har-0002", &opts)
        .expect("--allow-incomplete gera o script");
    let script = output.text;
    assert!(
        script.contains("fail('cadeia incompleta: field sem produtor com corpo observ"),
        "passo incompleto precisa falhar explicitamente:\n{script}"
    );
    assert!(
        !script.contains("UNIQUE_B_222"),
        "valor capturado não substitui a origem ausente:\n{script}"
    );
    assert!(
        script.contains("('field', None, 'sem origem observada')"),
        "parâmetro continua obrigatório, sem padrão:\n{script}"
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.code == "priming.incomplete_chain"),
        "aviso da cadeia incompleta ausente"
    );
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);
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
        "bool",
        "exit",
        "find_body_field",
        "find_control",
        "step_error",
        "step_expected",
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
