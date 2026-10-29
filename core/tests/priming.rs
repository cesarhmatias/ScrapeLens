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
    // O único `except SystemExit` é o do `main`, que grava o trace e re-lança.
    assert_eq!(script.matches("except SystemExit").count(), 1, "{script}");
    assert!(
        script.contains("trace_close(base)\n        raise"),
        "o except do main precisa re-lançar:\n{script}"
    );
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
        let request_at = body.find("resp = send(S,").unwrap();
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

/// Driver que roda passos do script gerado com um `S.request` falso, contando
/// quantas requisições foram disparadas antes do `fail()`.
const STEP_DRIVER: &str = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[3])
mode = sys.argv[1]
first = int(sys.argv[2])
class Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}
class Jar:
    def get(self, name):
        return None
class Session:
    cookies = Jar()
class S:
    calls = 0
    def request(self, *a, **k):
        S.calls += 1
        if mode == 'http403':
            return Resp(403, 'no')
        if mode == 'nocontrols':
            return Resp(200, '<html><body>ok</body></html>')
        if mode == 'fillederror':
            return Resp(200, '<html><body><textarea name="STAMP">7</textarea>'
                             '<textarea name="ERRORMESSAGE">Placa invalida</textarea></body></html>')
        return Resp(200, '<html><body><textarea name="STAMP">7</textarea></body></html>')
P = {n: d for n, d, _ in mod['PARAMS']}
try:
    for index in (first, first + 1):
        if 'step_%d' % index not in mod:
            break
        mod['step_%d' % index](S(), {}, P, None)
except SystemExit as exc:
    sys.stderr.write('%s\nCALLS=%d' % (exc, S.calls))
else:
    sys.stderr.write('NO-FAIL CALLS=%d' % S.calls)
"#;

#[test]
fn each_step_stops_on_bad_response_before_the_next_request() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let script = generate(&bundle, &id);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();

    let run = |mode: &str, first: &str| {
        let out = python(&["-c", STEP_DRIVER, mode, first], &path);
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // Status fora de 2xx/3xx: falha no próprio passo, sem pedir o seguinte.
    let stderr = run("http403", "1");
    assert!(stderr.contains("priming: passo 1: HTTP 403"), "{stderr}");
    assert!(stderr.contains("CALLS=1"), "pediu depois do erro: {stderr}");

    // Resposta sem o controle que o passo entrega aos seguintes.
    let stderr = run("nocontrols", "2");
    assert!(
        stderr.contains("priming: passo 2: resposta sem STAMP"),
        "{stderr}"
    );
    assert!(stderr.contains("CALLS=1"), "pediu depois do erro: {stderr}");

    // ERRORMESSAGE preenchido com HTTP 200: erro da aplicação, no passo.
    let stderr = run("fillederror", "2");
    assert!(
        stderr.contains("priming: a aplicação respondeu com ERRORMESSAGE no passo 2"),
        "{stderr}"
    );
    assert!(stderr.contains("CALLS=1"), "pediu depois do erro: {stderr}");
}

#[test]
fn step_error_fails_only_when_errormessage_is_filled() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let script = generate(&bundle, &id);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    let driver = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[1])
class Resp:
    def __init__(self, text):
        self.status_code = 200
        self.text = text
        self.content = text.encode()
        self.headers = {}
try:
    mod['step_error'](Resp('<html><body>sem erro</body></html>'), 9)
    sys.stdout.write('ABSENT-OK\n')
except SystemExit as exc:
    sys.stdout.write('ABSENT-FAIL %s\n' % exc)
try:
    mod['step_error'](Resp('<html><body><textarea name="ERRORMESSAGE">falhou</textarea></body></html>'), 9)
    sys.stdout.write('FILLED-OK\n')
except SystemExit as exc:
    sys.stdout.write('FILLED-FAIL %s\n' % exc)
"#;
    let out = python(&["-c", driver], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ABSENT-OK"),
        "ausência de ERRORMESSAGE virou erro: {stdout}"
    );
    assert!(
        stdout.contains("FILLED-FAIL") && stdout.contains("ERRORMESSAGE"),
        "ERRORMESSAGE preenchido não falhou: {stdout}"
    );
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
    // F1 refinado: navegação da própria cadeia é constante estrutural, não dado
    // de sessão — `op=S37` (query do passo) e `page=NatLogon` (query de uma
    // página da cadeia) podem ter o valor capturado como padrão.
    assert!(
        script.contains("('op', 'S37', 'constante estrutural')"),
        "op é navegação do fluxo e deveria ser constante estrutural:\n{script}"
    );
    assert!(
        script.contains("('page', 'NatLogon', 'constante estrutural')"),
        "page é navegação do fluxo e deveria ser constante estrutural:\n{script}"
    );
    assert!(script.contains("constante estrutural (rota/navegação)"));
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
fn second_round_target_extracts_stamp_from_the_chain_page() {
    // Rodada 2: o alvo consome STAMP=INIT, definido pelo controle da cscform.
    // O produtor registrado é a página da rodada 1 (fora da cadeia gerada);
    // o passo equivalente da própria cadeia (har-0038) define o mesmo valor,
    // então o script extrai em runtime em vez de pedir --stamp.
    let bundle = fixture("detran-pb-real-shape", "real-shape-2rounds.har");
    let script = generate(&bundle, "har-0056");
    assert!(
        !script.contains("('stamp',"),
        "STAMP de página virou parâmetro obrigatório:\n{script}"
    );
    assert!(
        !script.contains("('pageinitparam', None"),
        "PAGEINITPARAM de página virou parâmetro obrigatório:\n{script}"
    );
    assert!(
        script.contains("html_control(R['har-0038'], 'STAMP', 0"),
        "STAMP deveria ser extraído do controle da cscform da cadeia:\n{script}"
    );
    assert!(script.contains("definido pelo controle da página"));
    // Só o que é da sessão/cliente continua obrigatório.
    assert!(script.contains("('sessionid_cliente', None, 'montado no cliente')"));
    assert!(script.contains("('placa', None,"));
}

#[test]
fn page_control_and_literal_are_extracted_not_asked() {
    // A página da cadeia define STAMP por controle e PAGEINITPARAM por
    // literal; o script extrai ambos em runtime.
    let page = "<html><script>var PAGEINITPARAM = \"PI_XYZ\";</script>\
                <input type=\"hidden\" name=\"STAMP\" value=\"INIT\">\
                <div>TOK=abc12345</div></html>";
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/cscform.html",
            None,
            Some(page),
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("token=abc12345&PAGEINITPARAM=PI_XYZ&STAMP=INIT&y=2"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(!script.contains("('stamp',"), "{script}");
    assert!(!script.contains("('pageinitparam',"), "{script}");
    assert!(
        script.contains("html_control(R['har-0001'], 'STAMP'"),
        "STAMP deveria vir do controle da página:\n{script}"
    );
    assert!(
        script.contains("ctx_extract(R['har-0001'].text"),
        "PAGEINITPARAM deveria vir do literal da página:\n{script}"
    );
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
fn navigation_values_are_structural_constants() {
    // O passo 1 é navegação da cadeia (`op`/`page` na query e `SIM1000X.html`
    // no caminho); o alvo repete esses valores. São constantes estruturais.
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/app?op=S37&page=NatLogon",
            None,
            Some("TOK=abc12345"),
        ),
        (
            "GET",
            "https://mini.example.test/UIC-SERVICOS/SIM1000X.html",
            None,
            Some("TOK=def67890"),
        ),
        (
            "POST",
            "https://mini.example.test/target",
            Some("token=abc12345&token2=def67890&op=S37&page=NatLogon&page_2=SIM1000X&code=42"),
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0003");
    for expected in [
        "('op', 'S37', 'constante estrutural')",
        "('page', 'NatLogon', 'constante estrutural')",
        "('page_2', 'SIM1000X', 'constante estrutural')",
    ] {
        assert!(
            script.contains(expected),
            "{expected} deveria ser constante estrutural:\n{script}"
        );
    }
    // Fora da navegação, sem prova de constância, segue obrigatório.
    assert!(
        script.contains("('code', None, 'sem origem observada')"),
        "query que não é de navegação não pode ganhar padrão:\n{script}"
    );
}

#[test]
fn structural_constant_never_covers_sensitive_or_business_values() {
    // A placa aparece no caminho/query da navegação, mas é dado de negócio:
    // continua obrigatória e o valor capturado não entra no script.
    let bundle = mini_bundle(vec![(
        "GET",
        "https://mini.example.test/produto.html?placa=TST0T10",
        None,
        Some("ok"),
    )]);
    let script = generate(&bundle, "har-0001");
    assert!(
        script.contains("('placa', None,"),
        "placa não pode virar padrão:\n{script}"
    );
    assert!(
        !script.contains("TST0T10"),
        "placa capturada não pode aparecer no script"
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
        "find",
        "b64encode",
        "trace_time",
        "strftime",
        "pop",
        "rebase",
        "extend",
        "append",
        "dumps",
        "time",
        "timezone",
        "open",
        "ascii",
        "decode",
        "encode",
        "round",
        "bytes",
        "fromtimestamp",
        "memoryview",
        "fchmod",
        "isoformat",
        "trace_body",
        "trace_open",
        "trace_exchange",
        "trace_check",
        "trace_close",
        "send",
        "safe_text",
        "url_origin",
        "float",
        "json_num",
        "json_bool",
        "bool",
        "isprintable",
        "str",
        "urlsplit",
        "urljoin",
        "lower",
        "request",
        "items",
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
bad = [n for n in ast.walk(tree) if (isinstance(n, ast.Name) and n.id == '__import__') or (isinstance(n, ast.Attribute) and n.attr in ('system', 'popen', 'spawn'))]
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

/// Driver sem rede: sessão falsa que responde com um redirect e registra o
/// que foi enviado e para onde.
const REDIRECT_DRIVER: &str = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[1])
status, location = int(sys.argv[2]), sys.argv[3]
class Resp:
    def __init__(self, code, loc=None):
        self.status_code = code
        self.headers = {'Location': loc} if loc else {}
        self.text = ''
        self.content = b'x'
class S:
    cookies = {}
    def __init__(self):
        self.sent = []
    def request(self, method, url, **kw):
        assert kw.get('allow_redirects') is False, 'allow_redirects precisa ser False'
        self.sent.append((method, url))
        if len(self.sent) == 1:
            return Resp(status, location)
        return Resp(200)
s = S()
try:
    mod['step_1'](s, {}, {}, 'http://127.0.0.1:9')
    print('OK', s.sent)
except SystemExit as exc:
    print('FAIL', exc, s.sent)
"#;

#[test]
fn redirects_never_leave_the_base_origin() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    assert!(script.contains("allow_redirects=False"));
    for status in ["301", "302", "303", "307", "308"] {
        let out = Command::new("python3")
            .arg("-I")
            .args(["-c", REDIRECT_DRIVER])
            .arg(&path)
            .args([status, "http://evil.invalid/x"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("FAIL") && stdout.contains("redirect para outro origin"),
            "{status}: redirect para outro origin deveria falhar: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !stdout.contains("evil.invalid') ]") && stdout.matches("http://").count() <= 2,
            "{status}: nada pode ser enviado ao outro origin: {stdout}"
        );
        assert!(
            !stdout.contains("('GET', 'http://evil") && !stdout.contains("('POST', 'http://evil"),
            "{status}: enviou ao outro origin: {stdout}"
        );
        let out = Command::new("python3")
            .arg("-I")
            .args(["-c", REDIRECT_DRIVER])
            .arg(&path)
            .args([status, "/destino"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("OK") && stdout.contains("http://127.0.0.1:9/destino"),
            "{status}: mesmo origin deveria seguir: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn rebase_compares_the_exact_origin() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    let driver = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[1])
o = mod['CAPTURED_ORIGIN']
print(mod['rebase'](o + '.evil.example/x', 'http://127.0.0.1:1'))
print(mod['rebase'](o + '/x', 'http://127.0.0.1:1'))
"#;
    let out = python(&["-c", driver], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[0].contains(".evil.example") && !lines[0].starts_with("http://127.0.0.1:1"),
        "{stdout}"
    );
    assert_eq!(lines[1], "http://127.0.0.1:1/x");
}

#[test]
fn ctx_extract_is_linear_on_hostile_input() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    let driver = r#"
import runpy, sys, time
mod = runpy.run_path(sys.argv[1])
for text, before, after in [('Page' * 40000, 'Page', 'ZZ'), ('sId = "' * 40000, 'sId = "', '"X')]:
    t = time.time()
    try:
        mod['ctx_extract'](text, before, after, 'teste')
    except SystemExit:
        pass
    print('%.3f' % (time.time() - t))
print(mod['ctx_extract']('a[xyz]b', 'a[', ']b', 't'))
print(mod['safe_text']('a\x1b[31m\u202eb\n'))
"#;
    let out = python(&["-c", driver], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    for l in &lines[..2] {
        assert!(l.parse::<f64>().unwrap() < 1.0, "lento: {stdout}");
    }
    assert_eq!(lines[2], "xyz");
    assert_eq!(lines[3], "a?[31m?b?");
}

#[test]
fn foreign_origin_steps_are_refused_unless_allowed() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let mut bundle = bundle;
    // Move o primeiro passo não-alvo para outro host.
    let mut moved = false;
    for r in bundle.session.requests.iter_mut() {
        if !moved && r.id != id && r.url.starts_with("http") && r.url.contains("cscform") {
            r.url = r.url.replacen("://", "://outro.example.invalid-", 1);
            moved = true;
        }
    }
    assert!(moved);
    let err = to_python(&bundle.session, &bundle, &id, &PrimingOptions::default());
    if let Err(e) = err {
        assert!(e.to_string().contains("--allow-origin"), "{e}");
    }
}

#[test]
fn path_params_and_pii_names_are_data_not_literals() {
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/app;jsessionid=SESSVAL1234ABCD?nome=Fulano&email=a@b.test&callback=jQuery123_456&v=1.2.3&op=S37",
            None,
            Some("ok"),
        ),
        (
            "GET",
            "https://mini.example.test/target;jsessionid=SESSVAL1234ABCD?op=S37&nome=Fulano&email=a@b.test&callback=jQuery123_456&v=1.2.3&rg=99887&target=x",
            None,
            Some("ok"),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    for leaked in [
        "SESSVAL1234ABCD",
        "Fulano",
        "a@b.test",
        "jQuery123_456",
        "1.2.3",
        "99887",
    ] {
        assert!(!script.contains(leaked), "{leaked} vazou:\n{script}");
    }
    assert!(script.contains("jsessionid"), "{script}");
    assert!(script.contains("('path_jsessionid', None,"), "{script}");
    for name in ["nome", "email", "callback", "v", "rg"] {
        assert!(
            script.contains(&format!("('{name}', None,")),
            "{name} deveria ser obrigatório:\n{script}"
        );
    }
    // Estrutural continua padrão; `target` não é sensível por conter `rg`.
    assert!(script.contains("('op', 'S37', 'constante estrutural')"));
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);
}

/// HAR sintético com headers/Content-Type próprios; a última entrada é o alvo.
type CustomEntry<'a> = (
    &'a str,
    &'a str,
    &'a [(&'a str, &'a str)],
    Option<(&'a str, &'a str)>,
);

fn custom_bundle(entries: &[CustomEntry]) -> SessionBundle {
    let entries: Vec<serde_json::Value> = entries
        .iter()
        .enumerate()
        .map(|(i, (method, url, headers, body))| {
            let mut hs: Vec<serde_json::Value> = headers
                .iter()
                .map(|(k, v)| serde_json::json!({"name": k, "value": v}))
                .collect();
            let mut request = serde_json::json!({
                "method": method, "url": url, "httpVersion": "HTTP/1.1",
                "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0
            });
            if let Some((ctype, text)) = body {
                hs.push(serde_json::json!({"name": "Content-Type", "value": ctype}));
                request["bodySize"] = serde_json::json!(text.len());
                request["postData"] = serde_json::json!({"mimeType": ctype, "text": text});
            }
            request["headers"] = serde_json::Value::Array(hs);
            serde_json::json!({
                "startedDateTime": format!("2026-10-27T12:00:{i:02}.000Z"), "time": 1,
                "request": request,
                "response": {
                    "status": 200, "statusText": "", "httpVersion": "HTTP/1.1",
                    "headers": [], "cookies": [], "headersSize": -1, "bodySize": 40,
                    "redirectURL": "",
                    "content": {"size": 40, "mimeType": "text/html", "text": "<input type=hidden name=\"tok\" value=\"abc12345\">"}
                },
                "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
            })
        })
        .collect();
    let har = serde_json::json!({
        "log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}
    });
    import_har(har.to_string().as_bytes()).expect("HAR").bundle
}

#[test]
fn credential_headers_are_never_literal_and_referer_is_runtime_only() {
    let secrets = [
        ("x-api-key", "AKEYVALUE111"),
        ("X-Auth-Token", "ATOKENVALUE222"),
        ("x-csrf-token", "CSRFVALUE333"),
        ("x-xsrf-token", "XSRFVALUE444"),
        ("x-session-id", "SESSIONVALUE555"),
        ("x-jwt", "JWTVALUE666"),
        ("x-access-token", "ACCESSVALUE777"),
        ("private-token", "PRIVVALUE888"),
        ("x-amz-security-token", "AMZVALUE999"),
        ("x-custom-secret", "CUSTSECRET000"),
        ("x-user", "USERVALUE1010"),
        ("x-device-id", "DEVICEVALUE1111"),
        ("x-trace", "eyJhbGciOiJIUzI1NiJ9.payload.sig"),
    ];
    let mut headers: Vec<(&str, &str)> = secrets.to_vec();
    headers.push((
        "Referer",
        "https://h.example.test/pagina?cpf=00000000191&q=1",
    ));
    headers.push(("User-Agent", "Mozilla/5.0 teste"));
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &headers, None)]);
    let script = generate(&bundle, "har-0001");
    for (name, value) in secrets {
        assert!(!script.contains(value), "{name} vazou:\n{script}");
    }
    assert!(!script.contains("00000000191"), "query do Referer vazou");
    assert!(
        !script.contains("'Referer'"),
        "sem passo anterior, Referer é omitido"
    );
    assert!(
        script.contains("Mozilla/5.0 teste"),
        "User-Agent segue literal"
    );
    assert!(script.contains("('x_api_key', None,"), "{script}");
    assert!(script.contains("('x_jwt', None,"), "{script}");

    // Com passo anterior de mesmo origin+caminho, o Referer vem do runtime.
    let bundle = custom_bundle(&[
        (
            "GET",
            "https://h.example.test/pagina?cpf=00000000191",
            &[],
            None,
        ),
        (
            "GET",
            "https://h.example.test/alvo?tok=abc12345",
            &[("Referer", "https://h.example.test/pagina?cpf=00000000191")],
            None,
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(
        script.contains("'Referer': referer_for(R['har-0001'].url, url)"),
        "{script}"
    );
    assert!(!script.contains("00000000191"));
}

#[test]
fn json_body_is_decomposed_and_sensitive_fields_are_required() {
    let body = r#"{"STAMP":"INIT","nome":"Fulano Teste","cpf":"00000000191","cartao":"4111111111111111","n":3,"ok":true,"end":{"rua":"Rua Sintetica 1"}}"#;
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("application/json", body)),
    )]);
    let script = generate(&bundle, "har-0001");
    for leaked in [
        "Fulano Teste",
        "00000000191",
        "4111111111111111",
        "Rua Sintetica",
    ] {
        assert!(!script.contains(leaked), "{leaked} vazou:\n{script}");
    }
    assert!(script.contains("json.dumps("), "{script}");
    for name in ["nome", "cpf", "cartao", "end_rua"] {
        assert!(
            script.contains(&format!("('{name}', None,")),
            "{name}:\n{script}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);
}

#[test]
fn non_form_non_json_body_is_refused_unless_allowed() {
    let body = "<req><nome>Fulano Teste</nome><cpf>00000000191</cpf><mail>a@b.test</mail><obs>livre</obs></req>";
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("text/xml", body)),
    )]);
    let err = to_python(
        &bundle.session,
        &bundle,
        "har-0001",
        &PrimingOptions::default(),
    )
    .expect_err("recusa por padrão");
    assert!(err.to_string().contains("--allow-literal-body"), "{err}");
    let opts = PrimingOptions {
        allow_literal_body: true,
        ..PrimingOptions::default()
    };
    let out = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("com a opção");
    for leaked in ["Fulano Teste", "00000000191", "a@b.test"] {
        assert!(!out.text.contains(leaked), "{leaked} vazou:\n{}", out.text);
    }
    assert!(out.text.contains("livre"), "o resto fica congelado");
    assert!(out
        .warnings
        .iter()
        .any(|w| w.code == "priming.body_literal"));
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&out.text, &dir);
}

#[test]
fn dynamic_ids_are_never_structural_constants() {
    let url = "https://h.example.test/app?op=S37&t=eyJhbGciOiJIUzI1NiJ9&u=01ARZ3NDEKTSV4RRFFQ69G5FAV&d=2026-10-27T12:00:00Z&n=12345&m=aB3dE9xK&sess_ref=abc";
    let bundle = custom_bundle(&[("GET", url, &[], None)]);
    let script = generate(&bundle, "har-0001");
    for leaked in [
        "eyJhbGciOiJIUzI1NiJ9",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "2026-10-27T12:00:00Z",
        "12345",
        "aB3dE9xK",
    ] {
        assert!(!script.contains(leaked), "{leaked} virou padrão:\n{script}");
    }
    assert!(script.contains("('op', 'S37', 'constante estrutural')"));
    assert!(script.contains("('sess_ref', None,"), "{script}");
}

#[test]
fn script_ignores_environment_proxy_by_default() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    assert!(script.contains("--usar-proxy-do-ambiente"));
    assert!(script.contains("S.trust_env = bool(args.usar_proxy_do_ambiente)"));
    assert!(script.contains("Python < 3.13"));
}

#[test]
fn json_under_a_form_content_type_is_never_literal() {
    let body =
        r#"{"STAMP":"INIT","nome":"Fulano Teste","cpf":"00000000191","cartao":"4111111111111111"}"#;
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("application/x-www-form-urlencoded; charset=UTF-8", body)),
    )]);
    let script = generate(&bundle, "har-0001");
    for leaked in ["Fulano Teste", "00000000191", "4111111111111111"] {
        assert!(!script.contains(leaked), "{leaked} vazou:\n{script}");
    }
    assert!(script.contains("json.dumps("), "{script}");
    assert!(script.contains("('cpf', None,"));
    assert!(script.contains("application/x-www-form-urlencoded"));
    // Texto livre com cara de form, sem '=' e longo: recusado.
    let free = "Fulano Teste de Tal, CPF 00000000191, mora na Rua Sintetica 1 em Cidade";
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("application/x-www-form-urlencoded", free)),
    )]);
    let err = to_python(
        &bundle.session,
        &bundle,
        "har-0001",
        &PrimingOptions::default(),
    )
    .expect_err("recusa");
    assert!(err.to_string().contains("sem '='"), "{err}");
}

#[test]
fn auth_schemes_by_value_and_extra_names_are_never_literal() {
    let headers = [
        ("x-hmac", "HMACVALUE1"),
        ("x-bearer", "BEARERVALUE2"),
        ("x-digest", "DIGESTVALUE3"),
        ("x-nonce", "NONCEVALUE4"),
        ("x-foo", "Bearer SCHEMEVALUE5"),
        ("x-bar", "Basic SCHEMEVALUE6"),
        ("x-baz", "Digest SCHEMEVALUE7"),
        ("x-qux", "Negotiate SCHEMEVALUE8"),
        ("x-forwarded-for", "203.0.113.9"),
        ("x-note", "texto livre"),
    ];
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &headers, None)]);
    let script = generate(&bundle, "har-0001");
    for (name, value) in headers {
        if name == "x-note" {
            assert!(script.contains(value));
        } else {
            let secret = value.rsplit(' ').next().unwrap();
            assert!(!script.contains(secret), "{name} vazou:\n{script}");
        }
    }
    assert!(!script.contains("203.0.113.9") && !script.contains("'x-forwarded-for'"));
    assert!(script.contains("('x_foo', None,"), "{script}");
}

#[test]
fn cross_origin_referer_carries_only_the_origin() {
    let bundle = custom_bundle(&[
        (
            "GET",
            "https://outro.example.test/pagina?cpf=00000000191",
            &[],
            None,
        ),
        (
            "GET",
            "https://h.example.test/alvo?tok=abc12345",
            &[(
                "Referer",
                "https://outro.example.test/pagina?cpf=00000000191",
            )],
            None,
        ),
    ]);
    let opts = PrimingOptions {
        allow_origins: vec!["https://outro.example.test".to_string()],
        ..PrimingOptions::default()
    };
    let out = to_python(&bundle.session, &bundle, "har-0002", &opts).expect("gera");
    assert!(
        out.text
            .contains("'Referer': referer_for(R['har-0001'].url, url)"),
        "{}",
        out.text
    );
    assert!(!out.text.contains("00000000191"));
}

const PII_JSON: &str = r#"{"STAMP":"INIT","nome":"Maria Silva","email":"a@b.test","cpf":"12345678909","cartao":"4111111111111111","dados":{"cpf2":"98765432100"}}"#;
const PII_VALUES: [&str; 6] = [
    "Maria Silva",
    "a@b.test",
    "12345678909",
    "4111111111111111",
    "98765432100",
    "4111",
];

fn assert_no_pii(script: &str, label: &str) {
    for value in PII_VALUES {
        assert!(!script.contains(value), "{label}: {value} vazou:\n{script}");
    }
}

fn form_bundle(body: &str) -> SessionBundle {
    custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("application/x-www-form-urlencoded", body)),
    )])
}

#[test]
fn json_inside_field_values_is_decomposed_recursively() {
    let encoded: String = url_encode(PII_JSON);
    let double = url_encode(&encoded);
    let nested = serde_json::json!({"payload": PII_JSON, "x": 1}).to_string();
    for (label, body) in [
        ("data=<json> codificado", format!("data={encoded}")),
        ("data=<json> cru", format!("data={PII_JSON}")),
        (
            "payload + outros",
            format!("payload={encoded}&x=1&STAMP=INIT"),
        ),
        ("a=1&b=<json>", format!("a=1&b={encoded}")),
        ("codificado duas vezes", format!("data={double}")),
    ] {
        let script = generate(&form_bundle(&body), "har-0001");
        assert_no_pii(&script, label);
        assert!(script.contains("json.dumps("), "{label}:\n{script}");
        let dir = tempfile::tempdir().unwrap();
        ast_calls(&script, &dir);
    }
    // JSON dentro de string JSON, sob application/json.
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some(("application/json", &nested)),
    )]);
    assert_no_pii(&generate(&bundle, "har-0001"), "{\"payload\":\"<json>\"}");
}

#[test]
fn partial_json_and_free_text_with_pii_are_refused_or_parameterised() {
    let partial = format!("data={}", url_encode(&PII_JSON[..90]));
    let free = "Maria Silva CPF 12345678909 tel 83999";
    for (label, body) in [("JSON parcial", partial.as_str()), ("campo sem =", free)] {
        match to_python(
            &form_bundle(body).session,
            &form_bundle(body),
            "har-0001",
            &PrimingOptions::default(),
        ) {
            Ok(out) => assert_no_pii(&out.text, label),
            Err(e) => assert!(
                !e.to_string().contains("12345678909") && !e.to_string().contains("Maria"),
                "{label}: a mensagem não pode trazer o valor: {e}"
            ),
        }
    }
    // A barreira final recusa listando tipos, sem valores.
    let bundle = form_bundle(free);
    let err = to_python(
        &bundle.session,
        &bundle,
        "har-0001",
        &PrimingOptions::default(),
    )
    .expect_err("recusa");
    let message = err.to_string();
    assert!(message.contains("dado pessoal"), "{message}");
    assert!(!message.contains("12345678909"));
}

#[test]
fn referer_for_sends_only_the_origin_across_origins() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    let driver = r#"
import runpy, sys
mod = runpy.run_path(sys.argv[1])
f = mod['referer_for']
print(f('https://a.test/p?cpf=1', 'https://b.test/x'))
print(f('https://a.test/p?q=1', 'https://a.test/x'))
"#;
    let out = python(&["-c", driver], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        ["https://a.test/", "https://a.test/p?q=1"],
        "{stdout}"
    );
}

#[test]
fn header_and_query_literals_with_pii_become_required_parameters() {
    let bundle = custom_bundle(&[(
        "GET",
        "https://h.example.test/api?contato=a%40b.test&cartao_x=4111111111111111&q=1",
        &[("X-Note", "fale com a@b.test")],
        None,
    )]);
    let script = generate(&bundle, "har-0001");
    assert!(!script.contains("a@b.test") && !script.contains("a%40b.test"));
    assert!(!script.contains("4111111111111111"));
}

fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[test]
fn business_pii_formats_never_reach_literals_or_the_plan() {
    // (rótulo, valor): placa com hífen, Mercosul com hífen, chassi, +55,
    // cartão série 2 e de 19 dígitos (Luhn), largura total.
    let values = [
        ("placa hífen", "ABC-1234"),
        ("placa Mercosul hífen", "ABC-1D23"),
        ("chassi", "9BWZZZ377VT004251"),
        ("+55 pontuado", "+55 83 99999-8888"),
        ("55 cru", "5583999998888"),
        ("cartão série 2", "2223000048400011"),
        ("cartão 19", "6221260000000000001"),
        ("largura total", "１２３４５６７８９０９"),
    ];
    for (label, value) in values {
        let encoded = url_encode(value);
        // Query com nome genérico (nunca constante estrutural).
        let bundle = custom_bundle(&[(
            "GET",
            &format!("https://h.example.test/go?ref={encoded}&p=1"),
            &[],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(
            !script.contains(value) && !script.contains(&encoded),
            "{label} em query:\n{script}"
        );
        assert!(
            script.contains("('ref', None,"),
            "{label}: query deve ser obrigatória"
        );
        // Header de nome qualquer.
        let bundle = custom_bundle(&[(
            "GET",
            "https://h.example.test/go",
            &[("x-foo", value)],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(!script.contains(value), "{label} em header:\n{script}");
        // Segmento de caminho: vira parâmetro, nunca literal nem plano.
        let bundle = custom_bundle(&[(
            "GET",
            &format!("https://h.example.test/go/{encoded}/fim"),
            &[],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(
            !script.contains(value) && !script.contains(&encoded),
            "{label} no caminho:\n{script}"
        );
        assert!(script.contains("path_segmento_2"), "{label}:\n{script}");
        assert!(script.contains("/fim"));
        // Chave de form.
        let bundle = form_bundle(&format!("{encoded}=1"));
        match to_python(
            &bundle.session,
            &bundle,
            "har-0001",
            &PrimingOptions::default(),
        ) {
            Ok(out) => assert!(!out.text.contains(value), "{label} em chave:\n{}", out.text),
            Err(e) => assert!(!e.to_string().contains(value)),
        }
    }
    // O mesmo placa_ref=ABC-1234 do revisor.
    let bundle = custom_bundle(&[(
        "GET",
        "https://h.example.test/go?placa_ref=ABC-1234",
        &[],
        None,
    )]);
    let script = generate(&bundle, "har-0001");
    assert!(!script.contains("ABC-1234"));
    assert!(script.contains("('placa_ref', None,"));
}

/// Adaptador de brinquedo `kv:a=1;b=2` para exercitar o caminho genérico do
/// priming sem nenhum conhecimento de protocolo real no core.
struct KvAdapter;

impl scrapelens_core::adapter::ProtocolAdapter for KvAdapter {
    fn id(&self) -> &str {
        "kv"
    }
    fn detect(
        &self,
        field: &str,
        value: &str,
        _ctx: &scrapelens_core::adapter::AdapterContext<'_>,
    ) -> bool {
        field == "XML" && value.starts_with("kv:")
    }
    fn decode(&self, value: &str) -> scrapelens_core::Result<scrapelens_core::adapter::Decoded> {
        use scrapelens_core::adapter::{AdapterPart, PartRole};
        let body = value.strip_prefix("kv:").unwrap_or(value);
        let mut parts = vec![AdapterPart {
            name: "op".into(),
            value: "kv:".into(),
            offset: 0,
            len: 3,
            role: PartRole::Structure,
        }];
        let mut at = 3;
        for pair in body.split(';') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            parts.push(AdapterPart {
                name: format!("p.{k}"),
                value: v.to_string(),
                offset: at + k.len() + 1,
                len: v.len(),
                role: PartRole::Value,
            });
            at += pair.len() + 1;
        }
        Ok(scrapelens_core::adapter::Decoded { parts })
    }
    fn encode(&self, d: &scrapelens_core::adapter::Decoded) -> scrapelens_core::Result<String> {
        let pairs: Vec<String> = d
            .parts
            .iter()
            .filter(|p| p.name != "op")
            .map(|p| format!("{}={}", p.name.trim_start_matches("p."), p.value))
            .collect();
        Ok(format!("kv:{}", pairs.join(";")))
    }
}

#[test]
fn claimed_field_is_built_by_parts_with_the_adapter_encoder() {
    use scrapelens_core::adapter::AdapterRegistry;
    use scrapelens_core::export::priming::AdapterEncoder;
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/api",
        &[],
        Some((
            "application/x-www-form-urlencoded",
            "XML=kv%3Av_placa%3DTST0T10%3Bmodo%3Dfixo",
        )),
    )]);
    let mut opts = PrimingOptions::default();
    opts.flow.adapters = AdapterRegistry::new().with(std::sync::Arc::new(KvAdapter));
    // Sem codificador Python, volta ao tratamento por trechos.
    let plain = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("gera");
    assert!(!plain.text.contains("kv_encode"));
    opts.adapter_encoders.push(AdapterEncoder {
        adapter_id: "kv".into(),
        function: "kv_encode".into(),
        decoder: String::new(),
        source: "def kv_encode(parts):\n    return 'kv:' + ';'.join(\n        n[2:] + '=' + v for n, r, v in parts if n != 'op')\n".into(),
    });
    let out = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("gera");
    assert!(
        out.text
            .contains("kv_encode([('op', 'S', 'kv:'), ('p.v_placa', 'V', P['placa'])"),
        "{}",
        out.text
    );
    assert!(out.text.contains("def kv_encode"));
    assert!(
        !out.text.contains("TST0T10"),
        "placa capturada não pode ficar"
    );
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&out.text, &dir);
}

/// Driver sem rede: injeta um módulo `requests` falso e roda o `main` do
/// script gerado com `--trace`.
const TRACE_DRIVER: &str = r#"
import json, runpy, sys, types
script, status, *argv = sys.argv[1:]
class Hdr(dict):
    pass
class Req:
    def __init__(self, method, url, body):
        self.method, self.url, self.body = method, url, body
        self.headers = Hdr({'Accept': '*/*', 'User-Agent': 'fake/1.0'})
class Resp:
    def __init__(self, req, code):
        self.status_code = code
        self.headers = Hdr({'Content-Type': 'text/html'})
        self.text = '<input type="hidden" name="tok" value="abc12345">'
        self.content = self.text.encode()
        if __import__('os').environ.get('TRACE_BIG'):
            self.content = b'x' * (3 * 1024 * 1024)
        self.request = req
        self.url = req.url
class Jar:
    def get(self, name):
        return None
class Session:
    trust_env = True
    cookies = Jar()
    def request(self, method, url, **kw):
        data = kw.get('data')
        return Resp(Req(method, url, data), int(status))
fake = types.ModuleType('requests')
fake.Session = Session
sys.modules['requests'] = fake
mod = runpy.run_path(script, run_name='priming_test')
sys.argv = [script] + argv
try:
    mod['main']()
    print('RC 0')
except SystemExit as exc:
    print('RC', exc.code)
"#;

fn trace_run(script: &std::path::Path, status: u32, args: &[&str]) -> std::process::Output {
    Command::new("python3")
        .arg("-I")
        .args(["-c", TRACE_DRIVER])
        .arg(script)
        .arg(status.to_string())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn trace_file_has_the_schema_mode_0600_and_refuses_existing_files_and_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &[], None)]);
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("priming.py");
    std::fs::write(&script_path, &script).unwrap();

    // Execução ok.
    let trace = dir.path().join("trace.json");
    let out = trace_run(&script_path, 200, &["--trace", trace.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("RC 0"), "{stdout}{stderr}");
    assert!(
        stderr.contains("o trace contém dados da sua sessão; não compartilhe sem sanitizar"),
        "{stderr}"
    );
    let mode = std::fs::metadata(&trace).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    assert_eq!(doc["schema"], "scrapelens.trace/1");
    let exchange = &doc["steps"][0];
    assert_eq!(exchange["checks"][0]["ok"], true);
    assert_eq!(exchange["method"], "GET");
    assert_eq!(exchange["status"], 200);
    assert!(exchange["requestHeaders"].is_array() && exchange["responseHeaders"].is_array());
    assert_eq!(exchange["responseBody"]["truncated"], false);

    // Já existe: recusa, sem sobrescrever.
    let before = std::fs::read(&trace).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", trace.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert_eq!(std::fs::read(&trace).unwrap(), before);
    // Link simbólico (existente e pendente): recusa e não escreve no alvo.
    let target = dir.path().join("alvo.txt");
    std::fs::write(&target, "intacto").unwrap();
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", link.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "intacto");
    let dangling = dir.path().join("pendente.json");
    symlink(dir.path().join("nao-existe.json"), &dangling).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", dangling.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert!(!dir.path().join("nao-existe.json").exists());

    // Falha no passo: o trace é gravado até o passo ruim, com a falha registrada.
    let failing = dir.path().join("falha.json");
    let out = trace_run(&script_path, 403, &["--trace", failing.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: passo 1: HTTP 403"));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&failing).unwrap()).unwrap();
    assert_eq!(doc["steps"][0]["checks"][0]["ok"], false);
    assert!(doc["steps"][0]["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("HTTP 403"));
    assert_eq!(doc["steps"][0]["status"], 403);
    // O core importa o trace gravado (esquema exato).
    let session = dir.path().join("trace-session");
    let import = Command::new(env!("CARGO_BIN_EXE_scrapelens-core"))
        .arg("import-trace")
        .arg(&failing)
        .arg("--out")
        .arg(&session)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert_eq!(
        std::fs::metadata(&failing).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Sem --trace, nada é criado; no modo plano (passo que altera estado, sem
    // --confirmar), nada é gravado.
    let post = custom_bundle(&[(
        "POST",
        "https://h.example.test/alvo",
        &[],
        Some(("application/x-www-form-urlencoded", "a=1")),
    )]);
    let post_script = dir.path().join("post.py");
    std::fs::write(&post_script, generate(&post, "har-0001")).unwrap();
    let plan_trace = dir.path().join("plano.json");
    let out = trace_run(
        &post_script,
        200,
        &["--trace", plan_trace.to_str().unwrap()],
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nada foi enviado"));
    assert!(!plan_trace.exists());
}

#[test]
fn trace_bodies_are_capped_at_2_mib_with_truncated_state() {
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &[], None)]);
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("p.py");
    std::fs::write(&script, generate(&bundle, "har-0001")).unwrap();
    let trace = dir.path().join("t.json");
    let out = Command::new("python3")
        .arg("-I")
        .args(["-c", TRACE_DRIVER])
        .arg(&script)
        .arg("200")
        .args(["--trace", trace.to_str().unwrap()])
        .env("TRACE_BIG", "1")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC 0"));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    let body = &doc["steps"][0]["responseBody"];
    assert_eq!(body["truncated"], true);
    assert_eq!(body["size"], 3 * 1024 * 1024);
    assert_eq!(body["text"].as_str().unwrap().len(), 2 * 1024 * 1024);
}

#[test]
fn trace_records_every_step_of_a_multi_step_chain() {
    let bundle = custom_bundle(&[
        ("GET", "https://h.example.test/pagina", &[], None),
        ("GET", "https://h.example.test/alvo?tok=abc12345", &[], None),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("p.py");
    std::fs::write(&script, generate(&bundle, "har-0002")).unwrap();
    let trace = dir.path().join("t.json");
    let out = trace_run(&script, 200, &["--trace", trace.to_str().unwrap()]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("RC 0"),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    let steps = doc["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 2, "{doc}");
    assert!(steps.iter().all(|s| s["checks"][0]["ok"] == true));
}
