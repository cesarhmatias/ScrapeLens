//! Python priming script (docs/11-priming-success.md §1, acceptance 1 and 4).

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
    import_har(&bytes).expect("imports HAR").bundle
}

fn generate(bundle: &SessionBundle, id: &str) -> String {
    to_python(&bundle.session, bundle, id, &PrimingOptions::default())
        .expect("generates the script")
        .text
}

fn python(args: &[&str], file: &std::path::Path) -> std::process::Output {
    Command::new("python3")
        .arg("-I")
        .args(args)
        .arg(file)
        .output()
        .expect("python3 available")
}

/// `ast.parse` + list of the names called anywhere in the module.
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
        "ast.parse failed: {}",
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
    // One `step_N` per plan step; each one checks status and ERRORMESSAGE
    // INSIDE the function, before returning the response to the next request.
    let steps = script
        .match_indices("\ndef step_")
        .filter(|(i, _)| {
            script[i + "\ndef step_".len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert!(steps >= 9, "expected steps for the target:\n{script}");
    assert_eq!(
        script
            .matches("if not (200 <= resp.status_code < 400):")
            .count(),
        steps
    );
    assert_eq!(script.matches("\n    step_error(resp, ").count(), steps);
    assert_eq!(
        script.matches("except UnicodeEncodeError as exc").count(),
        steps
    );
    // A missing ERRORMESSAGE must not become a swallowed error: no
    // `except SystemExit` in the script, and the check only fails if there is a value.
    // The only `except SystemExit` is the one in `main`, which writes the trace and re-raises.
    assert_eq!(script.matches("except SystemExit").count(), 1, "{script}");
    assert!(
        script.contains("trace_close(base)\n        raise"),
        "the except in main must re-raise:\n{script}"
    );
    assert!(!script.contains("erro = ''"), "{script}");
    assert!(script.contains("if value is not None and value.strip():"));
    // Every step that produces a control for another has the check in its own
    // function, before `return resp`; never in the main loop.
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
                "field check out of order in step {name}:\n{body}"
            );
        }
    }
    // The XML that the producing step hands to the following ones is checked there.
    let producer = script
        .split("\ndef step_")
        .find(|chunk| chunk.contains("('control', 'XML', 0)"))
        .expect("no step checks the XML it produces");
    assert!(
        producer.contains("step_expected(resp, S,"),
        "producer step without a check of the XML:\n{producer}"
    );
}

/// Minimal HAR with a header whose value does not fit in latin-1.
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
        .expect("HAR with a header outside latin-1")
        .bundle
}

/// Driver that runs steps of the generated script with a fake `S.request`, counting
/// how many requests were fired before `fail()`.
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
                             '<textarea name="ERRORMESSAGE">Invalid plate</textarea></body></html>')
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

    // Status outside 2xx/3xx: fails in the step itself, without requesting the next one.
    let stderr = run("http403", "1");
    assert!(stderr.contains("priming: step 1: HTTP 403"), "{stderr}");
    assert!(stderr.contains("CALLS=1"), "requested after the error: {stderr}");

    // Response without the control that the step hands to the following ones.
    let stderr = run("nocontrols", "2");
    assert!(
        stderr.contains("priming: step 2: response without STAMP"),
        "{stderr}"
    );
    assert!(stderr.contains("CALLS=1"), "requested after the error: {stderr}");

    // ERRORMESSAGE filled in with HTTP 200: application error, at the step.
    let stderr = run("fillederror", "2");
    assert!(
        stderr.contains("priming: the application responded with ERRORMESSAGE in step 2"),
        "{stderr}"
    );
    assert!(stderr.contains("CALLS=1"), "requested after the error: {stderr}");
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
    mod['step_error'](Resp('<html><body>no error</body></html>'), 9)
    sys.stdout.write('ABSENT-OK\n')
except SystemExit as exc:
    sys.stdout.write('ABSENT-FAIL %s\n' % exc)
try:
    mod['step_error'](Resp('<html><body><textarea name="ERRORMESSAGE">failed</textarea></body></html>'), 9)
    sys.stdout.write('FILLED-OK\n')
except SystemExit as exc:
    sys.stdout.write('FILLED-FAIL %s\n' % exc)
"#;
    let out = python(&["-c", driver], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ABSENT-OK"),
        "absence of ERRORMESSAGE became an error: {stdout}"
    );
    assert!(
        stdout.contains("FILLED-FAIL") && stdout.contains("ERRORMESSAGE"),
        "filled ERRORMESSAGE did not fail: {stdout}"
    );
}

#[test]
fn header_outside_latin1_fails_with_a_clear_priming_message() {
    let bundle = header_outside_latin1_bundle();
    let script = generate(&bundle, "har-0001");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    // `requests` encodes headers in latin-1. The driver simulates the exception in the
    // step (no network and without depending on the `requests` package).
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
        "message without prefix:\n{stderr}"
    );
    assert!(
        stderr.contains("outside latin-1"),
        "message should point to the header outside latin-1:\n{stderr}"
    );
    assert!(
        !stderr.contains("UnicodeEncodeError"),
        "the raw error must not leak:\n{stderr}"
    );
}

#[test]
fn real_shape_script_has_app_steps_extractions_and_parameters() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let script = generate(&bundle, &id);
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);

    // Only application steps: no /TSPD/ nor static scripts.
    assert!(!script.contains("/TSPD/"), "protection outside the script");
    assert!(!script.contains("jquery-ui"));
    assert!(!script.contains("CIS_V1_SYNTH.js"));
    // Header.
    assert!(script.contains("Semantic reproduction"));
    assert!(script.contains("are NOT guaranteed"));
    assert!(script.contains("Not executed by ScrapeLens"));
    assert!(script.contains("--confirm"));
    assert!(script.contains("--confirmar"), "legacy spelling is still accepted");
    // STAMP from the HTML control; delta from the textarea fragment (context).
    assert!(script.contains("('STAMP', html_control(R["));
    assert!(script.contains("html_control(R['har-0024'], 'XML', 0") || script.contains("'XML', 0"));
    assert!(
        script.contains("checked(ctx_extract(html_control("),
        "delta by the textarea fragment"
    );
    // SESSIONID: extracted prefix + partial-composition comment.
    assert!(script.contains("assembled on the client: complete here"));
    assert!(script.contains("P['sessionid_cliente']"));
    // F1: the part built on the client is required, with no captured value.
    assert!(
        script.contains("('sessionid_cliente', None, 'assembled on client')"),
        "partial-composition suffix must not have a captured default"
    );
    // Plate and CPF: required parameters, without the captured value.
    assert!(script.contains("P['placa']"));
    assert!(script.contains("('placa', None,"));
    assert!(
        !script.contains("TST0T10"),
        "captured plate must not stay in the script"
    );
    assert!(
        !script.contains("00000000191"),
        "captured CPF must not stay in the script"
    );
    // Captured dynamic values do not appear as literals.
    assert!(!script.contains("'4105'"), "captured STAMP");
    assert!(!script.contains("DLTC0005"), "captured delta");
    assert!(!script.contains("CSAN00011"), "captured session prefix");
    assert!(
        !script.contains("SYNTHPID000000000000000000000011"),
        "captured processId"
    );
    // F1 refined: navigation of the chain itself is a structural constant, not session data
    // — `op=S37` (step query) and `page=NatLogon` (query of a
    // chain page) may have the captured value as default.
    assert!(
        script.contains("('op', 'S37', 'structural constant')"),
        "op is flow navigation and should be a structural constant:\n{script}"
    );
    assert!(
        script.contains("('page', 'NatLogon', 'structural constant')"),
        "page is flow navigation and should be a structural constant:\n{script}"
    );
    assert!(script.contains("structural constant (route/navigation)"));
}

/// Minimal HAR with `entries` (method, url, request body, response text).
/// `None` as response text = response without observable body (`unavailable`).
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
                // Size > 0 without text = `unavailable` (not `empty`).
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
        .expect("minimal HAR")
        .bundle
}

#[test]
fn second_round_target_extracts_stamp_from_the_chain_page() {
    // Round 2: the target consumes STAMP=INIT, defined by the cscform control.
    // The registered producer is the round 1 page (outside the generated chain);
    // the equivalent step of the chain itself (har-0038) defines the same value,
    // so the script extracts it at runtime instead of asking for --stamp.
    let bundle = fixture("detran-pb-real-shape", "real-shape-2rounds.har");
    let script = generate(&bundle, "har-0056");
    assert!(
        !script.contains("('stamp',"),
        "page STAMP became a required parameter:\n{script}"
    );
    assert!(
        !script.contains("('pageinitparam', None"),
        "page PAGEINITPARAM became a required parameter:\n{script}"
    );
    assert!(
        script.contains("html_control(R['har-0038'], 'STAMP', 0"),
        "STAMP should be extracted from the cscform control of the chain:\n{script}"
    );
    assert!(script.contains("defined by the page control"));
    // Only what belongs to the session/client remains required.
    assert!(script.contains("('sessionid_cliente', None, 'assembled on client')"));
    assert!(script.contains("('placa', None,"));
}

#[test]
fn page_control_and_literal_are_extracted_not_asked() {
    // The chain page defines STAMP via a control and PAGEINITPARAM via a
    // literal; the script extracts both at runtime.
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
        "STAMP should come from the page control:\n{script}"
    );
    assert!(
        script.contains("ctx_extract(R['har-0001'].text"),
        "PAGEINITPARAM should come from the page literal:\n{script}"
    );
}

#[test]
fn value_without_origin_is_a_default_only_with_constancy_proof() {
    // Same (field, value) in two requests and outside any response:
    // protocol constant, may become the default.
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
        script.contains("('mode', 'CONST_MODE', 'protocol constant')"),
        "proven constancy should allow the default:\n{script}"
    );

    // Single occurrence: required parameter, without the captured value.
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
        script.contains("('mode', None, 'no observed origin')"),
        "value without a proof of constancy must be required:\n{script}"
    );
    assert!(
        !script.contains("ONLY_ONCE_XYZ"),
        "captured value must not appear in the script"
    );
}

#[test]
fn navigation_values_are_structural_constants() {
    // Step 1 is chain navigation (`op`/`page` in the query and `SIM1000X.html`
    // in the path); the target repeats these values. They are structural constants.
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
        "('op', 'S37', 'structural constant')",
        "('page', 'NatLogon', 'structural constant')",
        "('page_2', 'SIM1000X', 'structural constant')",
    ] {
        assert!(
            script.contains(expected),
            "{expected} should be a structural constant:\n{script}"
        );
    }
    // Outside navigation, without proof of constancy, it stays required.
    assert!(
        script.contains("('code', None, 'no observed origin')"),
        "non-navigation query must not get a default:\n{script}"
    );
}

#[test]
fn structural_constant_never_covers_sensitive_or_business_values() {
    // The plate appears in the navigation path/query, but it is business data:
    // it stays required and the captured value does not enter the script.
    let bundle = mini_bundle(vec![(
        "GET",
        "https://mini.example.test/produto.html?placa=TST0T10",
        None,
        Some("ok"),
    )]);
    let script = generate(&bundle, "har-0001");
    assert!(
        script.contains("('placa', None,"),
        "plate must not become a default:\n{script}"
    );
    assert!(
        !script.contains("TST0T10"),
        "captured plate must not appear in the script"
    );
}

#[test]
fn stamp_without_producer_is_required_and_never_a_captured_literal() {
    let bundle = mini_bundle(vec![
        (
            "GET",
            "https://mini.example.test/page",
            None,
            Some("<html>no STAMP on this page</html>"),
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
        script.contains("('stamp', None, 'no observed origin')"),
        "STAMP without producer must be required:\n{script}"
    );
    assert!(
        !script.contains("STAMP_UNIQUE_42"),
        "captured STAMP must not stay in code or in a comment:\n{script}"
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
        script.contains("assembled on the client"),
        "partial composition should be recognized:\n{script}"
    );
    assert!(
        script.contains("('sessionid_cliente', None, 'assembled on client')"),
        "suffix assembled on the client must be required:\n{script}"
    );
    assert!(
        !script.contains("999999999999"),
        "captured suffix must not stay in code or in a comment:\n{script}"
    );
}

#[test]
fn incomplete_chain_is_refused_and_allow_incomplete_emits_explicit_fail() {
    // The first response has no body; the target consumes a value that could only
    // have come from it. The third is the complete equivalent occurrence.
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
    .expect_err("incomplete chain must be refused");
    let message = err.to_string();
    assert!(message.contains("incomplete chain"), "{message}");
    assert!(message.contains("har-0002 [field]"), "{message}");
    assert!(message.contains("har-0001 (unavailable)"), "{message}");
    assert!(message.contains("har-0003"), "suggestion missing: {message}");
    assert!(
        message.contains("No captured value is used in their place"),
        "{message}"
    );
    assert!(message.contains("--allow-incomplete"), "{message}");

    let opts = PrimingOptions {
        allow_incomplete: true,
        ..PrimingOptions::default()
    };
    let output = to_python(&bundle.session, &bundle, "har-0002", &opts)
        .expect("--allow-incomplete generates the script");
    let script = output.text;
    assert!(
        script.contains("fail('incomplete chain: field has no producer with an observable body"),
        "incomplete step must fail explicitly:\n{script}"
    );
    assert!(
        !script.contains("UNIQUE_B_222"),
        "captured value does not replace the missing origin:\n{script}"
    );
    assert!(
        script.contains("('field', None, 'no observed origin')"),
        "parameter stays required, with no default:\n{script}"
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.code == "priming.incomplete_chain"),
        "incomplete chain warning missing"
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
    // Without --confirm (or --confirmar): runs without `requests`, prints the plan and exits with 0.
    let out = python(&[], &path);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Priming plan"), "{stdout}");
    assert!(stdout.contains("(changes state)"));
    assert!(stdout.contains("Nothing was sent"));
    assert!(!stdout.contains("HTTP 200"), "no request sent");
    // With --confirm and without required parameters: refuses before sending.
    let out = Command::new("python3")
        .args(["-I"])
        .arg(&path)
        .arg("--confirm")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("required parameters missing"));
}

#[test]
fn each_confirm_spelling_is_accepted_and_without_one_nothing_is_sent() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let script = generate(&bundle, &first_placa_request(&bundle));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("priming.py");
    std::fs::write(&path, &script).unwrap();
    // Neither spelling: the plan is printed and nothing is sent.
    let out = python(&[], &path);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Nothing was sent"), "{stdout}");
    assert!(!stdout.contains("HTTP 200"), "no request sent: {stdout}");
    // Each spelling passes the confirmation gate and reaches the required-parameter check.
    for flag in ["--confirm", "--confirmar"] {
        let out = Command::new("python3")
            .args(["-I"])
            .arg(&path)
            .arg(flag)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{flag}: refuses without the required parameters");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("Nothing was sent"), "{flag} must pass the gate: {stdout}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("required parameters missing"),
            "{flag}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn plain_get_chain_does_not_require_confirm() {
    // A GET target without steps that change state runs without the flag (plan + execution).
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

/// HAR with hostile names/values in a POST that consumes the STAMP of a page.
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
        .expect("hostile HAR")
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
    // No calls beyond the known ones of the generated script.
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
        "split",
        "vars",
        "type",
        "hexdigest",
        "sha256",
        "trace_plan_hash",
        "trace_error",
        "check_arguments",
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
            "unexpected call in the generated script: {call}\n{script}"
        );
    }
    // The payload may only exist in comments (inert, made by `comment`)
    // or inside escaped literals; never raw in the code.
    let code: String = script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!code.contains("__import__('os')"), "raw payload in the code");
    assert!(!script.contains('\u{202e}'), "raw bidi in the code");
    assert!(!script.contains('\u{0}'));
    // A hostile sentinel does not become an instruction: ast only sees constants.
    let probe = r#"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
bad = [n for n in ast.walk(tree) if (isinstance(n, ast.Name) and n.id == '__import__') or (isinstance(n, ast.Attribute) and n.attr in ('system', 'popen', 'spawn'))]
print(len(bad))
"#;
    let path = dir.path().join("priming.py");
    let out = python(&["-c", probe], &path);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
    // Without --confirm prints the plan and exits.
    let out = python(&[], &path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing was sent"));
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

/// Driver without network: fake session that answers with a redirect and records
/// what was sent and where.
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
        assert kw.get('allow_redirects') is False, 'allow_redirects must be False'
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
            stdout.contains("FAIL") && stdout.contains("redirect to another origin"),
            "{status}: redirect to another origin should fail: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !stdout.contains("evil.invalid') ]") && stdout.matches("http://").count() <= 2,
            "{status}: nothing may be sent to the other origin: {stdout}"
        );
        assert!(
            !stdout.contains("('GET', 'http://evil") && !stdout.contains("('POST', 'http://evil"),
            "{status}: sent to the other origin: {stdout}"
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
            "{status}: same origin should be followed: {stdout}{}",
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
        mod['ctx_extract'](text, before, after, 'test')
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
        assert!(l.parse::<f64>().unwrap() < 1.0, "slow: {stdout}");
    }
    assert_eq!(lines[2], "xyz");
    assert_eq!(lines[3], "a?[31m?b?");
}

#[test]
fn foreign_origin_steps_are_refused_unless_allowed() {
    let bundle = fixture("detran-pb-real-shape", "real-shape-1round.har");
    let id = first_placa_request(&bundle);
    let mut bundle = bundle;
    // Moves the first non-target step to another host.
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
        assert!(!script.contains(leaked), "{leaked} leaked:\n{script}");
    }
    assert!(script.contains("jsessionid"), "{script}");
    assert!(script.contains("('path_jsessionid', None,"), "{script}");
    for name in ["nome", "email", "callback", "v", "rg"] {
        assert!(
            script.contains(&format!("('{name}', None,")),
            "{name} should be required:\n{script}"
        );
    }
    // Structural stays default; `target` is not sensitive for containing `rg`.
    assert!(script.contains("('op', 'S37', 'structural constant')"));
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&script, &dir);
}

/// Synthetic HAR with its own headers/Content-Type; the last entry is the target.
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
        assert!(!script.contains(value), "{name} leaked:\n{script}");
    }
    assert!(!script.contains("00000000191"), "Referer query leaked");
    assert!(
        !script.contains("'Referer'"),
        "without an earlier step, Referer is omitted"
    );
    assert!(
        script.contains("Mozilla/5.0 teste"),
        "User-Agent stays literal"
    );
    assert!(script.contains("('x_api_key', None,"), "{script}");
    assert!(script.contains("('x_jwt', None,"), "{script}");

    // With a previous step of the same origin+path, the Referer comes from runtime.
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
        assert!(!script.contains(leaked), "{leaked} leaked:\n{script}");
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
    .expect_err("refused by default");
    assert!(err.to_string().contains("--allow-literal-body"), "{err}");
    let opts = PrimingOptions {
        allow_literal_body: true,
        ..PrimingOptions::default()
    };
    let out = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("with the option");
    for leaked in ["Fulano Teste", "00000000191", "a@b.test"] {
        assert!(!out.text.contains(leaked), "{leaked} leaked:\n{}", out.text);
    }
    assert!(out.text.contains("livre"), "the rest stays frozen");
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
        assert!(!script.contains(leaked), "{leaked} became a default:\n{script}");
    }
    assert!(script.contains("('op', 'S37', 'structural constant')"));
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
        assert!(!script.contains(leaked), "{leaked} leaked:\n{script}");
    }
    assert!(script.contains("json.dumps("), "{script}");
    assert!(script.contains("('cpf', None,"));
    assert!(script.contains("application/x-www-form-urlencoded"));
    // Free text that looks like a form, without '=' and long: refused.
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
    .expect_err("refused");
    assert!(err.to_string().contains("without '='"), "{err}");
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
            assert!(!script.contains(secret), "{name} leaked:\n{script}");
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
        assert!(!script.contains(value), "{label}: {value} leaked:\n{script}");
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
        ("data=<json> encoded", format!("data={encoded}")),
        ("data=<json> raw", format!("data={PII_JSON}")),
        (
            "payload + others",
            format!("payload={encoded}&x=1&STAMP=INIT"),
        ),
        ("a=1&b=<json>", format!("a=1&b={encoded}")),
        ("encoded twice", format!("data={double}")),
    ] {
        let script = generate(&form_bundle(&body), "har-0001");
        assert_no_pii(&script, label);
        assert!(script.contains("json.dumps("), "{label}:\n{script}");
        let dir = tempfile::tempdir().unwrap();
        ast_calls(&script, &dir);
    }
    // JSON inside a JSON string, under application/json.
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
    for (label, body) in [("partial JSON", partial.as_str()), ("field without =", free)] {
        match to_python(
            &form_bundle(body).session,
            &form_bundle(body),
            "har-0001",
            &PrimingOptions::default(),
        ) {
            Ok(out) => assert_no_pii(&out.text, label),
            Err(e) => assert!(
                !e.to_string().contains("12345678909") && !e.to_string().contains("Maria"),
                "{label}: the message must not carry the value: {e}"
            ),
        }
    }
    // The final barrier refuses, listing types without values.
    let bundle = form_bundle(free);
    let err = to_python(
        &bundle.session,
        &bundle,
        "har-0001",
        &PrimingOptions::default(),
    )
    .expect_err("refused");
    let message = err.to_string();
    assert!(message.contains("personal data"), "{message}");
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
        &[("X-Note", "contact a@b.test")],
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
    // (label, value): plate with hyphen, Mercosul with hyphen, chassis, +55,
    // card series 2 and 19-digit (Luhn), full width.
    let values = [
        ("plate hyphen", "ABC-1234"),
        ("Mercosul plate hyphen", "ABC-1D23"),
        ("chassis", "9BWZZZ377VT004251"),
        ("+55 punctuated", "+55 83 99999-8888"),
        ("55 raw", "5583999998888"),
        ("card series 2", "2223000048400011"),
        ("card 19", "6221260000000000001"),
        ("full width", "１２３４５６７８９０９"),
    ];
    for (label, value) in values {
        let encoded = url_encode(value);
        // Query with a generic name (never a structural constant).
        let bundle = custom_bundle(&[(
            "GET",
            &format!("https://h.example.test/go?ref={encoded}&p=1"),
            &[],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(
            !script.contains(value) && !script.contains(&encoded),
            "{label} in query:\n{script}"
        );
        assert!(
            script.contains("('ref', None,"),
            "{label}: query must be required"
        );
        // Header with any name.
        let bundle = custom_bundle(&[(
            "GET",
            "https://h.example.test/go",
            &[("x-foo", value)],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(!script.contains(value), "{label} in header:\n{script}");
        // Path segment: becomes a parameter, never a literal nor a plan entry.
        let bundle = custom_bundle(&[(
            "GET",
            &format!("https://h.example.test/go/{encoded}/fim"),
            &[],
            None,
        )]);
        let script = generate(&bundle, "har-0001");
        assert!(
            !script.contains(value) && !script.contains(&encoded),
            "{label} in path:\n{script}"
        );
        assert!(script.contains("path_segmento_2"), "{label}:\n{script}");
        assert!(script.contains("/fim"));
        // Form key.
        let bundle = form_bundle(&format!("{encoded}=1"));
        match to_python(
            &bundle.session,
            &bundle,
            "har-0001",
            &PrimingOptions::default(),
        ) {
            Ok(out) => assert!(!out.text.contains(value), "{label} in key:\n{}", out.text),
            Err(e) => assert!(!e.to_string().contains(value)),
        }
    }
    // The same placa_ref=ABC-1234 from the reviewer.
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

/// Toy adapter `kv:a=1;b=2` to exercise the generic path of the
/// priming with no real protocol knowledge in the core.
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
    // Without a Python encoder, falls back to fragment handling.
    let plain = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("generates");
    assert!(!plain.text.contains("kv_encode"));
    opts.adapter_encoders.push(AdapterEncoder {
        adapter_id: "kv".into(),
        function: "kv_encode".into(),
        decoder: String::new(),
        source: "def kv_encode(parts):\n    return 'kv:' + ';'.join(\n        n[2:] + '=' + v for n, r, v in parts if n != 'op')\n".into(),
    });
    let out = to_python(&bundle.session, &bundle, "har-0001", &opts).expect("generates");
    assert!(
        out.text
            .contains("kv_encode([('op', 'S', 'kv:'), ('p.v_placa', 'V', P['placa'])"),
        "{}",
        out.text
    );
    assert!(out.text.contains("def kv_encode"));
    assert!(
        !out.text.contains("TST0T10"),
        "captured plate must not stay"
    );
    let dir = tempfile::tempdir().unwrap();
    ast_calls(&out.text, &dir);
}

/// Driver without network: injects a fake `requests` module and runs the `main` of the
/// generated script with `--trace`.
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
        kind = __import__('os').environ.get('TRACE_RAISE')
        if kind == 'ConnectionError':
            raise ConnectionError('connection closed by the server')
        if kind == 'Timeout':
            raise TimeoutError('timed out')
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

const BAD_ARGV_DRIVER: &str = r#"
import runpy, sys
m = runpy.run_path(sys.argv[1], run_name='t')
sys.argv = [sys.argv[1], '--trace', '/tmp/\udcff-x']
try:
    m['main']()
except SystemExit as e:
    print('RC', e.code)
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

    // Successful run.
    let trace = dir.path().join("trace.json");
    let out = trace_run(&script_path, 200, &["--trace", trace.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("RC 0"), "{stdout}{stderr}");
    assert!(
        stderr.contains("the trace contains data from your session; do not share it without sanitizing"),
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

    // Already exists: refuses, without overwriting.
    let before = std::fs::read(&trace).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", trace.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert_eq!(std::fs::read(&trace).unwrap(), before);
    // Symbolic link (existing and dangling): refuses and does not write to the target.
    let target = dir.path().join("target.txt");
    std::fs::write(&target, "intact").unwrap();
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", link.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "intact");
    let dangling = dir.path().join("pendente.json");
    symlink(dir.path().join("does-not-exist.json"), &dangling).unwrap();
    let out = trace_run(&script_path, 200, &["--trace", dangling.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace:"));
    assert!(!dir.path().join("does-not-exist.json").exists());

    // Step failure: the trace is written up to the bad step, with the failure recorded.
    let failing = dir.path().join("failure.json");
    let out = trace_run(&script_path, 403, &["--trace", failing.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: step 1: HTTP 403"));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&failing).unwrap()).unwrap();
    assert_eq!(doc["steps"][0]["checks"][0]["ok"], false);
    assert!(doc["steps"][0]["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("HTTP 403"));
    assert_eq!(doc["steps"][0]["status"], 403);
    // The core imports the written trace (exact schema).
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

    // Without --trace, nothing is created; in plan mode (step that changes state, without
    // --confirm), nothing is written.
    let post = custom_bundle(&[(
        "POST",
        "https://h.example.test/alvo",
        &[],
        Some(("application/x-www-form-urlencoded", "a=1")),
    )]);
    let post_script = dir.path().join("post.py");
    std::fs::write(&post_script, generate(&post, "har-0001")).unwrap();
    let plan_trace = dir.path().join("plan.json");
    let out = trace_run(
        &post_script,
        200,
        &["--trace", plan_trace.to_str().unwrap()],
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing was sent"));
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

#[test]
fn trace_lists_user_parameters_with_their_parts_and_never_values() {
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/alvo",
        &[],
        Some(("application/x-www-form-urlencoded", "placa=TST0T10")),
    )]);
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("p.py");
    std::fs::write(&script, generate(&bundle, "har-0001")).unwrap();
    let trace = dir.path().join("t.json");
    let out = trace_run(
        &script,
        200,
        &[
            "--confirm",
            "--placa",
            "ZZZ9Z99",
            "--trace",
            trace.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("RC 0"),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = std::fs::read_to_string(&trace).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let parameters = doc["parameters"].as_array().unwrap();
    assert!(
        parameters
            .iter()
            .any(|p| p["name"] == "placa" && p["part"] == "placa"),
        "{parameters:?}"
    );
    // `op` kept its default (it is not user input).
    assert!(
        parameters.iter().all(|p| p["name"] != "op"),
        "{parameters:?}"
    );
    // Names only: the passed value does not appear in `parameters`.
    assert!(!serde_json::to_string(parameters)
        .unwrap()
        .contains("ZZZ9Z99"));
}

#[test]
fn transport_errors_leave_a_valid_incomplete_trace_and_never_zero_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &[], None)]);
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("p.py");
    std::fs::write(&script, generate(&bundle, "har-0001")).unwrap();
    for kind in ["ConnectionError", "Timeout"] {
        let trace = dir.path().join(format!("{kind}.json"));
        let out = Command::new("python3")
            .arg("-I")
            .args(["-c", TRACE_DRIVER])
            .arg(&script)
            .arg("200")
            .args(["--trace", trace.to_str().unwrap()])
            .env("TRACE_RAISE", kind)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("RC priming: step 1: transport error"),
            "{kind}: {stdout}"
        );
        let raw = std::fs::read(&trace).unwrap();
        assert!(!raw.is_empty(), "{kind}: empty trace");
        assert_eq!(
            std::fs::metadata(&trace).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let doc: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(doc["complete"], false, "{kind}");
        assert_eq!(doc["target"], "har-0001");
        assert_eq!(doc["plan"]["hash"].as_str().unwrap().len(), 16);
        let step = &doc["steps"][0];
        assert!(
            step["error"]
                .as_str()
                .unwrap()
                .contains(kind.trim_end_matches("Error"))
                || step["error"].as_str().unwrap().contains("Error"),
            "{step}"
        );
        assert_eq!(step["checks"][0]["ok"], false);
        assert!(step["status"].is_null());
        // Importable by the Core.
        let session = dir.path().join(format!("s-{kind}"));
        let import = Command::new(env!("CARGO_BIN_EXE_scrapelens-core"))
            .arg("import-trace")
            .arg(&trace)
            .arg("--out")
            .arg(&session)
            .output()
            .unwrap();
        assert!(
            import.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&import.stderr)
        );
    }
}

#[test]
fn invalid_arguments_fail_before_any_request_and_complete_is_true_on_success() {
    let bundle = custom_bundle(&[("GET", "https://h.example.test/alvo", &[], None)]);
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("p.py");
    std::fs::write(&script, generate(&bundle, "har-0001")).unwrap();
    // --trace empty is an error; nothing is requested.
    let out = trace_run(&script, 200, &["--trace", ""]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --trace requires"));
    // invalid --base-url and --timeout out of range.
    let out = trace_run(&script, 200, &["--base-url", "ftp://x"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --base-url"));
    let out = trace_run(&script, 200, &["--timeout", "0"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC priming: --timeout"));
    // Invalid bytes in argv (surrogate escape): fails before running.
    let out = Command::new("python3")
        .arg("-I")
        .args(["-c", BAD_ARGV_DRIVER])
        .arg(&script)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RC priming: argument --trace has invalid bytes"),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Success: complete=true.
    let trace = dir.path().join("ok.json");
    let out = trace_run(&script, 200, &["--trace", trace.to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC 0"));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    assert_eq!(doc["complete"], true);
}

fn python_with_requests() -> Option<String> {
    ["/tmp/sl-venv-req/bin/python", "/tmp/rev10/venv/bin/python"]
        .iter()
        .find(|p| {
            std::path::Path::new(p).exists()
                && Command::new(p)
                    .args(["-c", "import requests"])
                    .status()
                    .is_ok_and(|s| s.success())
        })
        .map(|p| p.to_string())
}

#[test]
fn real_sockets_that_close_or_stay_silent_leave_a_valid_incomplete_trace() {
    use std::io::Read;
    use std::net::TcpListener;
    let Some(python) = python_with_requests() else {
        return; // without `requests` installed, the fake-based test above covers the logic
    };
    for mode in ["close", "silent"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                if mode == "silent" {
                    let mut buf = [0u8; 1024];
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let _ = stream.read(&mut buf);
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                }
                // "close": closes without responding.
            }
        });
        let bundle = custom_bundle(&[("GET", &format!("http://127.0.0.1:{port}/alvo"), &[], None)]);
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("p.py");
        std::fs::write(&script, generate(&bundle, "har-0001")).unwrap();
        let trace = dir.path().join("t.json");
        let out = Command::new(&python)
            .arg("-I")
            .arg(&script)
            .args(["--timeout", "0.5", "--trace", trace.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("priming: step 1: transport error"),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let raw = std::fs::read(&trace).unwrap();
        assert!(!raw.is_empty(), "{mode}: empty trace");
        let doc: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(doc["complete"], false, "{mode}");
        assert!(doc["steps"][0]["error"].as_str().unwrap().len() > 3);
        let import = Command::new(env!("CARGO_BIN_EXE_scrapelens-core"))
            .arg("import-trace")
            .arg(&trace)
            .arg("--out")
            .arg(dir.path().join("sess"))
            .output()
            .unwrap();
        assert!(
            import.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&import.stderr)
        );
        let _ = handle.join();
    }
}

#[test]
fn plan_hash_is_computed_at_generation_by_the_core_and_the_script_has_no_hashlib() {
    let bundle = custom_bundle(&[(
        "POST",
        "https://h.example.test/alvo",
        &[],
        Some(("application/x-www-form-urlencoded", "placa=TST0T10")),
    )]);
    let script = generate(&bundle, "har-0001");
    assert!(
        !script.contains("hashlib"),
        "the script does not need hashlib"
    );
    let literal = script
        .lines()
        .find_map(|l| l.strip_prefix("PLAN_HASH = '"))
        .and_then(|l| l.strip_suffix('\''))
        .expect("PLAN_HASH constant");
    // The hash uses exactly the names of the REQUIRED parameters (`plan.parameters`).
    let names = vec!["placa".to_string()];
    let expected = scrapelens_core::validate::plan_hash(
        &bundle.session,
        &bundle,
        "har-0001",
        &scrapelens_core::flow::FlowOptions::default(),
        &names,
    )
    .unwrap();
    assert_eq!(literal, expected);
    // Running the script with `--trace`, the recorded hash is the same.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.py");
    std::fs::write(&path, &script).unwrap();
    let trace = dir.path().join("t.json");
    let out = trace_run(
        &path,
        200,
        &[
            "--confirm",
            "--placa",
            "ZZZ9Z99",
            "--trace",
            trace.to_str().unwrap(),
        ],
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("RC 0"));
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    assert_eq!(doc["plan"]["hash"], literal);
    assert_eq!(doc["plan"]["parameters"], serde_json::json!(["placa"]));
}

#[test]
fn overriding_an_optional_parameter_changes_neither_plan_hash_nor_plan_parameters() {
    // `op` has a default (structural constant): optional.
    let bundle = custom_bundle(&[
        ("GET", "https://h.example.test/app?op=S37", &[], None),
        (
            "POST",
            "https://h.example.test/alvo?op=S37",
            &[],
            Some((
                "application/x-www-form-urlencoded",
                "placa=TST0T10&tok=abc12345",
            )),
        ),
    ]);
    let script = generate(&bundle, "har-0002");
    assert!(script.contains("('op', 'S37',"), "{script}");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.py");
    std::fs::write(&path, &script).unwrap();
    let run = |extra: &[&str], name: &str| {
        let trace = dir.path().join(name);
        let mut args = vec!["--confirm", "--placa", "ZZZ9Z99"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--trace", trace.to_str().unwrap()]);
        let out = trace_run(&path, 200, &args);
        assert!(String::from_utf8_lossy(&out.stdout).contains("RC 0"));
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&trace).unwrap()).unwrap()
    };
    let base = run(&[], "a.json");
    let overridden = run(&["--op", "OTHER"], "b.json");
    assert_eq!(base["plan"], overridden["plan"]);
    assert_eq!(base["plan"]["parameters"], serde_json::json!(["placa"]));
    // Top-level `parameters` still has all the used ones (here, `op` is an extra).
    let names = |d: &serde_json::Value| -> Vec<String> {
        d["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(!names(&base).contains(&"op".to_string()));
    assert!(names(&overridden).contains(&"op".to_string()));
}
