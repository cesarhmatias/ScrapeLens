//! Sucesso da aplicação × HTTP (docs/11-priming-sucesso.md §2, aceite 3).

use std::path::PathBuf;

use scrapelens_core::assess::{assess_session, AssessRules, ResponseOutcome, VerdictKind};
use scrapelens_core::import_har;

fn har(dir: &str, name: &str) -> scrapelens_core::SessionBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(dir)
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    import_har(&bytes).expect("importa HAR").bundle
}

fn run(bundle: &scrapelens_core::SessionBundle, rules: &AssessRules) -> Vec<ResponseOutcome> {
    assess_session(&bundle.session, bundle, rules)
}

/// HAR mínimo com respostas (método, url, status, mime, corpo).
fn mini(entries: &[(&str, &str, u16, &str, &str)]) -> scrapelens_core::SessionBundle {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .enumerate()
        .map(|(i, (method, url, status, mime, text))| {
            serde_json::json!({
                "startedDateTime": format!("2026-10-26T23:00:{:02}.000Z", i),
                "time": 1,
                "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1",
                    "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
                "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                    "headers": [], "cookies": [], "headersSize": -1, "bodySize": text.len(),
                    "redirectURL": "",
                    "content": {"size": text.len(), "mimeType": mime, "text": text}},
                "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
            })
        })
        .collect();
    let har = serde_json::json!({"log": {"version": "1.2",
        "creator": {"name": "t", "version": "1"}, "entries": items}});
    import_har(har.to_string().as_bytes())
        .expect("HAR mínimo")
        .bundle
}

fn form(xml: &str, stamp: &str, err: &str) -> String {
    format!(
        "<html><body><form><textarea name=\"XML\">{xml}</textarea>\
         <textarea name=\"ERRORMESSAGE\">{err}</textarea>\
         <input type=\"hidden\" name=\"STAMP\" value=\"{stamp}\"></form></body></html>"
    )
}

const CONN: &str = "https://app.example.test/servlet/Connector";

#[test]
fn blocked_har_gets_coherent_verdicts() {
    let outcomes = run(
        &har("detran-pb", "detran-pb-blocked.har"),
        &AssessRules::default(),
    );
    assert_eq!(outcomes.len(), 3);
    // 200 com desafio de proteção e sem controles → bloqueio, nunca app-ok.
    assert_eq!(outcomes[0].verdict, "blocked? (TSPD)");
    assert!(outcomes[0].http_ok);
    // Connector 200 sem XML/STAMP e sem nada aprendido → não afirma nada.
    assert_eq!(outcomes[1].verdict, "indeterminado");
    assert!(outcomes[1].http_ok);
    assert!(outcomes[1].reason.contains("sem sinais"));
    // 403 explícito.
    assert_eq!(outcomes[2].verdict, "blocked? (http-403)");
    assert!(!outcomes[2].http_ok);
    assert!(outcomes
        .iter()
        .all(|o| o.verdict_kind != VerdictKind::AppOk));
}

#[test]
fn real_shape_normal_responses_are_app_ok() {
    let bundle = har("detran-pb-real-shape", "real-shape-1round.har");
    let outcomes = run(&bundle, &AssessRules::default());
    let mut connectors = 0;
    for (request, outcome) in bundle.session.requests.iter().zip(&outcomes) {
        if request.url.ends_with("/servlet/Connector") {
            connectors += 1;
            assert_eq!(outcome.verdict, "app-ok", "{}", outcome.url);
            assert!(outcome.http_ok && !outcome.app_signals.is_empty());
        }
        // Guard TSPD em página com controles ou JS não vira bloqueio.
        assert_ne!(
            outcome.verdict_kind,
            VerdictKind::Blocked,
            "{}",
            outcome.url
        );
        assert_ne!(
            outcome.verdict_kind,
            VerdictKind::AppError,
            "{}",
            outcome.url
        );
    }
    assert_eq!(connectors, 8);
}

#[test]
fn sanitized_form_bodies_are_app_ok() {
    let bundle = har("detran-pb", "detran-pb-sanitized.har");
    let outcomes = run(&bundle, &AssessRules::default());
    let ok = outcomes
        .iter()
        .filter(|o| o.url.ends_with("/Connector") && o.verdict == "app-ok")
        .count();
    assert_eq!(ok, 8);
}

#[test]
fn filled_errormessage_is_app_error_even_with_http_200() {
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp1", "1", "")),
        (
            "POST",
            CONN,
            200,
            "text/html",
            &form("", "2", "Placa inválida"),
        ),
    ]);
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[0].verdict, "app-ok");
    assert_eq!(outcomes[1].verdict, "app-error (ERRORMESSAGE)");
    assert!(outcomes[1].http_ok);
}

#[test]
fn route_fields_learned_in_session_make_missing_fields_indeterminate() {
    let no_stamp = "<html><body><form><textarea name=\"XML\">x</textarea></form></body></html>";
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp1", "1", "")),
        ("POST", CONN, 200, "text/html", no_stamp),
    ]);
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[1].verdict, "indeterminado");
    assert_eq!(outcomes[1].missing_fields, vec!["STAMP".to_string()]);
    assert!(outcomes[1].reason.contains("STAMP"));
}

#[test]
fn empty_xml_where_route_had_it_is_indeterminate() {
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp1", "1", "")),
        ("POST", CONN, 200, "text/html", &form("", "2", "")),
    ]);
    let o = &run(&bundle, &AssessRules::default())[1];
    assert_eq!(o.verdict, "indeterminado");
    assert_eq!(o.missing_fields, vec!["XML".to_string()]);
}

#[test]
fn html_without_controls_replacing_a_known_route_is_blocked_with_question_mark() {
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp1", "1", "")),
        (
            "POST",
            CONN,
            200,
            "text/html",
            "<html><body>request rejected</body></html>",
        ),
    ]);
    let o = &run(&bundle, &AssessRules::default())[1];
    assert_eq!(o.verdict, "blocked? (html-sem-controles)");
    assert!(o.verdict.contains('?'));
}

#[test]
fn protection_marker_inside_page_with_controls_is_not_a_block() {
    let page = format!("<script src=\"/TSPD/x\"></script>{}", form("lp1", "1", ""));
    let o = &run(
        &mini(&[("POST", CONN, 200, "text/html", &page)]),
        &AssessRules::default(),
    )[0];
    assert_eq!(o.verdict, "app-ok");
}

#[test]
fn rate_limit_and_server_error_statuses() {
    let bundle = mini(&[
        (
            "GET",
            "https://app.example.test/a",
            429,
            "text/html",
            "slow down",
        ),
        (
            "GET",
            "https://app.example.test/b",
            500,
            "text/html",
            "boom",
        ),
    ]);
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[0].verdict, "blocked? (http-429)");
    assert_eq!(outcomes[1].verdict, "app-error (http-500)");
}

#[test]
fn json_fields_are_read_by_leaf_name() {
    let bundle = mini(&[
        (
            "POST",
            CONN,
            200,
            "application/json",
            "{\"data\":{\"XML\":\"abc\",\"STAMP\":\"7\"}}",
        ),
        (
            "POST",
            CONN,
            200,
            "application/json",
            "{\"data\":{\"ERRORMESSAGE\":\"falhou\"}}",
        ),
    ]);
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[0].verdict, "app-ok");
    assert_eq!(outcomes[1].verdict, "app-error (ERRORMESSAGE)");
}

#[test]
fn custom_rules_from_json_change_signals_and_markers() {
    let rules = AssessRules::from_json(
        r#"{
          "schema": "scrapelens.assess-rules/1",
          "fields": [
            {"name": "token", "signal": "TOKEN", "kind": "present-nonempty"},
            {"name": "erro", "signal": "ERRO", "kind": "error"}
          ],
          "requiredFields": ["token"],
          "protectionMarkers": [{"contains": "captcha", "signal": "CAPTCHA"}],
          "blockedStatuses": [418]
        }"#,
    )
    .expect("regras");
    let bundle = mini(&[
        (
            "POST",
            "https://x.test/a",
            200,
            "application/json",
            "{\"token\":\"t1\"}",
        ),
        (
            "POST",
            "https://x.test/a",
            200,
            "application/json",
            "{\"erro\":\"nao\"}",
        ),
        (
            "POST",
            "https://x.test/a",
            200,
            "application/json",
            "{\"outro\":1}",
        ),
        (
            "GET",
            "https://x.test/b",
            200,
            "text/html",
            "<html>Resolva o CAPTCHA</html>",
        ),
        ("GET", "https://x.test/c", 418, "text/plain", "tea"),
    ]);
    let v: Vec<String> = run(&bundle, &rules)
        .into_iter()
        .map(|o| o.verdict)
        .collect();
    assert_eq!(v[0], "app-ok");
    assert_eq!(v[1], "app-error (ERRO)");
    assert_eq!(v[2], "indeterminado");
    assert_eq!(v[3], "blocked? (CAPTCHA)");
    assert_eq!(v[4], "blocked? (http-418)");
    // Regras padrão não conhecem esses nomes.
    let default_v = run(&bundle, &AssessRules::default());
    assert_ne!(default_v[0].verdict, "app-ok");
}

#[test]
fn rules_reject_wrong_schema_and_bad_json() {
    assert!(AssessRules::from_json("{\"schema\":\"outro/9\"}").is_err());
    assert!(AssessRules::from_json("{").is_err());
    assert!(AssessRules::from_json("{\"schema\":\"scrapelens.assess-rules/1\",\"fields\":[{\"name\":\"a\",\"kind\":\"exec\"}]}").is_err());
}

#[test]
fn unavailable_body_is_indeterminate_not_ok() {
    let mut bundle = mini(&[("POST", CONN, 200, "text/html", &form("lp", "1", ""))]);
    bundle.session.requests[0].response_body.state = scrapelens_core::model::BodyState::Unavailable;
    let o = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(o.verdict, "indeterminado");
    assert!(o.reason.contains("indisponível"));
}
