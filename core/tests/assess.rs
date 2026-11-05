//! Application success × HTTP (docs/11-priming-sucesso.md §2, acceptance 3).

use std::path::PathBuf;

use scrapelens_core::assess::{
    assess_session, AssessRules, ResponseOutcome, SignalKind, VerdictKind,
};
use scrapelens_core::import_har;

fn har(dir: &str, name: &str) -> scrapelens_core::SessionBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(dir)
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    import_har(&bytes).expect("imports HAR").bundle
}

fn run(bundle: &scrapelens_core::SessionBundle, rules: &AssessRules) -> Vec<ResponseOutcome> {
    assess_session(&bundle.session, bundle, rules)
}

/// Minimal HAR with responses (method, url, status, mime, body).
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
        .expect("minimal HAR")
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
    // 200 with protection challenge and no controls → block, never app-ok.
    assert_eq!(outcomes[0].verdict, "blocked? (TSPD)");
    assert_eq!(outcomes[0].verdict_kind, VerdictKind::Blocked);
    assert!(outcomes[0].http_ok);
    // Connector 200 with the default F5 ASM rejection page, without a learned
    // model for this route: it is explicit evidence of blocking.
    assert_eq!(outcomes[1].verdict, "blocked? (f5-rejected)");
    assert_eq!(outcomes[1].verdict_kind, VerdictKind::Blocked);
    assert!(outcomes[1].http_ok);
    assert!(outcomes[1]
        .app_signals
        .iter()
        .any(|s| s.detail.contains("rejection")));
    // Explicit 403.
    assert_eq!(outcomes[2].verdict, "blocked? (http-403)");
    assert_eq!(outcomes[2].verdict_kind, VerdictKind::Blocked);
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
    let mut forms = 0;
    let mut not_assessed = 0;
    let mut protection = 0;
    for (request, outcome) in bundle.session.requests.iter().zip(&outcomes) {
        let form_page = request.url.contains("cscform.html");
        if request.url.ends_with("/servlet/Connector") || form_page {
            if form_page {
                forms += 1;
            } else {
                connectors += 1;
            }
            assert_eq!(outcome.verdict, "app-ok", "{}", outcome.url);
            assert_eq!(outcome.verdict_kind, VerdictKind::AppOk);
            assert!(outcome.http_ok && !outcome.app_signals.is_empty());
        } else if request.url.contains("/TSPD/") {
            // Protection route: normal session handshake, not a block.
            protection += 1;
            assert_eq!(outcome.verdict, "not-assessed", "{}", outcome.url);
            assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
            assert!(
                outcome
                    .app_signals
                    .iter()
                    .any(|s| s.signal == "protection" && s.kind == SignalKind::Info),
                "{} without informational protection signal",
                outcome.url
            );
        } else {
            not_assessed += 1;
            assert_eq!(
                outcome.verdict, "not-assessed",
                "{} is {}",
                outcome.url, outcome.verdict
            );
            assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
        }
    }
    // 30 responses: 8 Connector + 3 cscform pages (they have controls) and the rest
    // with no signal (pages, frames, static files) or a protection route.
    assert_eq!(connectors, 8);
    assert_eq!(forms, 3);
    assert!(protection >= 1, "fixture without /TSPD/ route");
    assert_eq!(not_assessed + protection, 19);
    assert_eq!(outcomes.len(), 30);
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| o.verdict_kind == VerdictKind::Blocked)
            .count(),
        0,
        "session that worked must not have blocked?"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| o.verdict_kind == VerdictKind::Undetermined)
            .count(),
        0
    );
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
            &form("", "2", "Invalid plate"),
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
    assert_eq!(outcomes[1].verdict, "undetermined");
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
    assert_eq!(o.verdict, "undetermined");
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
            "<html><body>no controls</body></html>",
        ),
    ]);
    let o = &run(&bundle, &AssessRules::default())[1];
    assert_eq!(o.verdict, "blocked? (html-without-controls)");
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
fn page_that_only_cites_the_protection_script_is_not_a_block() {
    // Application page: cites /TSPD/ in a <script src>, without controls and without
    // a learned expectation. It used to be `blocked?`; now it is `not-assessed`.
    let page = "<html><head><script src=\"/TSPD/abc.js\"></script></head><body><div id=\"app\"></div></body></html>";
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/easynat-app?op=S37",
        200,
        "text/html",
        page,
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "not-assessed", "{}", outcome.verdict);
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
    // The marker stays visible as an informational signal.
    assert!(outcome
        .app_signals
        .iter()
        .any(|s| s.signal == "TSPD" && s.detail.contains("cited")));
}

#[test]
fn protection_route_is_not_assessed_with_info_signal() {
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/TSPD/?type=20",
        200,
        "text/html",
        "<html><script>var x=1;</script></html>",
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "not-assessed");
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
    assert!(outcome
        .app_signals
        .iter()
        .any(|s| s.signal == "protection" && s.kind == SignalKind::Info));
    // Configurable: without this prefix in the rules, the same response also does not
    // block (it just no longer has the dedicated signal).
    let mut rules = AssessRules::default();
    rules.protection_paths.clear();
    let outcome = &run(&bundle, &rules)[0];
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
}

#[test]
fn protection_route_serving_javascript_is_not_assessed() {
    // The challenge also arrives as `text/javascript`; the protection route is the
    // normal handshake, not evidence of blocking.
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/TSPD/?type=18&uid=abc",
        200,
        "text/javascript",
        "var _0x1234=function(){return 1};",
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "not-assessed");
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
    assert!(outcome.app_signals.iter().any(|s| s.signal == "protection"));
    // 403/429 on the protection route itself is explicit evidence; the 200 of
    // the handshake (above) stays not-assessed.
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/TSPD/?type=18",
        403,
        "text/html",
        "no",
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "blocked? (http-403)");
    assert_eq!(outcome.verdict_kind, VerdictKind::Blocked);
}

#[test]
fn challenge_content_without_the_expected_page_is_a_block() {
    // Challenge content (protection variable) in place of the expected page.
    let bundle = mini(&[
        (
            "GET",
            "https://app.example.test/entry",
            200,
            "text/html",
            "<html><body>ok</body></html>",
        ),
        (
            "GET",
            "https://app.example.test/entry",
            200,
            "text/html",
            "<html><body><script>var _tsChallenge = 'X';</script></body></html>",
        ),
    ]);
    let outcome = &run(&bundle, &AssessRules::default())[1];
    assert_eq!(outcome.verdict, "blocked? (TSPD)");
    assert!(outcome.verdict.contains('?'));
}

#[test]
fn route_that_had_controls_and_now_cites_protection_is_a_block() {
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp1", "1", "")),
        (
            "POST",
            CONN,
            200,
            "text/html",
            "<html><script src=\"/TSPD/x.js\"></script></html>",
        ),
    ]);
    let outcome = &run(&bundle, &AssessRules::default())[1];
    assert_eq!(outcome.verdict, "blocked? (TSPD)");
    assert_eq!(outcome.verdict_kind, VerdictKind::Blocked);
}

#[test]
fn reference_marker_alone_does_not_block_custom_rules() {
    let rules = AssessRules::from_json(
        r#"{
          "schema": "scrapelens.assess-rules/1",
          "protectionMarkers": [{"contains": "captcha", "signal": "CAPTCHA"}]
        }"#,
    )
    .expect("rules");
    let bundle = mini(&[(
        "GET",
        "https://x.test/p",
        200,
        "text/html",
        "<html><script src=\"/captcha/widget.js\"></script><div id=\"app\"></div></html>",
    )]);
    let outcome = &run(&bundle, &rules)[0];
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
    assert!(outcome.app_signals.iter().any(|s| s.signal == "CAPTCHA"));
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
            "{\"data\":{\"ERRORMESSAGE\":\"failed\"}}",
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
            {"name": "erro", "signal": "ERROR", "kind": "error"}
          ],
          "requiredFields": ["token"],
          "protectionMarkers": [{"contains": "captcha", "signal": "CAPTCHA", "kind": "challenge"}],
          "blockedStatuses": [418]
        }"#,
    )
    .expect("rules");
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
            "{\"erro\":\"no\"}",
        ),
        (
            "POST",
            "https://x.test/a",
            200,
            "application/json",
            "{\"other\":1}",
        ),
        (
            "GET",
            "https://x.test/b",
            200,
            "text/html",
            "<html>Solve the CAPTCHA</html>",
        ),
        ("GET", "https://x.test/c", 418, "text/plain", "tea"),
    ]);
    let v: Vec<String> = run(&bundle, &rules)
        .into_iter()
        .map(|o| o.verdict)
        .collect();
    assert_eq!(v[0], "app-ok");
    assert_eq!(v[1], "app-error (ERROR)");
    assert_eq!(v[2], "undetermined");
    assert_eq!(v[3], "blocked? (CAPTCHA)");
    assert_eq!(v[4], "blocked? (http-418)");
    // Default rules do not know these names.
    let default_v = run(&bundle, &AssessRules::default());
    assert_ne!(default_v[0].verdict, "app-ok");
}

#[test]
fn challenge_marker_wins_over_a_citation_on_the_same_page() {
    // A page may cite /TSPD/ and still carry the challenge content; the
    // content is stronger evidence than the citation.
    let page = "<html><head><script src=\"/TSPD/x.js\"></script></head>\
                <body><script>var _tsChallenge = 'X';</script></body></html>";
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/entry",
        200,
        "text/html",
        page,
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "blocked? (TSPD)");
    assert_eq!(outcome.verdict_kind, VerdictKind::Blocked);
}

/// Default F5 ASM block page (real structure; fictitious values).
const F5_REJECTED: &str = "<html><head><title>Request Rejected</title></head><body>\
The requested URL was rejected. Please consult with your administrator.<br><br>\
Your support ID is: 1234567890</body></html>";

#[test]
fn f5_rejection_page_blocks_without_a_learned_route() {
    // A single response, route never seen: the default F5 page is explicit evidence,
    // not `not-assessed`.
    let bundle = mini(&[("POST", CONN, 200, "text/html", F5_REJECTED)]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "blocked? (f5-rejected)");
    assert_eq!(outcome.verdict_kind, VerdictKind::Blocked);
    assert!(outcome.http_ok);
    assert!(outcome
        .app_signals
        .iter()
        .any(|s| s.detail.contains("rejection")));
}

#[test]
fn f5_rejection_variant_with_support_id_blocks() {
    let body = "<html><body>Your support ID is: 987654321</body></html>";
    let bundle = mini(&[("POST", CONN, 200, "text/html", body)]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "blocked? (f5-rejected)");
}

#[test]
fn f5_text_in_a_page_with_the_expected_controls_is_app_ok() {
    // Route with learned controls: a 200 that carries them and merely cites the text
    // of the rejection is the application responding.
    let ok = form("lp1", "1", "");
    let quoting = format!("{ok}<p>Request Rejected by manager</p>");
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &ok),
        ("POST", CONN, 200, "text/html", &ok),
        ("POST", CONN, 200, "text/html", &quoting),
    ]);
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[2].verdict, "app-ok");
    // Without an expectation, but with controls, it is also app-ok.
    let bundle = mini(&[("POST", CONN, 200, "text/html", &quoting)]);
    assert_eq!(run(&bundle, &AssessRules::default())[0].verdict, "app-ok");
    // Same learned route, now without the controls: rejection.
    let bundle = mini(&[
        ("POST", CONN, 200, "text/html", &ok),
        ("POST", CONN, 200, "text/html", &ok),
        ("POST", CONN, 200, "text/html", F5_REJECTED),
    ]);
    assert_eq!(
        run(&bundle, &AssessRules::default())[2].verdict,
        "blocked? (f5-rejected)"
    );
}

#[test]
fn rules_json_requires_schema_and_rejects_unknown_keys() {
    assert!(AssessRules::from_json("{}").is_err());
    assert!(AssessRules::from_json(r#"{"fields":[]}"#).is_err());
    assert!(AssessRules::from_json(
        r#"{"schema":"scrapelens.assess-rules/1","protectionPath":["/"]}"#
    )
    .is_err());
    assert!(AssessRules::from_json(
        r#"{"schema":"scrapelens.assess-rules/1","fields":[{"name":"a","kind":"present","x":1}]}"#
    )
    .is_err());
    let rules =
        AssessRules::from_json(r#"{"schema":"scrapelens.assess-rules/1","protectionPaths":["/"]}"#)
            .expect("rules");
    assert!(rules.warnings().iter().any(|w| w.contains("\"/\"")));
    let empty = AssessRules::from_json(
        r#"{"schema":"scrapelens.assess-rules/1","fields":[],"protectionMarkers":[],"protectionPaths":[],"blockedStatuses":[]}"#,
    )
    .expect("rules");
    assert!(empty.warnings().iter().any(|w| w.contains("turn off")));
    assert!(AssessRules::default().warnings().is_empty());
}

#[test]
fn f5_text_on_the_protection_route_stays_not_assessed() {
    // Real /TSPD/ pages carry "Your support ID is"; the protection route
    // is a normal handshake and stays `not-assessed`, without becoming `f5-rejected`.
    let bundle = mini(&[(
        "GET",
        "https://app.example.test/TSPD/?type=20",
        200,
        "text/html",
        F5_REJECTED,
    )]);
    let outcome = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(outcome.verdict, "not-assessed");
    assert_eq!(outcome.verdict_kind, VerdictKind::NotAssessed);
    assert!(outcome.app_signals.iter().any(|s| s.signal == "protection"));
}

#[test]
fn rules_reject_wrong_schema_and_bad_json() {
    assert!(AssessRules::from_json("{\"schema\":\"other/9\"}").is_err());
    assert!(AssessRules::from_json("{").is_err());
    assert!(AssessRules::from_json("{\"schema\":\"scrapelens.assess-rules/1\",\"fields\":[{\"name\":\"a\",\"kind\":\"exec\"}]}").is_err());
}

#[test]
fn unavailable_body_without_route_expectation_is_not_assessed() {
    let mut bundle = mini(&[(
        "GET",
        "https://app.example.test/static.js",
        200,
        "text/javascript",
        "var x=1",
    )]);
    bundle.session.requests[0].response_body.state = scrapelens_core::model::BodyState::Unavailable;
    let o = &run(&bundle, &AssessRules::default())[0];
    assert_eq!(o.verdict, "not-assessed");
    assert_eq!(o.verdict_kind, VerdictKind::NotAssessed);
    assert!(o.reason.contains("unavailable"));
}

#[test]
fn unavailable_or_truncated_body_on_a_learned_route_is_indeterminate() {
    let mut bundle = mini(&[
        ("POST", CONN, 200, "text/html", &form("lp", "1", "")),
        ("POST", CONN, 200, "text/html", &form("lp", "2", "")),
        ("POST", CONN, 200, "text/html", &form("lp", "3", "")),
    ]);
    bundle.session.requests[1].response_body.state = scrapelens_core::model::BodyState::Unavailable;
    bundle.session.requests[1].response_body.attachment = None;
    bundle.session.requests[2].response_body.state = scrapelens_core::model::BodyState::Truncated;
    bundle.session.requests[2].response_body.attachment = None;
    let outcomes = run(&bundle, &AssessRules::default());
    assert_eq!(outcomes[0].verdict, "app-ok");
    assert_eq!(outcomes[1].verdict, "undetermined");
    assert_eq!(outcomes[1].verdict_kind, VerdictKind::Undetermined);
    assert!(outcomes[1].reason.contains("unavailable") || outcomes[1].reason.contains("missing"));
    assert!(outcomes[1].missing_fields.iter().any(|f| f == "XML"));
    assert_eq!(outcomes[2].verdict, "undetermined");
    assert!(
        outcomes[2].reason.contains("truncated")
            || outcomes[2].missing_fields.iter().any(|f| f == "STAMP")
    );
}

#[test]
fn rules_json_rejects_empty_marker_and_non_error_statuses() {
    assert!(AssessRules::from_json(
        r#"{"schema":"scrapelens.assess-rules/1","protectionMarkers":[{"contains":""}]}"#
    )
    .is_err());
    for status in ["200", "302", "99", "600"] {
        let text =
            format!(r#"{{"schema":"scrapelens.assess-rules/1","blockedStatuses":[{status}]}}"#);
        assert!(AssessRules::from_json(&text).is_err(), "{status}");
    }
    assert!(AssessRules::from_json(
        r#"{"schema":"scrapelens.assess-rules/1","blockedStatuses":[403,429,503]}"#
    )
    .is_ok());
}

#[test]
fn rules_json_rejects_blank_names_and_paths() {
    for body in [
        r#""fields":[{"name":"  ","kind":"present"}]"#,
        r#""requiredFields":[""]"#,
        r#""protectionPaths":[" "]"#,
    ] {
        let text = format!(r#"{{"schema":"scrapelens.assess-rules/1",{body}}}"#);
        assert!(AssessRules::from_json(&text).is_err(), "{body}");
    }
}
