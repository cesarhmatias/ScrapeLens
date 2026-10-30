//! CDP: objetos de header não são sequência; `headersText` h1 é a exceção.

use scrapelens_core::correlate::{attach_netlog, CorrelationOptions};
use scrapelens_core::model::{MatchState, Protocol, Verification};
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::netlog::parse_netlog;

fn read_experiment(file: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h1-page")
        .join(file);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn request_object_is_subset_and_response_headers_text_is_verified() {
    let capture = parse_cdp_jsonl(&read_experiment("cdp-events.jsonl")).unwrap();
    assert!(capture.events_total > 0);
    assert!(capture.events_used > 0);
    let (session, _) = build_cdp_session(&capture);
    assert!(!session.requests.is_empty());

    let request = session
        .requests
        .iter()
        .find(|request| request.url.contains("/echo-order?from=jsheaders"))
        .expect("requestWillBeSent de /echo-order?from=jsheaders");

    assert_eq!(request.protocol, Protocol::H1);
    assert_eq!(request.status, Some(200));
    assert_eq!(
        request.request_headers.verification(),
        Verification::Unverified
    );
    // ExtraInfo colapsa duplicatas: só o último x-rep sobrevive.
    // `x-dup` veio da Fetch API e o ExtraInfo o mantém como um único valor.
    assert_eq!(request.request_headers.first_value("x-dup"), Some("a, b"));
    // O bloco original do Blink continua como evidência.
    assert!(request.attempts[0].header_evidence.iter().any(|evidence| {
        evidence.event == "Network.requestWillBeSent.request.headers"
            && evidence.view.contains("user-agent")
    }));
    // No h1 o headersText da resposta é verificado e mantém 2 set-cookie.
    let setcookie = session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/setcookie"))
        .expect("requisição /setcookie");
    assert_eq!(
        setcookie.response_headers.verification(),
        Verification::Verified
    );
    assert_eq!(setcookie.response_headers.get_all("set-cookie").len(), 2);
    assert_eq!(setcookie.set_cookies.len(), 2);
}

#[test]
fn real_h1_correlation_matches_and_prefers_netlog_sequence() {
    let cdp = parse_cdp_jsonl(&read_experiment("cdp-events.jsonl")).unwrap();
    let (mut session, _) = build_cdp_session(&cdp);
    let netlog_bytes = read_experiment("chrome-netlog.json");
    let netlog = parse_netlog(&netlog_bytes).unwrap();
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    assert!(outcome.matched_attempts > 0, "{outcome:?}");
    assert_eq!(
        outcome.ambiguous_attempts, 0,
        "a matriz reporta correlação inequívoca nos 60 casos"
    );
    let request = session
        .requests
        .iter()
        .find(|request| request.url.contains("/echo-order?from=jsheaders"))
        .expect("requisição correlacionada");
    assert_eq!(request.match_state, MatchState::Matched);
    let attempt = &request.attempts[0];
    assert_eq!(attempt.match_state, MatchState::Matched);
    assert_eq!(
        attempt.request_headers.verification(),
        Verification::Verified
    );
    assert_eq!(attempt.request_headers.first_value("x-dup"), Some("a, b"));
    let index = |name: &str| {
        attempt
            .request_headers
            .headers
            .iter()
            .position(|header| header.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("header {name} ausente na visão primária"))
    };
    assert!(index("x-zeta") < index("x-alpha"));
    assert!(index("x-alpha") < index("x-mid"));
    // O bloco CDP continua guardado, mesmo tendo cedido a visão primária.
    assert!(attempt
        .header_evidence
        .iter()
        .any(|evidence| evidence.event.contains("responseReceivedExtraInfo")));
}

#[test]
fn initiator_keeps_type_url_line_and_stack_top() {
    let line = |id: &str, url: &str, extra: &str, init: &str| {
        format!(
            r#"{{"method":"Network.requestWillBeSent","params":{{"requestId":"{id}","timestamp":1.0,"wallTime":1.0,"type":"XHR","request":{{"url":"{url}","method":"GET","headers":{{}}}},"initiator":{init}{extra}}}}}"#
        )
    };
    let script = r#"{"type":"script","url":"https://x.test/a.js","lineNumber":7,"stack":{"callFrames":[{"functionName":"go","url":"https://x.test/a.js","lineNumber":12,"columnNumber":3},{"functionName":"outer","url":"https://x.test/b.js","lineNumber":1}]}}"#;
    let jsonl = [
        line(
            "1",
            "https://x.test/p",
            "",
            r#"{"type":"parser","url":"https://x.test/"}"#,
        ),
        line("2", "https://x.test/r", "", script),
        line("3", "https://x.test/o", "", r#"{"type":"other"}"#),
    ]
    .join("\n");
    let capture = parse_cdp_jsonl(jsonl.as_bytes()).unwrap();
    let (session, _) = build_cdp_session(&capture);
    let init = |suffix: &str| {
        session
            .requests
            .iter()
            .find(|r| r.url.ends_with(suffix))
            .and_then(|r| r.attempts[0].initiator.clone())
            .unwrap_or_else(|| panic!("initiator de {suffix}"))
    };
    assert_eq!(init("/p").kind, "parser");
    assert_eq!(init("/p").url.as_deref(), Some("https://x.test/"));
    let s = init("/r");
    assert_eq!((s.kind.as_str(), s.line_number), ("script", Some(7)));
    let top = s.stack_top.expect("topo do stack");
    assert_eq!(top.function.as_deref(), Some("go"));
    assert_eq!(top.line_number, Some(12));
    assert_eq!(init("/o").kind, "other");
    // sessão antiga sem os campos novos continua válida
    let old: scrapelens_core::model::Initiator =
        serde_json::from_str(r#"{"kind":"parser","url":"u"}"#).unwrap();
    assert!(old.stack_top.is_none() && old.line_number.is_none());
}

// ---- multi-alvo (docs/14, onda 2) ----

fn event(session: &str, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"sessionId": session, "method": method, "params": params}).to_string()
}

fn request_event(session: &str, id: &str, url: &str, ts: f64) -> String {
    event(
        session,
        "Network.requestWillBeSent",
        serde_json::json!({
            "requestId": id, "timestamp": ts, "wallTime": 1.0, "type": "XHR",
            "request": {"url": url, "method": "GET", "headers": {}},
        }),
    )
}

fn response_event(session: &str, id: &str, url: &str, ts: f64, from_sw: bool) -> String {
    event(
        session,
        "Network.responseReceived",
        serde_json::json!({
            "requestId": id, "timestamp": ts,
            "response": {
                "url": url, "status": 200, "headers": {}, "protocol": "http/1.1",
                "fromServiceWorker": from_sw,
            },
        }),
    )
}

fn attached(session: &str, target_id: &str, kind: &str, url: &str, parent: Option<&str>) -> String {
    let mut line = serde_json::json!({
        "sessionId": session,
        "method": "Target.attachedToTarget",
        "params": {
            "sessionId": session,
            "targetInfo": {"targetId": target_id, "type": kind, "url": url},
        },
    });
    if let Some(parent) = parent {
        line["parentSessionId"] = serde_json::json!(parent);
    }
    line.to_string()
}

#[test]
fn colliding_request_ids_stay_separate_by_session_and_keep_target() {
    let jsonl = [
        attached("S1", "T1", "page", "https://a.test/", None),
        attached("S2", "T2", "iframe", "https://b.test/", Some("S1")),
        request_event("S1", "req-1", "https://a.test/x", 10.0),
        request_event("S2", "req-1", "https://b.test/y", 10.1),
        response_event("S1", "req-1", "https://a.test/x", 10.2, false),
        response_event("S2", "req-1", "https://b.test/y", 10.3, false),
    ]
    .join("\n");
    let capture = parse_cdp_jsonl(jsonl.as_bytes()).unwrap();
    assert_eq!(capture.requests.len(), 2, "{capture:?}");
    assert!(capture.targets.contains_key("S1") && capture.targets.contains_key("S2"));
    let (session, _) = build_cdp_session(&capture);
    assert_eq!(session.requests.len(), 2);
    let x = session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/x"))
        .expect("/x");
    let y = session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/y"))
        .expect("/y");
    assert_eq!(x.cdp.as_ref().unwrap().session_id.as_deref(), Some("S1"));
    assert_eq!(x.target.as_ref().unwrap().kind.as_str(), "page");
    assert_eq!(y.target.as_ref().unwrap().kind.as_str(), "iframe");
    assert_eq!(
        y.target.as_ref().unwrap().parent_session_id.as_deref(),
        Some("S1")
    );
}

#[test]
fn bodies_are_mapped_by_session_and_request_id() {
    use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
    let jsonl = [
        attached("S1", "T1", "page", "https://a.test/", None),
        attached("S2", "T2", "worker", "https://a.test/w.js", Some("S1")),
        request_event("S1", "req-1", "https://a.test/x", 10.0),
        request_event("S2", "req-1", "https://a.test/y", 10.1),
    ]
    .join("\n");
    let capture = parse_cdp_jsonl(jsonl.as_bytes()).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let bodies = [
        r#"{"v":1,"sessionId":"S1","requestId":"req-1","attemptIndex":0,"kind":"response","state":"captured","data":"page-body"}"#,
        r#"{"v":1,"sessionId":"S2","requestId":"req-1","attemptIndex":0,"kind":"response","state":"captured","data":"worker-body"}"#,
    ]
    .join("\n");
    let mut attachments = std::collections::BTreeMap::new();
    let outcome = apply_cdp_bodies(&mut session, &mut attachments, bodies.as_bytes());
    assert_eq!(outcome.applied, 2, "{outcome:?}");
    let body = |suffix: &str| {
        let request = session
            .requests
            .iter()
            .find(|request| request.url.ends_with(suffix))
            .unwrap();
        let attachment = request.attempts[0]
            .response_body
            .attachment
            .clone()
            .expect("anexo");
        String::from_utf8(attachments[&attachment].clone()).unwrap()
    };
    assert_eq!(body("/x"), "page-body");
    assert_eq!(body("/y"), "worker-body");
}

#[test]
fn service_worker_observations_link_only_with_evidence() {
    let doc = |from_sw: bool| {
        [
            attached("S1", "T1", "page", "https://a.test/", None),
            attached(
                "S2",
                "T2",
                "service_worker",
                "https://a.test/sw.js",
                Some("S1"),
            ),
            request_event("S1", "req-1", "https://a.test/marker", 20.0),
            request_event("S2", "req-2", "https://a.test/marker", 20.005),
            response_event("S1", "req-1", "https://a.test/marker", 20.01, from_sw),
            response_event("S2", "req-2", "https://a.test/marker", 20.02, from_sw),
        ]
        .join("\n")
    };
    let capture = parse_cdp_jsonl(doc(true).as_bytes()).unwrap();
    let (session, _) = build_cdp_session(&capture);
    assert_eq!(session.requests.len(), 2);
    assert!(
        session.requests.iter().all(|request| {
            request
                .links
                .iter()
                .any(|link| link.resolution == "linked" && link.kind == "service_worker")
        }),
        "{:#?}\n---\n{:?}",
        session.requests,
        session.warnings
    );
    assert!(!session
        .warnings
        .iter()
        .any(|warning| warning.code == "cdp.service_worker_ambiguous"));

    let capture = parse_cdp_jsonl(doc(false).as_bytes()).unwrap();
    let (session, _) = build_cdp_session(&capture);
    assert!(session.requests.iter().all(|request| {
        request
            .links
            .iter()
            .any(|link| link.resolution == "ambiguous")
    }));
    assert!(session
        .warnings
        .iter()
        .any(|warning| warning.code == "cdp.service_worker_ambiguous"));
}

#[test]
fn old_cdp_file_without_session_id_is_one_implicit_session() {
    let jsonl = [
        r#"{"method":"Network.requestWillBeSent","params":{"requestId":"1","timestamp":1.0,"wallTime":1.0,"request":{"url":"https://x.test/a","method":"GET","headers":{}}}}"#,
        r#"{"method":"Network.responseReceived","params":{"requestId":"1","timestamp":1.1,"response":{"url":"https://x.test/a","status":200,"headers":{},"protocol":"http/1.1"}}}"#,
    ]
    .join("\n");
    let capture = parse_cdp_jsonl(jsonl.as_bytes()).unwrap();
    let (session, _) = build_cdp_session(&capture);
    assert_eq!(session.requests.len(), 1);
    assert!(session.requests[0]
        .cdp
        .as_ref()
        .unwrap()
        .session_id
        .is_none());
    assert!(session.requests[0].target.is_none());
    assert!(!session
        .warnings
        .iter()
        .any(|warning| warning.code == "cdp.target_unknown"));
}

#[test]
fn old_live_session_without_session_id_has_no_target_provenance() {
    // Bruto real anterior à rodada 10 (campo `session`, não `sessionId`):
    // sessão implícita, sem alvo e sem cdp.target_unknown.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h1-plain/cdp-events.jsonl");
    let jsonl = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let capture = parse_cdp_jsonl(&jsonl).unwrap();
    assert!(!capture.requests.is_empty());
    let (session, _) = build_cdp_session(&capture);
    assert_eq!(session.requests.len(), 2, "h1-plain tem 2 requisições");
    assert!(
        session
            .requests
            .iter()
            .all(|request| request.cdp.as_ref().unwrap().session_id.is_none()),
        "{:?}",
        session.requests
    );
    assert!(session
        .requests
        .iter()
        .all(|request| request.target.is_none()));
    assert!(!session
        .warnings
        .iter()
        .any(|warning| warning.code == "cdp.target_unknown"));
}

#[test]
fn capture_setup_timeout_is_a_warning_naming_the_command() {
    let jsonl = [
        request_event("S1", "r1", "https://a.test/x", 1.0),
        event(
            "S1",
            "Capture.targetSetupTimeout",
            serde_json::json!({"command": "Target.setAutoAttach", "targetId": "T2"}),
        ),
    ]
    .join("\n");
    let capture = parse_cdp_jsonl(jsonl.as_bytes()).unwrap();
    let (session, _) = build_cdp_session(&capture);
    let warning = session
        .warnings
        .iter()
        .find(|warning| warning.code == "cdp.target_setup_timeout")
        .unwrap_or_else(|| panic!("{:?}", session.warnings));
    assert!(
        warning
            .message
            .contains("configuração incompleta: Target.setAutoAttach sem resposta"),
        "{}",
        warning.message
    );
    assert!(!session
        .warnings
        .iter()
        .any(|warning| warning.code == "cdp.target_attach_failed"));
}
