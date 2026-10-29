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
