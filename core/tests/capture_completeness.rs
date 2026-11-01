//! Captura sem requisições: a razão de completude vinda do CDP sobrevive à
//! importação conjunta com o NetLog, e `Capture.sessionSetup` é um evento conhecido.

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::model::CompletenessState;
use scrapelens_core::parse::cdp::parse_cdp_jsonl;
use scrapelens_core::parse::import_capture;

fn event(session: &str, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"sessionId": session, "method": method, "params": params}).to_string()
}

fn setup_only() -> String {
    [
        serde_json::json!({
            "sessionId": "S1", "method": "Target.attachedToTarget",
            "params": {"sessionId": "S1",
                "targetInfo": {"targetId": "T1", "type": "page", "url": "https://a.test/"}},
        })
        .to_string(),
        event(
            "S1",
            "Capture.sessionSetup",
            serde_json::json!({
                "targetId": "T1", "type": "page", "waitingForDebugger": false,
            }),
        ),
    ]
    .join("\n")
}

fn real_netlog() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h1-page/chrome-netlog.json");
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn session_setup_is_a_known_event_counted_as_used_without_warning() {
    let capture = parse_cdp_jsonl(setup_only().as_bytes()).unwrap();
    assert_eq!(capture.unhandled_events, 0);
    assert_eq!(capture.events_total, 2);
    assert_eq!(capture.events_used, 2, "attachedToTarget + sessionSetup");
    let imported = import_capture(
        setup_only().as_bytes(),
        br#"{"constants":{},"events":[]}"#,
        CorrelationOptions::default(),
    )
    .unwrap();
    assert!(
        !imported
            .bundle
            .session
            .warnings
            .iter()
            .any(|w| w.code == "cdp.unhandled_events"),
        "{:?}",
        imported.bundle.session.warnings
    );
}

#[test]
fn capture_without_requests_is_partial_with_an_explicit_reason() {
    let imported = import_capture(
        setup_only().as_bytes(),
        br#"{"constants":{},"events":[]}"#,
        CorrelationOptions::default(),
    )
    .unwrap();
    let session = &imported.bundle.session;
    assert!(session.requests.is_empty());
    assert_eq!(
        session.session.completeness.state,
        CompletenessState::Partial
    );
    assert!(
        session
            .session
            .completeness
            .reasons
            .iter()
            .any(|r| r.contains("nenhuma requisição CDP utilizável")),
        "{:?}",
        session.session.completeness.reasons
    );
}

#[test]
fn netlog_events_without_any_cdp_request_are_listed_as_a_reason() {
    let imported = import_capture(
        setup_only().as_bytes(),
        &real_netlog(),
        CorrelationOptions::default(),
    )
    .unwrap();
    let session = &imported.bundle.session;
    assert_eq!(
        session.session.completeness.state,
        CompletenessState::Partial
    );
    let reasons = &session.session.completeness.reasons;
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("nenhuma requisição CDP utilizável")),
        "{reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("NetLog") && r.contains("sem correspondência")),
        "{reasons:?}"
    );
}
