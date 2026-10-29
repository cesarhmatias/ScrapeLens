//! Importador `scrapelens.trace/1`: válido, truncado e malformado.

use scrapelens_core::model::{BodyState, OrderState};
use scrapelens_core::parse::import_trace;
use serde_json::{json, Value};

fn step(n: u32) -> Value {
    json!({
        "method": "POST", "url": format!("https://x.test/app/Connector?n={n}"),
        "requestHeaders": [["Content-Type","application/x-www-form-urlencoded"],["X-Dup","a"],{"name":"X-Dup","value":"b"}],
        "requestBody": {"text": "SESSIONID=abc&STAMP=7"},
        "status": 200,
        "responseHeaders": [["Content-Type","text/html"],["Set-Cookie","a=1"],["Set-Cookie","b=2"]],
        "responseBody": {"text": "XML=ok"},
        "elapsedMs": 12.5,
        "checks": [{"name":"app-ok","ok":true}]
    })
}

fn trace(steps: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema":"scrapelens.trace/1","generator":"t","startedAt":"2026-10-29T12:00:00Z","steps":steps})).unwrap()
}

#[test]
fn valid_trace_becomes_a_labeled_session_with_duplicates_and_bodies() {
    let imported = import_trace(&trace(vec![step(1), step(2)])).unwrap();
    let s = &imported.bundle.session;
    assert_eq!(s.requests.len(), 2);
    assert!(s.session.labels.iter().any(|l| l == "script-trace"));
    let a = &s.requests[0].attempts[0];
    assert_eq!(
        a.request_headers
            .headers
            .iter()
            .filter(|h| h.name == "X-Dup")
            .count(),
        2
    );
    assert_eq!(
        a.response_headers
            .headers
            .iter()
            .filter(|h| h.name == "Set-Cookie")
            .count(),
        2
    );
    assert_eq!(a.request_headers.order_state, OrderState::Unknown);
    assert_eq!(a.provenance.method, "script-trace");
    assert_eq!(a.status, Some(200));
    assert_eq!(a.request_body.state, BodyState::Captured);
    assert!(a.response_body.attachment.is_some());
    assert!(imported.bundle.attachments.len() >= 2);
}

#[test]
fn truncated_body_error_and_failed_check_become_warnings() {
    let mut bad = step(1);
    bad["responseBody"] = json!({"text":"abc","truncated":true,"size":999});
    bad["checks"] = json!([{"name":"app-ok","ok":false,"detail":"errorMessage"}]);
    bad["error"] = json!("timeout");
    let imported = import_trace(&trace(vec![bad])).unwrap();
    let a = &imported.bundle.session.requests[0].attempts[0];
    assert_eq!(a.response_body.state, BodyState::Truncated);
    assert_eq!(a.response_body.bytes, Some(999));
    assert_eq!(a.response_body.truncated_at, Some(3));
    let codes: Vec<_> = imported
        .bundle
        .session
        .warnings
        .iter()
        .map(|w| w.code.as_str())
        .collect();
    for c in [
        "trace.body_truncated",
        "trace.check_failed",
        "trace.step_error",
    ] {
        assert!(codes.contains(&c), "{codes:?}");
    }
}

#[test]
fn malformed_traces_fail_with_a_clear_error_never_panic() {
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"not json".to_vec(), "JSON inválido"),
        (br#"{"steps":[]}"#.to_vec(), "schema"),
        (
            br#"{"schema":"scrapelens.trace/2","steps":[]}"#.to_vec(),
            "não suportado",
        ),
        (br#"{"schema":"scrapelens.trace/1"}"#.to_vec(), "steps"),
        (trace(vec![json!({"url":"https://x.test/"})]), "method"),
        (
            trace(vec![json!({"method":"GET","url":"file:///etc/passwd"})]),
            "http(s)",
        ),
        (
            trace(vec![
                json!({"method":"GET","url":"https://x.test/","status":7}),
            ]),
            "status",
        ),
        (
            trace(vec![
                json!({"method":"GET","url":"https://x.test/","requestHeaders":[["only-name"]]}),
            ]),
            "requestHeaders",
        ),
        (
            trace(vec![
                json!({"method":"GET","url":"https://x.test/","responseBody":{"text":1}}),
            ]),
            "responseBody.text",
        ),
        (trace(vec![json!(5)]), "não é objeto"),
        (
            trace(vec![
                json!({"method":"GET","url":"https://x.test/","elapsedMs":-1}),
            ]),
            "elapsedMs",
        ),
    ];
    for (bytes, needle) in cases {
        let err = import_trace(&bytes).expect_err(needle).to_string();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

#[test]
fn large_trace_is_linear() {
    let steps: Vec<Value> = (0..5000).map(step).collect();
    let started = std::time::Instant::now();
    let imported = import_trace(&trace(steps)).unwrap();
    assert_eq!(imported.bundle.session.requests.len(), 5000);
    assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
}
