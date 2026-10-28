//! Propagação por valor na sanitização (sessão sintética, valores falsos).

use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use serde_json::{json, Value};

const SID: &str = "CSAN00000_000000000001";
const SLASHY: &str = "ab/cd+ef\"gh_0123456789";
const FORM: &str = "application/x-www-form-urlencoded";

fn event(id: &str, url: &str, ct: &str, post: &str, ts: f64) -> Value {
    json!({"method": "Network.requestWillBeSent", "params": {
        "requestId": id, "loaderId": "L", "timestamp": ts, "wallTime": 1793046000.0 + ts,
        "request": {"url": url, "method": "POST", "headers": {"content-type": ct}, "postData": post, "hasPostData": true},
        "type": "XHR", "frameId": "F"}})
}

fn body_line(id: &str, kind: &str, ct_data: &str) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":0,"kind":kind,"state":"captured","encoding":"utf8",
        "data":ct_data,"originalSize":ct_data.len(),"capturedSize":ct_data.len(),"source":"x","reason":null,"timestamp":1.0})
}

fn jsonl(values: &[Value]) -> Vec<u8> {
    values
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>()
        .into_bytes()
}

fn sanitized() -> (
    SessionBundle,
    std::collections::BTreeMap<String, usize>,
    Vec<String>,
) {
    let form_body = format!("SESSIONID={SID}&XML=i2212%C2%A0{SID}100000dummy&n=abc12&flag=true");
    let json_body = format!(
        "{{\"token\":{},\"note\":{}}}",
        serde_json::to_string(SLASHY).unwrap(),
        serde_json::to_string(&format!("ref {SLASHY} fim")).unwrap()
    );
    let pct = SLASHY
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'_' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect::<String>();
    let enc_form = format!("password={pct}&copy={pct}");
    let q_url = format!("https://example.test/a?token={SID}&ref={SID}&short=abc12");
    let events = [
        event("1.1", "https://example.test/f", FORM, &form_body, 1.0),
        event(
            "1.2",
            "https://example.test/j",
            "application/json",
            &json_body,
            2.0,
        ),
        event("1.3", &q_url, FORM, &enc_form, 3.0),
        event("1.4", "https://example.test/h", FORM, "a=1", 4.0),
        json!({"method": "Network.responseReceived", "params": {"requestId": "1.4", "loaderId": "L", "timestamp": 4.1, "type": "XHR",
            "response": {"url": "https://example.test/h", "status": 200, "statusText": "", "headers": {"content-type": "text/html"}, "protocol": "http/1.1"}}}),
    ];
    let html = format!("<script>var m_currentSessionId = \"{SID}\";</script>");
    let bodies = [
        body_line("1.1", "request", &form_body),
        body_line("1.2", "request", &json_body),
        body_line("1.3", "request", &enc_form),
        body_line("1.4", "response", &html),
    ];
    let capture = parse_cdp_jsonl(&jsonl(&events)).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let mut attachments = Default::default();
    apply_cdp_bodies(&mut session, &mut attachments, &jsonl(&bodies));
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    let codes = export.warnings.iter().map(|w| w.code.clone()).collect();
    (export.bundle, export.redactions, codes)
}

fn everything(bundle: &SessionBundle) -> String {
    let mut text = serde_json::to_string(&bundle.session).unwrap();
    for bytes in bundle.attachments.values() {
        text.push_str(&String::from_utf8_lossy(bytes));
    }
    text
}

#[test]
fn session_value_in_opaque_field_url_and_json_is_redacted_everywhere() {
    let (bundle, redactions, codes) = sanitized();
    let all = everything(&bundle);
    assert!(!all.contains(SID), "valor de sessão vazou");
    assert!(!all.contains(SLASHY));
    assert!(!all.contains("ab%2Fcd"), "forma percent-encoded vazou");
    assert!(!all.contains("ab\\/cd"));
    assert!(codes.iter().any(|c| c == "sanitize.value_propagation"));
    assert!(redactions.keys().any(|k| k.starts_with("propagated:")));
}

#[test]
fn opaque_form_field_stays_parseable_and_short_values_remain() {
    let (bundle, _, _) = sanitized();
    let req = bundle
        .session
        .requests
        .iter()
        .find(|r| r.url.ends_with("/f"))
        .unwrap();
    let name = req.request_body.attachment.as_ref().unwrap();
    let text = String::from_utf8(bundle.attachments[name].clone()).unwrap();
    let pairs: Vec<(&str, &str)> = text
        .split('&')
        .map(|p| p.split_once('=').unwrap())
        .collect();
    assert_eq!(pairs.len(), 4, "{text}");
    assert_eq!(pairs[0], ("SESSIONID", "[REDACTED]"));
    assert_eq!(pairs[1].0, "XML");
    assert!(pairs[1].1.contains("REDACTED") && pairs[1].1.contains("dummy"));
    // valores curtos/triviais não são propagados
    assert_eq!(pairs[2], ("n", "abc12"));
    assert_eq!(pairs[3], ("flag", "true"));
    // query: `short=abc12` permanece; `ref=<SID>` foi redigido
    let url = bundle
        .session
        .requests
        .iter()
        .find(|r| r.url.contains("/a?"))
        .unwrap()
        .url
        .clone();
    assert!(url.contains("short=abc12"));
    assert!(!url.contains(SID));
    assert!(url.contains("ref="));
}

#[test]
fn html_response_is_omitted_not_claimed_sanitized() {
    let (bundle, _, codes) = sanitized();
    let req = bundle
        .session
        .requests
        .iter()
        .find(|r| r.url.ends_with("/h"))
        .unwrap();
    assert_eq!(
        req.response_body.state,
        scrapelens_core::model::BodyState::Discarded
    );
    assert!(codes.iter().any(|c| c == "sanitize.attachment_omitted"));
}

#[test]
fn trivial_values_are_not_collected() {
    let events = [event(
        "2.1",
        "https://example.test/x?token=true&password=12345678",
        FORM,
        "a=true&b=12345678",
        1.0,
    )];
    let capture = parse_cdp_jsonl(&jsonl(&events)).unwrap();
    let (session, _) = build_cdp_session(&capture);
    let export = sanitize_bundle(&SessionBundle::new(session), &SanitizeOptions::default());
    assert!(!export
        .redactions
        .keys()
        .any(|k| k.starts_with("propagated:")));
    assert!(!export
        .warnings
        .iter()
        .any(|w| w.code == "sanitize.value_propagation"));
}
