//! CDP bodies (`cdp-bodies.jsonl`) and search: synthetic mini-fixtures.

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::export::{curl, python, request_body_bytes, ExportOptions};
use scrapelens_core::model::{BodyState, SessionBundle, Source};
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use scrapelens_core::parse::import_capture_with_bodies;
use scrapelens_core::search::{search, Scope, SearchQuery};
use serde_json::{json, Value};

fn will_be_sent(
    id: &str,
    url: &str,
    method: &str,
    ct: Option<&str>,
    post: Option<&str>,
    redirect: Option<u16>,
    ts: f64,
) -> Value {
    let mut headers = json!({"user-agent": "synthetic"});
    if let Some(ct) = ct {
        headers["content-type"] = json!(ct);
    }
    let mut params = json!({
        "requestId": id, "loaderId": "L", "timestamp": ts, "wallTime": 1793046000.0 + ts,
        "request": {"url": url, "method": method, "headers": headers, "postData": post, "hasPostData": post.is_some()},
        "type": "XHR", "frameId": "F"
    });
    if let Some(status) = redirect {
        params["redirectResponse"] = json!({"url": "https://example.test/old", "status": status, "headers": {"location": url}});
    }
    json!({"method": "Network.requestWillBeSent", "params": params})
}

fn response(id: &str, url: &str, status: u16, ct: &str, ts: f64) -> Value {
    json!({"method": "Network.responseReceived", "params": {"requestId": id, "loaderId": "L", "timestamp": ts, "type": "XHR",
        "response": {"url": url, "status": status, "statusText": "", "headers": {"content-type": ct}, "protocol": "http/1.1"}}})
}

fn jsonl(values: &[Value]) -> Vec<u8> {
    values
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>()
        .into_bytes()
}

fn line(
    id: &str,
    attempt: u32,
    kind: &str,
    state: &str,
    enc: Option<&str>,
    data: Option<&str>,
    reason: Option<&str>,
) -> Value {
    json!({"v": 1, "requestId": id, "attemptIndex": attempt, "kind": kind, "state": state,
        "encoding": enc, "data": data, "originalSize": data.map(str::len), "capturedSize": data.map(str::len),
        "source": "requestWillBeSent.postData", "reason": reason, "timestamp": 1.5})
}

struct Built {
    bundle: SessionBundle,
    warnings: Vec<String>,
}

fn build(events: &[Value], bodies: &[Value]) -> Built {
    let capture = parse_cdp_jsonl(&jsonl(events)).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let mut attachments = Default::default();
    let outcome = apply_cdp_bodies(&mut session, &mut attachments, &jsonl(bodies));
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    Built {
        bundle,
        warnings: outcome.warnings.iter().map(|w| w.code.clone()).collect(),
    }
}

fn by_cdp<'a>(b: &'a SessionBundle, id: &str) -> &'a scrapelens_core::model::LogicalRequest {
    b.session
        .requests
        .iter()
        .find(|r| r.cdp.as_ref().and_then(|c| c.request_id.as_deref()) == Some(id))
        .unwrap()
}

const FORM: &str = "application/x-www-form-urlencoded";

fn detran_like() -> Built {
    let u = "https://example.test/connector";
    build(
        &[
            will_be_sent(
                "1.1",
                u,
                "POST",
                Some(FORM),
                Some("cmd=cmd_consultar_placa&placa=ABC1D23&x=a%20b"),
                None,
                1.0,
            ),
            response("1.1", u, 200, "text/plain", 1.1),
            will_be_sent(
                "1.2",
                u,
                "POST",
                Some(FORM),
                Some("cmd=cmd_nova&placa=ZZZ9Z99"),
                None,
                2.0,
            ),
            response("1.2", u, 200, "text/plain", 2.1),
        ],
        &[
            line(
                "1.1",
                0,
                "request",
                "captured",
                Some("utf8"),
                Some("cmd=cmd_consultar_placa&placa=ABC1D23&x=a%20b"),
                None,
            ),
            line(
                "1.2",
                0,
                "request",
                "captured",
                Some("utf8"),
                Some("cmd=cmd_nova&placa=ZZZ9Z99"),
                None,
            ),
            line(
                "1.1",
                0,
                "response",
                "captured",
                Some("utf8"),
                Some("{\"ok\":\"resposta-um\",\"n\":[1,\"dois\"]}"),
                None,
            ),
        ],
    )
}

#[test]
fn same_url_and_method_are_distinguished_by_body_only() {
    let built = detran_like();
    assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    let result = search(&built.bundle, &SearchQuery::new("cmd_consultar_placa"));
    assert_eq!(result.matches.len(), 1);
    let m = &result.matches[0];
    assert_eq!(m.scope, Scope::RequestBody);
    assert!(m.decoded);
    assert_eq!(m.field.as_deref(), Some("cmd"));
    assert_eq!(m.byte_offset, Some(4));
    assert_eq!(m.request_id, by_cdp(&built.bundle, "1.1").id);
    // the synthetic plate of the 1st query finds only the 1st; nothing by URL
    let plate = search(&built.bundle, &SearchQuery::new("ABC1D23"));
    assert_eq!(plate.matches.len(), 1);
    assert_eq!(plate.matches[0].field.as_deref(), Some("placa"));
    let nova = search(&built.bundle, &SearchQuery::new("cmd_nova"));
    assert_eq!(nova.matches[0].request_id, by_cdp(&built.bundle, "1.2").id);
    assert!(search(&built.bundle, &SearchQuery::new("connector"))
        .matches
        .iter()
        .all(|m| m.scope == Scope::Url));
}

#[test]
fn percent_decoded_view_and_scopes() {
    let built = detran_like();
    let mut q = SearchQuery::new("a b");
    q.scopes = vec![Scope::RequestBody];
    let r = search(&built.bundle, &q);
    assert_eq!(r.matches.len(), 1);
    assert!(r.matches[0].decoded);
    assert_eq!(r.matches[0].field.as_deref(), Some("x"));
    // 6 scopes: url, headers (req/resp), cookies, body req/resp
    let mut q = SearchQuery::new("example.test");
    q.scopes = vec![Scope::Url];
    assert_eq!(search(&built.bundle, &q).matches.len(), 2);
    let mut q = SearchQuery::new("synthetic");
    q.scopes = vec![Scope::RequestHeaders];
    let r = search(&built.bundle, &q);
    assert_eq!(r.matches[0].field.as_deref(), Some("user-agent"));
    let mut q = SearchQuery::new("text/plain");
    q.scopes = vec![Scope::ResponseHeaders];
    assert_eq!(
        search(&built.bundle, &q).matches[0].field.as_deref(),
        Some("content-type")
    );
    let mut q = SearchQuery::new("dois");
    q.scopes = vec![Scope::ResponseBody];
    let r = search(&built.bundle, &q);
    assert_eq!(r.matches[0].field.as_deref(), Some("n[1]"));
    assert!(r.matches[0].decoded);
    let mut q = SearchQuery::new("dois");
    q.scopes = vec![Scope::RequestBody];
    assert!(search(&built.bundle, &q).matches.is_empty());
    let mut q = SearchQuery::new("sid");
    q.scopes = vec![Scope::Cookies];
    assert!(search(&built.bundle, &q).matches.is_empty());
    // case sensitivity
    let mut q = SearchQuery::new("CMD_NOVA");
    assert_eq!(search(&built.bundle, &q).matches.len(), 1);
    q.case_sensitive = true;
    assert!(search(&built.bundle, &q).matches.is_empty());
}

#[test]
fn cookies_scope_searches_cookie_pairs() {
    let mut ev = will_be_sent(
        "2.1",
        "https://example.test/a",
        "GET",
        None,
        None,
        None,
        1.0,
    );
    ev["params"]["request"]["headers"]["cookie"] = json!("SESSIONID=SYNTH123; other=1");
    let built = build(&[ev], &[]);
    let mut q = SearchQuery::new("SYNTH123");
    q.scopes = vec![Scope::Cookies];
    let r = search(&built.bundle, &q);
    assert_eq!(r.matches.len(), 1);
    assert_eq!(r.matches[0].field.as_deref(), Some("SESSIONID"));
}

#[test]
fn redirect_307_has_request_body_on_each_attempt_and_302_response_is_unavailable() {
    let built = build(
        &[
            will_be_sent(
                "3.1",
                "https://example.test/old",
                "POST",
                Some(FORM),
                Some("a=1"),
                None,
                1.0,
            ),
            will_be_sent(
                "3.1",
                "https://example.test/new",
                "POST",
                Some(FORM),
                Some("a=1"),
                Some(307),
                1.1,
            ),
            response("3.1", "https://example.test/new", 200, "text/plain", 1.2),
        ],
        &[
            line(
                "3.1",
                0,
                "request",
                "captured",
                Some("utf8"),
                Some("a=1"),
                None,
            ),
            line(
                "3.1",
                1,
                "request",
                "captured",
                Some("utf8"),
                Some("a=1"),
                None,
            ),
            line(
                "3.1",
                0,
                "response",
                "unavailable",
                None,
                None,
                Some("redirect response: CDP does not provide a body"),
            ),
            line(
                "3.1",
                1,
                "response",
                "captured",
                Some("utf8"),
                Some("fim"),
                None,
            ),
        ],
    );
    assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    let req = by_cdp(&built.bundle, "3.1");
    assert_eq!(req.attempts.len(), 2);
    for attempt in &req.attempts {
        assert_eq!(attempt.request_body.state, BodyState::Captured);
        assert_eq!(attempt.request_body.provenance.source, Source::Cdp);
        assert_eq!(
            attempt.request_body.provenance.source_id.as_deref(),
            Some("3.1")
        );
        assert_eq!(
            attempt.request_body.provenance.event.as_deref(),
            Some("requestWillBeSent.postData")
        );
    }
    assert_ne!(
        req.attempts[0].request_body.attachment,
        req.attempts[1].request_body.attachment
    );
    let redirect_body = &req.attempts[0].response_body;
    assert_eq!(redirect_body.state, BodyState::Unavailable);
    assert!(redirect_body.note.as_deref().unwrap().contains("redirect"));
    // The "main" body is the one from the last attempt.
    assert_eq!(req.response_body.state, BodyState::Captured);
    // Search returns the right attempt.
    let r = search(&built.bundle, &SearchQuery::new("fim"));
    assert_eq!(r.matches[0].attempt_id, req.attempts[1].id);
    let r = search(&built.bundle, &SearchQuery::new("a=1"));
    let ids: Vec<_> = r.matches.iter().map(|m| m.attempt_id.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn truncated_is_searched_and_marked_partial() {
    // Non-ASCII test input ("início") checks UTF-8 handling in truncated bodies.
    let mut l = line(
        "4.1",
        0,
        "request",
        "truncated",
        Some("utf8"),
        Some("{\"a\":\"início\",\"b\":\"cort"),
        None,
    );
    l["originalSize"] = json!(9000);
    let built = build(
        &[will_be_sent(
            "4.1",
            "https://example.test/t",
            "POST",
            Some("application/json"),
            Some("x"),
            None,
            1.0,
        )],
        &[l],
    );
    let body = &by_cdp(&built.bundle, "4.1").request_body;
    assert_eq!(body.state, BodyState::Truncated);
    assert_eq!(body.bytes, Some(9000));
    assert!(body.truncated_at.unwrap() < 9000);
    let r = search(&built.bundle, &SearchQuery::new("início"));
    assert_eq!(r.matches.len(), 1);
    assert_eq!(r.matches[0].field.as_deref(), Some("a"));
    assert!(r.partial);
    assert_eq!(r.partial_attempts.len(), 1);
    assert!(!search(&detran_like().bundle, &SearchQuery::new("cmd")).partial);
}

#[test]
fn base64_text_is_decoded_and_binary_is_skipped() {
    use base64::Engine;
    let text = base64::engine::general_purpose::STANDARD.encode("token=segredo-sintetico");
    let bin = base64::engine::general_purpose::STANDARD.encode([0xffu8, 0x00, 0xfe, 0x80]);
    let built = build(
        &[
            will_be_sent(
                "5.1",
                "https://example.test/b",
                "POST",
                Some(FORM),
                Some("x"),
                None,
                1.0,
            ),
            will_be_sent(
                "5.2",
                "https://example.test/c",
                "POST",
                Some("application/octet-stream"),
                Some("x"),
                None,
                2.0,
            ),
        ],
        &[
            line(
                "5.1",
                0,
                "request",
                "captured",
                Some("base64"),
                Some(&text),
                None,
            ),
            line(
                "5.2",
                0,
                "request",
                "captured",
                Some("base64"),
                Some(&bin),
                None,
            ),
        ],
    );
    let r = search(&built.bundle, &SearchQuery::new("segredo"));
    assert_eq!(r.matches.len(), 1);
    assert_eq!(r.matches[0].field.as_deref(), Some("token"));
    assert_eq!(r.skipped_binary, 1);
    let bin_att = by_cdp(&built.bundle, "5.2")
        .request_body
        .attachment
        .clone()
        .unwrap();
    assert_eq!(
        built.bundle.attachment(&bin_att).unwrap(),
        &[0xff, 0, 0xfe, 0x80]
    );
}

#[test]
fn orphans_invalid_lines_and_unavailable_reason() {
    // Non-ASCII test inputs ("órfão") check UTF-8 handling.
    let built = build(
        &[will_be_sent(
            "6.1",
            "https://example.test/o",
            "GET",
            None,
            None,
            None,
            1.0,
        )],
        &[
            line(
                "9.9",
                0,
                "request",
                "captured",
                Some("utf8"),
                Some("órfão"),
                None,
            ),
            line(
                "6.1",
                7,
                "request",
                "captured",
                Some("utf8"),
                Some("nonexistent-attempt"),
                None,
            ),
            line(
                "6.1",
                0,
                "response",
                "discarded",
                None,
                None,
                Some("session body budget exceeded"),
            ),
            line(
                "6.1",
                0,
                "request",
                "captured",
                Some("base64"),
                Some("!!não-base64"), // invalid base64 (non-ASCII input)
                None,
            ),
        ],
    );
    assert_eq!(
        built
            .warnings
            .iter()
            .filter(|c| *c == "cdp.body_orphan")
            .count(),
        2
    );
    assert!(built.warnings.iter().any(|c| c == "cdp.body_line_invalid"));
    let req = by_cdp(&built.bundle, "6.1");
    assert_eq!(req.response_body.state, BodyState::Discarded);
    assert!(req
        .response_body
        .note
        .as_deref()
        .unwrap()
        .contains("budget"));
    assert_eq!(req.request_body.state, BodyState::Unavailable);
    assert!(built.bundle.attachments.is_empty());
    // an orphan never becomes an association by URL/time
    assert!(search(&built.bundle, &SearchQuery::new("órfão"))
        .matches
        .is_empty());
}

#[test]
fn missing_file_keeps_unavailable_with_one_warning() {
    let events = jsonl(&[
        will_be_sent(
            "7.1",
            "https://example.test/a",
            "GET",
            None,
            None,
            None,
            1.0,
        ),
        will_be_sent(
            "7.2",
            "https://example.test/b",
            "POST",
            Some(FORM),
            Some("a=1"),
            None,
            2.0,
        ),
    ]);
    let netlog = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/netlog-h2.json"
    ))
    .unwrap();
    let imported =
        import_capture_with_bodies(&events, &netlog, None, CorrelationOptions::default()).unwrap();
    let count = imported
        .bundle
        .session
        .warnings
        .iter()
        .filter(|w| w.code == "cdp.bodies_file_absent")
        .count();
    assert_eq!(count, 1);
    assert!(imported
        .bundle
        .session
        .requests
        .iter()
        .all(|r| r.request_body.state == BodyState::Unavailable));
    assert!(imported.bundle.attachments.is_empty());

    let bodies = jsonl(&[line(
        "7.2",
        0,
        "request",
        "captured",
        Some("utf8"),
        Some("a=1"),
        None,
    )]);
    let with = import_capture_with_bodies(
        &events,
        &netlog,
        Some(&bodies),
        CorrelationOptions::default(),
    )
    .unwrap();
    assert!(with
        .bundle
        .session
        .warnings
        .iter()
        .all(|w| w.code != "cdp.bodies_file_absent"));
    assert_eq!(with.bundle.attachments.len(), 1);
}

#[test]
fn export_includes_captured_body_of_final_attempt() {
    let built = build(
        &[
            will_be_sent(
                "8.1",
                "https://example.test/p",
                "POST",
                Some(FORM),
                Some("a=1"),
                None,
                1.0,
            ),
            response("8.1", "https://example.test/p", 200, "text/plain", 1.1),
        ],
        &[line(
            "8.1",
            0,
            "request",
            "captured",
            Some("utf8"),
            Some("a=1&b='2'"),
            None,
        )],
    );
    let request = by_cdp(&built.bundle, "8.1");
    let bytes = request_body_bytes(&built.bundle, request).expect("captured body");
    assert_eq!(bytes, b"a=1&b='2'");
    let options = ExportOptions::default();
    let c = curl::to_curl(request, Some(bytes), &options).unwrap();
    assert!(c.body_included);
    assert!(c.text.contains("--data-binary"));
    let p = python::to_python(request, Some(bytes), &options).unwrap();
    assert!(p.body_included);
    // no body available: nothing is invented
    assert!(
        request_body_bytes(&detran_like().bundle, by_cdp(&detran_like().bundle, "1.1")).is_some()
    );
    let none = build(
        &[will_be_sent(
            "8.2",
            "https://example.test/q",
            "GET",
            None,
            None,
            None,
            1.0,
        )],
        &[],
    );
    assert!(request_body_bytes(&none.bundle, by_cdp(&none.bundle, "8.2")).is_none());
}
