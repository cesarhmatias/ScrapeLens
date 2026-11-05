//! Regressions from the independent review of wave 4a (see docs/08, section "Revisão da onda 4a").

use scrapelens_core::export::sanitize::{is_sensitive_header, sanitize_bundle, SanitizeOptions};
use scrapelens_core::export::{curl, python, ExportOptions};
use scrapelens_core::model::{AttemptOutcome, BodyState, SessionBundle, Verification};
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies_with_capture;
use scrapelens_core::search::{search, Scope, SearchQuery};
use serde_json::{json, Value};

const FORM: &str = "application/x-www-form-urlencoded";

fn req(
    id: &str,
    url: &str,
    method: &str,
    headers: Value,
    post: Option<&str>,
    redirect: Option<u16>,
    ts: f64,
) -> Value {
    let mut params = json!({
        "requestId": id, "loaderId": "L", "timestamp": ts, "wallTime": 1793046000.0 + ts,
        "request": {"url": url, "method": method, "headers": headers, "postData": post, "hasPostData": post.is_some()},
        "type": "XHR", "frameId": "F"});
    if let Some(status) = redirect {
        params["redirectResponse"] = json!({"url": "https://example.test/old", "status": status, "headers": {"location": url}});
    }
    json!({"method": "Network.requestWillBeSent", "params": params})
}

fn finish(id: &str, url: &str, ts: f64) -> Vec<Value> {
    vec![
        json!({"method": "Network.responseReceived", "params": {"requestId": id, "loaderId": "L", "timestamp": ts, "type": "XHR",
            "response": {"url": url, "status": 200, "statusText": "", "headers": {"content-type": "text/plain"}, "protocol": "http/1.1"}}}),
        json!({"method": "Network.loadingFinished", "params": {"requestId": id, "timestamp": ts + 0.01, "encodedDataLength": 1}}),
    ]
}

fn line(id: &str, attempt: u32, kind: &str, data: &str) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":attempt,"kind":kind,"state":"captured","encoding":"utf8",
        "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":1.0})
}

fn jsonl(values: &[Value]) -> Vec<u8> {
    values
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>()
        .into_bytes()
}

fn bundle(events: &[Value], bodies: &[Value]) -> SessionBundle {
    let capture = parse_cdp_jsonl(&jsonl(events)).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let mut attachments = Default::default();
    apply_cdp_bodies_with_capture(
        &mut session,
        &mut attachments,
        &jsonl(bodies),
        Some(&capture),
    );
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    bundle
}

fn everything(bundle: &SessionBundle) -> String {
    let mut text = serde_json::to_string(&bundle.session).unwrap();
    for bytes in bundle.attachments.values() {
        text.push_str(&String::from_utf8_lossy(bytes));
    }
    text
}

fn sanitized(b: &SessionBundle) -> SessionBundle {
    sanitize_bundle(b, &SanitizeOptions::default()).bundle
}

// ---- 1 -------------------------------------------------------------------

#[test]
fn item1_propagation_never_touches_enums_and_never_fails_open() {
    let url = "https://example.test/u?ref=SessAbcdef123456";
    let mut events = vec![
        req(
            "1.1",
            "https://example.test/login",
            "POST",
            json!({"content-type": FORM, "x-note": "seen Pa55w0rd-secret-9", "cookie": "sid=SessAbcdef123456"}),
            Some("state=completed&password=Pa55w0rd-secret-9"),
            None,
            1.0,
        ),
        req("1.2", url, "GET", json!({}), None, None, 2.0),
    ];
    events.extend(finish("1.1", "https://example.test/login", 1.1));
    events.extend(finish("1.2", url, 2.1));
    let b = bundle(
        &events,
        &[line(
            "1.1",
            0,
            "request",
            "state=completed&password=Pa55w0rd-secret-9",
        )],
    );
    assert_eq!(
        b.session.requests[0].attempts[0].outcome,
        AttemptOutcome::Completed
    );
    let s = sanitized(&b);
    let all = everything(&s);
    assert!(!all.contains("Pa55w0rd-secret-9"), "password leaked");
    assert!(!all.contains("SessAbcdef123456"), "cookie leaked");
    assert_eq!(
        s.session.requests[0].attempts[0].outcome,
        AttemptOutcome::Completed
    );
    // the sanitized session still deserializes
    let round: scrapelens_core::SessionV1 =
        serde_json::from_value(serde_json::to_value(&s.session).unwrap()).unwrap();
    assert_eq!(round.requests.len(), 2);
}

// ---- 2 -------------------------------------------------------------------

#[test]
fn item2_percent_hex_case_insensitive_and_plus_for_space() {
    let events = vec![
        req(
            "2.1",
            "https://example.test/a",
            "POST",
            json!({"content-type": "application/json"}),
            Some("{}"),
            None,
            1.0,
        ),
        req(
            "2.2",
            "https://example.test/b?x=a%2fb%3Dc%2bd%26e%3ff&y=my+secret+value+ok",
            "GET",
            json!({}),
            None,
            None,
            2.0,
        ),
    ];
    let b = bundle(
        &events,
        &[line(
            "2.1",
            0,
            "request",
            r#"{"token":"a/b=c+d&e?f","password":"my secret value ok"}"#,
        )],
    );
    let all = everything(&sanitized(&b));
    assert!(!all.contains("a%2fb"), "{all}");
    assert!(!all.contains("%3D"));
    assert!(!all.contains("my+secret"), "{all}");
}

// ---- 3 -------------------------------------------------------------------

#[test]
fn item3_custom_headers_classified_by_name_and_propagate() {
    for name in [
        "X-Auth",
        "X-Jwt-Thing",
        "X-Session-Foo",
        "X-Api-Key",
        "X-User-Password",
        "X-Signature-V2",
        "X-Credential",
    ] {
        assert!(is_sensitive_header(name), "{name}");
    }
    for name in [":authority", "Accept", "X-Author", "User-Agent"] {
        assert!(!is_sensitive_header(name), "{name}");
    }
    let events = vec![
        req(
            "3.1",
            "https://example.test/a",
            "GET",
            json!({"x-auth": "authvalue-12345", "x-jwt-thing": "eyJhbGciOi.payload.sig"}),
            None,
            None,
            1.0,
        ),
        req(
            "3.2",
            "https://example.test/b?echo=authvalue-12345&j=eyJhbGciOi.payload.sig",
            "GET",
            json!({}),
            None,
            None,
            2.0,
        ),
    ];
    let all = everything(&sanitized(&bundle(&events, &[])));
    assert!(!all.contains("authvalue-12345"));
    assert!(!all.contains("eyJhbGciOi.payload.sig"));
}

// ---- 4 -------------------------------------------------------------------

#[test]
fn item4_generic_keys_redacted_in_place_without_propagating() {
    let events = vec![
        req(
            "4.1",
            "https://example.test/a",
            "POST",
            json!({"content-type": "application/json"}),
            Some("{}"),
            None,
            1.0,
        ),
        req(
            "4.2",
            "https://example.test/cmd_consultar_placa/list",
            "GET",
            json!({}),
            None,
            None,
            2.0,
        ),
        req(
            "4.3",
            "https://example.test/c",
            "POST",
            json!({"content-type": FORM}),
            Some("x"),
            None,
            3.0,
        ),
    ];
    let b = bundle(
        &events,
        &[
            line(
                "4.1",
                0,
                "request",
                r#"{"key":"cmd_consultar_placa","code":"codevalue-123"}"#,
            ),
            line(
                "4.3",
                0,
                "request",
                "cpf=12345678901&cpfecho=12345678901&n=1234567",
            ),
        ],
    );
    let s = sanitized(&b);
    let body = |id: &str| {
        let r = s
            .session
            .requests
            .iter()
            .find(|r| r.cdp.as_ref().unwrap().request_id.as_deref() == Some(id))
            .unwrap();
        String::from_utf8(s.attachments[r.request_body.attachment.as_ref().unwrap()].clone())
            .unwrap()
    };
    let json_body = body("4.1");
    assert!(
        !json_body.contains("cmd_consultar_placa"),
        "generic key redacted in place: {json_body}"
    );
    assert!(
        s.session.requests[1].url.contains("cmd_consultar_placa"),
        "did not propagate"
    );
    let form = body("4.3");
    assert!(!form.contains("12345678901"), "{form}");
    assert!(
        form.contains("n=1234567"),
        "short digits remain: {form}"
    );
}

// ---- 5 -------------------------------------------------------------------

#[test]
fn item5_search_decodes_json_escapes_url_percent_and_maps_offsets() {
    let events = vec![
        req(
            "5.1",
            "https://example.test/x?q=Cmd%5FConsultar",
            "POST",
            json!({"content-type": "application/json"}),
            Some("{}"),
            None,
            1.0,
        ),
        req(
            "5.2",
            "https://example.test/y",
            "POST",
            json!({"content-type": FORM}),
            Some("x"),
            None,
            2.0,
        ),
    ];
    let b = bundle(
        &events,
        &[
            line(
                "5.1",
                0,
                "request",
                r#"{"city":"São Paulo","q":"diz \"oi\""}"#,
            ),
            line("5.2", 0, "request", "XML=%3Ccmd_abc&x=1"),
        ],
    );
    let r = search(&b, &SearchQuery::new("São Paulo"));
    assert_eq!(r.matches.len(), 1);
    assert!(r.matches[0].decoded);
    assert_eq!(r.matches[0].field.as_deref(), Some("city"));
    assert_eq!(r.matches[0].byte_offset, Some(9));
    let r = search(&b, &SearchQuery::new("diz \"oi\""));
    assert_eq!(r.matches[0].field.as_deref(), Some("q"));
    let mut q = SearchQuery::new("Cmd_Consultar");
    q.scopes = vec![Scope::Url];
    let r = search(&b, &q);
    assert_eq!(r.matches.len(), 1);
    assert!(r.matches[0].decoded);
    // raw still finds the original
    let mut q = SearchQuery::new("Cmd%5F");
    q.scopes = vec![Scope::Url];
    assert!(!search(&b, &q).matches[0].decoded);
    let r = search(&b, &SearchQuery::new("cmd_"));
    let m = r
        .matches
        .iter()
        .find(|m| m.scope == Scope::RequestBody)
        .unwrap();
    assert_eq!(m.field.as_deref(), Some("XML"));
    assert_eq!(m.byte_offset, Some(7), "points to the 'c' of cmd_ in the original");
}

// ---- 6 -------------------------------------------------------------------

#[test]
fn item6_transformed_marks_body_as_not_identical_to_wire() {
    let events = vec![req(
        "6.1",
        "https://example.test/a",
        "POST",
        json!({"content-type": FORM}),
        Some("a=1"),
        None,
        1.0,
    )];
    let mut transformed = line("6.1", 0, "request", "a=1");
    transformed["transformed"] = json!(["chrome-decoded", "charset:iso-8859-1->utf-8"]);
    let b = bundle(&events, &[transformed]);
    let body = &b.session.requests[0].request_body;
    assert_eq!(
        body.transformed,
        vec!["chrome-decoded", "charset:iso-8859-1->utf-8"]
    );
    assert!(body.provenance.verification <= Verification::Partial);
    assert!(body
        .provenance
        .notes
        .iter()
        .any(|n| n.contains("not identical to the wire")));
    let json = serde_json::to_value(body).unwrap();
    assert!(json.get("transformed").is_some());
    // without the field: nothing serialized and verification unchanged
    let plain = bundle(&events, &[line("6.1", 0, "request", "a=1")]);
    let body = &plain.session.requests[0].request_body;
    assert!(body.transformed.is_empty());
    assert!(serde_json::to_value(body)
        .unwrap()
        .get("transformed")
        .is_none());
    assert_eq!(body.provenance.verification, Verification::Unverified);
    // preserved by sanitization
    let s = sanitized(&b);
    assert_eq!(s.session.requests[0].request_body.transformed.len(), 2);
}

// ---- 7 -------------------------------------------------------------------

#[test]
fn item7_bodyless_get_is_empty_with_evidence_not_misleading_message() {
    let events = vec![
        req(
            "7.1",
            "https://example.test/a",
            "GET",
            json!({}),
            None,
            None,
            1.0,
        ),
        req(
            "7.2",
            "https://example.test/b",
            "POST",
            json!({"content-type": FORM}),
            Some("x"),
            None,
            2.0,
        ),
    ];
    let b = bundle(&events, &[line("7.2", 1, "request", "órfão")]);
    let get = &b.session.requests[0].request_body;
    assert_eq!(get.state, BodyState::Empty);
    assert_eq!(get.note.as_deref(), Some("CDP: request without body"));
    // POST with hasPostData and no line stays unavailable, never empty
    let post = &b.session.requests[1].request_body;
    assert_eq!(post.state, BodyState::Unavailable);
    // without a bodies file (apply not called) the old message remains
    let capture = parse_cdp_jsonl(&jsonl(&events)).unwrap();
    let (session, _) = build_cdp_session(&capture);
    assert_eq!(
        session.requests[0].request_body.state,
        BodyState::Unavailable
    );
}

// ---- 8 -------------------------------------------------------------------

#[test]
fn item8_export_flags_307_url_mismatch() {
    let events = vec![
        req(
            "8.1",
            "https://example.test/old",
            "POST",
            json!({"content-type": FORM}),
            Some("a=1"),
            None,
            1.0,
        ),
        req(
            "8.1",
            "https://example.test/new",
            "POST",
            json!({"content-type": FORM}),
            Some("a=1"),
            Some(307),
            1.1,
        ),
        req(
            "8.2",
            "https://example.test/same",
            "GET",
            json!({}),
            None,
            None,
            2.0,
        ),
    ];
    let b = bundle(&events, &[]);
    let r = &b.session.requests[0];
    let options = ExportOptions::default();
    for text in [
        curl::to_curl(r, None, &options).unwrap().text,
        python::to_python(r, None, &options).unwrap().text,
    ] {
        assert!(text.contains("1st attempt"), "{text}");
        assert!(text.contains("https://example.test/new"));
    }
    let plain = curl::to_curl(&b.session.requests[1], None, &options)
        .unwrap()
        .text;
    assert!(!plain.contains("1st attempt"));
}

// ---- 9 -------------------------------------------------------------------

#[test]
fn item9_origin_labels_for_capture_imports() {
    use scrapelens_core::correlate::CorrelationOptions;
    use scrapelens_core::import_capture_labeled;
    let events = jsonl(&[req(
        "9.1",
        "https://example.test/a",
        "GET",
        json!({}),
        None,
        None,
        1.0,
    )]);
    let netlog = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/netlog-h2.json"
    ))
    .unwrap();
    let labels = |extra: &[&str]| {
        let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        import_capture_labeled(
            &events,
            &netlog,
            None,
            &extra,
            CorrelationOptions::default(),
        )
        .unwrap()
        .bundle
        .session
        .session
        .labels
    };
    assert_eq!(labels(&[]), vec!["capture-import"]);
    assert_eq!(labels(&["live-capture"]), vec!["live-capture"]);
    assert_eq!(
        labels(&["synthetic-fixture"]),
        vec!["capture-import", "synthetic-fixture"]
    );
    assert_eq!(
        labels(&["synthetic-fixture", "synthetic-fixture"]),
        vec!["capture-import", "synthetic-fixture"]
    );
}

#[test]
fn item9_cli_label_flag_is_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("s");
    let har = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/har-minimal.json"
    );
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_scrapelens-core"))
        .args(["import-har", har, "--out"])
        .arg(&out)
        .args(["--label", "synthetic-fixture", "--label", "outro"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let session: Value =
        serde_json::from_slice(&std::fs::read(out.join("session.json")).unwrap()).unwrap();
    let labels: Vec<&str> = session["session"]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        labels.contains(&"har-import")
            && labels.contains(&"synthetic-fixture")
            && labels.contains(&"outro"),
        "{labels:?}"
    );
}

// ---- 10 ------------------------------------------------------------------

#[test]
fn item10_match_has_exact_length_and_flags_inexact_mapping() {
    let events = vec![
        req(
            "10.1",
            "https://example.test/a",
            "POST",
            json!({"content-type": FORM}),
            Some("x"),
            None,
            1.0,
        ),
        req(
            "10.2",
            "https://example.test/b",
            "POST",
            json!({"content-type": "application/json"}),
            Some("x"),
            None,
            2.0,
        ),
    ];
    let b = bundle(
        &events,
        &[
            line("10.1", 0, "request", "XML=%3Ccmd_abc&x=1"),
            line("10.2", 0, "request", r#"{"a":"x\ud800cmd_y"}"#),
        ],
    );
    let r = search(&b, &SearchQuery::new("cmd_"));
    let form = r
        .matches
        .iter()
        .find(|m| m.field.as_deref() == Some("XML"))
        .unwrap();
    assert_eq!(
        (form.byte_offset, form.byte_length, form.exact),
        (Some(7), Some(4), true)
    );
    let json_match = r
        .matches
        .iter()
        .find(|m| m.field.as_deref() == Some("a"))
        .unwrap();
    assert!(!json_match.exact);
    assert_eq!(json_match.byte_offset, Some(6));
    assert_eq!(json_match.byte_length, Some(12), "covers the whole value");
}

// ---- finishing touches of round 4 -----------------------------------------------

#[test]
fn a1_export_warns_when_body_is_transformed() {
    let events = vec![req(
        "11.1",
        "https://example.test/a",
        "POST",
        json!({"content-type": FORM}),
        Some("a=1"),
        None,
        1.0,
    )];
    let mut l = line("11.1", 0, "request", "a=1");
    l["transformed"] = json!(["lossy-postData", "chrome-decoded"]);
    let b = bundle(&events, &[l]);
    let r = &b.session.requests[0];
    let bytes = scrapelens_core::export::request_body_bytes(&b, r).unwrap();
    let options = ExportOptions::default();
    let c = curl::to_curl(r, Some(bytes), &options).unwrap();
    let p = python::to_python(r, Some(bytes), &options).unwrap();
    for out in [&c, &p] {
        assert!(
            out.text
                .contains("WARNING: body transformed (lossy-postData, chrome-decoded)"),
            "{}",
            out.text
        );
        assert!(out.text.contains("the bytes may differ from those sent"));
        assert!(out
            .warnings
            .iter()
            .any(|w| w.code == "export.body_transformed"));
    }
    let plain = bundle(&events, &[line("11.1", 0, "request", "a=1")]);
    let r = &plain.session.requests[0];
    let bytes = scrapelens_core::export::request_body_bytes(&plain, r).unwrap();
    assert!(!curl::to_curl(r, Some(bytes), &options)
        .unwrap()
        .text
        .contains("transformed"));
}

#[test]
fn a2_double_percent_encoding_is_redacted() {
    let events = vec![
        req(
            "12.1",
            "https://example.test/a",
            "GET",
            json!({"cookie": "sid=a/b=c+d&e?f"}),
            None,
            None,
            1.0,
        ),
        req(
            "12.2",
            "https://example.test/b",
            "POST",
            json!({"content-type": FORM}),
            Some("x"),
            None,
            2.0,
        ),
    ];
    let b = bundle(
        &events,
        &[line(
            "12.2",
            0,
            "request",
            "dbl=a%252Fb%253Dc%252Bd%2526e%253Ff&low=a%252fb%253dc%252bd%2526e%253ff",
        )],
    );
    let all = everything(&sanitized(&b));
    assert!(!all.contains("%252F") && !all.contains("%252f"), "{all}");
    assert!(!all.contains("%253D") && !all.contains("%253d"), "{all}");
}

#[test]
fn a4_empty_get_provenance_is_honest() {
    let events = vec![req(
        "13.1",
        "https://example.test/a",
        "GET",
        json!({}),
        None,
        None,
        1.0,
    )];
    let b = bundle(&events, &[]);
    let body = &b.session.requests[0].request_body;
    assert_eq!(body.state, BodyState::Empty);
    assert_eq!(body.provenance.method, "requestWillBeSent");
    assert!(body.provenance.notes.iter().any(|n| n.contains("inferred")));
}
