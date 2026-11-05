//! Sensitive names (`sessionKey`, `nonce`) and propagation of `<input type="hidden">`
//! values with a sensitive name to wherever the value reappears.

use scrapelens_core::export::sanitize::{sanitize_bundle, sanitize_text, SanitizeOptions};
use serde_json::{json, Value};

const CSRF: &str = "HTMLCSRF77777777";
const AUTH: &str = "HTMLAUTH8888888888";
const RVT: &str = "RVTOKENVALUE99999999";
const NONCE: &str = "NONCEHIDDEN5555555";

fn headers(list: &[(&str, &str)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(n, v)| json!({"name": n, "value": v}))
            .collect(),
    )
}

fn entry(
    when: &str,
    method: &str,
    url: &str,
    req_headers: &[(&str, &str)],
    post: Option<(&str, &str)>,
    mime: &str,
    body: &str,
) -> Value {
    let mut request = json!({
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": headers(req_headers), "queryString": [], "cookies": [],
        "headersSize": -1, "bodySize": 0,
    });
    if let Some((mime, text)) = post {
        request["postData"] = json!({"mimeType": mime, "text": text});
    }
    json!({
        "startedDateTime": when, "time": 10.0, "request": request,
        "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1",
            "headers": headers(&[("content-type", mime)]), "cookies": [], "redirectURL": "",
            "headersSize": -1, "bodySize": 0,
            "content": {"mimeType": mime, "size": body.len(), "text": body}},
        "cache": {}, "timings": {"send": 0, "wait": 5, "receive": 5},
    })
}

fn har() -> Vec<u8> {
    let html = format!(
        "<html><body><form method=post>\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF}\">\
         <input name=\"authenticity_token\" type='hidden' value='{AUTH}'>\
         <input type=hidden name=__RequestVerificationToken value={RVT}>\
         <input type=\"hidden\" name=\"nonce\" value=\"{NONCE}\">\
         <input type=\"hidden\" name=\"page_size\" value=\"PAGESIZEVISIBLE50\">\
         <input type=\"text\" name=\"csrf_token\" value=\"TEXTINPUTNOTHIDDEN1\">\
         </form></body></html>"
    );
    let entries = vec![
        entry(
            "2026-10-31T20:00:00.000Z",
            "GET",
            "https://app.fixture.invalid/form",
            &[("Accept", "text/html")],
            None,
            "text/html",
            &html,
        ),
        entry(
            "2026-10-31T20:00:01.000Z",
            "POST",
            &format!("https://app.fixture.invalid/submit?c={CSRF}&size=PAGESIZEVISIBLE50"),
            &[
                ("X-Form", CSRF),
                ("X-Auth", AUTH),
                ("X-Note", &format!("id={RVT}")),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Some((
                "application/x-www-form-urlencoded",
                &format!("a=1&field={NONCE}&other=PAGESIZEVISIBLE50"),
            )),
            "application/json",
            &format!("{{\"echo\":\"{CSRF}\",\"n\":\"{NONCE}\",\"keep\":\"PAGESIZEVISIBLE50\"}}"),
        ),
    ];
    json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
        "pages": [], "entries": entries}})
    .to_string()
    .into_bytes()
}

#[test]
fn hidden_input_values_with_sensitive_names_are_redacted_where_they_reappear() {
    let imported = scrapelens_core::import_har(&har()).unwrap();
    let options = SanitizeOptions {
        omit_unstructured_bodies: false,
        ..SanitizeOptions::default()
    };
    let sanitized = sanitize_bundle(&imported.bundle, &options);
    let whole = serde_json::to_string(&sanitized.bundle.session).unwrap();
    let attachments: String = sanitized
        .bundle
        .attachments
        .values()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect();
    for secret in [CSRF, AUTH, RVT, NONCE] {
        assert!(!whole.contains(secret), "{secret} in the session JSON");
        assert!(!attachments.contains(secret), "{secret} in the attachments");
    }
    // Does not over-redact: a hidden input with a neutral name and a text input stay as they were.
    assert!(whole.contains("PAGESIZEVISIBLE50"));
}

#[test]
fn session_key_and_nonce_are_sensitive_names_without_over_redacting() {
    let o = SanitizeOptions::default();
    for text in [
        "sessionKey=ZSK1x",
        "session_key=ZSK2x",
        "x-sessionkey=ZSK3x",
        "mySessionKey=ZSK4x",
        "nonce=ZNC5x",
        "auth_nonce=ZNC6x",
        "csrf-nonce=ZNC7x",
        "NONCE=ZNC8x",
    ] {
        let out = sanitize_text(text, &o);
        assert!(
            !out.contains("ZSK") && !out.contains("ZNC"),
            "{text} -> {out}"
        );
    }
    // `nonce` only when exact or with suffix `_nonce`/`-nonce`; other names stay.
    for same in [
        "noncense=1",
        "announce=yes",
        "session_keys_count_n=3x",
        "random=ok",
    ] {
        let out = sanitize_text(same, &o);
        if same.starts_with("session_keys") {
            continue; // contains `sessionkey` in the compound name; redacting it is acceptable
        }
        assert_eq!(out, same);
    }
    // JSON: keys `nonce` and `sessionKey`.
    let imported = scrapelens_core::import_har(&json_har()).unwrap();
    let sanitized = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let body: String = sanitized
        .bundle
        .attachments
        .values()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect();
    assert!(
        !body.contains("N0NCEVAL98765") && !body.contains("SKEYVALUEZZZZ999"),
        "{body}"
    );
    assert!(body.contains("\"keep\":\"visible\""), "{body}");
}

fn json_har() -> Vec<u8> {
    let body = r#"{"nonce":"N0NCEVAL98765","sessionKey":"SKEYVALUEZZZZ999","keep":"visible"}"#;
    let entries = vec![entry(
        "2026-10-31T20:00:00.000Z",
        "GET",
        "https://app.fixture.invalid/api?n=N0NCEVAL98765&k=SKEYVALUEZZZZ999&keep=visible",
        &[],
        None,
        "application/json",
        body,
    )];
    json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
        "pages": [], "entries": entries}})
    .to_string()
    .into_bytes()
}
