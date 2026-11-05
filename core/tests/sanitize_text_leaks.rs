//! Regression: a marked secret in the query must not survive in ANY field of the
//! sanitized session (startLine, :path, Referer/Location/Origin, redirects,
//! warnings, notes, failures, target, initiator...). Scans the whole JSON.

use scrapelens_core::export::sanitize::{sanitize_bundle, sanitize_text, SanitizeOptions};
use scrapelens_core::model::entities::{Initiator, InitiatorFrame};
use scrapelens_core::model::{
    HeaderEntry, Provenance, Source, TargetKind, TargetProvenance, Verification, Warning,
};

const MARK: &str = "SEGREDO-MARCADO-7";

fn prov() -> Provenance {
    Provenance::new(Source::NetLog, "test", Verification::Verified)
}

#[test]
fn sanitize_text_masks_only_sensitive_query_params() {
    let o = SanitizeOptions::default();
    let t = |s: &str| sanitize_text(s, &o);
    assert_eq!(
        t("GET /p?token=ABC&page=2 HTTP/1.1"),
        "GET /p?token=%5BREDACTED%5D&page=2 HTTP/1.1"
    );
    assert_eq!(
        t("0; url=/x?a=1&access_token=ZZZ"),
        "0; url=/x?a=1&access_token=%5BREDACTED%5D"
    );
    assert_eq!(
        t("report-uri /r?api_key=K1;"),
        "report-uri /r?api_key=%5BREDACTED%5D;"
    );
    assert_eq!(
        t("\"https://a.test/p?token=ABC\" falhou"),
        "\"https://a.test/p?token=%5BREDACTED%5D\" falhou"
    );
    // Without '?': a sensitive `name=value` is also redacted; a non-sensitive name is not.
    assert_eq!(t("token=ABC sem query"), "token=%5BREDACTED%5D sem query");
    assert_eq!(t("max-age=60; code_x=1"), "max-age=60; code_x=1");
    assert_eq!(t("/p?page=2&q=abc"), "/p?page=2&q=abc");
    assert_eq!(t("HTTP/1.1 200 OK"), "HTTP/1.1 200 OK");
    // Accents and text after the terminator.
    assert_eq!(
        t("não vi ?token=ABC depois"),
        "não vi ?token=%5BREDACTED%5D depois"
    );
}

#[test]
fn marked_secret_in_query_survives_nowhere_in_the_sanitized_session() {
    let har = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/acceptance/sanitize/secret.har"),
    )
    .unwrap();
    let mut imported = scrapelens_core::import_har(&har).unwrap();
    let q = format!("?token={MARK}");
    let session = &mut imported.bundle.session;
    {
        let request = &mut session.requests[0];
        request.url = format!("https://x.invalid/page{q}");
        request
            .provenance
            .notes
            .push(format!("visto em https://x.invalid/a{q}"));
        request.target = Some(TargetProvenance {
            target_id: Some("T1".into()),
            kind: TargetKind::Page,
            url: Some(format!("https://x.invalid/p{q}")),
            ..TargetProvenance::default()
        });
        let attempt = &mut request.attempts[0];
        attempt.url = request.url.clone();
        attempt.failure = Some(format!("net::ERR_FAILED em https://x.invalid/f{q}"));
        attempt.initiator = Some(Initiator {
            kind: "script".into(),
            url: Some(format!("https://x.invalid/a.js{q}")),
            line_number: None,
            stack_top: Some(InitiatorFrame {
                url: Some(format!("https://x.invalid/b.js{q}")),
                function: None,
                line_number: None,
            }),
        });
        for view in [
            &mut attempt.request_headers,
            &mut attempt.response_headers,
            &mut request.request_headers,
        ] {
            view.start_line = Some(format!("GET /page{q} HTTP/1.1"));
            view.raw_block = Some(format!("GET /page{q} HTTP/1.1\n"));
            view.notes.push(format!("linha /page{q}"));
            view.pseudo_headers
                .push(HeaderEntry::new(":path", format!("/page{q}"), &prov()));
            for (name, value) in [
                ("Referer", format!("https://x.invalid/r{q}")),
                ("Location", format!("/next{q}")),
                ("Origin", format!("https://x.invalid{q}")),
                ("Refresh", format!("0; url=/go{q}")),
                ("Refresh", format!("0; url=/go#access_token={MARK}")),
                ("Location", format!("/cb#access_token={MARK}")),
                ("Refresh", format!("5; token={MARK}")),
                (
                    "X-Original-Url",
                    format!("https://admin:{MARK}@x.invalid/p"),
                ),
                (
                    "Referer",
                    format!("https://x.invalid/h;jsessionid={MARK}?x=1"),
                ),
                ("Ocp-Apim-Subscription-Key", MARK.to_string()),
                ("X-Vtex-Api-Appkey", MARK.to_string()),
                ("Authorization", format!("bearer {MARK}")),
                ("X-Other", format!("ApiKey {MARK}")),
                ("X-Original-Url", format!("/orig{q}")),
                (
                    "Content-Security-Policy",
                    format!("default-src 'self'; report-uri /csp{q}"),
                ),
            ] {
                view.headers.push(HeaderEntry::new(name, value, &prov()));
            }
        }
    }
    session.warnings.push(
        Warning::new(
            "x.aviso",
            format!("falha ao carregar https://x.invalid/w{q}"),
        )
        .with_detail(serde_json::json!({"url": format!("/d{q}")})),
    );
    session.session.notes.push("nota".into());

    let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let json = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(
        !json.contains(MARK),
        "the secret survived in the sanitized session: {json}"
    );
    // What is not a secret stays readable.
    assert!(json.contains("/page?token=%5BREDACTED%5D"));
}

#[test]
fn every_url_form_is_redacted_in_text_and_in_references() {
    use scrapelens_core::export::sanitize::{sanitize_url, sanitize_url_reference};
    let o = SanitizeOptions::default();
    let t = |s: &str| sanitize_text(s, &o);
    let r = |s: &str| sanitize_url_reference(s, &o);
    // fragment
    assert!(!r("/cb#access_token=ZZ1").contains("ZZ1"));
    assert!(!r("https://a.test/cb#access_token=ZZ2").contains("ZZ2"));
    assert!(!t("0; url=/x#access_token=ZZ3").contains("ZZ3"));
    // matrix parameter
    assert!(!r("/home;jsessionid=ZZ4?x=1").contains("ZZ4"));
    assert!(!sanitize_url("https://a.test/a;jsessionid=ZZ5/b?x=1", &o).contains("ZZ5"));
    assert!(
        r("/home;jsessionid=ZZ4?x=1").ends_with("?x=1"),
        "the rest of the URL stays"
    );
    // userinfo in free text
    let u = t("X-Original-Url: https://admin:ZZ6@host.test/p");
    assert!(!u.contains("ZZ6") && u.contains("@host.test/p"), "{u}");
    // `name=` without `?`, `%3D` and varied separators
    assert!(!t("Refresh: 0; token=ZZ7").contains("ZZ7"));
    assert!(!t("/cb?x=1&token%3DZZ8").contains("ZZ8"));
    assert!(!t("u=a,access_token=ZZ9,b=2").contains("ZZ9"));
    // credential names
    for name in [
        "jwt",
        "senha",
        "pwd",
        "otp",
        "passcode",
        "pin",
        "auth_key",
        "ticket",
        "SAMLResponse",
        "x-api-key",
        "client_secret",
        "csrf_token",
        "Ocp-Apim-Subscription-Key",
        "X-VTEX-API-AppKey",
        "minha-senha",
        "user_pwd",
    ] {
        let out = t(&format!("a=1&{name}=ZZVALOR"));
        assert!(!out.contains("ZZVALOR"), "{name}: {out}");
    }
}

#[test]
fn credential_header_names_and_schemes_are_redacted() {
    use scrapelens_core::export::sanitize::is_sensitive_header;
    for name in [
        "Ocp-Apim-Subscription-Key",
        "X-VTEX-API-AppKey",
        "X-Foo-Api-Key",
        "X-Client-Secret",
        "X-Csrf-Token",
        "X-Senha",
        "X-Passcode",
        "X-Jwt",
    ] {
        assert!(is_sensitive_header(name), "{name}");
    }
    assert!(!is_sensitive_header("Accept"));
    assert!(!is_sensitive_header(":authority"));
}

#[test]
fn set_cookie_parse_error_does_not_carry_the_raw_value() {
    let har = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/acceptance/sanitize/secret.har"),
    )
    .unwrap();
    let mut imported = scrapelens_core::import_har(&har).unwrap();
    let record = scrapelens_core::model::SetCookieRecord::from_raw("NAMELESSZZ10; Path=/", &prov());
    assert!(
        record
            .parse_error
            .as_deref()
            .unwrap_or("")
            .contains("NAMELESSZZ10"),
        "precondition"
    );
    imported.bundle.session.requests[0].attempts[0]
        .set_cookies
        .push(record.clone());
    imported.bundle.session.requests[0].set_cookies.push(record);
    let export = sanitize_bundle(&imported.bundle, &SanitizeOptions::default());
    let json = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(!json.contains("NAMELESSZZ10"), "{json}");
}
