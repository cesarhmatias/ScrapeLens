//! Regressão: um segredo marcado na query não pode sobrar em NENHUM campo da
//! sessão sanitizada (startLine, :path, Referer/Location/Origin, redirects,
//! avisos, notas, falhas, alvo, iniciador...). Varre o JSON inteiro.

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
    // Sem '?' ou sem nome sensível: intacto.
    assert_eq!(t("token=ABC sem query"), "token=ABC sem query");
    assert_eq!(t("/p?page=2&q=abc"), "/p?page=2&q=abc");
    assert_eq!(t("HTTP/1.1 200 OK"), "HTTP/1.1 200 OK");
    // Acentos e texto depois do terminador.
    assert_eq!(
        t("não vi ?token=ABC depois"),
        "não vi ?token=%5BREDACTED%5D depois"
    );
}

#[test]
fn marked_secret_in_query_survives_nowhere_in_the_sanitized_session() {
    let har = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/aceite/sanitize/secret.har"),
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
        "o segredo sobrou na sessão sanitizada: {json}"
    );
    // O que não é segredo continua legível.
    assert!(json.contains("/page?token=%5BREDACTED%5D"));
}
