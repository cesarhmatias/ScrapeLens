//! Corpus permanente dos achados das revisões de segurança (rodadas 25 a 30):
//! todos os casos de texto/URL dos PoCs do Revisor (`cases.jsonl`, extraídos dos
//! literais com o marcador de segredo) + casos benignos e de fidelidade
//! (`benign.jsonl`). Regras:
//! - nenhum marcador (`forbid`) sobra na saída, em texto, URL, caminho+query e
//!   em cada portador (header de requisição/resposta, Location, string JSON,
//!   campo de formulário, valor de query);
//! - `same`: a saída é igual à entrada; `keep`: os trechos ficam em todas as
//!   saídas aplicáveis (texto e URL); `idem`: só idempotência;
//! - idempotência: sanitizar duas vezes dá o mesmo que uma.
//!
//! Um commit que faça qualquer caso regredir não entra.

use scrapelens_core::export::sanitize::{
    sanitize_bundle, sanitize_path_and_query, sanitize_text, sanitize_url, sanitize_url_reference,
    SanitizeOptions,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Case {
    kind: String,
    input: String,
    #[serde(default)]
    forbid: Vec<String>,
    #[serde(default)]
    keep: Vec<String>,
    #[serde(default)]
    echo: Vec<String>,
}

fn cases() -> Vec<Case> {
    let mut all = Vec::new();
    for raw in [
        include_str!("corpus/cases.jsonl"),
        include_str!("corpus/benign.jsonl"),
        include_str!("corpus/added.jsonl"),
    ] {
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            all.push(serde_json::from_str::<Case>(line).expect("linha do corpus inválida"));
        }
    }
    all
}

fn is_url(case: &Case) -> bool {
    case.kind == "url"
        || ((case.input.starts_with("http") || case.input.starts_with('/'))
            && !case.input.contains([' ', '\n']))
}

/// Casos que o sanitizador de TEXTO trata (os demais têm mecanismo próprio:
/// JSON, HTML com propagação, Cookie, Set-Cookie).
fn text_level(case: &Case) -> bool {
    matches!(case.kind.as_str(), "text" | "url" | "same" | "keep" | "idem")
}

#[test]
fn corpus_text_and_url_never_leak_keep_fidelity_and_are_idempotent() {
    let o = SanitizeOptions::default();
    let mut failures = Vec::new();
    for case in cases().into_iter().filter(text_level) {
        let mut outputs: Vec<(&str, String, String)> = Vec::new();
        let text = sanitize_text(&case.input, &o);
        outputs.push(("text", text.clone(), sanitize_text(&text, &o)));
        if is_url(&case) {
            let url = sanitize_url(&case.input, &o);
            outputs.push(("url", url.clone(), sanitize_url(&url, &o)));
            if !case.input.contains(":/") && !case.input.starts_with("//") {
                let pq = sanitize_path_and_query(&case.input, &o);
                outputs.push(("pq", pq.clone(), sanitize_path_and_query(&pq, &o)));
            }
            let reference = sanitize_url_reference(&case.input, &o);
            // A6-M2: o texto sobre uma URL já redigida não pode truncá-la nem mudá-la.
            outputs.push(("url→text", reference.clone(), sanitize_text(&reference, &o)));
        }
        for (label, once, twice) in &outputs {
            for marker in &case.forbid {
                if once.contains(marker.as_str()) {
                    failures.push(format!(
                        "[{label}] {marker} sobrou: {:?} -> {once:?}",
                        case.input
                    ));
                }
            }
            if case.kind != "same" && once != twice {
                failures.push(format!(
                    "[{label}] não idempotente: {:?} -> {once:?} -> {twice:?}",
                    case.input
                ));
            }
            if case.kind == "same" && *label == "text" && once != &case.input {
                failures.push(format!(
                    "[{label}] mudou o benigno {:?} -> {once:?}",
                    case.input
                ));
            }
            // `keep`: os trechos ficam em TODA saída aplicável (texto e, se tem forma de
            // URL, também a de URL): o caminho cru não pode perder segmentos.
            if case.kind == "keep" && matches!(*label, "text" | "url") {
                for piece in &case.keep {
                    if !once.contains(piece.as_str()) {
                        failures.push(format!(
                            "[{label}] perdeu {piece:?}: {:?} -> {once:?}",
                            case.input
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} falhas:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn headers(list: &[(String, String)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(n, v)| json!({"name": n, "value": v}))
            .collect(),
    )
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Cada caso do corpus em cada portador de uma sessão importada e sanitizada.
#[test]
fn corpus_cases_in_every_carrier_never_leak() {
    let cases: Vec<Case> = cases()
        .into_iter()
        .filter(|c| text_level(c) && c.kind != "same")
        .collect();
    let mut entries = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let lit = &case.input;
        let req_headers = vec![
            (format!("X-C-{i}"), lit.clone()),
            ("Referer".to_string(), lit.clone()),
        ];
        let resp_headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (format!("X-R-{i}"), lit.clone()),
            ("Location".to_string(), lit.clone()),
            ("Link".to_string(), format!("<{lit}>; rel=next")),
        ];
        let json_body = json!({"v": lit, "list": [lit], "nested": {"k": lit}}).to_string();
        let form = format!("f{i}={}&page=2", percent_encode(lit));
        let url = format!(
            "https://app.corpus.invalid/p{i}?c={}&page=2",
            percent_encode(lit)
        );
        entries.push(json!({
            "startedDateTime": "2026-10-31T20:00:00.000Z", "time": 10.0,
            "request": {"method": "POST", "url": url, "httpVersion": "HTTP/1.1",
                "headers": headers(&req_headers), "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": 0,
                "postData": {"mimeType": "application/x-www-form-urlencoded", "text": form}},
            "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": headers(&resp_headers), "cookies": [], "redirectURL": "",
                "headersSize": -1, "bodySize": 0,
                "content": {"mimeType": "application/json", "size": json_body.len(), "text": json_body}},
            "cache": {}, "timings": {"send": 0, "wait": 5, "receive": 5},
        }));
    }
    let har = json!({"log": {"version": "1.2", "creator": {"name": "corpus", "version": "1"},
        "pages": [], "entries": entries}})
    .to_string();
    let imported = scrapelens_core::import_har(har.as_bytes()).expect("HAR do corpus");
    let options = SanitizeOptions {
        omit_unstructured_bodies: false,
        ..SanitizeOptions::default()
    };
    let sanitized = sanitize_bundle(&imported.bundle, &options);
    let session = serde_json::to_string(&sanitized.bundle.session).unwrap();
    let attachments: String = sanitized
        .bundle
        .attachments
        .values()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect();
    let mut failures = Vec::new();
    for case in &cases {
        for marker in &case.forbid {
            // O marcador só é checado se não é parte do próprio nome do portador.
            if session.contains(marker.as_str()) {
                failures.push(format!("sessão: {marker} (de {:?})", case.input));
            }
            if attachments.contains(marker.as_str()) {
                failures.push(format!("anexos: {marker} (de {:?})", case.input));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} falhas:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn build_session(entries: Vec<Value>) -> (String, String) {
    let har = json!({"log": {"version": "1.2", "creator": {"name": "corpus", "version": "1"},
        "pages": [], "entries": entries}})
    .to_string();
    let imported = scrapelens_core::import_har(har.as_bytes()).expect("HAR do corpus");
    let options = SanitizeOptions {
        omit_unstructured_bodies: false,
        ..SanitizeOptions::default()
    };
    let sanitized = sanitize_bundle(&imported.bundle, &options);
    let session = serde_json::to_string(&sanitized.bundle.session).unwrap();
    let attachments = sanitized
        .bundle
        .attachments
        .values()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect::<String>();
    (session, attachments)
}

fn plain_entry(
    url: &str,
    req_headers: &[(String, String)],
    resp_headers: &[(String, String)],
    mime: &str,
    body: &str,
) -> Value {
    json!({
        "startedDateTime": "2026-10-31T20:00:00.000Z", "time": 10.0,
        "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
            "headers": headers(req_headers), "queryString": [], "cookies": [],
            "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "statusText": "", "httpVersion": "HTTP/1.1",
            "headers": headers(resp_headers), "cookies": [], "redirectURL": "",
            "headersSize": -1, "bodySize": 0,
            "content": {"mimeType": mime, "size": body.len(), "text": body}},
        "cache": {}, "timings": {"send": 0, "wait": 5, "receive": 5},
    })
}

/// Documentos JSON (corpo de resposta), HTML com `<input type=hidden>` cujo valor
/// reaparece num header seguinte, `Cookie` e `Set-Cookie`: cada um pelo seu mecanismo.
#[test]
fn corpus_documents_cookies_and_propagation_never_leak() {
    let all = cases();
    let mut entries = Vec::new();
    let mut checks: Vec<(String, String)> = Vec::new(); // (marcador, origem)
    for (i, case) in all.iter().enumerate() {
        match case.kind.as_str() {
            "json" => {
                entries.push(plain_entry(
                    &format!("https://app.corpus.invalid/doc{i}"),
                    &[],
                    &[("content-type".into(), "application/json".into())],
                    "application/json",
                    &case.input,
                ));
            }
            "html" => {
                entries.push(plain_entry(
                    &format!("https://app.corpus.invalid/form{i}"),
                    &[],
                    &[("content-type".into(), "text/html".into())],
                    "text/html",
                    &case.input,
                ));
                for (j, value) in case.echo.iter().enumerate() {
                    entries.push(plain_entry(
                        &format!("https://app.corpus.invalid/submit{i}-{j}"),
                        &[(format!("X-Echo-{i}-{j}"), value.clone())],
                        &[("content-type".into(), "text/plain".into())],
                        "text/plain",
                        "ok",
                    ));
                }
            }
            "cookie" => {
                entries.push(plain_entry(
                    &format!("https://app.corpus.invalid/cookie{i}"),
                    &[("Cookie".into(), case.input.clone())],
                    &[("content-type".into(), "text/plain".into())],
                    "text/plain",
                    "ok",
                ));
            }
            "setcookie" => {
                entries.push(plain_entry(
                    &format!("https://app.corpus.invalid/setcookie{i}"),
                    &[],
                    &[
                        ("content-type".into(), "text/plain".into()),
                        ("Set-Cookie".into(), case.input.clone()),
                    ],
                    "text/plain",
                    "ok",
                ));
            }
            _ => continue,
        }
        for marker in &case.forbid {
            checks.push((marker.clone(), case.input.chars().take(60).collect()));
        }
    }
    assert!(!entries.is_empty());
    let (session, attachments) = build_session(entries);
    let failures: Vec<String> = checks
        .iter()
        .filter(|(marker, _)| {
            session.contains(marker.as_str()) || attachments.contains(marker.as_str())
        })
        .map(|(marker, origin)| format!("{marker} sobrou (de {origin:?})"))
        .collect();
    assert!(
        failures.is_empty(),
        "{} falhas:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
