//! Regressão de segurança: um segredo marcado na query não aparece em NENHUMA
//! saída das 14 ferramentas sem `reveal`. Varre toda linha que o servidor
//! escreveu em stdout (e as mensagens de elicitação), não só campos conhecidos.

mod common;

use common::client::{fake_server, Client, Elicit};
use common::*;
use scrapelens_core::model::entities::{Initiator, InitiatorFrame};
use scrapelens_core::model::{
    Body, HeaderEntry, Provenance, SetCookieRecord, Source, TargetKind, TargetProvenance,
    Verification, Warning,
};
use serde_json::{json, Value};

const MARK: &str = "SEGREDO-MARCADO-7";

/// Um marcador único por forma de vazamento (revisão: fragmento, matriz,
/// userinfo, `nome=` sem `?`, nomes de credencial, corpos, parseError...).
const FORMS: [&str; 27] = [
    "MK-FRAG-LOCATION",
    "MK-FRAG-REFRESH",
    "MK-BARE-REFRESH",
    "MK-USERINFO",
    "MK-MATRIX",
    "MK-APIM-HEADER",
    "MK-APPKEY-HEADER",
    "MK-SECRET-HEADER",
    "MK-TOKEN-HEADER",
    "MK-APIKEY-HEADER",
    "MK-LOWER-BEARER",
    "MK-Q-JWT",
    "MK-Q-SENHA",
    "MK-Q-PWD",
    "MK-Q-OTP",
    "MK-Q-PASSCODE",
    "MK-PARSE-ERROR",
    "MK-B-JWT",
    "MK-B-PWD",
    "MK-B-OTP",
    "MK-B-PASSCODE",
    "MK-B-SENHA",
    "MK-F-SENHA",
    "MK-ENC-TOKEN",
    "MK-NESTED-REDIRECT",
    "MK-TAB-BEARER",
    "MK-NESTED-FORM",
];

fn prov() -> Provenance {
    Provenance::new(Source::NetLog, "test", Verification::Verified)
}

/// Sessão nativa com o segredo marcado em todo campo que carrega URL ou alvo.
fn poisoned_session(dir: &std::path::Path) {
    let imported = scrapelens_core::import_har(flow_har("").as_bytes()).unwrap();
    let mut bundle = imported.bundle;
    let q = format!("?token={MARK}");
    let mut bundle_attachments: Vec<(String, Vec<u8>)> = Vec::new();
    let session = &mut bundle.session;
    for (n, request) in session.requests.iter_mut().enumerate() {
        request.url = format!("{}{q}", request.url.split('?').next().unwrap());
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
        for attempt in &mut request.attempts {
            attempt.url = request.url.clone();
            attempt.started_at = Some(100.0 + n as f64);
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
            for view in [&mut attempt.request_headers, &mut attempt.response_headers] {
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
                    ("Location", "/cb#access_token=MK-FRAG-LOCATION".to_string()),
                    (
                        "Refresh",
                        "0; url=/x#access_token=MK-FRAG-REFRESH".to_string(),
                    ),
                    ("Refresh", "5; token=MK-BARE-REFRESH".to_string()),
                    (
                        "X-Original-Url",
                        "https://admin:MK-USERINFO@x.invalid/p".to_string(),
                    ),
                    (
                        "Referer",
                        "https://x.invalid/h;jsessionid=MK-MATRIX?x=1".to_string(),
                    ),
                    ("Ocp-Apim-Subscription-Key", "MK-APIM-HEADER".to_string()),
                    ("X-Vtex-Api-Appkey", "MK-APPKEY-HEADER".to_string()),
                    ("X-Foo-Secret", "MK-SECRET-HEADER".to_string()),
                    ("X-Client-Token", "MK-TOKEN-HEADER".to_string()),
                    ("X-Foo-Api-Key", "MK-APIKEY-HEADER".to_string()),
                    ("Authorization", "bearer MK-LOWER-BEARER".to_string()),
                    ("X-Enc", "/r?a=1&token%3DMK-ENC-TOKEN".to_string()),
                    (
                        "Referer",
                        "https://x.invalid/cb?redirect_uri=https%3A%2F%2Fa.invalid%2Fx%3Ftoken%3DMK-NESTED-REDIRECT"
                            .to_string(),
                    ),
                    ("Proxy-Authorization", "Bearer\tMK-TAB-BEARER".to_string()),
                    (
                        "Link",
                        "<https://x.invalid/n?next=%2Fcb%3Fjwt%3DMK-NESTED-FORM>; rel=next".to_string(),
                    ),
                ] {
                    view.headers.push(HeaderEntry::new(name, value, &prov()));
                }
            }
        }
        let extra =
            "&jwt=MK-Q-JWT&senha=MK-Q-SENHA&pwd=MK-Q-PWD&otp=MK-Q-OTP&passcode=MK-Q-PASSCODE";
        request.url.push_str(extra);
        for attempt in &mut request.attempts {
            attempt.url.push_str(extra);
            let record = SetCookieRecord::from_raw("NAMELESS-MK-PARSE-ERROR; Path=/", &prov());
            attempt.set_cookies.push(record);
        }
        if n == 1 {
            let json_body = br#"{"jwt":"MK-B-JWT","pwd":"MK-B-PWD","otp":"MK-B-OTP","passcode":"MK-B-PASSCODE","senha":"MK-B-SENHA","ok":1}"#;
            let form_body = b"senha=MK-F-SENHA&page=2";
            bundle_attachments.push(("poison-json".to_string(), json_body.to_vec()));
            bundle_attachments.push(("poison-form".to_string(), form_body.to_vec()));
            let json = Body::captured("poison-json", json_body.len() as u64, &prov())
                .with_content_type("application/json");
            let form = Body::captured("poison-form", form_body.len() as u64, &prov())
                .with_content_type("application/x-www-form-urlencoded");
            request.attempts[0].request_body = json.clone();
            request.attempts[0].response_body = form.clone();
            request.request_body = json;
            request.response_body = form;
        }
        request.request_headers = request.attempts[0].request_headers.clone();
        request.response_headers = request.attempts[0].response_headers.clone();
    }
    session.warnings.push(Warning::new(
        "x.aviso",
        format!("falha ao carregar https://x.invalid/w{q}"),
    ));
    for (name, bytes) in bundle_attachments {
        bundle.insert_attachment(name, bytes);
    }
    scrapelens_core::store::write_session_dir(&bundle, dir).unwrap();
}

#[test]
fn marked_query_secret_never_leaves_any_of_the_14_tools() {
    let work = tempfile::tempdir().unwrap();
    let extra = work.path().join("extra");
    poisoned_session(&extra.join("poison"));
    // Uma cópia para importar pela ferramenta (a saída do import também conta).
    let sessions = work.path().join("sessions");
    let mut client = Client::start(
        &fake_server(),
        &[
            "--sessions-dir",
            sessions.to_str().unwrap(),
            "--extra-sessions-dir",
            extra.to_str().unwrap(),
        ],
        Elicit::Accept,
    );
    client.handshake();
    let outputs: std::cell::RefCell<Vec<Value>> = std::cell::RefCell::new(Vec::new());
    let call = |client: &mut Client, name: &str, args: Value| -> Value {
        let (_, out) = client.tool(name, args);
        outputs.borrow_mut().push(out.clone());
        out
    };

    call(&mut client, "list_sessions", json!({}));
    call(
        &mut client,
        "import_session",
        json!({"path": extra.join("poison"), "name": "copia"}),
    );
    for sid in ["poison", "copia"] {
        let list = call(
            &mut client,
            "list_requests",
            json!({"session_id": sid, "text": "fixture"}),
        );
        assert!(list["total"].as_u64().unwrap() >= 1, "{list}");
        for id in ["har-0001", "har-0002", "har-0003"] {
            for verbose in [false, true] {
                call(
                    &mut client,
                    "get_request",
                    json!({"session_id": sid, "request_id": id, "verbose": verbose}),
                );
            }
            call(
                &mut client,
                "get_request",
                json!({"session_id": sid, "request_id": id, "attempt": "0"}),
            );
            for part in ["request", "response"] {
                call(
                    &mut client,
                    "get_body",
                    json!({"session_id": sid, "request_id": id, "part": part}),
                );
            }
            call(
                &mut client,
                "trace_value",
                json!({"session_id": sid, "request_id": id}),
            );
        }
        call(
            &mut client,
            "search_bodies",
            json!({"session_id": sid, "query": "page"}),
        );
        call(
            &mut client,
            "search_bodies",
            json!({"session_id": sid, "query": "token"}),
        );
        call(
            &mut client,
            "search_bodies",
            json!({"session_id": sid, "query": MARK}),
        );
        call(
            &mut client,
            "diff_requests",
            json!({"session_id": sid, "request_a": "har-0001", "request_b": "har-0002"}),
        );
        call(
            &mut client,
            "diff_sessions",
            json!({"session_id_a": sid, "session_id_b": "poison"}),
        );
        call(
            &mut client,
            "trace_value",
            json!({"session_id": sid, "cookie": "sid"}),
        );
        call(&mut client, "site_profile", json!({"session_id": sid}));
    }

    // Ferramentas de captura (navegador falso): navigate com o segredo na query.
    let (_, started) = client.tool(
        "start_capture",
        json!({"allowed_hosts": ["site.invalid.test"], "start_url": format!("http://site.invalid.test/?token={MARK}")}),
    );
    outputs.borrow_mut().push(started.clone());
    let id = started["captureId"].as_str().unwrap().to_string();
    call(
        &mut client,
        "navigate",
        json!({"capture_id": id, "url": format!("http://site.invalid.test/page2?token={MARK}")}),
    );
    call(&mut client, "capture_status", json!({"capture_id": id}));
    let stopped = call(&mut client, "stop_capture", json!({"capture_id": id}));
    call(
        &mut client,
        "site_profile",
        json!({"session_id": stopped["sessionId"]}),
    );

    // Todas as 14 ferramentas foram exercitadas.
    let (_, tools) = (0, client.request("tools/list", json!({})));
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 14);

    // Varre o JSON inteiro de cada saída, as linhas brutas do stdout e as elicitações.
    let all_marks: Vec<&str> = std::iter::once(MARK).chain(FORMS).collect();
    for mark in &all_marks {
        for output in outputs.borrow().iter() {
            assert!(
                !output.to_string().contains(mark),
                "{mark} vazou em: {output}"
            );
        }
        for line in &client.seen {
            assert!(!line.contains(mark), "{mark} vazou no stdout: {line}");
        }
        for message in &client.elicitations {
            assert!(
                !message.contains(mark),
                "{mark} vazou na elicitação: {message}"
            );
        }
    }
    // A sessão original continua intacta (o segredo existe nela): sem reveal ele não sai.
    let original = std::fs::read_to_string(extra.join("poison/session.json")).unwrap();
    assert!(
        original.contains(MARK),
        "a sessão de teste precisa conter o segredo"
    );
    let (ok, stderr) = client.finish();
    assert!(ok, "{stderr}");
}
