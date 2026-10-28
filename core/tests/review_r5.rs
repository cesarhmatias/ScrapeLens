//! Regressões da revisão independente da Rodada 5 (docs/09 → "Revisão da rodada 5"),
//! com os cenários do revisor (T1–T9, t4, injeção).

use scrapelens_core::compare::{compare_sessions, CompareOptions};
use scrapelens_core::export::curl::to_curl_with_origins;
use scrapelens_core::export::python::to_python_with_origins;
use scrapelens_core::export::{comment, request_body_bytes, ExportOptions};
use scrapelens_core::flow::{
    priming_chain, value_origins, Confidence, EvidenceKind, FlowOptions, OriginStatus, Role,
    StepClass, Strength, Timing, ValueOrigin, ValueOrigins,
};
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use serde_json::{json, Value};

const FORM: &str = "application/x-www-form-urlencoded";

#[derive(Default)]
struct S {
    ev: Vec<Value>,
    bd: Vec<Value>,
}

#[derive(Default)]
struct R<'a> {
    headers: Option<Value>,
    body: Option<&'a str>,
    resp: Option<&'a str>,
    resp_headers: Option<Value>,
    dur: Option<f64>,
    rct: Option<&'a str>,
}

impl S {
    fn req(&mut self, id: &str, t: f64, url: &str, method: &str, r: R) {
        let mut h = r.headers.unwrap_or(json!({}));
        if r.body.is_some() {
            h["content-type"] = json!(FORM);
        }
        self.ev.push(json!({"method": "Network.requestWillBeSent", "params": {
            "requestId": id, "loaderId": "L", "timestamp": t, "wallTime": 1793000000.0 + t,
            "request": {"url": url, "method": method, "headers": h, "hasPostData": r.body.is_some()},
            "type": "XHR", "frameId": "F"}}));
        if let Some(body) = r.body {
            self.bd.push(line(id, "request", body, t));
        }
        let dur = r.dur.unwrap_or(0.05);
        let mut rh = r.resp_headers.unwrap_or(json!({}));
        rh["content-type"] = json!(r.rct.unwrap_or("text/html"));
        self.ev.push(json!({"method": "Network.responseReceived", "params": {
            "requestId": id, "loaderId": "L", "timestamp": t + dur / 2.0, "type": "XHR",
            "response": {"url": url, "status": 200, "statusText": "", "headers": rh, "protocol": "http/1.1"}}}));
        self.ev.push(json!({"method": "Network.loadingFinished", "params": {"requestId": id, "timestamp": t + dur, "encodedDataLength": 1}}));
        if let Some(resp) = r.resp {
            self.bd.push(line(id, "response", resp, t + dur));
        }
    }

    fn build(&self) -> SessionBundle {
        let jl = |v: &[Value]| {
            v.iter()
                .map(|x| format!("{x}\n"))
                .collect::<String>()
                .into_bytes()
        };
        let capture = parse_cdp_jsonl(&jl(&self.ev)).unwrap();
        let (mut session, _) = build_cdp_session(&capture);
        let mut attachments = Default::default();
        apply_cdp_bodies(&mut session, &mut attachments, &jl(&self.bd));
        let mut b = SessionBundle::new(session);
        b.attachments = attachments;
        b
    }
}

fn line(id: &str, kind: &str, data: &str, ts: f64) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":0,"kind":kind,"state":"captured","encoding":"utf8",
        "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":ts})
}

fn lid(b: &SessionBundle, cdp: &str) -> String {
    b.session
        .requests
        .iter()
        .find(|r| r.cdp.as_ref().and_then(|c| c.request_id.as_deref()) == Some(cdp))
        .unwrap()
        .id
        .clone()
}

fn origins(b: &SessionBundle, cdp: &str) -> ValueOrigins {
    value_origins(&b.session, b, &lid(b, cdp), &FlowOptions::default()).unwrap()
}

fn entry<'a>(o: &'a ValueOrigins, field: &str) -> &'a ValueOrigin {
    o.values
        .iter()
        .find(|v| v.field == field && v.parent.is_none())
        .unwrap_or_else(|| panic!("{field} ausente"))
}

// ---- 1: injeção em comentários ---------------------------------------------------------

fn injection_bundle(tmp: &str) -> SessionBundle {
    let name = format!("x\ntouch {tmp}/PWNED_CURL #\r\u{2028}import os;os.system(1)#'\"\u{2029}");
    let enc: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("<p>var v = \"INJECTVAL123456\";</p>"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/b",
        "POST",
        R {
            body: Some(&format!("{enc}=INJECTVAL123456&ok=1")),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    s.build()
}

#[test]
fn comment_helper_never_emits_a_non_comment_line() {
    let text = "a\nb\rc\u{2028}d\u{2029}e\u{b}f\u{c}g\u{85}h\u{202e}i\0j\u{1b}[31mk";
    let out = comment(text);
    assert!(
        out.lines().all(|l| l.starts_with("# ") || l == "#"),
        "{out:?}"
    );
    assert!(
        !out.contains('\r')
            && !out.contains('\u{2028}')
            && !out.contains('\u{202e}')
            && !out.contains('\0')
    );
    assert!(out.lines().count() <= 8);
    assert!(comment(&"x".repeat(10_000)).chars().count() < 300);
    assert_eq!(comment(""), "#\n");
}

#[test]
fn injected_field_names_stay_inside_comments_in_curl_and_python() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path().to_str().unwrap().to_string();
    let b = injection_bundle(&tmp);
    let id = lid(&b, "1.2");
    let request = b.session.find_request(&id).unwrap();
    let o = value_origins(&b.session, &b, &id, &FlowOptions::default()).unwrap();
    assert!(
        o.values.iter().any(|v| v.field.contains("touch")),
        "o nome malicioso chega às anotações"
    );
    let bytes = request_body_bytes(&b, request);
    let opts = ExportOptions::default();
    let curl = to_curl_with_origins(request, bytes, &opts, Some(&o))
        .unwrap()
        .text;
    let py = to_python_with_origins(request, bytes, &opts, Some(&o))
        .unwrap()
        .text;

    // cURL: tudo antes de `curl \` é comentário; nada executável fora do comando
    let head: Vec<&str> = curl.lines().take_while(|l| *l != "curl \\").collect();
    assert!(head.iter().all(|l| l.starts_with('#')), "{head:?}");
    assert!(
        curl.lines()
            .skip(head.len())
            .all(|l| l == "curl \\" || l.starts_with("  --")),
        "{curl}"
    );
    // Python: tudo antes de `import http.client` é comentário/vazio
    let head: Vec<&str> = py
        .lines()
        .take_while(|l| *l != "import http.client")
        .collect();
    assert!(
        head.iter().all(|l| l.is_empty() || l.starts_with('#')),
        "{head:?}"
    );
    assert!(!py.contains('\u{2028}') && !curl.contains('\u{2028}'));

    // prova: com curl trocado por `true`, o script não cria nada
    let script = dir.path().join("export.sh");
    std::fs::write(&script, &curl).unwrap();
    let before: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let status = std::process::Command::new("bash")
        .current_dir(dir.path())
        .arg("-c")
        .arg(format!("curl() {{ true; }}; . '{}'", script.display()))
        .status()
        .unwrap();
    assert!(status.success());
    let after: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after, "o script gerado criou arquivos");
    assert!(!dir.path().join("PWNED_CURL").exists());

    // Python: o AST só tem as chamadas esperadas (http.client), nada de os/system
    let ast = std::process::Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg("import ast,sys; t=ast.parse(open(sys.argv[1]).read()); names={n.id for n in ast.walk(t) if isinstance(n,ast.Name)}|{n.attr for n in ast.walk(t) if isinstance(n,ast.Attribute)}; print(sorted(names))")
        .arg({
            let p = dir.path().join("export.py");
            std::fs::write(&p, &py).unwrap();
            p
        })
        .output()
        .unwrap();
    let names = String::from_utf8_lossy(&ast.stdout);
    assert!(
        ast.status.success(),
        "{}",
        String::from_utf8_lossy(&ast.stderr)
    );
    assert!(
        !names.contains("system") && !names.contains("'os'"),
        "{names}"
    );
}

// ---- 2: causalidade temporal ---------------------------------------------------------

#[test]
fn response_finishing_after_the_target_starts_is_not_a_producer() {
    // T4: /slow inicia 1,0 e responde só em 11,0; /use inicia 2,0
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/slow",
        "GET",
        R {
            resp: Some("{\"sessId\":\"LATE1234LATE5678\"}"),
            rct: Some("application/json"),
            dur: Some(10.0),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "POST",
        R {
            body: Some("sessId=LATE1234LATE5678&q=1"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    assert_eq!(entry(&o, "sessId").status, OriginStatus::None);
    // T5: cookie de resposta lenta
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/slow",
        "GET",
        R {
            resp: Some("x"),
            resp_headers: Some(json!({"set-cookie": "sess=COOKIEVALUE12345; Path=/"})),
            dur: Some(10.0),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "GET",
        R {
            headers: Some(json!({"cookie": "sess=COOKIEVALUE12345"})),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    assert_eq!(
        entry(&origins(&b, "1.2"), "sess").status,
        OriginStatus::None
    );
    // resposta que termina antes do início do alvo continua valendo, com tempo observado
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/fast",
        "GET",
        R {
            resp: Some("x"),
            resp_headers: Some(json!({"set-cookie": "sess=COOKIEVALUE12345; Path=/"})),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "GET",
        R {
            headers: Some(json!({"cookie": "sess=COOKIEVALUE12345"})),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    assert_eq!(entry(&o, "sess").status, OriginStatus::Origin);
    assert_eq!(entry(&o, "sess").evidences[0].timing, Timing::Observed);
}

#[test]
fn missing_times_fall_back_to_session_order_and_are_marked_inferred() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("x"),
            resp_headers: Some(json!({"set-cookie": "sess=COOKIEVALUE12345; Path=/"})),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "GET",
        R {
            headers: Some(json!({"cookie": "sess=COOKIEVALUE12345"})),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let mut b = s.build();
    for r in &mut b.session.requests {
        for a in &mut r.attempts {
            a.ended_at = None;
        }
    }
    let o = origins(&b, "1.2");
    assert_eq!(entry(&o, "sess").evidences[0].timing, Timing::Inferred);
}

// ---- 3: reissued ---------------------------------------------------------------------

#[test]
fn reissued_only_when_the_value_circulated_between_producers() {
    let page = "<script>var cfg={\"sessId\":\"ABCDEFGH12345678\"}</script>";
    let f = Some(FORM);
    let _ = f;
    // T1: dois produtores concorrentes, sem uso entre eles → ambiguous
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some(page),
            dur: Some(0.5),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        1.1,
        "http://h.test/b",
        "GET",
        R {
            resp: Some(page),
            dur: Some(0.5),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        2.0,
        "http://h.test/use",
        "POST",
        R {
            body: Some("sessId=ABCDEFGH12345678&x=1"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.3");
    assert_eq!(entry(&o, "sessId").status, OriginStatus::Ambiguous);
    // T3: dois produtores em tempos diferentes, sem uso entre eles → ambiguous
    let tok = "{\"token\":\"ZZZZZZZZ99999999\"}";
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some(tok),
            rct: Some("application/json"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/b",
        "GET",
        R {
            resp: Some(tok),
            rct: Some("application/json"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "http://h.test/use",
        "POST",
        R {
            body: Some("token=ZZZZZZZZ99999999"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.3");
    assert_eq!(entry(&o, "token").status, OriginStatus::Ambiguous);
    // T2: com uso entre eles, o segundo só reemite
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some(page),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use1",
        "POST",
        R {
            body: Some("sessId=ABCDEFGH12345678"),
            resp: Some("<p>x</p>"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "http://h.test/b",
        "GET",
        R {
            resp: Some(page),
            ..Default::default()
        },
    );
    s.req(
        "1.4",
        4.0,
        "http://h.test/use2",
        "POST",
        R {
            body: Some("sessId=ABCDEFGH12345678"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.4");
    let v = entry(&o, "sessId");
    assert_eq!(v.status, OriginStatus::Origin);
    assert!(v.evidences.iter().any(|e| e.role == Role::Reissued));
}

// ---- 4 e 5: força da evidência e rótulo ------------------------------------------------

#[test]
fn generic_names_and_short_values_are_only_possible_origins() {
    // T6
    let mut s = S::default();
    s.req("1.1", 1.0, "http://h.test/list", "GET", R { resp: Some("{\"id\":\"7\",\"value\":\"3\",\"data\":\"12\",\"page\":\"2\",\"type\":\"a\",\"lang\":\"pt\",\"cliente\":\"AB\"}"), rct: Some("application/json"), ..Default::default() });
    s.req(
        "1.3",
        2.0,
        "http://h.test/save",
        "POST",
        R {
            body: Some("id=7&value=3&data=12&page=2&type=a&lang=pt&cliente=AB&placa=ABC1D23"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.3");
    for field in ["id", "value", "data", "page", "type", "lang", "cliente"] {
        let v = entry(&o, field);
        assert_eq!(v.confidence, Some(Confidence::Possible), "{field}");
        assert!(
            v.evidences.iter().all(|e| e.strength == Strength::Medium),
            "{field}"
        );
        assert!(
            v.label.starts_with("possível origem (same-field)"),
            "{field}: {}",
            v.label
        );
        assert_ne!(v.label, "origem observada");
    }
    assert_eq!(entry(&o, "placa").status, OriginStatus::None);
    // nome não genérico e valor >= 4: forte
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("{\"sessionToken\":\"abcd\"}"),
            rct: Some("application/json"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/b",
        "POST",
        R {
            body: Some("sessionToken=abcd"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.2");
    let v = entry(&o, "sessionToken");
    assert_eq!(
        (v.status, v.confidence),
        (OriginStatus::Origin, Some(Confidence::Strong))
    );
    assert_eq!(v.label, "origem observada");
    assert_eq!(v.evidences[0].kind, EvidenceKind::SameField);
}

#[test]
fn value_match_only_is_a_possible_origin_and_the_chain_marks_the_step_possible() {
    // T7: coincidências (UA, build, timestamp) casadas só por conteúdo. O produtor é
    // uma página (um .js estático viraria `context`, L3 da rodada 6).
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/page.html",
        "GET",
        R {
            resp: Some(&format!(
                "var UA=\"{ua}\"; var build=\"v20261027-abcdef12\";"
            )),
            rct: Some("text/html"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/send",
        "POST",
        R {
            body: Some("build=v20261027-abcdef12&placa=ABC1D23"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    let v = entry(&o, "build");
    assert_eq!(v.confidence, Some(Confidence::Possible));
    assert_eq!(v.label, "possível origem (value-match)");
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.2"), &FlowOptions::default()).unwrap();
    assert_eq!(chain.steps.len(), 1);
    assert_eq!(chain.steps[0].confidence, Confidence::Possible);
    // com evidência forte o passo é strong
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("x"),
            resp_headers: Some(json!({"set-cookie": "sess=COOKIEVALUE12345; Path=/"})),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "GET",
        R {
            headers: Some(json!({"cookie": "sess=COOKIEVALUE12345"})),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.2"), &FlowOptions::default()).unwrap();
    assert_eq!(chain.steps[0].confidence, Confidence::Strong);
}

// ---- 6 ----------------------------------------------------------------------------------

#[test]
fn a_field_is_not_duplicated_as_entry_and_as_part() {
    // T3/T4: valor inteiro com origem não gera também trechos
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("{\"token\":\"ZZZZZZZZ99999999\"}"),
            rct: Some("application/json"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/use",
        "POST",
        R {
            body: Some("token=ZZZZZZZZ99999999"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.2");
    let same: Vec<_> = o.values.iter().filter(|v| v.field == "token").collect();
    assert_eq!(
        same.len(),
        1,
        "{:?}",
        same.iter().map(|v| &v.label).collect::<Vec<_>>()
    );
    assert!(same[0].parent.is_none());
}

#[test]
fn unresolved_ignores_values_consumed_only_by_protection_steps() {
    // T9
    let mut s = S::default();
    s.req(
        "1.0",
        0.5,
        "http://h.test/entry",
        "GET",
        R {
            resp: Some("<html>"),
            resp_headers: Some(json!({"set-cookie": "JSESSIONID=JSESSVALUE0001ABCD; Path=/"})),
            ..Default::default()
        },
    );
    s.req("1.1", 1.0, "http://h.test/TSPD/?type=18", "GET", R { headers: Some(json!({"cookie": "JSESSIONID=JSESSVALUE0001ABCD", "x-prot-nonce": "NONCEVALUE0000AA"})), resp: Some("js"), resp_headers: Some(json!({"set-cookie": "TS01a1b2c3=TSVALUE0123456789AB; Path=/"})), ..Default::default() });
    s.req(
        "1.2",
        2.0,
        "http://h.test/app/page",
        "GET",
        R {
            headers: Some(
                json!({"cookie": "JSESSIONID=JSESSVALUE0001ABCD; TS01a1b2c3=TSVALUE0123456789AB"}),
            ),
            resp: Some("<script>var m_currentSessionId=\"SIDVALUE00112233\";</script>"),
            ..Default::default()
        },
    );
    s.req(
        "1.4",
        4.0,
        "http://h.test/app/connector",
        "POST",
        R {
            headers: Some(
                json!({"cookie": "JSESSIONID=JSESSVALUE0001ABCD; TS01a1b2c3=TSVALUE0123456789AB"}),
            ),
            body: Some("SESSIONID=SIDVALUE00112233&STAMP=1234&placa=ABC1D23"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.4"), &FlowOptions::default()).unwrap();
    assert!(chain
        .protection
        .iter()
        .any(|p| p.url.contains("/TSPD/") && p.class == StepClass::Protection));
    assert!(
        !chain.unresolved.iter().any(|u| u.field == "x-prot-nonce"),
        "valor consumido só pela proteção não é pendência: {:?}",
        chain.unresolved
    );
    assert!(
        chain.unresolved.iter().any(|u| u.field == "placa"),
        "valores da aplicação continuam pendentes"
    );
}

#[test]
fn compare_pairing_is_monotonic_and_keeps_ambiguities() {
    // t4: B tem outra ordem, um extra e um /q com campos diferentes
    let a_reqs = |s: &mut S| {
        s.req(
            "1.1",
            1.0,
            "http://h.test/p",
            "GET",
            R {
                resp: Some("<i>"),
                resp_headers: Some(json!({"set-cookie": "sid=AAAAAAAA11111111"})),
                ..Default::default()
            },
        );
        s.req(
            "1.2",
            2.0,
            "http://h.test/q",
            "POST",
            R {
                headers: Some(json!({"cookie": "sid=AAAAAAAA11111111"})),
                body: Some("zeta=1&alpha=2&same=k"),
                resp: Some("r1"),
                ..Default::default()
            },
        );
        s.req(
            "1.3",
            3.0,
            "http://h.test/q",
            "POST",
            R {
                headers: Some(json!({"cookie": "sid=AAAAAAAA11111111"})),
                body: Some("zeta=1&alpha=2&same=k"),
                resp: Some("r2"),
                ..Default::default()
            },
        );
        s.req(
            "1.4",
            4.0,
            "http://h.test/gone",
            "GET",
            R {
                resp: Some("g"),
                ..Default::default()
            },
        );
    };
    let mut sa = S::default();
    a_reqs(&mut sa);
    let mut sb = S::default();
    sb.req(
        "2.1",
        1.0,
        "http://h.test/p",
        "GET",
        R {
            resp: Some("<i>"),
            resp_headers: Some(json!({"set-cookie": "sid=BBBBBBBB22222222"})),
            ..Default::default()
        },
    );
    sb.req(
        "2.2",
        2.0,
        "http://h.test/extra",
        "GET",
        R {
            resp: Some("e"),
            ..Default::default()
        },
    );
    sb.req(
        "2.3",
        3.0,
        "http://h.test/q",
        "POST",
        R {
            headers: Some(json!({"cookie": "sid=BBBBBBBB22222222"})),
            body: Some("zeta=1&alpha=9&same=k&newf=n"),
            resp: Some("r1"),
            ..Default::default()
        },
    );
    sb.req(
        "2.4",
        4.0,
        "http://h.test/q",
        "POST",
        R {
            headers: Some(json!({"cookie": "sid=BBBBBBBB22222222"})),
            body: Some("zeta=1&alpha=2&same=k"),
            resp: Some("r2"),
            ..Default::default()
        },
    );
    let (a, b) = (sa.build(), sb.build());
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    assert!(
        r.pairs.iter().all(|p| !p.out_of_order),
        "sem cruzar a ordem"
    );
    let idx = |bundle: &SessionBundle, id: &str| {
        bundle
            .session
            .requests
            .iter()
            .position(|r| r.id == id)
            .unwrap()
    };
    let mut last = None;
    for p in &r.pairs {
        let j = idx(&b, &p.b.request_id);
        assert!(last.map_or(true, |l| j > l));
        last = Some(j);
    }
    // o /q de mesmo modelo (2.4) casa com o segundo de A; o de campos diferentes (2.3) com o primeiro
    let pair_of = |a_id: &str| {
        r.pairs
            .iter()
            .find(|p| p.a.request_id == lid(&a, a_id))
            .unwrap()
    };
    assert_eq!(pair_of("1.3").b.request_id, lid(&b, "2.4"));
    assert_eq!(pair_of("1.2").b.request_id, lid(&b, "2.3"));
    assert_eq!(pair_of("1.2").aligned_by, "path");
    assert!(!r.ambiguities.is_empty());
    assert_eq!(r.only_in_a.len(), 1);
    assert_eq!(r.only_in_b.len(), 1);
}

// ---- acabamento da rodada 5 -----------------------------------------------------------

#[test]
fn l1_common_prefix_of_a_named_field_is_not_an_origin() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("tok=TIEVALUE12345678"),
            rct: Some("text/plain"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/b",
        "POST",
        R {
            body: Some("tok=TIEVALUE87654321"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    assert_eq!(
        o.values.iter().filter(|v| v.field == "tok").count(),
        1,
        "sem trechos"
    );
    let v = entry(&o, "tok");
    assert_eq!(v.status, OriginStatus::None);
    assert!(v.evidences.is_empty());
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.2"), &FlowOptions::default()).unwrap();
    assert!(chain.steps.is_empty(), "{:?}", chain.steps);
    // valor idêntico continua sendo origem (valor inteiro)
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/a",
        "GET",
        R {
            resp: Some("tok=TIEVALUE12345678"),
            rct: Some("text/plain"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/b",
        "POST",
        R {
            body: Some("tok=TIEVALUE12345678"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    assert_eq!(
        entry(&origins(&s.build(), "1.2"), "tok").status,
        OriginStatus::Origin
    );
}

#[test]
fn l2_swapped_unique_requests_are_flagged_as_reordered() {
    let mut sa = S::default();
    sa.req(
        "1.1",
        1.0,
        "http://h.test/p",
        "GET",
        R {
            resp: Some("p"),
            ..Default::default()
        },
    );
    sa.req(
        "1.2",
        2.0,
        "http://h.test/r",
        "GET",
        R {
            resp: Some("r"),
            ..Default::default()
        },
    );
    let mut sb = S::default();
    sb.req(
        "2.1",
        1.0,
        "http://h.test/r",
        "GET",
        R {
            resp: Some("r"),
            ..Default::default()
        },
    );
    sb.req(
        "2.2",
        2.0,
        "http://h.test/p",
        "GET",
        R {
            resp: Some("p"),
            ..Default::default()
        },
    );
    let (a, b) = (sa.build(), sb.build());
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    assert!(
        r.pairs.iter().all(|p| !p.out_of_order),
        "pareamento segue monotônico"
    );
    assert_eq!(r.pairs.len(), 1);
    assert_eq!(r.only_in_a.len(), 1);
    assert_eq!(r.only_in_b.len(), 1);
    assert_eq!(r.reordered.len(), 1);
    assert_eq!(r.reordered[0].a.request_id, r.only_in_a[0].request_id);
    assert_eq!(r.reordered[0].b.request_id, r.only_in_b[0].request_id);
    assert!(r.reordered[0]
        .a
        .url
        .ends_with(&r.reordered[0].b.url[r.reordered[0].b.url.len() - 2..]));
    assert!(r.ambiguities.iter().any(|m| m.contains("reordenadas")));
    // sobras de modelos diferentes não são "reordenadas"
    let mut sc = S::default();
    sc.req(
        "3.1",
        1.0,
        "http://h.test/x",
        "GET",
        R {
            resp: Some("x"),
            ..Default::default()
        },
    );
    let c = sc.build();
    let r = compare_sessions(&a.session, &a, &c.session, &c, &CompareOptions::default());
    assert!(r.reordered.is_empty());
}

#[test]
fn l3_static_resources_are_context_never_steps() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/app.js",
        "GET",
        R {
            resp: Some("var build=\"v20261027-abcdef12\";"),
            rct: Some("application/javascript"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/send",
        "POST",
        R {
            body: Some("build=v20261027-abcdef12"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let v = entry(&origins(&b, "1.2"), "build").clone();
    assert_eq!(v.status, OriginStatus::None);
    assert!(v.evidences.is_empty());
    assert_eq!(v.context.len(), 1);
    assert!(v.label.contains("recurso estático"));
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.2"), &FlowOptions::default()).unwrap();
    assert!(chain.steps.is_empty());
    // presente no estático E em resposta dinâmica: só o dinâmico produz
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/app.js",
        "GET",
        R {
            resp: Some("var build=\"v20261027-abcdef12\";"),
            rct: Some("application/javascript"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/dyn",
        "GET",
        R {
            resp: Some("<p>var b=\"v20261027-abcdef12\"</p>"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "http://h.test/send",
        "POST",
        R {
            body: Some("build=v20261027-abcdef12"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.3");
    let v = entry(&o, "build");
    assert_eq!(v.evidences.len(), 1);
    assert_eq!(v.evidences[0].request_id, lid(&b, "1.2"));
    assert!(v.context.is_empty());
}
