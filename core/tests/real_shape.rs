//! Rodada 6 — fidelidade ao caso real (docs/10): respostas HTML com controles de
//! formulário, HAR sem cookies, rodadas, campos de negócio. Mini-fixtures próprias.

use scrapelens_core::compare::{compare_sessions, CompareOptions, RequestRange};
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::flow::{
    priming_chain, value_origins, Confidence, EvidenceKind, FlowOptions, OriginStatus, Role,
    StepClass, Strength, ValueOrigin, ValueOrigins,
};
use scrapelens_core::model::{BodyState, SessionBundle};
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use scrapelens_core::search::{search, SearchQuery};
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
    resp_type: Option<&'a str>,
    initiator: Option<Value>,
}

impl S {
    fn req(&mut self, id: &str, t: f64, url: &str, method: &str, r: R) {
        let mut h = r.headers.unwrap_or(json!({}));
        if r.body.is_some() {
            h["content-type"] = json!(FORM);
        }
        let mut params = json!({
            "requestId": id, "loaderId": "L", "timestamp": t, "wallTime": 1793000000.0 + t,
            "request": {"url": url, "method": method, "headers": h, "hasPostData": r.body.is_some()},
            "type": "XHR", "frameId": "F"});
        if let Some(initiator) = &r.initiator {
            params["initiator"] = initiator.clone();
        }
        self.ev
            .push(json!({"method": "Network.requestWillBeSent", "params": params}));
        if let Some(body) = r.body {
            self.bd.push(line(id, "request", body, t));
        }
        let resp_type = r.resp_type.unwrap_or("text/html");
        self.ev.push(json!({"method": "Network.responseReceived", "params": {
            "requestId": id, "loaderId": "L", "timestamp": t + 0.02, "type": "XHR",
            "response": {"url": url, "status": 200, "statusText": "", "headers": {"content-type": resp_type}, "protocol": "http/1.1"}}}));
        self.ev.push(json!({"method": "Network.loadingFinished", "params": {"requestId": id, "timestamp": t + 0.04, "encodedDataLength": 1}}));
        if let Some(resp) = r.resp {
            self.bd.push(line(id, "response", resp, t + 0.04));
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

/// Resposta do Connector na forma real: HTML com script antes, controles com
/// aspas duplas/simples/sem aspas, maiúsculas, entidades e textarea com `<` escapado.
fn connector_html(stamp: &str, delta: &str) -> String {
    format!(
        "<html><head><script>var f5 = \"<input name='STAMP' value='9999'>\"; function x(){{}}</script></head>\n<body><FORM method=post>\n\
         <INPUT TYPE=hidden NAME=STAMP VALUE=\"{stamp}\">\n\
         <input type='hidden' name='ECHO' value='a&amp;b&#x21;'>\n\
         <input name=BARE value=unquoted>\n\
         <input name=\"ERRORMESSAGE\">\n\
         <textarea name=\"XML\" rows=\"3\">lp08nextPage&lt;/UIC/VES0009X.html&gt;k05v_tmpx08{delta}</textarea>\n\
         <textarea name=\"ERRORMESSAGE2\"></textarea></FORM></body></html>"
    )
}

// ---- L1 ---------------------------------------------------------------------------------

#[test]
fn l1_html_controls_feed_same_field_and_value_match() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init0&STAMP=2004"),
            resp: Some(&connector_html("2005", "DLTA0005")),
            ..Default::default()
        },
    );
    s.req("1.2", 2.0, "https://x.test/app/Connector", "POST", R {
        body: Some("SESSIONID=S1&ECHO=a%26b!&STAMP=2005&XML=i2212001705027000195dummy-cmd_consultar_placa-falsex08DLTA0005"),
        resp: Some("<html></html>"),
        ..Default::default()
    });
    let b = s.build();
    let o = origins(&b, "1.2");
    // STAMP: same-field forte, vindo de <input hidden> (e não do script do F5)
    let stamp = entry(&o, "STAMP");
    assert_eq!(stamp.status, OriginStatus::Origin);
    assert_eq!(stamp.confidence, Some(Confidence::Strong));
    assert_eq!(stamp.evidences[0].kind, EvidenceKind::SameField);
    assert!(stamp.evidences[0].html_control);
    assert_eq!(stamp.evidences[0].request_id, lid(&b, "1.1"));
    // entidades decodificadas no valor
    assert_eq!(entry(&o, "ECHO").status, OriginStatus::Origin);
    // delta: trecho do XML vindo da textarea anterior (value-match, offset no original)
    let delta = o
        .values
        .iter()
        .find(|v| v.parent.as_deref() == Some("XML") && v.value.contains("DLTA0005"))
        .expect("trecho do delta");
    assert!(!delta.evidences.is_empty());
    let e = &delta.evidences[0];
    assert!(e.html_control);
    assert_eq!(e.kind, EvidenceKind::ValueMatch);
    let html = connector_html("2005", "DLTA0005");
    let at = e.producer_offset.unwrap() as usize;
    assert!(
        html[at..].starts_with("x08DLTA0005"),
        "offset original da textarea: {}",
        &html[at..at + 12]
    );
}

#[test]
fn l1_search_sees_html_controls_by_name() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init0"),
            resp: Some(&connector_html("2005", "DLTA0005")),
            ..Default::default()
        },
    );
    let b = s.build();
    let r = search(&b, &SearchQuery::new("</UIC/VES0009X.html>"));
    let m = r
        .matches
        .iter()
        .find(|m| m.field.as_deref() == Some("XML"))
        .expect("achado na textarea");
    assert!(m.decoded && m.html_control);
    let r = search(&b, &SearchQuery::new("a&b!"));
    assert!(
        r.matches
            .iter()
            .find(|m| m.field.as_deref() == Some("ECHO"))
            .unwrap()
            .decoded
    );
}

// ---- L2 / L7 (HAR) -----------------------------------------------------------------------

fn har(with_cookie: bool) -> Vec<u8> {
    let mut headers = vec![json!({"name": "Accept", "value": "*/*"})];
    if with_cookie {
        headers.push(json!({"name": "Cookie", "value": "a=b"}));
    }
    let entry = |method: &str, url: &str, post: bool| {
        let mut request = json!({"method": method, "url": url, "httpVersion": "HTTP/1.1", "headers": headers, "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0});
        if post {
            request["postData"] = json!({"mimeType": FORM, "text": "a=1"});
        }
        json!({"startedDateTime": "2026-10-26T20:00:00.000Z", "time": 1, "request": request,
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": [{"name": "content-type", "value": "text/html"}], "cookies": [], "content": {"size": 2, "mimeType": "text/html", "text": "ok"}, "redirectURL": "", "headersSize": -1, "bodySize": 2},
            "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}})
    };
    let mut no_body_post = entry("POST", "https://x.test/p", false);
    no_body_post["request"]["bodySize"] = json!(5);
    serde_json::to_vec(&json!({"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "537.36"},
        "entries": [entry("GET", "https://x.test/a", false), entry("HEAD", "https://x.test/b", false), entry("OPTIONS", "https://x.test/c", false), no_body_post, entry("POST", "https://x.test/d", true)]}}))
    .unwrap()
}

#[test]
fn l2_har_without_cookies_warns_and_origins_repeat_it() {
    let imported = scrapelens_core::import_har(&har(false)).unwrap();
    let codes: Vec<_> = imported
        .bundle
        .session
        .warnings
        .iter()
        .map(|w| w.code.as_str())
        .collect();
    assert!(codes.contains(&"har.cookies_absent"), "{codes:?}");
    let id = imported.bundle.session.requests[4].id.clone();
    let o = value_origins(
        &imported.bundle.session,
        &imported.bundle,
        &id,
        &FlowOptions::default(),
    )
    .unwrap();
    assert!(
        o.warnings.iter().any(|w| w.contains("não contém cookies")),
        "{:?}",
        o.warnings
    );
    let chain = priming_chain(
        &imported.bundle.session,
        &imported.bundle,
        &id,
        &FlowOptions::default(),
    )
    .unwrap();
    assert!(chain
        .warnings
        .iter()
        .any(|w| w.contains("não contém cookies")));
    // com cookie em alguma entrada: sem aviso
    let with = scrapelens_core::import_har(&har(true)).unwrap();
    assert!(with
        .bundle
        .session
        .warnings
        .iter()
        .all(|w| w.code != "har.cookies_absent"));
}

#[test]
fn l7_har_get_head_options_without_postdata_are_empty_not_applicable() {
    let imported = scrapelens_core::import_har(&har(false)).unwrap();
    let rs = &imported.bundle.session.requests;
    for r in &rs[..3] {
        assert_eq!(r.request_body.state, BodyState::Empty, "{}", r.method);
        assert_eq!(
            r.request_body.note.as_deref(),
            Some("não aplicável: método sem corpo")
        );
    }
    // POST sem postData: corpo esperado que não veio
    assert_eq!(rs[3].request_body.state, BodyState::Unavailable);
    assert_eq!(rs[4].request_body.state, BodyState::Captured);
}

// ---- L4 ---------------------------------------------------------------------------------

#[test]
fn l4_context_pages_by_referer_are_not_producers_or_steps() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Page.html",
        "GET",
        R {
            resp: Some("<html><body>pagina</body></html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            headers: Some(json!({"referer": "https://x.test/app/Page.html"})),
            body: Some("XML=init0&STAMP=2004"),
            resp: Some(&connector_html("2005", "DLTA0005")),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            headers: Some(json!({"referer": "https://x.test/app/Page.html#frag"})),
            body: Some("STAMP=2005&XML=cmd"),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.3"), &FlowOptions::default()).unwrap();
    assert_eq!(chain.steps.len(), 1, "o POST do Connector entra por STAMP");
    assert_eq!(chain.steps[0].request_id, lid(&b, "1.2"));
    assert_eq!(chain.steps[0].confidence, Confidence::Strong);
    assert_eq!(chain.pages.len(), 1);
    assert_eq!(chain.pages[0].request_id, lid(&b, "1.1"));
    assert_eq!(chain.pages[0].class, StepClass::Page);
    assert!(chain.pages[0].reason.starts_with("página de contexto"));
    assert!(
        !chain.steps.iter().any(|s| s.request_id == lid(&b, "1.1")),
        "página não é produtora"
    );
}

// ---- L5 ---------------------------------------------------------------------------------

fn all_text(b: &SessionBundle) -> String {
    let mut text = serde_json::to_string(&b.session).unwrap();
    for bytes in b.attachments.values() {
        text.push_str(&String::from_utf8_lossy(bytes));
    }
    text
}

#[test]
fn l5_business_fields_are_redacted_in_opaque_values_and_propagated() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=p0700007v_placaTST0T00p1300003cpf12345678901xx&STAMP=2004&v_placa_x=1"),
            resp: Some("<html><textarea name=\"XML\">v_placaTST0T00 eco</textarea></html>"),
            ..Default::default()
        },
    );
    s.req("1.2", 2.0, "https://x.test/app/Connector?ref=TST0T00", "POST", R {
        body: Some("placa=TST0T00&renavam=123456789&XML=aaaaaaaaaaaa-v_placaXY-bbbbbbbbbb-cmd_consultar_placa-falsecccc"),
        resp: Some("ok TST0T00"),
        ..Default::default()
    });
    let b = s.build();
    let before = all_text(&b);
    assert!(before.contains("TST0T00") && before.contains("12345678901"));
    let export = sanitize_bundle(&b, &SanitizeOptions::default());
    let after = all_text(&export.bundle);
    assert!(!after.contains("TST0T00"), "placa vazou");
    assert!(!after.contains("12345678901"), "CPF vazou");
    assert!(!after.contains("123456789&") && !after.contains("renavam=123456789"));
    // relatório por tipo, sem valores
    assert!(
        export
            .redactions
            .get("business:placa")
            .copied()
            .unwrap_or(0)
            >= 2,
        "{:?}",
        export.redactions
    );
    assert!(export.redactions.get("business:cpf").copied().unwrap_or(0) >= 1);
    assert!(
        export.redactions.keys().any(|k| k == "propagated:business"),
        "{:?}",
        export.redactions
    );
    // valor fora do formato: aviso, sem redação silenciosa
    let warn = export
        .warnings
        .iter()
        .find(|w| w.code == "sanitize.business_field_unmatched")
        .expect("aviso");
    assert!(!warn.message.contains("XY"));
    assert!(
        after.contains("v_placaXY"),
        "valor fora do formato permanece (com aviso)"
    );
    // lista configurável
    let options = SanitizeOptions {
        business_fields: vec!["matricula".to_string()],
        ..Default::default()
    };
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/a",
        "POST",
        R {
            body: Some("matricula=MAT99887766&placa=TST0T00"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let after = all_text(&sanitize_bundle(&b, &options).bundle);
    assert!(!after.contains("MAT99887766"));
    assert!(after.contains("TST0T00"), "fora da lista configurada");
}

// ---- L6 ---------------------------------------------------------------------------------

fn round(s: &mut S, base: f64, n: usize, stamp: &str) {
    let id = |k: usize| format!("{n}.{k}");
    s.req(
        &id(1),
        base,
        "https://x.test/app/easynat",
        "GET",
        R {
            resp: Some("<html>entrada</html>"),
            ..Default::default()
        },
    );
    s.req(
        &id(2),
        base + 0.1,
        "https://x.test/TSPD/?type=18",
        "GET",
        R {
            resp: Some("bin"),
            ..Default::default()
        },
    );
    s.req(
        &id(3),
        base + 0.2,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some(&format!("XML=init&STAMP={stamp}")),
            resp: Some("<html>r</html>"),
            ..Default::default()
        },
    );
    s.req(
        &id(4),
        base + 0.3,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some(&format!("XML=consulta&STAMP={stamp}")),
            resp: Some("<html>r</html>"),
            ..Default::default()
        },
    );
}

#[test]
fn l6_compare_by_rounds_application_only_with_unpaired_rounds_and_ranges() {
    let mut sa = S::default();
    round(&mut sa, 1.0, 1, "1000");
    let mut sb = S::default();
    round(&mut sb, 1.0, 1, "2000");
    round(&mut sb, 5.0, 2, "2100");
    let (a, b) = (sa.build(), sb.build());
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    assert!(r.entry_request.as_deref().unwrap().contains("/app/easynat"));
    assert_eq!(r.rounds.len(), 1);
    assert_eq!(r.unpaired_rounds.len(), 1);
    assert_eq!(
        (
            r.unpaired_rounds[0].side.as_str(),
            r.unpaired_rounds[0].round,
            r.unpaired_rounds[0].requests
        ),
        ("B", 1, 3)
    );
    assert_eq!(r.pairs.len(), 3, "só a aplicação: entrada + 2 POSTs");
    assert!(
        r.only_in_a.is_empty() && r.only_in_b.is_empty(),
        "rodada sem par não vira sobra"
    );
    assert!(r.ambiguities.is_empty(), "{:?}", r.ambiguities);
    assert_eq!(r.groups.len(), 1);
    assert_eq!(r.groups[0].kind, "protection");
    assert_eq!((r.groups[0].a.len(), r.groups[0].b.len()), (1, 2));
    // incluir tudo traz a proteção para o alinhamento
    let all = compare_sessions(
        &a.session,
        &a,
        &b.session,
        &b,
        &CompareOptions {
            include_all: true,
            ..Default::default()
        },
    );
    assert!(all.groups.is_empty() && all.pairs.len() > r.pairs.len());
    // faixa explícita: só a 2ª rodada de B (requisições 5..8)
    let ranged = compare_sessions(
        &a.session,
        &a,
        &b.session,
        &b,
        &CompareOptions {
            b_range: RequestRange::parse("5:8"),
            ..Default::default()
        },
    );
    assert!(ranged.unpaired_rounds.is_empty());
    assert_eq!(ranged.pairs.len(), 3);
    assert_eq!(ranged.pairs[0].b.request_id, b.session.requests[4].id);
    let by_id = RequestRange::parse(&format!(
        "{}:{}",
        b.session.requests[4].id, b.session.requests[7].id
    ))
    .unwrap();
    assert_eq!(by_id.from, b.session.requests[4].id);
    let bad = compare_sessions(
        &a.session,
        &a,
        &b.session,
        &b,
        &CompareOptions {
            b_range: RequestRange::parse("zzz:yyy"),
            ..Default::default()
        },
    );
    assert!(bad
        .warnings
        .iter()
        .any(|w| w.contains("faixa de B inválida")));
}

// ---- L8 ---------------------------------------------------------------------------------

#[test]
fn l8_unobservable_points_to_the_equivalent_occurrence_in_the_next_round() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=cmd_filtro"),
            resp: Some(&connector_html("2005", "DLTA0005")),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=consulta&STAMP=2005"),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=cmd_filtro"),
            resp: Some(&connector_html("2006", "DLTA0006")),
            ..Default::default()
        },
    );
    let mut b = s.build();
    // a resposta do cmd_filtro da 1ª rodada não está no HAR
    let first = lid(&b, "1.1");
    for r in &mut b.session.requests {
        if r.id == first {
            let body = scrapelens_core::Body::unavailable("response.content sem text");
            r.attempts[0].response_body = body.clone();
            r.response_body = body;
        }
    }
    let o = origins(&b, "1.2");
    let stamp = entry(&o, "STAMP");
    assert_eq!(stamp.status, OriginStatus::None);
    assert_eq!(stamp.unobservable.len(), 1);
    assert_eq!(stamp.unobservable[0].request_id, first);
    assert_eq!(
        stamp.unobservable[0].suggestion.as_deref(),
        Some(lid(&b, "1.3").as_str())
    );
    assert!(stamp.label.contains(&lid(&b, "1.3")), "{}", stamp.label);
}

// ---- valor composto (campo nomeado curto) e variável do Natural -------------------------------

#[test]
fn composite_rule_needs_full_cover_by_two_producers_and_partial_prefix_is_not_an_origin() {
    // a 2ª peça vem de uma folha JSON de outra resposta
    let mut s2 = S::default();
    s2.req(
        "1.1",
        1.0,
        "https://x.test/a",
        "GET",
        R {
            resp: Some("<script>var part_a = \"ALPHA0001\";</script>"),
            ..Default::default()
        },
    );
    let ev = json!({"method": "Network.responseReceived", "params": {"requestId": "1.2", "loaderId": "L", "timestamp": 2.02, "type": "XHR",
        "response": {"url": "https://x.test/b", "status": 200, "statusText": "", "headers": {"content-type": "application/json"}, "protocol": "http/1.1"}}});
    s2.req(
        "1.2",
        2.0,
        "https://x.test/b",
        "GET",
        R {
            resp: Some("{\"part_b\":\"987654321012\"}"),
            ..Default::default()
        },
    );
    s2.ev.push(ev); // sobrescreve o content-type para JSON
    s2.req(
        "1.3",
        3.0,
        "https://x.test/c",
        "POST",
        R {
            body: Some("token=ALPHA0001_987654321012&token2=ALPHA0001_555555555555"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s2.build();
    let o = origins(&b, "1.3");
    let full = entry(&o, "token");
    assert_eq!(full.status, OriginStatus::Composite);
    assert_eq!(full.confidence, Some(Confidence::Possible));
    let parts: Vec<_> = o
        .values
        .iter()
        .filter(|v| v.parent.as_deref() == Some("token"))
        .collect();
    let mut producers: Vec<_> = parts
        .iter()
        .flat_map(|p| p.evidences.iter().map(|e| e.request_id.clone()))
        .collect();
    producers.sort();
    producers.dedup();
    assert_eq!(producers, vec![lid(&b, "1.1"), lid(&b, "1.2")]);
    // só o prefixo tem produtor: cobertura parcial não vale
    let partial = entry(&o, "token2");
    assert_eq!(partial.status, OriginStatus::None);
    assert!(partial.evidences.is_empty());
    assert!(partial.label.starts_with("sem origem observada"));
}

#[test]
fn natural_variable_names_prefixed_with_v_are_business_fields() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/c",
        "POST",
        R {
            body: Some(
                "XML=p0500011v_cpf00000000191p0900002v_renavam12p1300003#f12_selected2.0&A=b",
            ),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let export = sanitize_bundle(&b, &SanitizeOptions::default());
    let after = all_text(&export.bundle);
    assert!(!after.contains("00000000191"), "CPF vazou");
    assert!(
        after.contains("v_renavam12"),
        "valor fora do formato permanece, com aviso"
    );
    assert!(export
        .warnings
        .iter()
        .any(|w| w.code == "sanitize.business_field_unmatched"));
    assert!(export.redactions.get("business:cpf").copied().unwrap_or(0) >= 1);
}

#[test]
fn partial_composition_hint_for_known_part_plus_unsourced_part() {
    // SESSIONID real: literal de 9 chars + "_" + 12 dígitos sem fonte observada
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/easynat",
        "GET",
        R {
            resp: Some("<script>var m_currentSessionId = \"CSAN00011\";</script>"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/c",
        "POST",
        R {
            body: Some("SESSIONID=CSAN00011_700000000011&other=ZZZZZZZZ_QQ"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    let v = entry(&o, "SESSIONID");
    assert_eq!(v.status, OriginStatus::None, "não é origem");
    assert!(v.evidences.is_empty());
    assert_eq!(v.partial_composition.len(), 1);
    let h = &v.partial_composition[0];
    assert_eq!((h.start, h.length), (0, 9));
    assert_eq!(h.producer_request_id, lid(&b, "1.1"));
    assert_eq!(h.field.as_deref(), Some("m_currentSessionId"));
    assert!(v
        .label
        .starts_with("sem origem observada; contém o valor de m_currentSessionId de "));
    assert!(v.label.contains("provável composição no cliente"));
    assert!(entry(&o, "other").partial_composition.is_empty());
    // sem passo na cadeia
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.2"), &FlowOptions::default()).unwrap();
    assert!(chain.steps.is_empty(), "{:?}", chain.steps);
    // caso TIEVALUE da R5, sem separador: nenhuma dica
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/a",
        "GET",
        R {
            resp: Some("tok=TIEVALUE12345678"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/b",
        "POST",
        R {
            body: Some("tok=TIEVALUE87654321"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let o = origins(&s.build(), "1.2");
    assert!(entry(&o, "tok").partial_composition.is_empty());
    assert_eq!(entry(&o, "tok").label, "sem origem observada");
}

#[test]
fn delta_at_the_end_survives_a_one_byte_overlap_with_a_longer_constant() {
    // A constante comum (13 bytes) engole 1 byte do "x06TOKEN" final: o delta
    // continua resolvido pelo trecho aparado.
    let mut s = S::default();
    let tail = "cISAddons.focusItemNamex06DLTC07";
    let prev = format!(
        "<textarea name=\"XML\">lp1600000v_situacao_atualK05v_tmpp2300003{tail}</textarea>"
    );
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init0&STAMP=INIT"),
            resp: Some(&prev),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some(&format!(
                "XML=i2212001705027000195dummyp2300003{tail}&STAMP=9"
            )),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    let hit = o
        .values
        .iter()
        .find(|v| v.parent.as_deref() == Some("XML") && v.value.contains("DLTC07"))
        .expect("trecho com o delta");
    assert!(hit
        .evidences
        .iter()
        .any(|e| e.request_id == lid(&b, "1.1") && e.html_control));
}

// ---- L4b: páginas só dos passos da aplicação; frames auxiliares recolhidos ---------------------

#[test]
fn l4b_pages_come_only_from_application_steps_and_aux_frames_are_collapsed() {
    let mut s = S::default();
    let base = "https://x.test/app";
    s.req(
        "1.1",
        1.0,
        &format!("{base}/entry"),
        "GET",
        R {
            resp: Some("<html>entrada</html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        1.1,
        &format!("{base}/Main.html"),
        "GET",
        R {
            headers: Some(json!({"referer": format!("{base}/entry")})),
            resp: Some("<html>principal</html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        1.2,
        &format!("{base}/Main_JLIBS.html"),
        "GET",
        R {
            headers: Some(json!({"referer": format!("{base}/Main.html")})),
            resp: Some("<html>frame</html>"),
            initiator: Some(json!({"type": "parser", "url": "https://x.test/app/Main.html"})),
            ..Default::default()
        },
    );
    s.req(
        "1.4",
        1.3,
        &format!("{base}/cscform.html"),
        "GET",
        R {
            headers: Some(json!({"referer": format!("{base}/Main_JLIBS.html")})),
            resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
            initiator: Some(json!({"type": "parser", "url": "https://x.test/app/Main_JLIBS.html"})),
            ..Default::default()
        },
    );
    // proteção cujo Referer é um frame auxiliar que só serve a ela
    s.req(
        "1.5",
        1.4,
        &format!("{base}/aboutBlank.html"),
        "GET",
        R {
            headers: Some(json!({"referer": format!("{base}/entry")})),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.6",
        1.5,
        "https://x.test/TSPD/?type=18",
        "GET",
        R {
            headers: Some(json!({"referer": format!("{base}/aboutBlank.html")})),
            resp: Some("js"),
            ..Default::default()
        },
    );
    s.req(
        "1.7",
        2.0,
        &format!("{base}/Connector"),
        "POST",
        R {
            headers: Some(json!({"referer": format!("{base}/cscform.html")})),
            body: Some("XML=init&STAMP=INIT"),
            resp: Some(&connector_html("2005", "DLTA0005")),
            ..Default::default()
        },
    );
    s.req(
        "1.8",
        3.0,
        &format!("{base}/Connector"),
        "POST",
        R {
            headers: Some(json!({"referer": format!("{base}/cscform.html")})),
            body: Some("XML=consulta&STAMP=2005"),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.8"), &FlowOptions::default()).unwrap();
    let ids = |v: &Vec<scrapelens_core::flow::ChainStep>| {
        v.iter().map(|p| p.request_id.clone()).collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&chain.pages),
        vec![lid(&b, "1.1"), lid(&b, "1.2")],
        "raiz + documento logo abaixo"
    );
    assert_eq!(
        ids(&chain.auxiliary_pages),
        vec![lid(&b, "1.3"), lid(&b, "1.4")]
    );
    for gone in ["1.5", "1.6"] {
        assert!(
            !ids(&chain.pages).contains(&lid(&b, gone))
                && !ids(&chain.auxiliary_pages).contains(&lid(&b, gone)),
            "{gone}"
        );
    }
    assert!(chain
        .pages
        .iter()
        .chain(&chain.auxiliary_pages)
        .all(|p| p.class == StepClass::Page));
}

// ---- STAMP=INIT: a página define o valor; o compare o vê como estático --------------------------

#[test]
fn init_stamp_is_defined_by_a_page_and_compares_as_static() {
    let build = |stamp2: &str| {
        let mut s = S::default();
        s.req(
            "1.1",
            1.0,
            "https://x.test/app/cscform.html",
            "GET",
            R {
                resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
                ..Default::default()
            },
        );
        s.req(
            "1.2",
            2.0,
            "https://x.test/app/Connector",
            "POST",
            R {
                body: Some("XML=init0&STAMP=INIT"),
                resp: Some(&connector_html(stamp2, "DLTA0005")),
                ..Default::default()
            },
        );
        s.build()
    };
    let (a, b) = (build("2005"), build("3005"));
    let o = origins(&a, "1.2");
    let st = entry(&o, "STAMP");
    assert_eq!(st.status, OriginStatus::Origin);
    assert_eq!(st.evidences[0].kind, EvidenceKind::SameField);
    assert!(st.evidences[0].html_control);
    assert_eq!(
        st.evidences[0].request_id,
        lid(&a, "1.1"),
        "quem define INIT é a página"
    );
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    let f = r
        .pairs
        .iter()
        .flat_map(|p| p.fields.iter())
        .find(|f| f.field == "STAMP")
        .unwrap();
    assert_eq!(f.class, scrapelens_core::compare::FieldClass::Static);
    assert!(
        f.origin_label.is_none(),
        "estático não vira 'obter em runtime'"
    );
}

#[test]
fn partial_composition_hint_also_on_repeated_values_and_in_unresolved() {
    // o valor já circulou em requisições anteriores (repeated); a dica usa só
    // produtores anteriores à 1ª ocorrência
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/easynat",
        "GET",
        R {
            resp: Some("<script>var m_currentSessionId = \"CSAN00011\";</script>"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/c",
        "POST",
        R {
            body: Some("SESSIONID=CSAN00011_700000000011"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    s.req(
        "1.3",
        3.0,
        "https://x.test/c",
        "POST",
        R {
            body: Some("SESSIONID=CSAN00011_700000000011"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.3");
    let v = entry(&o, "SESSIONID");
    assert_eq!(v.status, OriginStatus::Repeated);
    assert_eq!(v.partial_composition.len(), 1);
    assert_eq!(v.partial_composition[0].producer_request_id, lid(&b, "1.1"));
    assert!(
        v.label.contains("provável composição no cliente")
            && v.label.contains("valor já circulava em"),
        "{}",
        v.label
    );
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.3"), &FlowOptions::default()).unwrap();
    assert!(chain.steps.is_empty());
    let u = chain
        .unresolved
        .iter()
        .find(|u| u.field == "SESSIONID")
        .expect("pendência");
    assert_eq!(u.partial_composition.len(), 1);
    assert!(u.label.contains("provável composição no cliente"));
}

#[test]
fn r6_single_producer_is_not_ambiguous_and_buttons_are_not_producers() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/page",
        "GET",
        R {
            resp: Some(
                "<html><form><input type=hidden name=h value=VALUE12345678>\
                 <input type=hidden name=x value=VALUE12345678>\
                 <input type=submit name=acao value=Consultar>\
                 <input type=text name=nome value=Maria>\
                 <input type=image name=img value=ImageVal></form></html>",
            ),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "https://x.test/app/post",
        "POST",
        R {
            body: Some("x=VALUE12345678&acao=Consultar&nome=Maria&img=ImageVal"),
            resp: Some("<html></html>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    let x = entry(&o, "x");
    // `h` e `x` com o mesmo valor: o same-field `x` basta; nunca ambíguo por duplicata
    assert_eq!(x.status, OriginStatus::Origin, "{x:?}");
    assert_eq!(
        x.evidences
            .iter()
            .filter(|e| e.role == Role::Produced)
            .count(),
        1
    );
    // botão não é produtor
    let acao = entry(&o, "acao");
    assert!(acao.evidences.is_empty(), "{acao:?}");
    assert_eq!(entry(&o, "img").evidences.len(), 0);
    // text pré-preenchido: no máximo média
    let nome = entry(&o, "nome");
    assert!(nome
        .evidences
        .iter()
        .all(|e| e.strength != Strength::Strong));
}

#[test]
fn r6_business_names_are_exact_or_separated_and_formats_and_entities_are_covered() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/a",
        "POST",
        R {
            body: Some(
                "XML=aaaa-placaQWE1234-bbbb-placaABC-1234-cccc-cpf390.533.447-05-dddd-cnpj11.222.333/0001-81-eeee&template=ZZZPLATE99&kevin=KEVINVALUE1&x_cpf=39053344705",
            ),
            resp: Some("<p>&#80;lacaTST0T00 e placaTST1T11</p>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let after = all_text(&sanitize_bundle(&b, &SanitizeOptions::default()).bundle);
    for leaked in [
        "QWE1234",
        "ABC-1234",
        "390.533.447-05",
        "11.222.333/0001-81",
    ] {
        assert!(!after.contains(leaked), "vazou {leaked}");
    }
    assert!(!after.contains("TST0T00"), "vazou via entidade no nome");
    assert!(!after.contains("TST1T11"));
    // `template`/`kevin` não são campos de negócio (sufixo sem separador)
    assert!(after.contains("ZZZPLATE99") && after.contains("KEVINVALUE1"));
    // sufixo depois de separador continua valendo
    assert!(!after.contains("39053344705"));
}

#[test]
fn r6_invalid_ranges_warn_reload_is_not_a_round_and_initiator_url_gives_pages() {
    let mut sa = S::default();
    round(&mut sa, 1.0, 1, "1000");
    let mut sb = S::default();
    round(&mut sb, 1.0, 1, "2000");
    let (a, b) = (sa.build(), sb.build());
    for (range, why) in [("3:2", "invertida"), ("90:99", "fora dos limites")] {
        let r = compare_sessions(
            &a.session,
            &a,
            &b.session,
            &b,
            &CompareOptions {
                a_range: RequestRange::parse(range),
                ..Default::default()
            },
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("faixa de A") && w.contains(why)),
            "{range}: {:?}",
            r.warnings
        );
    }
    // reload da entrada sem passo de aplicação entre as ocorrências: 1 rodada só
    let mut sr = S::default();
    sr.req(
        "1.1",
        1.0,
        "https://x.test/app/easynat",
        "GET",
        R {
            resp: Some("<html>e</html>"),
            ..Default::default()
        },
    );
    sr.req(
        "1.2",
        2.0,
        "https://x.test/app/easynat",
        "GET",
        R {
            resp: Some("<html>e</html>"),
            ..Default::default()
        },
    );
    sr.req(
        "1.3",
        3.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init&STAMP=1000"),
            resp: Some("<html>r</html>"),
            ..Default::default()
        },
    );
    sr.req(
        "1.4",
        4.0,
        "https://x.test/app/easynat",
        "GET",
        R {
            resp: Some("<html>e</html>"),
            ..Default::default()
        },
    );
    sr.req(
        "1.5",
        5.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init&STAMP=1001"),
            resp: Some("<html>r</html>"),
            ..Default::default()
        },
    );
    let c = sr.build();
    let r = compare_sessions(&c.session, &c, &c.session, &c, &CompareOptions::default());
    assert_eq!(r.rounds.len(), 2, "reload não abre rodada: {:?}", r.rounds);
    // pages por initiator.url (sem Referer) e sem aviso de initiator ausente
    let mut sp = S::default();
    sp.req(
        "1.1",
        1.0,
        "https://x.test/app/Page.html",
        "GET",
        R {
            resp: Some("<html>p</html>"),
            ..Default::default()
        },
    );
    sp.req(
        "1.2",
        2.0,
        "https://x.test/app/Connector",
        "POST",
        R {
            body: Some("XML=init&STAMP=1"),
            resp: Some("<html></html>"),
            initiator: Some(json!({"type": "script", "url": "https://x.test/app/Page.html"})),
            ..Default::default()
        },
    );
    let p = sp.build();
    let chain = priming_chain(&p.session, &p, &lid(&p, "1.2"), &FlowOptions::default()).unwrap();
    assert_eq!(chain.pages.len(), 1, "{:?}", chain.pages);
    let o = origins(&p, "1.2");
    assert!(
        !o.warnings
            .iter()
            .any(|w| w.contains("initiator do CDP não é preservado")),
        "{:?}",
        o.warnings
    );
}

// ---- Rodada 7: cadeia na rodada do consumidor e scripts fora dos passos -----------------------

/// Um valor constante do protocolo (STAMP=INIT) tem produtores em todas as rodadas.
/// A cadeia usa o produtor da própria rodada do consumidor (produced ou reissued);
/// a rodada anterior não entra por causa dele.
#[test]
fn r7_chain_uses_the_producer_of_the_targets_round() {
    let mut s = S::default();
    for (base, prefix) in [(1.0, "1"), (5.0, "2")] {
        let id = |k: usize| format!("{prefix}.{k}");
        s.req(
            &id(1),
            base,
            "https://x.test/app/entry",
            "GET",
            R {
                resp: Some("<html>entrada</html>"),
                ..Default::default()
            },
        );
        s.req(
            &id(2),
            base + 0.1,
            "https://x.test/app/cscform.html",
            "GET",
            R {
                headers: Some(json!({"referer": "https://x.test/app/entry"})),
                resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
                ..Default::default()
            },
        );
        s.req(
            &id(3),
            base + 0.2,
            "https://x.test/app/Connector",
            "POST",
            R {
                headers: Some(json!({"referer": "https://x.test/app/cscform.html"})),
                body: Some("XML=init&STAMP=INIT"),
                resp: Some("<html>ok</html>"),
                ..Default::default()
            },
        );
    }
    let b = s.build();
    let target = lid(&b, "2.3");
    let chain = priming_chain(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let steps: Vec<String> = chain.steps.iter().map(|s| s.request_id.clone()).collect();
    assert!(
        steps.contains(&lid(&b, "2.2")),
        "o produtor mais recente é a cscform da rodada 2: {steps:?}"
    );
    assert!(
        !steps.contains(&lid(&b, "1.2")),
        "a cscform da rodada 1 não é passo da rodada 2: {steps:?}"
    );
    let pages: Vec<String> = chain.pages.iter().map(|s| s.request_id.clone()).collect();
    assert_eq!(
        pages,
        vec![lid(&b, "2.1"), lid(&b, "2.2")],
        "pages só da rodada do consumidor"
    );
    // As origens continuam listando todos os produtores, com o status de hoje.
    let o = origins(&b, "2.3");
    let st = entry(&o, "STAMP");
    assert_eq!(st.status, OriginStatus::Origin);
    let produced: Vec<&str> = st
        .evidences
        .iter()
        .filter(|e| e.role == Role::Produced)
        .map(|e| e.request_id.as_str())
        .collect();
    assert_eq!(
        produced,
        vec![lid(&b, "1.2")],
        "origem continua na rodada 1"
    );
    assert!(
        st.evidences
            .iter()
            .any(|e| e.role == Role::Reissued && e.request_id == lid(&b, "2.2")),
        "o produtor da rodada 2 é reemissão (INIT circulou): {:?}",
        st.evidences
            .iter()
            .map(|e| (e.role, e.request_id.as_str()))
            .collect::<Vec<_>>()
    );
}

/// Recurso estático nunca é passo: na forma real, nenhum `.js` entra em `steps`.
#[test]
fn r7_real_shape_steps_have_no_static_script() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/detran-pb-real-shape/real-shape-1round.har");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let b = scrapelens_core::import_har(&bytes)
        .expect("importa HAR")
        .bundle;
    let chain = priming_chain(&b.session, &b, "har-0026", &FlowOptions::default()).unwrap();
    let scripts: Vec<&str> = chain
        .steps
        .iter()
        .map(|s| s.url.split('?').next().unwrap_or(""))
        .filter(|p| p.ends_with(".js") || p.ends_with(".mjs"))
        .collect();
    assert!(scripts.is_empty(), "scripts em steps: {scripts:?}");
    let pages: std::collections::BTreeSet<&str> =
        chain.pages.iter().map(|p| p.request_id.as_str()).collect();
    assert_eq!(
        pages,
        ["har-0001", "har-0005", "har-0012", "har-0019"]
            .into_iter()
            .collect()
    );
}

/// Rodadas: frame iniciado pelo parser (cscform/JLIBS) não é entrada de rodada,
/// nem serve de fronteira. Duas rodadas de verdade continuam duas.
#[test]
fn r7_compare_rounds_ignore_parser_frames_when_detecting_the_entry() {
    let build = || {
        let mut s = S::default();
        for (base, n) in [(1.0, 1), (5.0, 2)] {
            let id = |k: usize| format!("{n}.{k}");
            s.req(
                &format!("{n}.0"),
                base - 0.2,
                "https://x.test/app/cscform.html",
                "GET",
                R {
                    resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
                    initiator: Some(json!({"type": "parser", "url": "https://x.test/app/entry"})),
                    ..Default::default()
                },
            );
            s.req(
                &id(1),
                base,
                "https://x.test/app/entry",
                "GET",
                R {
                    resp: Some("<html>entrada</html>"),
                    ..Default::default()
                },
            );
            s.req(
                &id(2),
                base + 0.1,
                "https://x.test/app/Connector",
                "POST",
                R {
                    body: Some("XML=init&STAMP=1000"),
                    resp: Some("<html>ok</html>"),
                    ..Default::default()
                },
            );
            s.req(
                &id(3),
                base + 0.2,
                "https://x.test/app/Connector",
                "POST",
                R {
                    body: Some("XML=consulta&STAMP=1000"),
                    resp: Some("<html>ok</html>"),
                    ..Default::default()
                },
            );
        }
        s.build()
    };
    let (a, b) = (build(), build());
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    assert_eq!(r.rounds.len(), 2, "{:?}", r.unpaired_rounds);
    assert!(r.unpaired_rounds.is_empty(), "{:?}", r.unpaired_rounds);
    let entry = r.entry_request.as_deref().unwrap_or("");
    assert!(
        entry.ends_with("|/app/entry"),
        "entrada deve ser o documento da aplicação, não o frame: {entry}"
    );
}

/// F3: a cadeia de um alvo da 2ª rodada não repete a 1ª. A fronteira é a
/// ocorrência mais recente do documento de entrada (o POST do Connector tem
/// Referer do próprio Connector, então a raiz de Referer não basta).
#[test]
fn r7_chain_of_the_second_round_does_not_repeat_the_first() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/detran-pb-real-shape/real-shape-2rounds.har");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let b = scrapelens_core::import_har(&bytes)
        .expect("importa HAR")
        .bundle;
    // har-0031 é o easynat-app que abre a 2ª rodada; har-0056 é o alvo.
    let chain = priming_chain(&b.session, &b, "har-0056", &FlowOptions::default()).unwrap();
    let round_one: Vec<&str> = chain
        .steps
        .iter()
        .map(|s| s.request_id.as_str())
        .filter(|id| *id < "har-0031")
        .collect();
    assert!(round_one.is_empty(), "passos da rodada 1: {round_one:?}");
    assert!(
        chain.steps.iter().any(|s| s.request_id == "har-0031"),
        "a entrada da rodada 2 é passo: {:?}",
        chain
            .steps
            .iter()
            .map(|s| &s.request_id)
            .collect::<Vec<_>>()
    );
    let pages: std::collections::BTreeSet<&str> =
        chain.pages.iter().map(|p| p.request_id.as_str()).collect();
    assert_eq!(
        pages,
        ["har-0031", "har-0035", "har-0042", "har-0049"]
            .into_iter()
            .collect(),
        "pages só da rodada do alvo"
    );
}

/// F3: dentro da rodada, uma constante reemitida por várias páginas (STAMP=INIT)
/// não repete cada reemissão. O passo é o primeiro produtor da rodada; a página
/// que só reemite o mesmo valor fica em `pages` (contexto), não em `steps`.
#[test]
fn r7_chain_does_not_repeat_reissued_constants() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/app/entry",
        "GET",
        R {
            resp: Some("<html>entrada</html>"),
            ..Default::default()
        },
    );
    // Primeiro produtor de STAMP=INIT na rodada.
    s.req(
        "1.2",
        1.1,
        "https://x.test/app/form1.html",
        "GET",
        R {
            headers: Some(json!({"referer": "https://x.test/app/entry"})),
            resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
            ..Default::default()
        },
    );
    // POST que também devolve um valor de negócio consumido pelo alvo.
    s.req(
        "1.3",
        1.2,
        "https://x.test/app/Connector",
        "POST",
        R {
            headers: Some(json!({"referer": "https://x.test/app/form1.html"})),
            body: Some("XML=init&STAMP=INIT"),
            resp: Some("<html><input type=hidden name=placa value=TOKEN987654321></html>"),
            ..Default::default()
        },
    );
    // Segunda página só reemite a mesma constante.
    s.req(
        "1.4",
        1.3,
        "https://x.test/app/form2.html",
        "GET",
        R {
            headers: Some(json!({"referer": "https://x.test/app/entry"})),
            resp: Some("<html><input type=hidden name=STAMP value=INIT></html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.5",
        1.4,
        "https://x.test/app/Connector",
        "POST",
        R {
            headers: Some(json!({"referer": "https://x.test/app/form2.html"})),
            body: Some("XML=cmd&STAMP=INIT&placa=TOKEN987654321"),
            resp: Some("<html>ok</html>"),
            ..Default::default()
        },
    );
    let b = s.build();
    let chain = priming_chain(&b.session, &b, &lid(&b, "1.5"), &FlowOptions::default()).unwrap();
    let steps: Vec<String> = chain.steps.iter().map(|s| s.request_id.clone()).collect();
    assert_eq!(
        steps,
        vec![lid(&b, "1.2"), lid(&b, "1.3")],
        "só o primeiro produtor da constante e o produtor do token"
    );
    let pages: Vec<String> = chain.pages.iter().map(|p| p.request_id.clone()).collect();
    assert!(
        pages.contains(&lid(&b, "1.4")),
        "a página que só reemite fica como contexto: {pages:?}"
    );
    // As origens continuam listando todos os produtores da constante.
    let o = origins(&b, "1.5");
    let st = entry(&o, "STAMP");
    let reissued: Vec<&str> = st
        .evidences
        .iter()
        .filter(|e| e.role == Role::Reissued)
        .map(|e| e.request_id.as_str())
        .collect();
    assert_eq!(reissued, vec![lid(&b, "1.4")], "{:?}", st.evidences);
}

/// Exceção da rodada: um valor FORTE cujo único produtor ficou na rodada anterior
/// (cookie definido uma única vez) entra na cadeia. Fragmentos médios de XML não
/// justificam subir (ver o teste da constante reemitida).
#[test]
fn r7_chain_climbs_to_a_one_time_cookie_from_the_previous_round() {
    let mk = |started: &str,
              method: &str,
              url: &str,
              req_headers: Value,
              req_cookies: Value,
              resp_headers: Value,
              text: &str| {
        json!({
            "startedDateTime": started, "time": 1,
            "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1",
                "headers": req_headers, "queryString": [], "cookies": req_cookies,
                "headersSize": -1, "bodySize": 0},
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                "headers": resp_headers, "cookies": [],
                "content": {"size": text.len(), "mimeType": "text/html", "text": text},
                "redirectURL": "", "headersSize": -1, "bodySize": text.len()},
            "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}
        })
    };
    let html = json!([{"name": "content-type", "value": "text/html"}]);
    let with_cookie = json!([
        {"name": "content-type", "value": "text/html"},
        {"name": "set-cookie", "value": "ONCE=abc12345; Path=/"}
    ]);
    let bytes = serde_json::to_vec(&json!({"log": {"version": "1.2",
    "creator": {"name": "WebInspector", "version": "537.36"},
    "entries": [
        mk("2026-10-26T20:00:00.000Z", "GET", "https://x.test/app/entry",
            json!([]), json!([]), with_cookie, "<html>entrada</html>"),
        // 2ª rodada: mesmo documento de entrada, sem reemitir o cookie.
        mk("2026-10-26T20:00:05.000Z", "GET", "https://x.test/app/entry",
            json!([]), json!([]), html.clone(), "<html>entrada 2</html>"),
        mk("2026-10-26T20:00:06.000Z", "POST", "https://x.test/app/Connector",
            json!([{"name": "Cookie", "value": "ONCE=abc12345"}]),
            json!([{"name": "ONCE", "value": "abc12345"}]),
            html, "<html>ok</html>"),
    ]}}))
    .unwrap();
    let b = scrapelens_core::import_har(&bytes)
        .expect("importa HAR")
        .bundle;
    let target = b.session.requests[2].id.clone();
    let chain = priming_chain(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let steps: Vec<&str> = chain.steps.iter().map(|s| s.request_id.as_str()).collect();
    assert_eq!(
        steps,
        vec![b.session.requests[0].id.as_str()],
        "o cookie de uma vez só vem da rodada anterior"
    );
    let o = value_origins(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let once = entry(&o, "ONCE");
    assert_eq!(once.status, OriginStatus::Origin);
    assert_eq!(once.evidences[0].kind, EvidenceKind::CookieJar);
}

/// Item 2 da revisão 8 (cr3): o SESSIONID só é produzido no easynat-app da rodada 1
/// como value-match do valor INTEIRO de um campo. Sem produtor na rodada do alvo,
/// a cadeia sobe para esse produtor em vez de sair sem ele.
#[test]
fn r8_chain_climbs_to_a_whole_value_session_id_from_the_previous_round() {
    let mut s = S::default();
    s.req(
        "1.0",
        1.0,
        "http://h.test/easynat-app",
        "GET",
        R {
            resp: Some(r#"<script>var m_currentSessionId="CSAN00000_000000000001";</script>"#),
            ..Default::default()
        },
    );
    s.req(
        "1.1",
        2.0,
        "http://h.test/connector",
        "POST",
        R {
            body: Some("SESSIONID=CSAN00000_000000000001&n=1"),
            resp: Some("<input type=hidden name=STAMP value=2006>"),
            ..Default::default()
        },
    );
    s.req(
        "2.0",
        4.0,
        "http://h.test/easynat-app",
        "GET",
        R {
            resp: Some("<html>x</html>"),
            ..Default::default()
        },
    );
    s.req(
        "2.1",
        5.0,
        "http://h.test/connector",
        "POST",
        R {
            body: Some("SESSIONID=CSAN00000_000000000001&STAMP=2006&n=2"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let target = lid(&b, "2.1");
    let chain = priming_chain(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let steps: Vec<&str> = chain.steps.iter().map(|s| s.request_id.as_str()).collect();
    assert!(
        steps.contains(&lid(&b, "1.0").as_str()),
        "value-match do valor inteiro sobe: {steps:?}"
    );
    assert!(
        steps.contains(&lid(&b, "1.1").as_str()),
        "STAMP forte também sobe: {steps:?}"
    );
    let o = origins(&b, "2.1");
    assert_eq!(entry(&o, "SESSIONID").status, OriginStatus::Origin);
}

/// Item 2 da revisão 8: fragmento de campo opaco não sobe de rodada, mas não
/// desaparece em silêncio: fica em `unresolved` com o motivo e o produtor antigo.
#[test]
fn r8_chain_withholds_opaque_fragment_and_reports_it() {
    let mut s = S::default();
    s.req(
        "1.0",
        1.0,
        "http://h.test/easynat-app",
        "GET",
        R {
            resp: Some("<html>entrada</html>"),
            ..Default::default()
        },
    );
    s.req(
        "1.1",
        2.0,
        "http://h.test/connector",
        "POST",
        R {
            body: Some("n=1"),
            resp: Some("<input type=hidden name=piece value=FRAGMENT01>"),
            ..Default::default()
        },
    );
    s.req(
        "2.0",
        4.0,
        "http://h.test/easynat-app",
        "GET",
        R {
            resp: Some("<html>entrada 2</html>"),
            ..Default::default()
        },
    );
    s.req(
        "2.1",
        5.0,
        "http://h.test/connector",
        "POST",
        R {
            body: Some("blob=QQQQQQQQQQFRAGMENT01WWWWWWWWWWZZZZZZZZZZ"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let target = lid(&b, "2.1");
    let chain = priming_chain(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let steps: Vec<&str> = chain.steps.iter().map(|s| s.request_id.as_str()).collect();
    assert!(
        !steps.contains(&lid(&b, "1.1").as_str()),
        "fragmento opaco não sobe: {steps:?}"
    );
    let old = lid(&b, "1.1");
    assert!(
        chain
            .unresolved
            .iter()
            .any(|u| u.label == format!("produtor só em rodada anterior ({old})")),
        "motivo presente: {:?}",
        chain
            .unresolved
            .iter()
            .map(|u| &u.label)
            .collect::<Vec<_>>()
    );
}

/// Item 3 da revisão 8: corpo JS com atribuição a membro (`window.cfg={"tok":"V"}`)
/// não é formulário. Sem a guarda de mídia, `=` + nome com ponto fazia o objeto
/// virar um único campo e o literal interno deixava de ser candidato.
#[test]
fn r8_js_member_assignment_literal_is_a_candidate() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "http://h.test/session.js?_=1",
        "GET",
        R {
            resp: Some(r#"window.cfg={"tok":"SHAREDVALUE123456"};"#),
            resp_type: Some("application/javascript"),
            ..Default::default()
        },
    );
    s.req(
        "1.2",
        2.0,
        "http://h.test/go",
        "POST",
        R {
            body: Some("x=SHAREDVALUE123456"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    let o = origins(&b, "1.2");
    let x = entry(&o, "x");
    assert_eq!(x.status, OriginStatus::Origin);
    assert_eq!(x.evidences[0].kind, EvidenceKind::ValueMatch);
    assert_eq!(x.evidences[0].request_id, lid(&b, "1.1"));
}

/// Item 4 da revisão 8: nome de negócio colado a uma letra, no meio de um token
/// de campo opaco e seguido de valor no formato (`…aplacaQWE1234`), vazava sem
/// redação nem aviso. Agora redige e conta, como no `v_placa`.
#[test]
fn r8_business_name_glued_to_letters_is_redacted() {
    let mut s = S::default();
    s.req(
        "1.1",
        1.0,
        "https://x.test/a",
        "POST",
        R {
            body: Some("XML=aaaaaplacaQWE1234&STAMP=2004"),
            resp: Some("ok"),
            ..Default::default()
        },
    );
    let b = s.build();
    assert!(all_text(&b).contains("QWE1234"));
    let export = sanitize_bundle(&b, &SanitizeOptions::default());
    let after = all_text(&export.bundle);
    assert!(!after.contains("QWE1234"), "placa colada vazou: {after}");
    assert!(
        export
            .redactions
            .get("business:placa")
            .copied()
            .unwrap_or(0)
            >= 1,
        "contagem: {:?}",
        export.redactions
    );
}
