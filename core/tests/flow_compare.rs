//! Origem dos valores, cadeia de priming e comparação (docs/09), mini-fixtures próprias.

use scrapelens_core::compare::{compare_sessions, CompareOptions, DynamicKind, FieldClass};
use scrapelens_core::export::curl::to_curl_with_origins;
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::export::ExportOptions;
use scrapelens_core::flow::{
    priming_chain, value_origins, ConsumedScope, EvidenceKind, FlowOptions, OriginStatus, Role,
    StepClass,
};
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use serde_json::{json, Value};

const FORM: &str = "application/x-www-form-urlencoded";

#[derive(Default)]
struct Flow {
    events: Vec<Value>,
    bodies: Vec<Value>,
    n: usize,
}

impl Flow {
    /// Uma requisição completa (pedido + resposta) no instante `ts`.
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        method: &str,
        url: &str,
        headers: Value,
        post: Option<&str>,
        resp_headers: Value,
        resp_body: Option<&str>,
        ts: f64,
    ) -> String {
        self.n += 1;
        let id = format!("{}.1", self.n);
        let mut h = headers;
        if post.is_some() {
            h["content-type"] = json!(FORM);
        }
        self.events.push(json!({"method": "Network.requestWillBeSent", "params": {
            "requestId": id, "loaderId": "L", "timestamp": ts, "wallTime": 1793046000.0 + ts,
            "request": {"url": url, "method": method, "headers": h, "postData": post, "hasPostData": post.is_some()},
            "type": "XHR", "frameId": "F"}}));
        let mut rh = resp_headers;
        if rh.get("content-type").is_none() {
            rh["content-type"] = json!("text/html");
        }
        self.events.push(json!({"method": "Network.responseReceived", "params": {
            "requestId": id, "loaderId": "L", "timestamp": ts + 0.01, "type": "XHR",
            "response": {"url": url, "status": 200, "statusText": "", "headers": rh, "protocol": "http/1.1"}}}));
        self.events.push(json!({"method": "Network.loadingFinished", "params": {"requestId": id, "timestamp": ts + 0.02, "encodedDataLength": 1}}));
        if let Some(post) = post {
            self.bodies.push(body_line(&id, "request", post));
        }
        if let Some(body) = resp_body {
            self.bodies.push(body_line(&id, "response", body));
        }
        id
    }

    fn bundle(&self) -> SessionBundle {
        let jsonl = |v: &[Value]| {
            v.iter()
                .map(|x| format!("{x}\n"))
                .collect::<String>()
                .into_bytes()
        };
        let capture = parse_cdp_jsonl(&jsonl(&self.events)).unwrap();
        let (mut session, _) = build_cdp_session(&capture);
        let mut attachments = Default::default();
        apply_cdp_bodies(&mut session, &mut attachments, &jsonl(&self.bodies));
        let mut bundle = SessionBundle::new(session);
        bundle.attachments = attachments;
        bundle
    }
}

fn body_line(id: &str, kind: &str, data: &str) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":0,"kind":kind,"state":"captured","encoding":"utf8",
        "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":1.0})
}

fn logical(b: &SessionBundle, cdp_id: &str) -> String {
    b.session
        .requests
        .iter()
        .find(|r| r.cdp.as_ref().and_then(|c| c.request_id.as_deref()) == Some(cdp_id))
        .unwrap()
        .id
        .clone()
}

fn find<'a>(
    o: &'a scrapelens_core::flow::ValueOrigins,
    scope: ConsumedScope,
    field: &str,
) -> &'a scrapelens_core::flow::ValueOrigin {
    o.values
        .iter()
        .find(|v| v.scope == scope && v.field == field && v.parent.is_none())
        .unwrap_or_else(|| {
            panic!(
                "{field} ausente: {:?}",
                o.values.iter().map(|v| &v.field).collect::<Vec<_>>()
            )
        })
}

const SID: &str = "CSAN00000_000000000001";

/// page → TSPD → init (STAMP/delta) → consulta (usa tudo).
fn detran_like(sid: &str, ck: &str, stamp: &str, delta: &str, plate: &str) -> Flow {
    let mut f = Flow::default();
    let html = format!("<script>\nvar m_currentSessionId = \"{sid}\";\n</script>");
    f.step(
        "GET",
        "https://x.test/app/entry?op=S37",
        json!({}),
        None,
        json!({"set-cookie": format!("JSESSIONID={ck}; Path=/\nTS01ab=0189{ck}; Path=/")}),
        Some(&html),
        1.0,
    );
    f.step(
        "GET",
        "https://x.test/TSPD/?type=18",
        json!({"cookie": format!("JSESSIONID={ck}; TS01ab=0189{ck}")}),
        None,
        json!({}),
        Some("bin"),
        2.0,
    );
    f.step(
        "POST",
        "https://x.test/app/Connector",
        json!({"cookie": format!("JSESSIONID={ck}; TS01ab=0189{ck}")}),
        Some(&format!("SESSIONID={sid}&XML=init{delta}0&STAMP=1")),
        json!({}),
        Some(&format!(
            "XML=lp08nextPagek05v_tmpx08{delta}1&STAMP={stamp}"
        )),
        3.0,
    );
    f.step("POST", "https://x.test/app/Connector",
        json!({"cookie": format!("JSESSIONID={ck}; TS01ab=0189{ck}")}),
        Some(&format!("SESSIONID={sid}&PAGEINITPARAM=&XML=cmd_consultar_placa_v_placa{plate}x08{delta}1&STAMP={stamp}")),
        json!({}), Some("XML=ok&STAMP=9"), 4.0);
    f
}

#[test]
fn origins_cookie_jar_same_field_value_match_and_none() {
    let b = detran_like(SID, "JSESS0000000000000001", "2001", "DLTA", "TST0T00").bundle();
    let target = logical(&b, "4.1");
    let o = value_origins(&b.session, &b, &target, &FlowOptions::default()).unwrap();

    let ck = find(&o, ConsumedScope::Cookie, "JSESSIONID");
    assert_eq!(ck.status, OriginStatus::Origin);
    assert_eq!(ck.evidences[0].kind, EvidenceKind::CookieJar);
    assert_eq!(ck.evidences[0].request_id, logical(&b, "1.1"));

    let sid = find(&o, ConsumedScope::Body, "SESSIONID");
    assert_eq!(sid.status, OriginStatus::Origin);
    assert_eq!(sid.evidences[0].kind, EvidenceKind::ValueMatch);
    assert_eq!(
        sid.evidences[0].field.as_deref(),
        Some("m_currentSessionId")
    );
    assert_eq!(sid.evidences[0].request_id, logical(&b, "1.1"));

    // STAMP curto vem da resposta anterior pelo mesmo nome (same-field).
    let stamp = find(&o, ConsumedScope::Body, "STAMP");
    assert_eq!(stamp.evidences[0].kind, EvidenceKind::SameField);
    assert_eq!(stamp.evidences[0].request_id, logical(&b, "3.1"));
    assert_eq!(stamp.evidences[0].role, Role::Produced);

    // vazio nunca casa; fica "sem origem observada"
    assert_eq!(
        find(&o, ConsumedScope::Body, "PAGEINITPARAM").status,
        OriginStatus::None
    );

    // o XML é composto: a sessão aparece como trecho com origem, a placa não
    let xml = find(&o, ConsumedScope::Body, "XML");
    assert_eq!(xml.status, OriginStatus::Composite);
    let parts: Vec<_> = o
        .values
        .iter()
        .filter(|v| v.parent.as_deref() == Some("XML"))
        .collect();
    assert!(
        parts.iter().any(|p| p.value.contains("x08DLTA1")),
        "{:?}",
        parts.iter().map(|p| &p.value).collect::<Vec<_>>()
    );
    assert!(
        !parts
            .iter()
            .any(|p| !p.evidences.is_empty() && p.value.contains("TST0T00")),
        "placa não tem origem"
    );
    let gap = parts
        .iter()
        .find(|p| p.value.contains("TST0T00"))
        .expect("trecho da placa");
    assert_eq!(gap.status, OriginStatus::None);
    assert_eq!(gap.label, "sem origem observada");
}

#[test]
fn short_coincidence_without_same_name_is_not_an_origin() {
    let mut f = Flow::default();
    f.step(
        "GET",
        "https://x.test/a",
        json!({"x-flag": "1"}),
        None,
        json!({"x-other": "7"}),
        Some("<p>seven 7 \"short\"</p>"),
        1.0,
    );
    f.step(
        "POST",
        "https://x.test/b",
        json!({}),
        Some("page=7&mode=short&n=1"),
        json!({}),
        None,
        2.0,
    );
    let b = f.bundle();
    let o = value_origins(&b.session, &b, &logical(&b, "2.1"), &FlowOptions::default()).unwrap();
    for field in ["page", "mode", "n"] {
        let v = find(&o, ConsumedScope::Body, field);
        assert_eq!(v.status, OriginStatus::None, "{field}");
        assert!(v.evidences.is_empty());
    }
}

#[test]
fn ambiguity_lists_all_candidates_and_marks_oldest_and_ties_are_excluded() {
    let token = "TOKEN-VALUE-ABCDEF123";
    let mut f = Flow::default();
    f.step(
        "GET",
        "https://x.test/a",
        json!({}),
        None,
        json!({"x-token": token}),
        Some("a"),
        1.0,
    );
    f.step(
        "GET",
        "https://x.test/b",
        json!({}),
        None,
        json!({}),
        Some(&format!("var t = \"{token}\";")),
        2.0,
    );
    f.step(
        "GET",
        "https://x.test/tie",
        json!({}),
        None,
        json!({"x-token": token}),
        Some("t"),
        3.0,
    );
    f.step(
        "POST",
        "https://x.test/c",
        json!({}),
        Some(&format!("auth={token}")),
        json!({}),
        None,
        3.0,
    );
    let b = f.bundle();
    let o = value_origins(&b.session, &b, &logical(&b, "4.1"), &FlowOptions::default()).unwrap();
    let v = find(&o, ConsumedScope::Body, "auth");
    assert_eq!(v.status, OriginStatus::Ambiguous);
    let produced: Vec<_> = v
        .evidences
        .iter()
        .filter(|e| e.role == Role::Produced)
        .collect();
    assert_eq!(produced.len(), 2);
    assert_eq!(
        v.evidences[v.oldest.unwrap()].request_id,
        logical(&b, "1.1")
    );
    assert_eq!(o.ties, vec![format!("{}-a1", logical(&b, "3.1"))]);
    assert!(
        v.evidences
            .iter()
            .all(|e| e.request_id != logical(&b, "3.1")),
        "empate não é produtor"
    );
}

#[test]
fn chain_is_ordered_with_reasons_and_separates_protection() {
    let b = detran_like(SID, "JSESS0000000000000001", "2001", "DLTA", "TST0T00").bundle();
    let chain =
        priming_chain(&b.session, &b, &logical(&b, "4.1"), &FlowOptions::default()).unwrap();
    let ids: Vec<_> = chain.steps.iter().map(|s| s.request_id.clone()).collect();
    assert_eq!(ids, vec![logical(&b, "1.1"), logical(&b, "3.1")]);
    assert!(chain
        .steps
        .iter()
        .all(|s| s.class == StepClass::Application && !s.reasons.is_empty()));
    assert!(chain.steps[0]
        .reasons
        .iter()
        .any(|r| r.field == "SESSIONID"));
    assert!(chain.steps[1].reasons.iter().any(|r| r.field == "STAMP"));
    assert_eq!(chain.protection.len(), 1);
    assert!(chain.protection[0].url.contains("/TSPD/"));
    assert!(!ids.contains(&chain.protection[0].request_id));
    assert!(
        !chain.unresolved.iter().any(|u| u.field == "PAGEINITPARAM"),
        "vazios não são pendência"
    );
}

#[test]
fn compare_classifies_dynamic_runtime_static_and_pairs_same_url_by_order() {
    let a = detran_like(SID, "JSESS0000000000000001", "2001", "DLTA", "TST0T00").bundle();
    let b = detran_like(
        "CSAN00000_000000000002",
        "JSESS0000000000000002",
        "3001",
        "DLTB",
        "TST0T55",
    )
    .bundle();
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    // L6: por padrão só a aplicação é alinhada; /TSPD/ vai para o grupo `protection`
    assert_eq!(r.pairs.len(), 3);
    assert_eq!(r.groups.len(), 1);
    assert_eq!(r.groups[0].kind, "protection");
    assert!(r.only_in_a.is_empty() && r.only_in_b.is_empty());
    // as duas requisições POST com a mesma URL são pareadas em ordem, sem cruzar
    assert_eq!(r.pairs[1].a.request_id, logical(&a, "3.1"));
    assert_eq!(r.pairs[1].b.request_id, logical(&b, "3.1"));
    assert_eq!(r.pairs[2].b.request_id, logical(&b, "4.1"));
    assert!(r.pairs.iter().all(|p| !p.out_of_order));

    let consulta = &r.pairs[2];
    let field = |scope, name: &str| {
        consulta
            .fields
            .iter()
            .find(|f| f.scope == scope && f.field == name)
            .unwrap()
    };
    let sid = field(ConsumedScope::Body, "SESSIONID");
    assert_eq!(
        (sid.class, sid.dynamic_kind),
        (FieldClass::Dynamic, Some(DynamicKind::Runtime))
    );
    assert_eq!(sid.origin.as_ref().unwrap().request_id, logical(&b, "1.1"));
    let stamp = field(ConsumedScope::Body, "STAMP");
    assert_eq!(stamp.dynamic_kind, Some(DynamicKind::Runtime));
    assert_eq!(stamp.origin.as_ref().unwrap().kind, EvidenceKind::SameField);
    let ck = field(ConsumedScope::Cookie, "JSESSIONID");
    assert_eq!(ck.origin.as_ref().unwrap().kind, EvidenceKind::CookieJar);
    assert_eq!(
        field(ConsumedScope::Body, "PAGEINITPARAM").class,
        FieldClass::Static
    );
    // XML: o delta é runtime; a placa é dinâmica sem origem; a constante não aparece
    let xml = field(ConsumedScope::Body, "XML");
    assert_eq!(xml.dynamic_kind, Some(DynamicKind::Composite));
    assert!(
        xml.parts
            .iter()
            .any(|p| p.dynamic_kind == DynamicKind::Runtime && p.b.contains("DLTB1")),
        "{:?}",
        xml.parts
    );
    assert!(
        xml.parts
            .iter()
            .any(|p| p.dynamic_kind == DynamicKind::NoOrigin && p.b.contains("TST0T55")),
        "{:?}",
        xml.parts
    );
    assert!(
        xml.parts
            .iter()
            .any(|p| p.class == FieldClass::Static && p.b.contains("cmd_consultar")),
        "constante aparece como estática"
    );
    assert!(
        !xml.parts
            .iter()
            .any(|p| p.class == FieldClass::Dynamic && p.b.contains("cmd_consultar")),
        "constante não é dinâmica"
    );
}

#[test]
fn compare_reports_leftovers_repeated_fields_and_no_alphabetical_sort() {
    let mut fa = Flow::default();
    fa.step(
        "GET",
        "https://x.test/p?z=1&a=2&z=3",
        json!({}),
        None,
        json!({}),
        Some("x"),
        1.0,
    );
    fa.step(
        "GET",
        "https://x.test/only-a",
        json!({}),
        None,
        json!({}),
        Some("x"),
        2.0,
    );
    let mut fb = Flow::default();
    fb.step(
        "GET",
        "https://x.test/p?z=1&a=9&z=4",
        json!({}),
        None,
        json!({}),
        Some("x"),
        1.0,
    );
    fb.step(
        "GET",
        "https://x.test/only-b",
        json!({}),
        None,
        json!({}),
        Some("x"),
        2.0,
    );
    let (a, b) = (fa.bundle(), fb.bundle());
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    assert_eq!(r.only_in_a.len(), 1);
    assert_eq!(r.only_in_b.len(), 1);
    let names: Vec<_> = r.pairs[0]
        .fields
        .iter()
        .map(|f| (f.field.clone(), f.occurrence, f.class))
        .collect();
    assert_eq!(
        names,
        vec![
            ("z".to_string(), 0, FieldClass::Static),
            ("a".to_string(), 0, FieldClass::Dynamic),
            ("z".to_string(), 1, FieldClass::Dynamic),
        ]
    );
    assert_eq!(
        r.pairs[0].fields[1].dynamic_kind,
        Some(DynamicKind::NoOrigin)
    );
}

#[test]
fn sanitized_session_declares_redacted_values_and_leaks_nothing() {
    let b = detran_like(SID, "JSESS0000000000000001", "2001", "DLTA", "TST0T00").bundle();
    let s = sanitize_bundle(&b, &SanitizeOptions::default()).bundle;
    let target = logical(&s, "4.1");
    let o = value_origins(&s.session, &s, &target, &FlowOptions::default()).unwrap();
    assert!(o.redacted_values > 0);
    assert!(o.warnings.iter().any(|w| w.contains("redigido")));
    let json = serde_json::to_string(&o).unwrap();
    assert!(!json.contains(SID) && !json.contains("JSESS0000000000000001"));
    let c = compare_sessions(&s.session, &s, &s.session, &s, &CompareOptions::default());
    assert!(c.redacted_fields > 0);
    assert!(c.warnings.iter().any(|w| w.contains("redigido")));
}

#[test]
fn export_annotates_runtime_origins_without_changing_the_command() {
    let b = detran_like(SID, "JSESS0000000000000001", "2001", "DLTA", "TST0T00").bundle();
    let id = logical(&b, "4.1");
    let request = b.session.find_request(&id).unwrap();
    let origins = value_origins(&b.session, &b, &id, &FlowOptions::default()).unwrap();
    let bytes = scrapelens_core::export::request_body_bytes(&b, request);
    let plain = to_curl_with_origins(request, bytes, &ExportOptions::default(), None)
        .unwrap()
        .text;
    let annotated = to_curl_with_origins(request, bytes, &ExportOptions::default(), Some(&origins))
        .unwrap()
        .text;
    assert!(annotated.contains("obter em runtime (origem:"));
    assert!(annotated.contains("SESSIONID"));
    let strip = |t: &str| {
        t.lines()
            .filter(|l| !l.starts_with("# obter em runtime"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(strip(&annotated), strip(&plain), "o comando não muda");
}

#[test]
fn unobservable_previous_responses_are_reported_for_values_without_origin() {
    let mut f = Flow::default();
    f.step(
        "GET",
        "https://x.test/page",
        json!({}),
        None,
        json!({}),
        Some("<p>nada</p>"),
        1.0,
    );
    // o corpo da resposta de 2.1 não foi capturado
    f.step(
        "POST",
        "https://x.test/filtro",
        json!({}),
        Some("cmd=filtro&STAMP=2004"),
        json!({}),
        None,
        2.0,
    );
    f.step(
        "POST",
        "https://x.test/consulta",
        json!({}),
        Some("cmd=consulta&STAMP=2005"),
        json!({}),
        None,
        3.0,
    );
    let mut b = f.bundle();
    // simula `unavailable` na resposta de 2.1 (CDP: recurso despejado)
    let id = logical(&b, "2.1");
    for r in &mut b.session.requests {
        if r.id == id {
            let body =
                scrapelens_core::Body::unavailable("No resource with given identifier found");
            r.attempts[0].response_body = body.clone();
            r.response_body = body;
        }
    }
    let target = logical(&b, "3.1");
    let o = value_origins(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let stamp = find(&o, ConsumedScope::Body, "STAMP");
    assert_eq!(stamp.status, OriginStatus::None);
    assert_eq!(stamp.unobservable.len(), 1);
    assert_eq!(stamp.unobservable[0].request_id, id);
    assert_eq!(stamp.unobservable[0].state, "unavailable");
    assert!(stamp.unobservable[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("No resource"));
    assert_eq!(
        stamp.label,
        "sem origem observada; 1 resposta(s) anterior(es) sem corpo observável"
    );
    // cadeia: pendência também aponta a resposta sem corpo
    let chain = priming_chain(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    let pending = chain
        .unresolved
        .iter()
        .find(|u| u.field == "STAMP")
        .unwrap();
    assert_eq!(pending.unobservable[0].request_id, id);
    assert!(pending.label.contains("sem corpo observável"));
    // valores com origem não ganham a marca
    let ok = value_origins(&b.session, &b, &logical(&b, "2.1"), &FlowOptions::default()).unwrap();
    assert!(ok.values.iter().all(|v| v.unobservable.is_empty()));
}

fn opaque_flow(sid: &str, pid: &str, delta: &str, plate: &str) -> SessionBundle {
    let mut f = Flow::default();
    let html = format!(
        "<script>\nvar m_currentSessionId = \"{sid}\";\nvar m_currentProcessId = \"{pid}\";\n</script>"
    );
    f.step(
        "GET",
        "https://x.test/app/entry",
        json!({}),
        None,
        json!({}),
        Some(&html),
        1.0,
    );
    f.step(
        "POST",
        "https://x.test/app/Connector",
        json!({}),
        Some("XML=lp08nextPage"),
        json!({}),
        Some(&format!("XML=lp0800027nextPagek05v_tmpx08{delta}&STAMP=1")),
        2.0,
    );
    let xml = format!("i2212001705025000005{sid}{pid}SA90001_dummycmd_consultar_placafalsep1400000v_placa{plate}p1300003#f12_selected2.0x08{delta}");
    f.step(
        "POST",
        "https://x.test/app/Connector",
        json!({}),
        Some(&format!("XML={xml}")),
        json!({}),
        Some("XML=ok"),
        3.0,
    );
    f.bundle()
}

#[test]
fn opaque_parts_align_between_the_same_anchors_and_snap_to_known_values() {
    // IDs com prefixo comum longo: só o último dígito difere
    let a = opaque_flow(
        "CSAN00000_000000000001",
        "100000000001",
        "DLTA0005",
        "TST0T00",
    );
    let b = opaque_flow(
        "CSAN00000_000000000002",
        "100000000002",
        "DLTB0005",
        "TST0T02",
    );
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    let pair = r
        .pairs
        .iter()
        .find(|p| p.a.request_id == logical(&a, "3.1"))
        .unwrap();
    let xml = pair.fields.iter().find(|f| f.field == "XML").unwrap();
    let dynamic: Vec<_> = xml
        .parts
        .iter()
        .filter(|p| p.class == FieldClass::Dynamic)
        .collect();
    let texts: Vec<(&str, &str)> = dynamic
        .iter()
        .map(|p| (p.a.as_str(), p.b.as_str()))
        .collect();
    assert_eq!(
        texts,
        vec![
            ("CSAN00000_000000000001", "CSAN00000_000000000002"),
            ("100000000001", "100000000002"),
            ("TST0T00", "TST0T02"),
            ("x08DLTA0005", "x08DLTB0005"),
        ],
        "{:?}",
        xml.parts
    );
    // SESSIONID e processId: runtime com origem na página; delta: resposta anterior; placa: sem origem
    assert_eq!(dynamic[0].dynamic_kind, DynamicKind::Runtime);
    assert_eq!(
        dynamic[0].origin.as_ref().unwrap().request_id,
        logical(&b, "1.1")
    );
    assert_eq!(
        dynamic[1].origin.as_ref().unwrap().request_id,
        logical(&b, "1.1")
    );
    assert_eq!(dynamic[2].dynamic_kind, DynamicKind::NoOrigin);
    assert_eq!(dynamic[2].origin_label, "dinâmico sem origem");
    assert_eq!(
        dynamic[3].origin.as_ref().unwrap().request_id,
        logical(&b, "2.1")
    );
    // âncoras estáticas nunca contêm pedaço de um valor dinâmico
    for p in xml.parts.iter().filter(|p| p.class == FieldClass::Static) {
        for token in ["CSAN00000_00000000000", "TST0T0", "DLT"] {
            assert!(
                !p.a.contains(token),
                "âncora cortou valor conhecido: {}",
                p.a
            );
        }
    }
    // mesmo dado nos dois lados: tudo estático
    let same = compare_sessions(&a.session, &a, &a.session, &a, &CompareOptions::default());
    assert_eq!(same.counts.dynamic, 0);
}

#[test]
fn counts_include_the_dynamic_parts_of_composite_fields() {
    let a = opaque_flow(
        "CSAN00000_000000000001",
        "100000000001",
        "DLTA0005",
        "TST0T00",
    );
    let b = opaque_flow(
        "CSAN00000_000000000002",
        "100000000002",
        "DLTB0005",
        "TST0T02",
    );
    let r = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    let pair = r
        .pairs
        .iter()
        .find(|p| p.a.request_id == logical(&a, "3.1"))
        .unwrap();
    // 4 trechos dinâmicos no XML (3 runtime + 1 sem origem), STAMP/outros fora
    assert_eq!(pair.parts_counts.dynamic, 4);
    assert_eq!(pair.parts_counts.runtime, 3);
    assert_eq!(pair.parts_counts.no_origin, 1);
    assert!(
        pair.counts.no_origin >= 1,
        "a placa aparece em counts: {:?}",
        pair.counts
    );
    for c in [&pair.counts, &r.counts] {
        assert_eq!(c.dynamic, c.runtime + c.no_origin, "total coerente");
    }
    assert_eq!(r.parts_counts.no_origin, 1);
}
