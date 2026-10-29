//! `validate` (captura × trace) e `map_origin`, com sessões sintéticas e hosts diferentes.

use scrapelens_core::compare::{compare_sessions, CompareOptions, OriginMap};
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::import_trace;
use scrapelens_core::validate::{validate, ValidateOptions, ValidationVerdict};
use serde_json::{json, Value};

fn step(
    origin: &str,
    method: &str,
    path: &str,
    post: Option<&str>,
    status: Option<u16>,
    body: &str,
) -> Value {
    json!({
        "method": method, "url": format!("{origin}{path}"),
        "requestHeaders": [["Host", origin.split("://").nth(1).unwrap()], ["User-Agent", if origin.starts_with("https") {"Chrome"} else {"python-requests"}]],
        "requestBody": post.map(|p| json!({"text": p})),
        "status": status,
        "responseHeaders": [["Content-Type", "text/html"]],
        "responseBody": status.map(|_| json!({"text": body})),
    })
}

fn bundle(
    origin: &str,
    stamp: &str,
    last_status: Option<u16>,
    with_last: bool,
    trace: bool,
) -> SessionBundle {
    let mut steps = vec![
        step(
            origin,
            "GET",
            "/app/entry",
            None,
            Some(200),
            "<html>entry</html>",
        ),
        step(
            origin,
            "POST",
            "/app/Connector",
            Some("OP=init&STAMP=INIT"),
            Some(200),
            &format!("OP=ok&STAMP={stamp}"),
        ),
    ];
    if with_last {
        steps.push(step(
            origin,
            "POST",
            "/app/Connector",
            Some(&format!("OP=consulta&STAMP={stamp}&PLACA=ABC1D23")),
            last_status,
            "OP=ok&STAMP=99",
        ));
    }
    let bytes = serde_json::to_vec(
        &json!({"schema":"scrapelens.trace/1","target":"har-0003","complete":true,"steps":steps}),
    )
    .unwrap();
    let mut b = import_trace(&bytes).unwrap().bundle;
    if !trace {
        b.session.session.labels.retain(|l| l != "script-trace");
    }
    b
}

fn run(
    a: &SessionBundle,
    b: &SessionBundle,
    map: Option<OriginMap>,
) -> scrapelens_core::validate::Validation {
    let mut options = ValidateOptions::default();
    options.compare.map_origin = map;
    validate(&a.session, a, &b.session, b, &options)
}

const CAP: &str = "https://real.test";
const TR: &str = "http://127.0.0.1:8791";

#[test]
fn equivalent_trace_with_another_host_and_other_dynamic_values() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let tr = bundle(TR, "BBBB2222", Some(200), true, true);
    let v = run(&cap, &tr, None); // mapeamento automático
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.summary.starts_with("execução equivalente à captura"),
        "{}",
        v.summary
    );
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("mapeadas automaticamente")),
        "{:?}",
        v.warnings
    );
    assert_eq!(v.mapped_origin.as_ref().unwrap().to, TR);
    assert_eq!(v.steps.len(), 3);
    assert!(v.steps.iter().all(|s| s.capture_request_id.is_some()));
    // o STAMP mudou, com origem: esperado
    assert!(
        v.steps[2].expected.iter().any(|n| n.field == "STAMP"),
        "{:?}",
        v.steps[2]
    );
    assert!(
        v.steps.iter().all(|s| s.unexpected.is_empty()),
        "{:?}",
        v.steps
    );
}

#[test]
fn without_mapping_and_both_non_trace_hosts_do_not_pair() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let tr = bundle(TR, "BBBB2222", Some(200), true, false); // sem rótulo script-trace
    let r = compare_sessions(
        &cap.session,
        &cap,
        &tr.session,
        &tr,
        &CompareOptions::default(),
    );
    assert_eq!(r.pairs.len(), 0);
    let options = CompareOptions {
        map_origin: OriginMap::parse(&format!("{CAP}={TR}")),
        ..CompareOptions::default()
    };
    let r = compare_sessions(&cap.session, &cap, &tr.session, &tr, &options);
    assert_eq!(r.pairs.len(), 3);
    assert!(OriginMap::parse("sem-igual").is_none());
}

#[test]
fn diverging_trace_points_at_the_bad_step() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let tr = bundle(TR, "BBBB2222", Some(403), true, true);
    let v = run(&cap, &tr, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(
        v.summary.starts_with("diverge no passo 3 ("),
        "{}",
        v.summary
    );
    assert!(v.summary.contains("403"), "{}", v.summary);
}

#[test]
fn trace_that_stops_with_a_transport_error_is_incomplete() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    // erro de transporte registrado no passo 3
    let steps = vec![
        step(
            TR,
            "GET",
            "/app/entry",
            None,
            Some(200),
            "<html>entry</html>",
        ),
        step(
            TR,
            "POST",
            "/app/Connector",
            Some("OP=init&STAMP=INIT"),
            Some(200),
            "OP=ok&STAMP=BBBB2222",
        ),
        {
            let mut s = step(
                TR,
                "POST",
                "/app/Connector",
                Some("OP=consulta&STAMP=BBBB2222&PLACA=ABC1D23"),
                None,
                "",
            );
            s["error"] = json!("timeout");
            s
        },
    ];
    let tr_json = import_trace(
        &serde_json::to_vec(&json!({"schema":"scrapelens.trace/1","steps":steps})).unwrap(),
    )
    .unwrap()
    .bundle;
    let v = run(&cap, &tr_json, None);
    assert_eq!(v.verdict, ValidationVerdict::Incomplete, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(
        v.summary.starts_with("incompleta: parou no passo 3"),
        "{}",
        v.summary
    );
}

#[test]
fn extra_step_in_the_trace_diverges() {
    let cap = bundle(CAP, "AAAA1111", Some(200), false, false);
    let tr = bundle(TR, "BBBB2222", Some(200), true, true);
    let v = run(&cap, &tr, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
}

#[test]
fn constant_field_that_changed_is_unexpected() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let mut steps: Vec<Value> = vec![
        step(
            TR,
            "GET",
            "/app/entry",
            None,
            Some(200),
            "<html>entry</html>",
        ),
        step(
            TR,
            "POST",
            "/app/Connector",
            Some("OP=init&STAMP=INIT"),
            Some(200),
            "OP=ok&STAMP=BBBB2222",
        ),
        step(
            TR,
            "POST",
            "/app/Connector",
            Some("OP=consulta&STAMP=BBBB2222&PLACA=ZZZ9Z99"),
            Some(200),
            "OP=ok&STAMP=99",
        ),
    ];
    steps[2]["responseHeaders"] = json!([["Content-Type", "text/html"]]);
    let tr = import_trace(
        &serde_json::to_vec(&json!({"schema":"scrapelens.trace/1","steps":steps})).unwrap(),
    )
    .unwrap()
    .bundle;
    let v = run(&cap, &tr, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(
        v.steps[2].unexpected.iter().any(|n| n.field == "PLACA"),
        "{:?}",
        v.steps[2]
    );
}

#[test]
fn declared_user_parameters_are_expected_differences() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let steps = |with_params: bool| {
        let mut t = json!({"schema":"scrapelens.trace/1","target":"har-0003","complete":true,"steps":[
            step(TR, "GET", "/app/entry", None, Some(200), "<html>entry</html>"),
            step(TR, "POST", "/app/Connector", Some("OP=init&STAMP=INIT"), Some(200), "OP=ok&STAMP=BBBB2222"),
            step(TR, "POST", "/app/Connector", Some("OP=consulta&STAMP=BBBB2222&PLACA=ZZZ9Z99"), Some(200), "OP=ok&STAMP=99"),
        ]});
        if with_params {
            t["parameters"] = json!([{"name":"placa","part":"PLACA"}]);
        }
        import_trace(&serde_json::to_vec(&t).unwrap())
            .unwrap()
            .bundle
    };
    let v = run(&cap, &steps(false), None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges);
    let v = run(&cap, &steps(true), None);
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(v.steps[2]
        .expected
        .iter()
        .any(|n| n.reason.contains("parâmetro do usuário")));
    // esquema: parameters malformado é erro claro
    let bad = json!({"schema":"scrapelens.trace/1","parameters":[{}],"steps":[]});
    assert!(import_trace(&serde_json::to_vec(&bad).unwrap()).is_err());
}

// ---- proveniência, completude e parâmetros (docs/13, revisão da rodada 9) ----

const F: &str = "application/x-www-form-urlencoded";

fn pstep(origin: &str, method: &str, path: &str, req: Option<&str>, resp: &str) -> Value {
    json!({
        "method": method, "url": format!("{origin}{path}"), "status": 200,
        "requestHeaders": req.map(|_| json!([["content-type", F]])).unwrap_or(json!([])),
        "requestBody": req.map(|r| json!({"text": r})),
        "responseHeaders": [["content-type", "text/html"]],
        "responseBody": {"text": resp},
    })
}

fn hidden(v: &str) -> String {
    format!("<input type=hidden name=\"STAMP\" value=\"{v}\"><textarea name=\"XML\">ok</textarea>")
}

fn import(doc: Value, trace: bool) -> SessionBundle {
    let mut b = import_trace(&serde_json::to_vec(&doc).unwrap())
        .unwrap()
        .bundle;
    if !trace {
        b.session.session.labels.retain(|l| l != "script-trace");
    }
    b
}

fn pcap() -> SessionBundle {
    let o = "http://app.test";
    import(
        json!({"schema":"scrapelens.trace/1","steps":[
            pstep(o, "GET", "/entry", None, "<html>entry</html>"),
            pstep(o, "GET", "/a", None, &hidden("STAMPCAP1234567")),
            pstep(o, "POST", "/go", Some("STAMP=STAMPCAP1234567&q=cadastro&sig=0123456789abcdef0123456789abcdef&placa=ABC1D23"), &hidden("STAMPCAP7654321")),
            pstep(o, "POST", "/go2", Some("STAMP=STAMPCAP7654321&q=consulta"), &hidden("STAMPCAP0000000")),
        ]}),
        false,
    )
}

/// `go`: o POST /go; `go2`: o POST /go2; todos em loopback.
fn ptrace(go: &str, go2: &str, extra: Value) -> SessionBundle {
    let o = "http://127.0.0.1:18791";
    let mut doc = json!({"schema":"scrapelens.trace/1","target":"har-0004","complete":true,"steps":[
        pstep(o, "GET", "/entry", None, "<html>entry</html>"),
        pstep(o, "GET", "/a", None, &hidden("STAMPNEW0000001")),
        pstep(o, "POST", "/go", Some(go), &hidden("STAMPNEW0000002")),
        pstep(o, "POST", "/go2", Some(go2), &hidden("STAMPNEW0000003")),
    ]});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        doc[k] = v;
    }
    import(doc, true)
}

const GOOD_GO: &str =
    "STAMP=STAMPNEW0000001&q=cadastro&sig=0123456789abcdef0123456789abcdef&placa=XYZ9K88";
const GOOD_GO2: &str = "STAMP=STAMPNEW0000002&q=consulta";

fn pv(tr: &SessionBundle) -> scrapelens_core::validate::Validation {
    run(&pcap(), tr, None)
}

#[test]
fn faithful_trace_with_a_valid_parameter_is_equivalent() {
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    let v = pv(&ptrace(GOOD_GO, GOOD_GO2, json!({})));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "placa sem declarar");
}

#[test]
fn frozen_captured_value_diverges_even_though_it_equals_the_capture() {
    // V3: STAMP igual ao capturado, ausente da resposta pareada
    let go = "STAMP=STAMPCAP1234567&q=cadastro&sig=0123456789abcdef0123456789abcdef&placa=XYZ9K88";
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(v.summary.contains("congelado"), "{}", v.summary);
}

#[test]
fn value_from_another_response_diverges_as_different_origin() {
    // V18: o STAMP do /go2 vem da resposta de /a, não da de /go
    let v = pv(&ptrace(
        GOOD_GO,
        "STAMP=STAMPNEW0000001&q=consulta",
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(4));
    assert!(v.summary.contains("origem diferente"), "{}", v.summary);
}

#[test]
fn changed_constant_diverges_and_forged_parameters_are_ignored_with_a_warning() {
    // V5/V7: sig (constante longa) trocada; declarar sig/STAMP/q como parâmetro não mascara
    let go = "STAMP=STAMPNEW0000001&q=cadastro&sig=ffffffffffffffffffffffffffffffff&placa=XYZ9K88";
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"},{"name":"sig"},{"name":"STAMP"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("parâmetro inválido") && w.contains("sig")),
        "{:?}",
        v.warnings
    );
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("parâmetro inválido") && w.contains("STAMP")),
        "{:?}",
        v.warnings
    );
}

#[test]
fn incomplete_traces_are_never_equivalent() {
    // V2/V2b/V16: prefixo da cadeia, sem alvo/complete, ou só GETs
    let full = ptrace(GOOD_GO, GOOD_GO2, json!({"parameters":[{"name":"placa"}]}));
    assert_eq!(pv(&full).verdict, ValidationVerdict::Equivalent);
    let no_target = ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "target": null}),
    );
    assert_eq!(pv(&no_target).verdict, ValidationVerdict::Incomplete);
    let not_complete = ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "complete": false}),
    );
    assert_eq!(pv(&not_complete).verdict, ValidationVerdict::Incomplete);
    let o = "http://127.0.0.1:18791";
    let gets = import(
        json!({"schema":"scrapelens.trace/1","target":"har-0004","complete":true,"steps":[
            pstep(o, "GET", "/entry", None, "<html>entry</html>"),
            pstep(o, "GET", "/a", None, &hidden("STAMPNEW0000001")),
        ]}),
        true,
    );
    let v = pv(&gets);
    assert_eq!(v.verdict, ValidationVerdict::Incomplete, "{v:#?}");
}

#[test]
fn only_loopback_hosts_are_mapped_automatically() {
    // V12: o trace em outro host não é mapeado sozinho
    let o = "http://evil.example";
    let doc = json!({"schema":"scrapelens.trace/1","target":"har-0004","complete":true,"steps":[
        pstep(o, "GET", "/entry", None, "<html>entry</html>"),
        pstep(o, "GET", "/a", None, &hidden("STAMPNEW0000001")),
        pstep(o, "POST", "/go", Some(GOOD_GO), &hidden("STAMPNEW0000002")),
        pstep(o, "POST", "/go2", Some(GOOD_GO2), &hidden("STAMPNEW0000003")),
    ], "parameters":[{"name":"placa"}]});
    let tr = import(doc, true);
    let v = pv(&tr);
    assert_ne!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(v.summary.contains("--map-origin"), "{}", v.summary);
    assert!(v.mapped_origin.is_none());
    // com --map-origin explícito, equivalente, e o resumo cita o mapeamento
    let map = OriginMap::parse("http://app.test=http://evil.example");
    let v = run(&pcap(), &tr, map);
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(v.summary.contains("origem mapeada"), "{}", v.summary);
}

fn hash_for(names: &[&str]) -> String {
    let cap = pcap();
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    scrapelens_core::validate::plan_hash(
        &cap.session,
        &cap,
        "har-0004",
        &Default::default(),
        &names,
    )
    .unwrap()
}

#[test]
fn copied_plan_hash_diverges_and_missing_plan_warns() {
    // hash de outro plano (copiado) → diverge
    let other = hash_for(&["outro"]);
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "plan": {"hash": other, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.summary
            .contains("plano diferente do gerado a partir desta captura"),
        "{}",
        v.summary
    );
    assert!(v.warnings.iter().any(|w| w.contains("plano não confere")));
    // hash certo (parâmetros do plano = placa) → equivalente
    let h = hash_for(&["placa"]);
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "plan": {"hash": h, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        !v.warnings.iter().any(|w| w.contains("plano")),
        "{:?}",
        v.warnings
    );
    // o usuário sobrescreveu um opcional: nome extra só no `parameters` de topo
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"},{"name":"q"}], "plan": {"hash": h, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    // sem `plan`: aviso, sem divergência
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("plano ausente: execução não verificada contra o plano")),
        "{:?}",
        v.warnings
    );
}
