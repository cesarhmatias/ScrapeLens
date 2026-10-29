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
    let bytes = serde_json::to_vec(&json!({"schema":"scrapelens.trace/1","steps":steps})).unwrap();
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
    assert_eq!(v.summary, "execução equivalente à captura");
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
    assert_eq!(v.summary, "incompleta: parou no passo 3");
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
        let mut t = json!({"schema":"scrapelens.trace/1","steps":[
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
