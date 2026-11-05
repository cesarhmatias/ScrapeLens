//! `validate` (capture × trace) and `map_origin`, with synthetic sessions and different hosts.

use std::sync::Arc;

use scrapelens_core::adapter::{
    AdapterContext, AdapterPart, AdapterRegistry, Decoded, PartRole, ProtocolAdapter,
};
use scrapelens_core::compare::{compare_sessions, CompareOptions, OriginMap};
use scrapelens_core::error::{CoreError, Result};
use scrapelens_core::flow::FlowOptions;
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::import_trace;
use scrapelens_core::validate::{validate, ValidateOptions, ValidationVerdict};
use serde_json::{json, Value};

/// Minimal adapter for the protocol-part tests: `LP!` + records
/// `<nn:name><name><mm:value><value>`, with the `delta` part.
struct Lp;

impl ProtocolAdapter for Lp {
    fn id(&self) -> &str {
        "lp-test"
    }
    fn detect(&self, field: &str, value: &str, _ctx: &AdapterContext<'_>) -> bool {
        field == "XML" && value.starts_with("LP!")
    }
    fn decode(&self, value: &str) -> Result<Decoded> {
        let bad = |why: &str| CoreError::LimitExceeded {
            message: format!("lp-test: {why}"),
        };
        let mut i = 3;
        let mut parts = Vec::new();
        let read = |i: &mut usize| -> Result<(usize, usize)> {
            let n: usize = value
                .get(*i..*i + 2)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| bad("length"))?;
            let start = *i + 2;
            if start + n > value.len() {
                return Err(bad("truncated"));
            }
            *i = start + n;
            Ok((start, n))
        };
        while i < value.len() {
            let (ns, nl) = read(&mut i)?;
            let (vs, vl) = read(&mut i)?;
            let name = &value[ns..ns + nl];
            parts.push(AdapterPart {
                name: if name == "delta" {
                    name.into()
                } else {
                    format!("p.{name}")
                },
                value: value[vs..vs + vl].to_string(),
                offset: vs,
                len: vl,
                role: if name == "delta" {
                    PartRole::Delta
                } else {
                    PartRole::Value
                },
            });
        }
        Ok(Decoded { parts })
    }
    fn encode(&self, d: &Decoded) -> Result<String> {
        let mut out = String::from("LP!");
        for p in &d.parts {
            let name = p.name.strip_prefix("p.").unwrap_or(&p.name);
            out += &format!("{:02}{}{:02}{}", name.len(), name, p.value.len(), p.value);
        }
        Ok(out)
    }
}

fn lp(delta: &str, plate: &str) -> String {
    format!(
        "LP!{:02}delta{:02}{delta}07v_placa{:02}{plate}",
        5,
        delta.len(),
        plate.len()
    )
}

fn lp_flow() -> FlowOptions {
    FlowOptions {
        adapters: AdapterRegistry::new().with(Arc::new(Lp)),
        ..FlowOptions::default()
    }
}

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

fn run_flow(
    a: &SessionBundle,
    b: &SessionBundle,
    flow: FlowOptions,
) -> scrapelens_core::validate::Validation {
    let mut options = ValidateOptions::default();
    options.compare.flow = flow;
    validate(&a.session, a, &b.session, b, &options)
}

/// Capture with protocol field `XML` (adapter `Lp`): the target's delta comes
/// from the previous POST's response. `d_prev` is that response's delta.
fn lp_capture(d_prev: &str) -> SessionBundle {
    let o = "http://app.test";
    let prev = format!(
        "<input type=hidden name=\"STAMP\" value=\"S2\"><textarea name=\"XML\">{}</textarea>",
        lp(d_prev, "ABC1D23")
    );
    import(
        json!({"schema":"scrapelens.trace/1","steps":[
            pstep(o, "GET", "/a", None, "<html><input type=hidden name=\"STAMP\" value=\"S1\"></html>"),
            pstep(o, "POST", "/go", Some(&format!("STAMP=S1&XML={}", lp("D1", "ABC1D23"))), &prev),
            pstep(o, "POST", "/go2", Some(&format!("STAMP=S2&XML={}", lp(d_prev, "ABC1D23"))), "<html>ok</html>"),
        ]}),
        false,
    )
}

/// Trace of the plan for `lp_capture`: the previous POST's response carries `d_prev` and the
/// target sends `d_target`. `plan` present with the plan hash and names `["placa"]`.
fn lp_trace(d_prev: &str, d_target: &str, names: &[&str], extra: Value) -> SessionBundle {
    let o = "http://127.0.0.1:18791";
    let cap = lp_capture("D2");
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let h =
        scrapelens_core::validate::plan_hash(&cap.session, &cap, "har-0003", &lp_flow(), &names)
            .unwrap();
    let prev = format!(
        "<input type=hidden name=\"STAMP\" value=\"S2\"><textarea name=\"XML\">{}</textarea>",
        lp(d_prev, "ABC1D23")
    );
    let mut doc = json!({"schema":"scrapelens.trace/1","target":"har-0003","complete":true,"steps":[
        pstep(o, "GET", "/a", None, "<html><input type=hidden name=\"STAMP\" value=\"S1\"></html>"),
        pstep(o, "POST", "/go", Some(&format!("STAMP=S1&XML={}", lp("D1", "ABC1D23"))), &prev),
        pstep(o, "POST", "/go2", Some(&format!("STAMP=S2&XML={}", lp(d_target, "ABC1D23"))), "<html>ok</html>"),
    ]});
    doc["plan"] = json!({"version":2, "hash": h, "parameters": names});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        doc[k] = v;
    }
    let mut b = import_trace(&serde_json::to_vec(&doc).unwrap())
        .unwrap()
        .bundle;
    b.session.session.labels.retain(|l| l != "script-trace");
    b.session.session.labels.push("script-trace".to_string());
    b
}

const CAP: &str = "https://real.test";
const TR: &str = "http://127.0.0.1:8791";

#[test]
fn equivalent_trace_with_another_host_and_other_dynamic_values() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let tr = bundle(TR, "BBBB2222", Some(200), true, true);
    let v = run(&cap, &tr, None); // automatic mapping
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.summary.starts_with("execution equivalent to capture"),
        "{}",
        v.summary
    );
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("mapped automatically")),
        "{:?}",
        v.warnings
    );
    assert_eq!(v.mapped_origin.as_ref().unwrap().to, TR);
    assert_eq!(v.steps.len(), 3);
    assert!(v.steps.iter().all(|s| s.capture_request_id.is_some()));
    // STAMP changed, with origin: expected
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
    let tr = bundle(TR, "BBBB2222", Some(200), true, false); // without script-trace label
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
    assert!(OriginMap::parse("no-equal").is_none());
}

#[test]
fn diverging_trace_points_at_the_bad_step() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    let tr = bundle(TR, "BBBB2222", Some(403), true, true);
    let v = run(&cap, &tr, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(
        v.summary.starts_with("diverges at step 3 ("),
        "{}",
        v.summary
    );
    assert!(v.summary.contains("403"), "{}", v.summary);
}

#[test]
fn trace_that_stops_with_a_transport_error_is_incomplete() {
    let cap = bundle(CAP, "AAAA1111", Some(200), true, false);
    // transport error recorded at step 3
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
        v.summary.starts_with("incomplete: stopped at step 3"),
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
        .any(|n| n.reason.contains("user parameter")));
    // schema: malformed parameters is a clear error
    let bad = json!({"schema":"scrapelens.trace/1","parameters":[{}],"steps":[]});
    assert!(import_trace(&serde_json::to_vec(&bad).unwrap()).is_err());
}

// ---- provenance, completeness and parameters (docs/13, round 9 review) ----

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

/// `go`: the POST /go; `go2`: the POST /go2; all on loopback.
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
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "plate not declared");
}

#[test]
fn frozen_captured_value_diverges_even_though_it_equals_the_capture() {
    // V3: STAMP equal to the captured one, absent from the paired response
    let go = "STAMP=STAMPCAP1234567&q=cadastro&sig=0123456789abcdef0123456789abcdef&placa=XYZ9K88";
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(v.summary.contains("frozen"), "{}", v.summary);
}

#[test]
fn value_from_another_response_diverges_as_different_origin() {
    // V18: the STAMP of /go2 comes from the response of /a, not from /go
    let v = pv(&ptrace(
        GOOD_GO,
        "STAMP=STAMPNEW0000001&q=consulta",
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(4));
    assert!(v.summary.contains("different origin"), "{}", v.summary);
}

#[test]
fn changed_constant_diverges_and_forged_parameters_are_ignored_with_a_warning() {
    // V5/V7: sig (long constant) swapped; declaring sig/STAMP/q as parameters does not mask
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
        json!({"parameters":[{"name":"placa"},{"name":"STAMP"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("invalid parameter") && w.contains("STAMP")),
        "{:?}",
        v.warnings
    );
    // `sig` is a required parameter of the regenerated plan (pair (sig, sig)):
    // declaring it is consistent with the plan, so the swap no longer diverges.
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"},{"name":"sig"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.steps[2]
            .expected
            .iter()
            .any(|n| n.field == "sig" && n.reason.contains("user parameter")),
        "{:?}",
        v.steps[2]
    );
    // item under a plan name with a part that the plan does not produce is not exempt
    let v = pv(&ptrace(
        go,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"},{"name":"sig","part":"q"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w == "parameter does not match the plan: sig → q"),
        "{:?}",
        v.warnings
    );
}

#[test]
fn incomplete_traces_are_never_equivalent() {
    // V2/V2b/V16: chain prefix, without target/complete, or only GETs
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
    // V12: a trace on another host is not mapped by itself
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
    // with an explicit --map-origin, equivalent, and the summary cites the mapping
    let map = OriginMap::parse("http://app.test=http://evil.example");
    let v = run(&pcap(), &tr, map);
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(v.summary.contains("mapped origin"), "{}", v.summary);
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
    // hash of another plan (copied) → diverges
    let other = hash_for(&["other"]);
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "plan": {"version":2,"hash": other, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.summary
            .contains("plan differs from the one generated from this capture"),
        "{}",
        v.summary
    );
    assert!(v.warnings.iter().any(|w| w.contains("plan does not match")));
    // correct hash (plan parameters = placa) → equivalent
    let h = hash_for(&["placa"]);
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "plan": {"version":2,"hash": h, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        !v.warnings.iter().any(|w| w.contains("plan")),
        "{:?}",
        v.warnings
    );
    // the user overrode an optional item: extra name only in the top-level `parameters`
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"},{"name":"q"}], "plan": {"version":2,"hash": h, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    // without `plan`: warning, no divergence
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}]}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("plan missing: execution not verified against the plan")),
        "{:?}",
        v.warnings
    );
}

#[test]
fn faithful_plan_has_no_spurious_warnings() {
    // faithful trace from the current generator: `plan.parameters` does not go through the checks and
    // the (name, part) pair that the plan regenerated from the capture produces is exempt.
    let names = ["placa", "cpf", "sessionid_cliente", "SESSIONID", "sig"];
    let h = hash_for(&names);
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({
            "parameters": [{"name":"placa"},{"name":"sig"}],
            "plan": {"version":2, "hash": h, "parameters": names},
        }),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    // the only permitted warning: the automatic origin mapping (different hosts).
    let spurious: Vec<&String> = v
        .warnings
        .iter()
        .filter(|w| !w.contains("mapped automatically"))
        .collect();
    assert!(spurious.is_empty(), "{spurious:?}");
    // plan name with a part that the plan does NOT produce: not exempt, warns and
    // goes through the normal checks (long constant).
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({
            "parameters": [{"name":"placa"},{"name":"sessionid_cliente","part":"sig"}],
            "plan": {"version":2, "hash": h, "parameters": names},
        }),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w == "parameter does not match the plan: sessionid_cliente → sig"),
        "{:?}",
        v.warnings
    );
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("invalid parameter: `sig`")),
        "{:?}",
        v.warnings
    );
    // forged nonexistent item (without a part) also warns
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({
            "parameters": [{"name":"placa"},{"name":"forjado"}],
            "plan": {"version":2, "hash": h, "parameters": names},
        }),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("invalid parameter: `forjado`")),
        "{:?}",
        v.warnings
    );
}

#[test]
fn only_the_pair_the_plan_produces_is_exempt() {
    // D1/E2/D5 from the reviewer's matrix with a real protocol part (`XML.delta`).
    let cap = lp_capture("D2");
    let v = run_flow(
        &cap,
        &lp_trace("D2", "D2", &["placa"], json!({})),
        lp_flow(),
    );
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    let spurious: Vec<&String> = v
        .warnings
        .iter()
        .filter(|w| !w.contains("mapped automatically"))
        .collect();
    assert!(spurious.is_empty(), "{spurious:?}");
    // D1: frozen delta + param(sessionid_cliente, XML.delta) → not exempt
    let v = run_flow(
        &cap,
        &lp_trace(
            "D3",
            "D2",
            &["placa", "sessionid_cliente"],
            json!({"parameters":[{"name":"sessionid_cliente","part":"XML.delta"}]}),
        ),
        lp_flow(),
    );
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(v.summary.contains("frozen"), "{}", v.summary);
    assert!(
        v.warnings
            .iter()
            .any(|w| w == "parameter does not match the plan: sessionid_cliente → XML.delta"),
        "{:?}",
        v.warnings
    );
    // E2: invented delta + param(cpf, XML.delta) → not exempt
    let v = run_flow(
        &cap,
        &lp_trace(
            "D3",
            "DZ",
            &["placa", "cpf"],
            json!({"parameters":[{"name":"cpf","part":"XML.delta"}]}),
        ),
        lp_flow(),
    );
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(3));
    assert!(
        v.steps[2]
            .unexpected
            .iter()
            .any(|n| n.field == "XML.delta" && (n.reason.contains("no origin") || n.reason.contains("without origin"))),
        "{:?}",
        v.steps[2]
    );
    // D5: faithful + param(cpf, XML.delta) → equivalent, but warns and is not exempt
    let v = run_flow(
        &cap,
        &lp_trace(
            "D2",
            "D2",
            &["placa", "cpf"],
            json!({"parameters":[{"name":"cpf","part":"XML.delta"}]}),
        ),
        lp_flow(),
    );
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w == "parameter does not match the plan: cpf → XML.delta"),
        "{:?}",
        v.warnings
    );
    // without `plan`: the exemption still comes from the plan regenerated from the capture
    let mut no_plan = lp_trace(
        "D2",
        "D2",
        &["placa"],
        json!({"parameters":[{"name":"placa","part":"XML.p.v_placa"}]}),
    );
    no_plan
        .session
        .session
        .notes
        .retain(|n| !n.starts_with("trace-plan"));
    let v = run_flow(&cap, &no_plan, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    let spurious: Vec<&String> = v
        .warnings
        .iter()
        .filter(|w| {
            !w.contains("mapped automatically")
                && !w.starts_with("plan missing: execution not verified")
        })
        .collect();
    assert!(spurious.is_empty(), "{spurious:?}");
}

#[test]
fn forged_parameters_under_plan_names_do_not_mask_stamp() {
    // E4/E5: frozen/invented STAMP with part STAMP under the name cpf.
    let cap = pcap();
    let h = hash_for(&["placa", "cpf"]);
    let plan = json!({"version":2, "hash": h, "parameters":["placa","cpf"]});
    let frozen = ptrace(
        GOOD_GO,
        "STAMP=STAMPCAP7654321&q=consulta",
        json!({"parameters":[{"name":"cpf","part":"STAMP"}], "plan": plan}),
    );
    let v = run(&cap, &frozen, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(4), "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w == "parameter does not match the plan: cpf → STAMP"),
        "{:?}",
        v.warnings
    );
    let invented = ptrace(
        GOOD_GO,
        "STAMP=9999&q=consulta",
        json!({"parameters":[{"name":"cpf","part":"STAMP"}], "plan": plan}),
    );
    let v = run(&cap, &invented, None);
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert_eq!(v.step, Some(4), "{v:#?}");
}

#[test]
fn unverified_plan_parameters_do_not_mask_values() {
    // L13–L15, N1 and N3: `plan.parameters` without a verified plan does not classify
    // any field; frozen/invented value keeps diverging.
    let cap = lp_capture("D2");
    let make = |prev: &str, target: &str| lp_trace(prev, target, &["placa"], json!({}));
    let add_delta = |t: &mut SessionBundle| {
        t.session
            .session
            .notes
            .push("trace-plan-param: XML.delta".to_string());
    };
    // N2: v2 control without hash, without item → diverges
    let mut t = make("D3", "D2");
    t.session
        .session
        .notes
        .retain(|n| !n.starts_with("trace-plan-hash"));
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    // N1: v2 without hash + plan.parameters += XML.delta + frozen delta
    let mut t = make("D3", "D2");
    t.session
        .session
        .notes
        .retain(|n| !n.starts_with("trace-plan-hash"));
    add_delta(&mut t);
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(v.summary.contains("frozen"), "{}", v.summary);
    // L13: v1 + plan.parameters += XML.delta + frozen delta
    let mut t = make("D3", "D2");
    t.session.session.notes = t
        .session
        .session
        .notes
        .iter()
        .map(|n| {
            if n.starts_with("trace-plan-version: ") {
                "trace-plan-version: 1".to_string()
            } else {
                n.clone()
            }
        })
        .collect();
    add_delta(&mut t);
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    // L15: missing version + plan.parameters += XML.delta + frozen delta
    let mut t = make("D3", "D2");
    t.session
        .session
        .notes
        .retain(|n| !n.starts_with("trace-plan-version"));
    add_delta(&mut t);
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    // L14/N3: v1 + plan.parameters += XML.delta + invented delta
    let mut t = make("D3", "DZ");
    t.session.session.notes = t
        .session
        .session
        .notes
        .iter()
        .map(|n| {
            if n.starts_with("trace-plan-version: ") {
                "trace-plan-version: 1".to_string()
            } else {
                n.clone()
            }
        })
        .collect();
    add_delta(&mut t);
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Diverges, "{v:#?}");
    assert!(
        v.steps[2]
            .unexpected
            .iter()
            .any(|n| n.field == "XML.delta" && (n.reason.contains("no origin") || n.reason.contains("without origin"))),
        "{:?}",
        v.steps[2]
    );
    // faithful v1, without forged item → equivalent, only with the version warning
    let mut t = make("D2", "D2");
    t.session.session.notes = t
        .session
        .session
        .notes
        .iter()
        .map(|n| {
            if n.starts_with("trace-plan-version: ") {
                "trace-plan-version: 1".to_string()
            } else {
                n.clone()
            }
        })
        .collect();
    let v = run_flow(&cap, &t, lp_flow());
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    let plan_warnings: Vec<&String> = v.warnings.iter().filter(|w| w.contains("plan")).collect();
    assert_eq!(plan_warnings.len(), 1, "{:?}", v.warnings);
    assert!(
        plan_warnings[0].contains("plan of an earlier version (v1)"),
        "{:?}",
        plan_warnings
    );
    assert!(
        !v.warnings.iter().any(|w| w.contains("invalid parameter")),
        "{:?}",
        v.warnings
    );
}

#[test]
fn old_plan_version_warns_instead_of_diverging() {
    let h = hash_for(&["placa"]);
    // missing version: earlier build → warning, without comparing the hash
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"parameters":[{"name":"placa"}], "plan": {"hash": h, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("plan of an earlier version (v1)")),
        "{:?}",
        v.warnings
    );
    // old version with a hash that does not match: still just a warning
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"plan": {"version":1, "hash": hash_for(&["other"]), "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("plan of an earlier version (v1)")),
        "{:?}",
        v.warnings
    );
    // plan without hash: precise message, without diverging
    let v = pv(&ptrace(
        GOOD_GO,
        GOOD_GO2,
        json!({"plan": {"version":2, "parameters": ["placa"]}}),
    ));
    assert_eq!(v.verdict, ValidationVerdict::Equivalent, "{v:#?}");
    assert!(
        v.warnings.iter().any(|w| w == "plan without fingerprint"),
        "{:?}",
        v.warnings
    );
}
