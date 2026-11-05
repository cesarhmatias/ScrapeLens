//! `ProtocolAdapter` extension point with an invented protocol (without Natural):
//! `LP!` + records `<nn:name><name><mm:value><value>` with 2-digit lengths.

use std::sync::Arc;

use scrapelens_core::adapter::{
    AdapterContext, AdapterPart, AdapterRegistry, Decoded, PartRole, ProtocolAdapter,
};
use scrapelens_core::compare::{compare_sessions, CompareOptions};
use scrapelens_core::error::{CoreError, Result};
use scrapelens_core::flow::{value_origins, ConsumedScope, FlowOptions, OriginStatus};
use scrapelens_core::model::SessionBundle;
use scrapelens_core::parse::cdp::{build_cdp_session, parse_cdp_jsonl};
use scrapelens_core::parse::cdp_bodies::apply_cdp_bodies;
use serde_json::{json, Value};

struct LenPrefix;

impl ProtocolAdapter for LenPrefix {
    fn id(&self) -> &str {
        "len-prefix"
    }
    fn detect(&self, field: &str, value: &str, _ctx: &AdapterContext<'_>) -> bool {
        field == "XML" && value.starts_with("LP!")
    }
    fn decode(&self, value: &str) -> Result<Decoded> {
        let bad = |why: &str| CoreError::LimitExceeded {
            message: format!("len-prefix: {why}"),
        };
        let b = value.as_bytes();
        let mut i = 3;
        let mut parts = Vec::new();
        let read = |i: &mut usize| -> Result<(usize, usize)> {
            let n: usize = value
                .get(*i..*i + 2)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| bad("length"))?;
            let start = *i + 2;
            if start + n > b.len() {
                return Err(bad("truncated"));
            }
            *i = start + n;
            Ok((start, n))
        };
        while i < b.len() {
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
        "LP!{:02}delta{:02}{delta}07v_placa{:02}{plate}02id081234567804flag08ABCDEFGH",
        5,
        delta.len(),
        plate.len()
    )
}

fn registry() -> FlowOptions {
    FlowOptions {
        adapters: AdapterRegistry::new().with(Arc::new(LenPrefix)),
        ..FlowOptions::default()
    }
}

fn body_line(id: &str, kind: &str, data: &str) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":0,"kind":kind,"state":"captured","encoding":"utf8",
        "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":1.0})
}

/// response with the delta (req 1) → query that returns it with a plate (req 2).
fn flow(delta: &str, plate: &str) -> SessionBundle {
    let (mut events, mut bodies) = (Vec::new(), Vec::new());
    let mut step = |n: u32, post: Option<String>, resp: String, ts: f64| {
        let id = format!("{n}.1");
        let mut h = json!({});
        if post.is_some() {
            h["content-type"] = json!("application/x-www-form-urlencoded");
        }
        events.push(json!({"method":"Network.requestWillBeSent","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts,"wallTime":1793046000.0+ts,"request":{"url":"https://x.test/app/Connector","method":"POST",
            "headers":h,"postData":post,"hasPostData":post.is_some()},"type":"XHR","frameId":"F"}}));
        events.push(json!({"method":"Network.responseReceived","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts+0.01,"type":"XHR","response":{"url":"https://x.test/app/Connector","status":200,
            "statusText":"","headers":{"content-type":"text/html"},"protocol":"http/1.1"}}}));
        events.push(json!({"method":"Network.loadingFinished","params":{"requestId":id,"timestamp":ts+0.02,"encodedDataLength":1}}));
        if let Some(p) = post {
            bodies.push(body_line(&id, "request", &p));
        }
        bodies.push(body_line(&id, "response", &resp));
    };
    step(
        1,
        Some("A=1".into()),
        format!("XML={}&STAMP=7", lp(delta, "ZZZ0Z00")),
        1.0,
    );
    step(
        2,
        Some(format!("XML={}&STAMP=7", lp(delta, plate))),
        "XML=ok".into(),
        2.0,
    );
    let jsonl = |v: &[Value]| {
        v.iter()
            .map(|x| format!("{x}\n"))
            .collect::<String>()
            .into_bytes()
    };
    let capture = parse_cdp_jsonl(&jsonl(&events)).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let mut attachments = Default::default();
    apply_cdp_bodies(&mut session, &mut attachments, &jsonl(&bodies));
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    bundle
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

#[test]
fn detect_and_round_trip() {
    let ctx = AdapterContext {
        url: "u",
        method: "POST",
        request: true,
        media: None,
    };
    let reg = registry().adapters;
    let text = lp("D3LTA-0001", "ABC1D23");
    let adapter = reg.claim("XML", &text, &ctx).expect("claimed");
    assert_eq!(adapter.id(), "len-prefix");
    assert!(reg.claim("OUTRO", &text, &ctx).is_none());
    assert!(reg.claim("XML", "plain", &ctx).is_none());
    let decoded = adapter.decode(&text).unwrap();
    assert_eq!(adapter.encode(&decoded).unwrap(), text);
    let p = &decoded.parts[1];
    assert_eq!(
        (p.name.as_str(), p.value.as_str()),
        ("p.v_placa", "ABC1D23")
    );
    assert_eq!(&text[p.offset..p.offset + p.len], "ABC1D23");
    // grammar violated → error, not panic
    assert!(adapter.decode("LP!99x").is_err());
}

#[test]
fn origins_use_internal_names_and_offsets_with_adapter() {
    let b = flow("D3LTA-0001", "ABC1D23");
    let target = logical(&b, "2.1");
    let o = value_origins(&b.session, &b, &target, &registry()).unwrap();
    let delta = o
        .values
        .iter()
        .find(|v| v.scope == ConsumedScope::Body && v.field == "XML.delta")
        .unwrap_or_else(|| {
            panic!(
                "{:?}",
                o.values.iter().map(|v| &v.field).collect::<Vec<_>>()
            )
        });
    assert_eq!(delta.value, "D3LTA-0001");
    assert_eq!(delta.parent.as_deref(), Some("XML"));
    assert_eq!(delta.offset, Some(12)); // "LP!05delta10"
    assert!(
        matches!(delta.status, OriginStatus::Origin),
        "{:?}",
        delta.status
    );
    assert_eq!(delta.evidences[0].request_id, logical(&b, "1.1"));
    let plate = o
        .values
        .iter()
        .find(|v| v.field == "XML.p.v_placa")
        .expect("plate");
    assert_eq!(plate.value, "ABC1D23");
    // no common substrings in place of the names
    let stray: Vec<_> = o
        .values
        .iter()
        .filter(|v| v.parent.as_deref() == Some("XML") && !v.field.starts_with("XML."))
        .map(|v| (&v.field, &v.value))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

#[test]
fn without_registry_nothing_changes() {
    let b = flow("D3LTA-0001", "ABC1D23");
    let target = logical(&b, "2.1");
    let o = value_origins(&b.session, &b, &target, &FlowOptions::default()).unwrap();
    assert!(!o.values.iter().any(|v| v.field.starts_with("XML.")));
    // the common-substring behavior still applies
    assert!(o.values.iter().any(|v| v.parent.as_deref() == Some("XML")));
}

#[test]
fn compare_shows_internal_names() {
    let a = flow("D3LTA-0001", "ABC1D23");
    let bb = flow("D3LTA-0002", "QWE9R88");
    let options = CompareOptions {
        flow: registry(),
        ..CompareOptions::default()
    };
    let r = compare_sessions(&a.session, &a, &bb.session, &bb, &options);
    let text = serde_json::to_string(&r).unwrap();
    assert!(text.contains("XML.delta"), "{text}");
    assert!(text.contains("XML.p.v_placa"), "{text}");
    let plain = compare_sessions(&a.session, &a, &bb.session, &bb, &CompareOptions::default());
    assert!(!serde_json::to_string(&plain).unwrap().contains("XML.delta"));
}

/// Producer in `<textarea name="XML">` with entities; the consumer returns it.
fn html_flow(delta: &str) -> (SessionBundle, usize) {
    // `&amp;` before the delta shifts the decoded × original offsets
    let payload = lp(delta, "ZZZ0Z00");
    let escaped = payload.replace('!', "&#33;");
    let page = format!(
        "<html><body><form><textarea name=\"XML\">{escaped}</textarea></form></body></html>"
    );
    let delta_at = page.find("delta").unwrap() + "delta10".len() - 2 + 2;
    let post = format!("XML={}&STAMP=7", lp(delta, "ABC1D23"));
    let jsonl = |v: &[Value]| {
        v.iter()
            .map(|x| format!("{x}\n"))
            .collect::<String>()
            .into_bytes()
    };
    let mut events = Vec::new();
    let mut bodies = Vec::new();
    for (n, ts, p, resp) in [
        (1u32, 1.0, None, page.clone()),
        (2, 2.0, Some(post), "ok".to_string()),
    ] {
        let id = format!("{n}.1");
        let mut h = json!({});
        if p.is_some() {
            h["content-type"] = json!("application/x-www-form-urlencoded");
        }
        events.push(json!({"method":"Network.requestWillBeSent","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts,"wallTime":1793046000.0+ts,"request":{"url":"https://x.test/app/Connector","method":"POST",
            "headers":h,"postData":p,"hasPostData":p.is_some()},"type":"XHR","frameId":"F"}}));
        events.push(json!({"method":"Network.responseReceived","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts+0.01,"type":"XHR","response":{"url":"https://x.test/app/Connector","status":200,
            "statusText":"","headers":{"content-type":"text/html"},"protocol":"http/1.1"}}}));
        events.push(json!({"method":"Network.loadingFinished","params":{"requestId":id,"timestamp":ts+0.02,"encodedDataLength":1}}));
        if let Some(p) = p {
            bodies.push(body_line(&id, "request", &p));
        }
        bodies.push(body_line(&id, "response", &resp));
    }
    let capture = parse_cdp_jsonl(&jsonl(&events)).unwrap();
    let (mut session, _) = build_cdp_session(&capture);
    let mut attachments = Default::default();
    apply_cdp_bodies(&mut session, &mut attachments, &jsonl(&bodies));
    let mut bundle = SessionBundle::new(session);
    bundle.attachments = attachments;
    (bundle, delta_at)
}

#[test]
fn html_textarea_with_entities_maps_offsets_to_the_original_html() {
    let (b, _) = html_flow("D3LTA-0001");
    let o = value_origins(&b.session, &b, &logical(&b, "2.1"), &registry()).unwrap();
    let delta = o
        .values
        .iter()
        .find(|v| v.field == "XML.delta")
        .expect("XML.delta");
    assert_eq!(delta.status, OriginStatus::Origin);
    let ev = &delta.evidences[0];
    assert_eq!(ev.request_id, logical(&b, "1.1"));
    assert_eq!(ev.field.as_deref(), Some("XML.delta"));
    let page = format!(
        "<html><body><form><textarea name=\"XML\">{}</textarea></form></body></html>",
        lp("D3LTA-0001", "ZZZ0Z00").replace('!', "&#33;")
    );
    assert!(ev.html_control);
    assert_eq!(
        ev.producer_offset,
        Some(page.find("D3LTA-0001").unwrap() as u64)
    );
    // without a registry there are no internal names
    let plain =
        value_origins(&b.session, &b, &logical(&b, "2.1"), &FlowOptions::default()).unwrap();
    assert!(!plain.values.iter().any(|v| v.field.starts_with("XML.")));
}

#[test]
fn adapter_does_not_change_request_alignment() {
    // B has no plate: with an adapter, the `XML.*` names must not change the model/pairing.
    let a = flow("D3LTA-0001", "ABC1D23");
    let b = flow("D3LTA-0002", "Q");
    let plain = compare_sessions(&a.session, &a, &b.session, &b, &CompareOptions::default());
    let options = CompareOptions {
        flow: registry(),
        ..CompareOptions::default()
    };
    let with = compare_sessions(&a.session, &a, &b.session, &b, &options);
    assert_eq!(plain.pairs.len(), with.pairs.len());
    assert_eq!(plain.ambiguities, with.ambiguities);
    assert_eq!(plain.only_in_a.len(), with.only_in_a.len());
}

#[test]
fn generic_last_component_of_adapter_part_is_only_possible() {
    use scrapelens_core::flow::Confidence;
    let b = flow("D3LTA-0001", "ABC1D23");
    let o = value_origins(&b.session, &b, &logical(&b, "2.1"), &registry()).unwrap();
    let get = |f: &str| o.values.iter().find(|v| v.field == f).unwrap();
    assert_eq!(get("XML.p.id").confidence, Some(Confidence::Possible));
    assert_eq!(get("XML.p.flag").confidence, Some(Confidence::Possible));
    assert_eq!(get("XML.delta").confidence, Some(Confidence::Strong));
}

#[test]
fn compare_resolves_the_origin_of_adapter_parts() {
    let a = flow("D3LTA-0001", "ABC1D23");
    let b = flow("D3LTA-0002", "QWE9R88");
    let options = CompareOptions {
        flow: registry(),
        ..CompareOptions::default()
    };
    let r = compare_sessions(&a.session, &a, &b.session, &b, &options);
    let delta = r
        .pairs
        .iter()
        .flat_map(|p| p.fields.iter())
        .find(|f| {
            f.field == "XML.delta" && f.class == scrapelens_core::compare::FieldClass::Dynamic
        })
        .expect("dynamic XML.delta");
    assert!(delta.origin.is_some(), "{delta:?}");
}
