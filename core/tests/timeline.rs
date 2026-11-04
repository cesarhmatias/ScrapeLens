//! Timeline (docs/13) with the invented length-prefix protocol.

use std::sync::Arc;

use scrapelens_core::adapter::{
    AdapterContext, AdapterPart, AdapterRegistry, Decoded, PartRole, ProtocolAdapter,
};
use scrapelens_core::error::{CoreError, Result};
use scrapelens_core::flow::FlowOptions;
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
    fn label_hint(&self, d: &Decoded) -> Option<String> {
        d.parts
            .iter()
            .any(|p| p.name == "p.event" && p.value.is_empty())
            .then(|| "init".to_string())
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

fn registry() -> FlowOptions {
    FlowOptions {
        adapters: AdapterRegistry::new().with(Arc::new(LenPrefix)),
        ..FlowOptions::default()
    }
}

use scrapelens_core::timeline::{timeline, Timeline, TimelineItem, TimelineOptions};

fn lp(event: &str, page: &str, delta: &str) -> String {
    let rec = |n: &str, v: &str| format!("{:02}{n}{:02}{v}", n.len(), v.len());
    format!(
        "LP!{}{}{}",
        rec("event", event),
        rec("page", page),
        rec("delta", delta)
    )
}

fn body_line(id: &str, kind: &str, data: &str) -> Value {
    json!({"v":1,"requestId":id,"attemptIndex":0,"kind":kind,"state":"captured","encoding":"utf8",
        "data":data,"originalSize":data.len(),"capturedSize":data.len(),"source":"x","reason":null,"timestamp":1.0})
}

fn session() -> SessionBundle {
    let (mut events, mut bodies) = (Vec::new(), Vec::new());
    let mut n = 0u32;
    let mut step = |method: &str, url: &str, ctype: &str, post: Option<String>, resp: String| {
        n += 1;
        let (id, ts) = (format!("{n:03}.1"), n as f64);
        let mut h = json!({});
        if post.is_some() {
            h["content-type"] = json!("application/x-www-form-urlencoded");
        }
        events.push(
            json!({"method":"Network.requestWillBeSent","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts,"wallTime":1793046000.0+ts,"request":{"url":url,"method":method,
            "headers":h,"postData":post,"hasPostData":post.is_some()},"type":"XHR","frameId":"F"}}),
        );
        events.push(
            json!({"method":"Network.responseReceived","params":{"requestId":id,"loaderId":"L",
            "timestamp":ts+0.01,"type":"XHR","response":{"url":url,"status":200,
            "statusText":"","headers":{"content-type":ctype},"protocol":"http/1.1"}}}),
        );
        events.push(json!({"method":"Network.loadingFinished","params":{"requestId":id,"timestamp":ts+0.02,"encodedDataLength":1}}));
        if let Some(p) = post {
            bodies.push(body_line(&id, "request", &p));
        }
        bodies.push(body_line(&id, "response", &resp));
    };
    for round in 0..2 {
        let d = format!("D3LTA-000{round}");
        step(
            "GET",
            "https://x.test/app/entry",
            "text/html",
            None,
            "<html>entry</html>".into(),
        );
        step(
            "GET",
            "https://x.test/TSPD/?type=18",
            "application/octet-stream",
            None,
            "bin".into(),
        );
        step(
            "GET",
            "https://x.test/static/app.css",
            "text/css",
            None,
            "body{}".into(),
        );
        step(
            "GET",
            "https://x.test/static/app2.css",
            "text/css",
            None,
            "body{}".into(),
        );
        step(
            "POST",
            "https://x.test/app/Connector",
            "text/html",
            Some(format!("XML={}&STAMP=1", lp("", "NatLogon", "x"))),
            format!("XML={}&STAMP=7", lp("", "NatLogon", &d)),
        );
        step(
            "POST",
            "https://x.test/app/Connector",
            "text/html",
            Some(format!(
                "XML={}&STAMP=7",
                lp("cmd_consultar_placa", "VES0009X", &d)
            )),
            "XML=ok&STAMP=8".into(),
        );
    }
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

fn events(t: &Timeline) -> Vec<&scrapelens_core::timeline::TimelineEvent> {
    t.items
        .iter()
        .filter_map(|i| match i {
            TimelineItem::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

#[test]
fn timeline_without_adapter_labels_with_method_and_path_and_groups_noise() {
    let b = session();
    let t = timeline(&b.session, &b, &TimelineOptions::default());
    assert_eq!(t.rounds, 2);
    assert_eq!(t.counts.events, 6);
    assert_eq!((t.counts.protection, t.counts.statics), (2, 4));
    let ev = events(&t);
    assert_eq!(ev[1].label, "POST https://x.test/app/Connector");
    assert_eq!(ev[0].kind, "page");
    assert_eq!(ev[1].kind, "post");
    assert_eq!(
        (ev[0].round, ev[2].round, ev[3].round, ev[5].round),
        (1, 1, 2, 2)
    );
    // protection and static requests collapsed between the events, with counts
    let groups: Vec<_> = t
        .items
        .iter()
        .filter_map(|i| match i {
            TimelineItem::Group(g) => Some((g.kind.as_str(), g.count)),
            _ => None,
        })
        .collect();
    assert_eq!(
        groups,
        vec![
            ("protection", 1),
            ("static", 2),
            ("protection", 1),
            ("static", 2)
        ]
    );
    // values do not leak: only names
    let json = serde_json::to_string(&t).unwrap();
    assert!(!json.contains("D3LTA-"));
    assert!(
        ev[2].consumed.iter().any(|n| n == "STAMP"),
        "{:?}",
        ev[2].consumed
    );
    assert!(
        ev[1].produced.iter().any(|n| n == "STAMP"),
        "{:?}",
        ev[1].produced
    );
}

#[test]
fn timeline_with_adapter_labels_event_at_page_and_names_internal_values() {
    let b = session();
    let options = TimelineOptions {
        flow: registry(),
        ..TimelineOptions::default()
    };
    let t = timeline(&b.session, &b, &options);
    let ev = events(&t);
    assert_eq!(ev[1].label, "init @ NatLogon");
    assert_eq!(ev[2].label, "cmd_consultar_placa @ VES0009X");
    assert_eq!(ev[0].label, "GET https://x.test/app/entry");
    assert!(
        ev[2].consumed.iter().any(|n| n == "XML.delta"),
        "{:?}",
        ev[2].consumed
    );
    assert!(
        ev[1].produced.iter().any(|n| n == "XML.delta"),
        "{:?}",
        ev[1].produced
    );
    assert!(!serde_json::to_string(&t).unwrap().contains("D3LTA-"));
}

#[test]
fn timeline_has_a_verdict_per_event() {
    let b = session();
    let t = timeline(&b.session, &b, &TimelineOptions::default());
    for e in events(&t) {
        assert!(!e.verdict.is_empty(), "{}", e.request_id);
    }
}

#[test]
fn timeline_scales_roughly_linearly() {
    use scrapelens_core::parse::import_trace;
    let make = |n: usize| {
        let steps: Vec<Value> = (0..n)
            .map(|i| {
                json!({"method":"POST","url":"http://a.test/go",
                    "requestHeaders":[["Content-Type","application/x-www-form-urlencoded"]],
                    "requestBody":{"text":format!("T=TOK{:08}&x={i}", i.saturating_sub(1))},
                    "status":200,"responseHeaders":[["Content-Type","text/html"]],
                    "responseBody":{"text":format!("<input type=hidden name=\"T\" value=\"TOK{i:08}\">")}})
            })
            .collect();
        let bytes =
            serde_json::to_vec(&json!({"schema":"scrapelens.trace/1","steps":steps})).unwrap();
        import_trace(&bytes).unwrap().bundle
    };
    let time = |n: usize| {
        let b = make(n);
        let started = std::time::Instant::now();
        let t = timeline(&b.session, &b, &TimelineOptions::default());
        assert_eq!(t.counts.events, n);
        started.elapsed().as_secs_f64()
    };
    let (small, large) = (time(400), time(1600));
    // 4x more requests: with ~n^2.7 cost it would be ~40x; accepts up to ~12x
    assert!(
        large < small.max(0.02) * 12.0 + 0.5,
        "400 → {small:.3}s, 1600 → {large:.3}s"
    );
}
