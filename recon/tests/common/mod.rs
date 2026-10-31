//! Sessões sintéticas em memória (nenhuma rede, nenhum site real). Cada
//! requisição é descrita com o que a detecção lê.
#![allow(dead_code)]

use scrapelens_core::model::{
    Attempt, AttemptOutcome, Body, BrowserInfo, Completeness, CookieField, HeaderView,
    LogicalRequest, Protocol, Provenance, SessionBundle, SessionMeta, SessionV1, SetCookieRecord,
    Source, Verification,
};

#[derive(Clone, Default)]
pub struct Req {
    pub id: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub rtype: Option<String>,
    pub protocol: Option<Protocol>,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub set_cookies: Vec<String>,
    pub cookie_header: Option<String>,
    pub request_body: Option<(String, String)>,  // (content-type, texto)
    pub response_body: Option<(String, String)>, // (content-type, texto)
    pub failure: Option<String>,
}

impl Req {
    pub fn new(id: &str, method: &str, url: &str, status: Option<u16>, rtype: &str) -> Req {
        Req {
            id: id.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            status,
            rtype: Some(rtype.to_string()),
            ..Req::default()
        }
    }
    pub fn doc(id: &str, url: &str, status: u16) -> Req {
        Req::new(id, "GET", url, Some(status), "Document")
    }
    pub fn xhr(id: &str, method: &str, url: &str, status: u16) -> Req {
        Req::new(id, method, url, Some(status), "XHR")
    }
    pub fn script(id: &str, url: &str, status: u16) -> Req {
        Req::new(id, "GET", url, Some(status), "Script")
    }
    pub fn rh(mut self, name: &str, value: &str) -> Req {
        self.resp_headers.push((name.to_string(), value.to_string()));
        self
    }
    pub fn qh(mut self, name: &str, value: &str) -> Req {
        self.req_headers.push((name.to_string(), value.to_string()));
        self
    }
    pub fn set_cookie(mut self, raw: &str) -> Req {
        self.set_cookies.push(raw.to_string());
        self
    }
    pub fn cookie(mut self, header: &str) -> Req {
        self.cookie_header = Some(header.to_string());
        self
    }
    pub fn resp_body(mut self, content_type: &str, text: &str) -> Req {
        self.response_body = Some((content_type.to_string(), text.to_string()));
        self
    }
    pub fn req_body(mut self, content_type: &str, text: &str) -> Req {
        self.request_body = Some((content_type.to_string(), text.to_string()));
        self
    }
    pub fn proto(mut self, p: Protocol) -> Req {
        self.protocol = Some(p);
        self
    }
    pub fn fail(mut self, text: &str) -> Req {
        self.failure = Some(text.to_string());
        self.status = None;
        self
    }
}

fn prov() -> Provenance {
    Provenance::new(Source::Cdp, "synthetic", Verification::Partial)
}

pub fn build(reqs: Vec<Req>) -> SessionBundle {
    let p = prov();
    let mut meta = SessionMeta::new("sintetica", "2026-10-31T00:00:00Z", BrowserInfo::default());
    meta.completeness = Completeness::complete();
    meta.labels = vec!["synthetic-fixture".to_string()];
    let mut session = SessionV1::new(meta);
    let mut bundle_attachments: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, r) in reqs.iter().enumerate() {
        let mut logical = LogicalRequest::new(&r.id, &r.url, &r.method);
        logical.resource_type = r.rtype.clone();
        let mut a = Attempt::new(format!("{}.a1", r.id), &r.id, 0, &r.url, &r.method);
        a.status = r.status;
        a.protocol = r.protocol.unwrap_or(Protocol::H1);
        a.started_at = Some(i as f64);
        a.ended_at = Some(i as f64 + 0.5);
        a.outcome = if r.failure.is_some() { AttemptOutcome::Failed } else { AttemptOutcome::Completed };
        a.failure = r.failure.clone();
        a.request_headers = HeaderView::from_pairs(r.req_headers.clone(), &p);
        a.response_headers = HeaderView::from_pairs(r.resp_headers.clone(), &p);
        a.set_cookies = r.set_cookies.iter().map(|raw| SetCookieRecord::from_raw(raw, &p)).collect();
        if let Some(h) = &r.cookie_header {
            a.cookie = CookieField::from_header_values(std::slice::from_ref(h), &p);
        }
        if let Some((ct, text)) = &r.request_body {
            let name = format!("req-{}.bin", r.id);
            a.request_body = Body::captured(&name, text.len() as u64, &p).with_content_type(ct);
            bundle_attachments.push((name, text.clone().into_bytes()));
        }
        if let Some((ct, text)) = &r.response_body {
            let name = format!("resp-{}.bin", r.id);
            a.response_body = Body::captured(&name, text.len() as u64, &p).with_content_type(ct);
            bundle_attachments.push((name, text.clone().into_bytes()));
        }
        logical.attempts.push(a);
        logical.refresh_primary_from_attempt();
        logical.resource_type = r.rtype.clone();
        session.requests.push(logical);
    }
    let mut bundle = SessionBundle::new(session);
    for (name, bytes) in bundle_attachments {
        bundle.insert_attachment(name, bytes);
    }
    bundle
}

/// Documento principal 200 + os pedidos extras.
pub fn with_main(extra: Vec<Req>) -> SessionBundle {
    let mut reqs = vec![Req::doc("r0", "https://app.test/", 200).resp_body("text/html", "<html></html>")];
    reqs.extend(extra);
    build(reqs)
}
