//! Projeções JSON compactas do modelo do core. Headers continuam arrays
//! ordenados de pares, com duplicatas, pseudoheaders separados e a ordem
//! original; nada é ordenado nem fundido aqui.

use scrapelens_core::model::{
    Attempt, Body, BodyState, CookieField, HeaderView, LogicalRequest, SetCookieRecord,
};
use serde_json::{json, Map, Value};

pub const PLACEHOLDER: &str = "[REDACTED]";

/// `host[:porta]` em minúsculas, ou string vazia.
pub fn host_of(url: &str) -> String {
    url.split_once("://")
        .map(|(_, rest)| {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            authority.to_ascii_lowercase()
        })
        .unwrap_or_default()
}

pub fn body_state(body: &Body) -> &'static str {
    body.state.as_str()
}

fn source_label(view: &HeaderView) -> Value {
    view.iter_all()
        .next()
        .map(|entry| json!(entry.provenance.source.as_str()))
        .unwrap_or(Value::Null)
}

fn method_label(view: &HeaderView) -> Value {
    view.iter_all()
        .next()
        .map(|entry| json!(entry.provenance.method))
        .unwrap_or(Value::Null)
}

pub fn header_view(view: &HeaderView, verbose: bool) -> Value {
    let pair = |entry: &scrapelens_core::model::HeaderEntry| -> Value {
        if verbose {
            let mut object = Map::new();
            object.insert("name".into(), json!(entry.name));
            object.insert("value".into(), json!(entry.value));
            object.insert("source".into(), json!(entry.provenance.source.as_str()));
            object.insert("method".into(), json!(entry.provenance.method));
            object.insert(
                "verification".into(),
                json!(entry.provenance.verification.as_str()),
            );
            if let Some(event) = &entry.provenance.event {
                object.insert("event".into(), json!(event));
            }
            if let Some(id) = &entry.provenance.source_id {
                object.insert("sourceId".into(), json!(id));
            }
            if let Some(ts) = entry.provenance.timestamp {
                object.insert("timestamp".into(), json!(ts));
            }
            if let Some(version) = &entry.provenance.browser_version {
                object.insert("browserVersion".into(), json!(version));
            }
            Value::Object(object)
        } else {
            json!([entry.name, entry.value])
        }
    };
    let mut object = Map::new();
    if let Some(line) = &view.start_line {
        object.insert("startLine".into(), json!(line));
    }
    object.insert(
        "orderState".into(),
        serde_json::to_value(view.order_state).unwrap_or(Value::Null),
    );
    object.insert("source".into(), source_label(view));
    object.insert("method".into(), method_label(view));
    object.insert("verification".into(), json!(view.verification().as_str()));
    object.insert(
        "pseudoHeaders".into(),
        Value::Array(view.pseudo_headers.iter().map(pair).collect()),
    );
    object.insert(
        "headers".into(),
        Value::Array(view.headers.iter().map(pair).collect()),
    );
    if let Some(raw) = &view.raw_block {
        object.insert("rawBlock".into(), json!(raw));
    }
    if !view.notes.is_empty() {
        object.insert("notes".into(), json!(view.notes));
    }
    Value::Object(object)
}

pub fn cookie_field(field: &CookieField) -> Value {
    json!({
        "raw": field.raw,
        "pairs": field.pairs.iter().map(|p| json!({"name": p.name, "value": p.value})).collect::<Vec<_>>(),
        "wireLines": field.wire_lines,
        "unparsed": field.unparsed,
        "notes": field.notes,
    })
}

pub fn set_cookie(record: &SetCookieRecord) -> Value {
    let mut object = Map::new();
    object.insert("raw".into(), json!(record.raw));
    if let Some(parsed) = &record.parsed {
        object.insert("name".into(), json!(parsed.name));
        object.insert(
            "attributes".into(),
            json!({
                "domain": parsed.domain,
                "path": parsed.path,
                "expires": parsed.expires,
                "maxAge": parsed.max_age,
                "secure": parsed.secure,
                "httpOnly": parsed.http_only,
                "sameSite": parsed.same_site,
                "partitioned": parsed.partitioned,
                "extensions": parsed.extensions,
            }),
        );
    }
    if let Some(error) = &record.parse_error {
        object.insert("parseError".into(), json!(error));
    }
    object.insert("source".into(), json!(record.provenance.source.as_str()));
    Value::Object(object)
}

/// Descritor de corpo (sem conteúdo). `masked` só aparece na visão mascarada.
///
/// `body` é o corpo da visão em uso; `original` é o corpo correspondente na
/// sessão original: estado, tamanho e tipo (metadados, não segredo) saem dele,
/// para a visão mascarada não esconder que existe um corpo.
pub fn body_descriptor(body: &Body, original: &Body, masked_view: bool) -> Value {
    let meta = if masked_view { original } else { body };
    let mut object = Map::new();
    object.insert("state".into(), json!(body_state(meta)));
    if let Some(bytes) = meta.bytes {
        object.insert("bytes".into(), json!(bytes));
    }
    if let Some(at) = meta.truncated_at {
        object.insert("truncatedAt".into(), json!(at));
    }
    if let Some(ct) = &meta.content_type {
        object.insert("contentType".into(), json!(ct));
    }
    if let Some(enc) = &meta.content_encoding {
        object.insert("contentEncoding".into(), json!(enc));
    }
    if !meta.transformed.is_empty() {
        object.insert("transformed".into(), json!(meta.transformed));
    }
    if let Some(note) = &body.note {
        object.insert("note".into(), json!(note));
    }
    object.insert(
        "hasContent".into(),
        json!(meta.attachment.is_some() && meta.has_bytes()),
    );
    if masked_view {
        if let Some(kind) = masked_kind(body) {
            object.insert("masked".into(), json!(kind));
        }
    }
    Value::Object(object)
}

/// `unsupported` (corpo não sanitizável, conteúdo retido) ou `redacted`.
pub fn masked_kind(body: &Body) -> Option<&'static str> {
    let note = body.note.as_deref().unwrap_or("");
    if body.state == BodyState::Discarded && note.contains("sanitização") {
        Some("unsupported")
    } else if note.starts_with("corpo sanitizado") {
        Some("redacted")
    } else {
        None
    }
}

pub fn sources_of(request: &LogicalRequest) -> Vec<&'static str> {
    let mut sources: Vec<&'static str> = Vec::new();
    let mut add = |label: &'static str| {
        if !sources.contains(&label) {
            sources.push(label);
        }
    };
    for attempt in &request.attempts {
        add(attempt.provenance.source.as_str());
        for evidence in &attempt.header_evidence {
            add(evidence.view.iter_all().next().map_or_else(
                || attempt.provenance.source.as_str(),
                |entry| entry.provenance.source.as_str(),
            ));
        }
    }
    if request.cdp.is_some() && !sources.contains(&"cdp") {
        sources.push("cdp");
    }
    if !request.netlog.is_empty() && !sources.contains(&"netlog") {
        sources.push("netlog");
    }
    if sources.is_empty() {
        sources.push(request.provenance.source.as_str());
    }
    sources
}

pub fn request_summary(request: &LogicalRequest, original: &LogicalRequest) -> Value {
    let mut object = Map::new();
    object.insert("requestId".into(), json!(request.id));
    object.insert("method".into(), json!(request.method));
    object.insert("url".into(), json!(request.url));
    object.insert("host".into(), json!(host_of(&request.url)));
    if let Some(status) = request.status {
        object.insert("status".into(), json!(status));
    }
    if let Some(kind) = &request.resource_type {
        object.insert("resourceType".into(), json!(kind));
    }
    object.insert(
        "protocol".into(),
        serde_json::to_value(request.protocol).unwrap_or(Value::Null),
    );
    if let Some(ms) = request.timings.total_ms {
        object.insert("totalMs".into(), json!(ms));
    }
    if let Some(start) = request
        .attempts
        .iter()
        .filter_map(|a| a.started_at)
        .reduce(f64::min)
    {
        object.insert("startedAt".into(), json!(start));
    }
    object.insert("attempts".into(), json!(request.attempts.len()));
    object.insert("redirects".into(), json!(request.redirects.len()));
    object.insert("sources".into(), json!(sources_of(request)));
    object.insert(
        "match".into(),
        serde_json::to_value(request.match_state).unwrap_or(Value::Null),
    );
    if let Some(target) = &request.target {
        object.insert("targetType".into(), json!(target.kind.as_str()));
    }
    object.insert(
        "hasRequestBody".into(),
        json!(original.request_body.has_bytes()),
    );
    object.insert(
        "hasResponseBody".into(),
        json!(original.response_body.has_bytes()),
    );
    if !request.links.is_empty() {
        object.insert("links".into(), json!(request.links.len()));
    }
    Value::Object(object)
}

fn attempt_summary(attempt: &Attempt) -> Value {
    json!({
        "id": attempt.id,
        "index": attempt.index,
        "url": attempt.url,
        "method": attempt.method,
        "status": attempt.status,
        "outcome": attempt.outcome,
        "failure": attempt.failure,
        "connectionId": attempt.connection_id,
        "streamSessionId": attempt.stream_session_id,
        "protocol": attempt.protocol,
        "match": attempt.match_state,
        "source": attempt.provenance.source.as_str(),
    })
}

pub fn request_detail(
    request: &LogicalRequest,
    original: &LogicalRequest,
    attempt: Option<&Attempt>,
    verbose: bool,
    masked: bool,
) -> Value {
    // Corpos da sessão original (metadados) para a mesma visão.
    let (orig_req_body, orig_resp_body) = match attempt {
        Some(a) => original
            .attempts
            .iter()
            .find(|o| o.id == a.id)
            .map_or((&original.request_body, &original.response_body), |o| {
                (&o.request_body, &o.response_body)
            }),
        None => (&original.request_body, &original.response_body),
    };
    // Visão: a tentativa pedida ou a primária da requisição lógica.
    let (
        url,
        method,
        status,
        protocol,
        req_h,
        resp_h,
        cookie,
        set_cookies,
        req_body,
        resp_body,
        timings,
        cdp,
        netlog,
        match_state,
        candidates,
    ) = match attempt {
        Some(a) => (
            &a.url,
            &a.method,
            a.status,
            a.protocol,
            &a.request_headers,
            &a.response_headers,
            &a.cookie,
            &a.set_cookies,
            &a.request_body,
            &a.response_body,
            &a.timings,
            a.cdp.as_ref(),
            &a.netlog,
            a.match_state,
            &a.match_candidates,
        ),
        None => (
            &request.url,
            &request.method,
            request.status,
            request.protocol,
            &request.request_headers,
            &request.response_headers,
            &request.cookie,
            &request.set_cookies,
            &request.request_body,
            &request.response_body,
            &request.timings,
            request.cdp.as_ref(),
            &request.netlog,
            request.match_state,
            &request.match_candidates,
        ),
    };
    let initiator = attempt
        .and_then(|a| a.initiator.as_ref())
        .or_else(|| request.attempts.last().and_then(|a| a.initiator.as_ref()));
    let evidence_source = if attempt.is_some() {
        attempt.map(|a| &a.header_evidence[..]).unwrap_or(&[])
    } else {
        request
            .attempts
            .last()
            .map(|a| &a.header_evidence[..])
            .unwrap_or(&[])
    };
    let mut object = Map::new();
    object.insert("requestId".into(), json!(request.id));
    object.insert("method".into(), json!(method));
    object.insert("url".into(), json!(url));
    if let Some(status) = status {
        object.insert("status".into(), json!(status));
    }
    object.insert(
        "protocol".into(),
        serde_json::to_value(protocol).unwrap_or(Value::Null),
    );
    if let Some(kind) = &request.resource_type {
        object.insert("resourceType".into(), json!(kind));
    }
    if let Some(a) = attempt {
        object.insert("attemptId".into(), json!(a.id));
    }
    if let Some(target) = &request.target {
        object.insert(
            "target".into(),
            serde_json::to_value(target).unwrap_or(Value::Null),
        );
    }
    object.insert(
        "links".into(),
        serde_json::to_value(&request.links).unwrap_or(Value::Null),
    );
    object.insert(
        "attempts".into(),
        Value::Array(request.attempts.iter().map(attempt_summary).collect()),
    );
    object.insert(
        "redirects".into(),
        serde_json::to_value(&request.redirects).unwrap_or(Value::Null),
    );
    object.insert("request".into(), header_view(req_h, verbose));
    object.insert("response".into(), header_view(resp_h, verbose));
    object.insert("cookies".into(), cookie_field(cookie));
    object.insert(
        "setCookies".into(),
        Value::Array(set_cookies.iter().map(set_cookie).collect()),
    );
    object.insert(
        "headerEvidence".into(),
        Value::Array(
            evidence_source
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "role": e.role,
                        "protocol": e.protocol,
                        "event": e.event,
                        "sourceId": e.source_id,
                        "streamId": e.stream_id,
                        "orderState": e.view.order_state,
                        "headers": e.view.headers.len(),
                        "pseudoHeaders": e.view.pseudo_headers.len(),
                        "verification": e.view.verification().as_str(),
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "requestBody".into(),
        body_descriptor(req_body, orig_req_body, masked),
    );
    object.insert(
        "responseBody".into(),
        body_descriptor(resp_body, orig_resp_body, masked),
    );
    object.insert("timings".into(), timings_json(timings));
    if let Some(initiator) = initiator {
        object.insert(
            "initiator".into(),
            serde_json::to_value(initiator).unwrap_or(Value::Null),
        );
    }
    object.insert(
        "origin".into(),
        json!({
            "sources": sources_of(request),
            "cdp": cdp,
            "netlog": if netlog.is_empty() { Value::Null } else { serde_json::to_value(netlog).unwrap_or(Value::Null) },
            "match": match_state,
            "matchCandidates": candidates,
            "provenance": {
                "source": request.provenance.source.as_str(),
                "method": request.provenance.method,
                "verification": request.provenance.verification.as_str(),
                "notes": request.provenance.notes,
            },
        }),
    );
    Value::Object(object)
}

pub fn timings_json(timings: &scrapelens_core::model::Timings) -> Value {
    let span = |s: &Option<scrapelens_core::model::entities::Span>| {
        s.as_ref()
            .map(|s| json!({"start": s.start, "end": s.end, "ms": s.duration_ms()}))
    };
    json!({
        "requestTime": timings.request_time,
        "wallTime": timings.wall_time,
        "dns": span(&timings.dns),
        "connect": span(&timings.connect),
        "tls": span(&timings.tls),
        "send": span(&timings.send),
        "wait": span(&timings.wait),
        "receive": span(&timings.receive),
        "totalMs": timings.total_ms,
        "estimated": timings.estimated,
    })
}
