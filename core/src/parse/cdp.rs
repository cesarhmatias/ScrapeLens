//! Parser de eventos CDP (`cdp-events.jsonl`).
//!
//! O CDP é usado para a navegação e para os objetos de header "fácil". Pela
//! matriz D2, nenhum objeto `headers` do CDP comprova sequência/duplicatas;
//! `responseReceivedExtraInfo.headersText` (h1) é a exceção verificada.
//! Cada bloco preserva a origem; a visão primária pode vir do NetLog na
//! correlação, sem apagar o original CDP.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::error::{CoreError, Result};
use crate::model::{
    policy, Attempt, AttemptOutcome, Body, BrowserInfo, CdpRef, Completeness, Connection,
    CookieField, HeaderEvidence, HeaderRole, HeaderView, LogicalRequest, OrderState, Provenance,
    Protocol, Redirect, SessionBundle, SessionMeta, SessionV1, Source, Timings, Verification,
    Warning,
};
use crate::parse::netlog::epoch_ms_to_iso;
use crate::parse::{ImportedSession, ImportReport, InputFormat};

#[derive(Debug, Clone, Default)]
pub struct CdpCapture {
    pub events_total: usize,
    pub events_used: usize,
    pub unhandled_events: usize,
    pub unhandled_samples: Vec<String>,
    pub sessions: Vec<String>,
    pub requests: Vec<CdpRequest>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Default)]
pub struct CdpRequest {
    pub request_id: String,
    pub loader_id: Option<String>,
    pub frame_id: Option<String>,
    pub resource_type: Option<String>,
    pub attempts: Vec<CdpAttempt>,
    pub redirects: Vec<CdpRedirect>,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CdpAttempt {
    pub url: String,
    pub method: String,
    pub protocol: Protocol,
    pub status: Option<u16>,
    pub request_headers: HeaderView,
    pub request_headers_extra: Option<HeaderView>,
    pub response_headers: HeaderView,
    pub response_headers_extra: Option<HeaderView>,
    pub cookie: CookieField,
    pub set_cookies: Vec<crate::model::SetCookieRecord>,
    pub header_evidence: Vec<HeaderEvidence>,
    pub timestamp: Option<f64>,
    pub wall_time: Option<String>,
    pub ended_at: Option<f64>,
    pub connection_id: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub redirect_url: Option<String>,
    pub redirect_status: Option<u16>,
    pub failure: Option<String>,
    pub outcome: AttemptOutcome,
    pub cdp: CdpRef,
}

#[derive(Debug, Clone, Default)]
pub struct CdpRedirect {
    pub status: Option<u16>,
    pub location: String,
    pub from_url: String,
    pub to_url: String,
}

pub fn parse_cdp_jsonl(json: &[u8]) -> Result<CdpCapture> {
    let text = std::str::from_utf8(json).map_err(|error| CoreError::UnsupportedFormat {
        message: format!("cdp-events.jsonl não é UTF-8: {error}"),
    })?;
    let mut capture = CdpCapture::default();
    let mut requests: BTreeMap<String, CdpRequest> = BTreeMap::new();
    let mut request_extra: BTreeMap<String, HeaderView> = BTreeMap::new();
    let mut response_extra: BTreeMap<String, HeaderView> = BTreeMap::new();
    let mut unhandled: BTreeMap<String, usize> = BTreeMap::new();

    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        capture.events_total += 1;
        let event: Value = match serde_json::from_str(line) {
            Ok(event) => event,
            Err(error) => {
                capture.warnings.push(Warning::new(
                    "cdp.line_invalid",
                    format!("linha {} de cdp-events.jsonl inválida: {error}", line_index + 1),
                ));
                continue;
            }
        };
        let session = event.get("session").and_then(Value::as_str);
        if let Some(session) = session {
            if !capture.sessions.iter().any(|known| known == session) {
                capture.sessions.push(session.to_string());
            }
        }
        let method = event.get("method").and_then(Value::as_str).unwrap_or("");
        let params = event.get("params").and_then(Value::as_object);
        match method {
            "Network.requestWillBeSent" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let request = params.get("request").and_then(Value::as_object);
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                let wall_time = params.get("wallTime").and_then(Value::as_f64);
                let cdp = cdp_ref(params, request_id);

                if let Some(restart) = requests.get_mut(request_id) {
                    // Redirect: fecha a tentativa anterior com redirectResponse.
                    if let Some(redirect) = params.get("redirectResponse").and_then(Value::as_object) {
                        let status = redirect
                            .get("status")
                            .and_then(Value::as_u64)
                            .map(|status| status as u16);
                        let redirect_view = redirect_view(redirect, request_id, session, timestamp);
                        let location = redirect_view.first_value("location").map(str::to_string);
                        if let Some(last) = restart.attempts.last_mut() {
                            last.response_headers = redirect_view;
                            last.status = status;
                            last.outcome = AttemptOutcome::Completed;
                            last.ended_at = timestamp;
                            if last.set_cookies.is_empty() {
                                for header in last.response_headers.get_all("set-cookie") {
                                    last.set_cookies.push(crate::model::SetCookieRecord::from_raw(
                                        &header.value,
                                        &header.provenance,
                                    ));
                                }
                            }
                        }
                        if let Some(location) = location {
                            restart.redirects.push(CdpRedirect {
                                status,
                                location: location.clone(),
                                from_url: restart
                                    .attempts
                                    .last()
                                    .map(|attempt| attempt.url.clone())
                                    .unwrap_or_default(),
                                to_url: request
                                    .and_then(|request| request.get("url"))
                                    .and_then(Value::as_str)
                                    .unwrap_or(&location)
                                    .to_string(),
                            });
                        }
                    }
                }

                let mut attempt = CdpAttempt {
                    url: request
                        .and_then(|request| request.get("url"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    method: request
                        .and_then(|request| request.get("method"))
                        .and_then(Value::as_str)
                        .unwrap_or("GET")
                        .to_string(),
                    timestamp,
                    wall_time: wall_time.map(|value| epoch_ms_to_iso((value * 1000.0) as i64)),
                    cdp: cdp.clone(),
                    outcome: AttemptOutcome::Pending,
                    ..Default::default()
                };

                let blink_provenance = policy::provenance_for(
                    Source::Cdp,
                    Some("Network.requestWillBeSent.request.headers"),
                    policy::Direction::Request,
                    policy::WireProtocol::Unknown,
                    "cdp.request.headers",
                    None,
                )
                .with_source_id(request_id.to_string())
                .with_timestamp(timestamp.unwrap_or_default())
                .with_note("subconjunto; ordem diferente do fio; duplicatas não representáveis");
                if let Some(headers) = request.and_then(|request| request.get("headers")) {
                    attempt.request_headers = header_object_to_view(
                        headers,
                        &blink_provenance,
                        "Network.requestWillBeSent.request.headers",
                    );
                }
                if let Some(extra) = request_extra.remove(request_id) {
                    attempt.request_headers_extra = Some(extra);
                    attempt.header_evidence.push(HeaderEvidence {
                        id: format!("{request_id}-req-blink"),
                        role: HeaderRole::Request,
                        protocol: Protocol::Unknown,
                        event: "Network.requestWillBeSent.request.headers".to_string(),
                        source_id: None,
                        stream_id: None,
                        view: attempt.request_headers.clone(),
                    });
                } else if !attempt.request_headers.is_empty() {
                    attempt.header_evidence.push(HeaderEvidence {
                        id: format!("{request_id}-req-blink"),
                        role: HeaderRole::Request,
                        protocol: Protocol::Unknown,
                        event: "Network.requestWillBeSent.request.headers".to_string(),
                        source_id: None,
                        stream_id: None,
                        view: attempt.request_headers.clone(),
                    });
                }

                attempt.cookie = CookieField::from_header_values(
                    &attempt.request_headers.cookie_field_values(),
                    &blink_provenance,
                );

                let request_entry = requests.entry(request_id.to_string()).or_default();
                request_entry.request_id = request_id.to_string();
                request_entry.loader_id = cdp.loader_id.clone();
                request_entry.frame_id = cdp.frame_id.clone();
                request_entry.resource_type = params
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                request_entry.attempts.push(attempt);
                capture.events_used += 1;
            }
            "Network.requestWillBeSentExtraInfo" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                let provenance = policy::provenance_for(
                    Source::Cdp,
                    Some("Network.requestWillBeSentExtraInfo.headers"),
                    policy::Direction::Request,
                    policy::WireProtocol::Unknown,
                    "cdp.extraInfo.headers",
                    None,
                )
                .with_source_id(request_id.to_string())
                .with_timestamp(timestamp.unwrap_or_default())
                .with_note("ordem ASCII; duplicatas colapsadas antes de expor");
                let view = params
                    .get("headers")
                    .map(|headers| {
                        header_object_to_view(
                            headers,
                            &provenance,
                            "Network.requestWillBeSentExtraInfo.headers",
                        )
                    })
                    .unwrap_or_default();

                if let Some(request) = requests.get_mut(request_id) {
                    if let Some(attempt) = request.attempts.last_mut() {
                        attempt.request_headers_extra = Some(view.clone());
                        attempt.header_evidence.push(HeaderEvidence {
                            id: format!("{request_id}-req-extra"),
                            role: HeaderRole::Request,
                            protocol: attempt.protocol,
                            event: "Network.requestWillBeSentExtraInfo.headers".to_string(),
                            source_id: None,
                            stream_id: None,
                            view: view.clone(),
                        });
                        if attempt.cookie.raw.is_empty() {
                            attempt.cookie = CookieField::from_header_values(
                                &view.cookie_field_values(),
                                &provenance,
                            );
                        }
                        if let Some(cookies) = params.get("associatedCookies").and_then(Value::as_array) {
                            for cookie in cookies {
                                let blocked = cookie
                                    .get("blockedReasons")
                                    .and_then(Value::as_array)
                                    .is_some_and(|reasons| !reasons.is_empty());
                                if blocked {
                                    attempt
                                        .cookie
                                        .notes
                                        .push("cookie associado bloqueado (associatedCookies)".to_string());
                                }
                            }
                        }
                    } else {
                        request_extra.insert(request_id.to_string(), view);
                    }
                } else {
                    request_extra.insert(request_id.to_string(), view);
                }
                capture.events_used += 1;
            }
            "Network.responseReceived" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let response = params.get("response").and_then(Value::as_object);
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                let protocol = response
                    .and_then(|response| response.get("protocol"))
                    .and_then(Value::as_str);
                let status = response
                    .and_then(|response| response.get("status"))
                    .and_then(Value::as_u64)
                    .filter(|status| *status > 0)
                    .map(|status| status as u16);
                let (view, evidence_event) = response_view(
                    response,
                    request_id,
                    timestamp,
                    protocol,
                    "Network.responseReceived",
                );
                let mut attempt = CdpAttempt {
                    protocol: Protocol::parse_opt(protocol),
                    status,
                    response_headers: view,
                    timestamp,
                    ended_at: timestamp,
                    outcome: if status.is_some() {
                        AttemptOutcome::Completed
                    } else {
                        AttemptOutcome::Pending
                    },
                    ..Default::default()
                };
                attempt.connection_id = response
                    .and_then(|response| response.get("connectionId"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                attempt.remote_ip = response
                    .and_then(|response| response.get("remoteIPAddress"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                attempt.remote_port = response
                    .and_then(|response| response.get("remotePort"))
                    .and_then(Value::as_u64)
                    .map(|port| port as u16);
                attempt.header_evidence.push(HeaderEvidence {
                    id: format!("{request_id}-resp-{evidence_event}"),
                    role: HeaderRole::Response,
                    protocol: attempt.protocol,
                    event: evidence_event,
                    source_id: None,
                    stream_id: None,
                    view: attempt.response_headers.clone(),
                });
                for header in attempt.response_headers.get_all("set-cookie") {
                    for value in split_joined_header(&header.value) {
                        attempt.set_cookies.push(crate::model::SetCookieRecord::from_raw(
                            &value,
                            &header.provenance,
                        ));
                    }
                }

                if let Some(request) = requests.get_mut(request_id) {
                    if let Some(current) = request.attempts.last_mut() {
                        current.protocol = attempt.protocol;
                        current.status = attempt.status;
                        current.response_headers = attempt.response_headers;
                        current.connection_id = attempt.connection_id;
                        current.remote_ip = attempt.remote_ip;
                        current.remote_port = attempt.remote_port;
                        current.ended_at = attempt.ended_at;
                        current.outcome = attempt.outcome;
                        current.set_cookies = attempt.set_cookies;
                        current.header_evidence.extend(attempt.header_evidence);
                    } else {
                        requests.entry(request_id.to_string()).or_default().attempts.push(attempt);
                    }
                } else {
                    let mut entry = CdpRequest {
                        request_id: request_id.to_string(),
                        ..Default::default()
                    };
                    entry.attempts.push(attempt);
                    requests.insert(request_id.to_string(), entry);
                }
                capture.events_used += 1;
            }
            "Network.responseReceivedExtraInfo" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                let status = params
                    .get("statusCode")
                    .and_then(Value::as_u64)
                    .map(|status| status as u16);
                let (view, event) = response_view_from_extra(
                    params,
                    request_id,
                    timestamp,
                    status,
                );
                if let Some(request) = requests.get_mut(request_id) {
                    if let Some(attempt) = request.attempts.last_mut() {
                        attempt.status = status.or(attempt.status);
                        attempt.response_headers_extra = Some(view.clone());
                        if view.verification() > attempt.response_headers.verification() {
                            attempt.response_headers = view.clone();
                        }
                        attempt.header_evidence.push(HeaderEvidence {
                            id: format!("{request_id}-resp-extra"),
                            role: HeaderRole::Response,
                            protocol: attempt.protocol,
                            event,
                            source_id: None,
                            stream_id: None,
                            view: view.clone(),
                        });
                        if view.verification() >= Verification::Verified {
                            attempt.set_cookies.clear();
                            for header in view.get_all("set-cookie") {
                                for value in split_joined_header(&header.value) {
                                    attempt.set_cookies.push(crate::model::SetCookieRecord::from_raw(
                                        &value,
                                        &header.provenance,
                                    ));
                                }
                            }
                        }
                    } else {
                        response_extra.insert(request_id.to_string(), view);
                    }
                } else {
                    response_extra.insert(request_id.to_string(), view);
                }
                capture.events_used += 1;
            }
            "Network.loadingFinished" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                if let Some(request) = requests.get_mut(request_id) {
                    if let Some(attempt) = request.attempts.last_mut() {
                        attempt.ended_at = timestamp;
                        if attempt.status.is_some() {
                            attempt.outcome = AttemptOutcome::Completed;
                        }
                    }
                }
                capture.events_used += 1;
            }
            "Network.loadingFailed" => {
                let Some(params) = params else { continue };
                let Some(request_id) = params.get("requestId").and_then(Value::as_str) else {
                    continue;
                };
                let timestamp = params.get("timestamp").and_then(Value::as_f64);
                let error = params
                    .get("errorText")
                    .and_then(Value::as_str)
                    .unwrap_or("loadingFailed");
                let canceled = params.get("canceled").and_then(Value::as_bool).unwrap_or(false);
                let failure = format!("{error}{}", if canceled { " (cancelado)" } else { "" });
                if let Some(request) = requests.get_mut(request_id) {
                    request.failure = Some(failure.clone());
                    if let Some(attempt) = request.attempts.last_mut() {
                        attempt.failure = Some(failure);
                        attempt.ended_at = timestamp;
                        attempt.outcome = if canceled {
                            AttemptOutcome::Aborted
                        } else {
                            AttemptOutcome::Failed
                        };
                    }
                }
                capture.events_used += 1;
            }
            other => {
                let key = if other.is_empty() { "<sem method>" } else { other };
                *unhandled.entry(key.to_string()).or_default() += 1;
            }
        }
    }

    // ExtraInfo que chegou antes do request/response: anexa agora, com aviso.
    for (request_id, extra) in request_extra {
        if let Some(request) = requests.get_mut(&request_id) {
            if let Some(attempt) = request.attempts.last_mut() {
                attempt.request_headers_extra = Some(extra);
            }
        } else {
            capture.warnings.push(Warning::new(
                "cdp.extra_info_without_request",
                format!("requestWillBeSentExtraInfo sem requestWillBeSent: {request_id}"),
            ));
        }
    }
    for (request_id, extra) in response_extra {
        if let Some(request) = requests.get_mut(&request_id) {
            if let Some(attempt) = request.attempts.last_mut() {
                attempt.response_headers_extra = Some(extra);
            }
        } else {
            capture.warnings.push(Warning::new(
                "cdp.response_extra_without_request",
                format!("responseReceivedExtraInfo sem request: {request_id}"),
            ));
        }
    }

    capture.unhandled_events = unhandled.values().sum();
    for (method, count) in &unhandled {
        if capture.unhandled_samples.len() < 10 {
            capture.unhandled_samples.push(format!("{method} × {count}"));
        }
    }
    if capture.unhandled_events > 0 {
        capture.warnings.push(Warning::new(
            "cdp.unhandled_events",
            format!(
                "{} evento(s) CDP de métodos não tratados (contados, não descartados)",
                capture.unhandled_events
            ),
        ).with_detail(serde_json::json!({ "samples": capture.unhandled_samples })));
    }

    // Ordena tentativas por timestamp (eventos podem chegar intercalados).
    for request in requests.values_mut() {
        request
            .attempts
            .sort_by(|a, b| a.timestamp.unwrap_or(0.0).partial_cmp(&b.timestamp.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
        if request.attempts.is_empty() {
            capture.warnings.push(Warning::new(
                "cdp.request_without_attempt",
                format!("requestId {} sem requestWillBeSent utilizável", request.request_id),
            ));
            continue;
        }
        capture.requests.push(request.clone());
    }
    Ok(capture)
}

fn cdp_ref(params: &Map<String, Value>, request_id: &str) -> CdpRef {
    CdpRef {
        session_id: params.get("sessionId").and_then(Value::as_str).map(str::to_string),
        request_id: Some(request_id.to_string()),
        loader_id: params.get("loaderId").and_then(Value::as_str).map(str::to_string),
        frame_id: params.get("frameId").and_then(Value::as_str).map(str::to_string),
    }
}

fn header_object_to_view(headers: &Value, provenance: &Provenance, event: &str) -> HeaderView {
    let mut view = HeaderView::new(OrderState::Reconstructed);
    if let Some(object) = headers.as_object() {
        for (name, value) in object {
            let value = match value {
                Value::String(value) => value.clone(),
                other => other.to_string(),
            };
            view.add(name, value, provenance);
        }
    } else if let Some(array) = headers.as_array() {
        for header in array {
            if let (Some(name), Some(value)) = (
                header.get("name").and_then(Value::as_str),
                header.get("value").and_then(Value::as_str),
            ) {
                view.add(name, value, provenance);
            }
        }
    }
    view.notes
        .push(format!("{event}: objeto não preserva sequência transmitida"));
    view
}

fn redirect_view(
    redirect: &Map<String, Value>,
    request_id: &str,
    _session: Option<&str>,
    timestamp: Option<f64>,
) -> HeaderView {
    let protocol = Protocol::parse_opt(redirect.get("protocol").and_then(Value::as_str));
    let wire = match protocol {
        Protocol::H1 => policy::WireProtocol::H1,
        Protocol::H2 => policy::WireProtocol::H2,
        Protocol::H3 => policy::WireProtocol::H3,
        Protocol::Unknown => policy::WireProtocol::Unknown,
    };
    let provenance = policy::provenance_for(
        Source::Cdp,
        Some("Network.requestWillBeSent.redirectResponse.headersText"),
        policy::Direction::Response,
        wire,
        "cdp.redirectResponse.headersText",
        None,
    )
    .with_source_id(request_id.to_string())
    .with_timestamp(timestamp.unwrap_or_default());
    if let Some(text) = redirect.get("headersText").and_then(Value::as_str) {
        let (view, _issues) = HeaderView::from_http_block(text, &provenance);
        return view;
    }
    let provenance = provenance.with_verification(Verification::Unverified);
    redirect
        .get("headers")
        .map(|headers| {
            header_object_to_view(
                headers,
                &provenance,
                "Network.requestWillBeSent.redirectResponse.headers",
            )
        })
        .unwrap_or_default()
}

fn response_view(
    response: Option<&Map<String, Value>>,
    request_id: &str,
    timestamp: Option<f64>,
    protocol: Option<&str>,
    event: &str,
) -> (HeaderView, String) {
    let protocol = Protocol::parse_opt(protocol);
    let wire = match protocol {
        Protocol::H1 => policy::WireProtocol::H1,
        Protocol::H2 => policy::WireProtocol::H2,
        Protocol::H3 => policy::WireProtocol::H3,
        Protocol::Unknown => policy::WireProtocol::Unknown,
    };
    if let Some(text) = response
        .and_then(|response| response.get("headersText"))
        .and_then(Value::as_str)
    {
        let provenance = policy::provenance_for(
            Source::Cdp,
            Some("Network.responseReceived.headersText"),
            policy::Direction::Response,
            wire,
            "cdp.response.headersText",
            None,
        )
        .with_source_id(request_id.to_string())
        .with_timestamp(timestamp.unwrap_or_default());
        let (view, _issues) = HeaderView::from_http_block(text, &provenance);
        return (view, format!("{event}.headersText"));
    }
    let provenance = policy::provenance_for(
        Source::Cdp,
        Some("Network.responseReceived.headers"),
        policy::Direction::Response,
        wire,
        "cdp.response.headers",
        None,
    )
    .with_source_id(request_id.to_string())
    .with_timestamp(timestamp.unwrap_or_default())
    .with_note("objeto CDP: ordem ASCII e duplicatas fundidas");
    let view = response
        .and_then(|response| response.get("headers"))
        .map(|headers| header_object_to_view(headers, &provenance, event))
        .unwrap_or_default();
    (view, format!("{event}.headers"))
}

fn response_view_from_extra(
    params: &Map<String, Value>,
    request_id: &str,
    timestamp: Option<f64>,
    status: Option<u16>,
) -> (HeaderView, String) {
    if let Some(text) = params.get("headersText").and_then(Value::as_str) {
        let provenance = policy::provenance_for(
            Source::Cdp,
            Some("Network.responseReceivedExtraInfo.headersText"),
            policy::Direction::Response,
            policy::WireProtocol::H1,
            "cdp.extraInfo.headersText",
            None,
        )
        .with_source_id(request_id.to_string())
        .with_timestamp(timestamp.unwrap_or_default());
        let (view, _issues) = HeaderView::from_http_block(text, &provenance);
        return (view, "Network.responseReceivedExtraInfo.headersText".to_string());
    }
    let provenance = policy::provenance_for(
        Source::Cdp,
        Some("Network.responseReceivedExtraInfo.headers"),
        policy::Direction::Response,
        policy::WireProtocol::Unknown,
        "cdp.extraInfo.headers",
        None,
    )
    .with_source_id(request_id.to_string())
    .with_timestamp(timestamp.unwrap_or_default())
    .with_note("objeto CDP ordenado em ASCII; duplicatas fundidas com \\n")
    .with_note(match status {
        Some(status) => format!("statusCode={status}"),
        None => "statusCode ausente".to_string(),
    });
    let view = params
        .get("headers")
        .map(|headers| {
            header_object_to_view(
                headers,
                &provenance,
                "Network.responseReceivedExtraInfo.headers",
            )
        })
        .unwrap_or_default();
    (view, "Network.responseReceivedExtraInfo.headers".to_string())
}

/// O objeto CDP funde `Set-Cookie` repetidos com `\n`. Reconstrói as linhas
/// para o parse de cookies, mantendo o valor original no HeaderView.
pub fn split_joined_header(value: &str) -> Vec<String> {
    if value.contains('\n') {
        value
            .split('\n')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        vec![value.to_string()]
    }
}

pub fn build_cdp_session(capture: &CdpCapture) -> (SessionV1, ImportReport) {
    let mut report = ImportReport::new(InputFormat::Cdp);
    report.source_events = capture.events_total;
    report.source_events_used = capture.events_used;

    let started_at = capture
        .requests
        .iter()
        .filter_map(|request| request.attempts.first())
        .filter_map(|attempt| attempt.wall_time.clone())
        .min()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let mut meta = SessionMeta::new(
        format!("cdp-{}", crate::parse::har::stable_id(b"cdp")),
        started_at,
        BrowserInfo {
            name: "Chrome".to_string(),
            ..BrowserInfo::default()
        },
    );
    meta.capture = Some(crate::model::CaptureMeta {
        mode: Some("cdp".to_string()),
        notes: Some("CDP: headers de objeto não comprovam sequência; use NetLog".to_string()),
        ..Default::default()
    });
    meta.completeness = Completeness::partial("captura CDP sem NetLog correlacionado");
    let mut session = SessionV1::new(meta);
    for warning in &capture.warnings {
        session.add_warning(warning.clone());
        report.warn(warning.clone());
    }

    let mut connections: BTreeMap<String, String> = BTreeMap::new();
    for (index, request) in capture.requests.iter().enumerate() {
        let logical_id = format!("cdp-r{:04}", index + 1);
        let first = request.attempts.first();
        let mut logical = LogicalRequest::new(
            &logical_id,
            first.map(|attempt| attempt.url.clone()).unwrap_or_default(),
            first.map(|attempt| attempt.method.clone()).unwrap_or_default(),
        );
        logical.resource_type = request.resource_type.clone();
        logical.cdp = Some(CdpRef {
            session_id: None,
            request_id: Some(request.request_id.clone()),
            loader_id: request.loader_id.clone(),
            frame_id: request.frame_id.clone(),
        });
        logical.provenance = Provenance::new(Source::Cdp, "Network.*", Verification::Unverified)
            .with_source_id(request.request_id.clone())
            .with_note("estrutura vinda do CDP; verificação por informação");

        for (attempt_index, parsed) in request.attempts.iter().enumerate() {
            let attempt_id = format!("{logical_id}-a{}", attempt_index + 1);
            let mut attempt = Attempt::new(
                &attempt_id,
                &logical_id,
                attempt_index as u32,
                &parsed.url,
                &parsed.method,
            );
            attempt.protocol = parsed.protocol;
            attempt.status = parsed.status;
            attempt.outcome = parsed.outcome;
            attempt.started_at = parsed.timestamp;
            attempt.ended_at = parsed.ended_at;
            attempt.failure = parsed.failure.clone();
            attempt.cdp = Some(parsed.cdp.clone());
            attempt.request_headers = parsed
                .request_headers_extra
                .clone()
                .unwrap_or_else(|| parsed.request_headers.clone());
            attempt.response_headers = parsed.response_headers.clone();
            attempt.cookie = parsed.cookie.clone();
            attempt.set_cookies = parsed.set_cookies.clone();
            attempt.header_evidence = parsed.header_evidence.clone();
            attempt.request_body = Body::unavailable(
                "corpo CDP não carregado; captura deve fornecer anexo separado",
            );
            attempt.response_body = Body::unavailable(
                "corpo CDP não carregado; captura deve fornecer anexo separado",
            );
            attempt.provenance = Provenance::new(
                Source::Cdp,
                "Network.attempt",
                Verification::Unverified,
            )
            .with_source_id(request.request_id.clone())
            .with_timestamp(parsed.timestamp.unwrap_or_default());

            if let (Some(start), Some(end)) = (parsed.timestamp, parsed.ended_at) {
                attempt.timings = Timings {
                    request_time: parsed.timestamp,
                    wall_time: parsed.wall_time.clone(),
                    total_ms: Some((end - start).max(0.0) * 1000.0),
                    estimated: false,
                    ..Default::default()
                };
            } else {
                attempt.timings.wall_time = parsed.wall_time.clone();
                attempt.timings.request_time = parsed.timestamp;
            }

            let host = parsed
                .url
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .and_then(|authority| authority.rsplit('@').next())
                .map(|authority| authority.split(':').next().unwrap_or(authority).to_string());
            let connection_key = parsed
                .connection_id
                .clone()
                .or_else(|| parsed.remote_ip.clone())
                .or_else(|| host.clone());
            if let Some(key) = connection_key {
                let connection_id = connections
                    .entry(key.clone())
                    .or_insert_with(|| {
                        let id = format!(
                            "cdp-conn-{}",
                            crate::parse::har::stable_id(key.as_bytes())
                        );
                        session.connections.push(Connection {
                            id: id.clone(),
                            netlog_id: None,
                            protocol: parsed.protocol,
                            host: host.clone(),
                            port: parsed.remote_port,
                            ip: parsed.remote_ip.clone(),
                            alpn: None,
                            tls_version: None,
                            reused: None,
                            provenance: Provenance::new(
                                Source::Cdp,
                                "response.connectionId",
                                Verification::Verified,
                            ),
                        });
                        id
                    })
                    .clone();
                attempt.connection_id = Some(connection_id);
            }

            if let Some(status) = parsed.status {
                logical.status = Some(status);
            }
            logical.attempts.push(attempt);
        }

        for (redirect_index, redirect) in request.redirects.iter().enumerate() {
            logical.redirects.push(Redirect {
                id: format!("{logical_id}-r{}", redirect_index + 1),
                logical_id: logical_id.clone(),
                from_attempt_id: format!("{logical_id}-a{}", redirect_index + 1),
                to_attempt_id: logical
                    .attempts
                    .get(redirect_index + 1)
                    .map(|attempt| attempt.id.clone()),
                status: redirect.status,
                location: Some(redirect.location.clone()),
                from_url: redirect.from_url.clone(),
                to_url: Some(redirect.to_url.clone()),
                provenance: Provenance::new(
                    Source::Cdp,
                    "redirectResponse",
                    Verification::Unverified,
                ),
            });
        }

        if request.failure.is_some() {
            session.add_warning(Warning::new(
                "cdp.request_failed",
                format!(
                    "requestId {} falhou: {}",
                    request.request_id,
                    request.failure.clone().unwrap_or_default()
                ),
            ));
        }
        logical.timings = logical
            .attempts
            .last()
            .map(|attempt| attempt.timings.clone())
            .unwrap_or_default();
        logical.refresh_primary_from_attempt();
        session.requests.push(logical);
    }

    if session.requests.is_empty() {
        session
            .session
            .completeness
            .add_reason("nenhuma requisição CDP utilizável");
    }
    session.recompute_completeness();
    (session, report)
}

pub fn import_cdp(json: &[u8]) -> Result<ImportedSession> {
    let capture = parse_cdp_jsonl(json)?;
    let (session, mut report) = build_cdp_session(&capture);
    report.bytes_read = json.len();
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: Some(json.to_vec()),
        netlog_json: None,
        attachments: Default::default(),
    };
    Ok(ImportedSession::new(bundle, report))
}
