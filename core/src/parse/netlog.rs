//! Importador de NetLog do Chrome.
//!
//! O NetLog é a única fonte que comprova ordem de transmissão (ver
//! `docs/02-matriz-fidelidade.md`). Este módulo preserva:
//! - pares na ordem do evento, com duplicatas;
//! - pseudoheaders separados;
//! - repetições fundidas por `\x00` nos eventos de sessão h2/h3 (expandidas);
//! - proveniência por bloco e verificação conforme D2;
//! - eventos desconhecidos e linhas malformadas como avisos, nunca silêncio.
//!
//! IDs do NetLog não são equivalentes aos do CDP: aqui só se usa a cadeia
//! explícita `HTTP_STREAM_JOB_BOUND_TO_REQUEST` para ligar headers de sessão ao
//! `URL_REQUEST`; a correlação com CDP fica em [`crate::correlate`].

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::error::{CoreError, Result};
use crate::model::{
    policy, Attempt, AttemptOutcome, Body, BrowserInfo, Completeness, Connection, CookieField,
    HeaderEvidence, HeaderRole, HeaderView, LogicalRequest, OrderState, Protocol, Provenance,
    Redirect, SessionBundle, SessionMeta, SessionV1, Source, StreamSession, Timings, Verification,
    Warning,
};
use crate::parse::{ImportReport, ImportedSession, InputFormat};

const MAX_UNKNOWN_SAMPLES: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct NetlogCapture {
    pub browser: BrowserInfo,
    pub started_at: Option<String>,
    pub events_total: usize,
    pub events_used: usize,
    pub events_unknown: usize,
    pub unknown_event_samples: Vec<String>,
    pub requests: Vec<NetlogUrlRequest>,
    pub warnings: Vec<Warning>,
    pub unlinked_session_events: usize,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogUrlRequest {
    pub source_id: u32,
    pub url: String,
    pub method: String,
    pub request_type: Option<String>,
    pub started_at: Option<f64>,
    pub ended_at: Option<f64>,
    pub net_error: Option<i32>,
    pub attempts: Vec<NetlogAttempt>,
    pub redirects: Vec<NetlogRedirect>,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogAttempt {
    pub url: String,
    pub method: String,
    pub started_at: Option<f64>,
    pub ended_at: Option<f64>,
    pub protocol: Protocol,
    pub status: Option<u16>,
    pub outcome: AttemptOutcome,
    pub send_transaction: Option<NetlogHeaderEvent>,
    pub send_session: Option<NetlogHeaderEvent>,
    pub recv_transaction: Option<NetlogHeaderEvent>,
    pub recv_session: Option<NetlogHeaderEvent>,
    pub redirect_to: Option<String>,
    pub net_error: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogHeaderEvent {
    pub event_name: String,
    pub event_index: usize,
    pub time: Option<f64>,
    pub source_id: Option<u32>,
    pub stream_id: Option<u32>,
    pub dependency_id: Option<u32>,
    pub protocol: Protocol,
    pub role: HeaderRole,
    pub view: HeaderView,
    pub nul_expanded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetlogRedirect {
    pub location: String,
    pub time: Option<f64>,
    pub from_url: String,
}

#[derive(Debug)]
enum Atom {
    Send(NetlogHeaderEvent),
    Recv(NetlogHeaderEvent),
    Redirect {
        location: String,
        time: Option<f64>,
        index: usize,
    },
    End {
        time: Option<f64>,
        net_error: Option<i32>,
        index: usize,
    },
}

#[derive(Debug)]
struct Builder {
    source_id: u32,
    url: String,
    method: String,
    request_type: Option<String>,
    started_at: Option<f64>,
    atoms: Vec<Atom>,
    net_error: Option<i32>,
    ended_at: Option<f64>,
}

impl Builder {
    fn new(source_id: u32) -> Self {
        Self {
            source_id,
            url: String::new(),
            method: "GET".to_string(),
            request_type: None,
            started_at: None,
            atoms: Vec::new(),
            net_error: None,
            ended_at: None,
        }
    }
}

pub fn parse_netlog(json: &[u8]) -> Result<NetlogCapture> {
    let root: Value =
        serde_json::from_slice(json).map_err(|error| CoreError::json("NetLog", error))?;
    let (constants, events) = match &root {
        Value::Object(object) => {
            let events = object
                .get("events")
                .and_then(Value::as_array)
                .ok_or_else(|| CoreError::MissingField {
                    field: "events".to_string(),
                })?;
            (
                object.get("constants").and_then(Value::as_object),
                events.as_slice(),
            )
        }
        Value::Array(events) => {
            // NetLog sem envelope: tolerado, mas explicitamente incompleto.
            (None, events.as_slice())
        }
        _ => {
            return Err(CoreError::UnsupportedFormat {
                message: "NetLog deve ser um objeto com {constants,events}".to_string(),
            })
        }
    };

    let mut capture = NetlogCapture {
        events_total: events.len(),
        ..Default::default()
    };
    if constants.is_none() {
        capture.warnings.push(Warning::new(
            "netlog.constants_missing",
            "NetLog sem objeto constants; tipos de evento não podem ser decodificados por nome",
        ));
    }

    let mut event_names: BTreeMap<u32, String> = BTreeMap::new();
    if let Some(constants) = constants {
        if let Some(types) = constants.get("logEventTypes").and_then(Value::as_object) {
            for (name, id) in types {
                if let Some(id) = id.as_u64() {
                    event_names.insert(id as u32, name.clone());
                }
            }
        }
        capture.browser = browser_from_constants(constants);
        if let Some(offset) = constants.get("timeTickOffset").and_then(as_f64) {
            capture.started_at =
                first_time(events).map(|time_ms| epoch_ms_to_iso(offset as i64 + time_ms as i64));
        }
    }
    if capture.started_at.is_none() {
        capture.started_at = Some("1970-01-01T00:00:00Z".to_string());
        capture.warnings.push(Warning::new(
            "netlog.no_wall_clock",
            "NetLog sem timeTickOffset; startedAt usa época Unix como marcador explícito",
        ));
    }

    // Cadeias explícitas:
    // - HTTP_STREAM_JOB_BOUND_TO_REQUEST: stream job -> URL_REQUEST (h2);
    // - HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS: quic_stream_id -> URL_REQUEST
    //   (h3; o evento de sessão só tem session id + quic_stream_id).
    let mut bound_to_request: BTreeMap<u32, u32> = BTreeMap::new();
    let mut quic_stream_requests: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut unknown_counts: BTreeMap<u32, usize> = BTreeMap::new();

    for (index, event) in events.iter().enumerate() {
        let object = match event.as_object() {
            Some(object) => object,
            None => {
                capture.events_unknown += 1;
                capture.warnings.push(Warning::new(
                    "netlog.event_not_object",
                    format!("evento {index} não é objeto; ignorado"),
                ));
                continue;
            }
        };
        let event_type = object.get("type").and_then(Value::as_u64);
        let name = event_type
            .and_then(|id| event_names.get(&(id as u32)).cloned())
            .unwrap_or_else(|| {
                let id = event_type.unwrap_or(0);
                *unknown_counts.entry(id as u32).or_default() += 1;
                format!("unknown:{id}")
            });
        if name == "HTTP_STREAM_JOB_BOUND_TO_REQUEST" {
            let source = object.get("source").and_then(Value::as_object);
            let dep = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("source_dependency"))
                .and_then(Value::as_object);
            if let (Some(source_id), Some(dep_id)) = (
                source
                    .and_then(|source| source.get("id"))
                    .and_then(Value::as_u64),
                dep.and_then(|dep| dep.get("id")).and_then(Value::as_u64),
            ) {
                bound_to_request.insert(source_id as u32, dep_id as u32);
            }
        } else if name == "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS" {
            if let (Some(request_id), Some(stream_id)) = (
                source_id(object),
                object
                    .get("params")
                    .and_then(Value::as_object)
                    .and_then(stream_id_of),
            ) {
                quic_stream_requests
                    .entry(stream_id)
                    .or_default()
                    .insert(request_id);
            }
        }
    }

    capture.events_unknown = unknown_counts.values().sum();
    for (id, count) in unknown_counts {
        if capture.unknown_event_samples.len() < MAX_UNKNOWN_SAMPLES {
            capture
                .unknown_event_samples
                .push(format!("type {id} × {count}"));
        }
    }
    if capture.events_unknown > 0 {
        capture.warnings.push(
            Warning::new(
                "netlog.unknown_event_type",
                format!(
                    "{} evento(s) de tipo desconhecido; preservados no arquivo bruto e contados",
                    capture.events_unknown
                ),
            )
            .with_detail(serde_json::json!({
                "samples": capture.unknown_event_samples,
            })),
        );
    }

    let mut builders: BTreeMap<u32, Builder> = BTreeMap::new();
    let mut pending_session: Vec<(NetlogHeaderEvent, Option<u32>)> = Vec::new();

    for (index, event) in events.iter().enumerate() {
        let Some(object) = event.as_object() else {
            continue;
        };
        let name = event_type_name(object, &event_names);
        let source_id = source_id(object);
        // NetLog grava `time` em milissegundos; o modelo usa segundos.
        let time = object.get("time").and_then(as_f64).map(|ms| ms / 1000.0);
        let phase = object.get("phase").and_then(Value::as_i64).unwrap_or(0);
        let params = object.get("params").and_then(Value::as_object);

        match name.as_str() {
            "URL_REQUEST_START_JOB" => {
                let Some(source_id) = source_id else { continue };
                if phase == 1 {
                    let builder = builders
                        .entry(source_id)
                        .or_insert_with(|| Builder::new(source_id));
                    if let Some(params) = params {
                        if let Some(url) = params.get("url").and_then(Value::as_str) {
                            if builder.url.is_empty() {
                                builder.url = url.to_string();
                            }
                            if builder.started_at.is_none() {
                                builder.started_at = time;
                            }
                        }
                        if let Some(method) = params.get("method").and_then(Value::as_str) {
                            builder.method = method.to_string();
                        }
                        if let Some(request_type) =
                            params.get("request_type").and_then(Value::as_str)
                        {
                            builder.request_type = Some(request_type.to_string());
                        }
                    }
                    capture.events_used += 1;
                } else if phase == 2 {
                    let builder = builders
                        .entry(source_id)
                        .or_insert_with(|| Builder::new(source_id));
                    let net_error = params
                        .and_then(|params| params.get("net_error"))
                        .and_then(Value::as_i64)
                        .map(|value| value as i32)
                        .filter(|value| *value != 0);
                    if let Some(net_error) = net_error {
                        builder.net_error = Some(net_error);
                    }
                    builder.ended_at = time;
                    builder.atoms.push(Atom::End {
                        time,
                        net_error,
                        index,
                    });
                    capture.events_used += 1;
                }
            }
            "URL_REQUEST_REDIRECTED" => {
                let Some(source_id) = source_id else { continue };
                let builder = builders
                    .entry(source_id)
                    .or_insert_with(|| Builder::new(source_id));
                if let Some(location) = params
                    .and_then(|params| params.get("location"))
                    .and_then(Value::as_str)
                {
                    builder.atoms.push(Atom::Redirect {
                        location: location.to_string(),
                        time,
                        index,
                    });
                    capture.events_used += 1;
                }
            }
            _ => {
                if is_header_event(&name) {
                    let Some(source_id) = source_id else { continue };
                    let role = if is_request_headers(&name) {
                        HeaderRole::Request
                    } else {
                        HeaderRole::Response
                    };
                    let protocol = protocol_for_event(&name);
                    let (view, nul_expanded, issues) = match parse_headers(
                        params,
                        &name,
                        index,
                        role,
                        protocol,
                        capture.browser.version.as_deref(),
                        time,
                    ) {
                        Ok(parsed) => parsed,
                        Err(warning) => {
                            capture.warnings.push(warning);
                            continue;
                        }
                    };
                    if !issues.is_empty() {
                        capture.warnings.push(
                            Warning::new(
                                "netlog.header_line_invalid",
                                format!(
                                    "{} (evento {index}): {} linha(s) de header sem separador ':'",
                                    name,
                                    issues.len()
                                ),
                            )
                            .with_detail(serde_json::json!({ "lines": issues })),
                        );
                    }
                    let header_event = NetlogHeaderEvent {
                        event_name: name.clone(),
                        event_index: index,
                        time,
                        source_id: Some(source_id),
                        stream_id: params.and_then(stream_id_of),
                        dependency_id: source_dependency_id(object),
                        protocol,
                        role,
                        view,
                        nul_expanded,
                    };
                    capture.events_used += 1;

                    if is_transaction_event(&name) {
                        let builder = builders
                            .entry(source_id)
                            .or_insert_with(|| Builder::new(source_id));
                        match role {
                            HeaderRole::Request => builder.atoms.push(Atom::Send(header_event)),
                            HeaderRole::Response => builder.atoms.push(Atom::Recv(header_event)),
                        }
                    } else {
                        pending_session.push((header_event, None));
                    }
                }
            }
        }
    }

    // Liga eventos de sessão ao URL_REQUEST pela cadeia explícita
    // HTTP_STREAM_JOB_BOUND_TO_REQUEST.
    let mut session_resolution: BTreeMap<(u32, u32), u32> = BTreeMap::new();
    for (event, resolution) in &mut pending_session {
        if event.role == HeaderRole::Request {
            let linked = event
                .dependency_id
                .and_then(|id| bound_to_request.get(&id).copied())
                .or_else(|| {
                    event.stream_id.and_then(|stream_id| {
                        quic_stream_requests.get(&stream_id).and_then(|requests| {
                            if requests.len() == 1 {
                                requests.iter().next().copied()
                            } else {
                                None
                            }
                        })
                    })
                })
                .or_else(|| event.dependency_id.filter(|id| builders.contains_key(id)));
            if let Some(request_id) = linked {
                *resolution = Some(request_id);
                if let Some(stream_id) = event.stream_id {
                    session_resolution
                        .insert((event.source_id.unwrap_or(0), stream_id), request_id);
                }
                let builder = builders
                    .entry(request_id)
                    .or_insert_with(|| Builder::new(request_id));
                builder.atoms.push(Atom::Send(event.clone()));
            } else {
                capture.unlinked_session_events += 1;
            }
        }
    }
    for (event, resolution) in &mut pending_session {
        if event.role == HeaderRole::Response {
            let linked = event.stream_id.and_then(|stream_id| {
                session_resolution
                    .get(&(event.source_id.unwrap_or(0), stream_id))
                    .copied()
            });
            if let Some(request_id) = linked {
                *resolution = Some(request_id);
                let builder = builders
                    .entry(request_id)
                    .or_insert_with(|| Builder::new(request_id));
                builder.atoms.push(Atom::Recv(event.clone()));
            } else {
                capture.unlinked_session_events += 1;
            }
        }
    }
    if capture.unlinked_session_events > 0 {
        capture.warnings.push(Warning::new(
            "netlog.session_headers_unlinked",
            format!(
                "{} evento(s) de headers de sessão h2/h3 sem cadeia explícita até um URL_REQUEST; não associados",
                capture.unlinked_session_events
            ),
        ));
    }

    for (_, mut builder) in builders {
        builder.atoms.sort_by(|left, right| {
            atom_time(left)
                .partial_cmp(&atom_time(right))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| atom_index(left).cmp(&atom_index(right)))
        });
        let request = build_request(builder);
        if request.url.is_empty() {
            capture.events_unknown += 1;
            capture.warnings.push(Warning::new(
                "netlog.request_without_url",
                format!(
                    "URL_REQUEST {} sem URL em URL_REQUEST_START_JOB; não importado",
                    request.source_id
                ),
            ));
            continue;
        }
        capture.requests.push(request);
    }

    if capture.requests.is_empty() {
        capture.warnings.push(Warning::error(
            "netlog.no_requests",
            "NetLog não produziu nenhuma requisição utilizável",
        ));
    }
    Ok(capture)
}

fn stream_id_of(params: &Map<String, Value>) -> Option<u32> {
    params
        .get("stream_id")
        .or_else(|| params.get("quic_stream_id"))
        .and_then(Value::as_u64)
        .map(|value| value as u32)
}

fn event_type_name(object: &Map<String, Value>, names: &BTreeMap<u32, String>) -> String {
    object
        .get("type")
        .and_then(Value::as_u64)
        .and_then(|id| names.get(&(id as u32)).cloned())
        .unwrap_or_else(|| "unknown:0".to_string())
}

fn is_header_event(name: &str) -> bool {
    is_request_headers(name)
        || matches!(
            name,
            "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"
                | "HTTP2_SESSION_RECV_HEADERS"
                | "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS"
        )
}

fn is_request_headers(name: &str) -> bool {
    matches!(
        name,
        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS"
            | "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"
            | "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"
            | "HTTP2_SESSION_SEND_HEADERS"
            | "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
    )
}

fn is_transaction_event(name: &str) -> bool {
    name.starts_with("HTTP_TRANSACTION_")
}

fn protocol_for_event(name: &str) -> Protocol {
    match name {
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"
        | "HTTP2_SESSION_SEND_HEADERS"
        | "HTTP2_SESSION_RECV_HEADERS" => Protocol::H2,
        "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"
        | "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
        | "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS" => Protocol::H3,
        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS" | "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" => {
            Protocol::H1
        }
        _ => Protocol::Unknown,
    }
}

fn parse_headers(
    params: Option<&Map<String, Value>>,
    event_name: &str,
    index: usize,
    role: HeaderRole,
    protocol: Protocol,
    browser_version: Option<&str>,
    timestamp: Option<f64>,
) -> std::result::Result<(HeaderView, bool, Vec<String>), Warning> {
    let params = params.ok_or_else(|| {
        Warning::new(
            "netlog.header_event_without_params",
            format!("{event_name} (evento {index}) sem params; ignorado"),
        )
    })?;
    let Some(headers) = params.get("headers") else {
        return Err(Warning::new(
            "netlog.header_event_without_headers",
            format!("{event_name} (evento {index}) sem params.headers; ignorado"),
        ));
    };

    let mut lines: Vec<String> = Vec::new();
    if let Some(array) = headers.as_array() {
        for value in array {
            if let Some(line) = value.as_str() {
                lines.push(line.to_string());
            } else if let Some(object) = value.as_object() {
                if let (Some(name), Some(value)) = (
                    object.get("name").and_then(Value::as_str),
                    object.get("value").and_then(Value::as_str),
                ) {
                    lines.push(format!("{name}: {value}"));
                }
            }
        }
    } else if let Some(text) = headers.as_str() {
        lines.extend(text.lines().map(str::to_string));
    } else {
        return Err(Warning::new(
            "netlog.headers_not_array",
            format!("{event_name} (evento {index}) tem params.headers em formato inesperado"),
        ));
    }

    let (expanded, nul_expanded) = expand_nul_duplicates(&lines);
    let direction = match role {
        HeaderRole::Request => policy::Direction::Request,
        HeaderRole::Response => policy::Direction::Response,
    };
    let wire_protocol = match protocol {
        Protocol::H1 => policy::WireProtocol::H1,
        Protocol::H2 => policy::WireProtocol::H2,
        Protocol::H3 => policy::WireProtocol::H3,
        Protocol::Unknown => policy::WireProtocol::Unknown,
    };
    let provenance = policy::provenance_for(
        Source::NetLog,
        Some(event_name),
        direction,
        wire_protocol,
        if is_transaction_event(event_name) {
            "netlog.headers"
        } else {
            "netlog.session.headers"
        },
        browser_version,
    )
    .with_source_id(index.to_string());
    let provenance = match timestamp {
        Some(timestamp) => provenance.with_timestamp(timestamp),
        None => provenance,
    };

    let (mut view, _issues, unparsed) =
        HeaderView::from_header_lines(&expanded, &provenance, OrderState::SourceOrder);
    view.raw_block = Some(lines.join("\n"));
    if nul_expanded {
        view.notes.push(
            "repetições fundidas por \\x00 no evento de sessão foram expandidas em pares distintos"
                .to_string(),
        );
        for entry in view
            .pseudo_headers
            .iter_mut()
            .chain(view.headers.iter_mut())
        {
            entry.provenance.notes.push("expandido de NUL".to_string());
        }
    }
    if !unparsed.is_empty() {
        view.notes.push(format!(
            "{} linha(s) sem ':' preservadas em raw_block e reportadas",
            unparsed.len()
        ));
    }
    Ok((view, nul_expanded, unparsed))
}

/// Expande `"x-resp-order: 1\x002"` em `"x-resp-order: 1"` e
/// `"x-resp-order: 2"` na mesma posição. Pseudoheaders (`:status: 1\x002`)
/// também são suportados.
pub fn expand_nul_duplicates(lines: &[String]) -> (Vec<String>, bool) {
    let mut expanded = Vec::new();
    let mut changed = false;
    for line in lines {
        if !line.contains('\0') {
            expanded.push(line.clone());
            continue;
        }
        match line.find(": ") {
            Some(sep) => {
                let name = &line[..sep];
                let rest = &line[sep + 2..];
                for part in rest.split('\0') {
                    expanded.push(format!("{name}: {part}"));
                    changed = true;
                }
            }
            None => expanded.push(line.clone()),
        }
    }
    (expanded, changed)
}

fn build_request(builder: Builder) -> NetlogUrlRequest {
    let mut attempts: Vec<NetlogAttempt> = Vec::new();
    let mut current = NetlogAttempt {
        url: builder.url.clone(),
        method: builder.method.clone(),
        started_at: builder.started_at,
        ..Default::default()
    };
    let mut redirects: Vec<NetlogRedirect> = Vec::new();
    let mut current_has_data = false;

    for atom in builder.atoms {
        match atom {
            Atom::Send(event) => {
                if event.role != HeaderRole::Request {
                    continue;
                }
                current.protocol = if current.protocol == Protocol::Unknown {
                    event.protocol
                } else {
                    current.protocol
                };
                if is_transaction_event(&event.event_name) {
                    if current.send_transaction.is_some() || current.recv_transaction.is_some() {
                        flush_attempt(&mut current, &mut attempts);
                        current = NetlogAttempt {
                            url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                            method: builder.method.clone(),
                            started_at: event.time,
                            protocol: event.protocol,
                            ..Default::default()
                        };
                    }
                    current.send_transaction = Some(event);
                } else if current.send_session.is_none() {
                    current.send_session = Some(event);
                } else {
                    // Segundo evento de sessão para a mesma tentativa: fica
                    // como evidência adicional apenas se for o mesmo stream.
                }
                current_has_data = true;
            }
            Atom::Recv(event) => {
                if event.role != HeaderRole::Response {
                    continue;
                }
                if is_transaction_event(&event.event_name) {
                    if current.recv_transaction.is_some() {
                        flush_attempt(&mut current, &mut attempts);
                        current = NetlogAttempt {
                            url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                            method: builder.method.clone(),
                            started_at: event.time,
                            protocol: current.protocol,
                            ..Default::default()
                        };
                    }
                    current.recv_transaction = Some(event);
                } else if current.recv_session.is_none() {
                    // Evento de sessão é evidência paralela, não nova tentativa.
                    current.recv_session = Some(event);
                }
                current_has_data = true;
            }
            Atom::Redirect {
                location,
                time,
                index: _,
            } => {
                current.redirect_to = Some(location.clone());
                current.ended_at = time.or(current.ended_at);
                flush_attempt(&mut current, &mut attempts);
                redirects.push(NetlogRedirect {
                    location: location.clone(),
                    time,
                    from_url: attempts.last().map(|a| a.url.clone()).unwrap_or_default(),
                });
                current = NetlogAttempt {
                    url: location,
                    method: builder.method.clone(),
                    started_at: time,
                    ..Default::default()
                };
                current_has_data = false;
            }
            Atom::End {
                time,
                net_error,
                index: _,
            } => {
                current.ended_at = time.or(current.ended_at);
                if net_error.is_some() {
                    current.net_error = net_error;
                }
            }
        }
    }
    if current_has_data || attempts.is_empty() {
        flush_attempt(&mut current, &mut attempts);
    }

    // Liga redirects às tentativas seguintes.
    for index in 0..attempts.len().saturating_sub(1) {
        if attempts[index].redirect_to.is_some() {
            attempts[index].ended_at = attempts[index]
                .ended_at
                .or_else(|| attempts[index + 1].started_at);
        }
    }

    for attempt in &mut attempts {
        if attempt.outcome == AttemptOutcome::Unknown {
            attempt.outcome = if attempt.net_error.is_some() {
                AttemptOutcome::Failed
            } else if attempt.status.is_some() {
                AttemptOutcome::Completed
            } else {
                AttemptOutcome::Unknown
            };
        }
    }
    NetlogUrlRequest {
        source_id: builder.source_id,
        url: builder.url,
        method: builder.method,
        request_type: builder.request_type,
        started_at: builder.started_at,
        ended_at: builder.ended_at,
        net_error: builder.net_error,
        attempts,
        redirects,
    }
}

fn flush_attempt(current: &mut NetlogAttempt, attempts: &mut Vec<NetlogAttempt>) {
    if current.send_transaction.is_none()
        && current.send_session.is_none()
        && current.recv_transaction.is_none()
        && current.recv_session.is_none()
        && current.redirect_to.is_none()
    {
        return;
    }
    if current.ended_at.is_none() {
        current.ended_at = current
            .recv_session
            .as_ref()
            .and_then(|event| event.time)
            .or_else(|| {
                current
                    .recv_transaction
                    .as_ref()
                    .and_then(|event| event.time)
            });
    }
    if current.protocol == Protocol::Unknown {
        current.protocol = current
            .send_transaction
            .as_ref()
            .map(|event| event.protocol)
            .or_else(|| current.send_session.as_ref().map(|event| event.protocol))
            .or_else(|| current.recv_session.as_ref().map(|event| event.protocol))
            .unwrap_or(Protocol::Unknown);
    }
    current.status = status_of(current);
    current.outcome = if current.net_error.is_some() {
        AttemptOutcome::Failed
    } else if current.status.is_some() {
        AttemptOutcome::Completed
    } else {
        AttemptOutcome::Unknown
    };
    attempts.push(std::mem::take(current));
    current.method = attempts
        .last()
        .map(|attempt| attempt.method.clone())
        .unwrap_or_else(|| "GET".to_string());
}

fn status_of(attempt: &NetlogAttempt) -> Option<u16> {
    attempt
        .recv_session
        .as_ref()
        .and_then(|event| header_status(&event.view))
        .or_else(|| {
            attempt
                .recv_transaction
                .as_ref()
                .and_then(|event| header_status(&event.view))
        })
}

fn header_status(view: &HeaderView) -> Option<u16> {
    if let Some(status) = view.first_value(":status") {
        return status.trim().parse().ok();
    }
    let line = view.start_line.as_deref()?;
    let mut parts = line.split_whitespace();
    let _ = parts.next()?;
    parts.next()?.parse().ok()
}

fn atom_time(atom: &Atom) -> Option<f64> {
    match atom {
        Atom::Send(event) | Atom::Recv(event) => event.time,
        Atom::Redirect { time, .. } | Atom::End { time, .. } => *time,
    }
}

fn atom_index(atom: &Atom) -> usize {
    match atom {
        Atom::Send(event) | Atom::Recv(event) => event.event_index,
        Atom::Redirect { index, .. } | Atom::End { index, .. } => *index,
    }
}

fn source_id(object: &Map<String, Value>) -> Option<u32> {
    object
        .get("source")
        .and_then(Value::as_object)
        .and_then(|source| source.get("id"))
        .and_then(Value::as_u64)
        .map(|id| id as u32)
}

fn source_dependency_id(object: &Map<String, Value>) -> Option<u32> {
    object
        .get("source_dependency")
        .or_else(|| {
            object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("source_dependency"))
        })
        .and_then(Value::as_object)
        .and_then(|dependency| dependency.get("id"))
        .and_then(Value::as_u64)
        .map(|id| id as u32)
}

fn browser_from_constants(constants: &Map<String, Value>) -> BrowserInfo {
    let Some(client) = constants.get("clientInfo").and_then(Value::as_object) else {
        return BrowserInfo::default();
    };
    BrowserInfo {
        name: client
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Chrome")
            .to_string(),
        version: client
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        platform: client
            .get("os_type")
            .and_then(Value::as_str)
            .map(str::to_string),
        user_agent: None,
    }
}

fn as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|value| value as f64))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn first_time(events: &[Value]) -> Option<f64> {
    events
        .iter()
        .filter_map(|event| event.get("time").and_then(as_f64))
        .fold(None, |acc: Option<f64>, time| {
            Some(acc.map_or(time, |acc| acc.min(time)))
        })
}

/// Converte milissegundos Unix para RFC 3339 UTC sem dependência de data.
pub fn epoch_ms_to_iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600_000;
    let minute = (rem % 3_600_000) / 60_000;
    let second = (rem % 60_000) / 1000;
    let millis = rem % 1000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

/// Constrói uma sessão v1 apenas com o NetLog (sem CDP).
pub fn build_netlog_session(capture: &NetlogCapture) -> (SessionV1, ImportReport) {
    let mut report = ImportReport::new(InputFormat::NetLog);
    report.source_events = capture.events_total;
    report.source_events_used = capture.events_used;
    report.source_events_unknown = capture.events_unknown;

    let mut meta = SessionMeta::new(
        format!("netlog-{}", crate::parse::har::stable_id(b"netlog")),
        capture
            .started_at
            .clone()
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        capture.browser.clone(),
    );
    meta.capture = Some(crate::model::CaptureMeta {
        mode: Some("netlog-import".to_string()),
        headless: None,
        browser_binary: None,
        chrome_args: None,
        notes: Some("importado sem CDP; associação entre fontes não foi tentada".to_string()),
    });
    meta.labels.push("netlog-import".to_string());
    meta.completeness = Completeness::partial(
        "NetLog não declara captura CDP; cobertura de requisições não confirmada",
    );
    let mut session = SessionV1::new(meta);

    for warning in &capture.warnings {
        session.add_warning(warning.clone());
        report.warn(warning.clone());
    }

    let mut connections: BTreeMap<String, String> = BTreeMap::new();
    let mut request_number = 0usize;

    for request in &capture.requests {
        request_number += 1;
        let logical_id = format!("netlog-r{request_number:04}");
        let mut logical = LogicalRequest::new(&logical_id, &request.url, &request.method);
        logical.resource_type = request.request_type.clone();
        logical.cdp = None;
        logical.netlog.source_ids.push(request.source_id);
        logical.provenance = Provenance::new(
            Source::NetLog,
            "URL_REQUEST_START_JOB",
            Verification::Partial,
        )
        .with_source_id(request.source_id.to_string())
        .with_note("requisição lida apenas do NetLog");
        if let Some(version) = &capture.browser.version {
            logical.provenance = logical.provenance.clone().with_browser_version(version);
        }
        if let Some(started_at) = request.started_at {
            logical.provenance = logical.provenance.clone().with_timestamp(started_at);
        }

        if request.attempts.is_empty() {
            session.add_warning(Warning::new(
                "netlog.request_without_headers",
                format!("URL_REQUEST {} sem eventos de headers", request.source_id),
            ));
        }

        for (index, parsed) in request.attempts.iter().enumerate() {
            let attempt_id = format!("{logical_id}-a{}", index + 1);
            let mut attempt = Attempt::new(
                &attempt_id,
                &logical_id,
                index as u32,
                &parsed.url,
                &parsed.method,
            );
            attempt.protocol = parsed.protocol;
            attempt.status = parsed.status;
            attempt.outcome = parsed.outcome;
            attempt.started_at = parsed.started_at;
            attempt.ended_at = parsed.ended_at;
            attempt.net_error_to_failure(parsed.net_error);
            attempt.netlog.source_ids.push(request.source_id);

            let primary_request = parsed
                .send_transaction
                .as_ref()
                .or(parsed.send_session.as_ref());
            if let Some(evidence) = primary_request {
                attempt.request_headers = evidence.view.clone();
                attempt.cookie = CookieField::from_header_values(
                    &evidence.view.cookie_field_values(),
                    &evidence
                        .view
                        .first("cookie")
                        .map(|entry| entry.provenance.clone())
                        .unwrap_or_default(),
                );
                if let Some(session_headers) = parsed.send_session.as_ref() {
                    if parsed.send_transaction.is_some() {
                        attempt.cookie.wire_lines = session_headers.view.cookie_field_values();
                        attempt.cookie.notes.push(
                            "linhas do fio lidas do evento de sessão; NetLog pode mostrar Cookie fundido"
                                .to_string(),
                        );
                    }
                }
            }
            if let Some(evidence) = parsed
                .recv_transaction
                .as_ref()
                .or(parsed.recv_session.as_ref())
            {
                attempt.response_headers = evidence.view.clone();
                for header in evidence.view.get_all("set-cookie") {
                    attempt
                        .set_cookies
                        .push(crate::model::SetCookieRecord::from_raw(
                            &header.value,
                            &header.provenance,
                        ));
                }
            }
            attempt.request_body = Body::unavailable("NetLog não contém corpo de requisição");
            attempt.response_body = Body::unavailable("NetLog não contém corpo de resposta");

            // Evidências originais preservadas por fonte.
            for (role, evidence) in [
                (HeaderRole::Request, parsed.send_transaction.as_ref()),
                (HeaderRole::Request, parsed.send_session.as_ref()),
                (HeaderRole::Response, parsed.recv_transaction.as_ref()),
                (HeaderRole::Response, parsed.recv_session.as_ref()),
            ] {
                if let Some(evidence) = evidence {
                    let header_id = format!("{attempt_id}-h{}", attempt.header_evidence.len() + 1);
                    if let Some(stream_id) = evidence.stream_id {
                        attempt.netlog.stream_ids.push(stream_id);
                    }
                    let evidence_protocol = if evidence.protocol == Protocol::H1
                        && evidence.event_name == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"
                        && parsed.protocol != Protocol::Unknown
                    {
                        parsed.protocol
                    } else {
                        evidence.protocol
                    };
                    attempt.header_evidence.push(HeaderEvidence {
                        id: header_id,
                        role,
                        protocol: evidence_protocol,
                        event: evidence.event_name.clone(),
                        source_id: evidence.source_id,
                        stream_id: evidence.stream_id,
                        view: evidence.view.clone(),
                    });
                }
            }

            if let Some(status) = attempt.status {
                logical.status = Some(status);
            }
            attempt.provenance = Provenance::new(
                Source::NetLog,
                "netlog.attempt",
                attempt.request_headers.verification(),
            )
            .with_source_id(request.source_id.to_string())
            .with_timestamp(parsed.started_at.unwrap_or_default());
            if let Some(version) = &capture.browser.version {
                attempt.provenance = attempt.provenance.clone().with_browser_version(version);
            }

            let total = match (parsed.started_at, parsed.ended_at) {
                (Some(start), Some(end)) => Some(((end - start).max(0.0)) * 1000.0),
                _ => None,
            };
            attempt.timings = Timings {
                request_time: parsed.started_at,
                total_ms: total,
                estimated: total.is_some(),
                ..Default::default()
            };

            // Conexão: derivada da URL; o NetLog não entrega um id estável aqui.
            let connection_key = connection_key(&parsed.url, parsed.protocol);
            if let Some((host, port)) = host_port(&parsed.url) {
                let connection_id = connections
                    .entry(connection_key.clone())
                    .or_insert_with(|| {
                        let id = format!(
                            "netlog-conn-{}",
                            crate::parse::har::stable_id(connection_key.as_bytes())
                        );
                        session.connections.push(Connection {
                            id: id.clone(),
                            netlog_id: None,
                            protocol: parsed.protocol,
                            host: Some(host),
                            port: Some(port),
                            ip: None,
                            alpn: None,
                            tls_version: None,
                            reused: None,
                            provenance: Provenance::new(
                                Source::NetLog,
                                "derived:url",
                                Verification::Partial,
                            )
                            .with_note("conexão derivada da URL; não é o id do stream job"),
                        });
                        id
                    })
                    .clone();
                attempt.connection_id = Some(connection_id);
            }

            // StreamSession: só quando há evento de sessão h2/h3 com stream id.
            if let Some(session_event) = parsed
                .send_session
                .as_ref()
                .or(parsed.recv_session.as_ref())
            {
                if let Some(stream_id) = session_event.stream_id {
                    let stream_id_str = format!("{logical_id}-s{}", stream_id);
                    if !session
                        .stream_sessions
                        .iter()
                        .any(|stream| stream.id == stream_id_str)
                    {
                        session.stream_sessions.push(StreamSession {
                            id: stream_id_str.clone(),
                            connection_id: attempt.connection_id.clone(),
                            protocol: parsed.protocol,
                            stream_id: Some(stream_id),
                            attempt_id: Some(attempt_id.clone()),
                            netlog_session_id: session_event.source_id,
                            provenance: Provenance::new(
                                Source::NetLog,
                                "netlog.stream_headers",
                                Verification::Partial,
                            )
                            .with_source_id(
                                session_event.source_id.unwrap_or_default().to_string(),
                            ),
                        });
                    }
                    attempt.stream_session_id = Some(stream_id_str);
                }
            }

            logical.attempts.push(attempt);
        }

        // Redirects ligando tentativas consecutivas.
        for (index, redirect) in request.redirects.iter().enumerate() {
            let from_attempt = logical
                .attempts
                .get(index)
                .map(|attempt| attempt.id.clone())
                .unwrap_or_else(|| format!("{logical_id}-a{}", index + 1));
            let to_attempt = logical
                .attempts
                .get(index + 1)
                .map(|attempt| attempt.id.clone());
            if to_attempt.is_none() {
                session.add_warning(Warning::new(
                    "netlog.redirect_without_attempt",
                    format!("redirect para {} sem tentativa seguinte", redirect.location),
                ));
            }
            logical.redirects.push(Redirect {
                id: format!("{logical_id}-r{}", index + 1),
                logical_id: logical_id.clone(),
                from_attempt_id: from_attempt,
                to_attempt_id: to_attempt,
                status: logical
                    .attempts
                    .get(index)
                    .and_then(|attempt| attempt.status),
                location: Some(redirect.location.clone()),
                from_url: redirect.from_url.clone(),
                to_url: logical
                    .attempts
                    .get(index + 1)
                    .map(|attempt| attempt.url.clone())
                    .or_else(|| Some(redirect.location.clone())),
                provenance: Provenance::new(
                    Source::NetLog,
                    "URL_REQUEST_REDIRECTED",
                    Verification::Verified,
                ),
            });
        }

        logical.timings = logical
            .attempts
            .last()
            .map(|attempt| attempt.timings.clone())
            .unwrap_or_default();
        logical.refresh_primary_from_attempt();
        if logical.protocol == Protocol::H1 {
            for entry in logical
                .response_headers
                .headers
                .iter_mut()
                .chain(logical.response_headers.pseudo_headers.iter_mut())
            {
                entry
                    .provenance
                    .notes
                    .push("evento transacional em h1".to_string());
            }
        }
        session.requests.push(logical);
    }

    for warning in &capture.warnings {
        if !session
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code)
        {
            session.add_warning(warning.clone());
        }
    }
    session.recompute_completeness();
    for warning in &session.warnings {
        if !report
            .warnings
            .iter()
            .any(|existing| existing.code == warning.code)
        {
            report.warn(warning.clone());
        }
    }
    report.attachments_missing = 0;
    (session, report)
}

/// Importa NetLog isolado.
pub fn import_netlog(json: &[u8]) -> Result<ImportedSession> {
    let capture = parse_netlog(json)?;
    let (session, mut report) = build_netlog_session(&capture);
    report.bytes_read = json.len();
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: Some(json.to_vec()),
        attachments: Default::default(),
    };
    Ok(ImportedSession::new(bundle, report))
}

fn connection_key(url: &str, protocol: Protocol) -> String {
    match host_port(url) {
        Some((host, port)) => format!("{host}:{port}|{}", protocol.as_str()),
        None => format!("{url}|{}", protocol.as_str()),
    }
}

fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, remainder) = stripped.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        _ => Some((authority.to_string(), default_port)),
    }
}

trait AttemptFailureExt {
    fn net_error_to_failure(&mut self, net_error: Option<i32>);
}
impl AttemptFailureExt for Attempt {
    fn net_error_to_failure(&mut self, net_error: Option<i32>) {
        if let Some(error) = net_error {
            self.failure = Some(format!("net_error {error}"));
        }
    }
}
