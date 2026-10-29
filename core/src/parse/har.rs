use base64::Engine;
use serde_json::{Map, Value};

use crate::error::{CoreError, Result};
use crate::model::{
    Attempt, AttemptOutcome, Body, BrowserInfo, Connection, CookieField, HeaderView,
    LogicalRequest, Protocol, Provenance, Redirect, SessionBundle, SessionMeta, SessionV1, Source,
    Span, Timings, Verification, Warning,
};
use crate::parse::{ImportReport, ImportedSession, InputFormat};

const MAX_HAR_BODY_BYTES: usize = 64 * 1024 * 1024;

const ENTRY_KEYS: &[&str] = &[
    "pageref",
    "startedDateTime",
    "time",
    "request",
    "response",
    "cache",
    "timings",
    "serverIPAddress",
    "connection",
    "comment",
];

/// HAR 1.2: importa com proveniência `har` e verificação **unverified** para
/// sequência/duplicatas (a matriz não comprovou a ordem do exportador HAR).
pub fn import_har(json: &[u8]) -> Result<ImportedSession> {
    let root: Value =
        serde_json::from_slice(json).map_err(|error| CoreError::json("HAR", error))?;
    let log =
        root.get("log")
            .and_then(Value::as_object)
            .ok_or_else(|| CoreError::MissingField {
                field: "log".to_string(),
            })?;

    let mut report = ImportReport::new(InputFormat::Har);
    report.bytes_read = json.len();

    let version = log.get("version").and_then(Value::as_str).unwrap_or("?");
    if version != "1.2" {
        report.warn(Warning::new(
            "har.version",
            format!("HAR declara versão {version}; importado como 1.2 de forma tolerante"),
        ));
    }

    let entries = log
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::MissingField {
            field: "log.entries".to_string(),
        })?;
    report.source_events = entries.len();

    let browser = har_browser(log);
    let started_at = entries
        .first()
        .and_then(|entry| entry.get("startedDateTime"))
        .and_then(Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string();
    let mut meta = SessionMeta::new(
        format!("har-{}", short_fingerprint(json)),
        started_at,
        browser.clone(),
    );
    meta.labels.push("har-import".to_string());
    meta.capture = Some(crate::model::CaptureMeta {
        mode: Some("har-import".to_string()),
        notes: Some("ordem e duplicatas de headers em HAR são não verificadas".to_string()),
        ..Default::default()
    });

    let mut session = SessionV1::new(meta);
    let mut attachments = std::collections::BTreeMap::new();
    let mut parsed_entries: Vec<ParsedEntry> = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        report.source_events_used += 1;
        match parse_entry(
            entry,
            index,
            &browser,
            &mut report,
            &mut attachments,
            &mut session.connections,
        ) {
            Some(parsed) => parsed_entries.push(parsed),
            None => {
                report.source_events_unknown += 1;
                report.warn(Warning::error(
                    "har.entry_skipped",
                    format!("entrada {index} não é objeto HAR válido; ignorada"),
                ));
            }
        }
    }

    // Agrupa cadeias de redirect (response.redirectURL == URL da próxima
    // entrada) em uma LogicalRequest com tentativas separadas.
    let mut cursor = 0usize;
    let mut logical_number = 0usize;
    while cursor < parsed_entries.len() {
        logical_number += 1;
        let mut chain: Vec<ParsedEntry> = vec![parsed_entries[cursor].clone()];
        while let Some(redirect_url) = chain.last().and_then(|entry| entry.redirect_url.clone()) {
            let next = parsed_entries.get(cursor + chain.len());
            match next {
                Some(next) if next.url == redirect_url => chain.push(next.clone()),
                _ => break,
            }
        }
        cursor += chain.len();

        let logical_id = format!("har-{logical_number:04}");
        let first = &chain[0];
        let mut logical =
            LogicalRequest::new(logical_id.clone(), first.url.clone(), first.method.clone());
        logical.protocol = first.protocol;
        logical.status = chain.last().and_then(|entry| entry.status);
        logical.provenance = Provenance::new(Source::Har, "log.entries", Verification::Unverified)
            .with_note("HAR: sequência transmitida não comprovada")
            .with_browser_version(browser.version.clone().unwrap_or_default());

        for (attempt_index, parsed) in chain.iter().enumerate() {
            let attempt_id = format!("{logical_id}-a{}", attempt_index + 1);
            let mut attempt = Attempt::new(
                attempt_id.clone(),
                logical_id.clone(),
                attempt_index as u32,
                parsed.url.clone(),
                parsed.method.clone(),
            );
            attempt.protocol = parsed.protocol;
            attempt.status = parsed.status;
            attempt.outcome = if parsed.status.is_some() {
                AttemptOutcome::Completed
            } else {
                AttemptOutcome::Pending
            };
            attempt.started_at = parsed.started_at;
            attempt.request_headers = parsed.request_headers.clone();
            attempt.response_headers = parsed.response_headers.clone();
            attempt.cookie = parsed.cookie.clone();
            attempt.set_cookies = parsed.set_cookies.clone();
            attempt.request_body = parsed.request_body.clone();
            attempt.response_body = parsed.response_body.clone();
            attempt.connection_id = parsed.connection_id.clone();
            attempt.initiator = parsed.initiator.clone();
            attempt.provenance = parsed.provenance.clone();

            if let Some(redirect_url) = &parsed.redirect_url {
                logical.redirects.push(Redirect {
                    id: format!("{logical_id}-r{}", attempt_index + 1),
                    logical_id: logical_id.clone(),
                    from_attempt_id: attempt_id.clone(),
                    to_attempt_id: chain
                        .get(attempt_index + 1)
                        .map(|_| format!("{logical_id}-a{}", attempt_index + 2)),
                    status: parsed.status,
                    location: Some(redirect_url.clone()),
                    from_url: parsed.url.clone(),
                    to_url: Some(redirect_url.clone()),
                    provenance: Provenance::new(
                        Source::Har,
                        "response.redirectURL",
                        Verification::Unverified,
                    ),
                });
                attempt.outcome = AttemptOutcome::Completed;
            }
            logical.attempts.push(attempt);
        }

        let last = chain.last().expect("chain não vazia");
        logical.timings = last.timings.clone();
        logical.refresh_primary_from_attempt();
        logical.netlog = Default::default();
        session.requests.push(logical);
    }

    if logical_number == 0 {
        session
            .session
            .completeness
            .add_reason("HAR sem entradas utilizáveis");
    } else if report.has_errors() {
        session
            .session
            .completeness
            .add_reason("HAR com entradas incompletas ou inválidas");
    } else {
        session.session.completeness = crate::model::Completeness::complete();
    }

    report.source_events_used = report
        .source_events
        .saturating_sub(report.source_events_unknown);
    session.session.completeness.counts.source_events = report.source_events;
    session.session.completeness.counts.source_events_used = report.source_events_used;
    session.session.completeness.counts.source_events_unknown = report.source_events_unknown;

    if !session.requests.is_empty() && !har_has_cookies(entries) {
        report.warn(Warning::new(
            "har.cookies_absent",
            "o HAR não contém cookies (exportação do DevTools os remove); origem de cookies não avaliável — use captura ao vivo (CDP/NetLog)",
        ));
    }
    for warning in &report.warnings {
        session.warnings.push(warning.clone());
    }
    session.recompute_completeness();
    let bundle = SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: None,
        attachments,
    };
    Ok(ImportedSession::new(bundle, report))
}

#[derive(Debug, Clone)]
struct ParsedEntry {
    url: String,
    method: String,
    protocol: Protocol,
    status: Option<u16>,
    started_at: Option<f64>,
    request_headers: HeaderView,
    response_headers: HeaderView,
    cookie: CookieField,
    set_cookies: Vec<crate::model::SetCookieRecord>,
    request_body: Body,
    response_body: Body,
    timings: Timings,
    redirect_url: Option<String>,
    connection_id: Option<String>,
    initiator: Option<crate::model::Initiator>,
    provenance: Provenance,
}

fn parse_entry(
    entry: &Value,
    index: usize,
    browser: &BrowserInfo,
    report: &mut ImportReport,
    attachments: &mut std::collections::BTreeMap<String, Vec<u8>>,
    connections: &mut Vec<Connection>,
) -> Option<ParsedEntry> {
    let object = entry.as_object()?;

    for key in object.keys() {
        if !ENTRY_KEYS.contains(&key.as_str()) && !key.starts_with('_') && key != "comment" {
            report.warn(Warning::new(
                "har.unknown_entry_field",
                format!("campo desconhecido na entrada {index}: {key}"),
            ));
        }
    }

    let request = object.get("request").and_then(Value::as_object);
    let response = object.get("response").and_then(Value::as_object);
    if request.is_none() {
        report.warn(Warning::error(
            "har.missing_request",
            format!("entrada {index} sem objeto request"),
        ));
    }
    if response.is_none() {
        report.warn(Warning::error(
            "har.missing_response",
            format!("entrada {index} sem objeto response; status indisponível"),
        ));
    }

    let url = request
        .and_then(|request| request.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let method = request
        .and_then(|request| request.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_string();
    if url.is_empty() {
        report.warn(Warning::error(
            "har.missing_url",
            format!("entrada {index} sem request.url"),
        ));
    }

    let protocol = Protocol::parse_opt(
        request
            .and_then(|request| request.get("httpVersion"))
            .and_then(Value::as_str),
    );

    let wall_time = object
        .get("startedDateTime")
        .and_then(Value::as_str)
        .map(str::to_string);
    let request_provenance =
        Provenance::new(Source::Har, "request.headers", Verification::Unverified)
            .with_event(format!("log.entries[{index}].request.headers"))
            .with_source_id(index.to_string())
            .with_browser_version(browser.version.clone().unwrap_or_default())
            .with_note("HAR: ordem e duplicatas não verificadas");
    let request_provenance = match &wall_time {
        Some(wall_time) => request_provenance.with_wall_time(wall_time),
        None => request_provenance,
    };

    let response_provenance =
        Provenance::new(Source::Har, "response.headers", Verification::Unverified)
            .with_event(format!("log.entries[{index}].response.headers"))
            .with_source_id(index.to_string())
            .with_browser_version(browser.version.clone().unwrap_or_default())
            .with_note("HAR: ordem e duplicatas não verificadas");
    let response_provenance = match &wall_time {
        Some(wall_time) => response_provenance.with_wall_time(wall_time),
        None => response_provenance,
    };

    let mut request_headers = HeaderView::new(crate::model::OrderState::SourceOrder);
    if let Some(headers) = request.and_then(|request| request.get("headers")) {
        parse_har_headers(
            headers,
            &request_provenance,
            &mut request_headers,
            "request",
            report,
        );
    }
    let mut response_headers = HeaderView::new(crate::model::OrderState::SourceOrder);
    if let Some(headers) = response.and_then(|response| response.get("headers")) {
        parse_har_headers(
            headers,
            &response_provenance,
            &mut response_headers,
            "response",
            report,
        );
    }

    let mut cookie = CookieField::from_header_values(
        &request_headers.cookie_field_values(),
        &request_provenance,
    );
    if cookie.raw.is_empty() {
        if let Some(cookies) = request.and_then(|request| request.get("cookies")) {
            if let Some(cookies) = cookies.as_array() {
                if !cookies.is_empty() {
                    let fallback =
                        Provenance::new(Source::Har, "request.cookies", Verification::Unverified)
                            .with_note(
                                "Cookie reconstruído de request.cookies (sem campo bruto no HAR)",
                            );
                    for cookie_value in cookies {
                        if let (Some(name), Some(value)) = (
                            cookie_value.get("name").and_then(Value::as_str),
                            cookie_value.get("value").and_then(Value::as_str),
                        ) {
                            cookie.add_pairs_from_header(&format!("{name}={value}"), &fallback);
                        }
                    }
                    cookie.notes.push(
                        "pares vieram de request.cookies; nenhum campo Cookie bruto".to_string(),
                    );
                }
            }
        }
    }

    let mut set_cookies = Vec::new();
    for header in response_headers.get_all("set-cookie") {
        set_cookies.push(crate::model::SetCookieRecord::from_raw(
            &header.value,
            &header.provenance,
        ));
    }
    if set_cookies.is_empty() {
        if let Some(cookies) = response.and_then(|response| response.get("cookies")) {
            if cookies
                .as_array()
                .is_some_and(|cookies| !cookies.is_empty())
            {
                report.warn(Warning::new(
                    "har.set_cookie_without_header",
                    format!(
                        "entrada {index} tem response.cookies sem linha Set-Cookie bruta; cookies não sintetizados"
                    ),
                ));
            }
        }
    }

    let request_id = format!("har-entry-{index:04}");
    let request_body = parse_request_body(
        request,
        &request_id,
        &method,
        &request_provenance,
        attachments,
        report,
    );
    let response_body = parse_response_body(
        response,
        &request_id,
        &response_provenance,
        attachments,
        report,
    );

    let status = response
        .and_then(|response| response.get("status"))
        .and_then(Value::as_i64)
        .filter(|status| (100..=599).contains(status))
        .map(|status| status as u16);

    let timings = parse_timings(object);
    let redirect_url = response
        .and_then(|response| response.get("redirectURL"))
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(|location| resolve_reference(&url, location));

    let connection_id = object
        .get("serverIPAddress")
        .and_then(Value::as_str)
        .map(|ip| {
            let id = format!("har-conn-{}", short_fingerprint(ip.as_bytes()));
            if !connections.iter().any(|connection| connection.id == id) {
                connections.push(Connection {
                    id: id.clone(),
                    netlog_id: None,
                    protocol,
                    host: host_of(&url),
                    port: None,
                    ip: Some(ip.to_string()),
                    alpn: None,
                    tls_version: None,
                    reused: None,
                    provenance: Provenance::new(
                        Source::Har,
                        "serverIPAddress",
                        Verification::Unverified,
                    ),
                });
            }
            id
        });

    let outcome_note = if response.is_none() {
        Some("HAR sem response".to_string())
    } else {
        None
    };

    Some(ParsedEntry {
        url,
        method,
        protocol,
        status,
        started_at: None,
        request_headers,
        response_headers,
        cookie,
        set_cookies,
        request_body,
        response_body,
        timings,
        redirect_url,
        connection_id,
        initiator: object
            .get("_initiator")
            .and_then(Value::as_object)
            .and_then(|init| crate::model::Initiator::from_json(init)),
        provenance: {
            let provenance = Provenance::new(Source::Har, "log.entries", Verification::Unverified)
                .with_event(format!("log.entries[{index}]"))
                .with_source_id(index.to_string())
                .with_browser_version(browser.version.clone().unwrap_or_default())
                .with_note(outcome_note.unwrap_or_else(|| "HAR importado".to_string()));
            match object.get("startedDateTime").and_then(Value::as_str) {
                Some(wall_time) => provenance.with_wall_time(wall_time),
                None => provenance,
            }
        },
    })
}

fn parse_har_headers(
    value: &Value,
    provenance: &Provenance,
    view: &mut HeaderView,
    side: &str,
    report: &mut ImportReport,
) {
    let Some(headers) = value.as_array() else {
        report.warn(Warning::new(
            "har.headers_not_array",
            format!("{side}.headers não é array; headers ausentes"),
        ));
        return;
    };
    for (index, header) in headers.iter().enumerate() {
        let name = header.get("name").and_then(Value::as_str);
        let value = header.get("value").and_then(Value::as_str);
        match (name, value) {
            (Some(name), Some(value)) if !name.is_empty() => {
                view.add(name, value, provenance);
            }
            _ => report.warn(Warning::new(
                "har.invalid_header",
                format!("{side}.headers[{index}] sem name/value válidos; ignorado"),
            )),
        }
    }
}

/// Algum Cookie/Set-Cookie/`cookies[]` em qualquer entrada?
fn har_has_cookies(entries: &[Value]) -> bool {
    entries.iter().any(|entry| {
        ["request", "response"].iter().any(|side| {
            let Some(part) = entry.get(*side) else {
                return false;
            };
            let cookies = part
                .get("cookies")
                .and_then(Value::as_array)
                .is_some_and(|list| !list.is_empty());
            let headers = part
                .get("headers")
                .and_then(Value::as_array)
                .is_some_and(|list| {
                    list.iter().any(|header| {
                        header
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| {
                                name.eq_ignore_ascii_case("cookie")
                                    || name.eq_ignore_ascii_case("set-cookie")
                            })
                    })
                });
            cookies || headers
        })
    })
}

fn parse_request_body(
    request: Option<&Map<String, Value>>,
    id: &str,
    method: &str,
    provenance: &Provenance,
    attachments: &mut std::collections::BTreeMap<String, Vec<u8>>,
    report: &mut ImportReport,
) -> Body {
    let Some(post_data) = request.and_then(|request| request.get("postData")) else {
        // Método sem corpo e sem postData: não é um corpo ausente.
        if matches!(
            method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS"
        ) {
            let mut body = Body::empty(provenance);
            body.note = Some("não aplicável: método sem corpo".to_string());
            return body;
        }
        return Body::unavailable("HAR não fornece postData");
    };
    let mime = post_data
        .get("mimeType")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(text) = post_data.get("text").and_then(Value::as_str) {
        let name = format!("{id}.request.bin");
        let mut bytes = text.as_bytes().to_vec();
        let truncated = bytes.len() > MAX_HAR_BODY_BYTES;
        if truncated {
            bytes.truncate(MAX_HAR_BODY_BYTES);
            report.warn(Warning::new(
                "har.body_truncated",
                format!(
                    "entrada {id}: corpo de requisição excede {} bytes; capturado truncado",
                    MAX_HAR_BODY_BYTES
                ),
            ));
        }
        let len = bytes.len() as u64;
        let mut body = if truncated {
            Body::truncated(&name, len, MAX_HAR_BODY_BYTES as u64, provenance)
        } else {
            Body::captured(&name, len, provenance)
        };
        body.content_type = mime;
        attachments.insert(name, bytes);
        body
    } else {
        let has_params = post_data
            .get("params")
            .and_then(Value::as_array)
            .is_some_and(|params| !params.is_empty());
        if has_params {
            report.warn(Warning::new(
                "har.post_data_params_only",
                format!("entrada {id} tem postData.params sem texto; corpo não reconstruído"),
            ));
        }
        Body::unavailable("postData sem text")
    }
}

fn parse_response_body(
    response: Option<&Map<String, Value>>,
    id: &str,
    provenance: &Provenance,
    attachments: &mut std::collections::BTreeMap<String, Vec<u8>>,
    report: &mut ImportReport,
) -> Body {
    let Some(content) = response.and_then(|response| response.get("content")) else {
        return Body::unavailable("HAR sem response.content");
    };
    let mime = content
        .get("mimeType")
        .and_then(Value::as_str)
        .map(str::to_string);
    let text = content.get("text").and_then(Value::as_str);
    let encoding = content.get("encoding").and_then(Value::as_str);

    let Some(text) = text else {
        let size = content.get("size").and_then(Value::as_u64).unwrap_or(0);
        return if size == 0 {
            let mut body = Body::empty(provenance);
            body.content_type = mime;
            body
        } else {
            Body::unavailable("response.content sem text")
        };
    };

    if encoding == Some("base64") && text.len() > MAX_HAR_BODY_BYTES * 2 {
        report.warn(Warning::new(
            "har.body_too_large",
            format!("entrada {id}: conteúdo base64 excede o limite; não decodificado"),
        ));
        return Body::discarded("conteúdo maior que o limite de importação");
    }
    let mut truncated = false;
    let mut bytes = match encoding {
        Some("base64") => match base64::engine::general_purpose::STANDARD.decode(text) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.warn(Warning::new(
                    "har.base64_invalid",
                    format!("entrada {id}: response.content.text base64 inválido: {error}"),
                ));
                return Body::unavailable("conteúdo base64 inválido");
            }
        },
        Some(other) => {
            report.warn(Warning::new(
                "har.unknown_encoding",
                format!(
                    "entrada {id}: encoding de conteúdo desconhecido {other:?}; tratado como texto"
                ),
            ));
            text.as_bytes().to_vec()
        }
        None => text.as_bytes().to_vec(),
    };

    if bytes.len() > MAX_HAR_BODY_BYTES {
        bytes.truncate(MAX_HAR_BODY_BYTES);
        truncated = true;
        report.warn(Warning::new(
            "har.body_truncated",
            format!(
                "entrada {id}: corpo de resposta excede {} bytes; capturado truncado",
                MAX_HAR_BODY_BYTES
            ),
        ));
    }

    if bytes.is_empty() {
        let mut body = Body::empty(provenance);
        body.content_type = mime;
        return body;
    }

    let name = format!("{id}.response.bin");
    let mut body = if truncated {
        Body::truncated(
            &name,
            bytes.len() as u64,
            MAX_HAR_BODY_BYTES as u64,
            provenance,
        )
    } else {
        Body::captured(&name, bytes.len() as u64, provenance)
    };
    body.content_type = mime;
    attachments.insert(name, bytes);
    body
}

fn parse_timings(entry: &Map<String, Value>) -> Timings {
    let time_ms = entry
        .get("time")
        .and_then(Value::as_f64)
        .filter(|time| *time >= 0.0);
    let started = entry
        .get("startedDateTime")
        .and_then(Value::as_str)
        .map(str::to_string);
    let timings = entry.get("timings").and_then(Value::as_object);

    let mut cursor = 0.0f64;
    let span = |field: &str, cursor: &mut f64| -> Option<Span> {
        let value = timings
            .and_then(|timings| timings.get(field))
            .and_then(Value::as_f64)
            .filter(|value| *value >= 0.0)?;
        let start = *cursor;
        *cursor += value / 1000.0;
        Some(Span {
            start,
            end: *cursor,
        })
    };

    let blocked = span("blocked", &mut cursor);
    let dns = span("dns", &mut cursor);
    let connect = span("connect", &mut cursor);
    let ssl = span("ssl", &mut cursor);
    let send = span("send", &mut cursor);
    let wait = span("wait", &mut cursor);
    let receive = span("receive", &mut cursor);

    let _ = blocked; // `blocked` não tem campo próprio no contrato v1.
    Timings {
        request_time: None,
        wall_time: started,
        dns,
        connect,
        tls: ssl,
        send,
        wait,
        receive,
        total_ms: time_ms,
        estimated: false,
    }
}

fn har_browser(log: &Map<String, Value>) -> BrowserInfo {
    let browser = log.get("browser").and_then(Value::as_object);
    let creator = log.get("creator").and_then(Value::as_object);
    let name = browser
        .and_then(|browser| browser.get("name"))
        .and_then(Value::as_str)
        .or_else(|| {
            creator
                .and_then(|creator| creator.get("name"))
                .and_then(Value::as_str)
        })
        .unwrap_or("HAR")
        .to_string();
    BrowserInfo {
        name,
        version: browser
            .and_then(|browser| browser.get("version"))
            .and_then(Value::as_str)
            .or_else(|| {
                creator
                    .and_then(|creator| creator.get("version"))
                    .and_then(Value::as_str)
            })
            .map(str::to_string),
        ..BrowserInfo::default()
    }
}

/// Resolve `Location` relativo contra a URL da requisição (HAR pode trazer
/// apenas `/path`). Mantém a forma absoluta quando já é absoluta.
fn resolve_reference(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    if location.starts_with("//") {
        return match base.split_once("://") {
            Some((scheme, _)) => format!("{scheme}:{location}"),
            None => location.to_string(),
        };
    }
    if location.starts_with('/') {
        return match base.split_once("://") {
            Some((scheme, rest)) => {
                let authority = rest.split('/').next().unwrap_or(rest);
                format!("{scheme}://{authority}{location}")
            }
            None => location.to_string(),
        };
    }
    match base.rfind('/') {
        Some(index) if index > base.find("://").map_or(0, |scheme| scheme + 2) => {
            format!("{}{}", &base[..=index], location)
        }
        _ => location.to_string(),
    }
}

fn host_of(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| authority.rsplit('@').next())
        .map(|authority| {
            if let Some(stripped) = authority.strip_prefix('[') {
                stripped.split(']').next().unwrap_or(authority).to_string()
            } else {
                authority.split(':').next().unwrap_or(authority).to_string()
            }
        })
}

pub(crate) fn short_fingerprint(bytes: &[u8]) -> String {
    // FNV-1a 64: identificador estável e barato, sem dependência extra.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Identificador estável e curto para fixtures/ids internos (FNV-1a 64).
pub(crate) fn stable_id(bytes: &[u8]) -> String {
    short_fingerprint(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyState, MatchState};

    fn fixture() -> Vec<u8> {
        include_bytes!("../../tests/fixtures/har-minimal.json").to_vec()
    }

    #[test]
    fn imports_har_with_order_and_duplicates() {
        let imported = import_har(&fixture()).unwrap();
        let session = &imported.bundle.session;
        assert_eq!(session.schema_version, 1);
        assert_eq!(session.requests.len(), 1);
        let request = &session.requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.protocol, Protocol::H1);
        assert_eq!(request.status, Some(201));
        assert_eq!(
            request
                .request_headers
                .get_all("x-rep")
                .iter()
                .map(|entry| entry.value.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(
            request.request_headers.verification(),
            Verification::Unverified
        );
        assert_eq!(request.match_state, MatchState::Unmatched);
        assert_eq!(request.cookie.pairs.len(), 2);
        assert_eq!(request.set_cookies.len(), 1);
        assert_eq!(request.request_body.state, BodyState::Captured);
        assert_eq!(
            imported
                .bundle
                .attachment("har-entry-0000.request.bin")
                .unwrap(),
            b"hello=world"
        );
        assert!(imported
            .bundle
            .attachment("har-entry-0000.response.bin")
            .is_some());
    }

    #[test]
    fn reports_incomplete_entry_without_failing() {
        let json = br#"{"log":{"version":"1.2","entries":[
            {"startedDateTime":"2026-10-26T20:00:00Z","time":1,
             "request":{"method":"GET","url":"https://a.test/","headers":[]},
             "timings":{}}
        ]}}"#;
        let imported = import_har(json).unwrap();
        assert_eq!(imported.bundle.session.requests.len(), 1);
        assert_eq!(imported.bundle.session.requests[0].status, None);
        assert!(imported
            .report
            .warnings
            .iter()
            .any(|w| w.code == "har.missing_response"));
    }

    #[test]
    fn invalid_har_is_an_error_not_empty_session() {
        assert!(import_har(b"not json").is_err());
        assert!(import_har(br#"{"log":{}}"#).is_err());
    }

    #[test]
    fn redirect_chain_gets_attempts_and_redirect() {
        let json = br#"{"log":{"version":"1.2","entries":[
          {"startedDateTime":"2026-10-26T20:00:00Z","time":1,
           "request":{"method":"GET","url":"https://a.test/1","headers":[]},
           "response":{"status":302,"redirectURL":"https://a.test/2","headers":[]},"timings":{}},
          {"startedDateTime":"2026-10-26T20:00:00Z","time":1,
           "request":{"method":"GET","url":"https://a.test/2","headers":[]},
           "response":{"status":200,"headers":[]},"timings":{}}
        ]}}"#;
        let imported = import_har(json).unwrap();
        let s = &imported.bundle.session;
        assert_eq!(s.requests.len(), 1);
        assert_eq!(s.requests[0].attempts.len(), 2);
        assert_eq!(s.requests[0].redirects.len(), 1);
        assert_eq!(
            s.requests[0].redirects[0].location.as_deref(),
            Some("https://a.test/2")
        );
        assert_eq!(
            s.requests[0].redirects[0].to_attempt_id.as_deref(),
            Some("har-0001-a2")
        );
    }

    #[test]
    fn base64_response_is_decoded() {
        let json = br#"{"log":{"version":"1.2","entries":[
          {"startedDateTime":"2026-10-26T20:00:00Z","time":1,
           "request":{"method":"GET","url":"https://a.test/","headers":[]},
           "response":{"status":200,"headers":[],"content":{"mimeType":"application/octet-stream","text":"AAEC","encoding":"base64","size":3}},"timings":{}}
        ]}}"#;
        let imported = import_har(json).unwrap();
        assert_eq!(
            imported
                .bundle
                .attachment("har-entry-0000.response.bin")
                .unwrap(),
            &[0, 1, 2]
        );
    }
}
