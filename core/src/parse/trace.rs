//! Importador do trace de execução do script de priming (`scrapelens.trace/1`).
//!
//! O script grava este JSON (arquivo 0600; contém dados da sessão, não
//! compartilhar sem sanitizar). O core nunca executa o script nem faz rede.
//!
//! ```json
//! {
//!   "schema": "scrapelens.trace/1",            // obrigatório, exato
//!   "generator": "scrapelens-priming 1.0",     // opcional
//!   "startedAt": "2026-10-29T12:00:00Z",       // opcional, ISO-8601 UTC
//!   "parameters": [ {"name":"placa","part":"XML.p.v_placa"} ],  // opcional: entradas do
//!                                              // usuário do script, SEM valores; `part` =
//!                                              // nome interno (parte de adaptador) ou campo
//!                                              // do form/query; sem `part`, vale `name`
//!   "target": "har-0127",                      // requestId do alvo NA CAPTURA (o validate exige
//!                                              // que seja pareado; sem ele, "incompleta")
//!   "complete": true,                          // o script executou todo o plano (false/ausente
//!                                              // = "incompleta")
//!   "plan": {"hash":"<hex>", "parameters":[…]},// opcional: impressão do plano (ver
//!                                              // `validate::plan_hash`); `plan.parameters`
//!                                              // vale como `parameters`
//!   "steps": [                                 // obrigatório; ordem de execução
//!     {
//!       "method": "POST",                      // obrigatório
//!       "url": "https://host/p?q=1",           // obrigatório (http/https)
//!       "requestHeaders": [["Name","value"]],  // pares [nome, valor] ou {"name","value"};
//!                                              // duplicatas preservadas; sem garantia de
//!                                              // ordem do fio
//!       "requestBody": Body | null,
//!       "status": 200,                         // null/ausente se não houve resposta
//!       "responseHeaders": [["Name","value"]],
//!       "responseBody": Body | null,
//!       "startedAt": "2026-10-29T12:00:01Z",   // opcional
//!       "elapsedMs": 123.4,                    // opcional, >= 0
//!       "error": "timeout",                    // opcional: falha de transporte
//!       "checks": [ {"name":"app-ok","ok":true,"detail":"…"} ]  // verificações do passo
//!     }
//!   ]
//! }
//! // Body = { "text": "…", "encoding": "utf8" (padrão) | "base64",
//! //          "truncated": false, "size": 12345 }   // size = tamanho real, se truncado
//! ```
//!
//! A sessão importada leva o rótulo `script-trace`, fonte "execução do
//! script" (proveniência `har`, método `script-trace`), headers com ordem
//! `Unknown` (não é a do fio) e corpos como anexos. Corpo `truncated` vira
//! estado `truncated`; verificação com `ok:false` e `error` viram avisos.
//! Entrada malformada é erro claro (nunca pânico); o custo é linear no
//! tamanho do arquivo (no máximo [`MAX_STEPS`] passos).

use serde_json::{json, Map, Value};

use crate::error::{CoreError, Result};
use crate::model::{BodyState, OrderState, Warning, WarningSeverity};
use crate::parse::{ImportReport, ImportedSession};

pub const TRACE_SCHEMA: &str = "scrapelens.trace/1";
pub const TRACE_LABEL: &str = "script-trace";
type BodyParts = (Map<String, Value>, bool, Option<u64>);
/// (req truncado, tamanho real, resp truncado, tamanho real, checks ruins, erro)
type StepNotes = (
    bool,
    Option<u64>,
    bool,
    Option<u64>,
    Vec<String>,
    Option<String>,
);

/// Prefixo das notas de sessão que carregam os parâmetros do usuário do trace.
pub const PARAM_NOTE_PREFIX: &str = "trace-param: ";
pub const TARGET_NOTE_PREFIX: &str = "trace-target: ";
pub const COMPLETE_NOTE_PREFIX: &str = "trace-complete: ";
pub const PLAN_HASH_NOTE_PREFIX: &str = "trace-plan-hash: ";
/// Nomes em `plan.parameters` (os parâmetros do plano, usados no hash).
pub const PLAN_PARAM_NOTE_PREFIX: &str = "trace-plan-param: ";
/// Presente quando o trace traz o objeto `plan`.
pub const PLAN_PRESENT_NOTE: &str = "trace-plan: present";

pub const MAX_STEPS: usize = 20_000;
/// Headers por lista (enviados e recebidos), por passo.
pub const MAX_HEADERS_PER_STEP: usize = 512;
/// Tamanho máximo do arquivo de trace.
pub const MAX_TRACE_BYTES: usize = 256 * 1024 * 1024;

fn bad(message: impl Into<String>) -> CoreError {
    CoreError::UnsupportedFormat {
        message: format!("trace: {}", message.into()),
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`.
fn valid_iso(text: &str) -> bool {
    let b = text.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !(digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10))
        || !(b[10] == b'T'
            && digits(11..13)
            && b[13] == b':'
            && digits(14..16)
            && b[16] == b':'
            && digits(17..19))
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    let tz = &text[i..];
    tz == "Z"
        || (tz.len() == 6
            && matches!(tz.as_bytes()[0], b'+' | b'-')
            && tz.as_bytes()[3] == b':'
            && digits(i + 1..i + 3)
            && digits(i + 4..i + 6))
}

fn headers_of(step: &Value, key: &str, index: usize) -> Result<Vec<Value>> {
    let Some(value) = step.get(key).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| bad(format!("steps[{index}].{key} não é lista")))?;
    if array.len() > MAX_HEADERS_PER_STEP {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "trace: steps[{index}].{key} com {} headers (máximo {MAX_HEADERS_PER_STEP})",
                array.len()
            ),
        });
    }
    array
        .iter()
        .enumerate()
        .map(|(n, h)| {
            let pair = match h {
                Value::Array(p) if p.len() == 2 => (p[0].as_str(), p[1].as_str()),
                Value::Object(o) => (
                    o.get("name").and_then(Value::as_str),
                    o.get("value").and_then(Value::as_str),
                ),
                _ => (None, None),
            };
            match pair {
                (Some(name), Some(value)) if !name.is_empty() => {
                    Ok(json!({"name": name, "value": value}))
                }
                _ => Err(bad(format!(
                    "steps[{index}].{key}[{n}] deve ser [nome, valor] com textos"
                ))),
            }
        })
        .collect()
}

/// `(content/postData em forma HAR, truncado, tamanho real)`
fn body_of(step: &Value, key: &str, index: usize) -> Result<Option<BodyParts>> {
    let Some(body) = step.get(key).filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let object = body
        .as_object()
        .ok_or_else(|| bad(format!("steps[{index}].{key} não é objeto")))?;
    let text = object
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("steps[{index}].{key}.text ausente ou não é texto")))?;
    let encoding = object
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("utf8");
    if encoding != "utf8" && encoding != "base64" {
        return Err(bad(format!(
            "steps[{index}].{key}.encoding {encoding:?} desconhecido (utf8|base64)"
        )));
    }
    let truncated = object
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let size = object.get("size").and_then(Value::as_u64);
    let mut out = Map::new();
    out.insert("text".into(), json!(text));
    if encoding == "base64" {
        out.insert("encoding".into(), json!("base64"));
    }
    Ok(Some((out, truncated, size)))
}

pub fn import_trace(json_bytes: &[u8]) -> Result<ImportedSession> {
    if json_bytes.len() > MAX_TRACE_BYTES {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "trace com {} bytes (máximo {MAX_TRACE_BYTES})",
                json_bytes.len()
            ),
        });
    }
    let root: Value =
        serde_json::from_slice(json_bytes).map_err(|e| CoreError::json("trace", e))?;
    match root.get("schema").and_then(Value::as_str) {
        Some(TRACE_SCHEMA) => {}
        Some(other) => {
            return Err(bad(format!(
                "schema {other:?} não suportado (esperado {TRACE_SCHEMA})"
            )))
        }
        None => {
            return Err(CoreError::MissingField {
                field: "schema".into(),
            })
        }
    }
    let steps =
        root.get("steps")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::MissingField {
                field: "steps".into(),
            })?;
    if steps.len() > MAX_STEPS {
        return Err(CoreError::LimitExceeded {
            message: format!("trace com {} passos (máximo {MAX_STEPS})", steps.len()),
        });
    }
    let generator = root
        .get("generator")
        .and_then(Value::as_str)
        .unwrap_or("script");
    let epoch = "1970-01-01T00:00:00Z";
    let started = root.get("startedAt").and_then(Value::as_str);
    if started.is_some_and(|t| !valid_iso(t)) {
        return Err(bad(
            "startedAt inválido (use ISO-8601, ex.: 2026-10-29T12:00:00Z)",
        ));
    }

    let mut entries = Vec::with_capacity(steps.len());
    // (índice, request truncado, response truncado, tamanhos reais, verificações ruins, erro)
    let mut notes: Vec<StepNotes> = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        if !step.is_object() {
            return Err(bad(format!("steps[{index}] não é objeto")));
        }
        let text_of = |key: &str| {
            step.get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| bad(format!("steps[{index}].{key} ausente ou vazio")))
        };
        let method = text_of("method")?;
        let url = text_of("url")?;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(bad(format!("steps[{index}].url não é http(s)")));
        }
        if url.len() > 16 * 1024 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(bad(format!(
                "steps[{index}].url com espaço, caractere de controle ou longa demais"
            )));
        }
        let mut request = json!({
            "method": method, "url": url, "httpVersion": "HTTP/1.1",
            "headers": headers_of(step, "requestHeaders", index)?,
            "cookies": [], "queryString": [], "headersSize": -1, "bodySize": -1,
        });
        let mut req_trunc = (false, None);
        if let Some((mut body, truncated, size)) = body_of(step, "requestBody", index)? {
            let mime = request["headers"]
                .as_array()
                .and_then(|h| {
                    h.iter().find(|h| {
                        h["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case("content-type"))
                    })
                })
                .and_then(|h| h["value"].as_str())
                .unwrap_or("application/octet-stream")
                .to_string();
            if body.get("encoding").is_some() {
                // postData HAR não tem encoding: decodifica o base64 aqui
                use base64::Engine;
                let raw = body["text"].as_str().unwrap_or("");
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .map_err(|e| bad(format!("steps[{index}].requestBody base64 inválido: {e}")))?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                body.insert("text".into(), json!(text));
                body.remove("encoding");
            }
            body.insert("mimeType".into(), json!(mime));
            request["postData"] = Value::Object(body);
            req_trunc = (truncated, size);
        }
        let status = step.get("status").and_then(Value::as_u64);
        if let Some(s) = step.get("status").filter(|v| !v.is_null()) {
            if !s.as_u64().is_some_and(|n| (100..=599).contains(&n)) {
                return Err(bad(format!(
                    "steps[{index}].status deve ser 100–599 ou null"
                )));
            }
        }
        let mut content = json!({"size": 0, "mimeType": "x-unknown"});
        let mut resp_trunc = (false, None);
        if let Some((body, truncated, size)) = body_of(step, "responseBody", index)? {
            let mime = headers_of(step, "responseHeaders", index)?
                .iter()
                .find(|h| {
                    h["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case("content-type"))
                })
                .and_then(|h| h["value"].as_str().map(str::to_string))
                .unwrap_or_else(|| "application/octet-stream".into());
            content = Value::Object(body);
            content["mimeType"] = json!(mime);
            content["size"] = json!(size.unwrap_or(0));
            resp_trunc = (truncated, size);
        }
        let elapsed = step.get("elapsedMs").and_then(Value::as_f64);
        if elapsed.is_some_and(|e| e < 0.0 || !e.is_finite()) {
            return Err(bad(format!("steps[{index}].elapsedMs inválido")));
        }
        let own_start = step.get("startedAt").and_then(Value::as_str);
        if own_start.is_some_and(|t| !valid_iso(t)) {
            return Err(bad(format!("steps[{index}].startedAt inválido (ISO-8601)")));
        }
        let step_start = own_start.or(started).unwrap_or(epoch);
        let mut bad_checks = Vec::new();
        if let Some(checks) = step.get("checks").filter(|v| !v.is_null()) {
            let list = checks
                .as_array()
                .ok_or_else(|| bad(format!("steps[{index}].checks não é lista")))?;
            for c in list {
                let name = c.get("name").and_then(Value::as_str);
                let ok = c.get("ok").and_then(Value::as_bool);
                match (name, ok) {
                    (Some(name), Some(false)) => {
                        let detail = c.get("detail").and_then(Value::as_str).unwrap_or("");
                        bad_checks.push(format!("{name}: {detail}"));
                    }
                    (Some(_), Some(true)) => {}
                    _ => return Err(bad(format!("steps[{index}].checks: use {{name, ok}}"))),
                }
            }
        }
        let error = step
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string);
        entries.push(json!({
            "startedDateTime": step_start,
            "time": elapsed.unwrap_or(0.0),
            "request": request,
            "response": {
                "status": status.unwrap_or(0), "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": headers_of(step, "responseHeaders", index)?,
                "cookies": [], "content": content, "redirectURL": "",
                "headersSize": -1, "bodySize": -1,
            },
            "cache": {}, "timings": {"send": 0, "wait": elapsed.unwrap_or(0.0), "receive": 0},
        }));
        notes.push((
            req_trunc.0,
            req_trunc.1,
            resp_trunc.0,
            resp_trunc.1,
            bad_checks,
            error,
        ));
    }

    let har = json!({"log": {
        "version": "1.2",
        "creator": {"name": "script-trace", "version": generator},
        "entries": entries,
    }});
    let mut imported = crate::parse::har::import_har(
        &serde_json::to_vec(&har).map_err(|e| CoreError::json("trace", e))?,
    )?;
    let mut report = ImportReport::new(crate::parse::InputFormat::Har);
    report.bytes_read = json_bytes.len();

    let session = &mut imported.bundle.session;
    if !session.session.labels.iter().any(|l| l == TRACE_LABEL) {
        session.session.labels.push(TRACE_LABEL.to_string());
    }
    let plan = root.get("plan").filter(|v| !v.is_null());
    let mut lists: Vec<&Value> = Vec::new();
    if let Some(p) = root.get("parameters").filter(|v| !v.is_null()) {
        lists.push(p);
    }
    if let Some(p) = plan
        .and_then(|p| p.get("parameters"))
        .filter(|v| !v.is_null())
    {
        lists.push(p);
    }
    for params in lists {
        let list = params
            .as_array()
            .ok_or_else(|| bad("parameters não é lista"))?;
        for (n, p) in list.iter().enumerate() {
            let (name, part) = match p {
                Value::String(s) => (Some(s.as_str()), None),
                _ => (
                    p.get("name").and_then(Value::as_str),
                    p.get("part").and_then(Value::as_str),
                ),
            };
            let part = part
                .filter(|s| !s.is_empty())
                .or(name.filter(|s| !s.is_empty()));
            let Some(part) = part else {
                return Err(bad(format!("parameters[{n}] precisa de name ou part")));
            };
            let note = format!("{PARAM_NOTE_PREFIX}{part}");
            if !session.session.notes.contains(&note) {
                session.session.notes.push(note);
            }
        }
    }
    if let Some(plan) = plan.filter(|p| p.is_object()) {
        session.session.notes.push(PLAN_PRESENT_NOTE.to_string());
        if let Some(list) = plan.get("parameters").and_then(Value::as_array) {
            for p in list {
                let name = match p {
                    Value::String(s) => Some(s.as_str()),
                    _ => p
                        .get("name")
                        .and_then(Value::as_str)
                        .or_else(|| p.get("part").and_then(Value::as_str)),
                };
                if let Some(name) = name.filter(|s| !s.is_empty()) {
                    session
                        .session
                        .notes
                        .push(format!("{PLAN_PARAM_NOTE_PREFIX}{name}"));
                }
            }
        }
    }
    if let Some(target) = root.get("target").filter(|v| !v.is_null()) {
        let target = target
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| bad("target deve ser texto (requestId do alvo na captura)"))?;
        session
            .session
            .notes
            .push(format!("{TARGET_NOTE_PREFIX}{target}"));
    }
    if let Some(complete) = root.get("complete").filter(|v| !v.is_null()) {
        let complete = complete
            .as_bool()
            .ok_or_else(|| bad("complete deve ser booleano"))?;
        session
            .session
            .notes
            .push(format!("{COMPLETE_NOTE_PREFIX}{complete}"));
    }
    if let Some(hash) = plan.and_then(|p| p.get("hash")).filter(|v| !v.is_null()) {
        let hash = hash
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or_else(|| bad("plan.hash deve ser texto"))?;
        session
            .session
            .notes
            .push(format!("{PLAN_HASH_NOTE_PREFIX}{hash}"));
    }
    session.session.notes.push(
        "fonte: execução do script (scrapelens.trace/1); headers sem garantia de ordem do fio"
            .to_string(),
    );
    let mut warnings: Vec<Warning> = Vec::new();
    for (request, (req_trunc, req_size, resp_trunc, resp_size, bad_checks, error)) in
        session.requests.iter_mut().zip(notes)
    {
        let id = request.id.clone();
        for attempt in request.attempts.iter_mut() {
            attempt.request_headers.order_state = OrderState::Unknown;
            attempt.response_headers.order_state = OrderState::Unknown;
            attempt.provenance.method = TRACE_LABEL.to_string();
            attempt
                .provenance
                .notes
                .push("execução do script".to_string());
            for (body, truncated, size) in [
                (&mut attempt.request_body, req_trunc, req_size),
                (&mut attempt.response_body, resp_trunc, resp_size),
            ] {
                if truncated && body.state == BodyState::Captured {
                    body.truncated_at = body.bytes;
                    body.state = BodyState::Truncated;
                    if size.is_some() {
                        body.bytes = size;
                    }
                }
            }
        }
        if req_trunc || resp_trunc {
            warnings.push(
                Warning::new(
                    "trace.body_truncated",
                    format!("{id}: corpo truncado no trace"),
                )
                .with_entity(&id),
            );
        }
        for check in bad_checks {
            warnings.push(
                Warning::new("trace.check_failed", format!("{id}: {check}")).with_entity(&id),
            );
        }
        if let Some(error) = error {
            warnings
                .push(Warning::new("trace.step_error", format!("{id}: {error}")).with_entity(&id));
        }
    }
    for mut w in warnings {
        w.severity = WarningSeverity::Warning;
        report.warn(w.clone());
        session.warnings.push(w);
    }
    imported.report.merge(report);
    Ok(imported)
}
