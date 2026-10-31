//! As nove ferramentas, como funções puras sobre [`Ctx`]. O servidor rmcp
//! (`server.rs`) só traduz parâmetros e resultados; os testes chamam estas
//! funções diretamente.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use scrapelens_core::compare::{compare_sessions, CompareOptions, OriginMap, RequestRange};
use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::diff::{diff_requests, DiffOptions};
use scrapelens_core::flow::{value_origins, FlowOptions};
use scrapelens_core::model::{BodyState, LogicalRequest};
use scrapelens_core::search::{search_with, Scope, SearchQuery};
use scrapelens_core::store::{ensure_private_dir, write_session_dir};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::{is_within, slug, valid_name};
use crate::error::{ToolError, ToolResult};
use crate::project::{self, host_of, PLACEHOLDER};
use crate::registry::{Ctx, View, BODY_READ_LIMIT};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_INLINE: usize = 32 * 1024;
const MAX_INLINE: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// utilidades
// ---------------------------------------------------------------------------

fn page(
    cursor: &Option<String>,
    limit: Option<usize>,
    default: usize,
    max: usize,
    total: usize,
) -> Result<(usize, usize), ToolError> {
    let limit = limit.unwrap_or(default);
    if limit == 0 || limit > max {
        return Err(ToolError::invalid(format!(
            "limit deve estar entre 1 e {max}"
        )));
    }
    let start = match cursor {
        None => 0,
        Some(text) => text
            .strip_prefix('o')
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| ToolError::invalid(format!("cursor inválido: {text:?}")))?,
    };
    let start = start.min(total);
    Ok((start, (start + limit).min(total)))
}

fn next_cursor(end: usize, total: usize) -> Option<String> {
    (end < total).then(|| format!("o{end}"))
}

fn with_view<R>(
    ctx: &Ctx,
    handle: &str,
    reveal: Option<bool>,
    f: impl FnOnce(&View<'_>) -> Result<R, ToolError>,
) -> Result<R, ToolError> {
    let reveal = reveal.unwrap_or(false);
    ctx.check_reveal(reveal)?;
    let entry = ctx.open(handle)?;
    let view = if reveal {
        View::original(&entry)
    } else {
        View::masked(&entry)?
    };
    f(&view)
}

fn find_request<'a>(view: &'a View<'_>, id: &str) -> Result<&'a LogicalRequest, ToolError> {
    view.session.find_request(id).ok_or_else(|| {
        ToolError::not_found(format!(
            "requisição {id:?} não encontrada na sessão {:?} (use list_requests)",
            view.entry.handle
        ))
    })
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, ToolError> {
    serde_json::to_value(value).map_err(|error| ToolError::new("io", error.to_string()))
}

fn finish(mut object: Map<String, Value>, view: &View<'_>) -> ToolResult {
    object.insert("revealed".into(), json!(!view.masked));
    Ok(Value::Object(object))
}

// ---------------------------------------------------------------------------
// list_sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListSessionsParams {
    /// Cursor opaco devolvido por uma chamada anterior (`nextCursor`).
    pub cursor: Option<String>,
    /// Itens por página (padrão 50, máximo 200).
    pub limit: Option<usize>,
}

pub fn list_sessions(ctx: &Ctx, params: ListSessionsParams) -> ToolResult {
    let handles = ctx.handles();
    let mut rows: Vec<(String, String, Value)> = Vec::new();
    for (handle, (_dir, read_only)) in &handles {
        match ctx.open(handle) {
            Ok(entry) => {
                let session = &entry.lazy.session;
                let attempts: usize = session.requests.iter().map(|r| r.attempts.len()).sum();
                rows.push((
                    session.session.started_at.clone(),
                    handle.clone(),
                    json!({
                        "sessionId": handle,
                        "readOnly": read_only,
                        "startedAt": session.session.started_at,
                        "endedAt": session.session.ended_at,
                        "browser": {
                            "name": session.session.browser.name,
                            "version": session.session.browser.version,
                        },
                        "captureMode": session.session.capture.as_ref().and_then(|c| c.mode.clone()),
                        "requests": session.requests.len(),
                        "attempts": attempts,
                        "completeness": {
                            "state": session.session.completeness.state,
                            "reasons": session.session.completeness.reasons,
                        },
                        "warnings": session.warnings.len(),
                        "labels": session.session.labels,
                    }),
                ));
            }
            Err(error) => rows.push((
                String::new(),
                handle.clone(),
                json!({"sessionId": handle, "readOnly": read_only, "error": error.to_value()["error"]}),
            )),
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let total = rows.len();
    let (start, end) = page(
        &params.cursor,
        params.limit,
        DEFAULT_LIMIT,
        MAX_LIMIT,
        total,
    )?;
    let sessions: Vec<Value> = rows[start..end].iter().map(|r| r.2.clone()).collect();
    let mut out = json!({"total": total, "hasMore": end < total, "sessions": sessions});
    if let Some(cursor) = next_cursor(end, total) {
        out["nextCursor"] = json!(cursor);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// import_session
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImportSessionParams {
    /// Caminho de um HAR, NetLog, diretório de sessão nativa (com session.json)
    /// ou diretório de captura (cdp-events.jsonl + NetLog).
    pub path: String,
    /// `auto` (padrão), `har`, `netlog`, `session` ou `capture`.
    pub format: Option<String>,
    /// Nome do handle (letras, números, `.`, `_`, `-`). Padrão: derivado do arquivo.
    pub name: Option<String>,
}

fn read_limited(ctx: &Ctx, path: &Path) -> Result<Vec<u8>, ToolError> {
    let meta = std::fs::metadata(path)
        .map_err(|error| ToolError::new("io", format!("{}: {error}", path.display())))?;
    if !meta.is_file() {
        return Err(ToolError::invalid(format!(
            "{} não é um arquivo regular",
            path.display()
        )));
    }
    if meta.len() > ctx.cfg.max_import_bytes {
        return Err(ToolError::new(
            "too_large",
            format!(
                "{} tem {} bytes (limite {}; ajuste --max-import-bytes)",
                path.display(),
                meta.len(),
                ctx.cfg.max_import_bytes
            ),
        ));
    }
    std::fs::read(path)
        .map_err(|error| ToolError::new("io", format!("{}: {error}", path.display())))
}

fn sniff_file_format(bytes: &[u8]) -> Result<&'static str, ToolError> {
    // Só as chaves de topo importam; o parse completo é do importador.
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| ToolError::new("import_failed", format!("JSON inválido: {error}")))?;
    let object = value.as_object();
    if object.is_some_and(|o| o.contains_key("log")) {
        Ok("har")
    } else if object.is_some_and(|o| o.contains_key("constants") || o.contains_key("events")) {
        Ok("netlog")
    } else {
        Err(ToolError::new(
            "import_failed",
            "formato não reconhecido (esperado HAR, NetLog, sessão nativa ou diretório de captura)",
        ))
    }
}

fn find_netlog(dir: &Path) -> Option<PathBuf> {
    for name in ["netlog.json", "chrome-netlog.json"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains("netlog") && n.ends_with(".json"))
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

pub fn import_session(ctx: &Ctx, params: ImportSessionParams) -> ToolResult {
    let input = Path::new(&params.path)
        .canonicalize()
        .map_err(|error| ToolError::not_found(format!("{}: {error}", params.path)))?;
    let requested = params.format.as_deref().unwrap_or("auto");
    if !["auto", "har", "netlog", "session", "capture"].contains(&requested) {
        return Err(ToolError::invalid(format!(
            "format inválido: {requested:?} (auto|har|netlog|session|capture)"
        )));
    }
    if let Some(name) = &params.name {
        if !valid_name(name) {
            return Err(ToolError::new(
                "outside_allowed_dir",
                format!("name inválido: {name:?} (use letras, números, '.', '_' e '-'; sem '/' nem '..')"),
            ));
        }
    }
    let meta = std::fs::metadata(&input)
        .map_err(|error| ToolError::new("io", format!("{}: {error}", input.display())))?;
    let (format, imported) = if meta.is_dir() {
        let format = match requested {
            "auto" if input.join("session.json").is_file() => "session",
            "auto" if input.join("cdp-events.jsonl").is_file() => "capture",
            "auto" => {
                return Err(ToolError::new(
                    "import_failed",
                    "diretório sem session.json nem cdp-events.jsonl",
                ))
            }
            other => other,
        };
        match format {
            "session" => (
                "session",
                scrapelens_core::import_session_dir(&input).map_err(import_failed)?,
            ),
            "capture" => {
                let cdp_path = input.join("cdp-events.jsonl");
                let netlog_path = find_netlog(&input).ok_or_else(|| {
                    ToolError::new("import_failed", "diretório de captura sem arquivo NetLog")
                })?;
                let cdp = read_limited(ctx, &cdp_path)?;
                let netlog = read_limited(ctx, &netlog_path)?;
                let bodies = scrapelens_core::parse::cdp_bodies::sibling_candidates(&cdp_path)
                    .into_iter()
                    .find(|candidate| candidate.is_file())
                    .map(|path| read_limited(ctx, &path))
                    .transpose()?;
                (
                    "capture",
                    scrapelens_core::import_capture_labeled(
                        &cdp,
                        &netlog,
                        bodies.as_deref(),
                        &[],
                        CorrelationOptions::default(),
                    )
                    .map_err(import_failed)?,
                )
            }
            other => {
                return Err(ToolError::invalid(format!(
                    "{} é um diretório; format {other:?} não se aplica",
                    input.display()
                )))
            }
        }
    } else {
        let bytes = read_limited(ctx, &input)?;
        let format = match requested {
            "auto" => sniff_file_format(&bytes)?,
            "har" => "har",
            "netlog" => "netlog",
            other => {
                return Err(ToolError::invalid(format!(
                    "{} é um arquivo; format {other:?} exige diretório",
                    input.display()
                )))
            }
        };
        let imported = if format == "har" {
            scrapelens_core::import_har(&bytes)
        } else {
            scrapelens_core::import_netlog(&bytes)
        }
        .map_err(import_failed)?;
        (format, imported)
    };

    let meta_id = imported.bundle.session.session.id.clone();
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sessao")
        .to_string();
    let derived = {
        let id = slug(&meta_id);
        let tail: String = id
            .chars()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}-{}", slug(&stem), tail)
    };
    let handle = params.name.clone().unwrap_or(derived);
    if !valid_name(&handle) {
        return Err(ToolError::invalid(format!(
            "handle derivado inválido: {handle:?}"
        )));
    }
    let target = ctx.cfg.sessions_dir.join(&handle);
    let mut already = false;
    if target.exists() {
        let existing_id = std::fs::read(target.join("session.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v["session"]["id"].as_str().map(str::to_string));
        if existing_id.as_deref() == Some(meta_id.as_str()) {
            already = true;
        } else {
            return Err(ToolError::new(
                "exists",
                format!("já existe uma sessão {handle:?} com outro conteúdo; use outro name"),
            ));
        }
    } else {
        write_import(ctx, &imported.bundle, &target)?;
    }
    let session = &imported.bundle.session;
    let warnings: Vec<Value> = session
        .warnings
        .iter()
        .chain(imported.report.warnings.iter())
        .take(50)
        .map(|w| json!({"code": w.code, "message": w.message, "severity": w.severity}))
        .collect();
    Ok(json!({
        "sessionId": handle,
        "alreadyImported": already,
        "format": format,
        "requests": session.requests.len(),
        "warningsTotal": session.warnings.len() + imported.report.warnings.len(),
        "warnings": warnings,
        "report": {
            "sourceEvents": imported.report.source_events,
            "sourceEventsUsed": imported.report.source_events_used,
            "sourceEventsUnknown": imported.report.source_events_unknown,
            "attachmentsLoaded": imported.report.attachments_loaded,
            "attachmentsMissing": imported.report.attachments_missing,
        },
    }))
}

fn import_failed(error: scrapelens_core::CoreError) -> ToolError {
    ToolError::new("import_failed", error.to_string())
}

fn write_import(
    ctx: &Ctx,
    bundle: &scrapelens_core::SessionBundle,
    target: &Path,
) -> Result<(), ToolError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = ctx
        .cfg
        .sessions_dir
        .join(format!(".import-{}-{nanos}", std::process::id()));
    if !is_within(&ctx.cfg.sessions_dir, &temp) || !is_within(&ctx.cfg.sessions_dir, target) {
        return Err(ToolError::new(
            "outside_allowed_dir",
            "destino fora de --sessions-dir",
        ));
    }
    let result = write_session_dir(bundle, &temp)
        .map_err(|error| ToolError::new("io", error.to_string()))
        .and_then(|()| {
            std::fs::rename(&temp, target)
                .map_err(|error| ToolError::new("io", format!("{}: {error}", target.display())))
        });
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temp);
    }
    result
}

// ---------------------------------------------------------------------------
// list_requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StatusParam {
    Number(u16),
    Text(String),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRequestsParams {
    /// Id da sessão (de list_sessions).
    pub session_id: String,
    /// Host (host[:porta]) exato, sem diferenciar maiúsculas.
    pub host: Option<String>,
    /// Método HTTP, sem diferenciar maiúsculas.
    pub method: Option<String>,
    /// Status: 200, "200", "2xx"/"4xx"... ou "none" (sem resposta).
    pub status: Option<StatusParam>,
    /// Tipo de recurso (Document, XHR, Fetch, Script...), sem diferenciar maiúsculas.
    pub resource_type: Option<String>,
    /// Substring (sem diferenciar maiúsculas) na URL. Para corpos use search_bodies.
    pub text: Option<String>,
    pub cursor: Option<String>,
    /// Itens por página (padrão 50, máximo 200).
    pub limit: Option<usize>,
    /// true devolve valores reais (exige --allow-reveal no servidor).
    pub reveal: Option<bool>,
}

enum StatusFilter {
    Exact(u16),
    Class(u16),
    None,
}

fn parse_status(param: &StatusParam) -> Result<StatusFilter, ToolError> {
    match param {
        StatusParam::Number(n) => Ok(StatusFilter::Exact(*n)),
        StatusParam::Text(text) => {
            let text = text.trim().to_ascii_lowercase();
            if text == "none" {
                return Ok(StatusFilter::None);
            }
            if let Some(class) = text.strip_suffix("xx") {
                if let Ok(n) = class.parse::<u16>() {
                    if (1..=5).contains(&n) {
                        return Ok(StatusFilter::Class(n));
                    }
                }
            }
            text.parse::<u16>().map(StatusFilter::Exact).map_err(|_| {
                ToolError::invalid(format!(
                    "status inválido: {text:?} (ex.: 200, \"2xx\", \"none\")"
                ))
            })
        }
    }
}

pub fn list_requests(ctx: &Ctx, params: ListRequestsParams) -> ToolResult {
    let status = params.status.as_ref().map(parse_status).transpose()?;
    with_view(ctx, &params.session_id, params.reveal, |view| {
        let host = params.host.as_ref().map(|h| h.to_ascii_lowercase());
        let method = params.method.as_ref().map(|m| m.to_ascii_uppercase());
        let kind = params
            .resource_type
            .as_ref()
            .map(|k| k.to_ascii_lowercase());
        let text = params.text.as_ref().map(|t| t.to_ascii_lowercase());
        let matching: Vec<&LogicalRequest> = view
            .session
            .requests
            .iter()
            .filter(|r| host.as_ref().is_none_or(|h| &host_of(&r.url) == h))
            .filter(|r| {
                method
                    .as_ref()
                    .is_none_or(|m| &r.method.to_ascii_uppercase() == m)
            })
            .filter(|r| {
                kind.as_ref().is_none_or(|k| {
                    r.resource_type
                        .as_ref()
                        .is_some_and(|t| &t.to_ascii_lowercase() == k)
                })
            })
            .filter(|r| {
                text.as_ref()
                    .is_none_or(|t| r.url.to_ascii_lowercase().contains(t))
            })
            .filter(|r| match &status {
                None => true,
                Some(StatusFilter::Exact(n)) => r.status == Some(*n),
                Some(StatusFilter::Class(c)) => r.status.is_some_and(|s| s / 100 == *c),
                Some(StatusFilter::None) => r.status.is_none(),
            })
            .collect();
        let total = matching.len();
        let (start, end) = page(
            &params.cursor,
            params.limit,
            DEFAULT_LIMIT,
            MAX_LIMIT,
            total,
        )?;
        let items: Vec<Value> = matching[start..end]
            .iter()
            .map(|r| project::request_summary(r, view.original_request(&r.id).unwrap_or(r)))
            .collect();
        let mut out = Map::new();
        out.insert("sessionId".into(), json!(view.entry.handle));
        out.insert("total".into(), json!(total));
        out.insert("hasMore".into(), json!(end < total));
        if let Some(cursor) = next_cursor(end, total) {
            out.insert("nextCursor".into(), json!(cursor));
        }
        out.insert("items".into(), Value::Array(items));
        finish(out, view)
    })
}

// ---------------------------------------------------------------------------
// get_request
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRequestParams {
    pub session_id: String,
    pub request_id: String,
    /// Id (ou índice, 0-based) da tentativa. Padrão: visão primária.
    pub attempt: Option<String>,
    /// true inclui a proveniência por header (fonte, método, verificação, evento).
    pub verbose: Option<bool>,
    pub reveal: Option<bool>,
}

pub fn get_request(ctx: &Ctx, params: GetRequestParams) -> ToolResult {
    with_view(ctx, &params.session_id, params.reveal, |view| {
        let request = find_request(view, &params.request_id)?;
        let attempt = match &params.attempt {
            None => None,
            Some(selector) => Some(
                request
                    .attempts
                    .iter()
                    .find(|a| &a.id == selector)
                    .or_else(|| {
                        selector
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| request.attempts.get(i))
                    })
                    .ok_or_else(|| {
                        ToolError::not_found(format!(
                            "tentativa {selector:?} não encontrada em {}",
                            request.id
                        ))
                    })?,
            ),
        };
        let detail = project::request_detail(
            request,
            view.original_request(&request.id).unwrap_or(request),
            attempt,
            params.verbose.unwrap_or(false),
            view.masked,
        );
        let mut out = match detail {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        out.insert("sessionId".into(), json!(view.entry.handle));
        if view.masked {
            // O sanitizador do core não toca em target/initiator: mascara aqui.
            for key in ["target", "initiator"] {
                if let Some(value) = out.get_mut(key) {
                    mask_url_fields(value);
                }
            }
        }
        let warnings: Vec<Value> = view
            .session
            .warnings
            .iter()
            .filter(|w| w.entity.as_deref() == Some(request.id.as_str()))
            .map(|w| json!({"code": w.code, "message": w.message, "severity": w.severity}))
            .collect();
        out.insert("warnings".into(), Value::Array(warnings));
        finish(out, view)
    })
}

// ---------------------------------------------------------------------------
// get_body
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetBodyParams {
    pub session_id: String,
    pub request_id: String,
    /// `response` (padrão) ou `request`.
    pub part: Option<String>,
    /// Byte inicial (padrão 0).
    pub offset: Option<u64>,
    /// Bytes a devolver (padrão: até o fim do que foi lido).
    pub length: Option<u64>,
    /// Limite inline em bytes (padrão 32768, máximo 262144); acima vai para arquivo.
    pub max_inline_bytes: Option<usize>,
    pub reveal: Option<bool>,
}

pub fn get_body(ctx: &Ctx, params: GetBodyParams) -> ToolResult {
    let part = params.part.as_deref().unwrap_or("response");
    if part != "response" && part != "request" {
        return Err(ToolError::invalid(
            "part deve ser \"response\" ou \"request\"",
        ));
    }
    let max_inline = params.max_inline_bytes.unwrap_or(DEFAULT_INLINE);
    if max_inline > MAX_INLINE {
        return Err(ToolError::invalid(format!(
            "max_inline_bytes máximo é {MAX_INLINE}"
        )));
    }
    with_view(ctx, &params.session_id, params.reveal, |view| {
        let request = find_request(view, &params.request_id)?;
        let body = if part == "request" {
            &request.request_body
        } else {
            &request.response_body
        };
        let original = view.original_request(&request.id).unwrap_or(request);
        let original_body = if part == "request" {
            &original.request_body
        } else {
            &original.response_body
        };
        let mut out = match project::body_descriptor(body, original_body, view.masked) {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        out.insert("sessionId".into(), json!(view.entry.handle));
        out.insert("requestId".into(), json!(request.id));
        out.insert("part".into(), json!(part));
        out.insert("inline".into(), json!(false));

        let readable = matches!(body.state, BodyState::Captured | BodyState::Truncated);
        let masked_out = view.masked && project::masked_kind(body) == Some("unsupported");
        let Some(name) = body.attachment.as_ref().filter(|_| readable && !masked_out) else {
            if masked_out {
                out.insert(
                    "hint".into(),
                    json!("corpo não estruturado retido por padrão; use reveal=true (exige --allow-reveal) para lê-lo"),
                );
            }
            return finish(out, view);
        };
        let (bytes, cut) = view
            .read_attachment(name, BODY_READ_LIMIT)
            .ok_or_else(|| ToolError::new("io", format!("anexo {name} indisponível na sessão")))?;
        let total = body.bytes.unwrap_or(bytes.len() as u64);
        let offset = params.offset.unwrap_or(0);
        if offset > bytes.len() as u64 {
            return Err(ToolError::invalid(format!(
                "offset {offset} além do corpo lido ({} bytes)",
                bytes.len()
            )));
        }
        let end = match params.length {
            Some(length) => offset.saturating_add(length).min(bytes.len() as u64),
            None => bytes.len() as u64,
        };
        let slice = &bytes[offset as usize..end as usize];
        out.insert(
            "range".into(),
            json!({"offset": offset, "length": slice.len(), "total": total}),
        );
        if cut {
            out.insert("readTruncated".into(), json!(true));
        }
        match std::str::from_utf8(slice) {
            Ok(text) if slice.len() <= max_inline => {
                out.insert("inline".into(), json!(true));
                out.insert("encoding".into(), json!("utf8"));
                out.insert("text".into(), json!(text));
            }
            result => {
                let textual = result.is_ok();
                let file = spill(
                    ctx,
                    &view.entry.handle,
                    &request.id,
                    part,
                    offset,
                    slice,
                    view.masked,
                    textual,
                )?;
                out.insert(
                    "encoding".into(),
                    json!(if textual { "utf8" } else { "binary" }),
                );
                out.insert("path".into(), json!(file.display().to_string()));
            }
        }
        finish(out, view)
    })
}

#[allow(clippy::too_many_arguments)]
fn spill(
    ctx: &Ctx,
    handle: &str,
    request_id: &str,
    part: &str,
    offset: u64,
    bytes: &[u8],
    masked: bool,
    textual: bool,
) -> Result<PathBuf, ToolError> {
    let dir = ctx.cfg.out_dir.join("bodies").join(slug(handle));
    ensure_private_dir(&ctx.cfg.out_dir.join("bodies"))?;
    ensure_private_dir(&dir)?;
    let canonical = dir
        .canonicalize()
        .map_err(|error| ToolError::new("io", format!("{}: {error}", dir.display())))?;
    if !is_within(&ctx.cfg.out_dir, &canonical) {
        return Err(ToolError::new(
            "outside_allowed_dir",
            "destino fora de --out-dir",
        ));
    }
    let file_name = format!(
        "{}-{part}-{offset}-{}{}.{}",
        slug(request_id),
        bytes.len(),
        if masked { ".masked" } else { "" },
        if textual { "txt" } else { "bin" }
    );
    let path = canonical.join(file_name);
    let tmp = canonical.join(format!(".tmp-{}", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| ToolError::new("io", format!("{}: {error}", tmp.display())))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| ToolError::new("io", error.to_string()))?;
    }
    std::fs::rename(&tmp, &path)
        .map_err(|error| ToolError::new("io", format!("{}: {error}", path.display())))?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// search_bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchBodiesParams {
    pub session_id: String,
    /// Texto literal a procurar.
    pub query: String,
    /// Escopos: url, requestHeaders, responseHeaders, cookies, requestBody,
    /// responseBody. Vazio = todos.
    pub scopes: Option<Vec<String>>,
    pub case_sensitive: Option<bool>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub reveal: Option<bool>,
}

pub fn search_bodies(ctx: &Ctx, params: SearchBodiesParams) -> ToolResult {
    if params.query.is_empty() {
        return Err(ToolError::invalid("query não pode ser vazia"));
    }
    let mut scopes = Vec::new();
    for name in params.scopes.iter().flatten() {
        scopes.push(Scope::parse(name).ok_or_else(|| {
            ToolError::invalid(format!(
                "escopo inválido: {name:?} (url, requestHeaders, responseHeaders, cookies, requestBody, responseBody)"
            ))
        })?);
    }
    with_view(ctx, &params.session_id, params.reveal, |view| {
        let query = SearchQuery {
            text: params.query.clone(),
            scopes,
            case_sensitive: params.case_sensitive.unwrap_or(false),
            max_matches: 5000,
        };
        let source = view.source();
        let result = search_with(view.session, &source, &query);
        let total = result.matches.len();
        let (start, end) = page(
            &params.cursor,
            params.limit,
            DEFAULT_LIMIT,
            MAX_LIMIT,
            total,
        )?;
        let skipped_masked = if view.masked {
            view.session
                .requests
                .iter()
                .flat_map(|r| [&r.request_body, &r.response_body])
                .filter(|b| project::masked_kind(b) == Some("unsupported"))
                .count()
        } else {
            0
        };
        let mut out = Map::new();
        out.insert("sessionId".into(), json!(view.entry.handle));
        out.insert("total".into(), json!(total));
        out.insert("hasMore".into(), json!(end < total));
        if let Some(cursor) = next_cursor(end, total) {
            out.insert("nextCursor".into(), json!(cursor));
        }
        out.insert(
            "matches".into(),
            to_value(&result.matches[start..end].to_vec())?,
        );
        out.insert("partial".into(), json!(result.partial));
        out.insert("partialAttempts".into(), json!(result.partial_attempts));
        out.insert("skippedBinary".into(), json!(result.skipped_binary));
        out.insert("skippedMasked".into(), json!(skipped_masked));
        out.insert("limitReached".into(), json!(result.limit_reached));
        finish(out, view)
    })
}

// ---------------------------------------------------------------------------
// diff_requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffRequestsParams {
    pub session_id: String,
    pub request_a: String,
    pub request_b: String,
    /// Sessão de request_b (padrão: a mesma de request_a).
    pub other_session_id: Option<String>,
    /// Nomes de header/cookie ignorados na saída (sem diferenciar maiúsculas).
    pub ignore: Option<Vec<String>>,
    pub reveal: Option<bool>,
}

fn drop_named(value: &mut Value, group: &str, key: &str, ignore: &HashSet<String>) -> usize {
    let Some(list) = value
        .get_mut(group)
        .and_then(|g| g.get_mut(key))
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let before = list.len();
    list.retain(|item| {
        let name = item
            .get("name")
            .or_else(|| item.get(0).and_then(|first| first.get("name")))
            .and_then(Value::as_str)
            .unwrap_or("");
        !ignore.contains(&name.to_ascii_lowercase())
    });
    before - list.len()
}

pub fn diff_requests_tool(ctx: &Ctx, params: DiffRequestsParams) -> ToolResult {
    let reveal = params.reveal.unwrap_or(false);
    ctx.check_reveal(reveal)?;
    let entry_a = ctx.open(&params.session_id)?;
    let other_handle = params
        .other_session_id
        .clone()
        .unwrap_or_else(|| params.session_id.clone());
    let entry_b = ctx.open(&other_handle)?;
    let (view_a, view_b) = if reveal {
        (View::original(&entry_a), View::original(&entry_b))
    } else {
        (View::masked(&entry_a)?, View::masked(&entry_b)?)
    };
    let a = find_request(&view_a, &params.request_a)?;
    let b = find_request(&view_b, &params.request_b)?;
    let diff = diff_requests(a, b, &DiffOptions::default());
    let mut value = to_value(&diff)?;
    let ignore: HashSet<String> = params
        .ignore
        .iter()
        .flatten()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let mut ignored = 0;
    if !ignore.is_empty() {
        for group in ["requestHeaders", "responseHeaders", "setCookies"] {
            for key in ["added", "removed", "changed", "reordered"] {
                ignored += drop_named(&mut value, group, key, &ignore);
            }
        }
        for key in ["added", "removed", "changed"] {
            ignored += drop_named(&mut value, "cookies", key, &ignore);
        }
    }
    let mut out = match value {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    out.insert("sessionId".into(), json!(params.session_id));
    out.insert("otherSessionId".into(), json!(other_handle));
    out.insert("masked".into(), json!(!reveal));
    out.insert("ignored".into(), json!(ignored));
    if !reveal {
        out.insert(
            "maskNote".into(),
            json!("valores mascarados diferentes aparecem iguais ([REDACTED]); use reveal=true para compará-los"),
        );
    }
    out.insert("revealed".into(), json!(reveal));
    Ok(Value::Object(out))
}

// ---------------------------------------------------------------------------
// diff_sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MapOriginParam {
    /// Origem em A (https://host[:porta]).
    pub from: String,
    /// Origem em B.
    pub to: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffSessionsParams {
    pub session_id_a: String,
    pub session_id_b: String,
    /// Trata dois hosts como o mesmo ao alinhar.
    pub map_origin: Option<MapOriginParam>,
    /// Faixa de A: "de:ate" (ids ou números 1-based).
    pub a_range: Option<String>,
    pub b_range: Option<String>,
    /// Inclui proteção e recursos estáticos no alinhamento.
    pub include_all: Option<bool>,
    /// Só campos que não são estáticos em cada par (padrão true).
    pub only_changed: Option<bool>,
    pub cursor: Option<String>,
    /// Pares por página (padrão 10, máximo 50).
    pub limit: Option<usize>,
    pub reveal: Option<bool>,
}

pub fn diff_sessions(ctx: &Ctx, params: DiffSessionsParams) -> ToolResult {
    let reveal = params.reveal.unwrap_or(false);
    ctx.check_reveal(reveal)?;
    let entry_a = ctx.open(&params.session_id_a)?;
    let entry_b = ctx.open(&params.session_id_b)?;
    let (view_a, view_b) = if reveal {
        (View::original(&entry_a), View::original(&entry_b))
    } else {
        (View::masked(&entry_a)?, View::masked(&entry_b)?)
    };
    let range = |name: &str, text: &Option<String>| -> Result<Option<RequestRange>, ToolError> {
        text.as_ref()
            .map(|t| {
                RequestRange::parse(t)
                    .ok_or_else(|| ToolError::invalid(format!("{name}: faixa inválida {t:?}")))
            })
            .transpose()
    };
    let options = CompareOptions {
        include_all: params.include_all.unwrap_or(false),
        a_range: range("a_range", &params.a_range)?,
        b_range: range("b_range", &params.b_range)?,
        map_origin: params
            .map_origin
            .as_ref()
            .map(|m| {
                OriginMap::parse(&format!("{}={}", m.from, m.to)).ok_or_else(|| {
                    ToolError::invalid("map_origin: from/to devem ser origens (https://host)")
                })
            })
            .transpose()?,
        ..CompareOptions::default()
    };
    let comparison = compare_sessions(
        view_a.session,
        &view_a.source(),
        view_b.session,
        &view_b.source(),
        &options,
    );
    let mut value = to_value(&comparison)?;
    let only_changed = params.only_changed.unwrap_or(true);
    let pairs = value["pairs"].as_array().cloned().unwrap_or_default();
    let total = pairs.len();
    let (start, end) = page(&params.cursor, params.limit, 10, 50, total)?;
    let mut shown: Vec<Value> = pairs[start..end].to_vec();
    if only_changed {
        for pair in &mut shown {
            if let Some(fields) = pair.get_mut("fields").and_then(Value::as_array_mut) {
                fields.retain(|f| f.get("class").and_then(Value::as_str) != Some("static"));
            }
        }
    }
    value["pairs"] = Value::Array(shown);
    let mut out = match value {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    out.insert("sessionIdA".into(), json!(params.session_id_a));
    out.insert("sessionIdB".into(), json!(params.session_id_b));
    out.insert("masked".into(), json!(!reveal));
    out.insert("totalPairs".into(), json!(total));
    out.insert("hasMore".into(), json!(end < total));
    if let Some(cursor) = next_cursor(end, total) {
        out.insert("nextCursor".into(), json!(cursor));
    }
    out.insert("onlyChanged".into(), json!(only_changed));
    if !reveal {
        out.insert(
            "maskNote".into(),
            json!("valores mascarados diferentes aparecem iguais ([REDACTED]); o core classifica esses campos como redacted"),
        );
    }
    out.insert("revealed".into(), json!(reveal));
    Ok(Value::Object(out))
}

// ---------------------------------------------------------------------------
// trace_value
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceValueParams {
    pub session_id: String,
    /// Modo 1: nome de um cookie.
    pub cookie: Option<String>,
    /// Modo 2: valor literal (token, id).
    pub value: Option<String>,
    /// Modo 3: requisição cujos valores consumidos serão rastreados.
    pub request_id: Option<String>,
    /// Modo 3: restringe a um campo (header, cookie, parâmetro).
    pub field: Option<String>,
    /// Máximo por lista (padrão 50, máximo 200).
    pub limit: Option<usize>,
    pub reveal: Option<bool>,
}

pub fn trace_value(ctx: &Ctx, params: TraceValueParams) -> ToolResult {
    let modes = [
        params.cookie.is_some(),
        params.value.is_some(),
        params.request_id.is_some(),
    ];
    if modes.iter().filter(|m| **m).count() != 1 {
        return Err(ToolError::invalid(
            "informe exatamente um de: cookie, value, request_id",
        ));
    }
    let reveal = params.reveal.unwrap_or(false);
    ctx.check_reveal(reveal)?;
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ToolError::invalid(format!(
            "limit deve estar entre 1 e {MAX_LIMIT}"
        )));
    }
    // O cálculo usa sempre a sessão original; a saída é que é mascarada.
    let entry = ctx.open(&params.session_id)?;
    let view = View::original(&entry);
    let mut out = if let Some(name) = &params.cookie {
        trace_cookie(&view, name, limit, reveal)
    } else if let Some(value) = &params.value {
        trace_literal(&view, value, limit, reveal)?
    } else {
        trace_request(&view, &params, reveal)?
    };
    out.insert("sessionId".into(), json!(entry.handle));
    out.insert("revealed".into(), json!(reveal));
    Ok(Value::Object(out))
}

/// Requisições em ordem cronológica. `session.requests` não é cronológica em
/// capturas reais (vem por id); ordena por `Attempt.started_at` quando todas as
/// requisições têm tempo, senão mantém a ordem da sessão. O booleano diz se a
/// ordem é cronológica.
fn chronological<'a>(view: &View<'a>) -> (Vec<&'a LogicalRequest>, bool) {
    let mut list: Vec<&LogicalRequest> = view.session.requests.iter().collect();
    let start = |r: &LogicalRequest| {
        r.attempts
            .iter()
            .filter_map(|a| a.started_at)
            .reduce(f64::min)
    };
    if list.iter().all(|r| start(r).is_some()) {
        list.sort_by(|a, b| {
            start(a)
                .partial_cmp(&start(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        (list, true)
    } else {
        (list, false)
    }
}

fn order_note(chronological: bool) -> &'static str {
    if chronological {
        "ordem cronológica por startedAt (session.requests não é cronológica em capturas reais)"
    } else {
        "sem startedAt em todas as requisições: usada a ordem da sessão, que pode não ser cronológica"
    }
}

/// Mascara tokens de query/fragmento em todo campo `url` de um objeto JSON.
fn mask_url_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "url" {
                    if let Some(url) = item.as_str() {
                        *item = json!(shown_url(url, false));
                    }
                } else {
                    mask_url_fields(item);
                }
            }
        }
        Value::Array(list) => list.iter_mut().for_each(mask_url_fields),
        _ => {}
    }
}

/// URL como aparece na saída: tokens de query/fragmento mascarados sem reveal.
pub(crate) fn shown_url(url: &str, reveal: bool) -> String {
    if reveal {
        url.to_string()
    } else {
        scrapelens_core::export::sanitize::sanitize_url(
            url,
            &scrapelens_core::export::sanitize::SanitizeOptions::default(),
        )
    }
}

fn trace_cookie(view: &View<'_>, name: &str, limit: usize, reveal: bool) -> Map<String, Value> {
    let mut setters: Vec<Value> = Vec::new();
    let mut users: Vec<Value> = Vec::new();
    let mut first_value: Option<String> = None;
    let mut setters_total = 0;
    let mut users_total = 0;
    let (ordered, chrono) = chronological(view);
    for request in ordered {
        for attempt in &request.attempts {
            for record in &attempt.set_cookies {
                let Some(parsed) = record.parsed.as_ref().filter(|p| p.name == name) else {
                    continue;
                };
                setters_total += 1;
                if first_value.is_none() {
                    first_value = Some(parsed.value.clone());
                }
                if setters.len() < limit {
                    let mut item = json!({
                        "requestId": request.id,
                        "attemptId": attempt.id,
                        "url": shown_url(&attempt.url, reveal),
                        "startedAt": attempt.started_at,
                        "source": record.provenance.source.as_str(),
                        "verification": record.provenance.verification.as_str(),
                        "valueLength": parsed.value.chars().count(),
                        "attributes": {
                            "domain": parsed.domain, "path": parsed.path, "expires": parsed.expires,
                            "maxAge": parsed.max_age, "secure": parsed.secure,
                            "httpOnly": parsed.http_only, "sameSite": parsed.same_site,
                        },
                    });
                    if reveal {
                        item["value"] = json!(parsed.value);
                    }
                    setters.push(item);
                }
            }
            for pair in attempt.cookie.pairs.iter().filter(|p| p.name == name) {
                users_total += 1;
                if users.len() < limit {
                    let mut item = json!({
                        "requestId": request.id,
                        "attemptId": attempt.id,
                        "method": attempt.method,
                        "url": shown_url(&attempt.url, reveal),
                        "startedAt": attempt.started_at,
                        "source": pair.provenance.source.as_str(),
                        "valueLength": pair.value.chars().count(),
                        "afterFirstSetter": first_value.is_some(),
                        "sentValueEqualsFirstSetter": first_value.as_ref().map(|v| v == &pair.value),
                    });
                    if reveal {
                        item["value"] = json!(pair.value);
                    }
                    users.push(item);
                }
            }
        }
    }
    let mut notes = vec![order_note(chrono).to_string()];
    if setters_total == 0 {
        notes.push("nenhuma resposta observada define este cookie; ele pode vir de document.cookie, do perfil do navegador ou de captura incompleta — a origem não é afirmada".to_string());
    }
    if users_total == 0 {
        notes.push("nenhuma requisição observada envia este cookie".to_string());
    }
    let mut out = Map::new();
    out.insert("mode".into(), json!("cookie"));
    out.insert("cookie".into(), json!(name));
    out.insert(
        "firstSetter".into(),
        setters.first().cloned().unwrap_or(Value::Null),
    );
    out.insert("settersTotal".into(), json!(setters_total));
    out.insert("setters".into(), Value::Array(setters));
    out.insert("usersTotal".into(), json!(users_total));
    out.insert("users".into(), Value::Array(users));
    out.insert(
        "truncated".into(),
        json!(setters_total > limit || users_total > limit),
    );
    out.insert("notes".into(), json!(notes));
    out.insert("evidence".into(), json!("set-cookie-observed"));
    out
}

fn trace_literal(
    view: &View<'_>,
    value: &str,
    limit: usize,
    reveal: bool,
) -> Result<Map<String, Value>, ToolError> {
    if value.is_empty() {
        return Err(ToolError::invalid("value não pode ser vazio"));
    }
    let query = SearchQuery {
        text: value.to_string(),
        scopes: vec![
            Scope::Url,
            Scope::RequestHeaders,
            Scope::ResponseHeaders,
            Scope::RequestBody,
            Scope::ResponseBody,
        ],
        case_sensitive: true,
        max_matches: 5000,
    };
    let source = view.source();
    let result = search_with(view.session, &source, &query);
    let (ordered, chrono) = chronological(view);
    let index: std::collections::HashMap<&str, usize> = ordered
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();
    let mut matches = result.matches.clone();
    matches.sort_by_key(|m| {
        index
            .get(m.request_id.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
    let is_producer = |scope: Scope| matches!(scope, Scope::ResponseHeaders | Scope::ResponseBody);
    let first_producer = matches.iter().position(|m| is_producer(m.scope));
    let first_index =
        first_producer.and_then(|i| index.get(matches[i].request_id.as_str()).copied());
    let item = |m: &scrapelens_core::search::Match| {
        let at = index.get(m.request_id.as_str()).copied();
        json!({
            "requestId": m.request_id,
            "attemptId": m.attempt_id,
            "scope": m.scope,
            "field": m.field,
            "byteOffset": m.byte_offset,
            "position": match (first_index, at) {
                (Some(first), Some(at)) if at < first => "before-first-producer",
                (Some(_), Some(_)) => "at-or-after-first-producer",
                _ => "no-producer-observed",
            },
        })
    };
    let producers: Vec<&_> = matches.iter().filter(|m| is_producer(m.scope)).collect();
    let consumers: Vec<&_> = matches.iter().filter(|m| !is_producer(m.scope)).collect();
    let mut warnings: Vec<String> = Vec::new();
    if value.chars().count() < 8 {
        warnings.push("valor curto (< 8 caracteres): coincidências podem ser acaso".to_string());
    }
    if first_producer.is_none() {
        warnings.push("nenhuma resposta observada contém este valor: ele pode ter sido gerado no cliente, vir de um corpo não capturado ou de captura incompleta".to_string());
    }
    if result.partial {
        warnings.push("busca parcial: algum corpo truncado foi pesquisado".to_string());
    }
    if result.skipped_binary > 0 {
        warnings.push(format!(
            "{} corpo(s) binário(s) não pesquisados",
            result.skipped_binary
        ));
    }
    let mut out = Map::new();
    out.insert("mode".into(), json!("value"));
    out.insert("length".into(), json!(value.chars().count()));
    if reveal {
        out.insert("value".into(), json!(value));
    }
    out.insert("evidence".into(), json!("literal-match"));
    out.insert(
        "firstProducer".into(),
        first_producer
            .map(|i| item(&matches[i]))
            .unwrap_or(Value::Null),
    );
    out.insert("producersTotal".into(), json!(producers.len()));
    out.insert(
        "producers".into(),
        Value::Array(producers.iter().take(limit).map(|m| item(m)).collect()),
    );
    out.insert("consumersTotal".into(), json!(consumers.len()));
    out.insert(
        "consumers".into(),
        Value::Array(consumers.iter().take(limit).map(|m| item(m)).collect()),
    );
    out.insert(
        "truncated".into(),
        json!(producers.len() > limit || consumers.len() > limit || result.limit_reached),
    );
    out.insert("warnings".into(), json!(warnings));
    out.insert("notes".into(), json!([order_note(chrono)]));
    Ok(out)
}

fn trace_request(
    view: &View<'_>,
    params: &TraceValueParams,
    reveal: bool,
) -> Result<Map<String, Value>, ToolError> {
    let id = params.request_id.as_deref().unwrap_or("");
    find_request(view, id)?;
    let source = view.source();
    let origins = value_origins(view.session, &source, id, &FlowOptions::default())
        .map_err(|error| ToolError::new("io", error.to_string()))?;
    let mut value = to_value(&origins)?;
    if let Some(values) = value.get_mut("values").and_then(Value::as_array_mut) {
        if let Some(field) = &params.field {
            values.retain(|v| {
                v.get("field")
                    .and_then(Value::as_str)
                    .is_some_and(|f| f.eq_ignore_ascii_case(field))
            });
        }
        if !reveal {
            for item in values.iter_mut() {
                if item.get("value").is_some() {
                    item["value"] = json!(PLACEHOLDER);
                }
            }
        }
    }
    let mut out = match value {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    out.insert("mode".into(), json!("request"));
    Ok(out)
}

// ---------------------------------------------------------------------------
// site_profile
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SiteProfileParams {
    pub session_id: String,
    /// Requisição cujos tokens serão rastreados (padrão: as últimas XHR/fetch
    /// bem-sucedidas da aplicação).
    pub target_request_id: Option<String>,
}

/// Reconhecimento do site (proteções, bloqueios, cookies e tokens) com
/// evidência. A função do `recon` já redige valores (`[redigido, N bytes]`) e
/// tira a query das URLs, então roda sobre a sessão original (precisa dos
/// valores reais para rastrear tokens) sem vazar; as URLs passam por
/// `sanitize_url` mesmo assim.
pub fn site_profile(ctx: &Ctx, params: SiteProfileParams) -> ToolResult {
    let entry = ctx.open(&params.session_id)?;
    if let Some(id) = &params.target_request_id {
        entry.lazy.session.find_request(id).ok_or_else(|| {
            ToolError::not_found(format!("requisição {id:?} não encontrada na sessão"))
        })?;
    }
    let options = scrapelens_recon::ProfileOptions {
        target_request_id: params.target_request_id.clone(),
        ..scrapelens_recon::ProfileOptions::default()
    };
    let source = scrapelens_core::search::LazyBodies(&entry.lazy);
    let profile = scrapelens_recon::site_profile(&entry.lazy.session, &source, &options);
    let mut value = to_value(&profile)?;
    mask_url_fields(&mut value);
    if let Value::Object(map) = &mut value {
        map.insert("sessionId".into(), json!(entry.handle));
    }
    Ok(value)
}

/// Rede de segurança final de TODA saída sem `reveal`: em qualquer string, o
/// valor de parâmetro de query com nome sensível vira `[REDACTED]`. Roda sobre
/// o JSON inteiro, não só sobre campos conhecidos. Defesa em profundidade: o
/// sanitizador do core já cobre os campos do modelo.
pub fn scrub_output(value: &mut Value) {
    fn walk(value: &mut Value, options: &scrapelens_core::export::sanitize::SanitizeOptions) {
        match value {
            Value::String(text) => {
                if text.contains('?') {
                    *text = scrapelens_core::export::sanitize::sanitize_text(text, options);
                }
            }
            Value::Array(list) => list.iter_mut().for_each(|item| walk(item, options)),
            Value::Object(map) => map.values_mut().for_each(|item| walk(item, options)),
            _ => {}
        }
    }
    walk(
        value,
        &scrapelens_core::export::sanitize::SanitizeOptions::default(),
    );
}
