//! Corpos CDP (`cdp-bodies.jsonl`, contrato em `docs/08-corpos-busca.md` §1).
//!
//! Cada linha é mapeada **só** por `requestId` + `attemptIndex` para a tentativa
//! que o importador CDP já numerou. Linha sem requisição/tentativa
//! correspondente vira aviso; nunca há associação por URL ou horário. Os bytes
//! de `data` não são reinterpretados: `utf8` vira os bytes da string, `base64`
//! é decodificado.

use std::collections::BTreeMap;

use base64::Engine;
use serde::Deserialize;

use crate::model::{
    Body, BodyState, Provenance, SessionV1, Source, Verification, Warning, WarningSeverity,
};
use crate::store;

/// Nome do arquivo de corpos ao lado de `cdp-events.jsonl`.
pub const BODIES_FILE_NAME: &str = "cdp-bodies.jsonl";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BodyLine {
    #[serde(default)]
    v: u32,
    request_id: String,
    attempt_index: u32,
    kind: String,
    state: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    original_size: Option<u64>,
    #[serde(default)]
    captured_size: Option<u64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    timestamp: Option<f64>,
    #[serde(default)]
    transformed: Vec<String>,
}

/// Resultado de aplicar o arquivo de corpos.
#[derive(Debug, Default)]
pub struct BodiesOutcome {
    pub lines: usize,
    pub applied: usize,
    pub orphans: usize,
    pub warnings: Vec<Warning>,
}

fn warn(code: &str, message: String) -> Warning {
    let mut warning = Warning::new(code, message);
    warning.severity = WarningSeverity::Warning;
    warning
}

/// Candidatos de caminho para o arquivo de corpos irmão do `.jsonl` de eventos.
pub fn sibling_candidates(cdp_events: &std::path::Path) -> Vec<std::path::PathBuf> {
    let dir = cdp_events
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let mut candidates = vec![dir.join(BODIES_FILE_NAME)];
    if let Some(stem) = cdp_events
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".jsonl"))
    {
        candidates.push(dir.join(format!("{stem}-bodies.jsonl")));
    }
    candidates
}

/// Aplica as linhas de corpo à sessão, gravando bytes em `attachments`.
pub fn apply_cdp_bodies(
    session: &mut SessionV1,
    attachments: &mut BTreeMap<String, Vec<u8>>,
    jsonl: &[u8],
) -> BodiesOutcome {
    apply_cdp_bodies_with_capture(session, attachments, jsonl, None)
}

/// Como [`apply_cdp_bodies`]. Com a captura CDP original, uma requisição
/// GET/HEAD sem linha de corpo e sem `hasPostData` vira `empty` ("CDP:
/// requisição sem corpo") em vez de ficar `unavailable`.
pub fn apply_cdp_bodies_with_capture(
    session: &mut SessionV1,
    attachments: &mut BTreeMap<String, Vec<u8>>,
    jsonl: &[u8],
    capture: Option<&super::cdp::CdpCapture>,
) -> BodiesOutcome {
    let mut outcome = BodiesOutcome::default();
    // (índice lógico, índice da tentativa, kind) -> linha escolhida.
    let mut chosen: BTreeMap<(usize, usize, bool), BodyLine> = BTreeMap::new();
    let by_request: BTreeMap<&str, usize> = {
        let mut map = BTreeMap::new();
        for (index, request) in session.requests.iter().enumerate() {
            if let Some(id) = request
                .cdp
                .as_ref()
                .and_then(|cdp| cdp.request_id.as_deref())
            {
                map.entry(id).or_insert(index);
            }
        }
        map
    };
    let mut resolved: Vec<((usize, usize, bool), BodyLine)> = Vec::new();
    for (number, raw) in String::from_utf8_lossy(jsonl).lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        outcome.lines += 1;
        let line: BodyLine = match serde_json::from_str(raw) {
            Ok(line) => line,
            Err(error) => {
                outcome.warnings.push(warn(
                    "cdp.body_line_invalid",
                    format!("cdp-bodies.jsonl linha {}: {error}", number + 1),
                ));
                continue;
            }
        };
        if line.v != 1 {
            outcome.warnings.push(warn(
                "cdp.body_version_unknown",
                format!(
                    "cdp-bodies.jsonl linha {}: versão {} desconhecida; ignorada",
                    number + 1,
                    line.v
                ),
            ));
            continue;
        }
        let is_request = match line.kind.as_str() {
            "request" => true,
            "response" => false,
            other => {
                outcome.warnings.push(warn(
                    "cdp.body_line_invalid",
                    format!(
                        "cdp-bodies.jsonl linha {}: kind {other:?} desconhecido",
                        number + 1
                    ),
                ));
                continue;
            }
        };
        let slot = by_request
            .get(line.request_id.as_str())
            .and_then(|&request| {
                session.requests[request]
                    .attempts
                    .iter()
                    .position(|attempt| attempt.index == line.attempt_index)
                    .map(|attempt| (request, attempt, is_request))
            });
        let Some(slot) = slot else {
            outcome.orphans += 1;
            outcome.warnings.push(warn(
                "cdp.body_orphan",
                format!(
                    "corpo órfão (requestId {}, attemptIndex {}, {}): sem requisição/tentativa correspondente; não associado",
                    line.request_id, line.attempt_index, line.kind
                ),
            ));
            continue;
        };
        resolved.push((slot, line));
    }
    for (slot, line) in resolved {
        match chosen.get(&slot) {
            None => {
                chosen.insert(slot, line);
            }
            Some(existing) => {
                outcome.warnings.push(warn(
                    "cdp.body_duplicate",
                    format!(
                        "mais de uma linha de corpo para requestId {} attemptIndex {} ({}); mantida a que traz bytes",
                        line.request_id, line.attempt_index, line.kind
                    ),
                ));
                let new_has = matches!(line.state.as_str(), "captured" | "truncated");
                let old_has = matches!(existing.state.as_str(), "captured" | "truncated");
                if new_has && !old_has {
                    chosen.insert(slot, line);
                }
            }
        }
    }

    for ((request_index, attempt_index, is_request), line) in chosen {
        let request = &mut session.requests[request_index];
        let attempt = &mut request.attempts[attempt_index];
        let content_type = if is_request {
            attempt.request_headers.first_value("content-type")
        } else {
            attempt.response_headers.first_value("content-type")
        }
        .map(str::to_string);
        let suffix = if is_request { "request" } else { "response" };
        let name = format!("{}.{suffix}.body", attempt.id);
        let mut body = build_body(&line, &name, attachments, &mut outcome.warnings);
        if !line.transformed.is_empty() && body.has_bytes() {
            body.transformed = line.transformed.clone();
            body.provenance.verification =
                body.provenance.verification.weakest(Verification::Partial);
            body.provenance.notes.push(format!(
                "não idêntico ao fio: {}",
                line.transformed.join(", ")
            ));
        }
        if body.has_bytes() {
            if let Some(content_type) = content_type {
                body = body.with_content_type(content_type);
            }
        }
        if is_request {
            attempt.request_body = body;
        } else {
            attempt.response_body = body;
        }
        outcome.applied += 1;
    }
    if let Some(capture) = capture {
        mark_bodyless_requests(session, capture);
    }
    // O corpo "principal" do pedido lógico acompanha a última tentativa, como
    // os demais campos derivados em `refresh_primary_from_attempt`.
    for request in &mut session.requests {
        if let Some(last) = request.attempts.last() {
            request.request_body = last.request_body.clone();
            request.response_body = last.response_body.clone();
        }
    }
    outcome
}

fn build_body(
    line: &BodyLine,
    attachment: &str,
    attachments: &mut BTreeMap<String, Vec<u8>>,
    warnings: &mut Vec<Warning>,
) -> Body {
    let event = line
        .source
        .clone()
        .unwrap_or_else(|| "cdp-bodies.jsonl".to_string());
    let provenance = |verification| {
        Provenance::new(Source::Cdp, "cdp-bodies.jsonl", verification)
            .with_event(event.clone())
            .with_source_id(line.request_id.clone())
            .with_optional_timestamp(line.timestamp)
    };
    let reason = line
        .reason
        .clone()
        .unwrap_or_else(|| "sem motivo informado".to_string());
    let invalid = |why: String, warnings: &mut Vec<Warning>| {
        warnings.push(warn(
            "cdp.body_line_invalid",
            format!(
                "corpo de {} (attemptIndex {}) inválido: {why}",
                line.request_id, line.attempt_index
            ),
        ));
        let mut body = Body::unavailable(format!("linha de corpo inválida: {why}"));
        body.provenance = provenance(Verification::Unverified);
        body
    };
    match line.state.as_str() {
        "captured" | "truncated" => {
            let Some(data) = &line.data else {
                return invalid(format!("estado {} sem data", line.state), warnings);
            };
            let bytes = match line.encoding.as_deref() {
                Some("base64") => {
                    match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
                        Ok(bytes) => bytes,
                        Err(error) => return invalid(format!("base64: {error}"), warnings),
                    }
                }
                Some("utf8") | None => data.as_bytes().to_vec(),
                Some(other) => return invalid(format!("encoding {other:?}"), warnings),
            };
            if store::validate_attachment_name(attachment).is_err() {
                return invalid("nome de anexo inválido".to_string(), warnings);
            }
            let len = bytes.len() as u64;
            if let Some(declared) = line.captured_size {
                if declared != len {
                    warnings.push(warn(
                        "cdp.body_size_mismatch",
                        format!(
                            "corpo de {}: capturedSize={declared}, bytes decodificados={len}",
                            line.request_id
                        ),
                    ));
                }
            }
            attachments.insert(attachment.to_string(), bytes);
            if line.state == "truncated" {
                let mut body = Body::truncated(
                    attachment,
                    line.original_size.unwrap_or(len),
                    len,
                    &provenance(Verification::Partial),
                );
                body.note = Some(match line.original_size {
                    Some(original) => format!("truncado: {len} de {original} bytes"),
                    None => format!("truncado em {len} bytes (tamanho original desconhecido)"),
                });
                body
            } else {
                Body::captured(attachment, len, &provenance(Verification::Unverified))
            }
        }
        "empty" => {
            let mut body = Body::empty(&provenance(Verification::Unverified));
            body.note = line.reason.clone();
            body
        }
        "unavailable" | "discarded" => {
            let mut body = if line.state == "discarded" {
                Body::discarded(reason)
            } else {
                Body::unavailable(reason)
            };
            body.bytes = line.original_size;
            body.provenance = provenance(Verification::Unverified);
            debug_assert!(matches!(
                body.state,
                BodyState::Unavailable | BodyState::Discarded
            ));
            body
        }
        other => invalid(format!("state {other:?}"), warnings),
    }
}

/// GET/HEAD sem `hasPostData` e sem linha de corpo: `empty` com evidência.
fn mark_bodyless_requests(session: &mut SessionV1, capture: &super::cdp::CdpCapture) {
    for request in &mut session.requests {
        let Some(cdp_id) = request.cdp.as_ref().and_then(|cdp| cdp.request_id.clone()) else {
            continue;
        };
        let Some(source) = capture.requests.iter().find(|r| r.request_id == cdp_id) else {
            continue;
        };
        for attempt in &mut request.attempts {
            let Some(parsed) = source.attempts.get(attempt.index as usize) else {
                continue;
            };
            let bodyless_method =
                matches!(parsed.method.to_ascii_uppercase().as_str(), "GET" | "HEAD");
            if attempt.request_body.state == BodyState::Unavailable
                && attempt.request_body.provenance.source == Source::Derived
                && bodyless_method
                && !parsed.has_post_data
            {
                let provenance = Provenance::new(
                    Source::Cdp,
                    "requestWillBeSent.hasPostData",
                    Verification::Unverified,
                )
                .with_event("Network.requestWillBeSent")
                .with_source_id(cdp_id.clone());
                let mut body = Body::empty(&provenance);
                body.note = Some("CDP: requisição sem corpo".to_string());
                attempt.request_body = body;
            }
        }
    }
}
