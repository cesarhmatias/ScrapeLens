//! Adaptadores de protocolo registrados no app (hoje só `natural-ajax`) e a visão
//! estruturada derivada de campos que um adaptador reivindica. O bruto continua
//! primário na UI; esta visão é só uma leitura do decode.

use std::sync::Arc;

use scrapelens_core::adapter::{AdapterContext, AdapterRegistry, PartRole};
use scrapelens_core::export::priming::AdapterEncoder;
use scrapelens_core::flow::FlowOptions;
use scrapelens_core::model::{BodyState, LogicalRequest};
use scrapelens_core::search::{BodySource, LazyBodies};
use scrapelens_natural_ajax::{NaturalAjax, ADAPTER_ID, PYTHON_DECODER, PYTHON_ENCODER, PYTHON_FUNCTION};
use serde::Serialize;

pub fn registry() -> AdapterRegistry {
    AdapterRegistry::new().with(Arc::new(NaturalAjax))
}

/// `FlowOptions` com os adaptadores do app (origins, chain, compare, priming).
pub fn flow_options() -> FlowOptions {
    FlowOptions {
        adapters: registry(),
        ..FlowOptions::default()
    }
}

pub fn priming_encoders() -> Vec<AdapterEncoder> {
    vec![AdapterEncoder {
        adapter_id: ADAPTER_ID.to_string(),
        function: PYTHON_FUNCTION.to_string(),
        decoder: PYTHON_DECODER.to_string(),
        source: PYTHON_ENCODER.to_string(),
    }]
}

/// O script gerado usou o codificador do adaptador?
pub fn script_uses_adapter(text: &str) -> Option<&'static str> {
    text.contains(PYTHON_FUNCTION).then_some(ADAPTER_ID)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewPart {
    pub name: String,
    pub role: String,
    pub value: String,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterField {
    pub field: String,
    pub adapter_id: String,
    /// Texto bruto do campo (primário na UI).
    pub raw: String,
    /// Mensagem quando o decode falha; `parts` fica vazio.
    pub error: Option<String>,
    pub parts: Vec<ViewPart>,
    /// Partes não enviadas por causa dos limites (por campo e por corpo); o bruto tem tudo.
    pub omitted_parts: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterView {
    /// `request` ou `response`.
    pub side: String,
    pub fields: Vec<AdapterField>,
    /// Corpo indisponível/truncado ou sem campos reivindicados.
    pub note: Option<String>,
}

const MAX_FIELDS: usize = 20;
/// Partes enviadas por campo e por corpo (IPC e tabela da UI).
pub const MAX_PARTS_PER_FIELD: usize = 2_000;
pub const MAX_PARTS_PER_BODY: usize = 10_000;

/// Corta `parts` em `min(por campo, orçamento restante)`; devolve as mantidas e quantas foram omitidas.
pub fn cap_parts<T>(mut parts: Vec<T>, body_budget: usize) -> (Vec<T>, usize) {
    let keep = MAX_PARTS_PER_FIELD.min(body_budget);
    let omitted = parts.len().saturating_sub(keep);
    parts.truncate(keep);
    (parts, omitted)
}
/// Campo maior que isto não é decodificado na visão (a decodificação roda na thread de trabalho).
pub const MAX_FIELD_BYTES: usize = 512 * 1024;
/// Tempo máximo de decodificação por campo.
const DECODE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Quanto do bruto acompanha um campo que não foi decodificado.
const RAW_SHOWN_BYTES: usize = 64 * 1024;
pub const TOO_BIG_MESSAGE: &str = "campo grande demais para a visão do adaptador";

fn clip(raw: &str) -> String {
    if raw.len() <= RAW_SHOWN_BYTES {
        return raw.to_string();
    }
    let mut end = RAW_SHOWN_BYTES;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (+{} bytes não exibidos)", &raw[..end], raw.len() - end)
}

fn role_name(role: &PartRole) -> String {
    match role {
        PartRole::Structure => "estrutura".into(),
        PartRole::Name => "nome".into(),
        PartRole::Value => "valor".into(),
        PartRole::Delta => "delta".into(),
        PartRole::Other(other) => other.clone(),
    }
}

fn candidates(text: &str, media: &str) -> Vec<(String, String)> {
    let html = {
        let lower = text.get(..text.len().min(4096)).unwrap_or("").to_ascii_lowercase();
        lower.contains("<textarea") || lower.contains("<input") || lower.contains("<html")
    };
    if html {
        return scrapelens_core::html::html_controls(text)
            .into_iter()
            .map(|c| (c.name, c.value))
            .collect();
    }
    let form = media.contains("x-www-form-urlencoded") || (!media.contains("json") && text.contains('=') && !text.contains(['{', '<']));
    if !form {
        return Vec::new();
    }
    text.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                scrapelens_natural_ajax::extract::form_decode(k),
                scrapelens_natural_ajax::extract::form_decode(v),
            ))
        })
        .collect()
}

pub fn view(
    lazy: &scrapelens_core::lazy::LazySession,
    request: &LogicalRequest,
    side: &str,
) -> Result<AdapterView, String> {
    let request_side = match side {
        "request" => true,
        "response" => false,
        other => return Err(format!("lado desconhecido: {other:?} (use \"request\" ou \"response\")")),
    };
    let body = if request_side { &request.request_body } else { &request.response_body };
    let headers = if request_side { &request.request_headers } else { &request.response_headers };
    let mut view = AdapterView { side: side.to_string(), fields: Vec::new(), note: None };
    if !matches!(body.state, BodyState::Captured | BodyState::Truncated) {
        view.note = Some("corpo indisponível; não há campo para decodificar".into());
        return Ok(view);
    }
    let Some(name) = body.attachment.as_deref() else {
        view.note = Some("corpo sem anexo; não há campo para decodificar".into());
        return Ok(view);
    };
    let source = LazyBodies(lazy);
    let Some(loaded) = source.load(name) else {
        view.note = Some("não foi possível ler o corpo".into());
        return Ok(view);
    };
    let Ok(text) = String::from_utf8(loaded.bytes.into_owned()) else {
        view.note = Some("corpo binário; não há campo para decodificar".into());
        return Ok(view);
    };
    let media = headers
        .first_value("content-type")
        .or(body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    let adapters = registry();
    let ctx = AdapterContext { url: &request.url, method: &request.method, request: request_side, media: Some(&media) };
    for (field, value) in candidates(&text, &media) {
        // O tamanho é checado antes de `claim` (que já percorre a gramática).
        if value.len() > MAX_FIELD_BYTES {
            if view.fields.len() < MAX_FIELDS {
                view.fields.push(AdapterField {
                    field,
                    adapter_id: ADAPTER_ID.to_string(),
                    raw: clip(&value),
                    error: Some(format!("{TOO_BIG_MESSAGE} (limite {} KiB)", MAX_FIELD_BYTES / 1024)),
                    parts: Vec::new(),
                    omitted_parts: 0,
                });
            }
            continue;
        }
        let Some(adapter) = adapters.claim(&field, &value, &ctx) else { continue };
        if view.fields.len() >= MAX_FIELDS {
            view.note = Some(format!("mostrando os primeiros {MAX_FIELDS} campos reivindicados"));
            break;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let (adapter, value) = (Arc::clone(adapter), value.clone());
            std::thread::spawn(move || {
                let _ = tx.send(adapter.decode(&value));
            });
        }
        let decoded = rx
            .recv_timeout(DECODE_TIMEOUT)
            .unwrap_or_else(|_| Err(scrapelens_core::error::CoreError::LimitExceeded {
                message: format!("a decodificação passou de {} s; campo não decodificado", DECODE_TIMEOUT.as_secs()),
            }));
        let (parts, error) = match decoded {
            Ok(decoded) => (
                decoded
                    .parts
                    .into_iter()
                    .map(|p| ViewPart { name: p.name, role: role_name(&p.role), value: p.value, offset: p.offset, len: p.len })
                    .collect(),
                None,
            ),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let used: usize = view.fields.iter().map(|f| f.parts.len()).sum();
        let (parts, omitted_parts) = cap_parts(parts, MAX_PARTS_PER_BODY.saturating_sub(used));
        let raw = if error.is_some() { clip(&value) } else { value };
        view.fields.push(AdapterField { field, adapter_id: adapter.id().to_string(), raw, error, parts, omitted_parts });
    }
    if view.fields.is_empty() && view.note.is_none() {
        view.note = Some("nenhum campo deste corpo é reivindicado por um adaptador de protocolo".into());
    }
    if body.state == BodyState::Truncated {
        let extra = "corpo truncado: a visão cobre só o que foi capturado";
        view.note = Some(view.note.map_or(extra.to_string(), |n| format!("{n}; {extra}")));
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_are_capped_per_field_and_per_body() {
        let (kept, omitted) = cap_parts((0..524_288).collect::<Vec<_>>(), MAX_PARTS_PER_BODY);
        assert_eq!((kept.len(), omitted), (MAX_PARTS_PER_FIELD, 524_288 - MAX_PARTS_PER_FIELD));
        // orçamento do corpo quase esgotado
        let (kept, omitted) = cap_parts((0..500).collect::<Vec<_>>(), 120);
        assert_eq!((kept.len(), omitted), (120, 380));
        let (kept, omitted) = cap_parts((0..10).collect::<Vec<_>>(), 0);
        assert_eq!((kept.len(), omitted), (0, 10));
        let (kept, omitted) = cap_parts((0..10).collect::<Vec<_>>(), 50);
        assert_eq!((kept.len(), omitted), (10, 0));
    }
}
