//! Exportadores. Nenhum deles promete replicar TLS ou fingerprint do
//! navegador: o alvo é a requisição no nível HTTP, com escaping correto de
//! dados não confiáveis.

pub mod curl;
pub mod python;
pub mod sanitize;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{LogicalRequest, Warning};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOptions {
    /// Inclui corpo quando os bytes foram fornecidos pelo chamador.
    pub include_body: bool,
    /// Limite de bytes de corpo para uma exportação de linha de comando.
    pub max_body_bytes: usize,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_body: true,
            max_body_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOutput {
    pub text: String,
    #[serde(default)]
    pub warnings: Vec<Warning>,
    #[serde(default)]
    pub skipped_headers: Vec<String>,
    pub body_included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_note: Option<String>,
}

impl ExportOutput {
    pub fn new(text: String) -> Self {
        Self {
            text,
            warnings: Vec::new(),
            skipped_headers: Vec::new(),
            body_included: false,
            body_note: None,
        }
    }
}

/// Header exportável: nome válido e valor sem CR/LF/NUL.
pub struct ExportableHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Valida o nome contra o token HTTP (RFC 9110) e rejeita injeção de linha.
pub fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || byte.is_ascii_alphanumeric()
        })
}

pub fn is_safe_header_value(value: &str) -> bool {
    !value.contains(['\r', '\n', '\0'])
}

/// Coleta headers comuns na ordem da fonte; pseudoheaders ficam de fora e são
/// listados em `skipped_headers` (não são replicáveis por cURL/Python).
pub fn exportable_headers<'a>(
    request: &'a LogicalRequest,
    output: &mut ExportOutput,
) -> Vec<ExportableHeader<'a>> {
    let mut headers = Vec::new();
    for entry in request.request_headers.iter_all() {
        if entry.is_pseudo() {
            output
                .skipped_headers
                .push(format!("{}: pseudoheader não replicável", entry.name));
            continue;
        }
        if !is_header_token(&entry.name) {
            output
                .skipped_headers
                .push(format!("{}: nome de header inválido", entry.name));
            output.warnings.push(Warning::new(
                "export.invalid_header_name",
                format!("header descartado por nome inválido: {:?}", entry.name),
            ));
            continue;
        }
        if !is_safe_header_value(&entry.value) {
            output
                .skipped_headers
                .push(format!("{}: valor contém CR/LF/NUL", entry.name));
            output.warnings.push(Warning::new(
                "export.header_injection",
                format!(
                    "header {} descartado: valor contém CR, LF ou NUL e não pode ser reproduzido com segurança",
                    entry.name
                ),
            ));
            continue;
        }
        headers.push(ExportableHeader {
            name: &entry.name,
            value: &entry.value,
        });
    }
    headers
}

/// Remove `Content-Length` quando o corpo não será enviado; manter o header
/// produziria uma requisição que trava esperando bytes.
pub fn drop_content_length_without_body<'a>(
    headers: Vec<ExportableHeader<'a>>,
    body_included: bool,
    output: &mut ExportOutput,
) -> Vec<ExportableHeader<'a>> {
    if body_included {
        return headers;
    }
    headers
        .into_iter()
        .filter(|header| {
            if header.name.eq_ignore_ascii_case("content-length") {
                output.skipped_headers.push(
                    "content-length: removido porque o corpo não foi exportado".to_string(),
                );
                output.warnings.push(Warning::new(
                    "export.content_length_without_body",
                    "Content-Length original removido: o corpo não acompanha a exportação",
                ));
                false
            } else {
                true
            }
        })
        .collect()
}

/// Resolve o corpo a exportar. Retorna `None` quando o estado não permite ou
/// os bytes não foram carregados, sempre com aviso.
pub fn resolve_body<'a>(
    request: &LogicalRequest,
    bytes: Option<&'a [u8]>,
    options: &ExportOptions,
    output: &mut ExportOutput,
) -> Option<&'a [u8]> {
    if !options.include_body {
        output.body_note = Some("corpo omitido por opção (includeBody=false)".to_string());
        return None;
    }
    match bytes {
        Some(bytes) if bytes.len() > options.max_body_bytes => {
            output.warnings.push(Warning::new(
                "export.body_too_large",
                format!(
                    "corpo de {} bytes excede o limite de {} bytes da exportação",
                    bytes.len(),
                    options.max_body_bytes
                ),
            ));
            output.body_note = Some("corpo não incluído: acima do limite".to_string());
            None
        }
        Some(bytes) => {
            output.body_included = true;
            output.body_note = Some(match request.request_body.state {
                crate::model::BodyState::Truncated => {
                    "corpo truncado na captura; exportado apenas o trecho disponível".to_string()
                }
                crate::model::BodyState::Captured => "corpo capturado exportado como bytes".to_string(),
                _ => format!(
                    "corpo exportado a partir dos bytes fornecidos (estado {:?})",
                    request.request_body.state
                ),
            });
            Some(bytes)
        }
        None => {
            output.body_note = Some(format!(
                "corpo não incluído: estado {:?}{}",
                request.request_body.state,
                request
                    .request_body
                    .note
                    .as_deref()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default()
            ));
            None
        }
    }
}

/// URL do request (original; nunca normalizada para exportar).
pub fn export_url(request: &LogicalRequest) -> Result<&str> {
    if request.url.is_empty() {
        return Err(CoreError::Export {
            message: format!("requisição {} sem URL", request.id),
        });
    }
    if request.url.contains(['\r', '\n', '\0']) {
        return Err(CoreError::Export {
            message: "URL contém CR/LF/NUL; recusando gerar comando".to_string(),
        });
    }
    Ok(&request.url)
}
