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
                output
                    .skipped_headers
                    .push("content-length: removido porque o corpo não foi exportado".to_string());
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

/// Bytes do corpo de requisição a exportar. `request.request_body` acompanha a
/// última tentativa (a mesma de onde vêm os headers exportados); só
/// `captured`/`truncated` têm bytes, o resto devolve `None` e `resolve_body`
/// explica o estado.
pub fn request_body_bytes<'a>(
    bundle: &'a crate::model::SessionBundle,
    request: &LogicalRequest,
) -> Option<&'a [u8]> {
    if !request.request_body.has_bytes() {
        return None;
    }
    request
        .request_body
        .attachment
        .as_deref()
        .and_then(|name| bundle.attachment(name))
}

/// ÚNICA porta de entrada para texto em comentário do código gerado (cURL e
/// Python). O conteúdo pode vir da captura (nomes de campo, URLs, notas), então:
/// CR, LF, VT, FF, NEL, U+2028/U+2029 e qualquer outro controle quebram a linha
/// ou somem, caracteres de formatação/bidi são removidos, cada linha resultante
/// ganha o prefixo `# ` e o comprimento é limitado. Nada do conteúdo sai de um
/// comentário.
pub fn comment(text: &str) -> String {
    const MAX_LINE: usize = 240;
    const MAX_LINES: usize = 8;
    let is_break = |c: char| {
        matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        )
    };
    let is_format = |c: char| matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}');
    let mut out = String::new();
    let mut lines = 0;
    for piece in text.split(is_break) {
        let clean: String = piece
            .chars()
            .map(|c| if c == '\t' { ' ' } else { c })
            .filter(|c| !c.is_control() && !is_format(*c))
            .collect();
        let clean = clean.trim_end();
        if clean.trim().is_empty() {
            continue;
        }
        let shown: String = clean.chars().take(MAX_LINE).collect();
        out.push_str("# ");
        out.push_str(&shown);
        if clean.chars().count() > MAX_LINE {
            out.push('…');
        }
        out.push('\n');
        lines += 1;
        if lines >= MAX_LINES {
            break;
        }
    }
    if out.is_empty() {
        out.push_str("#\n");
    }
    out
}

/// Linhas de comentário "obter em runtime (origem: …)" para os valores da
/// requisição que têm produtor observado em resposta anterior. Não inclui
/// valores (só campo e origem) e não altera o código gerado.
pub fn runtime_origin_notes(origins: &crate::flow::ValueOrigins) -> Vec<String> {
    use crate::flow::{ConsumedScope, OriginStatus, Role, Strength};
    let mut lines = Vec::new();
    for value in &origins.values {
        if !matches!(value.status, OriginStatus::Origin | OriginStatus::Ambiguous) {
            continue;
        }
        let Some(evidence) = value.evidences.iter().find(|e| {
            e.role == Role::Produced && matches!(e.strength, Strength::Strong | Strength::Medium)
        }) else {
            continue;
        };
        let scope = match value.scope {
            ConsumedScope::Query => "query",
            ConsumedScope::Header => "header",
            ConsumedScope::Cookie => "cookie",
            ConsumedScope::Body => "corpo",
        };
        let part = if value.parent.is_some() {
            " (trecho)"
        } else {
            ""
        };
        let ambiguous = if value.status == OriginStatus::Ambiguous {
            ", ambíguo"
        } else {
            ""
        };
        lines.push(format!(
            "obter em runtime (origem: {} {:?}{ambiguous}): {scope} {}{part}",
            evidence.request_id, evidence.kind, value.field
        ));
        if lines.len() >= 60 {
            lines.push("… (demais origens omitidas)".to_string());
            break;
        }
    }
    lines
}

/// Aviso quando a URL exportada (1ª tentativa) difere da URL final após um
/// redirect 307/308, que preserva método e corpo.
pub fn redirect_url_note(request: &LogicalRequest) -> Option<String> {
    let first = request.attempts.first()?;
    let last = request.attempts.last()?;
    let preserved = request
        .attempts
        .iter()
        .rev()
        .skip(1)
        .any(|attempt| matches!(attempt.status, Some(307 | 308)));
    (preserved && first.url != last.url).then(|| {
        format!(
            "a URL exportada é a da 1ª tentativa ({:?}); após redirect 307/308 a requisição final foi para {:?}",
            first.url, last.url
        )
    })
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
                crate::model::BodyState::Captured => {
                    "corpo capturado exportado como bytes".to_string()
                }
                _ => format!(
                    "corpo exportado a partir dos bytes fornecidos (estado {:?})",
                    request.request_body.state
                ),
            });
            if !request.request_body.transformed.is_empty() {
                let list = request.request_body.transformed.join(", ");
                let mut note = format!(
                    "ATENÇÃO: corpo transformado ({list}); os bytes exportados não são idênticos aos do fio"
                );
                if request
                    .request_body
                    .transformed
                    .iter()
                    .any(|item| item == "lossy-postData")
                {
                    note.push_str("; lossy-postData: os bytes podem diferir dos enviados");
                }
                output
                    .warnings
                    .push(Warning::new("export.body_transformed", note.clone()));
                let base = output.body_note.take().unwrap_or_default();
                output.body_note = Some(format!("{base}. {note}"));
            }
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
    if request.url.contains(['\r', '\n', '\0']) || request.url.chars().any(char::is_whitespace) {
        return Err(CoreError::Export {
            message: "URL contém espaço/CR/LF/NUL; recusando gerar comando".to_string(),
        });
    }
    Ok(&request.url)
}
