//! Exporters. None of them promises to replicate TLS or the browser
//! fingerprint: the target is the request at the HTTP level, with correct
//! escaping of untrusted data.

pub mod curl;
pub mod priming;
pub mod python;
pub mod sanitize;
mod scrub;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{LogicalRequest, Warning};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOptions {
    /// Includes the body when the bytes were provided by the caller.
    pub include_body: bool,
    /// Body byte limit for a command-line export.
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

/// Exportable header: valid name and value without CR/LF/NUL.
pub struct ExportableHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Validates the name against the HTTP token (RFC 9110) and rejects line injection.
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

/// Collects common headers in source order; pseudoheaders are left out and are
/// listed in `skipped_headers` (they cannot be replicated by cURL/Python).
pub fn exportable_headers<'a>(
    request: &'a LogicalRequest,
    output: &mut ExportOutput,
) -> Vec<ExportableHeader<'a>> {
    let mut headers = Vec::new();
    for entry in request.request_headers.iter_all() {
        if entry.is_pseudo() {
            output
                .skipped_headers
                .push(format!("{}: pseudoheader not replicable", entry.name));
            continue;
        }
        if !is_header_token(&entry.name) {
            output
                .skipped_headers
                .push(format!("{}: invalid header name", entry.name));
            output.warnings.push(Warning::new(
                "export.invalid_header_name",
                format!("header discarded due to invalid name: {:?}", entry.name),
            ));
            continue;
        }
        if !is_safe_header_value(&entry.value) {
            output
                .skipped_headers
                .push(format!("{}: value contains CR/LF/NUL", entry.name));
            output.warnings.push(Warning::new(
                "export.header_injection",
                format!(
                    "header {} discarded: value contains CR, LF or NUL and cannot be reproduced safely",
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

/// Removes `Content-Length` when the body will not be sent; keeping the header
/// would produce a request that hangs waiting for bytes.
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
                    .push("content-length: removed because the body was not exported".to_string());
                output.warnings.push(Warning::new(
                    "export.content_length_without_body",
                    "Original Content-Length removed: the body does not accompany the export",
                ));
                false
            } else {
                true
            }
        })
        .collect()
}

/// Request body bytes to export. `request.request_body` follows the
/// last attempt (the same one the exported headers come from); only
/// `captured`/`truncated` have bytes, the rest returns `None` and `resolve_body`
/// explains the state.
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

/// ONLY entry point for text in a comment of the generated code (cURL and
/// Python). The content may come from the capture (field names, URLs, notes), so:
/// CR, LF, VT, FF, NEL, U+2028/U+2029 and any other control character either break
/// the line or disappear, formatting/bidi characters are removed, each resulting
/// line gets the `# ` prefix and the length is limited. Nothing from the content
/// leaves a comment.
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

/// Comment lines "get at runtime (origin: …)" for the request values that
/// have a producer observed in an earlier response. Does not include
/// values (only field and origin) and does not change the generated code.
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
            ConsumedScope::Body => "body",
        };
        let part = if value.parent.is_some() {
            " (excerpt)"
        } else {
            ""
        };
        let ambiguous = if value.status == OriginStatus::Ambiguous {
            ", ambiguous"
        } else {
            ""
        };
        lines.push(format!(
            "get at runtime (origin: {} {:?}{ambiguous}): {scope} {}{part}",
            evidence.request_id, evidence.kind, value.field
        ));
        if lines.len() >= 60 {
            lines.push("… (other origins omitted)".to_string());
            break;
        }
    }
    lines
}

/// Warning when the exported URL (1st attempt) differs from the final URL after a
/// 307/308 redirect, which preserves method and body.
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
            "the exported URL is that of the 1st attempt ({:?}); after a 307/308 redirect the final request went to {:?}",
            first.url, last.url
        )
    })
}

/// Resolves the body to export. Returns `None` when the state does not allow it or
/// the bytes were not loaded, always with a warning.
pub fn resolve_body<'a>(
    request: &LogicalRequest,
    bytes: Option<&'a [u8]>,
    options: &ExportOptions,
    output: &mut ExportOutput,
) -> Option<&'a [u8]> {
    if !options.include_body {
        output.body_note = Some("body omitted by option (includeBody=false)".to_string());
        return None;
    }
    match bytes {
        Some(bytes) if bytes.len() > options.max_body_bytes => {
            output.warnings.push(Warning::new(
                "export.body_too_large",
                format!(
                    "body of {} bytes exceeds the export limit of {} bytes",
                    bytes.len(),
                    options.max_body_bytes
                ),
            ));
            output.body_note = Some("body not included: above the limit".to_string());
            None
        }
        Some(bytes) => {
            output.body_included = true;
            output.body_note = Some(match request.request_body.state {
                crate::model::BodyState::Truncated => {
                    "body truncated in the capture; only the available excerpt exported".to_string()
                }
                crate::model::BodyState::Captured => {
                    "captured body exported as bytes".to_string()
                }
                _ => format!(
                    "body exported from the provided bytes (state {:?})",
                    request.request_body.state
                ),
            });
            if !request.request_body.transformed.is_empty() {
                let list = request.request_body.transformed.join(", ");
                let mut note = format!(
                    "WARNING: body transformed ({list}); the exported bytes are not identical to those on the wire"
                );
                if request
                    .request_body
                    .transformed
                    .iter()
                    .any(|item| item == "lossy-postData")
                {
                    note.push_str("; lossy-postData: the bytes may differ from those sent");
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
                "body not included: state {:?}{}",
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

/// Request URL (original; never normalized for export).
pub fn export_url(request: &LogicalRequest) -> Result<&str> {
    if request.url.is_empty() {
        return Err(CoreError::Export {
            message: format!("request {} has no URL", request.id),
        });
    }
    if request.url.contains(['\r', '\n', '\0']) || request.url.chars().any(char::is_whitespace) {
        return Err(CoreError::Export {
            message: "URL contains space/CR/LF/NUL; refusing to generate command".to_string(),
        });
    }
    Ok(&request.url)
}
