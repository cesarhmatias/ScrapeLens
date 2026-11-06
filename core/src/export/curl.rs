//! cURL exporter with correct shell quoting.
//!
//! The generated command is for bash/zsh (`$'...'` when there are control bytes).
//! URLs, headers and payloads are untrusted data: header names are validated,
//! CR/LF/NUL are refused and quotes are escaped. There is no promise to replicate
//! TLS, JA3/JA4, frame order or HPACK.

use crate::error::Result;
use crate::model::{LogicalRequest, Verification};

use super::{
    drop_content_length_without_body, export_url, exportable_headers, resolve_body, ExportOptions,
    ExportOutput,
};

pub fn to_curl(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
) -> Result<ExportOutput> {
    to_curl_with_origins(request, body, options, None)
}

/// Like [`to_curl`], annotating in a comment the "get at runtime" fields (with
/// their origin) when `origins` is given. The generated code does not change.
pub fn to_curl_with_origins(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
    origins: Option<&crate::flow::ValueOrigins>,
) -> Result<ExportOutput> {
    let url = export_url(request)?.to_string();
    let mut output = ExportOutput::new(String::new());
    let headers = exportable_headers(request, &mut output);
    let mut body = resolve_body(request, body, options, &mut output);
    if body.is_some_and(|bytes| bytes.contains(&0)) {
        // Bash cannot pass NUL in argv; refusing is better than truncating.
        output.body_included = false;
        output.body_note = Some(
            "body contains NUL and cannot be reproduced by a shell argument; omitted"
                .to_string(),
        );
        output.warnings.push(crate::model::Warning::new(
            "export.body_nul",
            "binary body with NUL omitted from cURL; use the Python export or the original attachment",
        ));
        body = None;
    }
    let headers = drop_content_length_without_body(headers, body.is_some(), &mut output);

    let verification = request.request_headers.verification();
    let mut text = String::new();
    text.push_str(&super::comment(&format!(
        "ScrapeLens — cURL export of request {}",
        request.id
    )));
    text.push_str(
        "# This export does NOT reproduce TLS or the browser fingerprint (JA3/JA4, frames, HPACK); only the HTTP request.\n",
    );
    if options.captured_through_proxy {
        text.push_str(
            "# This script does not use the capture proxy; requests may leave from another IP.\n",
        );
    }
    text.push_str(&super::comment(&format!(
        "captured protocol: {} · header verification: {}",
        request.protocol.as_str(),
        verification.as_str()
    )));
    if verification == Verification::Unverified {
        text.push_str(
            "# WARNING: header sequence NOT verified; treat as untrusted.\n",
        );
    }
    if !output.skipped_headers.is_empty() {
        text.push_str(&super::comment(&format!(
            "{} header(s)/field(s) not replicated:",
            output.skipped_headers.len()
        )));
        for skipped in &output.skipped_headers {
            text.push_str(&super::comment(&format!("  - {skipped}")));
        }
    }
    if let Some(note) = &output.body_note {
        text.push_str(&super::comment(&format!("body: {note}")));
    }
    if let Some(origins) = origins {
        for line in super::runtime_origin_notes(origins) {
            text.push_str(&super::comment(&line));
        }
    }
    if let Some(note) = super::redirect_url_note(request) {
        text.push_str(&super::comment(&format!("WARNING: {note}")));
    }
    text.push_str("# Contains credentials/cookies if the session was not sanitized.\n");

    text.push_str("curl \\\n");
    text.push_str(&format!(
        "  --request {} \\\n",
        shell_quote(&request.method)
    ));
    text.push_str(&format!("  --url {} \\\n", shell_quote(&url)));
    for header in &headers {
        text.push_str(&format!(
            "  --header {} \\\n",
            shell_quote(&format!("{}: {}", header.name, header.value))
        ));
    }
    if let Some(body) = body {
        text.push_str(&format!("  --data-binary {} \\\n", shell_quote_bytes(body)));
    }
    // Removes the trailing continuation and adds a line break.
    while text.ends_with(" \\\n") {
        text.truncate(text.len() - 3);
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    output.text = text;
    Ok(output)
}

/// POSIX single quotes; `'` becomes `'\''`. NUL is not accepted in an argument;
/// the caller has already removed it. For control bytes it uses `$'...'`.
pub fn shell_quote(value: &str) -> String {
    if value.chars().any(|ch| ch.is_control() && ch != '\t') || value.contains('\t') {
        return shell_quote_ansi(value.as_bytes());
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Bytes in bash ANSI-C quoting (`$'...'`), safe for NUL and non-UTF-8.
pub fn shell_quote_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "''".to_string();
    }
    let printable = bytes.iter().all(|byte| (0x20..=0x7e).contains(byte));
    if printable {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return format!("'{}'", text.replace('\'', "'\\''"));
        }
    }
    shell_quote_ansi(bytes)
}

fn shell_quote_ansi(bytes: &[u8]) -> String {
    let mut out = String::from("$'");
    for byte in bytes {
        match byte {
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('\'');
    out
}
