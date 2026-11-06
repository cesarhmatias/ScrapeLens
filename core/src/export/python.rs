//! Python 3 exporter using only the standard library.
//!
//! Uses `http.client` to preserve order and duplicates of headers (one
//! `putheader` per occurrence). Does not use `requests` (which would collapse
//! headers) and does not disable TLS verification: the reproduction is HTTP, not
//! a fingerprint.

use crate::error::{CoreError, Result};
use crate::model::{LogicalRequest, Verification};

use super::{
    drop_content_length_without_body, export_url, exportable_headers, is_header_token,
    is_safe_header_value, resolve_body, ExportOptions, ExportOutput,
};

pub fn to_python(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
) -> Result<ExportOutput> {
    to_python_with_origins(request, body, options, None)
}

/// Like [`to_python`], annotating in a comment the "get at runtime" fields (with
/// their origin) when `origins` is given. The generated code does not change.
pub fn to_python_with_origins(
    request: &LogicalRequest,
    body: Option<&[u8]>,
    options: &ExportOptions,
    origins: Option<&crate::flow::ValueOrigins>,
) -> Result<ExportOutput> {
    let url = export_url(request)?.to_string();
    let mut output = ExportOutput::new(String::new());
    let headers = exportable_headers(request, &mut output);
    let body = resolve_body(request, body, options, &mut output);
    let headers = drop_content_length_without_body(headers, body.is_some(), &mut output);

    let parsed = ParsedUrl::parse(&url).ok_or_else(|| CoreError::Export {
        message: format!("invalid URL for Python export: {url:?}"),
    })?;

    let host_header = request
        .request_headers
        .first("host")
        .filter(|entry| is_header_token(&entry.name) && is_safe_header_value(&entry.value))
        .map(|entry| entry.value.as_str());
    let authority = request
        .request_headers
        .first_value(":authority")
        .filter(|value| is_safe_header_value(value));
    let mut extra_host: Option<String> = None;
    let skip_host;
    if host_header.is_some() {
        skip_host = true;
    } else if let Some(authority) = authority {
        // h2/h3 have no Host; for HTTP/1.1 it must be synthesized.
        extra_host = Some(authority.to_string());
        skip_host = true;
    } else {
        skip_host = false;
    }

    let target = request
        .request_headers
        .first_value(":path")
        .filter(|path| !path.contains(['\r', '\n', '\0']) && !path.chars().any(char::is_whitespace))
        .map(str::to_string)
        .unwrap_or_else(|| parsed.target());

    let verification = request.request_headers.verification();
    let mut text = String::new();
    text.push_str("# -*- coding: utf-8 -*-\n");
    text.push_str(&super::comment(&format!(
        "ScrapeLens — Python export (http.client) of request {}",
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
    text.push_str(
        "# Preserves header order and duplicates; HTTP/2 pseudoheaders do not exist in HTTP/1.1.\n",
    );
    text.push_str(&super::comment(&format!(
        "captured protocol: {} · header verification: {}",
        request.protocol.as_str(),
        verification.as_str()
    )));
    if verification == Verification::Unverified {
        text.push_str("# WARNING: header sequence NOT verified.\n");
    }
    if !output.skipped_headers.is_empty() {
        for skipped in &output.skipped_headers {
            text.push_str(&super::comment(&format!("not replicated: {skipped}")));
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
    text.push_str("# Contains credentials/cookies if the session was not sanitized.\n\n");
    text.push_str("import http.client\n");
    if parsed.scheme == "https" {
        text.push_str("import ssl\n");
    }
    text.push('\n');
    if parsed.scheme == "https" {
        text.push_str(&format!(
            "conn = http.client.HTTPSConnection({}, {}, timeout=30, context=ssl.create_default_context())\n",
            python_str(&parsed.host),
            parsed.port
        ));
    } else {
        text.push_str(&format!(
            "conn = http.client.HTTPConnection({}, {}, timeout=30)\n",
            python_str(&parsed.host),
            parsed.port
        ));
    }
    text.push_str(&format!(
        "conn.putrequest({}, {}, skip_host={}, skip_accept_encoding=True)\n",
        python_str(&request.method),
        python_str(&target),
        if skip_host { "True" } else { "False" }
    ));

    if let Some(host) = extra_host {
        text.push_str(&format!(
            "conn.putheader({}, {})  # :authority converted to Host (HTTP/1.1)\n",
            python_str("Host"),
            python_str(&host)
        ));
    }
    for header in &headers {
        text.push_str(&format!(
            "conn.putheader({}, {})\n",
            python_str(header.name),
            python_str(header.value)
        ));
    }
    text.push_str("conn.endheaders()\n");
    if let Some(body) = body {
        text.push_str(&format!("conn.send({})\n", python_bytes(body)));
    }
    text.push_str("resp = conn.getresponse()\n");
    text.push_str("print(resp.status, resp.reason)\n");
    text.push_str("print(resp.read().decode(\"utf-8\", \"replace\"))\n");
    text.push_str("conn.close()\n");

    output.text = text;
    Ok(output)
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

impl ParsedUrl {
    fn parse(url: &str) -> Option<Self> {
        let url = url.split('#').next().unwrap_or(url);
        let (scheme, rest) = url.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((authority, rest)) => (authority, format!("/{rest}")),
            None => (rest, "/".to_string()),
        };
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let (host, remainder) = stripped.split_once(']')?;
            let port = remainder
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => {
                    (host.to_string(), port.parse().ok()?)
                }
                _ => (
                    authority.to_string(),
                    if scheme == "https" { 443 } else { 80 },
                ),
            }
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path.to_string(), Some(query.to_string())),
            None => (path_and_query, None),
        };
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };
        Some(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    fn target(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }
}

/// Python string literal with valid escapes; the file is UTF-8.
pub fn python_str(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                if (ch as u32) <= 0xff {
                    out.push_str(&format!("\\x{:02x}", ch as u32));
                } else {
                    out.push_str(&format!("\\u{:04x}", ch as u32));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Python `bytes` literal that is safe for any sequence.
pub fn python_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("b\"");
    for byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}
