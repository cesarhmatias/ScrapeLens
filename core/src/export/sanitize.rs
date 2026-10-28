//! Exportação sanitizada de uma sessão.
//!
//! Redige Authorization, Cookie/Set-Cookie, tokens em URL, cabeçalhos e corpos
//! sensíveis, e remove eventos brutos. Anexos que não podem ser sanitizados com
//! segurança (binários, texto não estruturado, JSON inválido, grande demais) são
//! **omitidos com aviso**, nunca copiados silenciosamente.
//!
//! Limite conhecido: tokens embutidos em segmentos de path, HTML/JS livre e
//! campos de texto sem estrutura não são detectados de forma confiável; esses
//! corpos são omitidos por padrão.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::Result;
use crate::model::{
    Body, BodyState, CookieField, HeaderView, Provenance, SessionBundle, SetCookieRecord, Source,
    Verification, Warning,
};
use crate::store;

#[derive(Debug, Clone)]
pub struct SanitizeOptions {
    pub placeholder: String,
    pub redact_fragments: bool,
    /// Omite corpos textuais não estruturados (HTML, JS, text/plain livre).
    pub omit_unstructured_bodies: bool,
    /// Mantém `cdp-events.jsonl`/`netlog.json`. Padrão: não.
    pub keep_raw_events: bool,
    pub max_body_bytes: usize,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        Self {
            placeholder: "[REDACTED]".to_string(),
            redact_fragments: true,
            omit_unstructured_bodies: true,
            keep_raw_events: false,
            max_body_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SanitizedExport {
    pub bundle: SessionBundle,
    pub warnings: Vec<Warning>,
    pub redactions: BTreeMap<String, usize>,
    pub omitted_attachments: Vec<String>,
}

impl SanitizedExport {
    /// Grava com permissões restritas (0700/0600) e sem os eventos brutos.
    ///
    /// Recusa sobrescrever uma sessão existente: reutilizar o diretório poderia
    /// deixar anexos/eventos brutos antigos ao lado da versão sanitizada.
    pub fn write_to(&self, dir: &std::path::Path) -> Result<()> {
        if dir.join(store::SESSION_FILE).exists() {
            return Err(crate::error::CoreError::Export {
                message: format!(
                    "destino já contém uma sessão ({}); use um diretório novo para a versão sanitizada",
                    dir.display()
                ),
            });
        }
        let attachments_dir = dir.join(store::ATTACHMENTS_DIR);
        if attachments_dir.exists() {
            let has_entries = std::fs::read_dir(&attachments_dir)
                .map_err(|error| crate::error::CoreError::io(&attachments_dir, error))?
                .next()
                .is_some();
            if has_entries {
                return Err(crate::error::CoreError::Export {
                    message: format!(
                        "destino já contém anexos ({}); use um diretório novo",
                        attachments_dir.display()
                    ),
                });
            }
        }
        for name in [store::CDP_EVENTS_FILE, store::NETLOG_FILE] {
            let path = dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|error| crate::error::CoreError::io(&path, error))?;
            }
        }
        store::write_session_dir(&self.bundle, dir)
    }
}

pub fn sanitize_bundle(bundle: &SessionBundle, options: &SanitizeOptions) -> SanitizedExport {
    let mut session = bundle.session.clone();
    let mut warnings = Vec::new();
    let mut redactions: BTreeMap<String, usize> = BTreeMap::new();
    let mut omitted_attachments = Vec::new();
    let mut generated: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut cache: BTreeMap<String, Option<String>> = BTreeMap::new();
    let counter = |key: &str, redactions: &mut BTreeMap<String, usize>| {
        *redactions.entry(key.to_string()).or_default() += 1;
    };

    for request in &mut session.requests {
        request.url = sanitize_url(&request.url, options);
        for redirect in &mut request.redirects {
            redirect.from_url = sanitize_url(&redirect.from_url, options);
            if let Some(to_url) = &redirect.to_url {
                redirect.to_url = Some(sanitize_url(to_url, options));
            }
            if let Some(location) = &redirect.location {
                redirect.location = Some(sanitize_url_reference(location, options));
            }
        }
        sanitize_header_view(&mut request.request_headers, options, &mut redactions);
        sanitize_header_view(&mut request.response_headers, options, &mut redactions);
        sanitize_cookie_field(&mut request.cookie, options, &mut redactions);
        for record in &mut request.set_cookies {
            sanitize_set_cookie(record, options, &mut redactions);
        }
        request.request_body = sanitize_body(
            &request.request_body,
            bundle,
            options,
            &mut cache,
            &mut generated,
            &mut warnings,
            &mut omitted_attachments,
            &mut redactions,
        );
        request.response_body = sanitize_body(
            &request.response_body,
            bundle,
            options,
            &mut cache,
            &mut generated,
            &mut warnings,
            &mut omitted_attachments,
            &mut redactions,
        );

        for attempt in &mut request.attempts {
            attempt.url = sanitize_url(&attempt.url, options);
            sanitize_header_view(&mut attempt.request_headers, options, &mut redactions);
            sanitize_header_view(&mut attempt.response_headers, options, &mut redactions);
            sanitize_cookie_field(&mut attempt.cookie, options, &mut redactions);
            for record in &mut attempt.set_cookies {
                sanitize_set_cookie(record, options, &mut redactions);
            }
            for evidence in &mut attempt.header_evidence {
                sanitize_header_view(&mut evidence.view, options, &mut redactions);
            }
            attempt.request_body = sanitize_body(
                &attempt.request_body,
                bundle,
                options,
                &mut cache,
                &mut generated,
                &mut warnings,
                &mut omitted_attachments,
                &mut redactions,
            );
            attempt.response_body = sanitize_body(
                &attempt.response_body,
                bundle,
                options,
                &mut cache,
                &mut generated,
                &mut warnings,
                &mut omitted_attachments,
                &mut redactions,
            );
        }
    }

    // Metadados de captura podem conter caminhos/args do usuário.
    if let Some(capture) = &mut session.session.capture {
        capture.browser_binary = None;
        capture.chrome_args = None;
        capture.notes = None;
    }
    let raw_removed = bundle.cdp_events_jsonl.is_some() || bundle.netlog_json.is_some();
    session.session.labels.push("sanitized".to_string());
    session.session.notes.push(
        "sessão sanitizada: headers/cookies/URLs/corpos sensíveis redigidos; eventos brutos removidos. Detecção heurística por nomes de parâmetros/headers, prefixos de autenticação e estrutura do corpo; revise o resultado antes de compartilhar."
            .to_string(),
    );

    // Detalhes de avisos podem repetir linhas cruas de header.
    for warning in &mut session.warnings {
        if warning.detail.take().is_some() {
            counter("warningDetail", &mut redactions);
        }
    }
    if raw_removed {
        if options.keep_raw_events {
            warnings.push(Warning::new(
                "sanitize.raw_events_kept",
                "eventos brutos mantidos por opção; eles podem conter dados sensíveis",
            ));
        } else {
            counter("rawEvents", &mut redactions);
            warnings.push(Warning::new(
                "sanitize.raw_events_removed",
                "cdp-events.jsonl e netlog.json não fazem parte da exportação sanitizada",
            ));
        }
    }

    propagate_sensitive_values(
        bundle,
        &mut session,
        &mut generated,
        options,
        &mut redactions,
        &mut warnings,
    );

    let mut sanitized_bundle = SessionBundle {
        session,
        cdp_events_jsonl: if options.keep_raw_events {
            bundle.cdp_events_jsonl.clone()
        } else {
            None
        },
        netlog_json: if options.keep_raw_events {
            bundle.netlog_json.clone()
        } else {
            None
        },
        attachments: generated,
    };
    for warning in &warnings {
        sanitized_bundle.session.warnings.push(warning.clone());
    }
    sanitized_bundle.session.recompute_completeness();

    SanitizedExport {
        bundle: sanitized_bundle,
        warnings,
        redactions,
        omitted_attachments,
    }
}

fn sanitize_header_view(
    view: &mut HeaderView,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
) {
    for entry in view
        .pseudo_headers
        .iter_mut()
        .chain(view.headers.iter_mut())
    {
        let lower = entry.name.to_ascii_lowercase();
        let by_name_only = !is_listed_sensitive_header(&lower) && is_sensitive_header(&lower);
        if is_sensitive_header(&lower)
            && !(by_name_only && redact_auth_scheme(&entry.value, options).is_some())
        {
            entry.value = options.placeholder.clone();
            entry
                .provenance
                .notes
                .push("valor redigido na exportação sanitizada".to_string());
            *redactions.entry(format!("header:{lower}")).or_default() += 1;
            continue;
        }
        // Heurística por valor: nomes fora da lista também podem carregar
        // `Bearer ...`, `Basic ...` etc. Redige o esquema + credencial.
        if let Some(redacted) = redact_auth_scheme(&entry.value, options) {
            entry.value = redacted;
            entry.provenance.notes.push(
                "valor com esquema de autenticação redigido (heurística por prefixo)".to_string(),
            );
            *redactions
                .entry("header:auth-scheme".to_string())
                .or_default() += 1;
            continue;
        }
        if is_url_header(&lower) {
            let sanitized = sanitize_url_reference(&entry.value, options);
            if sanitized != entry.value {
                entry.value = sanitized;
                *redactions.entry("header:url".to_string()).or_default() += 1;
            }
        }
        if entry.name == ":path" {
            let sanitized = sanitize_path_and_query(&entry.value, options);
            if sanitized != entry.value {
                entry.value = sanitized;
                *redactions
                    .entry("pseudoheader:path".to_string())
                    .or_default() += 1;
            }
        }
    }
    if view.raw_block.is_some() {
        view.raw_block = None;
        view.notes
            .push("rawBlock removido na sanitização (continha headers originais)".to_string());
    }
}

fn sanitize_cookie_field(
    cookie: &mut CookieField,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
) {
    if cookie.is_empty() {
        return;
    }
    let raw_count = cookie.raw.len().max(1);
    cookie.raw = (0..raw_count)
        .map(|_| options.placeholder.clone())
        .collect();
    for pair in &mut cookie.pairs {
        pair.value = options.placeholder.clone();
        pair.raw = format!("{}={}", pair.name, options.placeholder);
        pair.provenance.notes.push("cookie redigido".to_string());
    }
    for line in &mut cookie.wire_lines {
        *line = options.placeholder.clone();
    }
    cookie.unparsed.clear();
    *redactions.entry("cookie".to_string()).or_default() += raw_count;
    cookie
        .notes
        .push("valores de Cookie redigidos; nomes e contagem preservados".to_string());
}

fn sanitize_set_cookie(
    record: &mut SetCookieRecord,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
) {
    record.raw = options.placeholder.clone();
    if let Some(parsed) = &mut record.parsed {
        parsed.value = options.placeholder.clone();
        for (name, value) in &mut parsed.extensions {
            if is_sensitive_key(name) || is_sensitive_header(name) {
                *value = options.placeholder.clone();
            }
        }
    }
    record
        .provenance
        .notes
        .push("Set-Cookie redigido".to_string());
    *redactions.entry("setCookie".to_string()).or_default() += 1;
}

fn sanitize_body(
    body: &Body,
    bundle: &SessionBundle,
    options: &SanitizeOptions,
    cache: &mut BTreeMap<String, Option<String>>,
    generated: &mut BTreeMap<String, Vec<u8>>,
    warnings: &mut Vec<Warning>,
    omitted: &mut Vec<String>,
    redactions: &mut BTreeMap<String, usize>,
) -> Body {
    if !matches!(body.state, BodyState::Captured | BodyState::Truncated) {
        return body.clone();
    }
    let Some(original) = body.attachment.clone() else {
        return Body::discarded("sanitização: corpo capturado sem anexo associado");
    };
    if let Err(_error) = store::validate_attachment_name(&original) {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_invalid",
            format!("anexo com nome inválido omitido: {original:?}"),
        ));
        return Body::discarded("sanitização: nome de anexo inválido");
    }

    if let Some(cached) = cache.get(&original) {
        return match cached {
            Some(name) => {
                let bytes = generated.get(name).map(Vec::len).unwrap_or(0) as u64;
                Body {
                    state: body.state,
                    attachment: Some(name.clone()),
                    bytes: Some(bytes),
                    truncated_at: body.truncated_at,
                    content_type: body.content_type.clone(),
                    content_encoding: body.content_encoding.clone(),
                    note: Some("corpo sanitizado".to_string()),
                    transformed: body.transformed.clone(),
                    provenance: sanitized_provenance(),
                }
            }
            None => Body::discarded("sanitização: anexo omitido por não ser sanitizável"),
        };
    }

    let Some(bytes) = bundle.attachments.get(&original) else {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_missing",
            format!("anexo {original} não estava carregado; omitido da exportação"),
        ));
        return Body::discarded("sanitização: anexo indisponível");
    };
    if bytes.len() > options.max_body_bytes {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_too_large",
            format!(
                "anexo {original} tem {} bytes (limite {}); omitido",
                bytes.len(),
                options.max_body_bytes
            ),
        ));
        return Body::discarded("sanitização: anexo acima do limite");
    }

    let content_type = body.content_type.as_deref();
    match sanitize_bytes(bytes, content_type, options) {
        Ok((sanitized, kind)) => {
            let name = unique_attachment_name(&original, generated);
            generated.insert(name.clone(), sanitized.clone());
            cache.insert(original.clone(), Some(name.clone()));
            *redactions.entry(format!("body:{kind}")).or_default() += 1;
            Body {
                state: body.state,
                attachment: Some(name),
                bytes: Some(sanitized.len() as u64),
                truncated_at: body.truncated_at,
                content_type: body.content_type.clone(),
                content_encoding: body.content_encoding.clone(),
                note: Some(format!("corpo sanitizado ({kind})")),
                transformed: body.transformed.clone(),
                provenance: sanitized_provenance(),
            }
        }
        Err(reason) => {
            cache.insert(original.clone(), None);
            omitted.push(original.clone());
            warnings.push(Warning::new(
                "sanitize.attachment_omitted",
                format!("anexo {original} omitido: {reason}"),
            ));
            Body::discarded(format!("sanitização: {reason}"))
        }
    }
}

fn sanitize_bytes(
    bytes: &[u8],
    content_type: Option<&str>,
    options: &SanitizeOptions,
) -> std::result::Result<(Vec<u8>, &'static str), &'static str> {
    if bytes.is_empty() {
        return Ok((Vec::new(), "empty"));
    }
    let media = content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let looks_json = bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{' || *byte == b'[');
    if media.contains("json") || looks_json {
        let mut value: Value =
            serde_json::from_slice(bytes).map_err(|_| "JSON inválido ou não estruturado")?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        sanitize_json(&mut value, options, &mut counts);
        let serialized = serde_json::to_vec(&value).map_err(|_| "JSON não serializável")?;
        return Ok((serialized, "json"));
    }

    if media == "application/x-www-form-urlencoded"
        || (media.is_empty()
            && bytes.len() < 64 * 1024
            && bytes
                .iter()
                .all(|byte| *byte >= 0x20 || *byte == b'\n' || *byte == b'\r' || *byte == b'\t')
            && bytes.contains(&b'='))
    {
        let text = std::str::from_utf8(bytes).map_err(|_| "form não é UTF-8")?;
        let sanitized = sanitize_form(text, options);
        return Ok((sanitized.into_bytes(), "form"));
    }

    if options.omit_unstructured_bodies {
        Err("tipo de corpo não estruturado (HTML/JS/texto livre/binário) não é sanitizável com segurança")
    } else {
        Err("corpo textual não estruturado; opção de manter não implementada sem redação confiável")
    }
}

fn sanitize_json(
    value: &mut Value,
    options: &SanitizeOptions,
    counts: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if is_sensitive_key(key) {
                    *value = Value::String(options.placeholder.clone());
                    *counts.entry("json-key".to_string()).or_default() += 1;
                } else {
                    if is_url_key(key) {
                        if let Value::String(text) = value {
                            *text = sanitize_url_reference(text, options);
                        }
                    }
                    sanitize_json(value, options, counts);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_json(item, options, counts);
            }
        }
        Value::String(text) => {
            if text.contains("://") {
                let sanitized = sanitize_url_reference(text, options);
                if sanitized != *text {
                    *text = sanitized;
                    *counts.entry("json-url".to_string()).or_default() += 1;
                }
            }
            if let Some(redacted) = redact_auth_scheme(text, options) {
                *text = redacted;
                *counts.entry("json-auth-scheme".to_string()).or_default() += 1;
            }
        }
        _ => {}
    }
}

fn sanitize_form(text: &str, options: &SanitizeOptions) -> String {
    text.split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => {
                let decoded = percent_decode(name);
                if is_sensitive_key(&decoded) {
                    format!("{name}={}", options.placeholder)
                } else {
                    format!("{name}={value}")
                }
            }
            None => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn redact_auth_scheme(value: &str, options: &SanitizeOptions) -> Option<String> {
    for scheme in ["Bearer ", "Basic ", "Digest ", "Token "] {
        if let Some(rest) = value.strip_prefix(scheme) {
            if !rest.is_empty() {
                return Some(format!("{scheme}{}", options.placeholder));
            }
        }
    }
    None
}

/// Sanitiza URL absoluta ou referência relativa (Location/Referer/:path).
pub fn sanitize_url_reference(value: &str, options: &SanitizeOptions) -> String {
    if value.contains("://") {
        sanitize_url(value, options)
    } else {
        sanitize_path_and_query(value, options)
    }
}

pub fn sanitize_url(url: &str, options: &SanitizeOptions) -> String {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((left, right)) => (left, Some(right)),
        None => (url, None),
    };
    let sanitized_base = if let Some((scheme, rest)) = before_fragment.split_once("://") {
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((authority, rest)) => (authority, format!("/{rest}")),
            None => (rest, String::new()),
        };
        let authority = if let Some((_userinfo, host_port)) = authority.rsplit_once('@') {
            format!("{}@{}", url_placeholder(options), host_port)
        } else {
            authority.to_string()
        };
        format!(
            "{scheme}://{authority}{}",
            sanitize_path_and_query(&path_and_query, options)
        )
    } else {
        sanitize_path_and_query(before_fragment, options)
    };

    match fragment {
        Some(fragment) if !fragment.is_empty() => {
            if options.redact_fragments {
                format!("{sanitized_base}#{}", url_placeholder(options))
            } else {
                format!("{sanitized_base}#{}", sanitize_query(fragment, options))
            }
        }
        _ => sanitized_base,
    }
}

pub fn sanitize_path_and_query(value: &str, options: &SanitizeOptions) -> String {
    match value.split_once('?') {
        Some((path, query)) => format!("{path}?{}", sanitize_query(query, options)),
        None => value.to_string(),
    }
}

fn sanitize_query(query: &str, options: &SanitizeOptions) -> String {
    let placeholder = url_placeholder(options);
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _value)) => {
                if is_sensitive_key(&percent_decode(name)) {
                    format!("{name}={placeholder}")
                } else {
                    pair.to_string()
                }
            }
            None => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Placeholder percent-encoded para uso dentro de URL.
fn url_placeholder(options: &SanitizeOptions) -> String {
    options
        .placeholder
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~') {
                ch.to_string()
            } else {
                let mut buffer = [0u8; 4];
                ch.encode_utf8(&mut buffer)
                    .bytes()
                    .map(|byte| format!("%{byte:02X}"))
                    .collect()
            }
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' {
            out.push(b' ');
            index += 1;
            continue;
        }
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unique_attachment_name(original: &str, generated: &BTreeMap<String, Vec<u8>>) -> String {
    let base = format!("sanitized-{original}");
    if !generated.contains_key(&base) {
        return base;
    }
    for suffix in 2..10_000 {
        let candidate = format!("sanitized-{suffix}-{original}");
        if !generated.contains_key(&candidate) {
            return candidate;
        }
    }
    format!("sanitized-{}-{original}", generated.len() + 1)
}

fn sanitized_provenance() -> Provenance {
    Provenance::new(Source::Derived, "sanitize", Verification::Partial)
        .with_note("conteúdo derivado; original não incluído".to_string())
}

fn is_listed_sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "www-authenticate"
            | "proxy-authenticate"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-xsrf-token"
            | "private-token"
            | "x-amz-security-token"
            | "x-goog-api-key"
            | "authentication"
    ) {
        return true;
    }
    name.contains("token")
        || name.contains("secret")
        || name.contains("credential")
        || name.contains("signature")
        || name.contains("api-key")
        || name.contains("apikey")
        || name.ends_with("-password")
        || name == "x-session-id"
}

/// Header sensível: lista conhecida ou nome de credencial (`X-Auth`,
/// `X-Jwt-Thing`, `X-Session-Foo`...). `:authority`/`Author` não contam.
pub fn is_sensitive_header(name: &str) -> bool {
    if is_listed_sensitive_header(name) {
        return true;
    }
    let name = name.to_ascii_lowercase();
    let compact: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    !name.starts_with(':')
        && (has_secret_word(&compact)
            || compact.contains("jwt")
            || compact.contains("session")
            || compact.contains("passwd"))
}

fn is_url_header(name: &str) -> bool {
    matches!(
        name,
        "location" | "referer" | "origin" | "content-location" | "link"
    )
}

fn is_sensitive_key(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    let compact: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    const EXACT: &[&str] = &[
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "authorization",
        "password",
        "passwd",
        "pass",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "key",
        "access_key",
        "secret_key",
        "signature",
        "sig",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "csrf",
        "xsrf",
        "cookie",
        "set-cookie",
        "email",
        "phone",
        "cpf",
        "card",
        "card_number",
        "cvv",
        "ssn",
        "code",
        "state",
    ];
    if EXACT.contains(&name.as_str()) {
        return true;
    }
    compact.contains("token")
        || compact.contains("password")
        || compact.contains("passwd")
        || compact.contains("secret")
        || compact.contains("apikey")
        || compact.contains("signature")
        || compact.contains("credential")
        || compact.contains("accesskey")
        || compact.contains("csrf")
        || compact.contains("xsrf")
        || compact.ends_with("sessionid")
        || compact == "sid"
        || compact == "jsessionid"
        || compact == "phpsessid"
        || compact == "authorization"
        || compact.contains("email")
        || compact == "phone"
        || compact == "cpf"
        || compact == "cvv"
        || compact == "cardnumber"
        || compact.ends_with("apikey")
        || compact.ends_with("accesskey")
        || compact.ends_with("secretkey")
}

fn is_url_key(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "url" | "href" | "redirect" | "redirect_url" | "location" | "referer" | "callback"
    )
}

// ---------------------------------------------------------------------------
// Propagação por valor
// ---------------------------------------------------------------------------

/// Tamanho mínimo (bytes) de um valor sensível para ser propagado.
const PROPAGATION_MIN_LEN: usize = 8;
/// Valores só de dígitos (CPF, telefone) propagam a partir deste tamanho.
const PROPAGATION_MIN_DIGITS: usize = 10;

struct SensitiveValue {
    origin: &'static str,
    value: String,
}

/// Uma forma de escrita do valor. `pct` casa os dígitos hex de `%XX` sem
/// diferenciar maiúsculas e minúsculas e usa o placeholder percent-encoded.
struct Variant {
    text: String,
    pct: bool,
}

struct Needle {
    origin: &'static str,
    variants: Vec<Variant>,
}

/// Chaves de alta confiança: só elas (e headers de autenticação e cookies)
/// geram propagação. Chaves genéricas (`key`, `code`, `state`...) são
/// redigidas no lugar, sem propagar.
fn is_propagating_key(name: &str) -> bool {
    if !is_sensitive_key(name) {
        return false;
    }
    let compact: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    compact == "sid"
        || has_secret_word(&compact)
        || compact.contains("jwt")
        || compact.contains("cpf")
        || compact.contains("session")
}

/// Palavras de credencial em um nome compactado (sem separadores).
fn has_secret_word(compact: &str) -> bool {
    let without_author = compact.replace("authority", "").replace("author", "");
    [
        "token",
        "password",
        "passwd",
        "secret",
        "apikey",
        "credential",
        "signature",
    ]
    .iter()
    .any(|word| compact.contains(word))
        || without_author.contains("auth")
}

fn is_trivial_value(value: &str, options: &SanitizeOptions) -> bool {
    if value.len() < PROPAGATION_MIN_LEN {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "true" | "false" | "null" | "undefined") {
        return true;
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) && value.len() < PROPAGATION_MIN_DIGITS {
        return true;
    }
    let first = value.as_bytes()[0];
    if value.bytes().all(|byte| byte == first) {
        return true;
    }
    options.placeholder.contains(value) || value.contains(&options.placeholder)
}

/// Percent-encoding em maiúsculas; `plus` escreve espaço como `+`.
fn percent_encode_with(value: &str, keep: &str, plus: bool) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || keep.as_bytes().contains(&byte) {
            out.push(byte as char);
        } else if plus && byte == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn variants_of(value: &str) -> Vec<Variant> {
    let mut variants = vec![Variant {
        text: value.to_string(),
        pct: false,
    }];
    let json = serde_json::to_string(value).unwrap_or_default();
    let json = json.trim_matches('"').to_string();
    let mut candidates = vec![(json, false)];
    for keep in ["-._~", "-._~!'()*"] {
        candidates.push((percent_encode_with(value, keep, false), true));
        if value.contains(' ') {
            candidates.push((percent_encode_with(value, keep, true), true));
        }
    }
    for (candidate, pct) in candidates {
        if !candidate.is_empty() && !variants.iter().any(|known| known.text == candidate) {
            variants.push(Variant {
                text: candidate,
                pct,
            });
        }
    }
    variants
}

fn collect_query(query: &str, out: &mut Vec<SensitiveValue>) {
    for pair in query.split('#').next().unwrap_or("").split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            if is_propagating_key(&percent_decode(name)) {
                out.push(SensitiveValue {
                    origin: "urlQuery",
                    value: percent_decode(value),
                });
            }
        }
    }
}

fn collect_url(url: &str, out: &mut Vec<SensitiveValue>) {
    if let Some((_, query)) = url.split_once('?') {
        collect_query(query, out);
    }
}

fn collect_json(value: &Value, out: &mut Vec<SensitiveValue>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                match value {
                    Value::String(text) if is_propagating_key(key) => out.push(SensitiveValue {
                        origin: "bodyJson",
                        value: text.clone(),
                    }),
                    Value::String(_) => {}
                    other => collect_json(other, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_json(item, out)),
        _ => {}
    }
}

fn collect_body_bytes(bytes: &[u8], content_type: Option<&str>, out: &mut Vec<SensitiveValue>) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let media = content_type.unwrap_or("").to_ascii_lowercase();
    let looks_json = matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['));
    if media.contains("json") || looks_json {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            collect_json(&value, out);
        }
        return;
    }
    if media.contains("x-www-form-urlencoded") || (media.is_empty() && text.contains('=')) {
        for pair in text.split('&') {
            if let Some((name, value)) = pair.split_once('=') {
                if is_propagating_key(&percent_decode(name)) {
                    out.push(SensitiveValue {
                        origin: "bodyForm",
                        value: percent_decode(value),
                    });
                }
            }
        }
    }
}

fn collect_sensitive_values(bundle: &SessionBundle) -> Vec<SensitiveValue> {
    let mut out = Vec::new();
    let collect_headers = |view: &HeaderView, out: &mut Vec<SensitiveValue>| {
        for entry in view.pseudo_headers.iter().chain(view.headers.iter()) {
            let lower = entry.name.to_ascii_lowercase();
            if matches!(lower.as_str(), "cookie" | "set-cookie") {
                continue; // cobertos pelos pares/registros de cookie
            }
            if is_sensitive_header(&lower) {
                let value = ["Bearer ", "Basic ", "Digest ", "Token "]
                    .iter()
                    .find_map(|scheme| entry.value.strip_prefix(scheme))
                    .unwrap_or(&entry.value);
                out.push(SensitiveValue {
                    origin: "header",
                    value: value.to_string(),
                });
            } else if is_url_header(&lower) || entry.name == ":path" {
                collect_url(&entry.value, out);
            }
        }
    };
    let collect_cookies =
        |cookie: &CookieField, set: &[SetCookieRecord], out: &mut Vec<SensitiveValue>| {
            for pair in &cookie.pairs {
                out.push(SensitiveValue {
                    origin: "cookie",
                    value: pair.value.trim_matches('"').to_string(),
                });
            }
            for record in set {
                if let Some(parsed) = &record.parsed {
                    out.push(SensitiveValue {
                        origin: "setCookie",
                        value: parsed.value.trim_matches('"').to_string(),
                    });
                }
            }
        };
    let bodies = |body: &Body, out: &mut Vec<SensitiveValue>| {
        if let Some(bytes) = body
            .attachment
            .as_deref()
            .and_then(|name| bundle.attachments.get(name))
        {
            collect_body_bytes(bytes, body.content_type.as_deref(), out);
        }
    };
    for request in &bundle.session.requests {
        collect_url(&request.url, &mut out);
        for redirect in &request.redirects {
            collect_url(&redirect.from_url, &mut out);
            if let Some(to) = &redirect.to_url {
                collect_url(to, &mut out);
            }
        }
        collect_headers(&request.request_headers, &mut out);
        collect_headers(&request.response_headers, &mut out);
        collect_cookies(&request.cookie, &request.set_cookies, &mut out);
        bodies(&request.request_body, &mut out);
        bodies(&request.response_body, &mut out);
        for attempt in &request.attempts {
            collect_url(&attempt.url, &mut out);
            collect_headers(&attempt.request_headers, &mut out);
            collect_headers(&attempt.response_headers, &mut out);
            collect_cookies(&attempt.cookie, &attempt.set_cookies, &mut out);
            bodies(&attempt.request_body, &mut out);
            bodies(&attempt.response_body, &mut out);
        }
    }
    out
}

fn matches_at(hay: &[u8], needle: &[u8], pct: bool) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    if !pct {
        return hay == needle;
    }
    let mut index = 0;
    while index < needle.len() {
        if needle[index] == b'%' && index + 3 <= needle.len() {
            if hay[index..index + 3].eq_ignore_ascii_case(&needle[index..index + 3]) {
                index += 3;
                continue;
            }
            return false;
        }
        if hay[index] != needle[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Substitui todas as ocorrências de `variant`; devolve (texto, quantidade).
fn replace_variant(hay: &str, variant: &Variant, mark: &str) -> (String, usize) {
    let (hay_bytes, needle) = (hay.as_bytes(), variant.text.as_bytes());
    let mut out = String::with_capacity(hay.len());
    let (mut index, mut copied, mut count) = (0, 0, 0);
    while index + needle.len() <= hay_bytes.len() {
        if hay_bytes[index] == needle[0]
            && matches_at(&hay_bytes[index..index + needle.len()], needle, variant.pct)
        {
            out.push_str(&hay[copied..index]);
            out.push_str(mark);
            index += needle.len();
            copied = index;
            count += 1;
        } else {
            index += 1;
        }
    }
    out.push_str(&hay[copied..]);
    (out, count)
}

struct Propagator<'a> {
    needles: Vec<Needle>,
    options: &'a SanitizeOptions,
    url_mark: String,
    counts: BTreeMap<&'static str, usize>,
}

impl Propagator<'_> {
    /// Redige in-place; só chamado em campos de valor.
    fn apply(&mut self, text: &mut String) {
        let mut current: Option<String> = None;
        for needle in &self.needles {
            for variant in &needle.variants {
                let hay = current.as_deref().unwrap_or(text);
                if !hay.contains(&variant.text) && !variant.pct {
                    continue;
                }
                let mark = if variant.pct {
                    &self.url_mark
                } else {
                    &self.options.placeholder
                };
                let (replaced, found) = replace_variant(hay, variant, mark);
                if found > 0 {
                    *self.counts.entry(needle.origin).or_default() += found;
                    current = Some(replaced);
                }
            }
        }
        if let Some(replaced) = current {
            *text = replaced;
        }
    }

    fn view(&mut self, view: &mut HeaderView) {
        for entry in view
            .pseudo_headers
            .iter_mut()
            .chain(view.headers.iter_mut())
        {
            self.apply(&mut entry.value);
        }
    }

    fn cookies(&mut self, cookie: &mut CookieField, set_cookies: &mut [SetCookieRecord]) {
        for raw in &mut cookie.raw {
            self.apply(raw);
        }
        for pair in &mut cookie.pairs {
            self.apply(&mut pair.value);
            self.apply(&mut pair.raw);
        }
        for line in cookie
            .wire_lines
            .iter_mut()
            .chain(cookie.unparsed.iter_mut())
        {
            self.apply(line);
        }
        for record in set_cookies {
            self.apply(&mut record.raw);
            if let Some(parsed) = &mut record.parsed {
                self.apply(&mut parsed.value);
                for (_, value) in &mut parsed.extensions {
                    self.apply(value);
                }
            }
        }
    }

    fn body(&mut self, body: &mut Body) {
        if let Some(note) = &mut body.note {
            self.apply(note);
        }
    }
}

/// Redige, nos campos de valor da sessão sanitizada (URLs, valores de header,
/// cookies, notas e anexos de texto), cada valor que a política já tratou como
/// sensível com alta confiança, nas formas literal, percent-encoded (hex sem
/// diferenciar caixa, `+` como espaço) e JSON-escaped. Enums, IDs e nomes de
/// anexo nunca são tocados: a passagem percorre o modelo tipado, sem
/// serializar a sessão. Nenhum passo é falível; anexos que não são texto UTF-8
/// não são varridos e isso é declarado.
fn propagate_sensitive_values(
    original: &SessionBundle,
    session: &mut crate::model::SessionV1,
    generated: &mut BTreeMap<String, Vec<u8>>,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
    warnings: &mut Vec<Warning>,
) {
    let mut seen = std::collections::BTreeSet::new();
    let mut values: Vec<SensitiveValue> = collect_sensitive_values(original)
        .into_iter()
        .filter(|item| !is_trivial_value(&item.value, options))
        .filter(|item| seen.insert(item.value.clone()))
        .collect();
    values.sort_by(|a, b| {
        b.value
            .len()
            .cmp(&a.value.len())
            .then(a.value.cmp(&b.value))
    });
    if values.is_empty() {
        return;
    }
    let mut propagator = Propagator {
        needles: values
            .iter()
            .map(|item| Needle {
                origin: item.origin,
                variants: variants_of(&item.value),
            })
            .collect(),
        options,
        url_mark: url_placeholder(options),
        counts: BTreeMap::new(),
    };

    for request in &mut session.requests {
        propagator.apply(&mut request.url);
        for redirect in &mut request.redirects {
            propagator.apply(&mut redirect.from_url);
            if let Some(to) = &mut redirect.to_url {
                propagator.apply(to);
            }
            if let Some(location) = &mut redirect.location {
                propagator.apply(location);
            }
        }
        propagator.view(&mut request.request_headers);
        propagator.view(&mut request.response_headers);
        propagator.cookies(&mut request.cookie, &mut request.set_cookies);
        propagator.body(&mut request.request_body);
        propagator.body(&mut request.response_body);
        for attempt in &mut request.attempts {
            propagator.apply(&mut attempt.url);
            if let Some(failure) = &mut attempt.failure {
                propagator.apply(failure);
            }
            propagator.view(&mut attempt.request_headers);
            propagator.view(&mut attempt.response_headers);
            propagator.cookies(&mut attempt.cookie, &mut attempt.set_cookies);
            for evidence in &mut attempt.header_evidence {
                propagator.view(&mut evidence.view);
            }
            propagator.body(&mut attempt.request_body);
            propagator.body(&mut attempt.response_body);
        }
    }
    for warning in &mut session.warnings {
        propagator.apply(&mut warning.message);
    }

    let mut not_scanned = 0usize;
    let mut changed: Vec<String> = Vec::new();
    for (name, bytes) in generated.iter_mut() {
        let Ok(text) = std::str::from_utf8(bytes) else {
            not_scanned += 1;
            continue;
        };
        let mut text = text.to_string();
        let before = text.clone();
        propagator.apply(&mut text);
        if text != before {
            *bytes = text.into_bytes();
            changed.push(name.clone());
        }
    }
    for request in &mut session.requests {
        let attempts = request
            .attempts
            .iter_mut()
            .flat_map(|a| [&mut a.request_body, &mut a.response_body]);
        for body in [&mut request.request_body, &mut request.response_body]
            .into_iter()
            .chain(attempts)
        {
            if let Some(name) = &body.attachment {
                if changed.contains(name) {
                    body.bytes = generated.get(name).map(|b| b.len() as u64);
                }
            }
        }
    }

    let counts = std::mem::take(&mut propagator.counts);
    let total: usize = counts.values().sum();
    for (origin, count) in counts {
        *redactions
            .entry(format!("propagated:{origin}"))
            .or_default() += count;
    }
    if total > 0 {
        warnings.push(Warning::new(
            "sanitize.value_propagation",
            format!(
                "{total} ocorrência(s) de {} valor(es) sensível(is) já identificado(s) foram redigidas em outros campos (URLs, headers, corpos), em formas literal, percent-encoded e JSON-escaped; valores com menos de {PROPAGATION_MIN_LEN} bytes (ou {PROPAGATION_MIN_DIGITS} dígitos) ou triviais não são propagados e podem permanecer",
                values.len()
            ),
        ));
    }
    if not_scanned > 0 {
        *redactions
            .entry("propagated:notScanned".to_string())
            .or_default() += not_scanned;
        warnings.push(Warning::new(
            "sanitize.value_propagation_not_scanned",
            format!(
                "{not_scanned} anexo(s) binário(s)/não UTF-8 não foram varridos pela propagação por valor"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LogicalRequest, SessionMeta, SessionV1};

    fn provenance() -> Provenance {
        Provenance::new(Source::NetLog, "test", Verification::Verified)
    }

    fn bundle_with_body() -> (SessionBundle, LogicalRequest) {
        let mut session = SessionV1::new(SessionMeta::new(
            "s-1",
            "2026-10-26T20:00:00Z",
            crate::model::BrowserInfo::default(),
        ));
        let mut request = LogicalRequest::new(
            "r1",
            "https://user:pass@demo.invalid/x?token=secret&page=2#access",
            "POST",
        );
        request
            .request_headers
            .add("Authorization", "Bearer abc", &provenance());
        request
            .request_headers
            .add("cookie", "sid=xyz; theme=dark", &provenance());
        request.request_headers.add("x-rep", "a", &provenance());
        request.request_headers.add("x-rep", "b", &provenance());
        request.request_headers.add(
            "referer",
            "https://demo.invalid/back?token=zzz",
            &provenance(),
        );
        request
            .response_headers
            .add("set-cookie", "sid=abc; Path=/; HttpOnly", &provenance());
        request
            .set_cookies
            .push(crate::model::SetCookieRecord::from_raw(
                "sid=abc; Path=/; HttpOnly",
                &provenance(),
            ));
        request.cookie =
            CookieField::from_header_values(&["sid=xyz; theme=dark".to_string()], &provenance());
        request.request_body = Body::captured("r1.request.bin", 32, &provenance())
            .with_content_type("application/json");
        request.response_body = Body::captured("r1.response.bin", 8, &provenance())
            .with_content_type("application/octet-stream");
        session.requests.push(request.clone());
        let mut bundle = SessionBundle::new(session);
        bundle.insert_attachment(
            "r1.request.bin",
            br#"{"access_token":"abc","page":2,"user":{"email":"a@b.test","name":"Ana"}}"#.to_vec(),
        );
        bundle.insert_attachment("r1.response.bin", vec![0, 1, 2, 3]);
        (bundle, request)
    }

    #[test]
    fn redacts_headers_and_url_but_preserves_order_and_duplicates() {
        let (bundle, _) = bundle_with_body();
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let request = &export.bundle.session.requests[0];
        assert_eq!(
            request.request_headers.first_value("authorization"),
            Some("[REDACTED]")
        );
        assert_eq!(
            request.request_headers.first_value("cookie"),
            Some("[REDACTED]")
        );
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
            request
                .request_headers
                .iter_all()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Authorization", "cookie", "x-rep", "x-rep", "referer"]
        );
        assert!(request.url.contains("token=%5BREDACTED%5D"));
        assert!(request.url.contains("page=2"));
        assert!(request.url.contains("https://%5BREDACTED%5D@demo.invalid"));
        assert!(request.url.ends_with("#%5BREDACTED%5D"));
        assert!(request
            .request_headers
            .first_value("referer")
            .unwrap()
            .contains("token=%5BREDACTED%5D"));
        assert_eq!(request.cookie.pairs[0].value, "[REDACTED]");
        assert_eq!(request.cookie.pairs[1].value, "[REDACTED]");
        assert_eq!(request.set_cookies[0].raw, "[REDACTED]");
        assert_eq!(
            request.set_cookies[0].parsed.as_ref().unwrap().value,
            "[REDACTED]"
        );
    }

    #[test]
    fn structured_json_body_is_sanitized_and_written_as_attachment() {
        let (bundle, _) = bundle_with_body();
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let request = &export.bundle.session.requests[0];
        let name = request.request_body.attachment.as_ref().unwrap();
        assert!(name.starts_with("sanitized-"));
        let bytes = export.bundle.attachments.get(name).unwrap();
        let value: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(value["access_token"], "[REDACTED]");
        assert_eq!(value["page"], 2);
        assert_eq!(value["user"]["email"], "[REDACTED]");
        assert_eq!(value["user"]["name"], "Ana");
        assert_eq!(request.request_body.state, BodyState::Captured);
        // Original não é copiado.
        assert!(!export.bundle.attachments.contains_key("r1.request.bin"));
    }

    #[test]
    fn binary_body_is_omitted_with_warning() {
        let (bundle, _) = bundle_with_body();
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let request = &export.bundle.session.requests[0];
        assert_eq!(request.response_body.state, BodyState::Discarded);
        assert!(request.response_body.attachment.is_none());
        assert_eq!(
            export.omitted_attachments,
            vec!["r1.response.bin".to_string()]
        );
        assert!(export
            .warnings
            .iter()
            .any(|warning| warning.code == "sanitize.attachment_omitted"));
    }

    #[test]
    fn raw_events_are_removed_by_default() {
        let (mut bundle, _) = bundle_with_body();
        bundle.cdp_events_jsonl = Some(b"{\"method\":\"X\"}".to_vec());
        bundle.netlog_json = Some(b"{}".to_vec());
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        assert!(export.bundle.cdp_events_jsonl.is_none());
        assert!(export.bundle.netlog_json.is_none());
        assert!(export
            .warnings
            .iter()
            .any(|warning| warning.code == "sanitize.raw_events_removed"));
    }

    #[test]
    fn original_bundle_is_not_mutated() {
        let (bundle, _) = bundle_with_body();
        let before = serde_json::to_value(&bundle.session).unwrap();
        let _ = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let after = serde_json::to_value(&bundle.session).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn form_body_redacts_sensitive_keys_and_keeps_others() {
        let mut body = Body::captured("f.bin", 16, &provenance())
            .with_content_type("application/x-www-form-urlencoded");
        body.state = BodyState::Captured;
        let mut bundle = SessionBundle::new(SessionV1::new(SessionMeta::new(
            "s",
            "2026-10-26T20:00:00Z",
            crate::model::BrowserInfo::default(),
        )));
        bundle.insert_attachment("f.bin", b"user=ana&password=xyz&page=2".to_vec());
        let mut request = LogicalRequest::new("r", "https://a.test/", "POST");
        request.request_body = body;
        bundle.session.requests.push(request);
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let name = export.bundle.session.requests[0]
            .request_body
            .attachment
            .clone()
            .unwrap();
        assert_eq!(
            export.bundle.attachments.get(&name).unwrap(),
            b"user=ana&password=[REDACTED]&page=2"
        );
    }

    #[test]
    fn invalid_attachment_name_is_omitted_not_written() {
        let mut bundle = SessionBundle::new(SessionV1::new(SessionMeta::new(
            "s",
            "2026-10-26T20:00:00Z",
            crate::model::BrowserInfo::default(),
        )));
        let mut request = LogicalRequest::new("r", "https://a.test/", "POST");
        request.request_body =
            Body::captured("../escape.bin", 3, &provenance()).with_content_type("application/json");
        bundle.session.requests.push(request);
        bundle.insert_attachment("../escape.bin", b"{}".to_vec());
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        assert!(export.bundle.attachments.is_empty());
        assert!(export
            .warnings
            .iter()
            .any(|warning| warning.code == "sanitize.attachment_invalid"));
    }

    #[test]
    fn redacts_sid_jsessionid_and_phpsessid_in_url() {
        let (mut bundle, _) = bundle_with_body();
        bundle.session.requests[0].url =
            "https://demo.invalid/x?sid=ZZURLTOKEN-42&jsessionid=ZZJSESSION-1&phpsessid=ZZPHPSESS-2&page=2"
                .to_string();
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let raw = serde_json::to_string(&export.bundle.session).unwrap();
        assert!(!raw.contains("ZZURLTOKEN-42"), "sid não pode vazar");
        assert!(!raw.contains("ZZJSESSION-1"), "jsessionid não pode vazar");
        assert!(!raw.contains("ZZPHPSESS-2"), "phpsessid não pode vazar");
        assert!(raw.contains("page=2"), "parâmetro não sensível preservado");
        assert!(raw.contains("sid=%5BREDACTED%5D"));
        assert!(raw.contains("jsessionid=%5BREDACTED%5D"));
        assert!(raw.contains("phpsessid=%5BREDACTED%5D"));
    }

    #[test]
    fn redacts_bearer_value_in_unlisted_header_by_prefix() {
        let (mut bundle, _) = bundle_with_body();
        let provenance = bundle.session.requests[0].request_headers.headers[0]
            .provenance
            .clone();
        bundle.session.requests[0].request_headers.add(
            "X-Extra-Auth",
            "Bearer ZZAUTH-987654321",
            &provenance,
        );
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        let request = &export.bundle.session.requests[0];
        assert_eq!(
            request.request_headers.first_value("x-extra-auth"),
            Some("Bearer [REDACTED]")
        );
        let raw = serde_json::to_string(&export.bundle.session).unwrap();
        assert!(!raw.contains("ZZAUTH-987654321"), "Bearer não pode vazar");
        assert!(export
            .bundle
            .session
            .session
            .notes
            .iter()
            .any(|note| note.contains("heurística")));
        assert!(export.redactions.contains_key("header:auth-scheme"));
    }

    #[test]
    fn header_and_query_detection() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("X-Goog-Api-Key"));
        assert!(is_sensitive_header("X-Session-Id"));
        assert!(!is_sensitive_header("Content-Type"));
        assert!(is_sensitive_key("access_token"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("sid"));
        assert!(is_sensitive_key("JSESSIONID"));
        assert!(is_sensitive_key("PHPSESSID"));
        assert!(is_sensitive_key("user[email]"));
        assert!(!is_sensitive_key("page"));
        assert!(!is_sensitive_key("monkey"));
    }
}
