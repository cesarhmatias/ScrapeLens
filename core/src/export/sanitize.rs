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
        if is_sensitive_header(&lower) {
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

pub fn is_sensitive_header(name: &str) -> bool {
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
