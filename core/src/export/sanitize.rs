//! Exportação sanitizada de uma sessão.
//!
//! Redige Authorization, Cookie/Set-Cookie, tokens em URL, cabeçalhos e corpos
//! sensíveis, e remove eventos brutos. Anexos que não podem ser sanitizados com
//! segurança (binários, texto não estruturado, JSON inválido, grande demais) são
//! **omitidos com aviso**, nunca copiados silenciosamente.
//!
//! Campos de negócio (placa, v_placa, plate, renavam, cpf, cnpj, chassi, vin;
//! `SanitizeOptions::business_fields`): em campos nomeados o valor é redigido e
//! propagado; em campos opacos, nome + valor no formato do tipo é redigido (e
//! propagado pela sessão). `redactions["business:<tipo>"]` conta por tipo, sem
//! valores; nome sem valor no formato gera `sanitize.business_field_unmatched`.
//!
//! Limite conhecido: tokens embutidos em segmentos de path, HTML/JS livre e
//! campos de texto sem estrutura não são detectados de forma confiável; esses
//! corpos são omitidos por padrão.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Campos de negócio sensíveis (case-insensitive, também como sufixo do
    /// nome): em campos nomeados o valor é redigido e propagado; em campos
    /// opacos, a ocorrência do nome seguida de valor no formato do tipo.
    pub business_fields: Vec<String>,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        Self {
            placeholder: "[REDACTED]".to_string(),
            redact_fragments: true,
            omit_unstructured_bodies: true,
            keep_raw_events: false,
            max_body_bytes: 8 * 1024 * 1024,
            business_fields: DEFAULT_BUSINESS_FIELDS
                .iter()
                .map(|name| name.to_string())
                .collect(),
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
    BUSINESS.with(|b| *b.borrow_mut() = (options.business_fields.clone(), BTreeMap::new()));
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
        if let Some(target) = &mut request.target {
            if let Some(url) = &target.url {
                target.url = Some(sanitize_url(url, options));
            }
        }
        for note in &mut request.provenance.notes {
            *note = sanitize_text(note, options);
        }
        for link in &mut request.links {
            for line in &mut link.evidence {
                *line = sanitize_text(line, options);
            }
        }
        for candidate in &mut request.match_candidates {
            for reason in &mut candidate.reasons {
                *reason = sanitize_text(reason, options);
            }
        }
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
            if let Some(failure) = &mut attempt.failure {
                *failure = sanitize_text(failure, options);
            }
            for note in &mut attempt.provenance.notes {
                *note = sanitize_text(note, options);
            }
            for candidate in &mut attempt.match_candidates {
                for reason in &mut candidate.reasons {
                    *reason = sanitize_text(reason, options);
                }
            }
            if let Some(initiator) = &mut attempt.initiator {
                if let Some(url) = &initiator.url {
                    initiator.url = Some(sanitize_url(url, options));
                }
                if let Some(frame) = &mut initiator.stack_top {
                    if let Some(url) = &frame.url {
                        frame.url = Some(sanitize_url(url, options));
                    }
                }
            }
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

    // Mensagens de aviso podem trazer URLs com query.
    for warning in &mut session.warnings {
        warning.message = sanitize_text(&warning.message, options);
    }
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

    // contadores por tipo (sem valores) e aviso para nomes sem valor no formato
    let business = BUSINESS.with(|b| std::mem::take(&mut b.borrow_mut().1));
    for (kind, count) in business {
        if kind == "unmatched" {
            warnings.push(Warning::new(
                "sanitize.business_field_unmatched",
                format!("{count} ocorrência(s) de nome de campo de negócio (placa, cpf…) sem valor no formato esperado; não redigidas: revise o resultado"),
            ));
        } else {
            *redactions.entry(format!("business:{kind}")).or_default() += count;
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
        // Qualquer outro valor que carregue uma query (Refresh, X-Original-Url,
        // report-uri...): redige só os parâmetros sensíveis.
        if !is_url_header(&lower) && entry.name != ":path" {
            let sanitized = sanitize_text(&entry.value, options);
            if sanitized != entry.value {
                entry.value = sanitized;
                *redactions
                    .entry("header:text-query".to_string())
                    .or_default() += 1;
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
    if let Some(line) = &view.start_line {
        let sanitized = sanitize_text(line, options);
        if sanitized != *line {
            view.start_line = Some(sanitized);
            *redactions
                .entry("header:startLine".to_string())
                .or_default() += 1;
        }
    }
    for note in &mut view.notes {
        *note = sanitize_text(note, options);
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
    // A mensagem de erro de parse repete o valor cru.
    if record.parse_error.is_some() {
        record.parse_error = Some("Set-Cookie inválido (detalhe redigido)".to_string());
    }
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

/// Número "óbvio" que pode ficar visível sob uma chave sensível: 0 e 1, ou
/// qualquer número cuja chave descreve um tempo/contagem/tipo (`jwtExpiresIn`,
/// `tokenType`...).
fn number_may_stay_visible(key: &str, number: &serde_json::Number) -> bool {
    let compact: String = key
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    const BENIGN: [&str; 14] = [
        "expiresin", "expires", "expiry", "expiration", "ttl", "type", "length", "size", "count",
        "seconds", "enabled", "required", "valid", "version",
    ];
    matches!(number.as_i64(), Some(0 | 1))
        || BENIGN.iter().any(|suffix| compact.ends_with(suffix))
}

/// Sob uma chave de credencial: textos viram placeholder, booleanos e números
/// "óbvios" ficam, objetos e listas são percorridos.
fn redact_credential_value(value: &mut Value, key: &str, options: &SanitizeOptions) {
    match value {
        Value::String(_) => *value = Value::String(options.placeholder.clone()),
        Value::Number(number) => {
            if !number_may_stay_visible(key, number) {
                *value = Value::String(options.placeholder.clone());
            }
        }
        Value::Object(object) => {
            for (inner_key, inner) in object.iter_mut() {
                redact_credential_value(inner, inner_key, options);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_credential_value(item, key, options);
            }
        }
        Value::Bool(_) | Value::Null => {}
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
                    // Só texto e números não óbvios são credencial: `pin: true` e
                    // `jwtExpiresIn: 3600` ficam legíveis; strings aninhadas são redigidas.
                    redact_credential_value(value, key, options);
                    *counts.entry("json-key".to_string()).or_default() += 1;
                } else if is_business_key(key, &business_fields()) {
                    business_count(BusinessKind::of(key).label());
                    *value = Value::String(options.placeholder.clone());
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
            if text.len() >= 12 {
                *text = redact_business_text(text, &options.placeholder);
            }
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
            // `nome=valor` sensível, fragmento, matriz, userinfo e URL aninhada dentro do texto.
            let scrubbed = sanitize_text(text, options);
            if scrubbed != *text {
                *text = scrubbed;
                *counts.entry("json-text".to_string()).or_default() += 1;
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
                let fields = business_fields();
                if is_sensitive_key(&decoded) {
                    format!("{name}={}", options.placeholder)
                } else if is_business_key(&decoded, &fields) {
                    business_count(BusinessKind::of(&decoded).label());
                    format!("{name}={}", options.placeholder)
                } else if let Some(nested) = sanitize_nested_value(value, options, 0) {
                    format!("{name}={nested}")
                } else if value.len() >= 12 {
                    // campo opaco: nome de negócio + valor no formato dentro do valor
                    format!(
                        "{name}={}",
                        redact_business_text(value, &options.placeholder)
                    )
                } else {
                    format!("{name}={value}")
                }
            }
            None => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

const AUTH_SCHEMES: [&str; 11] = [
    "Bearer",
    "Basic",
    "Digest",
    "Token",
    "ApiKey",
    "OAuth",
    "SharedKey",
    "Negotiate",
    "NTLM",
    "AWS4-HMAC-SHA256",
    "Hawk",
];

/// Separa `<esquema><espaço em branco><credencial>` (esquema sem diferenciar
/// caixa; qualquer espaço em branco, inclusive TAB). Fatiamento seguro em UTF-8.
pub fn split_auth_scheme(value: &str) -> Option<(&str, &str)> {
    for scheme in AUTH_SCHEMES {
        let Some(prefix) = value.get(..scheme.len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case(scheme) {
            continue;
        }
        let tail = &value[scheme.len()..];
        if tail.chars().next().is_some_and(char::is_whitespace) {
            let rest = tail.trim_start();
            if !rest.is_empty() {
                return Some((prefix, rest));
            }
        }
    }
    None
}

fn redact_auth_scheme(value: &str, options: &SanitizeOptions) -> Option<String> {
    split_auth_scheme(value).map(|(scheme, _)| format!("{scheme} {}", options.placeholder))
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
    let (before_fragment, fragment) = match value.split_once('#') {
        Some((left, right)) => (left, Some(right)),
        None => (value, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let mut out = sanitize_matrix(path, options);
    if let Some(query) = query {
        out.push('?');
        out.push_str(&sanitize_query(query, options));
    }
    match fragment {
        Some(fragment) if !fragment.is_empty() => {
            out.push('#');
            if options.redact_fragments {
                out.push_str(&url_placeholder(options));
            } else {
                out.push_str(&sanitize_query(fragment, options));
            }
        }
        Some(_) => out.push('#'),
        None => {}
    }
    out
}

/// Parâmetros de matriz de caminho (`/a;jsessionid=X/b`): redige o valor
/// quando o nome é sensível.
fn sanitize_matrix(path: &str, options: &SanitizeOptions) -> String {
    if !path.contains(';') {
        return path.to_string();
    }
    let placeholder = url_placeholder(options);
    let sanitized = path
        .split('/')
        .map(|segment| {
            let mut parts = segment.split(';');
            let head = parts.next().unwrap_or("");
            let mut out = head.to_string();
            for param in parts {
                out.push(';');
                match param.split_once('=') {
                    Some((name, _))
                        if is_sensitive_key(&effective_name(name))
                            || is_business_key(&effective_name(name), &options.business_fields) =>
                    {
                        out.push_str(name);
                        out.push('=');
                        out.push_str(&placeholder);
                    }
                    // Valor com `nome=…` aninhado (`next=/cb%3Ftoken=X`): mesmas regras do texto.
                    Some(_) => out.push_str(&sanitize_text(param, options)),
                    None => out.push_str(param),
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/");
    // Parâmetro de matriz cujo valor contém `/` (`;next=/cb%3Ftoken=X`) atravessa
    // segmentos: o restante passa pelas regras de texto.
    if sanitized.contains('=') {
        sanitize_text(&sanitized, options)
    } else {
        sanitized
    }
}

/// Redige, em texto livre (linha de requisição, notas, mensagens, valores de
/// header que não são URL conhecida, avisos), em qualquer posição:
/// - o valor de `nome=valor` (e `nome%3Dvalor`) quando o nome é sensível, com
///   ou sem `?` antes (query, fragmento `#access_token=`, parâmetro de matriz
///   `;jsessionid=`, `Refresh: token=...`);
/// - o userinfo de URLs absolutas (`https://usuario:senha@host`).
///
/// O valor vai até um terminador (espaço, aspas, `<`, `>`, `(`, `)`, `,`, `;`,
/// `#`, `\\`) ou `&`. O resto do texto passa intacto.
pub fn sanitize_text(text: &str, options: &SanitizeOptions) -> String {
    sanitize_text_depth(&redact_auth_in_text(text, options), options, 0)
}

/// `Bearer <cred>` / `Basic <cred>` em texto livre: qualquer caixa e qualquer
/// espaço em branco (TAB incluído) entre o esquema e a credencial. Só age quando
/// o que segue parece credencial (dígito, símbolo, maiúscula depois da primeira
/// letra ou 16+ caracteres), para não apagar prosa como "Basic authentication".
fn redact_auth_in_text(text: &str, options: &SanitizeOptions) -> String {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("bearer") && !lower.contains("basic") {
        return text.to_string();
    }
    let looks_like_credential = |cred: &str| {
        cred.chars().count() >= 16
            || cred
                .chars()
                .any(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | '~' | '+' | '/' | '=' | '-'))
            || cred.chars().skip(1).any(|c| c.is_ascii_uppercase())
    };
    let is_cred_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '+' | '/' | '=' | '-');
    let mut out = String::with_capacity(text.len());
    let mut copied = 0; // bytes de `text` já copiados
    let mut from = 0;
    // Próxima ocorrência de cada esquema; só é recalculada quando ficou para trás
    // (uma busca por rodada daria tempo quadrático em "bearer bearer bearer...").
    let schemes = ["bearer", "basic"];
    let mut found: [Option<usize>; 2] = [None, None];
    let mut searched_from = [usize::MAX; 2];
    loop {
        for (i, scheme) in schemes.iter().enumerate() {
            let stale = found[i].is_some_and(|at| at < from);
            if searched_from[i] == usize::MAX || stale {
                found[i] = lower[from..].find(scheme).map(|at| from + at);
                searched_from[i] = from;
            }
        }
        let next = found
            .iter()
            .enumerate()
            .filter_map(|(i, at)| at.map(|at| (at, schemes[i].len())))
            .min();
        let Some((at, len)) = next else { break };
        from = at + len;
        let before_ok = text[..at]
            .chars()
            .next_back()
            .map_or(true, |c| !(c.is_ascii_alphanumeric() || c == '_'));
        if !before_ok {
            continue;
        }
        let after = &text[at + len..];
        let spaces = after.len() - after.trim_start().len();
        if spaces == 0 || !after[..spaces].chars().all(char::is_whitespace) {
            continue;
        }
        let cred_len = after[spaces..]
            .find(|c: char| !is_cred_char(c))
            .unwrap_or(after.len() - spaces);
        let cred = &after[spaces..spaces + cred_len];
        if cred.chars().count() < 4 || !looks_like_credential(cred) {
            continue;
        }
        out.push_str(&text[copied..at + len]);
        out.push(' ');
        out.push_str(&options.placeholder);
        copied = at + len + spaces + cred_len;
        from = copied;
    }
    out.push_str(&text[copied..]);
    out
}

/// Profundidade máxima de URLs aninhadas com percent-encoding
/// (`?next=%2Fcb%3Ftoken%3D...`).
const MAX_NESTED_DEPTH: usize = 4;

/// Redige URL/consulta aninhada em um valor percent-encoded. `None` = nada a
/// mudar. Decodifica, aplica as mesmas regras de [`sanitize_text`] (recursivo,
/// com limite de profundidade) e recodifica só se algo foi redigido.
fn sanitize_nested_value(value: &str, options: &SanitizeOptions, depth: usize) -> Option<String> {
    if depth >= MAX_NESTED_DEPTH {
        return None;
    }
    // Decodifica até estabilizar (codificação dupla/tripla), com limite de rodadas.
    let mut decoded = value.to_string();
    if value.contains(['%', '+']) {
        for _ in 0..MAX_DECODE_ROUNDS {
            let next = percent_decode(&decoded);
            if next == decoded {
                break;
            }
            decoded = next;
        }
    }
    if !decoded.contains(['?', '&', '=', '#', ';', '@']) {
        return None;
    }
    let sanitized = sanitize_text_depth(&decoded, options, depth + 1);
    if sanitized == decoded {
        return None;
    }
    Some(if decoded == value {
        sanitized
    } else {
        percent_encode_with(&sanitized, "-._~", false)
    })
}

/// Rodadas máximas de decodificação ao procurar segredo em valor aninhado.
const MAX_DECODE_ROUNDS: usize = 8;

/// Nome efetivo de um candidato `nome=`: decodifica até estabilizar e fica com o
/// último segmento depois de um separador (`next%3Ftoken` → `token`), para que
/// separadores codificados (`%3F`, `%26`, `%23`, `%3B`, `%2F`) valham como fronteira.
fn effective_name(candidate: &str) -> String {
    let mut decoded = candidate.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        let next = percent_decode(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    let tail = decoded
        .rsplit(['?', '&', '#', ';', '/', ',', '|', '='])
        .next()
        .unwrap_or("");
    tail.trim().to_string()
}

fn sanitize_text_depth(text: &str, options: &SanitizeOptions, depth: usize) -> String {
    if !text.contains('=') && !text.contains('%') && !text.contains('@') {
        return text.to_string();
    }
    let text = redact_userinfo_in_text(text, options);
    let is_end = |ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '<' | '>' | '(' | ')' | ',' | ';' | '#' | '\\'
            )
    };
    let is_boundary = |ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '?' | '&' | ';' | ',' | '#' | '/' | '"' | '\'' | '(' | '<' | '[' | '{' | '|' | '='
            )
    };
    let is_name =
        |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '%' | '+');
    let placeholder = url_placeholder(options);
    let mut out = String::with_capacity(text.len());
    let mut at_boundary = true;
    let mut rest = text.as_str();
    while let Some(ch) = rest.chars().next() {
        if at_boundary && is_name(ch) {
            // um possível `nome=` / `nome%3D`
            let name_len = rest.find(|c: char| !is_name(c)).unwrap_or(rest.len());
            let (candidate, after) = rest.split_at(name_len);
            // `nome%3Dvalor`: o `%` é caractere de nome, então o candidato inclui o valor.
            let encoded_eq = candidate.to_ascii_uppercase().find("%3D");
            let (name, value_part, eq_text) = if let Some(i) = encoded_eq {
                (&candidate[..i], &rest[i + 3..], "%3D")
            } else if let Some(value_part) = after.strip_prefix('=') {
                (candidate, value_part, "=")
            } else if let Some(value_part) = after
                .trim_start_matches(' ')
                .strip_prefix('=')
                .filter(|_| {
                    let effective = effective_name(candidate);
                    is_sensitive_key(&effective)
                        || is_business_key(&effective, &options.business_fields)
                })
            {
                // `token =valor` (o `+` de `token+%3Dvalor` decodifica para espaço)
                (candidate, value_part.trim_start_matches(' '), "=")
            } else {
                // Sem `=`: pode ser um pedaço aninhado inteiro codificado
                // (`x%3D1%26token%3DSEC`).
                match sanitize_nested_value(candidate, options, depth) {
                    Some(nested) => out.push_str(&nested),
                    None => out.push_str(candidate),
                }
                rest = after;
                at_boundary = false;
                continue;
            };
            let sensitive = !name.is_empty() && {
                let effective = effective_name(name);
                is_sensitive_key(&effective)
                    || is_business_key(&effective, &options.business_fields)
            };
            if !sensitive {
                if eq_text == "=" {
                    // `nome=valor` comum: o valor pode ser uma URL/consulta aninhada,
                    // codificada ou não. Codificado: analisa o valor inteiro;
                    // senão (ou se nada mudou) a varredura continua DENTRO do valor,
                    // então `?pin=`/`&token=` aninhados são vistos.
                    // O trecho analisado para no próximo `=`: cada byte entra em
                    // uma única análise por nível (tempo linear).
                    let value_len = value_part
                        .find(|c: char| is_end(c) || c == '&' || c == '=')
                        .unwrap_or(value_part.len());
                    let (value, tail) = value_part.split_at(value_len);
                    out.push_str(candidate);
                    out.push('=');
                    if value.contains('%') {
                        if let Some(nested) = sanitize_nested_value(value, options, depth) {
                            out.push_str(&nested);
                            rest = tail;
                            at_boundary = false;
                            continue;
                        }
                    }
                    // A varredura recomeça NO valor como início de palavra: assim
                    // `a=b=token=X` e `next=%2Fcb%3Ftoken=X` (fronteira codificada,
                    // tratada por `effective_name`) são vistos.
                    rest = value_part;
                    at_boundary = true;
                    continue;
                } else {
                    match sanitize_nested_value(candidate, options, depth) {
                        Some(nested) => out.push_str(&nested),
                        None => out.push_str(candidate),
                    }
                    rest = after;
                }
                at_boundary = false;
                continue;
            }
            let value_len = value_part
                .find(|c: char| is_end(c) || c == '&')
                .unwrap_or(value_part.len());
            out.push_str(name);
            out.push_str(eq_text);
            out.push_str(&placeholder);
            rest = &value_part[value_len..];
            at_boundary = false;
            continue;
        }
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
        at_boundary = is_boundary(ch);
    }
    out
}

/// Troca o userinfo de toda URL absoluta no texto (`esquema://user:pass@host`).
fn redact_userinfo_in_text(text: &str, options: &SanitizeOptions) -> String {
    if !text.contains("://") {
        return text.to_string();
    }
    let placeholder = url_placeholder(options);
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let authority_len = tail
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>')
            })
            .unwrap_or(tail.len());
        let (authority, after) = tail.split_at(authority_len);
        match authority.rsplit_once('@') {
            Some((_userinfo, host)) => {
                out.push_str(&placeholder);
                out.push('@');
                out.push_str(host);
            }
            None => out.push_str(authority),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn sanitize_query(query: &str, options: &SanitizeOptions) -> String {
    let placeholder = url_placeholder(options);
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => {
                let decoded = percent_decode(name);
                if is_sensitive_key(&decoded) || is_business_key(&decoded, &business_fields()) {
                    format!("{name}={placeholder}")
                } else {
                    match sanitize_nested_value(value, options, 0) {
                        Some(nested) => format!("{name}={nested}"),
                        None => pair.to_string(),
                    }
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
        || name.contains("csrf")
        || name.contains("xsrf")
        || name.contains("appkey")
        || name.contains("app-key")
        || name.contains("subscription-key")
        || name.contains("auth-key")
        || name.contains("passcode")
        || name.contains("senha")
        || name.ends_with("-password")
        || name.ends_with("-pwd")
        || name.ends_with("-otp")
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
        || compact.contains("appkey")
        || compact.contains("subscriptionkey")
        || compact.contains("authkey")
        || compact.contains("passcode")
        || compact.contains("senha")
        || compact.contains("samlresponse")
        || compact.contains("jwt")
        || matches!(
            compact.as_str(),
            "pwd" | "otp" | "pin" | "ticket" | "mfa" | "totp"
        )
        || compact.ends_with("pwd")
        || matches!(compact.as_str(), "totp" | "hotp" | "smsotp" | "emailotp")
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
// Campos de negócio sensíveis (placa, CPF…) — L5 da rodada 6
// ---------------------------------------------------------------------------

/// Lista padrão (configurável em [`SanitizeOptions::business_fields`]).
pub const DEFAULT_BUSINESS_FIELDS: &[&str] = &[
    "placa", "v_placa", "plate", "renavam", "cpf", "cnpj", "chassi", "vin",
];

thread_local! {
    /// Contexto da sanitização em curso: campos de negócio e contadores de
    /// redação por tipo (sem valores). Zerado/drenado em `sanitize_bundle`.
    static BUSINESS: std::cell::RefCell<(Vec<String>, BTreeMap<String, usize>)> =
        const { std::cell::RefCell::new((Vec::new(), BTreeMap::new())) };
}

fn business_fields() -> Vec<String> {
    BUSINESS.with(|b| b.borrow().0.clone())
}

fn business_count(key: &str) {
    BUSINESS.with(|b| *b.borrow_mut().1.entry(key.to_string()).or_default() += 1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusinessKind {
    Placa,
    Cpf,
    Cnpj,
    Renavam,
    Chassi,
    /// Campo configurado sem formato conhecido: só vale em campos nomeados.
    Other,
}

impl BusinessKind {
    fn of(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.contains("placa") || n.contains("plate") {
            BusinessKind::Placa
        } else if n.contains("cnpj") {
            BusinessKind::Cnpj
        } else if n.contains("cpf") {
            BusinessKind::Cpf
        } else if n.contains("renavam") {
            BusinessKind::Renavam
        } else if n.contains("chassi") || n == "vin" || n.ends_with("_vin") {
            BusinessKind::Chassi
        } else {
            BusinessKind::Other
        }
    }

    fn label(self) -> &'static str {
        match self {
            BusinessKind::Placa => "placa",
            BusinessKind::Cpf => "cpf",
            BusinessKind::Cnpj => "cnpj",
            BusinessKind::Renavam => "renavam",
            BusinessKind::Chassi => "chassi",
            BusinessKind::Other => "outro",
        }
    }

    /// Comprimento do valor no formato do tipo no início de `rest`, se casar.
    fn match_len(self, rest: &str) -> Option<usize> {
        let b = rest.as_bytes();
        let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
        match self {
            BusinessKind::Placa => {
                let ok = b.len() >= 7
                    && b[..3].iter().all(u8::is_ascii_alphabetic)
                    && b[3].is_ascii_digit()
                    && b[4].is_ascii_alphanumeric()
                    && b[5].is_ascii_digit()
                    && b[6].is_ascii_digit();
                // formato antigo com hífen: ABC-1234
                let dashed = b.len() >= 8
                    && b[..3].iter().all(u8::is_ascii_alphabetic)
                    && b[3] == b'-'
                    && b[4..8].iter().all(u8::is_ascii_digit);
                if dashed {
                    Some(8)
                } else {
                    ok.then_some(7)
                }
            }
            BusinessKind::Cpf => {
                if shaped(b, b"ddd.ddd.ddd-dd") {
                    Some(14)
                } else {
                    (digits == 11).then_some(11)
                }
            }
            BusinessKind::Cnpj => {
                if shaped(b, b"dd.ddd.ddd/dddd-dd") {
                    Some(18)
                } else {
                    (digits == 14).then_some(14)
                }
            }
            BusinessKind::Renavam => (9..=11).contains(&digits).then_some(digits),
            BusinessKind::Chassi => {
                let ok = b.len() >= 17
                    && b[..17].iter().all(|c| {
                        c.is_ascii_alphanumeric()
                            && !matches!(c.to_ascii_uppercase(), b'I' | b'O' | b'Q')
                    });
                ok.then_some(17)
            }
            BusinessKind::Other => None,
        }
    }
}

/// `b` começa com o molde (`d` = dígito, outros = literal).
fn shaped(b: &[u8], pattern: &[u8]) -> bool {
    b.len() >= pattern.len()
        && pattern.iter().zip(b).all(|(p, c)| {
            if *p == b'd' {
                c.is_ascii_digit()
            } else {
                p == c
            }
        })
}

/// O nome do campo é (ou termina em) um campo de negócio configurado.
fn is_business_key(name: &str, fields: &[String]) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    !lower.is_empty()
        && fields.iter().any(|field| {
            let field = field.to_ascii_lowercase();
            if field.is_empty() {
                return false;
            }
            // nome exato, ou sufixo depois de separador (`v_placa`, `x-cpf`)
            lower == field
                || lower
                    .strip_suffix(field.as_str())
                    .is_some_and(|head| head.ends_with(['_', '-', '.']))
        })
}

/// Ocorrências `nome` + valor no formato do tipo dentro de um texto opaco:
/// (início do valor, tamanho, tipo). Nomes colados a uma palavra (letra ou `_`
/// antes) não são campo. Nome sem valor no formato conta como não casado.
fn scan_business(text: &str, fields: &[String]) -> (Vec<(usize, usize, BusinessKind)>, usize) {
    if text.contains('&') {
        // Entidades no nome (`&#80;laca`): casa no texto decodificado e mapeia
        // os intervalos de volta ao original.
        let (decoded, map) = crate::html::decode_entities(text, 0);
        if decoded != text {
            let (hits, unmatched) = scan_business_plain(&decoded, fields);
            let mapped = hits
                .into_iter()
                .map(|(start, len, kind)| {
                    let (a, z) = (map[start], map[start + len]);
                    (a, z - a, kind)
                })
                .collect();
            return (mapped, unmatched);
        }
    }
    scan_business_plain(text, fields)
}

fn scan_business_plain(
    text: &str,
    fields: &[String],
) -> (Vec<(usize, usize, BusinessKind)>, usize) {
    let lower = text.to_ascii_lowercase();
    let mut names: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    names.dedup();
    let mut hits: Vec<(usize, usize, BusinessKind)> = Vec::new();
    // Intervalos já cobertos, por início. Nomes mais longos são processados
    // antes e os intervalos não se sobrepõem; guardar por início e consultar
    // só as bordas evita varrer todos a cada ocorrência (O(n²) em texto
    // hostil, ex.: `placa1` × 200 mil).
    let mut covered: BTreeMap<usize, usize> = BTreeMap::new();
    let mut unmatched = 0usize;
    for name in &names {
        if name.is_empty() {
            continue;
        }
        let kind = BusinessKind::of(name);
        let mut from = 0;
        while let Some(rel) = lower[from..].find(name.as_str()) {
            let at = from + rel;
            let end = at + name.len();
            from = end;
            if is_covered(&covered, at, end) {
                continue;
            }
            let prev = lower.as_bytes().get(at.wrapping_sub(1)).filter(|_| at > 0);
            // Colado a uma palavra (`consultar_placa`) não é campo; exceção: a
            // variável do Natural (`v_cpf`, `v_renavam`), precedida de `v_`.
            let natural_var = at >= 2
                && &lower.as_bytes()[at - 2..at] == b"v_"
                && (at == 2 || !lower.as_bytes()[at - 3].is_ascii_alphabetic());
            if prev.is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') && !natural_var {
                // Exceto quando o nome está no meio de um token alfanumérico e
                // vem seguido do valor no formato (`…aplacaQWE1234`): é
                // vazamento, então redige e conta em vez de ignorar.
                if let Some(len) = text.get(end..).and_then(|rest| kind.match_len(rest)) {
                    covered.insert(at, end + len);
                    hits.push((end, len, kind));
                }
                continue;
            }
            match text.get(end..).and_then(|rest| kind.match_len(rest)) {
                Some(len) => {
                    covered.insert(at, end + len);
                    hits.push((end, len, kind));
                }
                None => {
                    covered.insert(at, end);
                    unmatched += 1;
                }
            }
        }
    }
    hits.sort_by_key(|(start, len, _)| (*start, *len));
    (hits, unmatched)
}

/// `[at, end)` já está num intervalo coberto? Os intervalos não se sobrepõem;
/// só o anterior ao início (ou um que comece dentro do trecho, possível com
/// nomes de campo configurados que se sobrepõem) pode cruzar.
fn is_covered(covered: &BTreeMap<usize, usize>, at: usize, end: usize) -> bool {
    covered
        .range(..=at)
        .next_back()
        .is_some_and(|(_, e)| at < *e)
        || covered.range(at..end).next().is_some()
}

/// Redige os valores de negócio achados em um texto opaco, contando por tipo.
fn redact_business_text(text: &str, placeholder: &str) -> String {
    let fields = business_fields();
    if fields.is_empty() {
        return text.to_string();
    }
    let (hits, unmatched) = scan_business(text, &fields);
    for _ in 0..unmatched {
        business_count("unmatched");
    }
    if hits.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, len, kind) in hits {
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(placeholder);
        business_count(kind.label());
        cursor = start + len;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Valores de negócio de um texto opaco (para a propagação por valor).
fn find_business_values(text: &str) -> Vec<String> {
    let fields = business_fields();
    if fields.is_empty() {
        return Vec::new();
    }
    scan_business(text, &fields)
        .0
        .into_iter()
        .map(|(start, len, _)| text[start..start + len].to_string())
        .collect()
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
    /// Compara tudo sem diferenciar maiúsculas (formas duplamente codificadas).
    fold: bool,
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

fn is_trivial_value(value: &str, options: &SanitizeOptions, business: bool) -> bool {
    if business
        && value.len() >= 6
        && !options.placeholder.contains(value)
        && !value.contains(&options.placeholder)
    {
        return false; // valor de negócio no formato do tipo
    }
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
        fold: false,
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
    // Percent-encoding duplo (`%252F`): codifica de novo cada forma percent.
    let doubled: Vec<(String, bool)> = candidates
        .iter()
        .filter(|(_, pct)| *pct)
        .map(|(text, _)| (percent_encode_with(text, "-._~", false), true))
        .collect();
    for (candidate, pct) in candidates.into_iter().chain(doubled.clone()) {
        let fold = doubled.iter().any(|(text, _)| *text == candidate);
        if !candidate.is_empty() && !variants.iter().any(|known| known.text == candidate) {
            variants.push(Variant {
                text: candidate,
                pct,
                fold,
            });
        }
    }
    variants
}

fn collect_query(query: &str, out: &mut Vec<SensitiveValue>) {
    for pair in query.split('#').next().unwrap_or("").split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            if is_business_key(&percent_decode(name), &business_fields()) {
                out.push(SensitiveValue {
                    origin: "business",
                    value: percent_decode(value),
                });
            } else if is_propagating_key(&percent_decode(name)) {
                out.push(SensitiveValue {
                    origin: "urlQuery",
                    value: percent_decode(value),
                });
            }
        }
    }
}

fn collect_url(url: &str, out: &mut Vec<SensitiveValue>) {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((left, right)) => (left, Some(right)),
        None => (url, None),
    };
    if let Some((_, query)) = before_fragment.split_once('?') {
        collect_query(query, out);
    }
    // Fragmento com parâmetros (`#access_token=...`).
    if let Some(fragment) = fragment {
        collect_query(fragment, out);
    }
    let path_part = before_fragment.split('?').next().unwrap_or("");
    // Parâmetros de matriz (`;jsessionid=...`) e senha do userinfo.
    let (authority, path) = match path_part.split_once("://") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((authority, path)) => (Some(authority), path),
            None => (Some(rest), ""),
        },
        None => (None, path_part),
    };
    if let Some(authority) = authority {
        if let Some((userinfo, _)) = authority.rsplit_once('@') {
            let password = userinfo.split_once(':').map_or(userinfo, |(_, pass)| pass);
            out.push(SensitiveValue {
                origin: "urlUserinfo",
                value: percent_decode(password),
            });
        }
    }
    for segment in path.split('/') {
        for param in segment.split(';').skip(1) {
            if let Some((name, value)) = param.split_once('=') {
                if is_propagating_key(&percent_decode(name)) {
                    out.push(SensitiveValue {
                        origin: "urlMatrix",
                        value: percent_decode(value),
                    });
                }
            }
        }
    }
}

fn collect_json(value: &Value, out: &mut Vec<SensitiveValue>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                match value {
                    Value::String(text) if is_business_key(key, &business_fields()) => {
                        out.push(SensitiveValue {
                            origin: "business",
                            value: text.clone(),
                        })
                    }
                    Value::String(text) if is_propagating_key(key) => out.push(SensitiveValue {
                        origin: "bodyJson",
                        value: text.clone(),
                    }),
                    Value::String(text) => {
                        for found in find_business_values(text) {
                            out.push(SensitiveValue {
                                origin: "business",
                                value: found,
                            });
                        }
                    }
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
                let decoded = percent_decode(name);
                if is_business_key(&decoded, &business_fields()) {
                    out.push(SensitiveValue {
                        origin: "business",
                        value: percent_decode(value),
                    });
                } else if is_propagating_key(&decoded) {
                    out.push(SensitiveValue {
                        origin: "bodyForm",
                        value: percent_decode(value),
                    });
                } else {
                    for found in find_business_values(&percent_decode(value)) {
                        out.push(SensitiveValue {
                            origin: "business",
                            value: found,
                        });
                    }
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
                let value = split_auth_scheme(&entry.value)
                    .map_or(entry.value.as_str(), |(_, rest)| rest);
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

fn matches_at(hay: &[u8], needle: &[u8], pct: bool, fold: bool) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    if fold {
        return hay.eq_ignore_ascii_case(needle);
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
            && matches_at(
                &hay_bytes[index..index + needle.len()],
                needle,
                variant.pct,
                variant.fold,
            )
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
        if let Some(line) = &mut view.start_line {
            self.apply(line);
        }
        for note in &mut view.notes {
            self.apply(note);
        }
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
        .filter(|item| !is_trivial_value(&item.value, options, item.origin == "business"))
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
        if let Some(target) = &mut request.target {
            if let Some(url) = &mut target.url {
                propagator.apply(url);
            }
        }
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
            if let Some(initiator) = &mut attempt.initiator {
                if let Some(url) = &mut initiator.url {
                    propagator.apply(url);
                }
                if let Some(frame) = &mut initiator.stack_top {
                    if let Some(url) = &mut frame.url {
                        propagator.apply(url);
                    }
                }
            }
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
    let mut changed: BTreeSet<String> = BTreeSet::new();
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
            changed.insert(name.clone());
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
    fn business_scan_stays_linear_on_hostile_repeats() {
        let limit = if cfg!(debug_assertions) { 30.0 } else { 1.0 };
        let fields: Vec<String> = DEFAULT_BUSINESS_FIELDS
            .iter()
            .map(|f| f.to_string())
            .collect();
        BUSINESS.with(|b| *b.borrow_mut() = (fields, BTreeMap::new()));
        for text in [
            "placa1".repeat(200_000),
            "placaABC1D23;".repeat(100_000),
            "\"cpf 123\"".repeat(200_000),
        ] {
            let t = std::time::Instant::now();
            let _ = redact_business_text(&text, "[REDACTED]");
            let elapsed = t.elapsed();
            assert!(
                elapsed.as_secs_f64() < limit,
                "texto de {} bytes levou {elapsed:?}",
                text.len()
            );
        }
        BUSINESS.with(|b| *b.borrow_mut() = (Vec::new(), BTreeMap::new()));
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

    #[test]
    fn round2_nested_url_tab_after_scheme_and_obvious_values() {
        let o = SanitizeOptions::default();
        // R6: URL aninhada com percent-encoding (também em dois níveis).
        let out = sanitize_text("GET /cb?redirect_uri=https%3A%2F%2Fa.test%2Fx%3Ftoken%3DSEGMARC1 HTTP/1.1", &o);
        assert!(!out.contains("SEGMARC1"), "{out}");
        let out = sanitize_url("https://a.test/c?next=%2Fcb%3Fnext%3D%252Fz%253Ftoken%253DSEGMARC2", &o);
        assert!(!out.contains("SEGMARC2"), "{out}");
        // R8: TAB (e qualquer espaço) depois do esquema; UTF-8 sem panic.
        assert_eq!(split_auth_scheme("Bearer\tSEGMARC3").map(|(_, r)| r), Some("SEGMARC3"));
        assert!(redact_auth_scheme("bearer \t SEGMARC3", &o).is_some_and(|v| !v.contains("SEGMARC3")));
        assert!(split_auth_scheme("Béarer xyz").is_none());
        assert!(split_auth_scheme("日本語日本語日本語").is_none());
        // R13: booleano/número óbvio visível; string redigida; objeto-rótulo percorrido.
        let mut v: Value = serde_json::from_str(
            r#"{"pin":true,"ticket":{"id":"SEGMARC4x","open":false},"jwtExpiresIn":3600,"otp":"123456","password":"SEGMARC5","pinCount":3}"#,
        ).unwrap();
        sanitize_json(&mut v, &o, &mut BTreeMap::new());
        let text = v.to_string();
        assert_eq!(v["pin"], Value::Bool(true));
        assert_eq!(v["jwtExpiresIn"], 3600);
        assert_eq!(v["ticket"]["open"], Value::Bool(false));
        for secret in ["SEGMARC4x", "123456", "SEGMARC5"] {
            assert!(!text.contains(secret), "{secret} em {text}");
        }
    }
}
