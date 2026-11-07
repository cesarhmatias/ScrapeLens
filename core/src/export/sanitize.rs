//! Sanitized export of a session.
//!
//! Redacts Authorization, Cookie/Set-Cookie, tokens in URLs, headers and sensitive
//! bodies, and removes raw events. Attachments that cannot be sanitized safely
//! (binaries, unstructured text, invalid JSON, too large) are **omitted with a
//! warning**, never silently copied.
//!
//! Business fields (placa, v_placa, plate, renavam, cpf, cnpj, chassi, vin;
//! `SanitizeOptions::business_fields`): in named fields the value is redacted and
//! propagated; in opaque fields, name + value in the type's format is redacted (and
//! propagated through the session). `redactions["business:<tipo>"]` counts per type, without
//! values; a name without a value in the expected format raises `sanitize.business_field_unmatched`.
//!
//! Known limit: tokens embedded in path segments, free-form HTML/JS and
//! unstructured text fields are not reliably detected; those bodies are omitted
//! by default.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::error::Result;
use crate::model::{
    Body, BodyState, CookieField, HeaderView, Provenance, SessionBundle, SetCookieRecord, Source,
    Verification, Warning,
};
use crate::store;

use super::priming::SENSITIVE_SHORT_WORDS;
use super::secret::{detect_secret, SecretKind};

#[derive(Debug, Clone)]
pub struct SanitizeOptions {
    pub placeholder: String,
    pub redact_fragments: bool,
    /// Omits unstructured text bodies (HTML, JS, free text/plain).
    pub omit_unstructured_bodies: bool,
    /// Keeps `cdp-events.jsonl`/`netlog.json`. Default: no.
    pub keep_raw_events: bool,
    pub max_body_bytes: usize,
    /// Sensitive business fields (case-insensitive, also as a suffix of the
    /// name): in named fields the value is redacted and propagated; in opaque
    /// fields, an occurrence of the name followed by a value in the type's format.
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
    /// Writes with restricted permissions (0700/0600) and without the raw events.
    ///
    /// Refuses to overwrite an existing session: reusing the directory could
    /// leave old attachments/raw events next to the sanitized version.
    pub fn write_to(&self, dir: &std::path::Path) -> Result<()> {
        if dir.join(store::SESSION_FILE).exists() {
            return Err(crate::error::CoreError::Export {
                message: format!(
                    "destination already contains a session ({}); use a new directory for the sanitized version",
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
                        "destination already contains attachments ({}); use a new directory",
                        attachments_dir.display()
                    ),
                });
            }
        }
        // Cleanup relative to the directory descriptor: a name swapped for a
        // symlink between the checks and here cannot delete outside `dir`.
        let private = store::PrivateDir::open(dir)?;
        for name in [store::CDP_EVENTS_FILE, store::NETLOG_FILE] {
            private.remove_all(name)?;
        }
        store::write_session_dir(&self.bundle, dir)
    }
}

/// Sanitizes a COPY of the bundle (the original stays intact). For large sessions
/// use [`sanitize_bundle_owned`], which does not duplicate the session (docs/18 P7).
pub fn sanitize_bundle(bundle: &SessionBundle, options: &SanitizeOptions) -> SanitizedExport {
    sanitize_bundle_owned(bundle.clone(), options)
}

/// Like [`sanitize_bundle`], but CONSUMES the bundle and sanitizes the session in place:
/// without the masked copy (−927 MiB with 20 thousand captured requests, docs/18) and
/// releasing the original attachments when done. The sensitive values to propagate are
/// collected BEFORE any edit, so the result is identical to the by-reference version.
pub fn sanitize_bundle_owned(bundle: SessionBundle, options: &SanitizeOptions) -> SanitizedExport {
    BUSINESS.with(|b| *b.borrow_mut() = (options.business_fields.clone(), BTreeMap::new()));
    let sensitive = collect_sensitive_values(&bundle);
    let SessionBundle {
        mut session,
        cdp_events_jsonl,
        netlog_json,
        attachments,
    } = bundle;
    // A proxied session's remote endpoints are the proxy's; make that explicit first.
    crate::model::apply_proxy_facts(&mut session);
    let mut warnings = Vec::new();
    let mut redactions: BTreeMap<String, usize> = BTreeMap::new();
    let mut omitted_attachments = Vec::new();
    let mut generated: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut cache: BTreeMap<String, Option<String>> = BTreeMap::new();
    let counter = |key: &str, redactions: &mut BTreeMap<String, usize>| {
        *redactions.entry(key.to_string()).or_default() += 1;
    };
    // Wire evidence (HPACK-decoded headers, ClientHello) may contain credentials;
    // it never reaches a sanitized export.
    if !session.h2_wire.is_empty() || !session.tls_hellos.is_empty() {
        counter("wireEvidence", &mut redactions);
    }
    session.h2_wire.clear();
    session.tls_hellos.clear();

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
            &attachments,
            options,
            &mut cache,
            &mut generated,
            &mut warnings,
            &mut omitted_attachments,
            &mut redactions,
        );
        request.response_body = sanitize_body(
            &request.response_body,
            &attachments,
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
                &attachments,
                options,
                &mut cache,
                &mut generated,
                &mut warnings,
                &mut omitted_attachments,
                &mut redactions,
            );
            attempt.response_body = sanitize_body(
                &attempt.response_body,
                &attachments,
                options,
                &mut cache,
                &mut generated,
                &mut warnings,
                &mut omitted_attachments,
                &mut redactions,
            );
        }
    }

    // Capture metadata may contain the user's paths and arguments.
    if let Some(capture) = &mut session.session.capture {
        capture.browser_binary = None;
        capture.chrome_args = None;
        capture.notes = None;
        // The proxy keeps its scheme and whether it was authenticated; its address
        // and route go. `chromeArgs` (which held the address) is already removed.
        if let Some(proxy) = &mut capture.proxy {
            proxy.host = None;
            proxy.port = None;
            proxy.route = None;
        }
    }
    let raw_removed = cdp_events_jsonl.is_some() || netlog_json.is_some();
    session.session.labels.push("sanitized".to_string());
    session.session.notes.push(
        "sanitized session: headers/cookies/URLs/sensitive bodies redacted; raw events removed. Detection is heuristic, based on parameter/header names, authentication prefixes and body structure; review the result before sharing."
            .to_string(),
    );

    // Warning messages may carry URLs with a query.
    for warning in &mut session.warnings {
        warning.message = sanitize_text(&warning.message, options);
    }
    // Warning details may repeat raw header lines.
    for warning in &mut session.warnings {
        if warning.detail.take().is_some() {
            counter("warningDetail", &mut redactions);
        }
    }
    if raw_removed {
        if options.keep_raw_events {
            warnings.push(Warning::new(
                "sanitize.raw_events_kept",
                "raw events kept by option; they may contain sensitive data",
            ));
        } else {
            counter("rawEvents", &mut redactions);
            warnings.push(Warning::new(
                "sanitize.raw_events_removed",
                "cdp-events.jsonl and netlog.json are not part of the sanitized export",
            ));
        }
    }

    propagate_sensitive_values(
        sensitive,
        &mut session,
        &mut generated,
        options,
        &mut redactions,
        &mut warnings,
    );

    // counters per type (without values) and a warning for names without a value in the expected format
    let business = BUSINESS.with(|b| std::mem::take(&mut b.borrow_mut().1));
    for (kind, count) in business {
        if kind == "unmatched" {
            warnings.push(Warning::new(
                "sanitize.business_field_unmatched",
                format!("{count} occurrence(s) of a business field name (placa, cpf…) without a value in the expected format; not redacted: review the result"),
            ));
        } else {
            *redactions.entry(format!("business:{kind}")).or_default() += count;
        }
    }
    let mut sanitized_bundle = SessionBundle {
        session,
        cdp_events_jsonl: if options.keep_raw_events {
            cdp_events_jsonl
        } else {
            None
        },
        netlog_json: if options.keep_raw_events {
            netlog_json
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
                .push("value redacted in the sanitized export".to_string());
            *redactions.entry(format!("header:{lower}")).or_default() += 1;
            continue;
        }
        // Value-based heuristic: names outside the list may also carry
        // `Bearer ...`, `Basic ...` etc. Redacts the scheme + credential.
        if let Some(redacted) = redact_auth_scheme(&entry.value, options) {
            entry.value = redacted;
            entry
                .provenance
                .notes
                .push("value with authentication scheme redacted (prefix heuristic)".to_string());
            *redactions
                .entry("header:auth-scheme".to_string())
                .or_default() += 1;
            continue;
        }
        if let Some(kind) = detected_secret(&entry.value) {
            entry.value = options.placeholder.clone();
            entry.provenance.notes.push(format!(
                "value redacted by the {kind} format in the sanitized export"
            ));
            *redactions
                .entry(format!("secret-format:{kind}"))
                .or_default() += 1;
            continue;
        }
        if is_url_header(&lower) {
            let sanitized = sanitize_url_header_value(&lower, &entry.value, options);
            if sanitized != entry.value {
                entry.value = sanitized;
                *redactions.entry("header:url".to_string()).or_default() += 1;
            }
        }
        // Any other value that carries a query (Refresh, X-Original-Url,
        // report-uri...): redacts only the sensitive parameters.
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
        view.notes.push(
            "rawBlock removed during sanitization (it contained the original headers)".to_string(),
        );
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
        pair.provenance.notes.push("cookie redacted".to_string());
    }
    for line in &mut cookie.wire_lines {
        *line = options.placeholder.clone();
    }
    cookie.unparsed.clear();
    *redactions.entry("cookie".to_string()).or_default() += raw_count;
    cookie
        .notes
        .push("Cookie values redacted; names and count preserved".to_string());
}

fn sanitize_set_cookie(
    record: &mut SetCookieRecord,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
) {
    record.raw = options.placeholder.clone();
    // The parse error message repeats the raw value.
    if record.parse_error.is_some() {
        record.parse_error = Some("invalid Set-Cookie (detail redacted)".to_string());
    }
    if let Some(parsed) = &mut record.parsed {
        parsed.value = options.placeholder.clone();
        for (name, value) in &mut parsed.extensions {
            if is_sensitive_key(name) || is_sensitive_header(name) || detect_secret(value).is_some()
            {
                *value = options.placeholder.clone();
            }
        }
    }
    record
        .provenance
        .notes
        .push("Set-Cookie redacted".to_string());
    *redactions.entry("setCookie".to_string()).or_default() += 1;
}

// Internal signature of a single caller; grouping the accumulators into one struct
// would only add a type without gaining clarity.
#[allow(clippy::too_many_arguments)]
fn sanitize_body(
    body: &Body,
    attachments: &BTreeMap<String, Vec<u8>>,
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
        return Body::discarded("sanitization: captured body without an associated attachment");
    };
    if let Err(_error) = store::validate_attachment_name(&original) {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_invalid",
            format!("attachment with invalid name omitted: {original:?}"),
        ));
        return Body::discarded("sanitization: invalid attachment name");
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
                    note: Some("sanitized body".to_string()),
                    transformed: body.transformed.clone(),
                    provenance: sanitized_provenance(),
                }
            }
            None => {
                Body::discarded("sanitization: attachment omitted because it cannot be sanitized")
            }
        };
    }

    let Some(bytes) = attachments.get(&original) else {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_missing",
            format!("attachment {original} was not loaded; omitted from the export"),
        ));
        return Body::discarded("sanitization: attachment unavailable");
    };
    if bytes.len() > options.max_body_bytes {
        cache.insert(original.clone(), None);
        omitted.push(original.clone());
        warnings.push(Warning::new(
            "sanitize.attachment_too_large",
            format!(
                "attachment {original} has {} bytes (limit {}); omitted",
                bytes.len(),
                options.max_body_bytes
            ),
        ));
        return Body::discarded("sanitization: attachment above the limit");
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
                note: Some(format!("sanitized body ({kind})")),
                transformed: body.transformed.clone(),
                provenance: sanitized_provenance(),
            }
        }
        Err(reason) => {
            cache.insert(original.clone(), None);
            omitted.push(original.clone());
            warnings.push(Warning::new(
                "sanitize.attachment_omitted",
                format!("attachment {original} omitted: {reason}"),
            ));
            Body::discarded(format!("sanitization: {reason}"))
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
            serde_json::from_slice(bytes).map_err(|_| "invalid or unstructured JSON")?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        sanitize_json(&mut value, options, &mut counts);
        let serialized = serde_json::to_vec(&value).map_err(|_| "JSON cannot be serialized")?;
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
        let text = std::str::from_utf8(bytes).map_err(|_| "form is not UTF-8")?;
        let sanitized = sanitize_form(text, options);
        return Ok((sanitized.into_bytes(), "form"));
    }

    if options.omit_unstructured_bodies {
        Err("unstructured body type (HTML/JS/free text/binary) cannot be sanitized safely")
    } else {
        Err("unstructured text body; the keep option is not implemented without reliable redaction")
    }
}

/// An "obvious" number that may stay visible under a sensitive key: 0 and 1, or
/// any number whose key describes a time/count/type (`jwtExpiresIn`,
/// `tokenType`...).
fn number_may_stay_visible(key: &str, number: &serde_json::Number) -> bool {
    let compact: String = key
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    const BENIGN: [&str; 14] = [
        "expiresin",
        "expires",
        "expiry",
        "expiration",
        "ttl",
        "type",
        "length",
        "size",
        "count",
        "seconds",
        "enabled",
        "required",
        "valid",
        "version",
    ];
    matches!(number.as_i64(), Some(0 | 1)) || BENIGN.iter().any(|suffix| compact.ends_with(suffix))
}

/// Under a credential key: texts become the placeholder, booleans and "obvious"
/// numbers stay, objects and lists are traversed.
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
                    // Only text and non-obvious numbers are credentials: `pin: true` and
                    // `jwtExpiresIn: 3600` stay readable; nested strings are redacted.
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
            if let Some(kind) = detected_secret(text) {
                *text = options.placeholder.clone();
                *counts.entry(format!("secret-format:{kind}")).or_default() += 1;
                return;
            }
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
            // Sensitive `name=value`, fragment, matrix, userinfo and nested URL inside the text.
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
                } else if detect_secret(&percent_decode(value)).is_some() {
                    format!("{name}={}", options.placeholder)
                } else if let Some(nested) = sanitize_nested_value(value, options, 0) {
                    format!("{name}={nested}")
                } else if value.len() >= 12 {
                    // opaque field: business name + value in the format inside the value
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

/// Splits `<scheme><whitespace><credential>` (scheme case-insensitive; any
/// whitespace, including TAB). Safe slicing in UTF-8.
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

/// URL header value (`Location`, `Referer`, `Origin`, `Content-Location`, `Link`).
/// Only what LOOKS like a URL reference goes through the URL sanitizer; the rest
/// (free text, junk, quotes) follows the text rules. In both cases the result goes
/// through the text sanitizer (idempotent over an already redacted URL).
/// `Link: <url>; rel=next, <url2>`: each `<url>` is sanitized and the parameters
/// follow the text rules.
fn sanitize_url_header_value(lower_name: &str, value: &str, options: &SanitizeOptions) -> String {
    let one = |text: &str| {
        let url_like = text.starts_with(['/', '?', '#', '.'])
            || split_authority_prefix(text).is_some()
            || text.split_once(':').is_some_and(|(scheme, _)| {
                !scheme.is_empty()
                    && scheme
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic())
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            });
        let first = if url_like {
            sanitize_url_reference(text, options)
        } else {
            text.to_string()
        };
        sanitize_text(&first, options)
    };
    if lower_name == "link" && value.contains('<') {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(open) = rest.find('<') {
            out.push_str(&sanitize_text(&rest[..open], options));
            let after = &rest[open + 1..];
            match after.find('>') {
                Some(close) => {
                    out.push('<');
                    out.push_str(&one(&after[..close]));
                    out.push('>');
                    rest = &after[close + 1..];
                }
                None => {
                    out.push('<');
                    out.push_str(&one(after));
                    rest = "";
                }
            }
        }
        out.push_str(&sanitize_text(rest, options));
        return out;
    }
    one(value)
}

/// Sanitizes an absolute URL or a relative reference (Location/Referer/:path).
pub fn sanitize_url_reference(value: &str, options: &SanitizeOptions) -> String {
    if split_authority_prefix(value).is_some() {
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
    let sanitized_base = if let Some((prefix, rest)) = split_authority_prefix(before_fragment) {
        let authority_len = rest.find(['/', '\\', '?']).unwrap_or(rest.len());
        let (authority, path_and_query) = rest.split_at(authority_len);
        let authority = if let Some((_userinfo, host_port)) = authority.rsplit_once('@') {
            format!("{}@{}", url_placeholder(options), host_port)
        } else {
            authority.to_string()
        };
        format!(
            "{prefix}{authority}{}",
            sanitize_path_and_query(path_and_query, options)
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

/// `scheme://`, `scheme:/\\` (one or more `/` or `\\` after `scheme:`) or `//`
/// (relative to the scheme): returns (prefix up to the end of the slashes, rest).
fn split_authority_prefix(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let is_slash = |b: u8| b == b'/' || b == b'\\';
    let mut i = 0;
    if bytes.first().is_some_and(|b| b.is_ascii_alphabetic()) {
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'+' | b'-' | b'.'))
        {
            i += 1;
        }
        if bytes.get(i) != Some(&b':') || !bytes.get(i + 1).is_some_and(|b| is_slash(*b)) {
            return None;
        }
        i += 1;
    } else if !(bytes.len() >= 2 && is_slash(bytes[0]) && is_slash(bytes[1])) {
        return None;
    }
    while i < bytes.len() && is_slash(bytes[i]) {
        i += 1;
    }
    Some(text.split_at(i))
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

/// URL path (`/a;jsessionid=X/b`, `/s/token=X/y`, `;next=/cb%3Ftoken=X`): goes through
/// the same tokenizer as the text. The value of a SENSITIVE name in a path runs to the
/// end of the path (the query and fragment were already split off) and is redacted
/// whole, `/` included: a credential may contain `/`. It costs the rest of the path
/// after it (`/a;v=2/session=keep/b` → `/a;v=2/session=[REDACTED]`), an accepted
/// limitation (A7-B5). Non-sensitive names change nothing and the rest of the path
/// keeps being examined.
fn sanitize_matrix(path: &str, options: &SanitizeOptions) -> String {
    if !path.contains([';', '%', '=', '\u{FF1D}', '&']) {
        return path.to_string();
    }
    super::scrub::scrub(path, options).unwrap_or_else(|| path.to_string())
}

/// Redacts, in free text (request line, notes, messages, header values that are not
/// a known URL, warnings, JSON strings), at any position:
/// - the value of `name=value` when the name is sensitive, with or without a `?` before
///   (query, fragment `#access_token=`, matrix parameter `;jsessionid=`,
///   `Refresh: token=...`), including inside quotes/parentheses or after a space;
/// - encoded and nested forms (`next=%2Fcb%3Ftoken=...`, `redirect=https%3A…`);
/// - the userinfo of absolute URLs and `Bearer`/`Basic` in any case.
///
/// See `scrub.rs`: one tokenizer per level, which only produces edits to the
/// original text (what is not a secret is not rewritten).
pub fn sanitize_text(text: &str, options: &SanitizeOptions) -> String {
    super::scrub::scrub(text, options).unwrap_or_else(|| text.to_string())
}

/// Parameter value (query, form) with a nested URL/query, encoded or not.
/// `None` = nothing to change.
fn sanitize_nested_value(value: &str, options: &SanitizeOptions, _depth: usize) -> Option<String> {
    super::scrub::scrub(value, options)
}

fn sanitize_query(query: &str, options: &SanitizeOptions) -> String {
    let placeholder = url_placeholder(options);
    let fields = business_fields();
    let mut scrubber = super::scrub::Scrubber::new(options);
    query
        .split('&')
        .map(|pair| {
            if let Some((name, value)) = pair.split_once('=') {
                let decoded = percent_decode(name);
                if is_sensitive_key(&decoded) || is_business_key(&decoded, &fields) {
                    return format!("{name}={placeholder}");
                }
                if detect_secret(&percent_decode(value)).is_some() {
                    return format!("{name}={placeholder}");
                }
            }
            // `a=b=token=X`, `next=%2Fcb%3Ftoken=X`, `x%3Dtoken%3DX`: same rules as the text
            scrubber.run(pair).unwrap_or_else(|| pair.to_string())
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encoded placeholder for use inside a URL.
pub(super) fn url_placeholder(options: &SanitizeOptions) -> String {
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
        .with_note("derived content; original not included".to_string())
}

/// Portuguese credential names. Whole key segment only, shared with priming so
/// the generated scripts and the sanitizer do not diverge.
pub(super) const PT_CREDENTIAL_WORDS: &[&str] = &[
    "chave",
    "chaves",
    "segredo",
    "segredos",
    "sessao",
    "sessoes",
    "autorizacao",
    "autorizacoes",
    "credencial",
    "credenciais",
];

/// Portuguese personal-data names. `nome` counts as a key segment, not as a
/// substring, and not when it qualifies a technical noun (`nome_arquivo`).
pub(super) const PT_PII_WORDS: &[&str] = &[
    "nome",
    "nomes",
    "sobrenome",
    "sobrenomes",
    "matricula",
    "matriculas",
];

/// Portuguese signature names, a credential/PII on its own. Shared with the
/// plan-label exclusion below so `assinaturaPlano` is not a person's signature.
pub(super) const PT_SIGNATURE_WORDS: &[&str] = &["assinatura", "assinaturas"];

/// Qualifiers that turn `assinatura` into a subscription label rather than a
/// signature (`assinaturaPlano`, `assinaturaMensal`). Whole-segment rule, like
/// `nome_arquivo`: the segment is real, but the field is not personal data.
const ASSINATURA_TECHNICAL_WORDS: &[&str] = &[
    "plano",
    "planos",
    "plan",
    "plans",
    "mensal",
    "mensalidade",
    "mensalidades",
    "anual",
    "anualidade",
    "trimestral",
    "semestral",
    "subscription",
    "subscriptions",
    "assinante",
    "assinantes",
    "renovacao",
    "renovacoes",
    "tipo",
    "tipos",
    "status",
    "valor",
    "valores",
    "preco",
    "precos",
    "pagamento",
    "pagamentos",
    "fatura",
    "faturas",
    "cobranca",
    "cobrancas",
    "nivel",
    "niveis",
    "pacote",
    "pacotes",
    "produto",
    "produtos",
    "servico",
    "servicos",
];

/// Segments that make `nome` a file/field/protocol label instead of a person.
const NOME_TECHNICAL_WORDS: &[&str] = &[
    "arquivo",
    "arquivos",
    "file",
    "filename",
    "campo",
    "campos",
    "aba",
    "abas",
    "tela",
    "telas",
    "classe",
    "classes",
    "funcao",
    "funcoes",
    "metodo",
    "metodos",
    "pacote",
    "pacotes",
    "modulo",
    "modulos",
    "tipo",
    "tipos",
    "grupo",
    "grupos",
    "tabela",
    "tabelas",
    "coluna",
    "colunas",
    "script",
    "scripts",
    "teste",
    "testes",
    "pasta",
    "pastas",
    "diretorio",
    "diretorios",
    "caminho",
    "caminhos",
    "url",
    "urls",
    "host",
    "hosts",
    "app",
    "apps",
    "site",
    "sites",
    "produto",
    "produtos",
    "servico",
    "servicos",
    "empresa",
    "empresas",
    "filial",
    "filiais",
    "loja",
    "lojas",
    "marca",
    "marcas",
    "categoria",
    "categorias",
    "evento",
    "eventos",
    "acao",
    "acoes",
    "valor",
    "valores",
];

/// Lowercase and fold the Portuguese accents of a field name, so `sessão` and
/// `sessao` (and `autorização`/`autorizacao`) share one grammar.
pub(super) fn fold_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|ch| match ch {
            'á' | 'à' | 'â' | 'ã' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            other => other,
        })
        .collect()
}

/// Key segments: non-alphanumeric separators and camelCase boundaries (including
/// an acronym followed by a name, `XChaveApi` -> `x`, `chave`, `api`), folded.
fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    let mut chars = name.chars().peekable();
    while let Some(ch) = chars.next() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        let next_lower = chars.peek().is_some_and(|next| next.is_lowercase());
        if ch.is_uppercase() && !current.is_empty() && (prev_lower || next_lower) {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = ch.is_lowercase();
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words.into_iter().map(|word| fold_name(&word)).collect()
}

pub(super) fn compact_name(name: &str) -> String {
    fold_name(name)
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect()
}

/// True when a whole key segment is a Portuguese credential name. `chave` does
/// not match `chaveiro`, and `rg` is checked elsewhere as a whole segment only.
pub(super) fn has_pt_credential_word(name: &str) -> bool {
    pt_credential_in(&name_words(name))
}

/// True when a whole key segment is a Portuguese personal-data name. `nome`
/// inside `nome_arquivo` is a technical label, not a person.
pub(super) fn has_pt_pii_word(name: &str) -> bool {
    pt_pii_in(&name_words(name))
}

fn pt_credential_in(words: &[String]) -> bool {
    words
        .iter()
        .any(|word| PT_CREDENTIAL_WORDS.contains(&word.as_str()))
}

/// Short sensitive words shared with priming (`rg`, `sid`, `tel`...): whole key
/// segment only, so `cargo` and `org` do not match `rg`.
fn short_word_in(words: &[String]) -> bool {
    words
        .iter()
        .any(|word| SENSITIVE_SHORT_WORDS.contains(&word.as_str()))
}

fn pt_pii_in(words: &[String]) -> bool {
    if !words
        .iter()
        .any(|word| PT_PII_WORDS.contains(&word.as_str()))
    {
        return false;
    }
    let person_name = words
        .iter()
        .any(|word| matches!(word.as_str(), "nome" | "nomes"));
    if person_name
        && words
            .iter()
            .any(|word| NOME_TECHNICAL_WORDS.contains(&word.as_str()))
    {
        return false;
    }
    true
}

fn pt_signature_in(words: &[String]) -> bool {
    if !words
        .iter()
        .any(|word| PT_SIGNATURE_WORDS.contains(&word.as_str()))
    {
        return false;
    }
    !words
        .iter()
        .any(|word| ASSINATURA_TECHNICAL_WORDS.contains(&word.as_str()))
}

/// `codigo_acesso` / `codigoDeAcesso`: adjacent segments, so `codigo_acessorio`
/// and a plain product `codigo` stay visible.
fn pt_access_code_in(words: &[String]) -> bool {
    words
        .windows(2)
        .any(|pair| pair[0] == "codigo" && pair[1] == "acesso")
        || words
            .windows(3)
            .any(|triple| triple[0] == "codigo" && triple[1] == "de" && triple[2] == "acesso")
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

/// Sensitive header: a known list entry or a credential name (`X-Auth`,
/// `X-Jwt-Thing`, `X-Session-Foo`...). `:authority`/`Author` do not count.
pub fn is_sensitive_header(name: &str) -> bool {
    if is_listed_sensitive_header(name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    let compact: String = lower
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    let words = name_words(name);
    !lower.starts_with(':')
        && (has_secret_word(&compact)
            || pt_credential_in(&words)
            || pt_pii_in(&words)
            || pt_signature_in(&words)
            || short_word_in(&words)
            || compact.contains("jwt")
            || compact.contains("session")
            || compact.contains("passwd")
            || compact.contains("viewstate")
            || compact.contains("eventvalidation")
            || compact.contains("privatekey")
            || pt_access_code_in(&words))
}

fn is_url_header(name: &str) -> bool {
    matches!(
        name,
        "location" | "referer" | "origin" | "content-location" | "link"
    )
}

fn detected_secret(value: &str) -> Option<&'static str> {
    detect_secret(value).map(SecretKind::label)
}

pub(super) fn is_sensitive_key(name: &str) -> bool {
    let name = name.trim();
    let lower = fold_name(name);
    let compact = compact_name(name);
    let words = name_words(name);
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
        "__viewstate",
        "__eventvalidation",
        "private_key",
    ];
    if EXACT.contains(&lower.as_str()) {
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
        || compact.contains("viewstate")
        || compact.contains("eventvalidation")
        || compact.contains("privatekey")
        || compact.contains("jwt")
        || matches!(
            compact.as_str(),
            "pwd" | "otp" | "pin" | "ticket" | "mfa" | "totp"
        )
        || compact.ends_with("pwd")
        || matches!(compact.as_str(), "totp" | "hotp" | "smsotp" | "emailotp")
        || compact.contains("csrf")
        || compact.contains("xsrf")
        || compact.contains("sessionkey")
        || compact == "nonce"
        || lower.ends_with("_nonce")
        || lower.ends_with("-nonce")
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
        || pt_credential_in(&words)
        || pt_pii_in(&words)
        || pt_signature_in(&words)
        || short_word_in(&words)
        || pt_access_code_in(&words)
}

fn is_url_key(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "url" | "href" | "redirect" | "redirect_url" | "location" | "referer" | "callback"
    )
}

// ---------------------------------------------------------------------------
// Sensitive business fields (placa, CPF…) — L5 of round 6
// ---------------------------------------------------------------------------

/// Default list (configurable in [`SanitizeOptions::business_fields`]).
pub const DEFAULT_BUSINESS_FIELDS: &[&str] = &[
    "placa", "v_placa", "plate", "renavam", "cpf", "cnpj", "chassi", "vin",
];

thread_local! {
    /// Context of the sanitization in progress: business fields and redaction
    /// counters per type (without values). Reset/drained in `sanitize_bundle`.
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
    /// Configured field without a known format: only applies to named fields.
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

    /// Length of the value in the type's format at the start of `rest`, if it matches.
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
                // legacy format with a hyphen: ABC-1234
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

/// `b` starts with the pattern (`d` = digit, others = literal).
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

/// The field name is (or ends with) a configured business field.
pub(super) fn is_business_key(name: &str, fields: &[String]) -> bool {
    let name = name.trim();
    !name.is_empty()
        && fields.iter().any(|field| {
            if field.is_empty() {
                return false;
            }
            // exact name, or a suffix after a separator (`v_placa`, `x-cpf`)
            name.eq_ignore_ascii_case(field)
                || (name.len() > field.len()
                    && name.is_char_boundary(name.len() - field.len())
                    && name[name.len() - field.len()..].eq_ignore_ascii_case(field)
                    && name[..name.len() - field.len()].ends_with(['_', '-', '.']))
        })
}

/// Occurrences of `name` + a value in the type's format inside an opaque text:
/// (start of the value, length, type). Names glued to a word (a letter or `_`
/// before) are not fields. A name without a value in the format counts as unmatched.
fn scan_business(text: &str, fields: &[String]) -> (Vec<(usize, usize, BusinessKind)>, usize) {
    if text.contains('&') {
        // Entities in the name (`&#80;laca`): matches in the decoded text and maps
        // the ranges back to the original.
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
    // Ranges already covered, by start. Longer names are processed first and the
    // ranges do not overlap; storing by start and checking only the edges avoids
    // scanning all of them at each occurrence (O(n²) on hostile text, e.g.
    // `placa1` × 200 thousand).
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
            // Glued to a word (`consultar_placa`) it is not a field; exception: the
            // Natural variable (`v_cpf`, `v_renavam`), preceded by `v_`.
            let natural_var = at >= 2
                && &lower.as_bytes()[at - 2..at] == b"v_"
                && (at == 2 || !lower.as_bytes()[at - 3].is_ascii_alphabetic());
            if prev.is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') && !natural_var {
                // Except when the name is in the middle of an alphanumeric token and is
                // followed by the value in the format (`…aplacaQWE1234`): it is a leak,
                // so it is redacted and counted instead of ignored.
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

/// Is `[at, end)` already inside a covered range? The ranges do not overlap; only
/// the one before the start (or one that starts within the stretch, possible with
/// configured field names that overlap) can cross.
fn is_covered(covered: &BTreeMap<usize, usize>, at: usize, end: usize) -> bool {
    covered
        .range(..=at)
        .next_back()
        .is_some_and(|(_, e)| at < *e)
        || covered.range(at..end).next().is_some()
}

/// Redacts the business values found in an opaque text, counting per type.
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

/// Business values of an opaque text (for value propagation).
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
// Value propagation
// ---------------------------------------------------------------------------

/// Minimum size (bytes) of a sensitive value to be propagated.
const PROPAGATION_MIN_LEN: usize = 8;
/// Digits-only values (CPF, phone) propagate from this size on.
const PROPAGATION_MIN_DIGITS: usize = 10;

struct SensitiveValue {
    origin: &'static str,
    value: String,
}

/// One written form of the value. `pct` matches the hex digits of `%XX` without
/// distinguishing case and uses the percent-encoded placeholder.
struct Variant {
    text: String,
    pct: bool,
    /// Compares everything without distinguishing case (doubly encoded forms).
    fold: bool,
}

struct Needle {
    origin: &'static str,
    variants: Vec<Variant>,
}

/// High-confidence keys: only they (and authentication headers and cookies)
/// generate propagation. Generic keys (`key`, `code`, `state`...) are redacted in
/// place, without propagating.
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
        || compact.contains("csrf")
        || compact.contains("xsrf")
        || compact.contains("viewstate")
        || compact.contains("eventvalidation")
        || compact.contains("privatekey")
        || compact.ends_with("nonce")
}

/// Credential words in a compacted name (without separators).
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
        return false; // business value in the type's format
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

/// Uppercase percent-encoding; `plus` writes a space as `+`.
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
    // Double percent-encoding (`%252F`): encodes each percent form again.
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
            } else if detect_secret(&percent_decode(value)).is_some() {
                out.push(SensitiveValue {
                    origin: "urlQueryFormat",
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
    // Fragment with parameters (`#access_token=...`).
    if let Some(fragment) = fragment {
        collect_query(fragment, out);
    }
    let path_part = before_fragment.split('?').next().unwrap_or("");
    // Matrix parameters (`;jsessionid=...`) and the userinfo password.
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
                        if detect_secret(text).is_some() {
                            out.push(SensitiveValue {
                                origin: "bodyJsonFormat",
                                value: text.clone(),
                            });
                        }
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

/// `<input type="hidden" name="csrf_token" value="...">`: the value of a hidden input
/// with a sensitive name joins the value propagation set, to be redacted wherever it
/// reappears (headers, query, form and JSON of the following requests).
fn collect_hidden_inputs(html: &str, out: &mut Vec<SensitiveValue>) {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("<input") {
        let start = from + at;
        let Some(len) = html[start..].find('>') else {
            break;
        };
        let tag = &html[start + 6..start + len];
        from = start + len + 1;
        let attrs = html_attributes(tag);
        let get = |key: &str| {
            attrs
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, value)| value.as_str())
        };
        if !get("type").is_some_and(|t| t.trim().eq_ignore_ascii_case("hidden")) {
            continue;
        }
        let (Some(name), Some(value)) = (get("name").or_else(|| get("id")), get("value")) else {
            continue;
        };
        if is_propagating_key(&html_unescape(name)) {
            out.push(SensitiveValue {
                origin: "htmlHidden",
                value: html_unescape(value),
            });
        }
    }
}

/// Attributes of a tag (`name="value"`, `name='value'`, `name=value`, `name`).
fn html_attributes(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/')
        {
            i += 1;
        }
        if i == name_start {
            break;
        }
        let name = tag[name_start..i].to_string();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let value = if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
                let quote = bytes[i];
                let start = i + 1;
                let end = bytes[start..]
                    .iter()
                    .position(|b| *b == quote)
                    .map_or(bytes.len(), |n| start + n);
                i = (end + 1).min(bytes.len());
                tag[start..end].to_string()
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                tag[start..i].to_string()
            };
            attrs.push((name, value));
        } else {
            attrs.push((name, String::new()));
        }
    }
    attrs
}

/// Common HTML entities in attribute values.
fn html_unescape(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    // `&#NN;` / `&#xHH;` (one character)
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(at) = rest.find("&#") {
        result.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        let end = tail.find(';');
        let decoded = end.and_then(|end| {
            let code = &tail[..end];
            let number = match code.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => code.parse::<u32>().ok(),
            }?;
            char::from_u32(number).map(|ch| (ch, end))
        });
        match decoded {
            Some((ch, end)) => {
                result.push(ch);
                rest = &tail[end + 1..];
            }
            None => {
                result.push_str("&#");
                rest = tail;
            }
        }
    }
    result.push_str(rest);
    out = result.replace("&amp;", "&");
    out
}

fn collect_body_bytes(bytes: &[u8], content_type: Option<&str>, out: &mut Vec<SensitiveValue>) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let media = content_type.unwrap_or("").to_ascii_lowercase();
    if media.contains("html") || (media.is_empty() && text.contains("<input")) {
        collect_hidden_inputs(text, out);
        return;
    }
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
                } else if detect_secret(&percent_decode(value)).is_some() {
                    out.push(SensitiveValue {
                        origin: "bodyFormFormat",
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
                continue; // covered by the cookie pairs/records
            }
            if is_sensitive_header(&lower) {
                let value =
                    split_auth_scheme(&entry.value).map_or(entry.value.as_str(), |(_, rest)| rest);
                out.push(SensitiveValue {
                    origin: "header",
                    value: value.to_string(),
                });
            } else if is_url_header(&lower) || entry.name == ":path" {
                collect_url(&entry.value, out);
            } else if detect_secret(&entry.value).is_some() {
                out.push(SensitiveValue {
                    origin: "headerFormat",
                    value: entry.value.trim().to_string(),
                });
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

/// Replaces all occurrences of `variant`; returns (text, count).
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
    /// Redacts in place; only called on value fields.
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

/// Redacts, in the value fields of the sanitized session (URLs, header values, cookies,
/// notes and text attachments), each value that the policy has already treated as
/// sensitive with high confidence, in literal, percent-encoded (hex without case
/// distinction, `+` as space) and JSON-escaped forms. Enums, IDs and attachment names
/// are never touched: the pass walks the typed model, without serializing the session.
/// No step is fallible; attachments that are not UTF-8 text are not scanned and this
/// is declared.
fn propagate_sensitive_values(
    sensitive: Vec<SensitiveValue>,
    session: &mut crate::model::SessionV1,
    generated: &mut BTreeMap<String, Vec<u8>>,
    options: &SanitizeOptions,
    redactions: &mut BTreeMap<String, usize>,
    warnings: &mut Vec<Warning>,
) {
    let mut seen = std::collections::BTreeSet::new();
    let mut values: Vec<SensitiveValue> = sensitive
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
                "{total} occurrence(s) of {} sensitive value(s) already identified were redacted in other fields (URLs, headers, bodies), in literal, percent-encoded and JSON-escaped forms; values shorter than {PROPAGATION_MIN_LEN} bytes (or {PROPAGATION_MIN_DIGITS} digits) or trivial values are not propagated and may remain",
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
                "{not_scanned} binary/non-UTF-8 attachment(s) were not scanned by value propagation"
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
        // The original is not copied.
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
        assert!(!raw.contains("ZZURLTOKEN-42"), "sid must not leak");
        assert!(!raw.contains("ZZJSESSION-1"), "jsessionid must not leak");
        assert!(!raw.contains("ZZPHPSESS-2"), "phpsessid must not leak");
        assert!(raw.contains("page=2"), "non-sensitive parameter preserved");
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
        assert!(!raw.contains("ZZAUTH-987654321"), "Bearer must not leak");
        assert!(export
            .bundle
            .session
            .session
            .notes
            .iter()
            .any(|note| note.contains("heuristic")));
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
                "text of {} bytes took {elapsed:?}",
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
    fn dbg_access() {
        println!(
            "key access={} header X-Access={}",
            is_sensitive_key("access"),
            is_sensitive_header("X-Access")
        );
    }

    #[test]
    fn portuguese_names_are_sensitive_by_key_segment() {
        for name in [
            "chave",
            "chave_api",
            "chaveApi",
            "Chave-Api",
            "segredo",
            "segredos",
            "sessao",
            "sessão",
            "sessoes",
            "autorizacao",
            "autorização",
            "autorizacoes",
            "credencial",
            "credenciais",
            "nome",
            "nomeCompleto",
            "nome_cliente",
            "sobrenome",
            "rg",
            "user_rg",
            "rg_cliente",
            "tel",
            "fone",
            "jsid",
            "matricula",
            "codigo_acesso",
            "codigoDeAcesso",
            "assinatura",
            "assinaturas",
            "assinaturaDigital",
            "assinaturaEletronica",
        ] {
            assert!(is_sensitive_key(name), "{name} must be sensitive");
        }
        for name in [
            "chaveiro",
            "segredinho",
            "org",
            "cargo",
            "target",
            "tela",
            "renomear",
            "nomeado",
            "nome_arquivo",
            "nomeArquivo",
            "nome_do_arquivo",
            "codigo",
            "codigo_produto",
            "codigo_acessorio",
            "assinaturaPlano",
            "assinatura_plano",
            "planoAssinatura",
            "assinaturaMensal",
            "page",
            "monkey",
        ] {
            assert!(!is_sensitive_key(name), "{name} must not be sensitive");
        }
        for header in [
            "X-Chave-Api",
            "XChaveApi",
            "X-Sessao",
            "X-Sessão",
            "XAutorizacao",
            "Autorizacao",
            "Autorização",
            "X-Nome",
            "XNomeCompleto",
            "X-Rg",
            "X-Codigo-Acesso",
            "X-Tel",
            "X-Assinatura",
            "XAssinatura",
            "X-Assinatura-Digital",
        ] {
            assert!(is_sensitive_header(header), "{header} must be sensitive");
        }
        for header in [
            "Content-Type",
            "X-Forwarded-For",
            "X-Cargo",
            "X-Org",
            "X-Assinatura-Plano",
            "X-Assinatura-Mensal",
            "Author",
            "Origin",
            ":authority",
        ] {
            assert!(
                !is_sensitive_header(header),
                "{header} must not be sensitive"
            );
        }
    }

    #[test]
    fn portuguese_secrets_do_not_survive_url_headers_form_json_or_cookies() {
        let mut session = SessionV1::new(SessionMeta::new(
            "s-pt",
            "2026-10-26T20:00:00Z",
            crate::model::BrowserInfo::default(),
        ));
        let mut url_request = LogicalRequest::new(
            "r-url",
            "https://demo.invalid/x?chave=ZZCHAVE&sessao=ZZSESSAO&nome=ZZNOME&assinatura=ZZASSINA&page=2",
            "GET",
        );
        url_request
            .request_headers
            .add("X-Chave-Api", "ZZHDRCHAVE", &provenance());
        url_request
            .request_headers
            .add("Autorização", "ZZHDRAUTH", &provenance());
        url_request
            .request_headers
            .add("X-Nome", "ZZHDRNOME", &provenance());
        url_request.cookie = CookieField::from_header_values(
            &["sessao=ZZCOOKIE; tema=escuro".to_string()],
            &provenance(),
        );
        let mut form_request = LogicalRequest::new("r-form", "https://demo.invalid/form", "POST");
        form_request.request_body = Body::captured("form.bin", 48, &provenance())
            .with_content_type("application/x-www-form-urlencoded");
        let mut json_request = LogicalRequest::new("r-json", "https://demo.invalid/json", "POST");
        json_request.request_body =
            Body::captured("json.bin", 128, &provenance()).with_content_type("application/json");
        session
            .requests
            .extend([url_request, form_request, json_request]);
        let mut bundle = SessionBundle::new(session);
        bundle.insert_attachment(
            "form.bin",
            b"chave_api=ZZFORM&nome=ZZFORMNOME&codigo_acesso=ZZFORMCOD&page=2".to_vec(),
        );
        bundle.insert_attachment(
            "json.bin",
            br#"{"segredo":"ZZJSON","credencial":"ZZCRED","nome":"ZZJSONNOME","nome_arquivo":"page.html","assinatura":"ZZJSONASSINA","assinaturaPlano":"premium","codigo_acesso":"ZZCOD","page":2}"#.to_vec(),
        );
        let original = serde_json::to_string(&bundle.session).unwrap();
        assert!(
            original.contains("ZZCHAVE"),
            "full session must keep the value"
        );
        let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
        assert_eq!(
            original,
            serde_json::to_string(&bundle.session).unwrap(),
            "the full session is not mutated"
        );
        let session_json = serde_json::to_string(&export.bundle.session).unwrap();
        let form = export
            .bundle
            .attachments
            .get(
                export.bundle.session.requests[1]
                    .request_body
                    .attachment
                    .as_ref()
                    .unwrap(),
            )
            .unwrap();
        let json: Value = serde_json::from_slice(
            export
                .bundle
                .attachments
                .get(
                    export.bundle.session.requests[2]
                        .request_body
                        .attachment
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let all = format!("{session_json}{}", String::from_utf8_lossy(form));
        for secret in [
            "ZZCHAVE",
            "ZZSESSAO",
            "ZZNOME",
            "ZZHDRCHAVE",
            "ZZHDRAUTH",
            "ZZHDRNOME",
            "ZZCOOKIE",
            "ZZFORM",
            "ZZFORMNOME",
            "ZZFORMCOD",
            "ZZJSON",
            "ZZCRED",
            "ZZJSONNOME",
            "ZZCOD",
            "ZZASSINA",
            "ZZJSONASSINA",
        ] {
            assert!(!all.contains(secret), "{secret} leaked in {all}");
        }
        assert!(session_json.contains("page=2"));
        assert_eq!(json["page"], 2);
        assert_eq!(
            json["nome_arquivo"], "page.html",
            "a technical nome label is not PII"
        );
        assert_eq!(
            json["assinaturaPlano"], "premium",
            "a subscription plan label is not a signature"
        );
        let form_text = String::from_utf8_lossy(form);
        assert_eq!(
            form_text,
            "chave_api=[REDACTED]&nome=[REDACTED]&codigo_acesso=[REDACTED]&page=2"
        );
        assert_eq!(json["segredo"], "[REDACTED]");
        assert_eq!(json["credencial"], "[REDACTED]");
        assert_eq!(json["nome"], "[REDACTED]");
        assert_eq!(json["assinatura"], "[REDACTED]");
        assert_eq!(json["codigo_acesso"], "[REDACTED]");
        let sanitized_url = &export.bundle.session.requests[0];
        assert!(
            sanitized_url.url.contains("chave=%5BREDACTED%5D"),
            "{}",
            sanitized_url.url
        );
        assert!(
            sanitized_url.url.contains("sessao=%5BREDACTED%5D"),
            "{}",
            sanitized_url.url
        );
        assert!(
            sanitized_url.url.contains("nome=%5BREDACTED%5D"),
            "{}",
            sanitized_url.url
        );
        assert!(
            sanitized_url.url.contains("assinatura=%5BREDACTED%5D"),
            "{}",
            sanitized_url.url
        );
        assert_eq!(
            sanitized_url.request_headers.first_value("x-chave-api"),
            Some("[REDACTED]")
        );
        assert_eq!(
            sanitized_url.request_headers.first_value("autorização"),
            Some("[REDACTED]")
        );
        assert_eq!(
            sanitized_url.request_headers.first_value("x-nome"),
            Some("[REDACTED]")
        );
        assert_eq!(sanitized_url.cookie.pairs[0].value, "[REDACTED]");
        assert_eq!(sanitized_url.cookie.pairs[1].value, "[REDACTED]");
    }

    #[test]
    fn round2_nested_url_tab_after_scheme_and_obvious_values() {
        let o = SanitizeOptions::default();
        // R6: nested URL with percent-encoding (also at two levels).
        let out = sanitize_text(
            "GET /cb?redirect_uri=https%3A%2F%2Fa.test%2Fx%3Ftoken%3DSEGMARC1 HTTP/1.1",
            &o,
        );
        assert!(!out.contains("SEGMARC1"), "{out}");
        let out = sanitize_url(
            "https://a.test/c?next=%2Fcb%3Fnext%3D%252Fz%253Ftoken%253DSEGMARC2",
            &o,
        );
        assert!(!out.contains("SEGMARC2"), "{out}");
        // R8: TAB (and any whitespace) after the scheme; UTF-8 without panic.
        assert_eq!(
            split_auth_scheme("Bearer\tSEGMARC3").map(|(_, r)| r),
            Some("SEGMARC3")
        );
        assert!(
            redact_auth_scheme("bearer \t SEGMARC3", &o).is_some_and(|v| !v.contains("SEGMARC3"))
        );
        assert!(split_auth_scheme("Béarer xyz").is_none());
        assert!(split_auth_scheme("日本語日本語日本語").is_none());
        // R13: obvious boolean/number stays visible; string redacted; label object traversed.
        let mut v: Value = serde_json::from_str(
            r#"{"pin":true,"ticket":{"id":"SEGMARC4x","open":false},"jwtExpiresIn":3600,"otp":"123456","password":"SEGMARC5","pinCount":3}"#,
        ).unwrap();
        sanitize_json(&mut v, &o, &mut BTreeMap::new());
        let text = v.to_string();
        assert_eq!(v["pin"], Value::Bool(true));
        assert_eq!(v["jwtExpiresIn"], 3600);
        assert_eq!(v["ticket"]["open"], Value::Bool(false));
        for secret in ["SEGMARC4x", "123456", "SEGMARC5"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }
}
