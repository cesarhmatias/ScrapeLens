//! Priming script in Python (docs/11-priming-success.md §1).
//!
//! Generates a `requests.Session` script that recreates the session: each step
//! of the chain (`flow::priming_chain`, only `steps`) is replayed in order, and
//! the values that have an observed origin are EXTRACTED at runtime from the
//! producer's response, using the same kind of evidence. If the extraction does
//! not find the value, the script fails with a clear message; it never falls
//! back to the captured value.
//!
//! Security of the generated code: all captured data enters only as escaped
//! Python literals (ASCII, `\x`/`\u`/`\U`) or as comments produced by
//! [`super::comment`]. Parameter names are sanitized. The script is not executed
//! by ScrapeLens.
//!
//! Declared heuristics: values that look like user input inside opaque fields
//! without an origin (license plate, CPF/CNPJ/RENAVAM after `v_cpf`, `v_cnpj`,
//! `v_renavam`) become required parameters, with no default.
//!
//! Parameter default: a value with no observed origin only becomes the
//! parameter's default if it is a proven constant (it appears identical, in the
//! same field, in ≥ 2 requests of the session, or is in a static
//! resource/context). All others — including the suffix of `partialComposition`
//! and the `STAMP` without a producer — are required, and the captured value
//! does not enter the code.
//!
//! Incomplete chain: if a value consumed by the chain has no origin and there
//! was an earlier response without an observable body, `to_python` REFUSES by
//! default (listing the producers and the equivalent occurrence with a body).
//! `allow_incomplete` generates the script with an explicit `fail()` in those
//! steps.
//!
//! Each step validates its OWN response before returning: a status outside
//! 2xx/3xx, a control/field/cookie/header that it hands to the following steps
//! (through the chain), and a filled `ERRORMESSAGE` fail with
//! `priming: step N: …` and no request is sent afterwards. A header outside
//! latin-1 also fails with a clear `priming:` message, instead of a raw
//! `UnicodeEncodeError`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use crate::error::{CoreError, Result};
use crate::flow::{
    priming_chain, value_origins, ConsumedScope, Evidence, EvidenceKind, FlowOptions, OriginStatus,
    PrimingChain, ProducerScope, Role, Unobservable, ValueOrigin, ValueOrigins,
};
use crate::html::html_controls;
use crate::model::{BodyState, LogicalRequest, SessionV1, Warning};
use crate::search::BodySource;

use super::{comment, is_header_token, is_safe_header_value, ExportOutput};

#[derive(Debug, Clone, Default)]
pub struct PrimingOptions {
    pub flow: FlowOptions,
    /// Generates the script even when the chain depends on a response without
    /// an observable body, with an explicit `fail()` in those steps.
    pub allow_incomplete: bool,
    /// Origins (`scheme://host[:port]`) besides the target that the chain may
    /// contact; without them, a step with another origin is refused at
    /// generation time.
    pub allow_origins: Vec<String>,
    /// Accepts a body that is neither a form nor JSON, resent as captured; the
    /// detected sensitive/business values become required parameters.
    pub allow_literal_body: bool,
    /// Python encoders of the protocol adapters registered in `flow.adapters`:
    /// without them, the claimed field falls back to segment-based handling.
    pub adapter_encoders: Vec<AdapterEncoder>,
    /// Adapter parts principle. Default (strict): literal only for the
    /// Structure role, a proven constant (≥ 2 requests in the session or static
    /// context), a navigation value or a "UI constant" (`is_ui_constant`:
    /// booleans and numbers of up to 4 characters with sign/decimal: `true`,
    /// `-180`, `2.0`) or a command/resource name from the header (`event`,
    /// `page`, `model`, like `cmd_filtro`) that does not look like an identifier
    /// nor PII; every other part without an origin becomes a required parameter.
    /// With `lenient_parts`, only values that look like an
    /// identifier/secret/timestamp (UUID, hex, ULID, base64, timestamp, long
    /// mixed alphanumeric) become parameters and the rest stays literal. A value
    /// whose origin is in another round is never literal.
    pub lenient_parts: bool,
}

/// Python encoder equivalent to an adapter's `encode`. The `source` defines
/// `function(parts)`, which receives `(name, role, value)` in order, with role
/// `S` (structure), `N` (name), `V` (value), `D` (delta) or `O`.
#[derive(Debug, Clone, Default)]
pub struct AdapterEncoder {
    pub adapter_id: String,
    pub function: String,
    /// Python function `decode(texto)` that returns the same parts
    /// `(name, role, value)` as the adapter's `decode` (empty = no per-part
    /// extraction from responses).
    pub decoder: String,
    pub source: String,
}

const CONTEXT_BEFORE: usize = 16;
const CONTEXT_AFTER: usize = 6;
const SKIP_HEADERS: &[&str] = &[
    "cookie",
    "content-length",
    "host",
    "connection",
    "accept-encoding",
    "authorization",
    "proxy-authorization",
    "transfer-encoding",
    "te",
    "upgrade",
    "keep-alive",
    "expect",
];
const SENSITIVE_WORDS: &[&str] = &[
    "password",
    "passwd",
    "senha",
    "secret",
    "token",
    "authorization",
    "apikey",
    "api_key",
    "api-key",
    "cpf",
    "cnpj",
    "renavam",
    "cartao",
    "credential",
    "chave",
    "nome",
    "email",
    "telefone",
    "celular",
    "endereco",
    "endereço",
    "nascimento",
    "session",
    "callback",
    "key",
    "csrf",
    "xsrf",
    "jwt",
    "sess",
    "secret",
    "signature",
    "auth",
    "device",
    "user",
    "hmac",
    "bearer",
    "digest",
    "nonce",
];
/// Words too short to match as a substring (`rg` in `target`): they only count
/// as a whole word of the name (`rg`, `user_rg`, `sid`, `jsid`).
const SENSITIVE_SHORT_WORDS: &[&str] = &["rg", "sid", "sessid", "jsid", "tel", "fone"];
/// Abbreviations and PII/credential terms, only as a whole word of the name
/// (`v_pass` yes, `v_passo` no). They apply with and without an adapter.
const SENSITIVE_ABBREVIATIONS: &[&str] = &[
    "pwd",
    "pass",
    "psw",
    "pswd",
    "pin",
    "otp",
    "passcode",
    "seguranca",
    "cookie",
    "nm",
    "aniversario",
    "filiacao",
    "logradouro",
    "bairro",
    "titular",
    "proprietario",
    "razaosocial",
    "conta",
    "sexo",
    "mail",
    "cidade",
    "pw",
    "pswrd",
    "passw",
    "pwrd",
    "2fa",
    "mfa",
    "totp",
    "salt",
    "hash",
    "assinatura",
    "login",
    "usuario",
    "uid",
    "pai",
    "responsavel",
    "beneficiario",
    "agencia",
    "banco",
    "iban",
    "whatsapp",
    "rua",
    "complemento",
    "municipio",
    "documento",
    "sen",
    "snh",
    "nip",
    "ticket",
    "voucher",
    "chv",
    "doc",
];
/// Terms long enough to match as a substring (`codSeguranca`).
const SENSITIVE_LONG_TERMS: &[&str] = &[
    "seguranca",
    "aniversario",
    "filiacao",
    "logradouro",
    "proprietario",
    "razaosocial",
    "passcode",
    "passaporte",
];

/// Words of a name: non-alphanumeric separators and camelCase boundaries.
fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = c.is_ascii_lowercase();
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn has_sensitive_abbreviation(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_LONG_TERMS.iter().any(|t| lower.contains(t))
        || name_words(name)
            .iter()
            .any(|w| SENSITIVE_ABBREVIATIONS.contains(&w.as_str()))
}

/// ASCII Python literal with single quotes; nothing beyond `[ -~]` is emitted raw.
fn lit(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            c if (c as u32) <= 0xff => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if (c as u32) <= 0xffff => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\U{:08x}", c as u32);
            }
        }
    }
    out.push('\'');
    out
}

fn bytes_lit(bytes: &[u8]) -> String {
    let mut out = String::from("b'");
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b' '..=b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push('\'');
    out
}

fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SENSITIVE_WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| SENSITIVE_SHORT_WORDS.contains(&word))
        || has_sensitive_abbreviation(name)
}

fn is_plate_at(b: &[u8], i: usize) -> bool {
    if i + 7 > b.len() {
        return false;
    }
    let w = &b[i..i + 7];
    let ok = w[..3].iter().all(u8::is_ascii_uppercase)
        && w[3].is_ascii_digit()
        && (w[4].is_ascii_digit() || w[4].is_ascii_uppercase())
        && w[5].is_ascii_digit()
        && w[6].is_ascii_digit();
    let before_ok = i == 0 || !(b[i - 1].is_ascii_uppercase() || b[i - 1].is_ascii_digit());
    let after_ok =
        i + 7 == b.len() || !(b[i + 7].is_ascii_uppercase() || b[i + 7].is_ascii_digit());
    ok && before_ok && after_ok
}

/// Plate with a hyphen: `ABC-1234` and Mercosul `ABC-1D23`.
fn is_plate_dash_at(b: &[u8], i: usize) -> bool {
    if i + 8 > b.len() {
        return false;
    }
    let w = &b[i..i + 8];
    let ok = w[..3].iter().all(u8::is_ascii_uppercase)
        && w[3] == b'-'
        && w[4].is_ascii_digit()
        && (w[5].is_ascii_digit() || w[5].is_ascii_uppercase())
        && w[6].is_ascii_digit()
        && w[7].is_ascii_digit();
    let before_ok = i == 0 || !(b[i - 1].is_ascii_uppercase() || b[i - 1].is_ascii_digit());
    let after_ok =
        i + 8 == b.len() || !(b[i + 8].is_ascii_uppercase() || b[i + 8].is_ascii_digit());
    ok && before_ok && after_ok
}

/// VIN/chassis: 17 characters `[A-HJ-NPR-Z0-9]` in uppercase, with a letter and a digit.
fn is_vin_at(b: &[u8], i: usize) -> bool {
    if i + 17 > b.len() || (i > 0 && b[i - 1].is_ascii_alphanumeric()) {
        return false;
    }
    let w = &b[i..i + 17];
    let shaped = w.iter().all(|c| {
        (c.is_ascii_uppercase() || c.is_ascii_digit()) && !matches!(c, b'I' | b'O' | b'Q')
    });
    shaped
        && w.iter().any(u8::is_ascii_digit)
        && w.iter().any(u8::is_ascii_uppercase)
        && (i + 17 == b.len() || !b[i + 17].is_ascii_alphanumeric())
}

/// Full width (basic NFKC): `１２３` becomes `123`, `＠` becomes `@`.
fn fold_width(text: &str) -> String {
    text.chars()
        .map(|c| match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            0x3000 => ' ',
            _ => c,
        })
        .collect()
}

fn looks_sensitive_value(value: &str) -> bool {
    value.contains("REDACTED")
        || (0..value.len()).any(|i| {
            is_plate_at(value.as_bytes(), i)
                || is_plate_dash_at(value.as_bytes(), i)
                || is_vin_at(value.as_bytes(), i)
        })
}

/// Opaque identifier (CPF/case number/timestamp): long and digits only, or a
/// long hex. Never a structural constant, even if it appears in a navigation
/// URL.
fn looks_opaque_id(value: &str) -> bool {
    let digits = value.bytes().all(|b| b.is_ascii_digit());
    if digits && value.len() >= 5 {
        return true;
    }
    if looks_dynamic_token(value) {
        return true;
    }
    if value.len() >= 16 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return true;
    }
    // Versions and counters (`1.2.3`, `123_456`, `jQuery123_456`): they look like
    // a dynamic value, never a structural constant.
    if value.bytes().any(|b| b.is_ascii_digit())
        && value.bytes().any(|b| matches!(b, b'.' | b'_' | b'-'))
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return true;
    }
    let digits = value.bytes().filter(u8::is_ascii_digit).count();
    if digits >= 3 && value.contains('_') && value.bytes().any(|b| b.is_ascii_alphabetic()) {
        return true;
    }
    // Long, mixed Base64/base64url.
    value.len() >= 20
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
        && value.bytes().any(|b| b.is_ascii_digit())
        && value.bytes().any(|b| b.is_ascii_uppercase())
        && value.bytes().any(|b| b.is_ascii_lowercase())
}

/// Field value that is a valid JSON object/array.
fn json_container(text: &str) -> Option<serde_json::Value> {
    let trimmed = text.trim();
    if !trimmed.starts_with(['{', '[']) {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

/// Value of a request part with no origin tracked by the flow: searches the
/// responses of the earlier steps for a field of the same adapter whose decoded
/// part has the same value, and extracts it at runtime by the part's name
/// (immune to length changes).
#[allow(clippy::too_many_arguments)]
fn adapter_chain_expr(
    gen: &mut Gen,
    request: &LogicalRequest,
    opts: &PrimingOptions,
    encoder_index: usize,
    adapter: &dyn crate::adapter::ProtocolAdapter,
    field: &str,
    part_name: &str,
    value: &str,
) -> Option<String> {
    use crate::adapter::PartRole;
    let decoder = &opts.adapter_encoders[encoder_index].decoder;
    if decoder.is_empty() || value.is_empty() || looks_sensitive_value(value) || contains_pii(value)
    {
        return None;
    }
    // Same part name: an identical value is enough, however short. Without the
    // same name, only values that look dynamic qualify.
    let dynamic =
        value.len() >= 4 && (value.bytes().any(|b| b.is_ascii_digit()) || value.len() >= 8);
    // `XML.p.v_ctr` → `p.v_ctr`: the part name relative to the field.
    let part_name_in_field = part_name
        .strip_prefix(field)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(part_name);
    let pos = gen.steps.iter().position(|id| id == &request.id)?;
    let who = lit(&Gen::who(request, part_name));
    let previous: Vec<String> = gen.steps[..pos].to_vec();
    for rid in previous.iter().rev() {
        let producer = gen.session.find_request(rid)?.clone();
        let Some(text) = response_text(&producer, gen.source) else {
            continue;
        };
        let mut index = 0usize;
        for control in &html_controls(&text) {
            if control.name != field {
                continue;
            }
            let this_index = index;
            index += 1;
            let Ok(decoded) = adapter.decode(&control.value) else {
                continue;
            };
            let candidates: Vec<&crate::adapter::AdapterPart> = decoded
                .parts
                .iter()
                .filter(|p| matches!(p.role, PartRole::Value | PartRole::Delta))
                .collect();
            let same_name = candidates
                .iter()
                .find(|p| p.value == value && p.name == part_name_in_field);
            let Some(hit) = same_name.or_else(|| {
                dynamic
                    .then(|| candidates.iter().find(|p| p.value == value))
                    .flatten()
            }) else {
                continue;
            };
            let nth = candidates
                .iter()
                .filter(|p| p.name == hit.name)
                .position(|p| std::ptr::eq(*p, *hit))?;
            gen.expect(rid, Expectation::Control(field.to_string(), this_index));
            gen.notes.push(format!(
                "{part_name}: equal to {} from response {rid}; extracted at runtime by name",
                hit.name
            ));
            return Some(format!(
                "adapter_get({}, html_control(R[{}], {}, {this_index}, {who}), {}, {nth}, {who})",
                opts.adapter_encoders[encoder_index].decoder,
                lit(rid),
                lit(field),
                lit(&hit.name),
            ));
        }
    }
    None
}

/// How many requests of the session (any round) carry the part `name` with the
/// `value`, in the `field` field decoded by the adapter.
fn part_occurrences(
    gen: &mut Gen,
    adapter: &dyn crate::adapter::ProtocolAdapter,
    field: &str,
    part: &str,
    value: &str,
) -> usize {
    use crate::adapter::PartRole;
    if !gen.part_counts.contains_key(field) {
        let mut counts: HashMap<(String, String), usize> = HashMap::new();
        for request in &gen.session.requests {
            let Some(attachment) = request.request_body.attachment.as_deref() else {
                continue;
            };
            let Some(loaded) = gen.source.load(attachment) else {
                continue;
            };
            let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
            let mut seen: HashSet<(String, String)> = HashSet::new();
            for (k, v) in form_pairs(&text) {
                if k != field {
                    continue;
                }
                let Ok(decoded) = adapter.decode(&v) else {
                    continue;
                };
                for p in decoded.parts {
                    if p.role != PartRole::Structure && !p.value.is_empty() {
                        seen.insert((format!("{field}.{}", p.name), p.value));
                    }
                }
            }
            for key in seen {
                *counts.entry(key).or_default() += 1;
            }
        }
        gen.part_counts.insert(field.to_string(), counts);
    }
    gen.part_counts
        .get(field)
        .and_then(|m| m.get(&(part.to_string(), value.to_string())))
        .copied()
        .unwrap_or(0)
}

/// Does the same delta appear in another step of the plan? Then it is a
/// protocol constant (e.g. the delta of `init`), not a server echo.
fn delta_repeated_in_plan(
    gen: &Gen,
    request: &LogicalRequest,
    adapter: &dyn crate::adapter::ProtocolAdapter,
    field: &str,
    value: &str,
) -> bool {
    use crate::adapter::PartRole;
    gen.steps.iter().filter(|id| **id != request.id).any(|rid| {
        let Some(other) = gen.session.find_request(rid) else {
            return false;
        };
        let Some(attachment) = other.request_body.attachment.as_deref() else {
            return false;
        };
        let Some(loaded) = gen.source.load(attachment) else {
            return false;
        };
        let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
        form_pairs(&text).iter().any(|(k, v)| {
            k == field
                && adapter.decode(v).is_ok_and(|d| {
                    d.parts
                        .iter()
                        .any(|p| p.role == PartRole::Delta && p.value == value)
                })
        })
    })
}

/// Did an earlier step of the plan return an adapter field with a delta? Then
/// the delta sent now is an echo of the server state (not a constant).
fn earlier_response_has_delta(
    gen: &Gen,
    request: &LogicalRequest,
    adapter: &dyn crate::adapter::ProtocolAdapter,
    field: &str,
) -> bool {
    earlier_response_has_field(gen, request, adapter, field, true)
}

/// Did an earlier step of the plan return an adapter field (with a delta, if
/// `with_delta`)? Without that, the request's values are the protocol's initial
/// constants (handshake), not an echo of server state.
fn earlier_response_has_field(
    gen: &Gen,
    request: &LogicalRequest,
    adapter: &dyn crate::adapter::ProtocolAdapter,
    field: &str,
    with_delta: bool,
) -> bool {
    use crate::adapter::PartRole;
    let Some(pos) = gen.steps.iter().position(|id| id == &request.id) else {
        return false;
    };
    gen.steps[..pos].iter().any(|rid| {
        let Some(producer) = gen.session.find_request(rid) else {
            return false;
        };
        let Some(text) = response_text(producer, gen.source) else {
            return false;
        };
        html_controls(&text).iter().any(|control| {
            control.name == field
                && adapter
                    .decode(&control.value)
                    .is_ok_and(|d| !with_delta || d.parts.iter().any(|p| p.role == PartRole::Delta))
        })
    })
}

/// Field claimed by a protocol adapter: the script builds the parts (constants +
/// extracted + parameters) and calls the adapter's Python encoder, which
/// recomputes all the prefixes. `None` = not claimed.
#[allow(clippy::too_many_arguments)]
fn adapter_field_expr(
    gen: &mut Gen,
    request: &LogicalRequest,
    origins: &ValueOrigins,
    opts: &PrimingOptions,
    media: &str,
    name: &str,
    value: &str,
    siblings: &[(String, String)],
) -> Option<String> {
    use crate::adapter::{AdapterContext, PartRole};
    if opts.flow.adapters.is_empty() || value.is_empty() {
        return None;
    }
    let ctx = AdapterContext {
        url: &request.url,
        method: &request.method,
        request: true,
        media: Some(media),
    };
    let adapter = opts.flow.adapters.claim(name, value, &ctx)?;
    let encoder_index = opts
        .adapter_encoders
        .iter()
        .position(|e| e.adapter_id == adapter.id())?;
    let decoded = adapter.decode(value).ok()?;
    // Only when the encoder reproduces the captured value byte for byte.
    if adapter.encode(&decoded).ok().as_deref() != Some(value) {
        return None;
    }
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut items: Vec<String> = Vec::new();
    for part in &decoded.parts {
        let role = match &part.role {
            PartRole::Structure => "S",
            PartRole::Name => "N",
            PartRole::Value => "V",
            PartRole::Delta => "D",
            PartRole::Other(_) => "O",
        };
        let expr = if matches!(part.role, PartRole::Structure | PartRole::Name)
            || part.value.is_empty()
        {
            lit(&part.value)
        } else {
            let full = format!("{name}.{}", part.name);
            let occ = seen.entry(full.clone()).or_default();
            // The parts of the claimed field arrive with `parent = field`.
            let origin = origins.values.iter().find(|v| {
                v.scope == ConsumedScope::Body
                    && v.parent.as_deref() == Some(name)
                    && v.field == full
                    && v.occurrence == *occ
            });
            *occ += 1;
            // Another field of the same form with the same value (e.g. SESSIONID):
            // it is the same information, with the same parameter name.
            let label = siblings
                .iter()
                .find(|(k, v)| k != name && v == &part.value)
                .map_or(full.as_str(), |(k, _)| k.as_str())
                .to_string();
            let traced = origin.filter(|o| {
                matches!(o.status, OriginStatus::Redacted | OriginStatus::Composite)
                    || !o.partial_composition.is_empty()
            });
            let extracted = origin
                .filter(|o| {
                    traced.is_none()
                        && matches!(o.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                })
                .and_then(|o| gen.source_expr(o, &part.value, request, &label));
            match (traced, extracted) {
                (_, Some(expr)) => expr,
                (Some(o), None) => gen.value_expr(
                    request,
                    Some(o),
                    origins,
                    &label,
                    &part.value,
                    ConsumedScope::Body,
                ),
                (None, None) => {
                    let prop = part.name.strip_prefix("p.").unwrap_or(&part.name);
                    let business = match prop {
                        "v_cpf" => Some("cpf"),
                        "v_cnpj" => Some("cnpj"),
                        "v_renavam" => Some("renavam"),
                        _ => None,
                    };
                    // Last component of the name (`items[0].v_senha` → `v_senha`),
                    // using the same lists as the path without an adapter.
                    let last = prop
                        .rsplit('.')
                        .next()
                        .unwrap_or(prop)
                        .split('[')
                        .next()
                        .unwrap_or(prop);
                    let sensitive_part = is_sensitive_name(last) || is_pii_name(last);
                    match business {
                        Some(label) => {
                            gen.notes
                                .push(format!("{full}: user data; required parameter"));
                            gen.params
                                .get(label, &part.value, true, "user data", false)
                        }
                        None if sensitive_part && !part.value.is_empty() => {
                            gen.notes.push(format!(
                                "{full}: sensitive name; required parameter, no default"
                            ));
                            gen.params.get(
                                last.trim_start_matches("v_"),
                                &part.value,
                                true,
                                "sensitive data",
                                false,
                            )
                        }
                        None => match adapter_chain_expr(
                            gen,
                            request,
                            opts,
                            encoder_index,
                            adapter.as_ref(),
                            name,
                            &full,
                            &part.value,
                        ) {
                            Some(expr) => expr,
                            // Delta (or a value that looks like an identifier) with
                            // no origin and no proof of constancy: rule F1, required
                            // parameter.
                            None if matches!(part.role, PartRole::Delta)
                                && earlier_response_has_delta(
                                    gen,
                                    request,
                                    adapter.as_ref(),
                                    name,
                                )
                                && !delta_repeated_in_plan(
                                    gen,
                                    request,
                                    adapter.as_ref(),
                                    name,
                                    &part.value,
                                ) =>
                            {
                                gen.notes.push(format!(
                                    "{full}: no observed origin; provide the value from the earlier response"
                                ));
                                gen.fallback_param(&full, &part.value, false, false, false)
                            }
                            None => {
                                // Literal only for: a proven constant (≥ 2 requests
                                // of the session or static context) or a navigation
                                // value. The rest is a parameter.
                                let proven = part_occurrences(
                                    gen,
                                    adapter.as_ref(),
                                    name,
                                    &full,
                                    &part.value,
                                ) >= 2;
                                let in_static_context =
                                    origin.is_some_and(|o| !o.context.is_empty());
                                let navigation = gen.structural.contains(part.value.as_str());
                                let scrubbed = scrub_literal(&part.value, &mut gen.params);
                                let has_param =
                                    scrubbed.iter().any(|p| matches!(p, Piece::Expr(_)));
                                let identifier = looks_identifier_value(&part.value);
                                // Value with a producer observed outside the plan
                                // (another round): never literal.
                                let observed_elsewhere = origin
                                    .filter(|o| {
                                        matches!(
                                            o.status,
                                            OriginStatus::Origin | OriginStatus::Ambiguous
                                        )
                                    })
                                    .and_then(|o| {
                                        o.oldest
                                            .and_then(|i| o.evidences.get(i))
                                            .or_else(|| o.evidences.first())
                                    })
                                    .map(|e| e.request_id.clone());
                                if proven
                                    || in_static_context
                                    || navigation
                                    || has_param
                                    || is_ui_constant(&part.value)
                                    // Command/resource name from the header
                                    // (`event`, `page`, `model`): protocol structure,
                                    // unless it looks like an identifier.
                                    || (matches!(part.name.as_str(), "event" | "page" | "model")
                                        && !identifier
                                        && observed_elsewhere.is_none()
                                        && !contains_pii(&part.value))
                                    // No earlier response of the plan carries the
                                    // field: initial protocol constants.
                                    || (!identifier
                                        && observed_elsewhere.is_none()
                                        && !earlier_response_has_field(
                                            gen,
                                            request,
                                            adapter.as_ref(),
                                            name,
                                            false,
                                        ))
                                    || (opts.lenient_parts
                                        && !identifier
                                        && observed_elsewhere.is_none())
                                {
                                    pieces_expr(scrubbed)
                                } else if let Some(rid) = &observed_elsewhere {
                                    gen.notes.push(format!(
                                        "{full}: origin in another round ({rid}); provide the value"
                                    ));
                                    gen.params.get(
                                        &full,
                                        &part.value,
                                        false,
                                        &format!("origin in another round ({rid})"),
                                        false,
                                    )
                                } else {
                                    gen.notes.push(format!(
                                        "{full}: no observed origin and no proof of constancy; provide the value"
                                    ));
                                    gen.fallback_param(&full, &part.value, false, false, false)
                                }
                            }
                        },
                    }
                }
            }
        };
        gen.note_params(&format!("{name}.{}", part.name), &expr);
        items.push(format!("({}, {}, {})", lit(&part.name), lit(role), expr));
    }
    gen.encoders_used.insert(encoder_index);
    gen.claimed_fields.insert(name.to_string());
    gen.notes.push(format!(
        "{name}: protocol field {}; assembled from parts and re-encoded with recalculated lengths",
        adapter.id()
    ));
    Some(format!(
        "{}([{}])",
        opts.adapter_encoders[encoder_index].function,
        items.join(", ")
    ))
}

/// Form/query field value: embedded JSON is decomposed recursively;
/// otherwise, the normal treatment.
#[allow(clippy::too_many_arguments)]
fn field_expr<'a>(
    gen: &mut Gen,
    request: &LogicalRequest,
    origin: Option<&ValueOrigin>,
    origins: &'a ValueOrigins,
    name: &str,
    value: &str,
    scope: ConsumedScope,
) -> String {
    let extracted = origin.is_some_and(|o| matches!(o.status, OriginStatus::Origin));
    if !extracted {
        // JSON possibly percent-encoded more than once.
        let mut current = value.to_string();
        let mut layers = 0;
        let found = loop {
            if let Some(json) = json_container(&current) {
                break Some(json);
            }
            if layers >= 3 || !current.contains('%') {
                break None;
            }
            let next = percent_decode(&current);
            if next == current {
                break None;
            }
            current = next;
            layers += 1;
        };
        if let Some(json) = found {
            let find = |field: &str| -> Option<&'a ValueOrigin> {
                origins.values.iter().find(|v| {
                    v.scope == scope && v.parent.is_none() && v.field == field && v.occurrence == 0
                })
            };
            let mut expr = format!(
                "json.dumps({})",
                json_expr(gen, request, origins, &json, name, &find, scope, 1)
            );
            for _ in 0..layers {
                expr = format!("urllib.parse.quote({expr}, safe='')");
            }
            return expr;
        }
    }
    gen.value_expr(request, origin, origins, name, value, scope)
}

/// Body that starts with `{`/`[` and is valid JSON, whatever the Content-Type.
fn body_is_json(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let text = text.trim_start();
    text.starts_with(['{', '[']) && serde_json::from_str::<serde_json::Value>(text).is_ok()
}

/// JWT, ULID/KSUID, ISO date/timestamp and mixed alphanumeric: they look like a
/// dynamic value even when short.
fn looks_dynamic_token(value: &str) -> bool {
    let b = value.as_bytes();
    if value.starts_with("eyJ") {
        return true;
    }
    // ULID (26, Crockford) and KSUID (27, base62).
    let alnum = b.iter().all(u8::is_ascii_alphanumeric);
    if alnum && b.len() == 26 && b.iter().all(|c| !c.is_ascii_lowercase()) {
        return true;
    }
    if alnum && b.len() == 27 {
        return true;
    }
    // YYYY-MM-DD, with or without time.
    if b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    // Upper- and lowercase letters mixed with digits, 6+.
    b.len() >= 6
        && alnum
        && b.iter().any(u8::is_ascii_digit)
        && b.iter().any(u8::is_ascii_uppercase)
        && b.iter().any(u8::is_ascii_lowercase)
}

/// "UI constant": interface state that the server repeats without it being
/// session data. Only these values without an origin stay literal on their own
/// (besides a value repeated in the session, static context and navigation):
/// booleans (`true`/`false`) and numbers of up to 4 characters, with sign and/or
/// decimal part (`-180`, `2.0`, `1568`).
pub(crate) fn is_ui_constant(value: &str) -> bool {
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        return true;
    }
    if value.is_empty() || value.len() > 4 {
        return false;
    }
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    let mut dots = 0;
    let mut digits = 0;
    for c in body.chars() {
        match c {
            '0'..='9' => digits += 1,
            '.' => dots += 1,
            _ => return false,
        }
    }
    digits >= 1 && dots <= 1 && !body.starts_with('.') && !body.ends_with('.')
}

/// Identifier, secret or timestamp: UUID, hex, ULID/KSUID, base64, timestamp and
/// long mixed alphanumeric. Broader than `looks_opaque_id`, but without catching
/// short state values (`-180`, `2.0`, `true`).
fn looks_identifier_value(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() < 8 || b.iter().any(u8::is_ascii_whitespace) {
        return false;
    }
    if looks_opaque_id(value) || looks_secret_value(value) {
        return true;
    }
    let token_chars = b
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'+' | b'/' | b'=' | b'.'));
    let digits = b.iter().filter(|c| c.is_ascii_digit()).count();
    let letters = b.iter().filter(|c| c.is_ascii_alphabetic()).count();
    token_chars && digits >= 1 && letters >= 1 && b.len() >= 12
        || token_chars && digits >= 10
        || (b.len() >= 8
            && letters >= 4
            && digits >= 1
            && b.iter().any(u8::is_ascii_lowercase)
            && b.iter().any(u8::is_ascii_uppercase))
}

/// Header value that looks like a credential/identifier, whatever the name.
fn looks_secret_value(value: &str) -> bool {
    if value.starts_with("eyJ") {
        return true;
    }
    let lower = value.trim_start().to_ascii_lowercase();
    if ["bearer ", "basic ", "digest ", "negotiate "]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
    {
        return true;
    }
    let b = value.as_bytes();
    if b.len() >= 8 && b.iter().all(u8::is_ascii_digit) {
        return true;
    }
    b.len() >= 24
        && b.iter().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'+' | b'/' | b'=')
        })
        && b.iter().any(u8::is_ascii_digit)
        && b.iter().any(u8::is_ascii_alphabetic)
}

/// Credential/session/identity header: never emitted as a literal.
fn is_credential_header(lname: &str) -> bool {
    if lname == "user-agent" || lname.starts_with("sec-fetch-") || lname.starts_with("sec-ch-") {
        return false;
    }
    super::sanitize::is_sensitive_header(lname)
        || SENSITIVE_WORDS.iter().any(|w| lname.contains(w))
        || lname
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| SENSITIVE_SHORT_WORDS.contains(&word))
}

/// Origin (`scheme://host`) and path of a URL, without query, fragment or path
/// parameters.
fn origin_and_path(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    url.split(';').next().unwrap_or(url).to_string()
}

/// Navigation tokens of a URL: path segments, the resource name without
/// extension/`_JLIBS` and query values. They are candidates for a structural
/// constant (`op=S37`, `page=NatLogon`, `SIM1000X.html`).
fn navigation_tokens(url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let url = url.split('#').next().unwrap_or(url);
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };
    let path = match path.split_once('/') {
        Some((_, p)) => p,
        None => "",
    };
    for segment in path.split('/') {
        // `;name=value` in the path is data, never navigation.
        let segment = segment.split(';').next().unwrap_or(segment).trim();
        if segment.is_empty() {
            continue;
        }
        out.push(segment.to_string());
        if let Some((stem, _ext)) = segment.rsplit_once('.') {
            if !stem.is_empty() {
                out.push(stem.to_string());
                if let Some(base) = stem.strip_suffix("_JLIBS") {
                    if !base.is_empty() {
                        out.push(base.to_string());
                    }
                }
            }
        }
    }
    if let Some(query) = query {
        for (_, value) in form_pairs(query) {
            if !value.is_empty() {
                out.push(value);
            }
        }
    }
    out
}

/// Safe Python name for a parameter (`[a-z0-9_]`, does not start with a digit).
fn sanitize_name(raw: &str) -> String {
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    name = name.trim_matches('_').to_string();
    if name.is_empty() || name.as_bytes()[0].is_ascii_digit() {
        name = format!("param_{name}");
    }
    name.truncate(40);
    if matches!(name.as_str(), "confirm" | "confirmar" | "base_url" | "help" | "h") {
        name = format!("p_{name}");
    }
    name
}

#[derive(Debug, Clone)]
struct Param {
    name: String,
    default: Option<String>,
    captured: String,
    note: String,
}

/// What a step must deliver in its own response for the following steps of the
/// chain (checked in the step, before any other request).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Expectation {
    Cookie(String),
    Header(String),
    Control(String, usize),
    Field(String),
    /// Generic body (extraction by context): requires a non-empty response.
    Body,
}

impl Expectation {
    fn python(&self) -> String {
        match self {
            Expectation::Cookie(name) => format!("('cookie', {}, 0)", lit(name)),
            Expectation::Header(name) => format!("('header', {}, 0)", lit(name)),
            Expectation::Control(name, index) => format!("('control', {}, {index})", lit(name)),
            Expectation::Field(name) => format!("('field', {}, 0)", lit(name)),
            Expectation::Body => "('body', 'body', 0)".to_string(),
        }
    }
}

/// Where the value was found in the producer's response.
enum Located {
    Control(String, usize),
    Field(String),
    Body,
}

#[derive(Default)]
struct Params {
    list: Vec<Param>,
    /// Fragments built on the client (captured value → expression), so that the
    /// same fragment in opaque fields uses the same parameter.
    client_parts: Vec<(String, String)>,
}

impl Params {
    /// Registers (or reuses) a parameter; returns the expression `P[...]`.
    /// The same name with a different captured value becomes another parameter
    /// (`_2`…). `constant` can only be `true` when there is proof that the value
    /// is a protocol constant; without it the parameter is required and the
    /// captured value does not become the default.
    fn get(
        &mut self,
        raw: &str,
        captured: &str,
        sensitive: bool,
        note: &str,
        constant: bool,
    ) -> String {
        let base = sanitize_name(raw);
        let mut name = base.clone();
        let mut n = 1;
        loop {
            match self.list.iter().find(|p| p.name == name) {
                Some(p) if p.captured == captured => break,
                Some(_) => {
                    n += 1;
                    name = format!("{base}_{n}");
                }
                None => {
                    let default =
                        (!sensitive && constant && !captured.is_empty() && captured.len() <= 200)
                            .then(|| captured.to_string());
                    self.list.push(Param {
                        name: name.clone(),
                        default,
                        captured: captured.to_string(),
                        note: note.to_string(),
                    });
                    break;
                }
            }
        }
        format!("P[{}]", lit(&name))
    }
}

/// Piece of an assembled value: literal or Python expression.
enum Piece {
    Lit(String),
    Expr(String),
}

fn pieces_expr(pieces: Vec<Piece>) -> String {
    let parts: Vec<String> = pieces
        .into_iter()
        .filter_map(|p| match p {
            Piece::Lit(s) if s.is_empty() => None,
            Piece::Lit(s) => Some(lit(&s)),
            Piece::Expr(e) => Some(e),
        })
        .collect();
    match parts.len() {
        0 => "''".to_string(),
        1 => parts.into_iter().next().unwrap_or_default(),
        _ => parts.join(" + "),
    }
}

/// Splits out of a literal fragment the values that look like user input.
fn scrub_literal(text: &str, params: &mut Params) -> Vec<Piece> {
    let bytes = text.as_bytes();
    let mut hits: Vec<(usize, usize, &str)> = Vec::new();
    for i in 0..bytes.len() {
        if is_plate_at(bytes, i) {
            hits.push((i, i + 7, "placa"));
        }
    }
    for (kw, name, min, max) in [
        ("v_cpf", "cpf", 11usize, 11usize),
        ("v_cnpj", "cnpj", 14, 14),
        ("v_renavam", "renavam", 9, 11),
    ] {
        let mut from = 0;
        while let Some(p) = text[from..].find(kw) {
            let start = from + p + kw.len();
            let digits = bytes[start..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits >= min {
                let end = start + digits.min(max);
                hits.push((start, end, name));
            }
            from = start;
        }
    }
    let mut client: Vec<(usize, usize, String)> = Vec::new();
    for (value, expr) in &params.client_parts {
        let mut from = 0;
        while let Some(p) = text[from..].find(value.as_str()) {
            client.push((from + p, from + p + value.len(), expr.clone()));
            from += p + value.len();
        }
    }
    let mut marks: Vec<(usize, usize, Option<&str>, Option<String>)> = hits
        .into_iter()
        .map(|(a, b, n)| (a, b, Some(n), None))
        .collect();
    marks.extend(client.into_iter().map(|(a, b, e)| (a, b, None, Some(e))));
    marks.sort_by_key(|m| m.0);
    let mut out = Vec::new();
    let mut at = 0;
    for (start, end, name, expr) in marks {
        if start < at {
            continue;
        }
        out.push(Piece::Lit(text[at..start].to_string()));
        match (name, expr) {
            (Some(name), _) => out.push(Piece::Expr(params.get(
                name,
                &text[start..end],
                true,
                "user input inside opaque field",
                false,
            ))),
            (_, Some(expr)) => out.push(Piece::Expr(expr)),
            _ => {}
        }
        at = end;
    }
    out.push(Piece::Lit(text[at..].to_string()));
    out
}

// ---------------------------------------------------------------------------
// Decoding of captured bodies
// ---------------------------------------------------------------------------

fn percent_decode(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit() =>
            {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'%'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn form_pairs(text: &str) -> Vec<(String, String)> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split('&')
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(part), String::new()),
        })
        .collect()
}

fn response_text(request: &LogicalRequest, source: &dyn BodySource) -> Option<String> {
    if !matches!(
        request.response_body.state,
        BodyState::Captured | BodyState::Truncated
    ) {
        return None;
    }
    let loaded = source.load(request.response_body.attachment.as_deref()?)?;
    Some(String::from_utf8_lossy(&loaded.bytes).into_owned())
}

fn char_floor(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn char_ceil(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Gerador
// ---------------------------------------------------------------------------

struct Gen<'a> {
    session: &'a SessionV1,
    source: &'a dyn BodySource,
    step_ids: HashSet<String>,
    /// Step ids in plan order: a value whose producer ended up outside the chain
    /// can be extracted from the equivalent step that is inside it.
    steps: Vec<String>,
    params: Params,
    warnings: Vec<Warning>,
    /// Notes (they become comments) of the step being built.
    notes: Vec<String>,
    /// Constancy proof: (field, value) → number of distinct requests with that
    /// pair. Computed once, on demand.
    occurrences: Option<HashMap<(String, String), usize>>,
    /// Cache of "value appears in some response".
    response_hits: HashMap<String, bool>,
    /// Values that the chain itself uses as a navigation route: path segment,
    /// page/resource name or query value of `steps`/`pages`. They are structural
    /// constants, not session data.
    structural: BTreeSet<String>,
    /// Producer step → what its response must contain for the following
    /// consumers (filled in when each consumer is generated).
    expectations: BTreeMap<String, BTreeSet<Expectation>>,
    /// Indexes (into `opts.adapter_encoders`) of the encoders used.
    encoders_used: BTreeSet<usize>,
    /// Claimed field → (part name, value) → number of session requests that
    /// carry it (constancy proof of the parts).
    part_counts: HashMap<String, HashMap<(String, String), usize>>,
    /// Fields claimed by an adapter (to prune unused producers).
    claimed_fields: BTreeSet<String>,
    /// (parameter, part/field where it enters): names only, for the trace.
    param_uses: BTreeSet<(String, String)>,
}

impl Gen<'_> {
    /// Records that the expression `expr` uses parameters `P['name']` in `part`.
    fn note_params(&mut self, part: &str, expr: &str) {
        let mut rest = expr;
        while let Some(at) = rest.find("P['") {
            let after = &rest[at + 3..];
            let Some(end) = after.find("']") else { break };
            self.param_uses
                .insert((after[..end].to_string(), part.to_string()));
            rest = &after[end..];
        }
    }

    fn expect(&mut self, producer: &str, expectation: Expectation) {
        self.expectations
            .entry(producer.to_string())
            .or_default()
            .insert(expectation);
    }

    fn warn(&mut self, code: &str, message: String) {
        self.warnings.push(Warning::new(code, message));
    }

    fn who(step: &LogicalRequest, label: &str) -> String {
        format!("{} ({})", label, step.id)
    }

    /// (field, value) pairs that appear in the same field in ≥ 1 request,
    /// counting distinct requests. Cheap constancy proof: query fields and small
    /// form-urlencoded bodies (up to 1 MiB).
    fn occurrences(&mut self) -> &HashMap<(String, String), usize> {
        if self.occurrences.is_none() {
            let mut counts: HashMap<(String, String), usize> = HashMap::new();
            for request in &self.session.requests {
                let mut seen: HashSet<(String, String)> = HashSet::new();
                if let Some((_, query)) = request.url.split_once('?') {
                    let query = query.split('#').next().unwrap_or(query);
                    for (k, v) in form_pairs(query) {
                        if !v.is_empty() {
                            seen.insert((k.to_ascii_lowercase(), v));
                        }
                    }
                }
                let content_type = request
                    .request_headers
                    .first_value("content-type")
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if content_type.contains("x-www-form-urlencoded")
                    && request.request_body.has_bytes()
                {
                    if let Some(loaded) = request
                        .request_body
                        .attachment
                        .as_deref()
                        .and_then(|a| self.source.load(a))
                    {
                        if loaded.bytes.len() <= 1_048_576 {
                            let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
                            for (k, v) in form_pairs(&text) {
                                if !v.is_empty() {
                                    seen.insert((k.to_ascii_lowercase(), v));
                                }
                            }
                        }
                    }
                }
                for key in seen {
                    *counts.entry(key).or_default() += 1;
                }
            }
            self.occurrences = Some(counts);
        }
        self.occurrences.as_ref().expect("computed above")
    }

    /// Constancy proof: the same (field, value) in ≥ 2 distinct requests of the
    /// session AND the value never appears in a response (if the application
    /// produced it, it is a session value, not a protocol constant).
    fn is_proven_constant(&mut self, field: &str, value: &str) -> bool {
        if value.is_empty() || value.len() > 200 {
            return false;
        }
        let key = (field.to_ascii_lowercase(), value.to_string());
        let seen = self.occurrences().get(&key).copied().unwrap_or(0);
        seen >= 2 && !self.value_in_any_response(value)
    }

    /// `true` if the value appears in some captured response body.
    fn value_in_any_response(&mut self, value: &str) -> bool {
        if let Some(hit) = self.response_hits.get(value) {
            return *hit;
        }
        let needle = value.as_bytes();
        let mut hit = false;
        for request in &self.session.requests {
            if !matches!(
                request.response_body.state,
                BodyState::Captured | BodyState::Truncated
            ) {
                continue;
            }
            let Some(loaded) = request
                .response_body
                .attachment
                .as_deref()
                .and_then(|a| self.source.load(a))
            else {
                continue;
            };
            let hay = &loaded.bytes;
            if needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle) {
                hit = true;
                break;
            }
        }
        self.response_hits.insert(value.to_string(), hit);
        hit
    }

    /// Raw text of the producer's response, to locate context.
    fn producer_request(&self, evidence: &Evidence) -> Option<&LogicalRequest> {
        self.session.find_request(&evidence.request_id)
    }

    /// Expression that extracts, at runtime, the value of `origin` (or of the
    /// fragment `value`) from the producer's response. `None` if there is no way.
    fn source_expr(
        &mut self,
        origin: &ValueOrigin,
        value: &str,
        step: &LogicalRequest,
        label: &str,
    ) -> Option<String> {
        let usable = |e: &&Evidence| self.step_ids.contains(&e.request_id);
        let evidence = origin
            .oldest
            .and_then(|i| origin.evidences.get(i))
            .filter(usable)
            .or_else(|| {
                origin
                    .evidences
                    .iter()
                    .find(|e| e.role == Role::Produced && usable(e))
            })?;
        let producer = self.producer_request(evidence)?.clone();
        let who = lit(&Self::who(step, label));
        let rid = lit(&evidence.request_id);
        let field = evidence.field.clone();
        match evidence.scope {
            ProducerScope::SetCookie => {
                let name = field?;
                self.expect(&evidence.request_id, Expectation::Cookie(name.clone()));
                Some(format!("get_cookie(S, {}, {who})", lit(&name)))
            }
            ProducerScope::ResponseHeader | ProducerScope::Location => {
                let name = field.unwrap_or_else(|| "location".to_string());
                self.expect(&evidence.request_id, Expectation::Header(name.clone()));
                Some(format!("get_header(R[{rid}], {}, {who})", lit(&name)))
            }
            ProducerScope::ResponseBody => {
                let text = response_text(&producer, self.source)?;
                let (container, container_text, whole, located) =
                    self.body_container(&producer, &text, evidence, value, &rid, &who)?;
                self.expect(
                    &evidence.request_id,
                    match located {
                        Located::Control(name, index) => Expectation::Control(name, index),
                        Located::Field(name) => Expectation::Field(name),
                        Located::Body => Expectation::Body,
                    },
                );
                if whole {
                    return Some(container);
                }
                let pos = locate(&container_text, value, evidence, &producer, &text)?;
                let (before, after) = context_for(&container_text, pos, value.len());
                Some(format!(
                    "ctx_extract({container}, {}, {}, {who})",
                    lit(&before),
                    lit(&after)
                ))
            }
        }
    }

    /// Value that the chain generates, but whose recorded producer ended up
    /// outside it (earlier round, equivalent page): searches the earlier steps of
    /// the plan for a control/field/literal of the page with the same name and
    /// value and extracts it at runtime. This way `STAMP=INIT` from the cscform
    /// does not become `--stamp`.
    fn chain_definition_expr(
        &mut self,
        name: &str,
        value: &str,
        step: &LogicalRequest,
    ) -> Option<String> {
        if value.is_empty() || value.len() > 200 || looks_opaque_id(value) {
            return None;
        }
        let pos = self.steps.iter().position(|id| id == &step.id)?;
        let who = lit(&Self::who(step, name));
        let previous: Vec<String> = self.steps[..pos].to_vec();
        for rid in previous {
            let producer = self.session.find_request(&rid)?.clone();
            let Some(text) = response_text(&producer, self.source) else {
                continue;
            };
            // 1. Page control with the same name and the same value.
            let mut index = 0usize;
            for control in &html_controls(&text) {
                if control.name != name {
                    continue;
                }
                if control.value == value {
                    self.expect(&rid, Expectation::Control(name.to_string(), index));
                    self.notes.push(format!(
                        "{name}: defined by the page control ({rid}); extracted at runtime"
                    ));
                    return Some(format!(
                        "html_control(R[{}], {}, {}, {who})",
                        lit(&rid),
                        lit(name),
                        index
                    ));
                }
                index += 1;
            }
            // 2. Page form/JSON field with the same name and value.
            if form_pairs(&text)
                .iter()
                .any(|(k, v)| k == name && v == value)
            {
                self.expect(&rid, Expectation::Field(name.to_string()));
                self.notes.push(format!(
                    "{name}: defined by a page field ({rid}); extracted at runtime"
                ));
                return Some(format!(
                    "body_field(R[{}], {}, {who})",
                    lit(&rid),
                    lit(name)
                ));
            }
            // 3. Literal quoted next to the name in the page script.
            if let Some(expr) = self.page_literal_expr(&text, &rid, name, value, &who) {
                return Some(expr);
            }
        }
        None
    }

    /// Quoted literal, cited near the field name, in the page script.
    fn page_literal_expr(
        &mut self,
        text: &str,
        rid: &str,
        name: &str,
        value: &str,
        who: &str,
    ) -> Option<String> {
        let lower = text.to_ascii_lowercase();
        let needle = name.to_ascii_lowercase();
        let mut search = 0usize;
        while let Some(rel) = lower[search..].find(&needle) {
            let at = search + rel;
            let end = char_ceil(text, at + needle.len() + 96);
            let window = text.get(at..end)?;
            for quote in ['\'', '"'] {
                let literal = format!("{quote}{value}{quote}");
                if let Some(off) = window.find(&literal) {
                    let value_at = at + off + quote.len_utf8();
                    let (before, after) = context_for(text, value_at, value.len());
                    self.expect(rid, Expectation::Body);
                    self.notes.push(format!(
                        "{name}: literal from the page ({rid}); extracted at runtime"
                    ));
                    return Some(format!(
                        "ctx_extract(R[{}].text, {}, {}, {who})",
                        lit(rid),
                        lit(&before),
                        lit(&after)
                    ));
                }
            }
            search = at + needle.len();
        }
        None
    }

    /// Where to look: HTML control, form/JSON field or the whole body. Returns
    /// (container expression, container text, whole value?, location for the
    /// check in the producer step).
    fn body_container(
        &self,
        producer: &LogicalRequest,
        text: &str,
        evidence: &Evidence,
        value: &str,
        rid: &str,
        who: &str,
    ) -> Option<(String, String, bool, Located)> {
        if let Some(field) = evidence.field.as_deref() {
            if evidence.html_control {
                let controls = html_controls(text);
                let offset = evidence.producer_offset.unwrap_or(0) as usize;
                let chosen = controls
                    .iter()
                    .filter(|c| c.name == field)
                    .enumerate()
                    .find(|(_, c)| offset >= c.start && offset <= c.end)
                    .map(|(i, c)| (i, c.value.clone()));
                let (index, ctext) = chosen.or_else(|| {
                    controls
                        .iter()
                        .filter(|c| c.name == field)
                        .enumerate()
                        .find(|(_, c)| c.value.contains(value))
                        .map(|(i, c)| (i, c.value.clone()))
                })?;
                let expr = format!("html_control(R[{rid}], {}, {index}, {who})", lit(field));
                let whole = ctext == value && evidence.kind == EvidenceKind::SameField;
                return Some((
                    expr,
                    ctext,
                    whole,
                    Located::Control(field.to_string(), index),
                ));
            }
            // Form/JSON field; or script variable (in that case the raw body).
            let fields = form_pairs(text);
            if let Some((_, v)) = fields.iter().find(|(k, _)| k == field) {
                let expr = format!("body_field(R[{rid}], {}, {who})", lit(field));
                let whole = v == value && evidence.kind == EvidenceKind::SameField;
                return Some((expr, v.clone(), whole, Located::Field(field.to_string())));
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(v) = json_find(&json, field) {
                    let expr = format!("body_field(R[{rid}], {}, {who})", lit(field));
                    let whole = v == value && evidence.kind == EvidenceKind::SameField;
                    return Some((expr, v, whole, Located::Field(field.to_string())));
                }
            }
        }
        let _ = producer;
        Some((
            format!("R[{rid}].text"),
            text.to_string(),
            false,
            Located::Body,
        ))
    }

    /// Expression for a scalar value of `step` (body field, query or header).
    fn value_expr(
        &mut self,
        step: &LogicalRequest,
        origin: Option<&ValueOrigin>,
        origins: &ValueOrigins,
        name: &str,
        value: &str,
        scope: ConsumedScope,
    ) -> String {
        let label = name.to_string();
        let sensitive =
            is_sensitive_name(name) || looks_sensitive_value(value) || contains_pii(value);
        // Value also seen in a static resource/context: protocol constant.
        let in_context = origin.is_some_and(|o| !o.context.is_empty());
        let Some(origin) = origin else {
            return self.fallback_param(name, value, sensitive, in_context, true);
        };
        match origin.status {
            OriginStatus::Redacted => {
                self.notes.push(format!(
                    "{name}: value redacted in the capture; provide it through the parameter"
                ));
                self.params
                    .get(name, "", true, "redacted in capture", false)
            }
            OriginStatus::Origin | OriginStatus::Ambiguous => {
                if let Some(expr) = self.source_expr(origin, value, step, &label) {
                    let how = match origin.confidence {
                        Some(crate::flow::Confidence::Strong) => "strong",
                        _ => "possible",
                    };
                    let amb = if origin.status == OriginStatus::Ambiguous {
                        "; ambiguous: uses the oldest producer"
                    } else {
                        ""
                    };
                    self.notes
                        .push(format!("{name}: extracted at runtime (origin {how}{amb})"));
                    expr
                } else if let Some(expr) = self.chain_definition_expr(name, value, step) {
                    expr
                } else {
                    self.fallback_param(name, value, sensitive, in_context, false)
                }
            }
            OriginStatus::Composite if scope == ConsumedScope::Body => {
                self.opaque_expr(step, origins, name, value)
            }
            _ => {
                if let Some(pc) = origin.partial_composition.first() {
                    if let Some(expr) = self.partial_expr(step, name, value, pc) {
                        return expr;
                    }
                }
                let structural = origin.partial_composition.is_empty();
                if structural {
                    if let Some(expr) = self.chain_definition_expr(name, value, step) {
                        return expr;
                    }
                }
                self.fallback_param(name, value, sensitive, in_context, structural)
            }
        }
    }

    /// Parameter for a value with no observed origin: the captured value only
    /// becomes the default with a proof of constancy or when it is a structural
    /// constant of the chain itself (route/navigation); otherwise it is
    /// required.
    fn fallback_param(
        &mut self,
        name: &str,
        value: &str,
        sensitive: bool,
        in_context: bool,
        structural_ok: bool,
    ) -> String {
        if value.is_empty() {
            return "''".to_string();
        }
        let structural = structural_ok
            && !value.is_empty()
            && value.len() <= 200
            && !looks_opaque_id(value)
            && self.structural.contains(value);
        let constant = !sensitive
            && (in_context
                || structural
                || (!looks_opaque_id(value) && self.is_proven_constant(name, value)));
        if constant {
            self.notes.push(if structural {
                format!(
                    "{name}: structural constant (route/navigation); parameter with the captured value as default"
                )
            } else {
                format!(
                    "{name}: proven constant; parameter with the captured value as default"
                )
            });
        } else {
            self.notes.push(format!(
                "{name}: no observed origin; required parameter, no default"
            ));
        }
        self.params.get(
            name,
            value,
            sensitive,
            if constant {
                if structural {
                    "structural constant"
                } else {
                    "protocol constant"
                }
            } else {
                "no observed origin"
            },
            constant,
        )
    }

    /// `partialComposition`: part extracted from the producer + part assembled on the client.
    fn partial_expr(
        &mut self,
        step: &LogicalRequest,
        name: &str,
        value: &str,
        pc: &crate::flow::PartialComposition,
    ) -> Option<String> {
        let producer = self.session.find_request(&pc.producer_request_id)?.clone();
        if !self.step_ids.contains(&producer.id) {
            return None;
        }
        let end = pc.start + pc.length;
        let piece = value.get(pc.start..end)?;
        let text = response_text(&producer, self.source)?;
        let pos = text.find(piece)?;
        let rid = lit(&producer.id);
        let who = lit(&Self::who(step, name));
        self.expect(&pc.producer_request_id, Expectation::Body);
        let (cb, ca) = context_for(&text, pos, piece.len());
        let extracted = format!(
            "ctx_extract(R[{rid}].text, {}, {}, {who})",
            lit(&cb),
            lit(&ca)
        );
        let mut pieces = Vec::new();
        let before = &value[..pc.start];
        let after = &value[end..];
        if !before.is_empty() {
            // Part assembled on the client: no value proof, always required.
            pieces.push(Piece::Expr(self.params.get(
                &format!("{name}_cliente_inicio"),
                before,
                false,
                "assembled on client",
                false,
            )));
        }
        pieces.push(Piece::Expr(extracted));
        if !after.is_empty() {
            let expr = self.params.get(
                &format!("{name}_cliente"),
                after,
                false,
                "assembled on client",
                false,
            );
            self.params
                .client_parts
                .push((after.to_string(), expr.clone()));
            pieces.push(Piece::Expr(expr));
        }
        self.notes.push(format!(
            "{name}: assembled on the client: complete here (initial part extracted from the producer {}; the rest is the parameter {}_cliente, required)",
            pc.producer_request_id,
            sanitize_name(name)
        ));
        Some(pieces_expr(pieces))
    }

    /// Opaque field (`composite`): concatenates extracted fragments and literals.
    fn opaque_expr(
        &mut self,
        step: &LogicalRequest,
        origins: &ValueOrigins,
        name: &str,
        value: &str,
    ) -> String {
        let mut parts: Vec<&ValueOrigin> = origins
            .values
            .iter()
            .filter(|v| v.scope == ConsumedScope::Body && v.parent.as_deref() == Some(name))
            .filter(|v| v.offset.is_some())
            .collect();
        parts.sort_by_key(|v| v.offset.unwrap_or(0));
        let mut pieces: Vec<Piece> = Vec::new();
        let mut at = 0usize;
        let mut dynamic = 0usize;
        for part in parts {
            let start = part.offset.unwrap_or(0) as usize;
            let end = start + part.length;
            if start < at
                || end > value.len()
                || !value.is_char_boundary(start)
                || !value.is_char_boundary(end)
            {
                continue;
            }
            if start > at {
                pieces.extend(scrub_literal(&value[at..start], &mut self.params));
            }
            let text = &value[start..end];
            // Fragment with only letters/symbols (no digits) and only a possible
            // origin: a coincidence with the producer's text, probably a protocol
            // constant. It stays literal, with a note.
            let constant_like = part.confidence != Some(crate::flow::Confidence::Strong)
                && !text.bytes().any(|b| b.is_ascii_digit());
            if constant_like
                && matches!(part.status, OriginStatus::Origin | OriginStatus::Ambiguous)
            {
                self.notes.push(format!(
                    "{name}: fragment {start}..{end} without digits and only a possible origin: treated as a protocol constant"
                ));
            }
            let expr = (matches!(part.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                && !constant_like)
                .then(|| self.source_expr(part, text, step, &format!("{name}[{start}]")))
                .flatten();
            match expr {
                Some(e) => {
                    dynamic += 1;
                    let amb = if part.status == OriginStatus::Ambiguous {
                        ", ambiguous"
                    } else {
                        ""
                    };
                    self.notes.push(format!(
                        "{name}: fragment {start}..{end} extracted at runtime (possible origin{amb})"
                    ));
                    pieces.push(Piece::Expr(format!(
                        "checked({e}, {}, {})",
                        end - start,
                        lit(&format!("{name}[{start}]"))
                    )));
                }
                None => pieces.extend(scrub_literal(text, &mut self.params)),
            }
            at = end;
        }
        if at < value.len() {
            pieces.extend(scrub_literal(&value[at..], &mut self.params));
        }
        if dynamic == 0 {
            self.notes.push(format!(
                "{name}: opaque field without dynamic fragments; kept as captured"
            ));
        }
        pieces_expr(pieces)
    }
}

/// Minimal context (before, after) that uniquely identifies
/// `container[pos..pos+len]`; it starts short so that the script is not tied
/// to neighboring text that changes (page names, deltas). Empty before = start
/// of the text; empty after = end of the text.
fn context_for(container: &str, pos: usize, len: usize) -> (String, String) {
    let end = pos + len;
    let b0 = char_ceil(container, pos.saturating_sub(CONTEXT_BEFORE));
    let a1 = char_floor(container, end + CONTEXT_AFTER);
    let before_full = &container[b0..pos];
    let after_full = &container[end..a1];
    let before_chars: Vec<usize> = before_full.char_indices().map(|(i, _)| i).collect();
    let after_chars: Vec<usize> = after_full
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .collect();
    // Candidates: from shortest to longest (min. 4 before, 1 after).
    let befores: Vec<&str> = if before_full.is_empty() {
        vec![""]
    } else {
        let mut v: Vec<&str> = before_chars
            .iter()
            .rev()
            .map(|&i| &before_full[i..])
            .filter(|b| b.chars().count() >= 4.min(before_full.chars().count()))
            .collect();
        v.dedup();
        v
    };
    let afters: Vec<&str> = if after_full.is_empty() {
        vec![""]
    } else {
        after_chars.iter().map(|&i| &after_full[..i]).collect()
    };
    for b in &befores {
        for a in &afters {
            if simulate(container, b, a) == Some((pos, end)) {
                return ((*b).to_string(), (*a).to_string());
            }
        }
    }
    (before_full.to_string(), after_full.to_string())
}

/// Reproduces `re.search(esc(b) + '(.+?)' + esc(a) or \\Z)`: where the script
/// would extract (start, end) in this text. Empty before anchors at the start.
fn simulate(container: &str, before: &str, after: &str) -> Option<(usize, usize)> {
    let starts: Vec<usize> = if before.is_empty() {
        vec![0]
    } else {
        container
            .match_indices(before)
            .map(|(i, _)| i + before.len())
            .collect()
    };
    for start in starts {
        if start >= container.len() {
            continue;
        }
        let first = start + container[start..].chars().next().map_or(1, char::len_utf8);
        if after.is_empty() {
            return Some((start, container.len()));
        }
        if let Some(i) = container[first..].find(after) {
            return Some((start, first + i));
        }
    }
    None
}

/// Position of `value` in the producer's container (by offset when it matches, otherwise by search).
fn locate(
    container: &str,
    value: &str,
    evidence: &Evidence,
    _producer: &LogicalRequest,
    raw: &str,
) -> Option<usize> {
    if container == raw {
        if let Some(off) = evidence.producer_offset {
            let off = off as usize;
            if raw.get(off..off + value.len()) == Some(value) {
                return Some(off);
            }
        }
    }
    container.find(value)
}

fn json_find(value: &serde_json::Value, key: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == key {
                    return Some(match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    });
                }
                if let Some(found) = json_find(v, key) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(|v| json_find(v, key)),
        _ => None,
    }
}

fn split_origin(url: &str) -> (&str, &str) {
    let Some(scheme_end) = url.find("://") else {
        return ("", url);
    };
    let rest = &url[scheme_end + 3..];
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    url.split_at(scheme_end + 3 + cut)
}

/// Python expression (dict/list/value) for a JSON body; each leaf gets the same
/// treatment as a form field (extraction, parameter, constant).
#[allow(clippy::too_many_arguments)]
fn json_expr<'a>(
    gen: &mut Gen,
    request: &LogicalRequest,
    origins: &ValueOrigins,
    value: &serde_json::Value,
    path: &str,
    find: &dyn Fn(&str) -> Option<&'a ValueOrigin>,
    scope: ConsumedScope,
    depth: usize,
) -> String {
    use serde_json::Value;
    let last = path
        .rsplit(['.', '['])
        .next()
        .unwrap_or(path)
        .trim_end_matches(']');
    let leaf = |gen: &mut Gen, text: String| {
        let expr = gen.value_expr(
            request,
            find(path).or_else(|| find(last)),
            origins,
            path,
            &text,
            scope,
        );
        gen.note_params(path, &expr);
        expr
    };
    match value {
        Value::Object(map) => {
            let items: Vec<String> = map
                .iter()
                .map(|(key, child)| {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    format!(
                        "{}: {}",
                        lit(key),
                        json_expr(
                            gen,
                            request,
                            origins,
                            child,
                            &child_path,
                            find,
                            scope,
                            depth
                        )
                    )
                })
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        Value::Array(items) => {
            let items: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(i, child)| {
                    json_expr(
                        gen,
                        request,
                        origins,
                        child,
                        &format!("{path}[{i}]"),
                        find,
                        scope,
                        depth,
                    )
                })
                .collect();
            format!("[{}]", items.join(", "))
        }
        Value::String(text) => match json_container(text).filter(|_| depth < 8) {
            // JSON inside a JSON string: decomposed and reassembled in the same place.
            Some(inner) => format!(
                "json.dumps({})",
                json_expr(gen, request, origins, &inner, path, find, scope, depth + 1)
            ),
            None => leaf(gen, text.clone()),
        },
        Value::Number(number) => format!("json_num({})", leaf(gen, number.to_string())),
        Value::Bool(flag) => format!("json_bool({})", leaf(gen, flag.to_string())),
        Value::Null => "None".to_string(),
    }
}

/// Detectors of personal data/credentials in free text: value after a sensitive
/// name (`"cpf":`, `nome=`), e-mail, JWT, Bearer/Basic, plate and long digit
/// sequences (CPF, CNPJ, card with Luhn, phone). Returns `(start, end, kind)`,
/// without repeating the value.
fn pii_spans(text: &str, wide: bool) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    let is_name_byte = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.');
    // 1. Value right after a sensitive name (`nome=`, `"cpf":"`, `<email>`).
    let mut i = 0;
    while i < bytes.len() {
        if is_name_byte(bytes[i]) && (i == 0 || !is_name_byte(bytes[i - 1])) {
            let mut j = i;
            while j < bytes.len() && is_name_byte(bytes[j]) {
                j += 1;
            }
            let name = &text[i..j];
            if (wide && is_sensitive_name(name)) || is_pii_name(name) {
                let mut k = j;
                while k < bytes.len() && matches!(bytes[k], b'"' | b'\'' | b' ') {
                    k += 1;
                }
                if k < bytes.len() && matches!(bytes[k], b'=' | b':' | b'>') {
                    k += 1;
                    while k < bytes.len() && matches!(bytes[k], b'"' | b'\'' | b' ') {
                        k += 1;
                    }
                    let mut e = k;
                    while e < bytes.len()
                        && !matches!(
                            bytes[e],
                            b'"' | b'\'' | b'&' | b'<' | b',' | b'}' | b'\n' | b'\r'
                        )
                    {
                        e += 1;
                    }
                    if e > k && text.is_char_boundary(k) && text.is_char_boundary(e) {
                        spans.push((k, e, name.to_string()));
                    }
                } else if k > j && is_secret_word(name) {
                    // `senha hunter2hunter2`: secret right after the word.
                    let mut e = k;
                    while e < bytes.len() && !bytes[e].is_ascii_whitespace() {
                        e += 1;
                    }
                    if e - k >= 6 && text.is_char_boundary(k) && text.is_char_boundary(e) {
                        spans.push((k, e, name.to_string()));
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // 2. E-mail, JWT, plate, chassis and long digit sequences (CPF/CNPJ/card/phone).
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if is_plate_dash_at(bytes, i) {
            spans.push((i, i + 8, "placa".to_string()));
            i += 8;
            continue;
        }
        if is_vin_at(bytes, i) {
            spans.push((i, i + 17, "chassi".to_string()));
            i += 17;
            continue;
        }
        if b.is_ascii_digit() {
            let mut j = i;
            let mut digits = 0;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || (matches!(bytes[j], b'.' | b'-' | b' ' | b'/')
                        && j + 1 < bytes.len()
                        && bytes[j + 1].is_ascii_digit()))
            {
                if bytes[j].is_ascii_digit() {
                    digits += 1;
                }
                j += 1;
            }
            if digits >= 8 {
                let kind = digit_kind(&text[i..j]);
                if !kind.is_empty() {
                    spans.push((i, j, kind));
                }
            }
            i = j.max(i + 1);
            continue;
        }
        if is_plate_at(bytes, i) {
            spans.push((i, i + 7, "placa".to_string()));
            i += 7;
            continue;
        }
        if bytes[i..].starts_with(b"eyJ") {
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'.' | b'-' | b'_'))
            {
                j += 1;
            }
            spans.push((i, j, "token".to_string()));
            i = j;
            continue;
        }
        if b == b'@' {
            let mut s0 = i;
            while s0 > 0
                && (bytes[s0 - 1].is_ascii_alphanumeric()
                    || matches!(bytes[s0 - 1], b'.' | b'_' | b'-' | b'+'))
            {
                s0 -= 1;
            }
            let mut e = i + 1;
            while e < bytes.len()
                && (bytes[e].is_ascii_alphanumeric() || matches!(bytes[e], b'.' | b'-'))
            {
                e += 1;
            }
            if s0 < i && e > i + 1 {
                spans.push((s0, e, "email".to_string()));
            }
            i = e;
            continue;
        }
        i += 1;
    }
    for scheme in ["Bearer ", "Basic "] {
        let mut from = 0;
        while let Some(at) = text[from..].find(scheme) {
            let begin = from + at + scheme.len();
            let mut end = begin;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b'"' | b'\'')
            {
                end += 1;
            }
            if end - begin >= 8 {
                spans.push((begin, end, "token".to_string()));
            }
            from = end.max(begin);
        }
    }
    spans
}

fn is_secret_word(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["senha", "password", "passwd", "secret", "token"]
        .iter()
        .any(|w| lower == *w)
}

fn digit_kind(run: &str) -> String {
    let digits: Vec<u32> = run.chars().filter_map(|c| c.to_digit(10)).collect();
    let luhn = || {
        digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, d)| {
                if i % 2 == 1 {
                    let x = d * 2;
                    if x > 9 {
                        x - 9
                    } else {
                        x
                    }
                } else {
                    *d
                }
            })
            .sum::<u32>()
            % 10
            == 0
    };
    let formatted = run.bytes().any(|b| !b.is_ascii_digit());
    // Epoch in seconds (10 digits starting with 15-19) is not a phone number.
    let epoch = digits.len() == 10 && matches!(digits[0], 1) && (5..=9).contains(&digits[1]);
    match digits.len() {
        14 => "cnpj".to_string(),
        15 | 16 if (3..=6).contains(&digits[0]) && luhn() => "cartao".to_string(),
        // Series 2 (2221–2720).
        16 if digits[0] == 2
            && (2221..=2720).contains(&digits[..4].iter().fold(0, |a, d| a * 10 + d))
            && luhn() =>
        {
            "cartao".to_string()
        }
        // 19 digits (Maestro/UnionPay/Discover): known prefixes only.
        19 if matches!(digits[0] * 10 + digits[1], 50 | 56..=58 | 60 | 62 | 67) && luhn() => {
            "cartao".to_string()
        }
        // Phone with country code 55: 12 or 13 digits.
        12 | 13 if digits[0] == 5 && digits[1] == 5 => "telefone".to_string(),
        11 => "cpf_ou_telefone".to_string(),
        10 if (formatted || !epoch)
            && (11..=99).contains(&(digits[0] * 10 + digits[1]))
            && (2..=5).contains(&digits[2]) =>
        {
            "telefone".to_string()
        }
        8..=12 if !epoch && digits[0] != 0 => "digitos_longos".to_string(),
        // Other long lengths: counters and protocol constants.
        _ => String::new(),
    }
}

/// Names whose value is personal data/a credential on its own (not only session/key).
fn is_pii_name(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "cpf",
        "cnpj",
        "renavam",
        "nome",
        "email",
        "telefone",
        "celular",
        "endereco",
        "endereço",
        "nascimento",
        "nasc",
        "cartao",
        "password",
        "passwd",
        "senha",
        "secret",
        "mae",
        "cvv",
    ];
    let lower = name.to_ascii_lowercase();
    WORDS.iter().any(|w| lower.contains(w))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| matches!(word, "rg" | "tel" | "fone"))
        || has_sensitive_abbreviation(name)
}

fn contains_pii(text: &str) -> bool {
    !pii_spans(&fold_width(text), false).is_empty()
}

/// Python string literals (`'...'`, `b'...'`) of a generated fragment, already
/// decoded. Comment lines are ignored.
fn python_literals(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in code.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != '\'' {
                i += 1;
                continue;
            }
            i += 1;
            let mut cur = String::new();
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    match chars[i] {
                        'n' => cur.push('\n'),
                        'r' => cur.push('\r'),
                        't' => cur.push('\t'),
                        'x' | 'u' | 'U' => {
                            let width = match chars[i] {
                                'x' => 2,
                                'u' => 4,
                                _ => 8,
                            };
                            let hex: String = chars[i + 1..].iter().take(width).collect();
                            if let Some(c) =
                                u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                            {
                                cur.push(c);
                            }
                            i += hex.chars().count();
                        }
                        other => cur.push(other),
                    }
                } else {
                    cur.push(chars[i]);
                }
                i += 1;
            }
            i += 1;
            out.push(cur);
        }
    }
    out
}

/// Final and single barrier: no emitted literal may contain detectable personal
/// data/credentials. Returns the kinds found (without values).
fn literal_pii_kinds(code: &str) -> Vec<String> {
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for literal in python_literals(code) {
        // The decoded form (percent-encoding, up to 3 layers) too: the detector
        // cannot be bypassed by encoding.
        let literal = fold_width(&literal);
        let mut views = vec![literal.clone()];
        let mut current = literal;
        for _ in 0..3 {
            if !current.contains('%') {
                break;
            }
            let next = percent_decode(&current);
            if next == current {
                break;
            }
            views.push(next.clone());
            current = next;
        }
        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        for view in &views {
            for (_, _, kind) in pii_spans(view, false) {
                let entry = found.entry(kind).or_default();
                *entry = (*entry).max(1);
            }
        }
        for (kind, n) in found {
            *kinds.entry(kind).or_default() += n;
        }
    }
    kinds
        .into_iter()
        .map(|(k, n)| format!("{k} ({n})"))
        .collect()
}

/// Text body resent as captured: detected sensitive/business values become
/// required parameters. Returns the expression (bytes) and how many values were
/// replaced.
fn literal_body_expr(gen: &mut Gen, text: &str) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut spans = pii_spans(text, true);
    spans.sort_by_key(|(start, end, _)| (*start, std::cmp::Reverse(*end)));
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = 0;
    let mut found = 0;
    for (start, end, name) in spans {
        if start < cursor || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        if start > cursor {
            parts.push(bytes_lit(&bytes[cursor..start]));
        }
        let expr = gen.fallback_param(
            &format!("corpo_{name}"),
            &text[start..end],
            true,
            false,
            false,
        );
        parts.push(format!("{expr}.encode('utf-8')"));
        cursor = end;
        found += 1;
    }
    if cursor < bytes.len() {
        parts.push(bytes_lit(&bytes[cursor..]));
    }
    if parts.is_empty() {
        parts.push("b''".to_string());
    }
    (parts.join(" + "), found)
}

/// URL with path parameters (`;jsessionid=...`): each value becomes a required
/// parameter (session data, never a literal). Returns the URL for the plan
/// (values replaced by `<name>`) and the Python expression.
fn path_param_expr(gen: &mut Gen, url_base: &str) -> (String, String) {
    let (origin, path) = split_origin(url_base);
    let pii_segment = |seg: &str| {
        let base = seg.split(';').next().unwrap_or(seg);
        contains_pii(&percent_decode(base))
    };
    if !path.contains(';') && !path.split('/').any(pii_segment) {
        return (
            url_base.to_string(),
            format!("rebase({}, base)", lit(url_base)),
        );
    }
    enum Part {
        Lit(String),
        Expr(String),
    }
    let mut parts: Vec<Part> = vec![Part::Lit(origin.to_string())];
    let mut plan = String::from(origin);
    let push_lit = |parts: &mut Vec<Part>, text: &str| match parts.last_mut() {
        Some(Part::Lit(existing)) => existing.push_str(text),
        _ => parts.push(Part::Lit(text.to_string())),
    };
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            push_lit(&mut parts, "/");
            plan.push('/');
        }
        let mut pieces = segment.split(';');
        let base = pieces.next().unwrap_or("");
        if pii_segment(base) {
            let expr = gen.fallback_param(
                &format!("path_segmento_{index}"),
                &percent_decode(base),
                true,
                false,
                false,
            );
            parts.push(Part::Expr(format!("urllib.parse.quote({expr}, safe='')")));
            plan.push_str(&format!("<path_segmento_{index}>"));
        } else {
            push_lit(&mut parts, base);
            plan.push_str(base);
        }
        for param in pieces {
            let (name, value) = param.split_once('=').unwrap_or((param, ""));
            push_lit(&mut parts, &format!(";{name}="));
            plan.push_str(&format!(";{name}=<{name}>"));
            let expr = gen.fallback_param(&format!("path_{name}"), value, true, false, false);
            gen.note_params(&format!("path:{name}"), &expr);
            parts.push(Part::Expr(format!("urllib.parse.quote({expr}, safe='')")));
        }
    }
    let mut out: Vec<String> = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        match part {
            Part::Lit(text) if i == 0 => out.push(format!("rebase({}, base)", lit(text))),
            Part::Lit(text) => out.push(lit(text)),
            Part::Expr(expr) => out.push(expr.clone()),
        }
    }
    (plan, out.join(" + "))
}

/// Static resource (script, css, image, font, media): never a step.
fn is_static(request: &LogicalRequest) -> bool {
    let media = request
        .response_headers
        .first_value("content-type")
        .or(request.response_body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = request
        .url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    media.contains("javascript")
        || media.contains("ecmascript")
        || media.contains("text/css")
        || media.starts_with("image/")
        || media.starts_with("font/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || [
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
}

fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

/// Conditional cache headers: they are not application values and do not prove
/// a dependency on a missing body.
const CONDITIONAL_HEADERS: &[&str] = &["if-modified-since", "if-none-match", "if-range"];

/// Value consumed by the chain that could only have come from a response without
/// an observable body.
#[derive(Debug, Clone)]
struct MissingBody {
    request_id: String,
    field: String,
    producers: Vec<Unobservable>,
}

/// Dependencies of the chain on responses without an observable body: a value
/// with no observed origin (not repeated, without partial composition, not a
/// conditional header) whose only clues are earlier responses that are
/// `unavailable`/`discarded`/`truncated`.
fn missing_body_dependencies(chain: &PrimingChain) -> Vec<MissingBody> {
    let mut out: Vec<MissingBody> = Vec::new();
    for value in &chain.unresolved {
        if value.status != OriginStatus::None
            || !value.partial_composition.is_empty()
            || value.unobservable.is_empty()
            || CONDITIONAL_HEADERS.contains(&value.field.to_ascii_lowercase().as_str())
        {
            continue;
        }
        for request_id in &value.request_ids {
            match out.iter_mut().find(|m| m.request_id == *request_id) {
                Some(entry) => {
                    if !entry.producers.is_empty() {
                        entry.field.push_str(", ");
                    }
                    entry.field.push_str(&value.field);
                }
                None => out.push(MissingBody {
                    request_id: request_id.clone(),
                    field: value.field.clone(),
                    producers: value.unobservable.clone(),
                }),
            }
        }
    }
    out
}

fn incomplete_chain_error(missing: &[MissingBody]) -> CoreError {
    let consumers: Vec<String> = missing
        .iter()
        .map(|m| format!("{} [{}]", m.request_id, m.field))
        .collect();
    let mut producers: Vec<String> = Vec::new();
    for entry in missing.iter().flat_map(|m| m.producers.iter()) {
        let text = format!("{} ({})", entry.request_id, entry.state);
        if !producers.contains(&text) {
            producers.push(text);
        }
    }
    let shown: Vec<String> = producers.iter().take(6).cloned().collect();
    let more = if producers.len() > shown.len() {
        format!(" and {} more", producers.len() - shown.len())
    } else {
        String::new()
    };
    let mut suggestions: Vec<String> = Vec::new();
    for entry in missing.iter().flat_map(|m| m.producers.iter()) {
        if let Some(suggestion) = &entry.suggestion {
            if !suggestions.contains(suggestion) {
                suggestions.push(suggestion.clone());
            }
        }
    }
    let suggestion = if suggestions.is_empty() {
        "no equivalent occurrence with an observable body in this session".to_string()
    } else {
        format!(
            "generate the script for the equivalent occurrence with a full body: {}",
            suggestions.join(", ")
        )
    };
    CoreError::Export {
        message: format!(
            "incomplete chain: {} value(s) depend on response(s) without an observable body ({}). \
             Responses without a body: {}{}. No captured value is used in their place. {}; or use \
             --allow-incomplete to generate the script with an explicit fail() in those steps.",
            missing.len(),
            consumers.join("; "),
            shown.join(", "),
            more,
            suggestion
        ),
    }
}

/// Generates the priming script for the request `target_request_id`.
pub fn to_python(
    session: &SessionV1,
    source: &dyn BodySource,
    target_request_id: &str,
    opts: &PrimingOptions,
) -> Result<ExportOutput> {
    to_python_and_uses(session, source, target_request_id, opts).map(|(output, _)| output)
}

/// `(parameter, part/field)` pairs that the plan generated from the capture
/// installs in the script, in the same pass that produces the script. `validate`
/// uses this to exempt only the parts that the plan really produces (never those
/// the trace declares). Part/field names are the generator's (`SESSIONID`,
/// `XML.sid`…), without values.
pub fn plan_parameter_uses(
    session: &SessionV1,
    source: &dyn BodySource,
    target_request_id: &str,
    opts: &PrimingOptions,
) -> Result<BTreeSet<(String, String)>> {
    to_python_and_uses(session, source, target_request_id, opts).map(|(_, uses)| uses)
}

fn to_python_and_uses(
    session: &SessionV1,
    source: &dyn BodySource,
    target_request_id: &str,
    opts: &PrimingOptions,
) -> Result<(ExportOutput, BTreeSet<(String, String)>)> {
    let (output, extras, uses) =
        to_python_with(session, source, target_request_id, opts, &HashSet::new())?;
    // Producer steps that no step references are dropped from the plan.
    let unreferenced: HashSet<String> = extras.into_iter().collect();
    if unreferenced.is_empty() {
        return Ok((output, uses));
    }
    let (output, _, uses) =
        to_python_with(session, source, target_request_id, opts, &unreferenced)?;
    Ok((output, uses))
}

/// Generated script, extra steps to prune and `(parameter, part)` pairs used.
type GeneratedPlan = (ExportOutput, Vec<String>, BTreeSet<(String, String)>);

fn to_python_with(
    session: &SessionV1,
    source: &dyn BodySource,
    target_request_id: &str,
    opts: &PrimingOptions,
    excluded_extras: &HashSet<String>,
) -> Result<GeneratedPlan> {
    // The steps come from the chain without an adapter: parts of a claimed field
    // have fine-grained origins (including in earlier rounds) that must not pull
    // in extra steps nor refuse a chain that the generator without an adapter
    // completes. The origins of the parts (with an adapter) only decide HOW each
    // value is obtained.
    let chain_flow = FlowOptions {
        adapters: Default::default(),
        ..opts.flow.clone()
    };
    let mut chain = priming_chain(session, source, target_request_id, &chain_flow)?;
    // Producers of the adapter's PARTS that were left outside the base chain and
    // belong to the same round (from the first base step on) join the plan, in
    // session order: no value with an observed origin becomes a literal just
    // because its producer was not in the plan. Producers of earlier rounds stay
    // out (round 7 rule).
    let mut extra_ids: Vec<String> = Vec::new();
    if !opts.flow.adapters.is_empty() {
        if let Ok(with_parts) = priming_chain(session, source, target_request_id, &opts.flow) {
            let base_start = chain
                .steps
                .iter()
                .filter_map(|s| s.started_at)
                .fold(f64::INFINITY, f64::min);
            let known: HashSet<String> = chain.steps.iter().map(|s| s.request_id.clone()).collect();
            let extras: Vec<_> = with_parts
                .steps
                .into_iter()
                .filter(|s| {
                    !known.contains(&s.request_id)
                        && s.request_id != target_request_id
                        && !excluded_extras.contains(&s.request_id)
                        && (s.started_at.is_some_and(|t| t >= base_start)
                            // Earlier round: only with a value produced by the
                            // response (strong ValueMatch), not by a field that
                            // merely repeats (SameField).
                            || s.reasons.iter().any(|r| {
                                r.strength == crate::flow::Strength::Strong
                                    && r.kind == EvidenceKind::ValueMatch
                            }))
                })
                .collect();
            if !extras.is_empty() {
                extra_ids = extras.iter().map(|s| s.request_id.clone()).collect();
                chain.steps.extend(extras);
                chain.steps.sort_by(|a, b| {
                    a.started_at
                        .unwrap_or(f64::INFINITY)
                        .total_cmp(&b.started_at.unwrap_or(f64::INFINITY))
                });
            }
        }
    }
    let missing = missing_body_dependencies(&chain);
    if !missing.is_empty() && !opts.allow_incomplete {
        return Err(incomplete_chain_error(&missing));
    }
    let target = session
        .find_request(target_request_id)
        .ok_or_else(|| CoreError::Export {
            message: format!("request {target_request_id} not found"),
        })?;
    // The target is the last step; if the chain does not include it (no dependencies), add it.
    let mut step_reqs: Vec<(&LogicalRequest, Vec<String>, String)> = Vec::new();
    for step in &chain.steps {
        if let Some(r) = session.find_request(&step.request_id) {
            if r.id != target.id && (is_static(r) || excluded_extras.contains(&r.id)) {
                continue;
            }
            let reasons: Vec<String> = std::iter::once(step.reason.clone())
                .chain(std::iter::once(format!(
                    "confidence {}",
                    match step.confidence {
                        crate::flow::Confidence::Strong => "strong",
                        crate::flow::Confidence::Possible => "possible",
                    }
                )))
                .collect();
            step_reqs.push((r, reasons, step.reason.clone()));
        }
    }
    if !step_reqs.iter().any(|(r, _, _)| r.id == target.id) {
        step_reqs.push((target, vec!["target request".to_string()], String::new()));
    }

    let mut structural: BTreeSet<String> = BTreeSet::new();
    for url in std::iter::once(target.url.as_str())
        .chain(chain.steps.iter().map(|s| s.url.as_str()))
        .chain(chain.pages.iter().map(|s| s.url.as_str()))
        .chain(chain.auxiliary_pages.iter().map(|s| s.url.as_str()))
    {
        structural.extend(navigation_tokens(url));
    }

    let mut gen = Gen {
        session,
        source,
        step_ids: step_reqs.iter().map(|(r, _, _)| r.id.clone()).collect(),
        steps: step_reqs.iter().map(|(r, _, _)| r.id.clone()).collect(),
        params: Params::default(),
        warnings: Vec::new(),
        notes: Vec::new(),
        occurrences: None,
        response_hits: HashMap::new(),
        structural,
        expectations: BTreeMap::new(),
        encoders_used: BTreeSet::new(),
        part_counts: HashMap::new(),
        claimed_fields: BTreeSet::new(),
        param_uses: BTreeSet::new(),
    };
    let (captured_origin, _) = split_origin(&target.url);
    let captured_origin = captured_origin.to_string();
    let mut foreign: BTreeSet<String> = BTreeSet::new();
    for (request, _, _) in &step_reqs {
        let (origin, _) = split_origin(&request.url);
        if origin != captured_origin
            && !opts
                .allow_origins
                .iter()
                .any(|a| a.trim_end_matches('/').eq_ignore_ascii_case(origin))
        {
            foreign.insert(origin.to_string());
        }
    }
    if !foreign.is_empty() {
        return Err(CoreError::Export {
            message: format!(
                "the chain contacts different origin(s) from the target ({}); refused. Pass --allow-origin <scheme://host[:port]> for each one you accept contacting",
                foreign.into_iter().collect::<Vec<_>>().join(", ")
            ),
        });
    }

    // With `allow_incomplete`, each affected consumer fails explicitly instead of
    // going on with the incomplete chain.
    let mut incomplete_steps: BTreeMap<String, String> = BTreeMap::new();
    if opts.allow_incomplete {
        for entry in &missing {
            let producers: Vec<String> = entry
                .producers
                .iter()
                .take(4)
                .map(|u| format!("{} ({})", u.request_id, u.state))
                .collect();
            let more = entry.producers.len().saturating_sub(producers.len());
            incomplete_steps.entry(entry.request_id.clone()).or_insert_with(|| {
                format!(
                    "incomplete chain: {} has no producer with an observable body ({}{}); generate the script for the equivalent target from another round",
                    entry.field,
                    producers.join(", "),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    }
                )
            });
        }
    }

    let mut plan = String::new();
    let mut unresolved_comments = String::new();
    struct GeneratedStep {
        body: String,
        method: String,
        data_arg: String,
    }
    let mut steps_out: Vec<GeneratedStep> = Vec::new();
    for u in &chain.unresolved {
        let _ = write!(
            unresolved_comments,
            "{}",
            comment(&format!(
                "unresolved: {} {} ({}){}",
                u.request_ids.join(", "),
                u.field,
                u.label,
                if u.partial_composition.is_empty() {
                    ""
                } else {
                    " — assembled on the client: complete here"
                }
            ))
        );
    }

    let mut has_unsafe = false;
    for (n, (request, reasons, _)) in step_reqs.iter().enumerate() {
        let n = n + 1;
        gen.notes.clear();
        let origins = value_origins(session, source, &request.id, &opts.flow)?;
        has_unsafe |= !is_idempotent(&request.method);

        let find_origin = |scope: ConsumedScope, field: &str, occ: usize| -> Option<&ValueOrigin> {
            origins.values.iter().find(|v| {
                v.scope == scope && v.parent.is_none() && v.field == field && v.occurrence == occ
            })
        };

        // URL and query
        let (url_base, query) = match request.url.split_once('?') {
            Some((b, q)) => (
                b.split('#').next().unwrap_or(b),
                Some(q.split('#').next().unwrap_or(q)),
            ),
            None => (request.url.split('#').next().unwrap_or(&request.url), None),
        };
        let (url_base_clean, mut url_expr) = path_param_expr(&mut gen, url_base);
        if let Some(q) = query {
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            let mut items = Vec::new();
            for (k, v) in form_pairs(q) {
                let occ = seen.entry(k.clone()).or_default();
                let origin = find_origin(ConsumedScope::Query, &k, *occ);
                *occ += 1;
                let e = field_expr(
                    &mut gen,
                    request,
                    origin,
                    &origins,
                    &k,
                    &v,
                    ConsumedScope::Query,
                );
                gen.note_params(&k, &e);
                items.push(format!("({}, {})", lit(&k), e));
            }
            url_expr = format!(
                "{url_expr} + '?' + urllib.parse.urlencode([{}])",
                items.join(", ")
            );
        }

        // Headers
        let mut header_items = Vec::new();
        for entry in request.request_headers.iter_all() {
            let lname = entry.name.to_ascii_lowercase();
            if entry.name.starts_with(':') {
                continue;
            }
            if SKIP_HEADERS.contains(&lname.as_str()) {
                if lname == "authorization" || lname == "proxy-authorization" {
                    gen.notes
                        .push(format!("header {lname} omitted (credential)"));
                }
                continue;
            }
            if matches!(
                lname.as_str(),
                "x-forwarded-for" | "forwarded" | "x-real-ip"
            ) {
                gen.notes
                    .push(format!("header {lname} omitted (client address)"));
                continue;
            }
            if !is_header_token(&entry.name) || !is_safe_header_value(&entry.value) {
                gen.warn(
                    "priming.header_skipped",
                    format!("step {n}: header with invalid name/value omitted"),
                );
                continue;
            }
            let origin = find_origin(ConsumedScope::Header, &lname, 0);
            let value = if lname == "referer" {
                // Assembled at runtime with the real URL of the earlier step that has
                // the same origin+path; without a match, it is omitted. The captured
                // query never leaves.
                let wanted = origin_and_path(&entry.value);
                let producer = step_reqs[..n - 1]
                    .iter()
                    .rev()
                    .find(|(r, _, _)| origin_and_path(&r.url) == wanted);
                match producer {
                    Some((r, _, _)) => format!("referer_for(R[{}].url, url)", lit(&r.id)),
                    None => {
                        gen.notes.push(
                            "header referer omitted (no matching earlier step)"
                                .to_string(),
                        );
                        continue;
                    }
                }
            } else if lname == "origin" {
                format!("rebase({}, base)", lit(split_origin(&entry.value).0))
            } else if is_credential_header(&lname) || looks_secret_value(&entry.value) {
                if origin.is_some() {
                    gen.value_expr(
                        request,
                        origin,
                        &origins,
                        &lname,
                        &entry.value,
                        ConsumedScope::Header,
                    )
                } else {
                    gen.fallback_param(&lname, &entry.value, true, false, false)
                }
            } else if origin.is_some_and(|o| matches!(o.status, OriginStatus::Origin)) {
                gen.value_expr(
                    request,
                    origin,
                    &origins,
                    &lname,
                    &entry.value,
                    ConsumedScope::Header,
                )
            } else if contains_pii(&entry.value) {
                gen.fallback_param(&lname, &entry.value, true, false, false)
            } else {
                lit(&entry.value)
            };
            gen.note_params(&format!("header:{lname}"), &value);
            header_items.push(format!("{}: {}", lit(&entry.name), value));
        }

        // Body
        let content_type = request
            .request_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut body_line = String::new();
        if request.request_body.has_bytes() {
            let bytes = request
                .request_body
                .attachment
                .as_deref()
                .and_then(|a| source.load(a))
                .map(|l| l.bytes.into_owned());
            match bytes {
                Some(bytes)
                    if content_type.contains("x-www-form-urlencoded") && !body_is_json(&bytes) =>
                {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
                    let mut items = Vec::new();
                    let pairs = form_pairs(&text);
                    for (k, v) in &pairs {
                        if k.chars().count() > 40 && v.is_empty() {
                            return Err(CoreError::Export {
                                message: format!(
                                    "step {n} ({}): form field without '=' longer than 40 characters (body that is not a form); refused",
                                    request.id
                                ),
                            });
                        }
                        let occ = seen.entry(k.clone()).or_default();
                        let origin = find_origin(ConsumedScope::Body, k, *occ);
                        *occ += 1;
                        let e = match adapter_field_expr(
                            &mut gen,
                            request,
                            &origins,
                            opts,
                            &content_type,
                            k,
                            v,
                            &pairs,
                        ) {
                            Some(expr) => expr,
                            None => {
                                let expr = field_expr(
                                    &mut gen,
                                    request,
                                    origin,
                                    &origins,
                                    k,
                                    v,
                                    ConsumedScope::Body,
                                );
                                gen.note_params(k, &expr);
                                expr
                            }
                        };
                        items.push(format!("({}, {})", lit(k), e));
                    }
                    body_line = format!(
                        "data = urllib.parse.urlencode([\n        {}\n    ])\n",
                        items.join(",\n        ")
                    );
                }
                Some(bytes) if content_type.contains("json") || body_is_json(&bytes) => {
                    let text = String::from_utf8(bytes).map_err(|_| CoreError::Export {
                        message: format!(
                            "step {n}: JSON body that is not UTF-8 cannot be generated"
                        ),
                    })?;
                    let value: serde_json::Value =
                        serde_json::from_str(&text).map_err(|e| CoreError::Export {
                            message: format!(
                                "step {n}: body declared as JSON, but invalid ({e}); use --allow-literal-body"
                            ),
                        })?;
                    let expr = json_expr(
                        &mut gen,
                        request,
                        &origins,
                        &value,
                        "",
                        &|field: &str| find_origin(ConsumedScope::Body, field, 0),
                        ConsumedScope::Body,
                        0,
                    );
                    body_line = format!("data = json.dumps({expr})\n");
                }
                Some(bytes) => {
                    if !opts.allow_literal_body {
                        return Err(CoreError::Export {
                            message: format!(
                                "step {n} ({}): body '{}' that is neither form nor JSON; refused. Use --allow-literal-body to resend it, with sensitive values as parameters",
                                request.id,
                                content_type.split(';').next().unwrap_or("").trim()
                            ),
                        });
                    }
                    let text = String::from_utf8(bytes).map_err(|_| CoreError::Export {
                        message: format!(
                            "step {n} ({}): binary body cannot be inspected for sensitive data; refused",
                            request.id
                        ),
                    })?;
                    if fold_width(&text) != text && contains_pii(&text) {
                        return Err(CoreError::Export {
                            message: format!(
                                "step {n} ({}): body with full-width characters hiding personal data; refused",
                                request.id
                            ),
                        });
                    }
                    if text
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
                    {
                        return Err(CoreError::Export {
                            message: format!(
                                "step {n} ({}): binary body (control characters) cannot be inspected for sensitive data; refused",
                                request.id
                            ),
                        });
                    }
                    let (expr, found) = literal_body_expr(&mut gen, &text);
                    gen.warn(
                        "priming.body_literal",
                        format!(
                            "step {n}: body resent as captured; {found} sensitive/business value(s) became required parameters and the rest was frozen"
                        ),
                    );
                    gen.notes.push(
                        "body frozen (--allow-literal-body): what was not detected as sensitive stays literal"
                            .to_string(),
                    );
                    body_line = format!("data = {expr}\n");
                }
                None => {
                    gen.warn(
                        "priming.body_missing",
                        format!("step {n}: request body unavailable; sent empty"),
                    );
                }
            }
        }

        // Step body: comments, fail-safe and assembly. The request and the checks
        // on its own response are emitted afterwards (once it is known what the
        // following steps will consume from this response).
        let mut body = String::new();
        for r in reasons {
            for line in comment(&format!("step {n}: {r}")).lines() {
                let _ = writeln!(body, "    {line}");
            }
        }
        for note in gen.notes.clone() {
            for line in comment(&note).lines() {
                let _ = writeln!(body, "    {line}");
            }
        }
        if let Some(message) = incomplete_steps.get(&request.id) {
            // Explicit fail-safe: the step does not proceed with a value without an origin.
            let _ = writeln!(body, "    fail({})", lit(message));
        }
        let _ = writeln!(body, "    url = {url_expr}");
        let _ = writeln!(body, "    headers = {{{}}}", header_items.join(", "));
        let data_arg = if body_line.is_empty() {
            String::new()
        } else {
            body.push_str("    ");
            body.push_str(&body_line);
            ", data=data".to_string()
        };
        steps_out.push(GeneratedStep {
            body,
            method: request.method.to_ascii_uppercase(),
            data_arg,
        });

        let _ = writeln!(
            plan,
            "    ({}, {}, {}, {}, {}),",
            lit(&request.id),
            lit(&request.method.to_ascii_uppercase()),
            lit(&url_base_clean),
            lit(&reasons
                .first()
                .map(|r| r.chars().take(160).collect::<String>())
                .unwrap_or_default()),
            if is_idempotent(&request.method) {
                "True"
            } else {
                "False"
            }
        );
    }

    // Emission of the steps: each one checks its OWN response before returning,
    // so that the chain never sends another request after a bad response.
    let mut step_code = String::new();
    for (index, step) in steps_out.iter().enumerate() {
        let n = index + 1;
        let _ = write!(step_code, "\n\ndef step_{n}(S, R, P, base):\n");
        step_code.push_str(&step.body);
        let _ = writeln!(step_code, "    try:");
        let _ = writeln!(
            step_code,
            "        resp = send(S, {}, url, {n}, base, headers=headers{}, timeout=TIMEOUT)",
            lit(&step.method),
            step.data_arg
        );
        let _ = writeln!(step_code, "    except UnicodeEncodeError as exc:");
        let _ = writeln!(
            step_code,
            "        fail('step {n}: header with character outside latin-1: %s' % exc)"
        );
        let _ = writeln!(step_code, "    if not (200 <= resp.status_code < 400):");
        let _ = writeln!(
            step_code,
            "        fail('step {n}: HTTP %d' % resp.status_code)"
        );
        let expected = step_reqs
            .get(index)
            .and_then(|(request, _, _)| gen.expectations.get(&request.id));
        if let Some(expected) = expected.filter(|e| !e.is_empty()) {
            let items: Vec<String> = expected.iter().map(Expectation::python).collect();
            let _ = writeln!(
                step_code,
                "    step_expected(resp, S, {n}, [{}])",
                items.join(", ")
            );
        }
        let _ = writeln!(step_code, "    step_error(resp, {n})");
        let _ = writeln!(step_code, "    return resp");
    }

    // Parameters
    let mut params_code = String::new();
    for p in &gen.params.list {
        let _ = writeln!(
            params_code,
            "    ({}, {}, {}),",
            lit(&p.name),
            p.default.as_deref().map_or("None".to_string(), lit),
            lit(&p.note)
        );
    }

    let mut text = String::new();
    text.push_str("#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n");
    for line in [
        format!("Priming script generated by ScrapeLens for request {target_request_id}."),
        "Semantic reproduction: header order and transport fidelity (TLS, HTTP/2, fingerprint) are NOT guaranteed.".to_string(),
        "Not executed by ScrapeLens: you run it, under your own responsibility.".to_string(),
        "Steps that change state (POST/PUT/PATCH/DELETE) require --confirm; without it the script prints the plan and exits.".to_string(),
        "Values with an observed origin are extracted from the responses at runtime; the captured value is never used in place of an extracted one.".to_string(),
        "Sensitive or redacted values are required parameters, with no default.".to_string(),
    ] {
        text.push_str(&comment(&line));
    }
    let emitted = format!("{plan}\n{params_code}\n{step_code}");
    let kinds = literal_pii_kinds(&emitted);
    if !kinds.is_empty() {
        return Err(CoreError::Export {
            message: format!(
                "generation refused: the script would contain literals with personal data/credentials ({}); the fragment could not be mapped to a parameter. Values omitted",
                kinds.join(", ")
            ),
        });
    }
    text.push_str(&unresolved_comments);
    text.push_str(PRELUDE);
    let _ = writeln!(text, "CAPTURED_ORIGIN = {}", lit(&captured_origin));
    let _ = writeln!(
        text,
        "EXTRA_ORIGINS = [{}]",
        opts.allow_origins
            .iter()
            .map(|o| lit(o.trim_end_matches('/')))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !gen.encoders_used.is_empty() {
        text.push_str(ADAPTER_HELPERS);
    }
    for index in &gen.encoders_used {
        text.push_str(&opts.adapter_encoders[*index].source);
        text.push('\n');
    }
    // Plan printing: a single implementation, the core's (`validate::plan_hash`),
    // computed at generation with the same adapters as the generator and the
    // names of the script's required parameters. The validate must use the same
    // `--adapter`.
    // `plan.parameters`: only the names of the plan's REQUIRED parameters, and the
    // hash is computed with exactly these names (overriding an optional one does
    // not change it).
    let mut required: Vec<String> = gen
        .params
        .list
        .iter()
        .filter(|p| p.default.is_none())
        .map(|p| p.name.clone())
        .collect();
    required.sort();
    required.dedup();
    let plan_hash =
        crate::validate::plan_hash(session, source, target_request_id, &opts.flow, &required)?;
    // `plan.version`: validate only compares the hash when the version is the current one.
    let _ = writeln!(text, "PLAN_VERSION = {}", crate::validate::PLAN_VERSION);
    let _ = writeln!(text, "PLAN_HASH = {}", lit(&plan_hash));
    let _ = writeln!(
        text,
        "PLAN_PARAMETERS = [{}]",
        required
            .iter()
            .map(|n| lit(n))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(text, "TARGET = {}", lit(target_request_id));
    let _ = writeln!(
        text,
        "HAS_STATE_CHANGE = {}",
        if has_unsafe { "True" } else { "False" }
    );
    let _ = writeln!(text, "PLAN = [\n{plan}]");
    let _ = writeln!(text, "PARAMS = [\n{params_code}]");
    let _ = writeln!(
        text,
        "PARAM_USES = [{}]",
        gen.param_uses
            .iter()
            .map(|(n, p)| format!("({}, {})", lit(n), lit(p)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    text.push_str(&step_code);
    let _ = writeln!(
        text,
        "\n\nSTEPS = [{}]",
        (1..=step_reqs.len())
            .map(|n| format!("step_{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    text.push_str(MAIN);

    let mut output = ExportOutput::new(text);
    output.warnings = gen.warnings;
    for w in &chain.warnings {
        output
            .warnings
            .push(Warning::info("priming.chain", w.clone()));
    }
    if !incomplete_steps.is_empty() {
        output.warnings.push(Warning::new(
            "priming.incomplete_chain",
            format!(
                "{} step(s) fail explicitly: the chain depends on a response without an observable body (see --allow-incomplete)",
                incomplete_steps.len()
            ),
        ));
    }
    // Pruning: an unreferenced extra step, or an unreferenced base step whose role
    // was only to supply parts of the claimed field that another referenced step
    // already supplies (same part names, different values).
    let referenced = |rid: &str| output.text.contains(&format!("R[{}]", lit(rid)));
    let mut prune: Vec<String> = extra_ids
        .into_iter()
        .filter(|rid| !referenced(rid))
        .collect();
    if let Some(encoder_index) = gen.encoders_used.iter().next().copied() {
        if let Some(adapter) = opts
            .flow
            .adapters
            .get(&opts.adapter_encoders[encoder_index].adapter_id)
        {
            let names_of = |rid: &str, field: &str| -> BTreeSet<String> {
                let mut out = BTreeSet::new();
                if let Some(producer) = session.find_request(rid) {
                    if let Some(text) = response_text(producer, source) {
                        for control in html_controls(&text) {
                            if control.name == field {
                                if let Ok(decoded) = adapter.decode(&control.value) {
                                    out.extend(
                                        decoded
                                            .parts
                                            .into_iter()
                                            .filter(|p| !p.name.is_empty())
                                            .map(|p| p.name),
                                    );
                                }
                            }
                        }
                    }
                }
                out
            };
            for field in gen.claimed_fields.clone() {
                let mut supplied: BTreeSet<String> = BTreeSet::new();
                for step in &chain.steps {
                    if step.request_id != target_request_id && referenced(&step.request_id) {
                        supplied.extend(names_of(&step.request_id, &field));
                    }
                }
                for step in &chain.steps {
                    if step.request_id == target_request_id
                        || referenced(&step.request_id)
                        || prune.contains(&step.request_id)
                        || step.reasons.is_empty()
                        || !step
                            .reasons
                            .iter()
                            .all(|r| r.field.split('.').next().unwrap_or(&r.field) == field)
                    {
                        continue;
                    }
                    let mine = names_of(&step.request_id, &field);
                    if !mine.is_empty() && mine.is_subset(&supplied) {
                        prune.push(step.request_id.clone());
                    }
                }
            }
        }
    }
    prune.sort();
    prune.dedup();
    Ok((output, prune, gen.param_uses.clone()))
}

const PRELUDE: &str = r#"
import argparse
import base64
import datetime
import html.parser
import json
import os
import re
import sys
import time
import urllib.parse


def safe_text(value):
    """Text coming from a response: no ESC, controls or bidi/invisible characters."""
    return ''.join(c if (c.isprintable() and c not in '\u200e\u200f\u061c\u2028\u2029'
                         and not '\u202a' <= c <= '\u202e' and not '\u2066' <= c <= '\u2069'
                         and c != '\ufeff') else '?' for c in str(value))


def fail(message):
    sys.exit('priming: ' + safe_text(message))


class _Controls(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self._area = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else '') for k, v in attrs}
        if tag == 'input' and 'name' in a:
            if a.get('type', '').lower() in ('checkbox', 'radio') and not any(k == 'checked' for k, _ in attrs):
                return
            self.items.append((a['name'], a.get('value', '')))
        elif tag == 'textarea' and 'name' in a:
            self._area = [a['name'], '']

    def handle_data(self, data):
        if self._area is not None:
            self._area[1] += data

    def handle_endtag(self, tag):
        if tag == 'textarea' and self._area is not None:
            self.items.append((self._area[0], self._area[1]))
            self._area = None


def find_control(resp, name, index):
    parser = _Controls()
    parser.feed(resp.text)
    parser.close()
    found = [v for k, v in parser.items if k == name]
    if index >= len(found):
        return None
    return found[index]


def html_control(resp, name, index, who):
    value = find_control(resp, name, index)
    if value is None:
        fail('HTML control %r not found in the response of %s' % (name, who))
    return value


def find_body_field(resp, name):
    text = resp.text
    try:
        stack = [json.loads(text)]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if name in node:
                    return node[name] if isinstance(node[name], str) else json.dumps(node[name])
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    except ValueError:
        pass
    values = urllib.parse.parse_qs(text, keep_blank_values=True).get(name)
    if values:
        return values[0]
    return None


def body_field(resp, name, who):
    value = find_body_field(resp, name)
    if value is None:
        fail('field %r not found in the response of %s' % (name, who))
    return value


def step_expected(resp, session, index, expected):
    """Controls/fields that THIS step must deliver to the following steps."""
    missing = []
    for kind, name, extra in expected:
        if kind == 'cookie':
            ok = session.cookies.get(name) is not None
        elif kind == 'header':
            ok = resp.headers.get(name) is not None
        elif kind == 'control':
            ok = find_control(resp, name, extra) is not None
        elif kind == 'field':
            ok = find_body_field(resp, name) is not None
        else:
            ok = bool(resp.content)
        if not ok:
            missing.append(name)
    if missing:
        fail('step %d: response without %s (probably blocked or invalid session)'
             % (index, ', '.join(missing)))


def step_error(resp, index):
    """A filled ERRORMESSAGE is an application error; its absence is not an error."""
    value = find_control(resp, 'ERRORMESSAGE', 0)
    if value is not None and value.strip():
        fail('the application responded with ERRORMESSAGE in step %d: %s'
             % (index, safe_text(value.strip()[:200])))


def get_cookie(session, name, who):
    value = session.cookies.get(name)
    if value is None:
        fail('cookie %r is not in the cookie jar (%s)' % (name, who))
    return value


def get_header(resp, name, who):
    value = resp.headers.get(name)
    if value is None:
        fail('header %r missing from the response used by %s' % (name, who))
    return value


def ctx_extract(text, before, after, who):
    start = 0
    if before:
        at = text.find(before)
        if at < 0:
            fail('could not find the value by context (%r ... %r) for %s' % (before, after, who))
        start = at + len(before)
    if after:
        end = text.find(after, start + 1)
        if end < 0:
            fail('could not find the value by context (%r ... %r) for %s' % (before, after, who))
    else:
        end = len(text)
        if end <= start:
            fail('could not find the value by context (%r ... %r) for %s' % (before, after, who))
    return text[start:end]


def checked(value, size, who):
    if len(value) != size:
        sys.stderr.write('priming: warning: %s changed size (%d -> %d); the protocol length prefixes may need adjustment\n' % (who, size, len(value)))
    return value


def json_num(text):
    try:
        return int(text)
    except ValueError:
        return float(text)


def json_bool(text):
    return str(text).lower() == 'true'


def referer_for(previous_url, url):
    """Like the browser: across different origins, the Referer carries only the origin."""
    if url_origin(previous_url) != url_origin(url):
        return url_origin(previous_url) + '/'
    return previous_url


def url_origin(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.scheme + '://' + parts.netloc).lower()


def rebase(url, base):
    if base and url_origin(url) == CAPTURED_ORIGIN.lower():
        return base.rstrip('/') + url[len(CAPTURED_ORIGIN):]
    return url


TIMEOUT = 30
TRACE = {'fd': None, 'started': None, 'exchanges': [], 'checks': {}, 'errors': {}, 'params': [], 'complete': False}
TRACE_BODY_LIMIT = 2 * 1024 * 1024


def trace_body(data):
    """Body for the trace: UTF-8 text or base64, at most 2 MiB (truncated state)."""
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode('utf-8')
    size = len(data)
    chunk = bytes(data[:TRACE_BODY_LIMIT])
    truncated = size > TRACE_BODY_LIMIT
    try:
        out = {'text': chunk.decode('utf-8'), 'encoding': 'utf8', 'truncated': truncated}
    except UnicodeDecodeError:
        out = {'text': base64.b64encode(chunk).decode('ascii'), 'encoding': 'base64', 'truncated': truncated}
    if truncated:
        out['size'] = size
    return out


def trace_time(moment):
    return datetime.datetime.fromtimestamp(moment, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def trace_open(path):
    """Creates the trace file with 0600, without overwriting or following a symbolic link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        fail('--trace: %s already exists (or is a symbolic link); not overwriting' % safe_text(path))
    except OSError as exc:
        fail('--trace: could not create %s: %s' % (safe_text(path), safe_text(exc.strerror or exc)))
    os.fchmod(fd, 0o600)
    TRACE['fd'] = fd
    TRACE['started'] = time.time()
    sys.stderr.write('priming: the trace contains data from your session; do not share it without sanitizing\n')


def trace_exchange(index, method, url, resp, started):
    if TRACE['fd'] is None:
        return
    request = resp.request
    TRACE['exchanges'].append({
        'step': index,
        'method': method,
        'url': url,
        'requestHeaders': [[str(k), str(v)] for k, v in request.headers.items()],
        'requestBody': trace_body(request.body),
        'status': resp.status_code,
        'responseHeaders': [[str(k), str(v)] for k, v in resp.headers.items()],
        'responseBody': trace_body(resp.content),
        'startedAt': trace_time(started),
        'elapsedMs': round((time.time() - started) * 1000, 3),
    })


def trace_check(index, ok, reason):
    if TRACE['fd'] is not None:
        TRACE['checks'][index] = {'name': 'step', 'ok': ok}
        if reason:
            TRACE['checks'][index]['detail'] = reason


def trace_error(index, text):
    if TRACE['fd'] is not None:
        TRACE['errors'][index] = text


def trace_close(base=None):
    if TRACE['fd'] is None:
        return
    entries = []
    for index, (rid, method, url, _, _) in enumerate(PLAN, 1):
        mine = [e for e in TRACE['exchanges'] if e['step'] == index]
        check = TRACE['checks'].get(index)
        if not mine and check is None and index not in TRACE['errors']:
            continue
        if not mine:
            # Failure before any request (e.g. refused origin): records the planned request.
            mine = [{'step': index, 'method': method, 'url': rebase(url, base), 'requestHeaders': [],
                     'requestBody': None, 'status': None, 'responseHeaders': [], 'responseBody': None,
                     'error': TRACE['errors'].get(index) or (check or {}).get('detail') or 'step not sent'}]
        mine = [{k: v for k, v in entry.items() if k != 'step'} for entry in mine]
        if index in TRACE['errors'] and 'error' not in mine[-1]:
            mine[-1]['error'] = TRACE['errors'][index]
        if check is not None:
            mine[-1]['checks'] = [check]
        entries.extend(mine)
    doc = {
        'schema': 'scrapelens.trace/1',
        'generator': 'scrapelens-priming 1.0',
        'startedAt': trace_time(TRACE['started']),
        'target': TARGET,
        'complete': TRACE['complete'],
        'plan': {'version': PLAN_VERSION, 'hash': PLAN_HASH, 'parameters': PLAN_PARAMETERS},
        # Only the names of the user parameters and of the parts where they enter, never values.
        'parameters': [{'name': n, 'part': part} for n, part in PARAM_USES if n in TRACE['params']],
        'steps': entries,
    }
    data = json.dumps(doc, ensure_ascii=False).encode('utf-8')
    view = memoryview(data)
    while len(view):
        written = os.write(TRACE['fd'], view)
        view = view[written:]
    os.close(TRACE['fd'])
    TRACE['fd'] = None


def send(S, method, url, index, base, **kw):
    """Sends a step without following redirects on its own: only the SAME origin is followed."""
    home = url_origin(base) if base else CAPTURED_ORIGIN.lower()
    allowed = {home} | {o.lower() for o in EXTRA_ORIGINS}
    if url_origin(url) not in allowed:
        fail('step %d: origin %s not allowed; nothing was sent' % (index, url_origin(url)))
    started = time.time()
    resp = S.request(method, url, allow_redirects=False, **kw)
    trace_exchange(index, method, url, resp, started)
    hops = 0
    while resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location')
        if not location:
            fail('step %d: HTTP redirect %d without Location' % (index, resp.status_code))
        nxt = urllib.parse.urljoin(url, location)
        if url_origin(nxt) != url_origin(url):
            fail('step %d: redirect to another origin (%s) refused' % (index, safe_text(url_origin(nxt))))
        hops += 1
        if hops > 5:
            fail('step %d: too many redirects' % index)
        if resp.status_code == 303 or (resp.status_code in (301, 302) and method == 'POST'):
            method = 'GET'
            kw = {k: v for k, v in kw.items() if k not in ('data', 'json', 'files')}
            kw['headers'] = {k: v for k, v in kw.get('headers', {}).items()
                             if k.lower() not in ('content-type', 'content-length')}
        url = nxt
        started = time.time()
        resp = S.request(method, url, allow_redirects=False, **kw)
        trace_exchange(index, method, url, resp, started)
    return resp

"#;

const ADAPTER_HELPERS: &str = r#"
def adapter_get(decode, text, name, nth, who):
    found = [v for n, role, v in decode(text) if n == name and role in ('V', 'D')]
    if nth >= len(found):
        fail('part %r not found in the response used by %s' % (name, who))
    return found[nth]

"#;

const MAIN: &str = r#"

def check_arguments(args):
    """Validates argv before any request: invalid bytes, NUL, empty --trace, --timeout."""
    if args.trace is not None and not args.trace.strip():
        fail('--trace requires a file path (received empty text)')
    if not (0 < args.timeout < 3600):
        fail('--timeout must be between 0 and 3600 seconds')
    for key, value in sorted(vars(args).items()):
        if isinstance(value, str):
            try:
                value.encode('utf-8')
            except UnicodeEncodeError:
                fail('argument --%s has invalid bytes (not UTF-8)' % key.replace('p_', '', 1).replace('_', '-'))
            if '\x00' in value:
                fail('argument --%s contains NUL' % key.replace('p_', '', 1).replace('_', '-'))
    if args.base_url is not None:
        parts = urllib.parse.urlsplit(args.base_url)
        if parts.scheme not in ('http', 'https') or not parts.netloc:
            fail('--base-url must be http(s)://host[:port]')


def main():
    parser = argparse.ArgumentParser(description='Priming script (ScrapeLens)')
    parser.add_argument('--confirm', '--confirmar', action='store_true', help='runs the steps that change state (--confirmar is the legacy spelling)')
    parser.add_argument('--usar-proxy-do-ambiente', action='store_true', help='uses the environment proxy/.netrc (default: ignores)')
    parser.add_argument('--timeout', type=float, default=30.0, help='timeout of each request, in seconds (default: 30)')
    parser.add_argument('--trace', default=None, metavar='FILE', help='writes a JSON trace (scrapelens.trace/1) of the run; contains data from your session')
    parser.add_argument('--base-url', default=None, help='replaces the scheme/host/port of the captured target (e.g.: http://127.0.0.1:8791)')
    for name, default, note in PARAMS:
        parser.add_argument('--' + name.replace('_', '-'), dest='p_' + name, default=default,
                            required=False, help=(note + (' (required)' if default is None else ' (default: captured value)')).replace('%', '%%'))
    args = parser.parse_args()
    check_arguments(args)
    P = {name: getattr(args, 'p_' + name) for name, _, _ in PARAMS}
    base = args.base_url

    print('Priming plan for %s (%d steps):' % (TARGET, len(PLAN)))
    for index, (rid, method, url, reason, idem) in enumerate(PLAN, 1):
        print('  %d. %s %s [%s]%s' % (index, method, rebase(url, base), rid, '' if idem else ' (changes state)'))
        print('       %s' % reason)
    if HAS_STATE_CHANGE and not args.confirm:
        print('Nothing was sent: the plan has steps that change state. Use --confirm to run.')
        return 0
    missing = [name for name, default, _ in PARAMS if P[name] is None]
    if missing:
        fail('required parameters missing: ' + ', '.join('--' + m.replace('_', '-') for m in missing))

    try:
        import requests
    except ImportError:
        fail('the "requests" package is not installed (pip install requests)')
    S = requests.Session()
    S.trust_env = bool(args.usar_proxy_do_ambiente)
    if sys.version_info < (3, 13):
        sys.stderr.write('priming: warning: Python < 3.13; HTMLParser has known quadratic cases with hostile responses\n')
    R = {}
    global TIMEOUT
    TIMEOUT = args.timeout
    if args.trace is not None:
        trace_open(args.trace)
        # User-provided parameters: required or with a value different from the default.
        TRACE['params'] = [name for name, default, _ in PARAMS if default is None or P[name] != default]
    current = 0
    try:
        for index, (step, (rid, method, url, _, _)) in enumerate(zip(STEPS, PLAN), 1):
            current = index
            resp = step(S, R, P, base)
            R[rid] = resp
            trace_check(index, True, None)
            print('  [%d/%d] %s %s -> HTTP %d' % (index, len(STEPS), method, rebase(url, base), resp.status_code))
        TRACE['complete'] = True
    except SystemExit as exc:
        trace_check(current, False, safe_text(exc.code))
        trace_close(base)
        raise
    except BaseException as exc:
        # Transport error (ConnectionError, Timeout, any exception): the trace is never left empty.
        text = safe_text('%s: %s' % (type(exc).__name__, exc))[:300]
        trace_error(current, text)
        trace_check(current, False, 'transport error: ' + text)
        trace_close(base)
        if isinstance(exc, KeyboardInterrupt):
            raise
        fail('step %d: transport error (%s)' % (current, text))
    trace_close(base)
    print('Chain completed; last HTTP %d.' % R[PLAN[-1][0]].status_code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
"#;

#[cfg(test)]
mod ui_constant_tests {
    use super::is_ui_constant;

    #[test]
    fn ui_constants_are_explicit() {
        for yes in [
            "true", "false", "TRUE", "-180", "2.0", "1568", "+3", "0", "1.5",
        ] {
            assert!(is_ui_constant(yes), "{yes}");
        }
        for no in [
            "",
            "12345",
            "-1800",
            "2.00x",
            ".5",
            "5.",
            "1.2.3",
            "maybe",
            "abc",
            "1730000000123",
            "texto livre",
            "a1",
        ] {
            assert!(!is_ui_constant(no), "{no}");
        }
    }
}
