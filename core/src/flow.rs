//! Origin of values and the priming chain (`docs/09-chain-comparison.md` §1).
//!
//! API for the App:
//!
//! ```text
//! pub fn value_origins(session: &SessionV1, source: &dyn BodySource,
//!                      request_id: &str, options: &FlowOptions) -> Result<ValueOrigins>
//! pub fn priming_chain(session: &SessionV1, source: &dyn BodySource,
//!                      request_id: &str, options: &FlowOptions) -> Result<PrimingChain>
//! ```
//!
//! JSON schema (camelCase; `origins`, `chain` and `compare` in the CLI):
//!
//! ```text
//! origins: { requestId, attemptId, values: [ValueOrigin], redactedValues, ties, warnings }
//! ValueOrigin: { scope: query|header|cookie|body, field, occurrence, value, length,
//!   status: origin|ambiguous|repeated|none|composite|redacted, label (English),
//!   confidence: strong|possible|null ("possible origin (<kind>)" when only medium evidence exists),
//!   offset (fragments), oldest (index in evidences), parent (opaque field of the fragment),
//!   repeatedFrom[], unobservable: [{requestId, state, reason}], note, evidences: [ { kind: cookie-jar|same-field|value-match|initiator,
//!     strength: strong|medium|complement, role: produced|reissued, producerRequestId,
//!     producerAttemptId, scope: setCookie|responseHeader|location|responseBody, field,
//!     producerOffset, consumedOffset, consumedLength, timing: observed|inferred } ] }
//! chain: { requestId, steps: [ChainStep], protection: [ChainStep], pages: [ChainStep]
//!   (class: page, "context page" via Referer; never producers), unresolved[], warnings }
//! ChainStep: { requestId, attemptId, method, url, startedAt, class: application|protection,
//!   confidence: strong|possible, reason, reasons: [ { provides, field, kind, strength, consumedBy } ] }
//! ```
//!
//! Round 6 (docs/10), new fields:
//! - `evidences[].htmlControl`: the producer is an HTML form control
//!   (`input`/`textarea`/`select` from a text/html response; see [`crate::html`]);
//!   `producerOffset` points to the value in the original HTML, even with entities;
//! - `ValueOrigin.context[]` `{requestId, field, note}`: value also present in
//!   a static resource (script, css, font, image, media): may be a protocol
//!   constant; never a producer nor a step;
//! - `ValueOrigin.partialComposition[]` `{producerRequestId, field, start, length}`: short
//!   value without origin that contains (aligned to `_ - . : |` or to the edge, >= 8 bytes) the
//!   value of a producer and a part with no source: composition hint on the client, not
//!   an origin and does not create a step;
//! - `unobservable[].suggestion`: equivalent occurrence (same model) further on
//!   with an observable body;
//! - `chain.auxiliaryPages[]`: frames (documents with `initiator.kind == parser`, CDP
//!   `initiator` source or HAR `_initiator`) on the Referer path, outside `pages`;
//! - `chain.pages[]` (`class: page`): documents that loaded the page from which
//!   each step was emitted (Referer); "context page", never producers;
//! - HAR no-cookies warnings (`har.cookies_absent`) repeated in `warnings`.
//!
//! The `compare` schema is in [`crate::compare`].
//!
//! Fragments: only consumed values with >= 40 bytes (opaque fields, such as the
//! Natural XML) are searched by fragments; for the others the whole value counts.
//!
//! Rules:
//! - only producers whose RESPONSE ended (`ended_at`) before the start of the
//!   target attempt enter; a response that ends later is not a producer. Without
//!   times, the session order applies and the evidence gets `timing: inferred`. A
//!   tie in start never becomes a producer: it stays in `ties`;
//! - separate evidence: `cookieJar` (strong) and `sameField` (strong only with a name
//!   that is not generic — id, value, data, page, type, lang, name, key, code, state,
//!   status, action, op, mode, format, limit, offset, q, query, v, t, ts — and
//!   value with ≥ 4 characters; otherwise medium), `valueMatch`
//!   (medium; response value with >= 8 characters found in the request,
//!   whole or as a substring of an opaque field) and `initiator` (complement; the
//!   current model does not preserve the CDP initiator, which is declared);
//! - no candidate = `none` ("no observed origin"); several producers
//!   independent = `ambiguous` with all the candidates and the oldest
//!   indicated; `reissued` only when the value circulated in a request between one
//!   producer and the next (otherwise they are competing: `ambiguous`);
//! - "observed origin" requires strong evidence; medium only = `confidence:
//!   possible` ("possible origin (<kind>)"); the chain marks each step
//!   `strong` or `possible`;
//! - redacted values (`[REDACTED]`) do not match and are declared.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::adapter::{AdapterContext, AdapterRegistry, PartRole};
use crate::error::{CoreError, Result};
use crate::model::{Attempt, BodyState, SessionV1};
use crate::search::BodySource;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowOptions {
    /// Minimum length for `valueMatch`.
    pub min_match_len: usize,
    /// Maximum number of evidence entries returned per value.
    pub max_evidence: usize,
    /// Maximum number of DP cells used to compare two opaque fields.
    pub max_opaque_cells: usize,
    /// Protocol adapters (optional; empty = behavior without an adapter).
    #[serde(skip)]
    pub adapters: crate::adapter::AdapterRegistry,
}

impl Default for FlowOptions {
    fn default() -> Self {
        Self {
            min_match_len: 8,
            max_evidence: 8,
            max_opaque_cells: 4_000_000,
            adapters: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    CookieJar,
    SameField,
    ValueMatch,
    Initiator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Strength {
    Strong,
    Medium,
    Complement,
}

/// Origin confidence: `strong` requires strong evidence; only medium evidence is
/// `possible` ("possible origin").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    Strong,
    Possible,
}

/// How the producer → consumer order was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Timing {
    /// The producer's response ended (source time) before the target started.
    Observed,
    /// Start/end time was missing: the session order was used.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Produced,
    Reissued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProducerScope {
    SetCookie,
    ResponseHeader,
    Location,
    ResponseBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsumedScope {
    Query,
    Header,
    Cookie,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OriginStatus {
    /// One observed producer.
    Origin,
    /// More than one independent producer: see `oldest`.
    Ambiguous,
    /// No producer, but the value already circulated in an earlier request.
    Repeated,
    /// "No observed origin": constant, user input or generated on the client.
    None,
    /// Opaque field whose parts have their own origin (`parent` entries).
    Composite,
    /// Redacted value: not traceable.
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub strength: Strength,
    pub role: Role,
    /// Logical request that produces the value.
    #[serde(rename = "producerRequestId")]
    pub request_id: String,
    #[serde(rename = "producerAttemptId")]
    pub attempt_id: String,
    pub scope: ProducerScope,
    /// Name of the field/header/cookie/variable in the producer, when present.
    pub field: Option<String>,
    /// Offset of the value within the producer's body/value.
    pub producer_offset: Option<u64>,
    /// Where the fragment appears in the consumed value (opaque fields).
    pub consumed_offset: Option<u64>,
    pub consumed_length: Option<u64>,
    pub timing: Timing,
    /// The producer is an HTML form control (`input`/`textarea`/`select`).
    pub html_control: bool,
}

/// Informational hint (not an origin): the value contains, aligned to a separator
/// or to the edge, a producer's value, and the rest has no observed source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialComposition {
    pub producer_request_id: String,
    pub field: Option<String>,
    pub start: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextNote {
    pub request_id: String,
    pub field: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Unobservable {
    pub request_id: String,
    /// `unavailable`, `discarded` or `truncated`.
    pub state: String,
    pub reason: Option<String>,
    /// Equivalent occurrence (same model) further on, with an observable body:
    /// where to look for the same information.
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueOrigin {
    pub scope: ConsumedScope,
    pub field: String,
    /// Occurrence of the repeated field (0 = first).
    pub occurrence: usize,
    /// Value (preview of up to 160 characters).
    pub value: String,
    pub length: usize,
    pub status: OriginStatus,
    /// Human-readable label ("no observed origin", "ambiguous…"…).
    pub label: String,
    /// `strong` (strong evidence exists) or `possible` (only medium evidence).
    pub confidence: Option<Confidence>,
    /// Offset of the fragment in the consumed value (`parent` entries).
    pub offset: Option<u64>,
    /// Index in `evidences` of the oldest producer.
    pub oldest: Option<usize>,
    pub evidences: Vec<Evidence>,
    /// Earlier requests that already carried the value (`repeated`).
    pub repeated_from: Vec<String>,
    /// Earlier responses without an observable body (unavailable/discarded/
    /// truncated): the origin may be in them (up to 20; the total goes in the label).
    pub unobservable: Vec<Unobservable>,
    /// Value also present in static resources (may be a protocol constant):
    /// never a producer nor a step of the chain.
    pub context: Vec<ContextNote>,
    /// Probable partial composition (client): see [`PartialComposition`].
    pub partial_composition: Vec<PartialComposition>,
    /// Opaque field this fragment is part of (`composite`).
    pub parent: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueOrigins {
    pub request_id: String,
    pub attempt_id: String,
    pub values: Vec<ValueOrigin>,
    /// Number of redacted values (not traceable).
    pub redacted_values: usize,
    /// Attempts with the same start time, excluded as producers.
    pub ties: Vec<String>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Producer / consumer data per attempt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Item {
    scope: ProducerScope,
    field: Option<String>,
    value: String,
    offset: Option<u64>,
    /// May serve as `sameField` (has a field/header/cookie name).
    named: bool,
    /// HTML form control (`input`/`textarea`/`select`).
    html: bool,
    /// Pre-filled control that is not `hidden`: at most medium evidence.
    soft: bool,
}

#[derive(Debug)]
struct OpaqueField {
    name: String,
    value: String,
    /// Decoded → original offset map (HTML controls).
    map: Option<Vec<usize>>,
    html: bool,
}

#[derive(Debug, Default)]
struct ProducerData {
    items: Vec<Item>,
    /// Opaque response fields for comparison by substring.
    opaque: Vec<OpaqueField>,
}

#[derive(Debug, Clone)]
pub(crate) struct Consumed {
    pub(crate) scope: ConsumedScope,
    pub(crate) field: String,
    pub(crate) occurrence: usize,
    pub(crate) value: String,
    /// Claimed by an adapter: no fragments by common substring.
    pub(crate) adapted: bool,
    /// Part decoded by an adapter: parent field and offset in the original.
    pub(crate) part_of: Option<(String, u64)>,
}

const REDACTED_MARK: &str = "REDACTED";
/// Producer: response field kept for comparison by fragments.
const OPAQUE_MIN: usize = 16;
/// Consumer: only long values (>= 40 bytes, with internal structure such as the
/// XML of Natural) are searched by fragments. In common fields (form/JSON/query/
/// header) the whole value counts: a common prefix is not an origin.
pub(crate) const OPAQUE_CONSUMER_MIN: usize = 40;

fn is_redacted(value: &str) -> bool {
    value.contains(REDACTED_MARK)
}

fn pct_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_pairs(url: &str) -> Vec<(String, String)> {
    let Some((_, rest)) = url.split_once('?') else {
        return Vec::new();
    };
    rest.split('#')
        .next()
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (pct_decode(name), pct_decode(value)),
            None => (pct_decode(pair), String::new()),
        })
        .collect()
}

/// Protocol or constant headers: never "consumed values".
fn is_protocol_header(lower: &str) -> bool {
    lower.starts_with(':')
        || lower.starts_with("sec-")
        || lower.starts_with("accept")
        || matches!(
            lower,
            "host"
                | "content-length"
                | "content-type"
                | "content-encoding"
                | "user-agent"
                | "cache-control"
                | "pragma"
                | "connection"
                | "upgrade-insecure-requests"
                | "origin"
                | "referer"
                | "cookie"
                | "set-cookie"
                | "date"
                | "server"
                | "vary"
                | "etag"
                | "expires"
                | "last-modified"
                | "transfer-encoding"
                | "keep-alive"
                | "age"
        )
}

fn form_fields(text: &str) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for segment in text.split('&') {
        if let Some((name, value)) = segment.split_once('=') {
            out.push((
                pct_decode(name),
                pct_decode(value),
                (offset + name.len() + 1) as u64,
            ));
        }
        offset += segment.len() + 1;
    }
    out
}

fn looks_form(text: &str) -> bool {
    let head = &text[..text.len().min(4096)];
    !head.contains('<')
        && !head.contains('\n')
        && head.contains('=')
        && head
            .split('&')
            .next()
            .is_some_and(|first| first.split('=').next().is_some_and(is_field_name))
}

fn is_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']'))
}

fn json_leaves(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                json_leaves(child, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                json_leaves(child, &format!("{path}[{index}]"), out);
            }
        }
        Value::String(text) => out.push((path.to_string(), text.clone())),
        Value::Number(number) => out.push((path.to_string(), number.to_string())),
        Value::Bool(flag) => out.push((path.to_string(), flag.to_string())),
        Value::Null => {}
    }
}

/// Quoted literals (with the variable that receives them, when it appears).
fn string_literals(text: &str, min: usize) -> Vec<(String, u64, Option<String>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != quote && bytes[j] != b'\n' && j - start <= 2048 {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == quote {
            if j - start >= min {
                if let Some(literal) = text.get(start..j) {
                    out.push((literal.to_string(), start as u64, assigned_name(text, i)));
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Name of the variable/key immediately before `= "` or `: "`.
fn assigned_name(text: &str, quote_at: usize) -> Option<String> {
    let before = text.get(..quote_at)?.trim_end();
    let before = before
        .strip_suffix('=')
        .or_else(|| before.strip_suffix(':'))?;
    let before = before.trim_end();
    // quoted object key: `{"token": "…"}` / `{'token': '…'}`
    let before = before
        .strip_suffix(['"', '\''])
        .filter(|rest| rest.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(before);
    let name: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn body_text(source: &dyn BodySource, attempt_body: &crate::model::Body) -> Option<String> {
    if !matches!(
        attempt_body.state,
        BodyState::Captured | BodyState::Truncated
    ) {
        return None;
    }
    let name = attempt_body.attachment.as_deref()?;
    let loaded = source.load(name)?;
    String::from_utf8(loaded.bytes.into_owned()).ok()
}

fn media_of(headers: &crate::model::HeaderView, body: &crate::model::Body) -> String {
    headers
        .first_value("content-type")
        .or(body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Named fields of a body (form / JSON); `None` if it is free text.
fn named_fields(text: &str, media: &str) -> Option<Vec<(String, String, Option<u64>)>> {
    let json_like =
        media.contains("json") || matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['));
    if json_like {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let mut leaves = Vec::new();
            json_leaves(&value, "", &mut leaves);
            return Some(leaves.into_iter().map(|(n, v)| (n, v, None)).collect());
        }
    }
    // Script is not a form: `window.cfg={"tok":"V"}` has `=` and a name with a
    // dot, but the body is JS. Without this guard the object becomes a single field
    // `window.cfg` and the inner literals stop being candidates.
    let script = media.contains("javascript") || media.contains("ecmascript");
    if media.contains("x-www-form-urlencoded") || (!script && looks_form(text)) {
        return Some(
            form_fields(text)
                .into_iter()
                .map(|(n, v, o)| (n, v, Some(o)))
                .collect(),
        );
    }
    None
}

fn producer_data(
    attempt: &Attempt,
    source: &dyn BodySource,
    min: usize,
    adapters: &AdapterRegistry,
) -> ProducerData {
    let mut data = ProducerData::default();
    for record in &attempt.set_cookies {
        if let Some(parsed) = &record.parsed {
            data.items.push(Item {
                scope: ProducerScope::SetCookie,
                field: Some(parsed.name.clone()),
                value: parsed.value.trim_matches('"').to_string(),
                offset: None,
                named: true,
                html: false,
                soft: false,
            });
        }
    }
    for entry in attempt
        .response_headers
        .pseudo_headers
        .iter()
        .chain(attempt.response_headers.headers.iter())
    {
        let lower = entry.name.to_ascii_lowercase();
        if lower == "location" {
            data.items.push(Item {
                scope: ProducerScope::Location,
                field: Some("location".to_string()),
                value: entry.value.clone(),
                offset: None,
                named: false,
                html: false,
                soft: false,
            });
            for (name, value) in query_pairs(&entry.value) {
                data.items.push(Item {
                    scope: ProducerScope::Location,
                    field: Some(name),
                    value,
                    offset: None,
                    named: true,
                    html: false,
                    soft: false,
                });
            }
        } else if !is_protocol_header(&lower) {
            data.items.push(Item {
                scope: ProducerScope::ResponseHeader,
                field: Some(lower),
                value: entry.value.clone(),
                offset: None,
                named: true,
                html: false,
                soft: false,
            });
        }
    }
    if let Some(text) = body_text(source, &attempt.response_body) {
        let media = media_of(&attempt.response_headers, &attempt.response_body);
        let is_html = (media.contains("html") && text.contains('<'))
            || find_ci_ascii(&text, "<textarea")
            || find_ci_ascii(&text, "<input");
        if is_html {
            let actx = AdapterContext {
                url: &attempt.url,
                method: &attempt.method,
                request: false,
                media: Some(&media),
            };
            for c in crate::html::html_controls(&text) {
                // HTML control (value already without entities): adapter parts with
                // offset mapped back to the original HTML.
                if let Some(parts) = adapter_parts(adapters, &c.name, &c.value, &actx) {
                    for (part_name, part_value, part_offset) in parts {
                        let original = c.map.get(part_offset).copied().unwrap_or(c.start);
                        data.items.push(Item {
                            scope: ProducerScope::ResponseBody,
                            field: Some(format!("{}.{part_name}", c.name)),
                            value: part_value,
                            offset: Some(original as u64),
                            named: true,
                            html: true,
                            soft: false,
                        });
                    }
                }
                if c.value.len() >= OPAQUE_MIN {
                    data.opaque.push(OpaqueField {
                        name: c.name.clone(),
                        value: c.value.clone(),
                        map: Some(c.map.clone()),
                        html: true,
                    });
                }
                data.items.push(Item {
                    scope: ProducerScope::ResponseBody,
                    field: Some(c.name),
                    value: c.value,
                    offset: Some(c.start as u64),
                    named: true,
                    html: true,
                    soft: !c.hidden,
                });
            }
        }
        match named_fields(&text, &media) {
            Some(fields) if !is_html => {
                let actx = AdapterContext {
                    url: &attempt.url,
                    method: &attempt.method,
                    request: false,
                    media: Some(&media),
                };
                for (name, value, offset) in fields {
                    if let Some(parts) = adapter_parts(adapters, &name, &value, &actx) {
                        for (part_name, part_value, part_offset) in parts {
                            data.items.push(Item {
                                scope: ProducerScope::ResponseBody,
                                field: Some(format!("{name}.{part_name}")),
                                value: part_value,
                                offset: offset.map(|o| o + part_offset as u64),
                                named: true,
                                html: false,
                                soft: false,
                            });
                        }
                    }
                    if value.len() >= OPAQUE_MIN {
                        data.opaque.push(OpaqueField {
                            name: name.clone(),
                            value: value.clone(),
                            map: None,
                            html: false,
                        });
                    }
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: Some(name),
                        value,
                        offset,
                        named: true,
                        html: false,
                        soft: false,
                    });
                }
            }
            _ => {
                for (literal, offset, hint) in string_literals(&text, min) {
                    data.items.push(Item {
                        scope: ProducerScope::ResponseBody,
                        field: hint,
                        value: literal,
                        offset: Some(offset),
                        named: false,
                        html: false,
                        soft: false,
                    });
                }
            }
        }
    }
    data
}

/// Parts (relative name, value, offset) of a field claimed by an adapter;
/// `None` without a registry, without a claim or with a decoding error (falls
/// back to the behavior without an adapter).
fn adapter_parts(
    adapters: &AdapterRegistry,
    field: &str,
    value: &str,
    ctx: &AdapterContext<'_>,
) -> Option<Vec<(String, String, usize)>> {
    if adapters.is_empty() {
        return None;
    }
    let adapter = adapters.claim(field, value, ctx)?;
    let decoded = adapter.decode(value).ok()?;
    Some(
        decoded
            .parts
            .into_iter()
            .filter(|p| p.role != PartRole::Structure && !p.value.is_empty())
            .map(|p| (p.name, p.value, p.offset))
            .collect(),
    )
}

fn find_ci_ascii(text: &str, needle: &str) -> bool {
    let (h, n) = (text.as_bytes(), needle.as_bytes());
    h.len() >= n.len() && (0..=h.len() - n.len()).any(|i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

fn consumed_values(
    attempt: &Attempt,
    source: &dyn BodySource,
    adapters: &AdapterRegistry,
) -> Vec<Consumed> {
    let mut out: Vec<Consumed> = Vec::new();
    let mut counts: HashMap<(u8, String), usize> = HashMap::new();
    let mut push = |scope: ConsumedScope, field: String, value: String, out: &mut Vec<Consumed>| {
        let key = (scope as u8, field.to_ascii_lowercase());
        let occurrence = counts.entry(key).or_default();
        out.push(Consumed {
            scope,
            field,
            occurrence: *occurrence,
            value,
            adapted: false,
            part_of: None,
        });
        *occurrence += 1;
    };
    for (name, value) in query_pairs(&attempt.url) {
        push(ConsumedScope::Query, name, value, &mut out);
    }
    for entry in attempt
        .request_headers
        .pseudo_headers
        .iter()
        .chain(attempt.request_headers.headers.iter())
    {
        if !is_protocol_header(&entry.name.to_ascii_lowercase()) {
            push(
                ConsumedScope::Header,
                entry.name.clone(),
                entry.value.clone(),
                &mut out,
            );
        }
    }
    for pair in &attempt.cookie.pairs {
        push(
            ConsumedScope::Cookie,
            pair.name.clone(),
            pair.value.trim_matches('"').to_string(),
            &mut out,
        );
    }
    if let Some(text) = body_text(source, &attempt.request_body) {
        let media = media_of(&attempt.request_headers, &attempt.request_body);
        match named_fields(&text, &media) {
            Some(fields) => {
                let ctx = AdapterContext {
                    url: &attempt.url,
                    method: &attempt.method,
                    request: true,
                    media: Some(&media),
                };
                for (name, value, _) in fields {
                    let parts = adapter_parts(adapters, &name, &value, &ctx);
                    push(ConsumedScope::Body, name.clone(), value, &mut out);
                    if let Some(parts) = parts {
                        if let Some(last) = out.last_mut() {
                            last.adapted = true;
                        }
                        for (part_name, part_value, offset) in parts {
                            let before = out.len();
                            push(
                                ConsumedScope::Body,
                                format!("{name}.{part_name}"),
                                part_value,
                                &mut out,
                            );
                            out[before].part_of = Some((name.clone(), offset as u64));
                        }
                    }
                }
            }
            None => push(ConsumedScope::Body, "(body)".to_string(), text, &mut out),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Context (cache)
// ---------------------------------------------------------------------------

pub(crate) type Pos = (usize, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rel {
    Before,
    Tie,
    After,
}

pub(crate) struct FlowContext<'a> {
    pub(crate) session: &'a SessionV1,
    pub(crate) source: &'a dyn BodySource,
    pub(crate) options: FlowOptions,
    producers: RefCell<HashMap<Pos, Rc<ProducerData>>>,
    consumed: RefCell<HashMap<Pos, Rc<Vec<Consumed>>>>,
    /// Index by 8-byte prefix: producer values with >= 8 bytes.
    index: RefCell<Option<Rc<PrefixIndex>>>,
    seq: HashMap<Pos, usize>,
    by_attempt: HashMap<String, Pos>,
    /// request id → position of the last attempt.
    by_request: HashMap<String, Pos>,
    ordered: Vec<Pos>,
}

struct PrefixIndex {
    map: HashMap<[u8; 8], Vec<(Pos, usize)>>,
}

impl<'a> FlowContext<'a> {
    pub(crate) fn new(
        session: &'a SessionV1,
        source: &'a dyn BodySource,
        options: &FlowOptions,
    ) -> Self {
        let mut seq = HashMap::new();
        let mut by_attempt = HashMap::new();
        let mut by_request: HashMap<String, Pos> = HashMap::new();
        let mut ordered = Vec::new();
        let mut next = 0;
        for (ri, request) in session.requests.iter().enumerate() {
            if let Some(last) = request.attempts.len().checked_sub(1) {
                by_request.entry(request.id.clone()).or_insert((ri, last));
            }
            for (ai, attempt) in request.attempts.iter().enumerate() {
                seq.insert((ri, ai), next);
                by_attempt.insert(attempt.id.clone(), (ri, ai));
                ordered.push((ri, ai));
                next += 1;
            }
        }
        Self {
            session,
            source,
            options: options.clone(),
            producers: RefCell::new(HashMap::new()),
            consumed: RefCell::new(HashMap::new()),
            index: RefCell::new(None),
            seq,
            by_attempt,
            by_request,
            ordered,
        }
    }

    fn attempt(&self, pos: Pos) -> &'a Attempt {
        &self.session.requests[pos.0].attempts[pos.1]
    }

    pub(crate) fn positions(&self) -> impl Iterator<Item = Pos> + '_ {
        self.session
            .requests
            .iter()
            .enumerate()
            .flat_map(|(ri, r)| (0..r.attempts.len()).map(move |ai| (ri, ai)))
    }

    /// `Before` only if the candidate's response ended by the start of the target
    /// (`ended_at`); without times, the session order applies (see [`Self::inferred`]).
    fn rel(&self, candidate: Pos, target: Pos) -> Rel {
        if candidate == target {
            return Rel::After;
        }
        let (a, b) = (self.attempt(candidate), self.attempt(target));
        match (a.started_at, b.started_at) {
            (Some(x), Some(y)) => {
                if x == y {
                    Rel::Tie
                } else if x > y {
                    Rel::After
                } else {
                    match a.ended_at {
                        Some(end) if end <= y => Rel::Before,
                        Some(_) => Rel::After,
                        None => Rel::Before,
                    }
                }
            }
            _ => {
                if self.seq[&candidate] < self.seq[&target] {
                    Rel::Before
                } else {
                    Rel::After
                }
            }
        }
    }

    /// The candidate → target order came from the session sequence, not from times.
    fn inferred(&self, candidate: Pos, target: Pos) -> bool {
        let (a, b) = (self.attempt(candidate), self.attempt(target));
        a.started_at.is_none() || b.started_at.is_none() || a.ended_at.is_none()
    }

    /// The value circulated in a request after the response of `from` and up to
    /// the response of `to` (including the request of `to` itself, which sent it
    /// before the response arrived): then `to` only reissues the value.
    fn circulated(&self, text: &str, from: Pos, to: Pos) -> bool {
        let (lo, hi) = (self.seq[&from], self.seq[&to]);
        let after = self.attempt(from).ended_at;
        let before = self.attempt(to).ended_at.or(self.attempt(to).started_at);
        for pos in &self.ordered {
            let n = self.seq[pos];
            if n <= lo || n > hi || *pos == from {
                continue;
            }
            if let (Some(after), Some(before), Some(start)) =
                (after, before, self.attempt(*pos).started_at)
            {
                if start < after || start > before {
                    continue;
                }
            }
            if self
                .consumed_of(*pos)
                .iter()
                .any(|c| c.value.contains(text))
            {
                return true;
            }
        }
        false
    }

    /// Static resource (script, stylesheet, font, image, media) by type,
    /// MIME or extension: not a producer of session values.
    pub(crate) fn is_static(&self, pos: Pos) -> bool {
        self.static_candidate(pos) && !self.maybe_dynamic(pos)
    }

    /// A script with a query string, `Cache-Control: no-store|no-cache` or a
    /// JSON/JSONP body may be a dynamic producer, even if it looks static.
    fn maybe_dynamic(&self, pos: Pos) -> bool {
        let attempt = self.attempt(pos);
        let url = attempt.url.split('#').next().unwrap_or("");
        let path = url.split('?').next().unwrap_or("").to_ascii_lowercase();
        let is_script = path.ends_with(".js") || path.ends_with(".mjs");
        let mime = attempt
            .response_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_script = is_script || mime.contains("javascript") || mime.contains("ecmascript");
        if is_script && url.contains('?') {
            return true;
        }
        // `no-store`/`no-cache` only counts outside scripts: real JS libraries
        // often come like this (DETRAN case) and are not producers because of it.
        if !is_script {
            let cache = attempt
                .response_headers
                .first_value("cache-control")
                .unwrap_or("")
                .to_ascii_lowercase();
            if cache.contains("no-store") || cache.contains("no-cache") {
                return true;
            }
        }
        if is_script || mime.contains("json") {
            if let Some(text) = body_text(self.source, &attempt.response_body) {
                let t = text.trim_start();
                let jsonp = t.split_once('(').is_some_and(|(head, rest)| {
                    !head.is_empty()
                        && head
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
                        && rest.trim_start().starts_with(['{', '['])
                });
                if t.starts_with(['{', '[']) || jsonp {
                    return true;
                }
            }
        }
        false
    }

    fn static_candidate(&self, pos: Pos) -> bool {
        let request = &self.session.requests[pos.0];
        let attempt = self.attempt(pos);
        if let Some(kind) = request.resource_type.as_deref() {
            if matches!(
                kind.to_ascii_lowercase().as_str(),
                "script" | "stylesheet" | "font" | "image" | "media"
            ) {
                return true;
            }
        }
        let mime = attempt
            .response_headers
            .first_value("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if mime.contains("javascript")
            || mime.contains("ecmascript")
            || mime.contains("text/css")
            || mime.starts_with("image/")
            || mime.starts_with("font/")
            || mime.starts_with("audio/")
            || mime.starts_with("video/")
            || mime.contains("woff")
        {
            return true;
        }
        let path = attempt.url.split(['?', '#']).next().unwrap_or("");
        let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        path.contains('.')
            && matches!(
                ext.as_str(),
                "js" | "mjs"
                    | "css"
                    | "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "svg"
                    | "ico"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "otf"
                    | "eot"
                    | "webp"
                    | "map"
            )
    }

    fn producer(&self, pos: Pos) -> Rc<ProducerData> {
        if let Some(found) = self.producers.borrow().get(&pos) {
            return found.clone();
        }
        let data = Rc::new(producer_data(
            self.attempt(pos),
            self.source,
            self.options.min_match_len,
            &self.options.adapters,
        ));
        self.producers.borrow_mut().insert(pos, data.clone());
        data
    }

    fn consumed_of(&self, pos: Pos) -> Rc<Vec<Consumed>> {
        if let Some(found) = self.consumed.borrow().get(&pos) {
            return found.clone();
        }
        let data = Rc::new(consumed_values(
            self.attempt(pos),
            self.source,
            &self.options.adapters,
        ));
        self.consumed.borrow_mut().insert(pos, data.clone());
        data
    }

    fn prefix_index(&self) -> Rc<PrefixIndex> {
        if let Some(found) = self.index.borrow().as_ref() {
            return found.clone();
        }
        let mut map: HashMap<[u8; 8], Vec<(Pos, usize)>> = HashMap::new();
        for pos in self.positions().collect::<Vec<_>>() {
            let data = self.producer(pos);
            for (n, item) in data.items.iter().enumerate() {
                if item.value.len() >= self.options.min_match_len.max(8)
                    && !is_redacted(&item.value)
                {
                    let mut key = [0u8; 8];
                    key.copy_from_slice(&item.value.as_bytes()[..8]);
                    map.entry(key).or_default().push((pos, n));
                }
            }
        }
        let index = Rc::new(PrefixIndex { map });
        *self.index.borrow_mut() = Some(index.clone());
        index
    }

    pub(crate) fn find(&self, request_id: &str) -> Option<Pos> {
        self.by_request.get(request_id).copied()
    }

    pub(crate) fn consumed_for(&self, pos: Pos) -> Rc<Vec<Consumed>> {
        self.consumed_of(pos)
    }

    pub(crate) fn request_id(&self, pos: Pos) -> &'a str {
        &self.session.requests[pos.0].id
    }

    pub(crate) fn attempt_ref(&self, pos: Pos) -> &'a Attempt {
        self.attempt(pos)
    }
}

/// Names (without values) of the consumed fields that reappear as the value of an
/// earlier response, and of the response fields that were reused later.
/// Linear in the session size (indexes by value); serves the timeline, which does
/// not need the full origin classification.
pub(crate) fn linked_field_names(
    ctx: &FlowContext<'_>,
    only: &dyn Fn(&str) -> bool,
) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let min = ctx.options.min_match_len.max(8);
    // long value → producers; (field, value) → producers (any size >= 4)
    let mut long: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut named: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
    let mut consumed_names: HashMap<String, Vec<String>> = HashMap::new();
    let mut produced_names: HashMap<String, Vec<String>> = HashMap::new();
    let push = |list: &mut Vec<String>, name: &str| {
        if !list.iter().any(|n| n == name) {
            list.push(name.to_string());
        }
    };
    for pos in ctx.positions().collect::<Vec<_>>() {
        let id = ctx.request_id(pos).to_string();
        if only(&id) {
            for c in ctx.consumed_for(pos).iter() {
                if c.value.is_empty() || is_redacted(&c.value) {
                    continue;
                }
                let mut producers: Vec<&(String, String)> = Vec::new();
                if let Some(v) = named.get(&(c.field.to_ascii_lowercase(), c.value.clone())) {
                    producers.extend(v);
                }
                if c.value.len() >= min {
                    if let Some(v) = long.get(&c.value) {
                        producers.extend(v);
                    }
                }
                for (pid, pfield) in producers {
                    if *pid != id {
                        push(consumed_names.entry(id.clone()).or_default(), &c.field);
                        push(produced_names.entry(pid.clone()).or_default(), pfield);
                    }
                }
            }
        }
        for item in ctx.producer(pos).items.iter() {
            if item.value.is_empty() || is_redacted(&item.value) {
                continue;
            }
            let field = item.field.clone().unwrap_or_default();
            if item.named && !field.is_empty() {
                named
                    .entry((field.to_ascii_lowercase(), item.value.clone()))
                    .or_default()
                    .push((id.clone(), field.clone()));
            }
            if item.value.len() >= min {
                long.entry(item.value.clone())
                    .or_default()
                    .push((id.clone(), field));
            }
        }
    }
    (consumed_names, produced_names)
}

/// Generic field names: `same-field` with them is only medium evidence.
const GENERIC_NAMES: &[&str] = &[
    "id", "value", "data", "page", "type", "lang", "name", "key", "code", "state", "status",
    "action", "op", "mode", "format", "limit", "offset", "q", "query", "v", "t", "ts", "flag",
];

fn is_generic_name(name: &str) -> bool {
    GENERIC_NAMES
        .iter()
        .any(|generic| generic.eq_ignore_ascii_case(name))
}

/// Generic name; in adapter parts (`XML.p.id`) the last component counts.
fn is_generic_value(value: &Consumed) -> bool {
    if value.part_of.is_some() {
        let last = value.field.rsplit('.').next().unwrap_or(&value.field);
        return is_generic_name(last);
    }
    is_generic_name(&value.field)
}

fn preview(value: &str) -> String {
    let mut out: String = value.chars().take(160).collect();
    if value.chars().count() > 160 {
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------------------
// value_origins
// ---------------------------------------------------------------------------

/// Origin of the values consumed by the request `request_id` (last
/// attempt). See the module for the rules.
pub fn value_origins(
    session: &SessionV1,
    source: &dyn BodySource,
    request_id: &str,
    options: &FlowOptions,
) -> Result<ValueOrigins> {
    let ctx = FlowContext::new(session, source, options);
    origins_in(&ctx, request_id)
}

pub(crate) fn origins_in(ctx: &FlowContext<'_>, request_id: &str) -> Result<ValueOrigins> {
    let target = ctx
        .find(request_id)
        .ok_or_else(|| CoreError::MissingField {
            field: format!("request {request_id} (or without attempts)"),
        })?;
    let attempt = ctx.attempt(target);
    let consumed = ctx.consumed_of(target);
    let mut result = ValueOrigins {
        request_id: request_id.to_string(),
        attempt_id: attempt.id.clone(),
        values: Vec::new(),
        redacted_values: 0,
        ties: Vec::new(),
        warnings: Vec::new(),
    };
    if attempt.initiator.is_none() {
        result.warnings.push(
            "CDP initiator is not preserved in the model: `initiator` evidence unavailable"
                .to_string(),
        );
    }

    if let Some(w) = ctx
        .session
        .warnings
        .iter()
        .find(|w| w.code == "har.cookies_absent")
    {
        result.warnings.push(w.message.clone());
    }
    let mut earlier: Vec<Pos> = Vec::new();
    for pos in ctx.positions() {
        match ctx.rel(pos, target) {
            Rel::Before => earlier.push(pos),
            Rel::Tie => result.ties.push(ctx.attempt(pos).id.clone()),
            Rel::After => {}
        }
    }
    earlier.sort_by(|a, b| {
        let (x, y) = (ctx.attempt(*a).started_at, ctx.attempt(*b).started_at);
        match (x, y) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            _ => ctx.seq[a].cmp(&ctx.seq[b]),
        }
    });
    let earlier_set: BTreeSet<Pos> = earlier.iter().copied().collect();
    let rank: HashMap<Pos, usize> = earlier.iter().enumerate().map(|(i, p)| (*p, i)).collect();
    let index = ctx.prefix_index();

    for value in consumed.iter() {
        if is_redacted(&value.value) {
            result.redacted_values += 1;
            result.values.push(ValueOrigin {
                scope: value.scope,
                field: value.field.clone(),
                occurrence: value.occurrence,
                value: preview(&value.value),
                length: value.value.len(),
                status: OriginStatus::Redacted,
                label: "redacted: not traceable".to_string(),
                confidence: None,
                offset: None,
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
                unobservable: Vec::new(),
                context: Vec::new(),
                partial_composition: Vec::new(),
                parent: None,
                note: Some("redacted value: not traceable".to_string()),
            });
            continue;
        }
        let mut evidences: Vec<(usize, Evidence)> = Vec::new();

        // cookieJar / sameField: equality of name + value.
        for pos in &earlier {
            let data = ctx.producer(*pos);
            for item in data.items.iter() {
                if !item.named || item.value.is_empty() || item.value != value.value {
                    continue;
                }
                let name = item.field.as_deref().unwrap_or("");
                let kind = match (value.scope, item.scope) {
                    (ConsumedScope::Cookie, ProducerScope::SetCookie) if name == value.field => {
                        Some(EvidenceKind::CookieJar)
                    }
                    (ConsumedScope::Cookie, _) => None,
                    (_, ProducerScope::SetCookie) => None,
                    _ if name.eq_ignore_ascii_case(&value.field) => Some(EvidenceKind::SameField),
                    _ => None,
                };
                if let Some(kind) = kind {
                    let strength = if kind == EvidenceKind::SameField
                        && (is_generic_value(value) || value.value.len() < 4 || item.soft)
                    {
                        Strength::Medium
                    } else {
                        Strength::Strong
                    };
                    evidences.push((
                        rank[pos],
                        evidence(ctx, *pos, item, kind, strength, None, None),
                    ));
                }
            }
        }

        // whole valueMatch: producer value equal to the consumed value.
        let min = ctx.options.min_match_len.max(8);
        let bytes = value.value.as_bytes();
        let mut found: FoundMap = HashMap::new();
        if bytes.len() >= min {
            let partial_ok = bytes.len() >= OPAQUE_CONSUMER_MIN;
            // short named field: pieces only serve the whole decomposition
            let decomp_ok = !partial_ok && bytes.len() >= 16 && value.scope == ConsumedScope::Body;
            let strong_from: BTreeSet<Pos> = evidences.iter().map(|(r, _)| earlier[*r]).collect();
            for start in 0..=bytes.len() - 8 {
                let mut key = [0u8; 8];
                key.copy_from_slice(&bytes[start..start + 8]);
                let Some(candidates) = index.map.get(&key) else {
                    continue;
                };
                for (pos, n) in candidates {
                    if !earlier_set.contains(pos) {
                        continue;
                    }
                    let data = ctx.producer(*pos);
                    let item = &data.items[*n];
                    if !bytes[start..].starts_with(item.value.as_bytes()) {
                        continue;
                    }
                    if item.value.len() == bytes.len() {
                        if strong_from.contains(pos) {
                            continue; // already covered by strong evidence
                        }
                        evidences.push((
                            rank[pos],
                            evidence(
                                ctx,
                                *pos,
                                item,
                                EvidenceKind::ValueMatch,
                                Strength::Medium,
                                None,
                                None,
                            ),
                        ));
                    } else if (partial_ok || decomp_ok) && !ctx.is_static(*pos) {
                        found.entry((start, item.value.len())).or_default().push((
                            *pos,
                            item.scope,
                            item.field.clone(),
                            item.offset,
                            item.html,
                        ));
                    }
                }
            }
            if value.scope == ConsumedScope::Body && partial_ok && !value.adapted {
                opaque_candidates(ctx, value, &earlier, &mut found);
            }
        }
        let mut entry = finish_entry(ctx, value, evidences, &earlier);
        // Composite value: short named field covered ENTIRELY by >= 2 producer
        // values + separators. Partial coverage (only a prefix) does not count.
        let mut composite_cover = false;
        let mut partial_hints: Vec<PartialComposition> = Vec::new();
        if entry.status == OriginStatus::None
            && !found.is_empty()
            && bytes.len() < OPAQUE_CONSUMER_MIN
        {
            match cover_pieces(bytes, &found) {
                Some(chosen) => {
                    found.retain(|key, _| chosen.contains(key));
                    composite_cover = true;
                }
                None => {
                    partial_hints = aligned_hints(ctx, bytes, &found, &rank);
                    found.clear();
                }
            }
        }
        // a field with its own origin does not also become "composite" (no duplicate)
        let sub = if value.adapted
            || matches!(entry.status, OriginStatus::Origin | OriginStatus::Ambiguous)
        {
            Vec::new()
        } else {
            partial_entries(ctx, value, found, &rank)
        };
        if entry.status == OriginStatus::None && !sub.is_empty() {
            entry.status = OriginStatus::Composite;
            if composite_cover {
                entry.confidence = Some(Confidence::Possible);
            }
        }
        if entry.status == OriginStatus::None && !value.value.is_empty() {
            entry.repeated_from = repeated_from(ctx, value, &earlier);
            if !entry.repeated_from.is_empty() {
                entry.status = OriginStatus::Repeated;
            }
        }
        if matches!(entry.status, OriginStatus::None | OriginStatus::Repeated) {
            // Repeated: only producers before the 1st occurrence of the value count.
            if let Some(first) = entry.repeated_from.first().and_then(|id| ctx.find(id)) {
                if let Some(limit) = rank.get(&first).copied() {
                    partial_hints.retain(|h| {
                        ctx.find(&h.producer_request_id)
                            .and_then(|pos| rank.get(&pos).copied())
                            .is_some_and(|r| r < limit)
                    });
                }
            }
            entry.partial_composition = partial_hints;
        }
        if let Some((parent, offset)) = &value.part_of {
            entry.parent = Some(parent.clone());
            entry.offset = Some(*offset);
        }
        relabel(&mut entry);
        result.values.push(entry);
        for part in sub {
            result.values.push(part);
        }
    }
    for entry in result.values.iter_mut() {
        for e in entry.evidences.iter_mut() {
            if let Some(pos) = ctx.by_attempt.get(&e.attempt_id) {
                if ctx.inferred(*pos, target) {
                    e.timing = Timing::Inferred;
                }
            }
        }
    }
    let hidden: Vec<Unobservable> = earlier
        .iter()
        .filter_map(|pos| {
            let body = &ctx.attempt(*pos).response_body;
            matches!(
                body.state,
                BodyState::Unavailable | BodyState::Discarded | BodyState::Truncated
            )
            .then(|| Unobservable {
                request_id: ctx.request_id(*pos).to_string(),
                state: body.state.as_str().to_string(),
                reason: body.note.clone(),
                suggestion: equivalent_later(ctx, *pos),
            })
        })
        .collect();
    if !hidden.is_empty() {
        for entry in result.values.iter_mut().filter(|v| {
            v.length > 0 && matches!(v.status, OriginStatus::None | OriginStatus::Repeated)
        }) {
            entry.unobservable = hidden.iter().take(20).cloned().collect();
            entry.label = format!(
                "{}; {} earlier response(s) without observable body",
                entry.label,
                hidden.len()
            );
            if let Some(hint) = hidden.iter().find_map(|h| {
                h.suggestion
                    .as_ref()
                    .map(|s| format!(" (equivalent occurrence with body: {s})"))
            }) {
                entry.label.push_str(&hint);
            }
        }
    }
    if result.redacted_values > 0 {
        result.warnings.push(format!(
            "{} redacted value(s) ([REDACTED]) cannot be traced",
            result.redacted_values
        ));
    }
    Ok(result)
}

fn evidence(
    ctx: &FlowContext<'_>,
    pos: Pos,
    item: &Item,
    kind: EvidenceKind,
    strength: Strength,
    consumed_offset: Option<u64>,
    consumed_length: Option<u64>,
) -> Evidence {
    Evidence {
        kind,
        strength,
        role: Role::Produced,
        request_id: ctx.request_id(pos).to_string(),
        attempt_id: ctx.attempt(pos).id.clone(),
        scope: item.scope,
        field: item.field.clone(),
        producer_offset: item.offset,
        consumed_offset,
        consumed_length,
        timing: Timing::Observed,
        html_control: item.html,
    }
}

/// Sorts by time, marks reissues and decides the state.
fn finish_entry(
    _ctx: &FlowContext<'_>,
    value: &Consumed,
    mut raw: Vec<(usize, Evidence)>,
    _earlier: &[Pos],
) -> ValueOrigin {
    raw.sort_by_key(|(rank, _)| *rank);
    // The same bytes read by two paths (HTML control + literal `value="…"`)
    // are a single producer: dedupe by (attempt, overlapping interval).
    let width = value.value.len() as u64;
    let rank_of = |e: &Evidence| {
        let s = match e.strength {
            Strength::Strong => 2,
            Strength::Medium => 1,
            Strength::Complement => 0,
        };
        (s, e.html_control)
    };
    let mut deduped: Vec<(usize, Evidence)> = Vec::new();
    for (r, e) in raw {
        let dup = e.producer_offset.and_then(|o| {
            deduped.iter().position(|(_, d)| {
                d.attempt_id == e.attempt_id
                    && d.producer_offset
                        .is_some_and(|d_o| d_o.abs_diff(o) < width.max(1))
            })
        });
        match dup {
            Some(i) => {
                if rank_of(&e) > rank_of(&deduped[i].1) {
                    deduped[i] = (r, e);
                }
            }
            None => deduped.push((r, e)),
        }
    }
    let mut raw = deduped;
    // A static resource only gives context: a static value-match is never a producer.
    let mut context: Vec<ContextNote> = Vec::new();
    let is_static_ev = |e: &Evidence| {
        e.kind == EvidenceKind::ValueMatch
            && _ctx
                .by_attempt
                .get(&e.attempt_id)
                .is_some_and(|pos| _ctx.is_static(*pos))
    };
    if raw.iter().any(|(_, e)| is_static_ev(e)) {
        let has_dynamic = raw.iter().any(|(_, e)| !is_static_ev(e));
        let (statics, dynamic): (Vec<_>, Vec<_>) =
            raw.into_iter().partition(|(_, e)| is_static_ev(e));
        if !has_dynamic {
            for (_, e) in &statics {
                if !context.iter().any(|c| c.request_id == e.request_id) {
                    context.push(ContextNote {
                        request_id: e.request_id.clone(),
                        field: e.field.clone(),
                        note: "value also present in a static resource (may be a protocol constant)".to_string(),
                    });
                }
            }
        }
        raw = dynamic;
    }
    let mut last: HashMap<(EvidenceKind, ProducerScope, Option<String>, Option<u64>), Pos> =
        HashMap::new();
    let mut evidences = Vec::new();
    let mut produced = 0usize;
    for (_, mut e) in raw {
        let key = (e.kind, e.scope, e.field.clone(), e.consumed_offset);
        let pos = _ctx.by_attempt.get(&e.attempt_id).copied();
        let mut reissued = false;
        if let (Some(prev), Some(pos)) = (last.get(&key).copied(), pos) {
            reissued = _ctx.circulated(&value.value, prev, pos);
        }
        if let Some(pos) = pos {
            last.insert(key, pos);
        }
        if reissued {
            e.role = Role::Reissued;
        } else {
            produced += 1;
        }
        evidences.push(e);
    }
    let oldest = if evidences.is_empty() { None } else { Some(0) };
    let mut note = None;
    if evidences.len() > _ctx.options.max_evidence {
        note = Some(format!(
            "{} additional evidence(s) omitted (reissues)",
            evidences.len() - _ctx.options.max_evidence
        ));
        evidences.truncate(_ctx.options.max_evidence);
    }
    let status = match produced {
        0 => OriginStatus::None,
        1 => OriginStatus::Origin,
        _ => OriginStatus::Ambiguous,
    };
    let confidence = (status != OriginStatus::None).then(|| {
        if evidences
            .iter()
            .any(|e| e.role == Role::Produced && e.strength == Strength::Strong)
        {
            Confidence::Strong
        } else {
            Confidence::Possible
        }
    });
    ValueOrigin {
        scope: value.scope,
        field: value.field.clone(),
        occurrence: value.occurrence,
        value: preview(&value.value),
        length: value.value.len(),
        status,
        label: String::new(),
        confidence,
        offset: None,
        oldest,
        evidences,
        repeated_from: Vec::new(),
        unobservable: Vec::new(),
        context,
        partial_composition: Vec::new(),
        parent: None,
        note,
    }
}

/// Next occurrence of the same model (method + host + path + field names)
/// after `pos`, with an observable response body.
fn equivalent_later(ctx: &FlowContext<'_>, pos: Pos) -> Option<String> {
    let attempt = ctx.attempt(pos);
    let (host, path) = crate::compare::split_url(&attempt.url);
    let names = |p: Pos| -> Vec<String> {
        let mut n: Vec<String> = ctx
            .consumed_of(p)
            .iter()
            .filter(|c| matches!(c.scope, ConsumedScope::Query | ConsumedScope::Body))
            .map(|c| format!("{:?}:{}", c.scope, c.field))
            .collect();
        n.sort();
        n.dedup();
        n
    };
    let wanted = names(pos);
    let from = ctx.seq[&pos];
    for candidate in &ctx.ordered {
        if ctx.seq[candidate] <= from {
            continue;
        }
        let other = ctx.attempt(*candidate);
        if !other.method.eq_ignore_ascii_case(&attempt.method) {
            continue;
        }
        let (h, p) = crate::compare::split_url(&other.url);
        if h != host || p != path {
            continue;
        }
        if matches!(
            other.response_body.state,
            BodyState::Captured | BodyState::Truncated
        ) && names(*candidate) == wanted
        {
            return Some(ctx.request_id(*candidate).to_string());
        }
    }
    None
}

fn composition_label(entry: &ValueOrigin) -> String {
    let h = &entry.partial_composition[0];
    format!(
        "no observed origin; contains the value of {} from {} ({}) and a part with no observed source — probable composition in the client",
        h.field.as_deref().unwrap_or("?"),
        h.producer_request_id,
        if h.start == 0 { "prefix" } else { "fragment" }
    )
}

fn relabel(entry: &mut ValueOrigin) {
    entry.label = match entry.status {
        OriginStatus::Origin | OriginStatus::Ambiguous => {
            let oldest = entry.oldest.and_then(|i| entry.evidences.get(i));
            let kind = oldest.map_or("?", |e| match e.kind {
                EvidenceKind::CookieJar => "cookie-jar",
                EvidenceKind::SameField => "same-field",
                EvidenceKind::ValueMatch => "value-match",
                EvidenceKind::Initiator => "initiator",
            });
            let id = oldest.map_or("?", |e| e.request_id.as_str());
            match (entry.status, entry.confidence) {
                (OriginStatus::Origin, Some(Confidence::Strong)) => "observed origin".to_string(),
                (OriginStatus::Origin, _) => format!("possible origin ({kind})"),
                (_, Some(Confidence::Strong)) => format!("ambiguous (oldest: {id})"),
                _ => format!("possible origin ({kind}), ambiguous (oldest: {id})"),
            }
        }
        OriginStatus::Repeated if !entry.partial_composition.is_empty() => format!(
            "{} (value already circulated in {})",
            composition_label(entry),
            entry.repeated_from.join(", ")
        ),
        OriginStatus::Repeated => format!(
            "no observed origin (value already circulated in {})",
            entry.repeated_from.join(", ")
        ),
        OriginStatus::None if !entry.partial_composition.is_empty() => composition_label(entry),
        OriginStatus::None if !entry.context.is_empty() => {
            "no observed origin; value also present in a static resource (may be a protocol constant)".to_string()
        }
        OriginStatus::None => "no observed origin".to_string(),
        OriginStatus::Composite if entry.confidence == Some(Confidence::Possible) => {
            "possible composite origin: see fragments (parent)".to_string()
        }
        OriginStatus::Composite => "composite: see fragments (parent)".to_string(),
        OriginStatus::Redacted => "redacted: not traceable".to_string(),
    };
}

fn repeated_from(ctx: &FlowContext<'_>, value: &Consumed, earlier: &[Pos]) -> Vec<String> {
    let mut out = Vec::new();
    for pos in earlier {
        let data = ctx.consumed_of(*pos);
        if data.iter().any(|c| {
            c.scope == value.scope
                && c.field.eq_ignore_ascii_case(&value.field)
                && c.value == value.value
        }) {
            let id = ctx.request_id(*pos).to_string();
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

type Producer = (Pos, ProducerScope, Option<String>, Option<u64>, bool);
type FoundMap = HashMap<(usize, usize), Vec<Producer>>;

/// Fragments of an opaque field that match (>= 8) the same field in earlier
/// responses (maximal common substrings). A fragment that differs in a numeric
/// counter (`...0005` × `...0001`) is not a match.
fn opaque_candidates(
    ctx: &FlowContext<'_>,
    value: &Consumed,
    earlier: &[Pos],
    found: &mut FoundMap,
) {
    let min = ctx.options.min_match_len.max(8);
    let a = value.value.as_bytes();
    for pos in earlier {
        let data = ctx.producer(*pos);
        for field in data.opaque.iter() {
            let (name, other) = (&field.name, &field.value);
            if !name.eq_ignore_ascii_case(&value.field) || is_redacted(other) {
                continue;
            }
            let b = other.as_bytes();
            if a.len().saturating_mul(b.len()) > ctx.options.max_opaque_cells {
                continue;
            }
            for (start, len, other_start) in maximal_common(a, b, min) {
                if start == 0 && len == a.len() {
                    continue; // whole value: evidence of the field itself
                }
                if cut_in_number(a, b, start, len, other_start) {
                    continue;
                }
                let original = field
                    .map
                    .as_ref()
                    .and_then(|m| m.get(other_start).copied())
                    .unwrap_or(other_start);
                found.entry((start, len)).or_default().push((
                    *pos,
                    ProducerScope::ResponseBody,
                    Some(name.clone()),
                    Some(original as u64),
                    field.html,
                ));
            }
        }
    }
}

/// The common fragment ends (or starts) in the middle of a sequence of digits that
/// differs on both sides: it is a counter, not a shared value.
/// Pieces that cover the whole value (except separators `_ - . : |`), with at
/// least 2 distinct producers; `None` if there is a gap (a partial prefix does not count).
/// Known parts (>= 8) of a short value aligned to a separator `_ - . : |` or to
/// the edge: partial composition hint (not an origin).
fn aligned_hints(
    ctx: &FlowContext<'_>,
    bytes: &[u8],
    found: &FoundMap,
    rank: &HashMap<Pos, usize>,
) -> Vec<PartialComposition> {
    let sep = |b: u8| matches!(b, b'_' | b'-' | b'.' | b':' | b'|');
    let mut keys: Vec<&(usize, usize)> = found.keys().collect();
    keys.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut out = Vec::new();
    for &&(start, len) in &keys {
        let end = start + len;
        let left = start == 0 || sep(bytes[start - 1]);
        let right = end == bytes.len() || sep(bytes[end]);
        if len < 8 || !left || !right || (start == 0 && end == bytes.len()) {
            continue;
        }
        if taken.iter().any(|(s, l)| start < s + l && *s < end) {
            continue;
        }
        let Some((pos, _, field, _, _)) = found[&(start, len)]
            .iter()
            .min_by_key(|(pos, ..)| rank.get(pos).copied().unwrap_or(usize::MAX))
        else {
            continue;
        };
        taken.push((start, len));
        out.push(PartialComposition {
            producer_request_id: ctx.request_id(*pos).to_string(),
            field: field.clone(),
            start,
            length: len,
        });
    }
    out.sort_by_key(|h| h.start);
    out
}

fn cover_pieces(bytes: &[u8], found: &FoundMap) -> Option<Vec<(usize, usize)>> {
    let mut chosen: Vec<(usize, usize)> = Vec::new();
    let mut producers: BTreeSet<Pos> = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'_' | b'-' | b'.' | b':' | b'|') {
            i += 1;
            continue;
        }
        let best = found
            .keys()
            .filter(|(start, _)| *start == i)
            .max_by_key(|(_, len)| *len)?;
        chosen.push(*best);
        producers.insert(found[best][0].0);
        i += best.1;
    }
    (chosen.len() >= 2 && producers.len() >= 2).then_some(chosen)
}

fn cut_in_number(a: &[u8], b: &[u8], start: usize, len: usize, other_start: usize) -> bool {
    let digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let right = digit(a, start + len) && digit(b, other_start + len) && digit(a, start + len - 1);
    let left = start > 0
        && other_start > 0
        && digit(a, start - 1)
        && digit(b, other_start - 1)
        && digit(a, start);
    right || left
}

/// `parent` entries for the chosen fragments (longest first, without
/// overlap).
fn partial_entries(
    ctx: &FlowContext<'_>,
    value: &Consumed,
    found: FoundMap,
    rank: &HashMap<Pos, usize>,
) -> Vec<ValueOrigin> {
    let a = value.value.as_bytes();
    let mut chosen: Vec<_> = found.into_iter().collect();
    chosen.sort_by(|x, y| y.0 .1.cmp(&x.0 .1).then(x.0 .0.cmp(&y.0 .0)));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut out = Vec::new();
    let min_len = ctx.options.min_match_len.max(8);
    for ((orig_start, orig_len), producers) in chosen {
        // A fragment that overlaps an already chosen one is trimmed to what stays free
        // (>= minimum), instead of being discarded: the tip of a value (e.g. the delta
        // at the end of the XML) must not be lost to a 1-byte overlap.
        let (mut s0, mut e0) = (orig_start, orig_start + orig_len);
        for _ in 0..2 {
            for (ts, tl) in &taken {
                let te = ts + tl;
                if s0 < te && *ts < e0 {
                    if *ts <= s0 {
                        s0 = te.min(e0);
                    } else if te >= e0 {
                        e0 = (*ts).max(s0);
                    } else {
                        e0 = s0; // already chosen fragment in the middle: discard
                    }
                }
            }
        }
        if e0 <= s0 || e0 - s0 < min_len {
            continue;
        }
        let shift = (s0 - orig_start) as u64;
        let (start, len) = (s0, e0 - s0);
        let producers: Vec<_> = producers
            .into_iter()
            .map(|(pos, scope, field, offset, html)| {
                (pos, scope, field, offset.map(|o| o + shift), html)
            })
            .collect();
        taken.push((start, len));
        let mut raw = Vec::new();
        for (pos, scope, field, offset, html) in producers {
            let item = Item {
                scope,
                field,
                value: String::new(),
                offset,
                named: true,
                html,
                soft: false,
            };
            raw.push((
                rank[&pos],
                evidence(
                    ctx,
                    pos,
                    &item,
                    EvidenceKind::ValueMatch,
                    Strength::Medium,
                    Some(start as u64),
                    Some(len as u64),
                ),
            ));
        }
        let sub = Consumed {
            scope: value.scope,
            field: value.field.clone(),
            occurrence: value.occurrence,
            value: String::from_utf8_lossy(&a[start..start + len]).into_owned(),
            adapted: false,
            part_of: None,
        };
        let mut entry = finish_entry(ctx, &sub, raw, &[]);
        entry.parent = Some(value.field.clone());
        entry.offset = Some(start as u64);
        if a.len() < OPAQUE_CONSUMER_MIN {
            // components of a short named field: `token[0]`, `token[1]`…
            entry.field = format!("{}[{}]", value.field, out.len());
        }
        relabel(&mut entry);
        out.push((start, entry));
    }
    // Fragments without any producer: "no observed origin" (constants,
    // user input or generated on the client).
    if !taken.is_empty() {
        taken.sort();
        let mut cursor = 0usize;
        let mut gaps: Vec<(usize, usize)> = Vec::new();
        for (start, len) in &taken {
            if *start > cursor {
                gaps.push((cursor, *start));
            }
            cursor = cursor.max(start + len);
        }
        if cursor < a.len() {
            gaps.push((cursor, a.len()));
        }
        for (start, end) in gaps.into_iter().filter(|(s, e)| e - s >= 4) {
            let text = String::from_utf8_lossy(&a[start..end]).into_owned();
            let mut entry = ValueOrigin {
                scope: value.scope,
                field: value.field.clone(),
                occurrence: value.occurrence,
                value: preview(&text),
                length: end - start,
                status: OriginStatus::None,
                label: String::new(),
                confidence: None,
                offset: Some(start as u64),
                oldest: None,
                evidences: Vec::new(),
                repeated_from: Vec::new(),
                unobservable: Vec::new(),
                context: Vec::new(),
                partial_composition: Vec::new(),
                parent: Some(value.field.clone()),
                note: None,
            };
            relabel(&mut entry);
            out.push((start, entry));
        }
    }
    out.sort_by_key(|(start, _)| *start);
    out.into_iter().map(|(_, entry)| entry).collect()
}

/// Maximal common substrings (rightward) of `a` and `b` with >= `min` bytes:
/// (start in `a`, length, start in `b`).
pub(crate) fn maximal_common(a: &[u8], b: &[u8], min: usize) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    if a.len() < min || b.len() < min {
        return out;
    }
    // prev[j] = length of the common suffix ending at (i-1, j-1).
    let mut prev = vec![0u32; b.len() + 1];
    let mut cur = vec![0u32; b.len() + 1];
    // To detect rightward maximality we need the next row; so we keep candidates
    // and confirm them when the next diagonal does not grow.
    let mut pending: Vec<(usize, usize, u32)> = Vec::new(); // (i, j, len) of the previous row
    for i in 0..a.len() {
        for j in 0..b.len() {
            cur[j + 1] = if a[i] == b[j] { prev[j] + 1 } else { 0 };
        }
        // confirm candidates from the previous row
        for (pi, pj, plen) in pending.drain(..) {
            let grew = pi + 1 < a.len() && pj + 1 < b.len() && cur[pj + 2] == plen + 1;
            if !grew {
                let len = plen as usize;
                out.push((pi + 1 - len, len, pj + 1 - len));
            }
        }
        for j in 0..b.len() {
            if cur[j + 1] as usize >= min && (cur[j + 1] as usize) > 0 {
                pending.push((i, j, cur[j + 1]));
            }
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    for (pi, pj, plen) in pending {
        let len = plen as usize;
        out.push((pi + 1 - len, len, pj + 1 - len));
    }
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// priming_chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StepClass {
    Application,
    Protection,
    /// Context page (document that loaded the page from which a step was
    /// emitted): never a value producer.
    Page,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReason {
    /// Value that the request provides (field and preview).
    pub provides: String,
    pub field: String,
    pub kind: EvidenceKind,
    pub strength: Strength,
    /// Chain request that consumes the value.
    pub consumed_by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainStep {
    pub request_id: String,
    pub attempt_id: String,
    pub method: String,
    pub url: String,
    pub started_at: Option<f64>,
    pub class: StepClass,
    /// `strong` if any reason has strong evidence; otherwise `possible`.
    pub confidence: Confidence,
    /// Human-readable reason (fields the request provides and who consumes them).
    pub reason: String,
    pub reasons: Vec<StepReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrimingChain {
    pub request_id: String,
    /// Application requests needed, in flow order.
    pub steps: Vec<ChainStep>,
    /// Protection requests (/TSPD/, TS* cookies), kept apart.
    pub protection: Vec<ChainStep>,
    /// Context pages (Referer): documents that loaded the page from which each
    /// step was emitted. They do not produce values.
    pub pages: Vec<ChainStep>,
    /// Auxiliary frames on the Referer path (`*_JLIBS.html`, `cscform.html`…):
    /// collected outside `pages`.
    pub auxiliary_pages: Vec<ChainStep>,
    /// Values with no observed origin, ambiguous or redacted (unresolved).
    pub unresolved: Vec<UnresolvedValue>,
    pub redacted_values: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnresolvedValue {
    pub label: String,
    pub partial_composition: Vec<PartialComposition>,
    pub unobservable: Vec<Unobservable>,
    /// Requests that consume the value (the target and the chain steps).
    pub request_ids: Vec<String>,
    pub scope: ConsumedScope,
    pub field: String,
    pub status: OriginStatus,
}

pub(crate) fn is_protection_path(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url);
    path.contains("/TSPD/") || path.ends_with("/TSPD")
}

fn is_ts_cookie(name: &str) -> bool {
    name.len() > 2 && name.starts_with("TS") && name[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Document that loaded `pos` (Referer or `initiator.url`): GET HTML, earlier,
/// outside protection and static. It is the edge of the page chain.
fn referer_page_of(ctx: &FlowContext<'_>, pos: Pos) -> Option<Pos> {
    let attempt = ctx.attempt_ref(pos);
    let referer = attempt.request_headers.first_value("referer").or_else(|| {
        attempt.initiator.as_ref().and_then(|i| {
            i.url
                .as_deref()
                .or_else(|| i.stack_top.as_ref().and_then(|f| f.url.as_deref()))
        })
    })?;
    let referer = referer.split('#').next().unwrap_or(referer);
    ctx.positions()
        .filter(|cand| {
            let a = ctx.attempt_ref(*cand);
            *cand != pos
                && ctx.rel(*cand, pos) == Rel::Before
                && a.url.split('#').next() == Some(referer)
                && a.method.eq_ignore_ascii_case("GET")
                && !ctx.is_static(*cand)
                && !is_protection_path(&a.url)
        })
        .max_by_key(|cand| ctx.seq[cand])
}

/// Root of the Referer chain above `pos`: the entry of the round it belongs to.
fn referer_root(ctx: &FlowContext<'_>, pos: Pos) -> Option<Pos> {
    let mut cur = pos;
    let mut root = None;
    for _ in 0..12 {
        let Some(parent) = referer_page_of(ctx, cur) else {
            break;
        };
        root = Some(parent);
        cur = parent;
    }
    root
}

/// Entry document: application GET HTML, outside protection and static, and
/// not started by the parser (frame).
fn is_entry_document(ctx: &FlowContext<'_>, pos: Pos) -> bool {
    let a = ctx.attempt_ref(pos);
    if !a.method.eq_ignore_ascii_case("GET")
        || ctx.is_static(pos)
        || is_protection_path(&a.url)
        || a.initiator
            .as_ref()
            .is_some_and(|i| i.kind.eq_ignore_ascii_case("parser"))
    {
        return false;
    }
    a.response_headers
        .first_value("content-type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"))
}

/// Start of the target's round: the most recent occurrence, up to it, of the entry
/// document (the first application document of the session). A Connector POST has
/// the Connector's own Referer, so the Referer root alone does not find the round.
/// Without an entry document, it falls back to the root of the Referer chain.
fn round_start_of(ctx: &FlowContext<'_>, target: Pos) -> Option<Pos> {
    let first = ctx
        .positions()
        .filter(|pos| is_entry_document(ctx, *pos))
        .min_by_key(|pos| ctx.seq[pos]);
    if let Some(first) = first {
        let base = |pos: Pos| {
            let (host, path) = crate::compare::split_url(&ctx.attempt_ref(pos).url);
            format!("{host}|{path}")
        };
        let entry = base(first);
        let start = ctx
            .positions()
            .filter(|pos| ctx.seq[pos] < ctx.seq[&target])
            .filter(|pos| is_entry_document(ctx, *pos))
            .filter(|pos| base(*pos) == entry)
            .max_by_key(|pos| ctx.seq[pos]);
        return start.or(Some(first).filter(|pos| ctx.seq[pos] <= ctx.seq[&target]));
    }
    referer_root(ctx, target)
}

/// Transitive closure of the strong and medium origins of the target request.
pub fn priming_chain(
    session: &SessionV1,
    source: &dyn BodySource,
    request_id: &str,
    options: &FlowOptions,
) -> Result<PrimingChain> {
    let ctx = FlowContext::new(session, source, options);
    let mut chain = PrimingChain {
        request_id: request_id.to_string(),
        steps: Vec::new(),
        protection: Vec::new(),
        pages: Vec::new(),
        auxiliary_pages: Vec::new(),
        unresolved: Vec::new(),
        redacted_values: 0,
        warnings: Vec::new(),
    };
    let mut included: HashMap<String, ChainStep> = HashMap::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue = vec![request_id.to_string()];
    // The chain stays in the target's round: producers before the round's entry
    // (root of the target's Referer chain) do not become steps. Without a Referer
    // there is no boundary and the whole session applies.
    let round_start = ctx
        .find(request_id)
        .and_then(|target| round_start_of(&ctx, target))
        .map(|start| ctx.seq[&start]);
    while let Some(current) = queue.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let origins = origins_in(&ctx, &current)?;
        chain.redacted_values += origins.redacted_values;
        for w in &origins.warnings {
            if !chain.warnings.contains(w) {
                chain.warnings.push(w.clone());
            }
        }
        let current_protection = ctx
            .find(&current)
            .is_some_and(|pos| is_protection_path(&ctx.attempt_ref(pos).url));
        for value in &origins.values {
            if value.status == OriginStatus::Composite {
                continue;
            }
            if matches!(
                value.status,
                OriginStatus::None | OriginStatus::Redacted | OriginStatus::Repeated
            ) {
                if value.parent.is_none() && value.length > 0 && !current_protection {
                    chain.unresolved.push(UnresolvedValue {
                        label: value.label.clone(),
                        partial_composition: value.partial_composition.clone(),
                        unobservable: value.unobservable.clone(),
                        request_ids: vec![current.clone()],
                        scope: value.scope,
                        field: value.field.clone(),
                        status: value.status,
                    });
                }
                continue;
            }
            if value.status == OriginStatus::Ambiguous
                && value.parent.is_none()
                && !current_protection
            {
                chain.unresolved.push(UnresolvedValue {
                    label: value.label.clone(),
                    partial_composition: value.partial_composition.clone(),
                    unobservable: value.unobservable.clone(),
                    request_ids: vec![current.clone()],
                    scope: value.scope,
                    field: value.field.clone(),
                    status: value.status,
                });
            }
            // For the CHAIN, the step is the producer of the target's own round
            // (`produced` or `reissued`): a protocol constant value (e.g.
            // STAMP=INIT) is reissued by every page, and repeating the reissues
            // only bloats the chain without adding value. The first producer of
            // the round is chosen.
            //
            // Without a producer in the round, it climbs to the most recent earlier
            // one only when the evidence is strong (e.g. a cookie set only once) or
            // a value-match of the WHOLE value of a field (e.g. SESSIONID that only
            // appears in easynat-app of round 1). Opaque field fragments do not
            // climb: they become `unresolved` with the reason, so the chain never
            // comes out silently empty. The origins keep listing everything.
            let (nearest, withheld) = ctx
                .find(&current)
                .map(|consumer| {
                    let candidates: Vec<(Pos, &Evidence)> = value
                        .evidences
                        .iter()
                        .filter(|e| {
                            matches!(e.role, Role::Produced | Role::Reissued)
                                && matches!(e.strength, Strength::Strong | Strength::Medium)
                                && e.request_id != current
                        })
                        .filter_map(|e| ctx.find(&e.request_id).map(|pos| (pos, e)))
                        .filter(|(pos, _)| ctx.rel(*pos, consumer) == Rel::Before)
                        .collect();
                    let first_in_round = round_start.and_then(|start| {
                        candidates
                            .iter()
                            .copied()
                            .filter(|(pos, _)| ctx.seq[pos] >= start)
                            .min_by_key(|(pos, _)| ctx.seq[pos])
                    });
                    if first_in_round.is_some() || round_start.is_none() {
                        let chosen = first_in_round.or_else(|| {
                            candidates
                                .iter()
                                .copied()
                                .max_by_key(|(pos, _)| ctx.seq[pos])
                        });
                        return (chosen, None);
                    }
                    let whole_value = |e: &Evidence| {
                        e.strength == Strength::Strong
                            || (e.kind == EvidenceKind::ValueMatch
                                && e.consumed_offset.is_none()
                                && e.consumed_length.is_none())
                    };
                    match candidates
                        .iter()
                        .copied()
                        .filter(|(_, e)| whole_value(e))
                        .max_by_key(|(pos, _)| ctx.seq[pos])
                    {
                        Some(chosen) => (Some(chosen), None),
                        None => (
                            None,
                            candidates
                                .iter()
                                .copied()
                                .max_by_key(|(pos, _)| ctx.seq[pos]),
                        ),
                    }
                })
                .unwrap_or((None, None));
            if let Some((pos, e)) = nearest {
                let attempt = ctx.attempt_ref(pos);
                let producer_id = ctx.request_id(pos).to_string();
                let step = included
                    .entry(producer_id.clone())
                    .or_insert_with(|| ChainStep {
                        request_id: producer_id.clone(),
                        attempt_id: attempt.id.clone(),
                        method: attempt.method.clone(),
                        url: attempt.url.clone(),
                        started_at: attempt.started_at,
                        class: StepClass::Application,
                        confidence: Confidence::Possible,
                        reason: String::new(),
                        reasons: Vec::new(),
                    });
                step.reasons.push(StepReason {
                    provides: value.value.chars().take(60).collect(),
                    field: value.field.clone(),
                    kind: e.kind,
                    strength: e.strength,
                    consumed_by: current.clone(),
                });
                queue.push(producer_id);
            } else if let Some((pos, _)) = withheld {
                // Opaque field fragment: does not climb, but stays visible with the reason.
                let label = format!("producer only in an earlier round ({})", ctx.request_id(pos));
                let duplicate = chain.unresolved.iter().any(|u| {
                    u.request_ids.contains(&current) && u.field == value.field && u.label == label
                });
                if !current_protection
                    && value.status != OriginStatus::Ambiguous
                    && value.length > 0
                    && !duplicate
                {
                    chain.unresolved.push(UnresolvedValue {
                        label,
                        partial_composition: value.partial_composition.clone(),
                        unobservable: value.unobservable.clone(),
                        request_ids: vec![current.clone()],
                        scope: value.scope,
                        field: value.field.clone(),
                        status: value.status,
                    });
                }
            }
        }
    }
    let target_pos = ctx.find(request_id);
    let mut all: Vec<ChainStep> = included.into_values().collect();
    for step in &mut all {
        step.confidence = if step.reasons.iter().any(|r| r.strength == Strength::Strong) {
            Confidence::Strong
        } else {
            Confidence::Possible
        };
        let only_ts =
            !step.reasons.is_empty() && step.reasons.iter().all(|r| is_ts_cookie(&r.field));
        if is_protection_path(&step.url) || only_ts {
            step.class = StepClass::Protection;
        }
    }
    // /TSPD/ requests before the target enter as protection, even without
    // providing a consumed value (explicit rule by path).
    if let Some(target) = target_pos {
        for pos in ctx.positions() {
            let attempt = ctx.attempt_ref(pos);
            let id = ctx.request_id(pos);
            if ctx.rel(pos, target) == Rel::Before
                && is_protection_path(&attempt.url)
                && !all.iter().any(|s| s.request_id == id)
            {
                all.push(ChainStep {
                    request_id: id.to_string(),
                    attempt_id: attempt.id.clone(),
                    method: attempt.method.clone(),
                    url: attempt.url.clone(),
                    started_at: attempt.started_at,
                    class: StepClass::Protection,
                    confidence: Confidence::Possible,
                    reason: "protection: /TSPD/ path before the target request".to_string(),
                    reasons: vec![StepReason {
                        provides: "protection (/TSPD/ path)".to_string(),
                        field: String::new(),
                        kind: EvidenceKind::Initiator,
                        strength: Strength::Complement,
                        consumed_by: request_id.to_string(),
                    }],
                });
            }
        }
    }
    for step in &mut all {
        if step.reason.is_empty() {
            let mut parts: Vec<String> = Vec::new();
            for r in &step.reasons {
                let text = format!("provides {} to {} ({:?})", r.field, r.consumed_by, r.kind);
                if !parts.contains(&text) {
                    parts.push(text);
                }
            }
            let prefix = if step.class == StepClass::Protection {
                "protection: "
            } else {
                ""
            };
            step.reason = format!("{prefix}{}", parts.join("; "));
        }
    }
    all.sort_by(|a, b| {
        let key = |s: &ChainStep| {
            let pos = ctx.find(&s.request_id).unwrap_or((usize::MAX, 0));
            (s.started_at.map(|t| (t * 1e6) as i64), pos.0)
        };
        key(a).cmp(&key(b))
    });
    // Context pages, only from the target and the application steps (never from
    // protection or static). Climbs the Referer chain between documents: the root
    // (entry) and the document right below it are the pages; the intermediate
    // frames (e.g. `*_JLIBS.html`, `cscform.html`) are `auxiliaryPages`.
    {
        let emitters: Vec<(String, Pos)> = std::iter::once(request_id.to_string())
            .chain(
                all.iter()
                    .filter(|s| s.class == StepClass::Application)
                    .map(|s| s.request_id.clone()),
            )
            .filter_map(|id| ctx.find(&id).map(|pos| (id, pos)))
            .collect();
        let referer_page = |pos: Pos| -> Option<Pos> { referer_page_of(&ctx, pos) };
        let make = |cand: Pos, emitter: &str, aux: bool| {
            let a = ctx.attempt_ref(cand);
            ChainStep {
                request_id: ctx.request_id(cand).to_string(),
                attempt_id: a.id.clone(),
                method: a.method.clone(),
                url: a.url.clone(),
                started_at: a.started_at,
                class: StepClass::Page,
                confidence: Confidence::Possible,
                reason: if aux {
                    format!("auxiliary page (frame) on the path of {emitter}")
                } else {
                    format!(
                        "context page: loaded the page from which {emitter} was emitted (Referer)"
                    )
                },
                reasons: vec![StepReason {
                    provides: if aux {
                        "auxiliary page".to_string()
                    } else {
                        "context page".to_string()
                    },
                    field: String::new(),
                    kind: EvidenceKind::Initiator,
                    strength: Strength::Complement,
                    consumed_by: emitter.to_string(),
                }],
            }
        };
        let mut pages: Vec<ChainStep> = Vec::new();
        let mut auxiliary: Vec<ChainStep> = Vec::new();
        // Steps from earlier rounds (before the target's Referer root) do not
        // bring the pages of their round.
        for (emitter, pos) in emitters {
            if round_start.is_some_and(|start| ctx.seq[&pos] < start) {
                continue;
            }
            let mut ancestors: Vec<Pos> = Vec::new();
            let mut cur = pos;
            while let Some(parent) = referer_page(cur) {
                if ancestors.contains(&parent) || ancestors.len() >= 12 {
                    break;
                }
                ancestors.push(parent);
                cur = parent;
            }
            // Auxiliary frame = document started by the parser (iframe/frame); without
            // an initiator in the source, every document on the path is a page.
            for cand in ancestors {
                let id = ctx.request_id(cand);
                if id == request_id {
                    continue;
                }
                // Pages from earlier rounds do not enter the target's round.
                if round_start.is_some_and(|start| ctx.seq[&cand] < start) {
                    continue;
                }
                let aux = ctx
                    .attempt_ref(cand)
                    .initiator
                    .as_ref()
                    .is_some_and(|i| i.kind.eq_ignore_ascii_case("parser"));
                let list = if aux { &mut auxiliary } else { &mut pages };
                if !list.iter().any(|p| p.request_id == id) {
                    list.push(make(cand, &emitter, aux));
                }
            }
        }
        auxiliary.retain(|a| !pages.iter().any(|p| p.request_id == a.request_id));
        let by_time = |a: &ChainStep, b: &ChainStep| {
            a.started_at
                .partial_cmp(&b.started_at)
                .unwrap_or(std::cmp::Ordering::Equal)
        };
        pages.sort_by(by_time);
        auxiliary.sort_by(by_time);
        chain.pages = pages;
        chain.auxiliary_pages = auxiliary;
    }
    for step in all {
        match step.class {
            StepClass::Page => {}
            StepClass::Application => chain.steps.push(step),
            StepClass::Protection => chain.protection.push(step),
        }
    }
    let protection_ids: BTreeSet<String> = chain
        .protection
        .iter()
        .map(|step| step.request_id.clone())
        .collect();
    chain.unresolved.retain_mut(|u| {
        u.request_ids.retain(|id| !protection_ids.contains(id));
        !u.request_ids.is_empty()
    });
    // The same pending item (field, value/reason and hints) can be consumed by the
    // target and by a chain step (e.g. `n` in two requests): groups it into one
    // entry with the list of consumers instead of repeating the field.
    let mut grouped: Vec<UnresolvedValue> = Vec::new();
    for mut value in std::mem::take(&mut chain.unresolved) {
        if let Some(existing) = grouped.iter_mut().find(|u| {
            u.field == value.field
                && u.label == value.label
                && u.scope == value.scope
                && u.status == value.status
                && u.partial_composition == value.partial_composition
                && u.unobservable == value.unobservable
        }) {
            for id in value.request_ids.drain(..) {
                if !existing.request_ids.contains(&id) {
                    existing.request_ids.push(id);
                }
            }
        } else {
            grouped.push(value);
        }
    }
    chain.unresolved = grouped;
    chain.unresolved.dedup();
    Ok(chain)
}
