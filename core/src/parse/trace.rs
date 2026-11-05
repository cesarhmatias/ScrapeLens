//! Importer for the priming script's execution trace (`scrapelens.trace/1`).
//!
//! The script writes this JSON (file 0600; it contains session data, do not
//! share it without sanitizing). The core never runs the script and makes no network calls.
//!
//! ```json
//! {
//!   "schema": "scrapelens.trace/1",            // required, exact
//!   "generator": "scrapelens-priming 1.0",     // optional
//!   "startedAt": "2026-10-29T12:00:00Z",       // optional, ISO-8601 UTC
//!   "parameters": [ {"name":"placa","part":"XML.p.v_placa"} ],  // optional: the script's user
//!                                              // inputs, WITHOUT values; `part` = internal
//!                                              // name (adapter part) or form/query field;
//!                                              // without `part`, `name` is used.
//!                                              // The validate exempts only the (name, part) pair
//!                                              // that the capture's regenerated plan produces
//!                                              // (e.g. sessionid_cliente → XML.sid); any other
//!                                              // pair goes through the normal checks
//!   "target": "har-0127",                      // requestId of the target IN THE CAPTURE (validate requires
//!                                              // it to be paired; without it, "incomplete")
//!   "complete": true,                          // the script ran the whole plan (false/absent
//!                                              // = "incomplete")
//!   "plan": {"version":2,                      // optional: plan schema version; without it,
//!                                              // validate treats it as an earlier version and only warns
//!            "hash":"<hex>",                    // plan fingerprint (see
//!                                              // `validate::plan_hash`)
//!            "parameters":[…]},                 // REQUIRED plan parameters (names used in
//!                                              // the hash; classified as user parameter,
//!                                              // but not checked by `parameters`)
//!   "steps": [                                 // required; execution order
//!     {
//!       "method": "POST",                      // required
//!       "url": "https://host/p?q=1",           // required (http/https)
//!       "requestHeaders": [["Name","value"]],  // [name, value] pairs or {"name","value"};
//!                                              // duplicates preserved; no guarantee of
//!                                              // wire order
//!       "requestBody": Body | null,
//!       "status": 200,                         // null/absent if there was no response
//!       "responseHeaders": [["Name","value"]],
//!       "responseBody": Body | null,
//!       "startedAt": "2026-10-29T12:00:01Z",   // optional
//!       "elapsedMs": 123.4,                    // optional, >= 0
//!       "error": "timeout",                    // optional: transport failure
//!       "checks": [ {"name":"app-ok","ok":true,"detail":"…"} ]  // step checks
//!     }
//!   ]
//! }
//! // Body = { "text": "…", "encoding": "utf8" (default) | "base64",
//! //          "truncated": false, "size": 12345 }   // size = real size, if truncated
//! ```
//!
//! The imported session takes the label `script-trace`, source "script execution"
//! (provenance `har`, method `script-trace`), headers with order `Unknown` (not the
//! wire order) and bodies as attachments. A `truncated` body becomes the `truncated`
//! state; a check with `ok:false` and an `error` become warnings.
//! A malformed entry is a clear error (never a panic); the cost is linear in the
//! file size (at most [`MAX_STEPS`] steps).

use serde_json::{json, Map, Value};

use crate::error::{CoreError, Result};
use crate::model::{BodyState, OrderState, Warning, WarningSeverity};
use crate::parse::{ImportReport, ImportedSession};

pub const TRACE_SCHEMA: &str = "scrapelens.trace/1";
pub const TRACE_LABEL: &str = "script-trace";
type BodyParts = (Map<String, Value>, bool, Option<u64>);
/// (req truncated, real size, resp truncated, real size, bad checks, error)
type StepNotes = (
    bool,
    Option<u64>,
    bool,
    Option<u64>,
    Vec<String>,
    Option<String>,
);

/// Prefix of the session notes that carry the trace's user parameters.
/// The note's value is a JSON object `{"name":…,"part":…}` (the `validate` decides
/// the exemption by comparing the pair with the capture's regenerated plan).
pub const PARAM_NOTE_PREFIX: &str = "trace-param: ";
pub const TARGET_NOTE_PREFIX: &str = "trace-target: ";
pub const COMPLETE_NOTE_PREFIX: &str = "trace-complete: ";
pub const PLAN_HASH_NOTE_PREFIX: &str = "trace-plan-hash: ";
/// Names in `plan.parameters` (the plan parameters, used in the hash).
pub const PLAN_PARAM_NOTE_PREFIX: &str = "trace-plan-param: ";
/// Present when the trace carries the `plan` object.
pub const PLAN_PRESENT_NOTE: &str = "trace-plan: present";
/// Plan schema version (`plan.version`), when present.
pub const PLAN_VERSION_NOTE_PREFIX: &str = "trace-plan-version: ";

pub const MAX_STEPS: usize = 20_000;
/// Headers per list (sent and received), per step.
pub const MAX_HEADERS_PER_STEP: usize = 512;
/// Maximum size of the trace file.
pub const MAX_TRACE_BYTES: usize = 256 * 1024 * 1024;

fn bad(message: impl Into<String>) -> CoreError {
    CoreError::UnsupportedFormat {
        message: format!("trace: {}", message.into()),
    }
}

/// Name of an item in `parameters`/`plan.parameters`: direct text, or the
/// `name` and, if absent, the `part`.
fn param_name(p: &Value) -> Option<&str> {
    match p {
        Value::String(s) => Some(s.as_str()),
        _ => p
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| p.get("part").and_then(Value::as_str)),
    }
    .filter(|s| !s.is_empty())
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`.
fn valid_iso(text: &str) -> bool {
    let b = text.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !(digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10))
        || !(b[10] == b'T'
            && digits(11..13)
            && b[13] == b':'
            && digits(14..16)
            && b[16] == b':'
            && digits(17..19))
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    let tz = &text[i..];
    tz == "Z"
        || (tz.len() == 6
            && matches!(tz.as_bytes()[0], b'+' | b'-')
            && tz.as_bytes()[3] == b':'
            && digits(i + 1..i + 3)
            && digits(i + 4..i + 6))
}

fn headers_of(step: &Value, key: &str, index: usize) -> Result<Vec<Value>> {
    let Some(value) = step.get(key).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| bad(format!("steps[{index}].{key} is not a list")))?;
    if array.len() > MAX_HEADERS_PER_STEP {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "trace: steps[{index}].{key} with {} headers (maximum {MAX_HEADERS_PER_STEP})",
                array.len()
            ),
        });
    }
    array
        .iter()
        .enumerate()
        .map(|(n, h)| {
            let pair = match h {
                Value::Array(p) if p.len() == 2 => (p[0].as_str(), p[1].as_str()),
                Value::Object(o) => (
                    o.get("name").and_then(Value::as_str),
                    o.get("value").and_then(Value::as_str),
                ),
                _ => (None, None),
            };
            match pair {
                (Some(name), Some(value)) if !name.is_empty() => {
                    Ok(json!({"name": name, "value": value}))
                }
                _ => Err(bad(format!(
                    "steps[{index}].{key}[{n}] must be [name, value] with strings"
                ))),
            }
        })
        .collect()
}

/// `(content/postData in HAR form, truncated, real size)`
fn body_of(step: &Value, key: &str, index: usize) -> Result<Option<BodyParts>> {
    let Some(body) = step.get(key).filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let object = body
        .as_object()
        .ok_or_else(|| bad(format!("steps[{index}].{key} is not an object")))?;
    let text = object
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("steps[{index}].{key}.text missing or not a string")))?;
    let encoding = object
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("utf8");
    if encoding != "utf8" && encoding != "base64" {
        return Err(bad(format!(
            "steps[{index}].{key}.encoding {encoding:?} unknown (utf8|base64)"
        )));
    }
    let truncated = object
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let size = object.get("size").and_then(Value::as_u64);
    let mut out = Map::new();
    out.insert("text".into(), json!(text));
    if encoding == "base64" {
        out.insert("encoding".into(), json!("base64"));
    }
    Ok(Some((out, truncated, size)))
}

pub fn import_trace(json_bytes: &[u8]) -> Result<ImportedSession> {
    if json_bytes.len() > MAX_TRACE_BYTES {
        return Err(CoreError::LimitExceeded {
            message: format!(
                "trace with {} bytes (maximum {MAX_TRACE_BYTES})",
                json_bytes.len()
            ),
        });
    }
    let root: Value =
        serde_json::from_slice(json_bytes).map_err(|e| CoreError::json("trace", e))?;
    match root.get("schema").and_then(Value::as_str) {
        Some(TRACE_SCHEMA) => {}
        Some(other) => {
            return Err(bad(format!(
                "schema {other:?} not supported (expected {TRACE_SCHEMA})"
            )))
        }
        None => {
            return Err(CoreError::MissingField {
                field: "schema".into(),
            })
        }
    }
    let steps =
        root.get("steps")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::MissingField {
                field: "steps".into(),
            })?;
    if steps.len() > MAX_STEPS {
        return Err(CoreError::LimitExceeded {
            message: format!("trace with {} steps (maximum {MAX_STEPS})", steps.len()),
        });
    }
    let generator = root
        .get("generator")
        .and_then(Value::as_str)
        .unwrap_or("script");
    let epoch = "1970-01-01T00:00:00Z";
    let started = root.get("startedAt").and_then(Value::as_str);
    if started.is_some_and(|t| !valid_iso(t)) {
        return Err(bad(
            "startedAt invalid (use ISO-8601, e.g.: 2026-10-29T12:00:00Z)",
        ));
    }

    let mut entries = Vec::with_capacity(steps.len());
    // (index, request truncated, response truncated, real sizes, bad checks, error)
    let mut notes: Vec<StepNotes> = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        if !step.is_object() {
            return Err(bad(format!("steps[{index}] is not an object")));
        }
        let text_of = |key: &str| {
            step.get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| bad(format!("steps[{index}].{key} missing or empty")))
        };
        let method = text_of("method")?;
        let url = text_of("url")?;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(bad(format!("steps[{index}].url is not http(s)")));
        }
        if url.len() > 16 * 1024 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(bad(format!(
                "steps[{index}].url has a space, a control character, or is too long"
            )));
        }
        let mut request = json!({
            "method": method, "url": url, "httpVersion": "HTTP/1.1",
            "headers": headers_of(step, "requestHeaders", index)?,
            "cookies": [], "queryString": [], "headersSize": -1, "bodySize": -1,
        });
        let mut req_trunc = (false, None);
        if let Some((mut body, truncated, size)) = body_of(step, "requestBody", index)? {
            let mime = request["headers"]
                .as_array()
                .and_then(|h| {
                    h.iter().find(|h| {
                        h["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case("content-type"))
                    })
                })
                .and_then(|h| h["value"].as_str())
                .unwrap_or("application/octet-stream")
                .to_string();
            if body.get("encoding").is_some() {
                // HAR postData has no encoding: decode the base64 here
                use base64::Engine;
                let raw = body["text"].as_str().unwrap_or("");
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .map_err(|e| bad(format!("steps[{index}].requestBody base64 invalid: {e}")))?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                body.insert("text".into(), json!(text));
                body.remove("encoding");
            }
            body.insert("mimeType".into(), json!(mime));
            request["postData"] = Value::Object(body);
            req_trunc = (truncated, size);
        }
        let status = step.get("status").and_then(Value::as_u64);
        if let Some(s) = step.get("status").filter(|v| !v.is_null()) {
            if !s.as_u64().is_some_and(|n| (100..=599).contains(&n)) {
                return Err(bad(format!(
                    "steps[{index}].status must be 100–599 or null"
                )));
            }
        }
        let mut content = json!({"size": 0, "mimeType": "x-unknown"});
        let mut resp_trunc = (false, None);
        if let Some((body, truncated, size)) = body_of(step, "responseBody", index)? {
            let mime = headers_of(step, "responseHeaders", index)?
                .iter()
                .find(|h| {
                    h["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case("content-type"))
                })
                .and_then(|h| h["value"].as_str().map(str::to_string))
                .unwrap_or_else(|| "application/octet-stream".into());
            content = Value::Object(body);
            content["mimeType"] = json!(mime);
            content["size"] = json!(size.unwrap_or(0));
            resp_trunc = (truncated, size);
        }
        let elapsed = step.get("elapsedMs").and_then(Value::as_f64);
        if elapsed.is_some_and(|e| e < 0.0 || !e.is_finite()) {
            return Err(bad(format!("steps[{index}].elapsedMs invalid")));
        }
        let own_start = step.get("startedAt").and_then(Value::as_str);
        if own_start.is_some_and(|t| !valid_iso(t)) {
            return Err(bad(format!("steps[{index}].startedAt invalid (ISO-8601)")));
        }
        let step_start = own_start.or(started).unwrap_or(epoch);
        let mut bad_checks = Vec::new();
        if let Some(checks) = step.get("checks").filter(|v| !v.is_null()) {
            let list = checks
                .as_array()
                .ok_or_else(|| bad(format!("steps[{index}].checks is not a list")))?;
            for c in list {
                let name = c.get("name").and_then(Value::as_str);
                let ok = c.get("ok").and_then(Value::as_bool);
                match (name, ok) {
                    (Some(name), Some(false)) => {
                        let detail = c.get("detail").and_then(Value::as_str).unwrap_or("");
                        bad_checks.push(format!("{name}: {detail}"));
                    }
                    (Some(_), Some(true)) => {}
                    _ => return Err(bad(format!("steps[{index}].checks: use {{name, ok}}"))),
                }
            }
        }
        let error = step
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string);
        entries.push(json!({
            "startedDateTime": step_start,
            "time": elapsed.unwrap_or(0.0),
            "request": request,
            "response": {
                "status": status.unwrap_or(0), "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": headers_of(step, "responseHeaders", index)?,
                "cookies": [], "content": content, "redirectURL": "",
                "headersSize": -1, "bodySize": -1,
            },
            "cache": {}, "timings": {"send": 0, "wait": elapsed.unwrap_or(0.0), "receive": 0},
        }));
        notes.push((
            req_trunc.0,
            req_trunc.1,
            resp_trunc.0,
            resp_trunc.1,
            bad_checks,
            error,
        ));
    }

    let har = json!({"log": {
        "version": "1.2",
        "creator": {"name": "script-trace", "version": generator},
        "entries": entries,
    }});
    let mut imported = crate::parse::har::import_har(
        &serde_json::to_vec(&har).map_err(|e| CoreError::json("trace", e))?,
    )?;
    let mut report = ImportReport::new(crate::parse::InputFormat::Har);
    report.bytes_read = json_bytes.len();

    let session = &mut imported.bundle.session;
    if !session.session.labels.iter().any(|l| l == TRACE_LABEL) {
        session.session.labels.push(TRACE_LABEL.to_string());
    }
    let plan = root.get("plan").filter(|v| !v.is_null());
    // Top-level `parameters`: the script's user inputs. The note keeps the pair
    // (name, part); the validate exempts only the pair that the capture's
    // regenerated plan produces, never what the trace declares.
    if let Some(params) = root.get("parameters").filter(|v| !v.is_null()) {
        let list = params
            .as_array()
            .ok_or_else(|| bad("parameters is not a list"))?;
        for (n, p) in list.iter().enumerate() {
            let (name, part) = match p {
                Value::String(s) => (Some(s.as_str()), None),
                _ => (
                    p.get("name").and_then(Value::as_str),
                    p.get("part").and_then(Value::as_str),
                ),
            };
            let name = name.filter(|s| !s.is_empty());
            let part = part.filter(|s| !s.is_empty()).or(name);
            let Some(part) = part else {
                return Err(bad(format!("parameters[{n}] needs name or part")));
            };
            let note = format!(
                "{PARAM_NOTE_PREFIX}{}",
                json!({"name": name.unwrap_or(part), "part": part})
            );
            if !session.session.notes.contains(&note) {
                session.session.notes.push(note);
            }
        }
    }
    if let Some(plan) = plan.filter(|p| p.is_object()) {
        session.session.notes.push(PLAN_PRESENT_NOTE.to_string());
        if let Some(version) = plan.get("version").filter(|v| !v.is_null()) {
            let version = version
                .as_u64()
                .filter(|n| *n <= u64::from(u32::MAX))
                .ok_or_else(|| bad("plan.version must be an integer"))?;
            session
                .session
                .notes
                .push(format!("{PLAN_VERSION_NOTE_PREFIX}{version}"));
        }
        if let Some(list) = plan.get("parameters").and_then(Value::as_array) {
            for p in list {
                if let Some(name) = param_name(p) {
                    session
                        .session
                        .notes
                        .push(format!("{PLAN_PARAM_NOTE_PREFIX}{name}"));
                }
            }
        }
    }
    if let Some(target) = root.get("target").filter(|v| !v.is_null()) {
        let target = target
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| bad("target must be text (requestId of the target in the capture)"))?;
        session
            .session
            .notes
            .push(format!("{TARGET_NOTE_PREFIX}{target}"));
    }
    if let Some(complete) = root.get("complete").filter(|v| !v.is_null()) {
        let complete = complete
            .as_bool()
            .ok_or_else(|| bad("complete must be a boolean"))?;
        session
            .session
            .notes
            .push(format!("{COMPLETE_NOTE_PREFIX}{complete}"));
    }
    if let Some(hash) = plan.and_then(|p| p.get("hash")).filter(|v| !v.is_null()) {
        let hash = hash
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or_else(|| bad("plan.hash must be text"))?;
        session
            .session
            .notes
            .push(format!("{PLAN_HASH_NOTE_PREFIX}{hash}"));
    }
    session.session.notes.push(
        "source: script execution (scrapelens.trace/1); headers without a guarantee of wire order"
            .to_string(),
    );
    let mut warnings: Vec<Warning> = Vec::new();
    for (request, (req_trunc, req_size, resp_trunc, resp_size, bad_checks, error)) in
        session.requests.iter_mut().zip(notes)
    {
        let id = request.id.clone();
        for attempt in request.attempts.iter_mut() {
            attempt.request_headers.order_state = OrderState::Unknown;
            attempt.response_headers.order_state = OrderState::Unknown;
            attempt.provenance.method = TRACE_LABEL.to_string();
            attempt
                .provenance
                .notes
                .push("script execution".to_string());
            for (body, truncated, size) in [
                (&mut attempt.request_body, req_trunc, req_size),
                (&mut attempt.response_body, resp_trunc, resp_size),
            ] {
                if truncated && body.state == BodyState::Captured {
                    body.truncated_at = body.bytes;
                    body.state = BodyState::Truncated;
                    if size.is_some() {
                        body.bytes = size;
                    }
                }
            }
        }
        if req_trunc || resp_trunc {
            warnings.push(
                Warning::new(
                    "trace.body_truncated",
                    format!("{id}: body truncated in the trace"),
                )
                .with_entity(&id),
            );
        }
        for check in bad_checks {
            warnings.push(
                Warning::new("trace.check_failed", format!("{id}: {check}")).with_entity(&id),
            );
        }
        if let Some(error) = error {
            warnings
                .push(Warning::new("trace.step_error", format!("{id}: {error}")).with_entity(&id));
        }
    }
    for mut w in warnings {
        w.severity = WarningSeverity::Warning;
        report.warn(w.clone());
        session.warnings.push(w);
    }
    imported.report.merge(report);
    Ok(imported)
}
