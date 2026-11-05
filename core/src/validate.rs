//! Validation of the script execution (docs/13 §3): compares the capture with the
//! session imported from the trace and summarizes it in three verdicts:
//! - `equivalent`: "execution equivalent to capture";
//! - `diverges`: "diverges at step N (<reason>)" — status or assess verdict
//!   differs, extra step in the trace, missing step, field that should be
//!   constant and changed;
//! - `incomplete`: "incomplete: stopped at step N" — step N of the trace
//!   failed in transport (no response / `trace.step_error`).
//!
//! Step = position (1 = first) of the request in the trace session. Capture steps
//! that the trace did not execute after the last paired step do not count
//! (the script covers a chain up to the target, not the whole capture).
//! Expected differences (dynamics with equivalent origin, environment:
//! headers and cookies, valid user parameters) are kept apart from the
//! unexpected ones.
//!
//! Equivalent provenance: a field with origin in the capture's response R_k
//! must, in the trace, have origin in the response paired with R_k. A captured value
//! absent from the paired response = "frozen value"; coming from another response =
//! "different origin".
//!
//! Completeness: the trace declares `target` (requestId of the target in the capture, which
//! must be paired) and `complete=true`; otherwise it is "incomplete".
//!
//! `parameters` only applies to a field with no origin in the capture and that is not
//! constant (long opaque identifier); the others are ignored with the
//! warning "invalid parameter". `plan.parameters` of a verified plan (current version,
//! hash and target checked) classify as user parameter, without
//! these checks; in an unverified plan they receive the same treatment as the
//! top-level `parameters` and exempt nothing.
//! The exemption from `parameters` only applies to the (name, part) pair that the plan
//! regenerated from the capture actually produces (e.g. sessionid_cliente → XML.sid);
//! any other pair under a plan name goes through all checks and gets the warning
//! "parameter does not match the plan: <name> → <part>".
//!
//! Versioned plan: `plan.version` equal to [`PLAN_VERSION`] compares the plan hash
//! (divergence if it does not match); a missing or different version is a plan from an
//! earlier build and only warns; a plan without hash warns "plan without fingerprint".

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{
    compare_sessions, single_app_origin, split_url, CompareOptions, FieldClass, OriginMap,
};
use crate::error::Result;
use crate::export::priming::{plan_parameter_uses, AdapterEncoder, PrimingOptions};
use crate::flow::{
    origins_in, priming_chain, ConsumedScope, FlowContext, FlowOptions, OriginStatus, ValueOrigin,
    ValueOrigins,
};
use crate::model::SessionV1;
use crate::parse::trace::{
    COMPLETE_NOTE_PREFIX, PARAM_NOTE_PREFIX, PLAN_HASH_NOTE_PREFIX, PLAN_PARAM_NOTE_PREFIX,
    PLAN_PRESENT_NOTE, PLAN_VERSION_NOTE_PREFIX, TARGET_NOTE_PREFIX,
};
use crate::search::BodySource;

#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub compare: CompareOptions,
    pub rules: AssessRules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationVerdict {
    Equivalent,
    Diverges,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldNote {
    pub scope: String,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepValidation {
    /// Step position in the trace (1 = first).
    pub step: usize,
    pub trace_request_id: String,
    /// Paired capture request (`None` = extra step in the trace).
    pub capture_request_id: Option<String>,
    pub method: String,
    pub url: String,
    pub status_capture: Option<u16>,
    pub status_trace: Option<u16>,
    pub verdict_capture: Option<VerdictKind>,
    pub verdict_trace: VerdictKind,
    /// Dynamics with origin and environment differences.
    pub expected: Vec<FieldNote>,
    pub unexpected: Vec<FieldNote>,
    /// Divergence reason at this step, if any.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validation {
    pub schema: String,
    pub verdict: ValidationVerdict,
    pub step: Option<usize>,
    pub reason: Option<String>,
    /// Summary line: "execution equivalent to capture" etc.
    pub summary: String,
    pub steps: Vec<StepValidation>,
    /// Capture steps (POST/non-GET) without a pair among the paired trace steps.
    pub missing_in_trace: Vec<String>,
    pub mapped_origin: Option<OriginMap>,
    pub warnings: Vec<String>,
}

const ENV_HEADERS: &[&str] = &[
    "host",
    "origin",
    "referer",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "content-length",
    "connection",
    "date",
    "server",
    "cache-control",
    "pragma",
    "upgrade-insecure-requests",
];

fn env_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ENV_HEADERS.contains(&n.as_str()) || n.starts_with("sec-") || n.starts_with("x-forwarded")
}

type Key = (String, String, usize);

fn key_of(scope: ConsumedScope, field: &str, occurrence: usize) -> Key {
    (format!("{scope:?}"), field.to_string(), occurrence)
}

/// Long value (>= 16) without spaces: identifier/secret, not user input.
fn long_opaque(v: &str) -> bool {
    v.len() >= 16 && !v.contains(char::is_whitespace)
}

/// The capture marks the value as composed/generated in the client.
fn client_composed(v: &ValueOrigin) -> bool {
    !v.partial_composition.is_empty()
        || v.label.contains("composition in the client")
        || v.label.contains("composição no cliente")
        || v.label.contains("gerado no cliente")
}

/// Current plan version (`plan.version` in the trace). The hash is only compared
/// when the trace declares exactly this version; a missing or different version
/// is a plan from an earlier build and only produces a warning. Changed the hash definition?
/// Bump the version.
pub const PLAN_VERSION: u32 = 2;

/// Plan fingerprint of a target: chain steps (method + path
/// normalized, without host) and parameter names. FNV-1a 64 in hexadecimal.
/// The script generator writes this value to `plan.hash` in the trace.
pub fn plan_hash(
    capture: &SessionV1,
    source: &dyn BodySource,
    target: &str,
    flow: &FlowOptions,
    parameter_names: &[String],
) -> Result<String> {
    let chain = priming_chain(capture, source, target, flow)?;
    let mut text = String::new();
    let line = |text: &mut String, tag: &str, method: &str, url: &str| {
        let (_, path) = split_url(url);
        let _ = writeln!(text, "{tag} {} {path}", method.to_ascii_uppercase());
    };
    for step in &chain.steps {
        line(&mut text, "step", &step.method, &step.url);
    }
    if let Some(r) = capture.requests.iter().find(|r| r.id == target) {
        if let Some(a) = r.attempts.last() {
            line(&mut text, "target", &a.method, &a.url);
        }
    }
    let mut names: Vec<String> = parameter_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    for n in names {
        let _ = writeln!(text, "param {n}");
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Ok(format!("{hash:016x}"))
}

fn note_value<'a>(trace: &'a SessionV1, prefix: &str) -> Option<&'a str> {
    trace
        .session
        .notes
        .iter()
        .find_map(|n| n.strip_prefix(prefix))
}

/// Pairs `(parameter, part/field)` that the plan REGENERATED FROM THE CAPTURE installs.
/// Never uses what the trace declares: the generator is called with the capture, the target
/// and the same flow as the hash. Encoders only matter for the shape of the generated text;
/// here a marker per adapter is enough so that the parts are decoded
/// and the names registered (the text is discarded).
fn produced_parameter_uses(
    capture: &SessionV1,
    source: &dyn BodySource,
    target: &str,
    flow: &FlowOptions,
) -> Option<Vec<(String, String)>> {
    let adapter_encoders: Vec<AdapterEncoder> = flow
        .adapters
        .iter()
        .map(|a| AdapterEncoder {
            adapter_id: a.id().to_string(),
            function: format!("{}_encode", a.id().replace('-', "_")),
            decoder: String::new(),
            source: String::new(),
        })
        .collect();
    let opts = PrimingOptions {
        flow: flow.clone(),
        adapter_encoders,
        ..Default::default()
    };
    plan_parameter_uses(capture, source, target, &opts)
        .ok()
        .map(|uses| uses.into_iter().collect())
}

pub fn validate(
    capture: &SessionV1,
    capture_source: &dyn BodySource,
    trace: &SessionV1,
    trace_source: &dyn BodySource,
    options: &ValidateOptions,
) -> Validation {
    let cmp = compare_sessions(
        capture,
        capture_source,
        trace,
        trace_source,
        &options.compare,
    );
    let mut warnings = cmp.warnings.clone();
    let ctx_a = FlowContext::new(capture, capture_source, &options.compare.flow);
    let ctx_b = FlowContext::new(trace, trace_source, &options.compare.flow);
    let out_a = assess_session(capture, capture_source, &options.rules);
    let out_b = assess_session(trace, trace_source, &options.rules);
    let verdict_a = |id: &str| out_a.iter().find(|o| o.request_id == id);
    let verdict_b = |id: &str| out_b.iter().find(|o| o.request_id == id);
    let step_of = |id: &str| {
        trace
            .requests
            .iter()
            .position(|r| r.id == id)
            .map(|i| i + 1)
    };
    let trace_err = |id: &str| -> bool {
        trace
            .warnings
            .iter()
            .any(|w| w.code == "trace.step_error" && w.entity.as_deref() == Some(id))
    };
    let a_to_b: HashMap<&str, &str> = cmp
        .pairs
        .iter()
        .map(|p| (p.a.request_id.as_str(), p.b.request_id.as_str()))
        .collect();

    // capture origins per paired request (once)
    let origins_a: HashMap<&str, ValueOrigins> = cmp
        .pairs
        .iter()
        .filter_map(|p| {
            Some((
                p.a.request_id.as_str(),
                origins_in(&ctx_a, &p.a.request_id).ok()?,
            ))
        })
        .collect();
    let origins_b: HashMap<&str, ValueOrigins> = cmp
        .pairs
        .iter()
        .filter_map(|p| {
            Some((
                p.b.request_id.as_str(),
                origins_in(&ctx_b, &p.b.request_id).ok()?,
            ))
        })
        .collect();

    // declared target and the pairs that the plan REGENERATED FROM THE CAPTURE produces; only these
    // pairs can be exempt. Without a target (or if generation fails), nothing is exempt.
    let target_note = note_value(trace, TARGET_NOTE_PREFIX).map(str::to_string);
    let produced: Vec<(String, String)> = target_note
        .as_deref()
        .and_then(|t| produced_parameter_uses(capture, capture_source, t, &options.compare.flow))
        .unwrap_or_default();
    let plan_names: Vec<&str> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(PLAN_PARAM_NOTE_PREFIX))
        .collect();

    // plan fingerprint × recalculated from the capture and the target, only with the
    // plan parameters (`plan.parameters`); the top-level `parameters` (including
    // optional ones overridden by the user) is not part of the hash. The plan version
    // protects traces from earlier builds: without a current `plan.version`, it does not compare.
    // `plan.parameters` only classifies as a parameter when the plan is
    // verified (current version, hash and target checked); in other cases it
    // exempts nothing.
    let target = target_note;
    let mut plan_mismatch = false;
    let mut plan_verified = false;
    if !trace.session.notes.iter().any(|n| n == PLAN_PRESENT_NOTE) {
        warnings.push("plan missing: execution not verified against the plan".to_string());
    } else {
        let version =
            note_value(trace, PLAN_VERSION_NOTE_PREFIX).and_then(|v| v.parse::<u32>().ok());
        if version != Some(PLAN_VERSION) {
            let message = match version {
                Some(v) if v > PLAN_VERSION => format!(
                    "plan of a different version (v{v}): regenerate the script to verify against the plan"
                ),
                _ => {
                    let label = version.map_or_else(|| "v1".to_string(), |v| format!("v{v}"));
                    format!(
                        "plan of an earlier version ({label}): regenerate the script to verify against the plan"
                    )
                }
            };
            warnings.push(message);
        } else if let Some(declared_hash) = note_value(trace, PLAN_HASH_NOTE_PREFIX) {
            if let Some(target) = &target {
                let names: Vec<String> = plan_names.iter().map(|n| n.to_string()).collect();
                match plan_hash(
                    capture,
                    capture_source,
                    target,
                    &options.compare.flow,
                    &names,
                ) {
                    Ok(h) if h == declared_hash => plan_verified = true,
                    Ok(h) => {
                        plan_mismatch = true;
                        warnings.push(format!(
                            "plan does not match: the trace declares hash {declared_hash} and the capture with target {target} gives {h}"
                        ));
                    }
                    Err(e) => warnings.push(format!("plan not verified: {e}")),
                }
            } else {
                warnings.push("plan without target: execution not verified against the plan".to_string());
            }
        } else {
            warnings.push("plan without fingerprint".to_string());
        }
    }

    // parameters declared in the trace: `(name, part)`. Only the part that the plan
    // produces is exempt; the others go through the normal checks.
    let declared: Vec<(String, String)> = trace
        .session
        .notes
        .iter()
        .filter_map(|n| n.strip_prefix(PARAM_NOTE_PREFIX))
        .filter_map(|v| {
            let doc: Option<serde_json::Value> = serde_json::from_str(v).ok();
            let (name, part) = match doc {
                Some(o) => (
                    o.get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    o.get("part")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                ),
                // old format: only the part
                None => (Some(v.to_string()), Some(v.to_string())),
            };
            let part = part.filter(|s| !s.is_empty())?;
            Some((name.unwrap_or_else(|| part.clone()), part))
        })
        .collect();
    let mut params: Vec<&str> = Vec::new();
    for (name, part) in &declared {
        let produced_pair = produced
            .iter()
            .any(|(n, p)| n.eq_ignore_ascii_case(name) && p.eq_ignore_ascii_case(part));
        if produced_pair {
            if !params.iter().any(|p| p.eq_ignore_ascii_case(part)) {
                params.push(part.as_str());
            }
            continue;
        }
        let mut seen = false;
        let mut why: Option<&str> = None;
        for o in origins_a.values() {
            for v in o.values.iter().filter(|v| {
                matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                    && v.field.eq_ignore_ascii_case(part)
            }) {
                seen = true;
                if v.evidences
                    .iter()
                    .any(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                {
                    why = Some("has origin in capture");
                } else if long_opaque(&v.value) && why.is_none() {
                    why = Some("is a constant/long identifier");
                }
            }
        }
        match (seen, why) {
            (false, _) => warnings.push(format!(
                "invalid parameter: `{part}` does not exist in the paired steps of the capture"
            )),
            (true, Some(why)) => warnings.push(format!("invalid parameter: `{part}` {why}")),
            (true, None) => {}
        }
        let in_plan = plan_names.iter().any(|n| n.eq_ignore_ascii_case(name))
            || produced.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
        if in_plan {
            warnings.push(format!(
                "parameter does not match the plan: {name} → {part}"
            ));
            // does not classify: the part follows the normal provenance and diff
        } else if seen && why.is_none() && !params.iter().any(|p| p.eq_ignore_ascii_case(part)) {
            params.push(part.as_str());
        }
    }
    if plan_verified {
        // `plan.parameters` of a VERIFIED plan (current version, hash and target
        // checked): they classify as user parameters, without checks.
        for name in &plan_names {
            if !params.iter().any(|p| p.eq_ignore_ascii_case(name)) {
                params.push(name);
            }
        }
    } else {
        // Unverified plan (old/different version, no hash, hash that does not
        // match, or no target): the names in `plan.parameters` receive the same
        // treatment as top-level `parameters`. A name that is not a part does not generate
        // a "does not exist" warning; the concrete field follows the provenance/diff.
        for name in &plan_names {
            let mut seen = false;
            let mut why: Option<&str> = None;
            for o in origins_a.values() {
                for v in o.values.iter().filter(|v| {
                    matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                        && v.field.eq_ignore_ascii_case(name)
                }) {
                    seen = true;
                    if v.evidences
                        .iter()
                        .any(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                    {
                        why = Some("has origin in capture");
                    } else if long_opaque(&v.value) && why.is_none() {
                        why = Some("is a constant/long identifier");
                    }
                }
            }
            match (seen, why) {
                (false, _) => {}
                (true, Some(why)) => warnings.push(format!("invalid parameter: `{name}` {why}")),
                (true, None) => {
                    if !params.iter().any(|p| p.eq_ignore_ascii_case(name)) {
                        params.push(name);
                    }
                }
            }
        }
    }
    let is_param = |field: &str| params.iter().any(|p| p.eq_ignore_ascii_case(field));

    let mut steps: Vec<StepValidation> = Vec::new();
    let mut seen_b: std::collections::BTreeSet<String> = Default::default();
    for pair in &cmp.pairs {
        let (Some(step), Some(ob)) = (step_of(&pair.b.request_id), verdict_b(&pair.b.request_id))
        else {
            continue;
        };
        seen_b.insert(pair.b.request_id.clone());
        let oa = verdict_a(&pair.a.request_id);
        let (mut expected, mut unexpected) = (Vec::new(), Vec::new());
        let mut handled: std::collections::BTreeSet<Key> = Default::default();
        let note = |scope: ConsumedScope, field: &str, why: &str| FieldNote {
            scope: format!("{scope:?}").to_ascii_lowercase(),
            field: field.to_string(),
            reason: why.to_string(),
        };

        // 1) equivalent provenance of fields with origin in the capture
        if let (Some(va), Some(vb)) = (
            origins_a.get(pair.a.request_id.as_str()),
            origins_b.get(pair.b.request_id.as_str()),
        ) {
            for a in va.values.iter().filter(|v| {
                matches!(v.scope, ConsumedScope::Body | ConsumedScope::Query)
                    && !v.value.is_empty()
                    && matches!(v.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                    && v.parent
                        .as_ref()
                        .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
            }) {
                let producers_a: Vec<&str> = a
                    .evidences
                    .iter()
                    .filter(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                    .map(|e| e.request_id.as_str())
                    .collect();
                if producers_a.is_empty() {
                    continue;
                }
                let key = key_of(a.scope, &a.field, a.occurrence);
                let Some(b) = vb.values.iter().find(|v| {
                    key_of(v.scope, &v.field, v.occurrence) == key
                        && v.parent
                            .as_ref()
                            .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
                }) else {
                    continue; // field missing in the trace: handled by the diff
                };
                handled.insert(key);
                if is_param(&a.field) {
                    continue;
                }
                let paired: Vec<&str> = producers_a
                    .iter()
                    .filter_map(|id| a_to_b.get(id).copied())
                    .collect();
                let producers_b: Vec<&str> = b
                    .evidences
                    .iter()
                    .filter(|e| e.kind != crate::flow::EvidenceKind::Initiator)
                    .map(|e| e.request_id.as_str())
                    .collect();
                if producers_b.iter().any(|p| paired.contains(p)) {
                    if a.value != b.value {
                        expected.push(note(a.scope, &a.field, "dynamic with equivalent origin"));
                    }
                } else if !producers_b.is_empty() {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        &format!(
                            "different origin: in trace comes from {}, in capture came from {}",
                            producers_b.join(", "),
                            producers_a.join(", ")
                        ),
                    ));
                } else if a.value == b.value {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        "frozen value: matches captured value and is absent from paired response",
                    ));
                } else {
                    unexpected.push(note(
                        a.scope,
                        &a.field,
                        "value has no origin in trace (did not come from a previous response)",
                    ));
                }
            }
        }

        // 2) other differences (constants, inputs, environment, fragments)
        let a_origin = origins_a.get(pair.a.request_id.as_str());
        // opaque field decoded by adapter: the named parts have already been assessed
        let adapted: std::collections::BTreeSet<&str> = a_origin
            .into_iter()
            .flat_map(|o| o.values.iter())
            .filter_map(|v| {
                v.parent
                    .as_deref()
                    .filter(|p| v.field.starts_with(&format!("{p}.")))
            })
            .collect();
        let composed = |f: &crate::compare::FieldDiff| {
            a_origin.is_some_and(|o| {
                o.values.iter().any(|v| {
                    key_of(v.scope, &v.field, v.occurrence)
                        == key_of(f.scope, &f.field, f.occurrence)
                        && client_composed(v)
                })
            })
        };
        for f in &pair.fields {
            let env = f.scope == ConsumedScope::Cookie
                || (f.scope == ConsumedScope::Header && env_header(&f.field));
            if handled.contains(&key_of(f.scope, &f.field, f.occurrence))
                || (f.scope == ConsumedScope::Body && adapted.contains(f.field.as_str()))
            {
                continue;
            }
            match f.class {
                FieldClass::Static | FieldClass::Redacted => {}
                _ if is_param(&f.field) => {
                    expected.push(note(f.scope, &f.field, "expected (user parameter)"));
                }
                FieldClass::Dynamic => {
                    if env {
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "environment (cookie/header of the execution)",
                        ));
                    } else if f.origin.is_some()
                        || f.origin_label
                            .as_deref()
                            .is_some_and(|l| l.contains("runtime"))
                    {
                        // origin exists in trace and the capture did not declare it: accepted
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "dynamic with origin observed in trace",
                        ));
                    } else if !f.parts.is_empty() {
                        for p in f.parts.iter().filter(|p| p.class == FieldClass::Dynamic) {
                            if p.origin.is_some() {
                                expected.push(note(
                                    f.scope,
                                    &f.field,
                                    "dynamic fragment with observed origin",
                                ));
                            } else if long_opaque(&p.a) && long_opaque(&p.b) {
                                expected.push(note(
                                    f.scope,
                                    &f.field,
                                    "long fragment generated in the client",
                                ));
                            } else {
                                unexpected.push(note(
                                    f.scope,
                                    &f.field,
                                    "dynamic fragment without origin (should be constant)",
                                ));
                            }
                        }
                    } else if composed(f)
                        && long_opaque(f.a.as_deref().unwrap_or(""))
                        && long_opaque(f.b.as_deref().unwrap_or(""))
                    {
                        expected.push(note(
                            f.scope,
                            &f.field,
                            "identifier generated in the client (composition marked in capture)",
                        ));
                    } else {
                        unexpected.push(note(
                            f.scope,
                            &f.field,
                            "field that should be constant changed (no origin)",
                        ));
                    }
                }
                FieldClass::OnlyA | FieldClass::OnlyB => {
                    let side = if f.class == FieldClass::OnlyA {
                        "only in capture"
                    } else {
                        "only in trace"
                    };
                    if env {
                        expected.push(note(f.scope, &f.field, &format!("environment ({side})")));
                    } else {
                        unexpected.push(note(f.scope, &f.field, side));
                    }
                }
            }
        }

        let a_req = capture.requests.iter().find(|r| r.id == pair.a.request_id);
        let status_a = a_req.and_then(|r| r.attempts.last()).and_then(|a| a.status);
        let b_req = trace.requests.iter().find(|r| r.id == pair.b.request_id);
        let status_b = b_req.and_then(|r| r.attempts.last()).and_then(|a| a.status);
        let mut problem = None;
        if status_b.is_none() || status_b == Some(0) {
            // no response: transport failure, handled below
        } else if status_a != status_b {
            problem = Some(format!(
                "status {} in capture × {} in trace",
                status_a.map_or("?".into(), |s| s.to_string()),
                status_b.map_or("?".into(), |s| s.to_string())
            ));
        } else if oa.is_some_and(|oa| {
            // the capture is the reference: app-ok there requires app-ok in the trace;
            // otherwise, different verdicts only count if both were assessed
            if oa.verdict_kind == VerdictKind::AppOk {
                ob.verdict_kind != VerdictKind::AppOk
            } else {
                oa.verdict_kind != ob.verdict_kind
                    && oa.verdict_kind != VerdictKind::NotAssessed
                    && ob.verdict_kind != VerdictKind::NotAssessed
            }
        }) {
            problem = Some(format!(
                "verdict {} in trace × {} in capture",
                ob.verdict,
                oa.map_or("?", |o| o.verdict.as_str())
            ));
        } else if let Some(u) = unexpected.first() {
            problem = Some(format!("{} `{}`: {}", u.scope, u.field, u.reason));
        }
        steps.push(StepValidation {
            step,
            trace_request_id: pair.b.request_id.clone(),
            capture_request_id: Some(pair.a.request_id.clone()),
            method: pair.b.method.clone(),
            url: pair.b.url.clone(),
            status_capture: status_a,
            status_trace: status_b,
            verdict_capture: oa.map(|o| o.verdict_kind),
            verdict_trace: ob.verdict_kind,
            expected,
            unexpected,
            problem,
        });
    }
    // trace steps without a pair: extras
    for (i, r) in trace.requests.iter().enumerate() {
        if seen_b.contains(&r.id) {
            continue;
        }
        let Some(ob) = verdict_b(&r.id) else { continue };
        let a = r.attempts.last();
        steps.push(StepValidation {
            step: i + 1,
            trace_request_id: r.id.clone(),
            capture_request_id: None,
            method: a.map(|a| a.method.clone()).unwrap_or_default(),
            url: a.map(|a| a.url.clone()).unwrap_or_default(),
            status_capture: None,
            status_trace: a.and_then(|a| a.status),
            verdict_capture: None,
            verdict_trace: ob.verdict_kind,
            expected: Vec::new(),
            unexpected: Vec::new(),
            problem: Some("extra step in trace (no counterpart in capture)".to_string()),
        });
    }
    steps.sort_by_key(|s| s.step);

    // capture steps between paired steps that the trace did not execute
    let idx_a = |id: &str| capture.requests.iter().position(|q| q.id == id);
    let paired_a: Vec<usize> = cmp
        .pairs
        .iter()
        .filter_map(|p| idx_a(&p.a.request_id))
        .collect();
    let (lo, hi) = (
        paired_a.iter().copied().min().unwrap_or(0),
        paired_a.iter().copied().max().unwrap_or(0),
    );
    let missing: Vec<String> = cmp
        .only_in_a
        .iter()
        .filter(|r| !r.method.eq_ignore_ascii_case("GET"))
        .filter(|r| idx_a(&r.request_id).is_some_and(|i| i > lo && i < hi))
        .map(|r| r.request_id.clone())
        .collect();

    // verdict: first problem, in step order
    let mut verdict = ValidationVerdict::Equivalent;
    let (mut step, mut reason) = (None, None);
    if plan_mismatch {
        verdict = ValidationVerdict::Diverges;
        step = Some(1);
        reason = Some("plan differs from the one generated from this capture".to_string());
    } else if !trace.requests.is_empty() && cmp.pairs.is_empty() {
        let oa = single_app_origin(&ctx_a);
        let ob = single_app_origin(&ctx_b);
        verdict = ValidationVerdict::Diverges;
        step = Some(1);
        reason = Some(format!(
            "no trace step was paired with the capture{}; use --map-origin <capture-origin>=<trace-origin>",
            match (oa, ob) {
                (Some(a), Some(b)) if a != b => format!(" (different origins: {a} × {b})"),
                _ => String::new(),
            }
        ));
    }
    if verdict == ValidationVerdict::Equivalent {
        for s in &steps {
            let transport =
                trace_err(&s.trace_request_id) || matches!(s.status_trace, None | Some(0));
            if transport {
                verdict = ValidationVerdict::Incomplete;
                step = Some(s.step);
                reason = Some("no response (transport failure recorded in trace)".to_string());
                break;
            }
            if let Some(p) = &s.problem {
                verdict = ValidationVerdict::Diverges;
                step = Some(s.step);
                reason = Some(p.clone());
                break;
            }
        }
    }
    if verdict == ValidationVerdict::Equivalent && !missing.is_empty() {
        let first = &missing[0];
        let at = idx_a(first).unwrap_or(0);
        let next = cmp
            .pairs
            .iter()
            .filter(|p| idx_a(&p.a.request_id).is_some_and(|i| i > at))
            .filter_map(|p| step_of(&p.b.request_id))
            .min();
        verdict = ValidationVerdict::Diverges;
        step = next;
        reason = Some(format!("step missing in trace ({first})"));
    }
    // completeness: declared and paired target, and complete=true
    if verdict == ValidationVerdict::Equivalent {
        let complete = note_value(trace, COMPLETE_NOTE_PREFIX) == Some("true");
        let target_paired = target
            .as_deref()
            .is_some_and(|t| cmp.pairs.iter().any(|p| p.a.request_id == t));
        let last = trace.requests.len().max(1);
        let why = if target.is_none() {
            Some("the trace does not declare `target`".to_string())
        } else if !target_paired {
            Some(format!(
                "target {} is not among the paired steps",
                target.as_deref().unwrap_or("?")
            ))
        } else if !complete {
            Some("the trace does not declare `complete=true`".to_string())
        } else {
            None
        };
        if let Some(why) = why {
            verdict = ValidationVerdict::Incomplete;
            step = Some(last);
            reason = Some(why);
        }
    }
    let mapped = cmp
        .mapped_origin
        .as_ref()
        .map(|m| format!(" [mapped origin: {} → {}]", m.from, m.to))
        .unwrap_or_default();
    let summary = match (verdict, step) {
        (ValidationVerdict::Equivalent, _) => format!("execution equivalent to capture{mapped}"),
        (ValidationVerdict::Diverges, Some(n)) => {
            format!(
                "diverges at step {n} ({}){mapped}",
                reason.as_deref().unwrap_or("?")
            )
        }
        (ValidationVerdict::Diverges, None) => {
            format!("diverges ({}){mapped}", reason.as_deref().unwrap_or("?"))
        }
        (ValidationVerdict::Incomplete, Some(n)) => {
            format!(
                "incomplete: stopped at step {n} ({}){mapped}",
                reason.as_deref().unwrap_or("?")
            )
        }
        (ValidationVerdict::Incomplete, None) => format!("incomplete{mapped}"),
    };
    if trace.requests.is_empty() {
        return Validation {
            schema: "scrapelens.validate/1".to_string(),
            verdict: ValidationVerdict::Incomplete,
            step: Some(1),
            reason: Some("trace has no steps".to_string()),
            summary: "incomplete: stopped at step 1 (trace has no steps)".to_string(),
            steps,
            missing_in_trace: missing,
            mapped_origin: cmp.mapped_origin,
            warnings,
        };
    }
    Validation {
        schema: "scrapelens.validate/1".to_string(),
        verdict,
        step,
        reason,
        summary,
        steps,
        missing_in_trace: missing,
        mapped_origin: cmp.mapped_origin,
        warnings,
    }
}
