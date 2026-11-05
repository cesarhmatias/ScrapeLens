//! Application success × HTTP success (docs/11-priming-sucesso.md §2).
//!
//! An HTTP 200 does not prove that the application responded: it may be a
//! protection page, a response without the usual fields or a filled
//! `ERRORMESSAGE`. [`response_outcome`] assesses one response and
//! [`assess_session`] assesses the whole session, learning from the session
//! itself which fields each route usually carries.
//!
//! Principles: rules are data (JSON, no executable code), `blocked?` only
//! comes out with explicit evidence and always with "?", and what cannot be
//! asserted on a route that already has an expectation is `undetermined`,
//! with the list of what is missing. A response with no application signal
//! and no learned expectation for the route is `not-assessed`:
//! pages, frames, static or protection resources do not
//! fill the suspects list. Nothing here opens the network.
//!
//! A protection marker ALONE does not block: application pages cite
//! `/TSPD/` in a `<script src>`. `blocked?` requires status 403/429, challenge
//! content without the expected page, a route that carried controls and now
//! comes without them, or the default F5 ASM rejection page — always on an
//! APPLICATION route. Requests to protection routes (`/TSPD/`) are the normal
//! handshake: they come out `not-assessed` with the informational signal
//! `protection`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::html::html_controls;
use crate::model::{BodyState, LogicalRequest, SessionV1};
use crate::search::BodySource;

pub const RULES_SCHEMA: &str = "scrapelens.assess-rules/1";

/// How a field counts toward the assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    /// It is enough for the field to exist.
    Present,
    /// The field must exist and not be empty.
    PresentNonempty,
    /// Error field: non-empty becomes `app-error`.
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldRule {
    /// Field name (HTML control, form key or JSON path/key),
    /// case-insensitive.
    pub name: String,
    /// Signal name shown in the verdict; default = `name`.
    #[serde(default)]
    pub signal: Option<String>,
    pub kind: FieldKind,
}

impl FieldRule {
    fn signal(&self) -> &str {
        self.signal.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarkerRule {
    /// Text (case-insensitive) searched for in HTML responses.
    pub contains: String,
    #[serde(default)]
    pub signal: Option<String>,
    /// How the marker appears: citation (URL/script), challenge content or
    /// known rejection page.
    #[serde(default)]
    pub kind: MarkerKind,
}

/// How the protection marker appears in the response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerKind {
    /// Citation in an application page (`<script src="/TSPD/...">`): alone
    /// it is not evidence of blocking.
    #[default]
    Reference,
    /// Content of the challenge itself (variable/code of the protection): without the
    /// expected controls, it is a block.
    Challenge,
    /// Known rejection page (F5 ASM): always blocks, with or without
    /// controls and without depending on an expectation learned for the route.
    Rejection,
}

/// Assessment rules. Data only; `Default` is conservative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct AssessRules {
    pub schema: String,
    pub fields: Vec<FieldRule>,
    /// Fields every application response must carry (in addition to learned ones).
    pub required_fields: Vec<String>,
    /// Protection markers: they only block as a challenge, as a protection route
    /// or when they replace the expected page.
    pub protection_markers: Vec<MarkerRule>,
    /// Path prefixes that are themselves protection responses.
    pub protection_paths: Vec<String>,
    /// HTTP statuses that are explicit evidence of blocking.
    pub blocked_statuses: Vec<u16>,
    /// Learns, from the session, the fields each route (method + path) carries.
    pub learn_routes: bool,
}

impl Default for AssessRules {
    fn default() -> Self {
        let field = |name: &str, kind| FieldRule {
            name: name.to_string(),
            signal: None,
            kind,
        };
        let marker = |contains: &str, signal: &str, kind| MarkerRule {
            contains: contains.to_string(),
            signal: Some(signal.to_string()),
            kind,
        };
        Self {
            schema: RULES_SCHEMA.to_string(),
            fields: vec![
                field("XML", FieldKind::PresentNonempty),
                field("STAMP", FieldKind::Present),
                field("ERRORMESSAGE", FieldKind::Error),
            ],
            required_fields: Vec::new(),
            protection_markers: vec![
                marker("/TSPD/", "TSPD", MarkerKind::Reference),
                marker("_tsChallenge", "TSPD", MarkerKind::Challenge),
                // Default F5 ASM block page; the synthetic fixture uses
                // the short form "request rejected" and the title "Request Rejected".
                marker(
                    "The requested URL was rejected",
                    "f5-rejected",
                    MarkerKind::Rejection,
                ),
                marker("Your support ID is", "f5-rejected", MarkerKind::Rejection),
                marker("Request Rejected", "f5-rejected", MarkerKind::Rejection),
            ],
            protection_paths: vec!["/TSPD/".to_string()],
            blocked_statuses: vec![403, 429],
            learn_routes: true,
        }
    }
}

impl AssessRules {
    /// Reads rules from JSON. Missing fields take the default; a schema different
    /// from [`RULES_SCHEMA`] is rejected.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let raw: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("invalid assess rules: {e}"))?;
        if raw.get("schema").and_then(|v| v.as_str()).is_none() {
            return Err(format!(
                "assess rules without \"schema\" (expected {RULES_SCHEMA})"
            ));
        }
        let rules: Self =
            serde_json::from_value(raw).map_err(|e| format!("invalid assess rules: {e}"))?;
        let blank = |s: &String| s.trim().is_empty();
        if rules.fields.iter().any(|f| blank(&f.name))
            || rules.required_fields.iter().any(blank)
            || rules.protection_paths.iter().any(blank)
        {
            return Err(
                "assess rules: fields[].name, requiredFields[] and protectionPaths[] cannot be empty"
                    .into(),
            );
        }
        if rules
            .protection_markers
            .iter()
            .any(|m| m.contains.trim().is_empty())
        {
            return Err("assess rules: protection marker with empty \"contains\"".into());
        }
        if let Some(bad) = rules
            .blocked_statuses
            .iter()
            .find(|s| !(400..=599).contains(*s))
        {
            return Err(format!(
                "assess rules: blockedStatuses accepts only 4xx/5xx (got {bad})"
            ));
        }
        if rules.schema != RULES_SCHEMA {
            return Err(format!(
                "unknown rules schema: {} (expected {RULES_SCHEMA})",
                rules.schema
            ));
        }
        Ok(rules)
    }

    /// Warnings for legitimate rules that empty out or distort the assessment.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.fields.is_empty()
            && self.required_fields.is_empty()
            && self.protection_markers.is_empty()
            && self.protection_paths.is_empty()
            && self.blocked_statuses.is_empty()
        {
            out.push("the rules turn off all detections: nothing will be marked".to_string());
        }
        if self.fields.is_empty()
            && self.protection_markers.is_empty()
            && self.blocked_statuses.is_empty()
        {
            out.push(
                "no detection configured (fields, protectionMarkers and blockedStatuses empty)"
                    .to_string(),
            );
        }
        if self
            .protection_paths
            .iter()
            .any(|p| matches!(p.as_str(), "/" | "*"))
        {
            out.push(
                "protectionPaths contains \"/\": every request would be a protection route and would be left not-assessed"
                    .to_string(),
            );
        }
        if self
            .protection_markers
            .iter()
            .any(|m| m.contains.trim().is_empty())
        {
            out.push("there is an empty protection marker, which would match any HTML".to_string());
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalKind {
    /// Signal that the application responded.
    Ok,
    /// Error declared by the application (non-empty error field, HTTP 4xx/5xx).
    Error,
    /// Explicit evidence of protection/blocking.
    Protection,
    /// Expected field missing (or empty).
    Missing,
    /// Observation that does not change the verdict.
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSignal {
    pub signal: String,
    pub kind: SignalKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictKind {
    AppOk,
    AppError,
    Blocked,
    Undetermined,
    /// No application signal and no expectation learned for the route.
    NotAssessed,
}

impl VerdictKind {
    /// `counts` key in the JSON (`scrapelens.assess/1`), same as `verdictKind`.
    #[must_use]
    pub const fn count_key(self) -> &'static str {
        match self {
            Self::AppOk => "app-ok",
            Self::AppError => "app-error",
            Self::Blocked => "blocked",
            Self::Undetermined => "undetermined",
            Self::NotAssessed => "not-assessed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseOutcome {
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    /// 2xx/3xx.
    pub http_ok: bool,
    pub app_signals: Vec<AppSignal>,
    /// `app-ok`, `app-error (<signal>)`, `blocked? (<signal>)`, `undetermined`
    /// or `not-assessed`.
    pub verdict: String,
    pub verdict_kind: VerdictKind,
    /// Expected fields (learned on the route or required by the rules) that
    /// were missing or came back empty.
    pub missing_fields: Vec<String>,
    /// Why the verdict is `undetermined` or `not-assessed` (empty otherwise).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Fields learned per route (`"POST /servlet/Connector"` → names).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteExpectations {
    routes: BTreeMap<String, BTreeSet<String>>,
}

impl RouteExpectations {
    pub fn expected(&self, request: &LogicalRequest) -> Option<&BTreeSet<String>> {
        self.routes.get(&route_key(request))
    }
}

fn route_key(request: &LogicalRequest) -> String {
    let url = request.url.split(['?', '#']).next().unwrap_or("");
    format!("{} {}", request.method.to_ascii_uppercase(), url)
}

/// A field read from the response body.
struct Found {
    name: String,
    value: String,
}

struct ParsedBody {
    fields: Vec<Found>,
    html: bool,
    text: Option<String>,
    truncated: bool,
}

fn media_of(request: &LogicalRequest) -> String {
    request
        .response_headers
        .first_value("content-type")
        .or(request.response_body.content_type.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn parse_body(request: &LogicalRequest, source: &dyn BodySource) -> ParsedBody {
    let body = &request.response_body;
    let mut out = ParsedBody {
        fields: Vec::new(),
        html: false,
        text: None,
        truncated: body.state == BodyState::Truncated,
    };
    if !matches!(body.state, BodyState::Captured | BodyState::Truncated) {
        return out;
    }
    let Some(loaded) = body.attachment.as_deref().and_then(|n| source.load(n)) else {
        return out;
    };
    out.truncated |= loaded.cut;
    let text = String::from_utf8_lossy(&loaded.bytes).into_owned();
    let media = media_of(request);
    let head = text.trim_start();
    let html_like = media.contains("html")
        || head.starts_with('<')
            && !media.contains("json")
            && !media.contains("javascript")
            && !media.contains("xml");
    if html_like {
        out.html = true;
        for control in html_controls(&text) {
            out.fields.push(Found {
                name: control.name,
                value: control.value,
            });
        }
        // Plain form body under Content-Type html (the Connector case).
        if out.fields.is_empty() && looks_form(&text) {
            out.fields = form_fields(&text);
        }
    } else if media.contains("json") || head.starts_with('{') || head.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            json_leaves(&value, "", &mut out.fields);
        }
    } else if media.contains("x-www-form-urlencoded") || looks_form(&text) {
        out.fields = form_fields(&text);
    }
    out.text = Some(text);
    out
}

fn looks_form(text: &str) -> bool {
    let t = text.trim();
    !t.is_empty()
        && !t.contains(['<', '\n'])
        && t.split('&').all(|part| {
            part.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-[]".contains(c))
            })
        })
}

fn form_fields(text: &str) -> Vec<Found> {
    text.trim()
        .split('&')
        .filter_map(|part| part.split_once('='))
        .map(|(k, v)| Found {
            name: percent_decode(k),
            value: percent_decode(v),
        })
        .collect()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len()
                && raw.is_char_boundary(i + 1)
                && raw.is_char_boundary(i + 3) =>
            {
                match u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_leaves(value: &serde_json::Value, path: &str, out: &mut Vec<Found>) {
    if out.len() >= 5_000 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                json_leaves(child, &next, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                json_leaves(child, &format!("{path}[{index}]"), out);
            }
        }
        serde_json::Value::Null => out.push(Found {
            name: path.to_string(),
            value: String::new(),
        }),
        serde_json::Value::String(text) => out.push(Found {
            name: path.to_string(),
            value: text.clone(),
        }),
        other => out.push(Found {
            name: path.to_string(),
            value: other.to_string(),
        }),
    }
}

fn name_matches(found: &str, rule: &str) -> bool {
    let last = found.rsplit('.').next().unwrap_or(found);
    found.eq_ignore_ascii_case(rule) || last.eq_ignore_ascii_case(rule)
}

fn find<'a>(fields: &'a [Found], rule: &str) -> Option<&'a Found> {
    fields.iter().find(|f| name_matches(&f.name, rule))
}

/// Is there an application error or explicit block in this response? Whoever learns
/// the route ignores these responses.
fn is_clean_sample(request: &LogicalRequest, parsed: &ParsedBody, rules: &AssessRules) -> bool {
    let status_ok = request.status.is_some_and(|s| s < 400);
    status_ok
        && !rules
            .fields
            .iter()
            .filter(|r| r.kind == FieldKind::Error)
            .any(|r| find(&parsed.fields, &r.name).is_some_and(|f| !f.value.trim().is_empty()))
}

/// Learns, for each route, the positive fields that clean responses
/// carried.
pub fn learn_routes(
    session: &SessionV1,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> RouteExpectations {
    let mut learned = RouteExpectations::default();
    if !rules.learn_routes {
        return learned;
    }
    for request in &session.requests {
        let parsed = parse_body(request, source);
        if parsed.fields.is_empty() || !is_clean_sample(request, &parsed, rules) {
            continue;
        }
        for rule in rules.fields.iter().filter(|r| r.kind != FieldKind::Error) {
            let Some(found) = find(&parsed.fields, &rule.name) else {
                continue;
            };
            if rule.kind == FieldKind::PresentNonempty && found.value.is_empty() {
                continue;
            }
            learned
                .routes
                .entry(route_key(request))
                .or_default()
                .insert(rule.name.clone());
        }
    }
    learned
}

/// URL path (without scheme/host and without query/fragment).
fn path_of(url: &str) -> &str {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    match no_query.find("://") {
        Some(scheme) => {
            let rest = &no_query[scheme + 3..];
            let cut = rest.find('/').unwrap_or(rest.len());
            &rest[cut..]
        }
        None => no_query,
    }
}

/// Assesses a response with the rules only (without route learning).
pub fn response_outcome(
    request: &LogicalRequest,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> ResponseOutcome {
    response_outcome_with(request, source, rules, &RouteExpectations::default())
}

/// Assesses a response, also using the fields learned in the session.
pub fn response_outcome_with(
    request: &LogicalRequest,
    source: &dyn BodySource,
    rules: &AssessRules,
    learned: &RouteExpectations,
) -> ResponseOutcome {
    let parsed = parse_body(request, source);
    let http_ok = request.status.is_some_and(|s| (200..400).contains(&s));
    let mut signals: Vec<AppSignal> = Vec::new();
    let sig = |signal: &str, kind, detail: String| AppSignal {
        signal: signal.to_string(),
        kind,
        detail,
    };

    // 1. Error declared by the application.
    let mut error_signal: Option<String> = None;
    for rule in rules.fields.iter().filter(|r| r.kind == FieldKind::Error) {
        if let Some(found) = find(&parsed.fields, &rule.name) {
            if !found.value.trim().is_empty() {
                error_signal.get_or_insert_with(|| rule.signal().to_string());
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Error,
                    format!(
                        "field {} filled in ({} characters)",
                        found.name,
                        found.value.chars().count()
                    ),
                ));
            }
        }
    }

    // 2. Explicit evidence of blocking.
    let path = path_of(&request.url);
    let protection_path = rules
        .protection_paths
        .iter()
        .any(|p| !p.is_empty() && path.contains(p.as_str()));
    let mut block_signal: Option<String> = None;
    if protection_path {
        // Protection route: the handshake (challenge/cookie/script) is normal.
        // `blocked?` only if the APPLICATION responds with challenge/rejection or 403/429.
        signals.push(sig(
            "protection",
            SignalKind::Info,
            format!("protection route {path}; normal handshake, not assessed"),
        ));
        // 403/429 on the protection route itself is explicit evidence.
        if let Some(status) = request.status {
            if rules.blocked_statuses.contains(&status) {
                let name = format!("http-{status}");
                block_signal.get_or_insert_with(|| name.clone());
                signals.push(sig(&name, SignalKind::Protection, format!("HTTP {status}")));
            }
        }
    } else {
        if let Some(status) = request.status {
            if rules.blocked_statuses.contains(&status) {
                let name = format!("http-{status}");
                block_signal.get_or_insert_with(|| name.clone());
                signals.push(sig(&name, SignalKind::Protection, format!("HTTP {status}")));
            }
        }
        let marker_hit = parsed.html.then_some(()).and_then(|()| {
            let text = parsed.text.as_deref()?.to_ascii_lowercase();
            // Known rejection > challenge content > citation.
            let rank = |kind| match kind {
                MarkerKind::Rejection => 2,
                MarkerKind::Challenge => 1,
                MarkerKind::Reference => 0,
            };
            let mut best: Option<&MarkerRule> = None;
            for marker in &rules.protection_markers {
                if text.contains(&marker.contains.to_ascii_lowercase())
                    && best.map_or(true, |current| rank(marker.kind) > rank(current.kind))
                {
                    best = Some(marker);
                }
            }
            best
        });
        if let Some(marker) = marker_hit {
            let name = marker
                .signal
                .clone()
                .unwrap_or_else(|| marker.contains.clone());
            let no_controls = parsed.fields.is_empty();
            let replaces_expected = no_controls && learned.expected(request).is_some();
            let challenge = marker.kind == MarkerKind::Challenge && no_controls;
            // Rejection only counts without the expected controls: an application
            // page with the controls the route carries that merely cites the
            // rejection text is the application responding.
            let expected_here = {
                let mut e: BTreeSet<String> = rules.required_fields.iter().cloned().collect();
                if let Some(known) = learned.expected(request) {
                    e.extend(known.iter().cloned());
                }
                e
            };
            let controls_missing = if expected_here.is_empty() {
                no_controls
            } else {
                expected_here
                    .iter()
                    .any(|name| find(&parsed.fields, name).is_none())
            };
            let rejection = marker.kind == MarkerKind::Rejection && controls_missing;
            if rejection || challenge || replaces_expected {
                block_signal.get_or_insert_with(|| name.clone());
                let detail = if rejection {
                    format!(
                        "known rejection page (marker {})",
                        marker.contains
                    )
                } else if challenge {
                    format!(
                        "challenge content without the expected page (marker {})",
                        marker.contains
                    )
                } else {
                    format!(
                        "challenge content without the expected controls (marker {})",
                        marker.contains
                    )
                };
                signals.push(sig(&name, SignalKind::Protection, detail));
            } else {
                signals.push(sig(
                    &name,
                    SignalKind::Info,
                    format!(
                        "marker {} cited by an application page; alone it is not blocking",
                        marker.contains
                    ),
                ));
            }
        }
    }

    // 3. Sinais positivos e campos esperados ausentes.
    let mut positives = 0usize;
    for rule in rules.fields.iter().filter(|r| r.kind != FieldKind::Error) {
        if let Some(found) = find(&parsed.fields, &rule.name) {
            if rule.kind == FieldKind::PresentNonempty && found.value.is_empty() {
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Missing,
                    format!("{} present, but empty", found.name),
                ));
            } else {
                positives += 1;
                signals.push(sig(
                    rule.signal(),
                    SignalKind::Ok,
                    format!("{} present", found.name),
                ));
            }
        }
    }
    let mut expected: BTreeSet<String> = rules.required_fields.iter().cloned().collect();
    if let Some(known) = learned.expected(request) {
        expected.extend(known.iter().cloned());
    }
    let mut missing: Vec<String> = Vec::new();
    for name in &expected {
        let rule = rules
            .fields
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case(name));
        let nonempty = rule.is_some_and(|r| r.kind == FieldKind::PresentNonempty);
        match find(&parsed.fields, name) {
            Some(found) if !(nonempty && found.value.is_empty()) => {}
            _ => missing.push(name.clone()),
        }
    }

    // 4. Verdict.
    let status_text = request
        .status
        .map_or("no status".to_string(), |s| s.to_string());
    let mut reason = String::new();
    let (kind, verdict) = if protection_path && block_signal.is_none() {
        reason = format!("protection route {path}; normal handshake, not assessed");
        (VerdictKind::NotAssessed, "not-assessed".to_string())
    } else if let Some(signal) = error_signal {
        (VerdictKind::AppError, format!("app-error ({signal})"))
    } else if let Some(signal) = block_signal {
        (VerdictKind::Blocked, format!("blocked? ({signal})"))
    } else if request.status.is_some_and(|s| s >= 400) {
        let name = format!("http-{status_text}");
        signals.push(sig(&name, SignalKind::Error, format!("HTTP {status_text}")));
        (VerdictKind::AppError, format!("app-error ({name})"))
    } else if parsed.html && parsed.fields.is_empty() && learned.expected(request).is_some() {
        signals.push(sig(
            "html-without-controls",
            SignalKind::Protection,
            format!(
                "HTML without controls on a route that carried them ({})",
                missing.join(", ")
            ),
        ));
        (
            VerdictKind::Blocked,
            "blocked? (html-without-controls)".to_string(),
        )
    } else if !missing.is_empty() {
        let fields = missing.join(", ");
        reason = if parsed.text.is_none() {
            format!("response body unavailable; expected fields missing: {fields}")
        } else if parsed.truncated {
            format!("body truncated; expected fields missing: {fields}")
        } else {
            format!("expected fields missing: {fields}")
        };
        (VerdictKind::Undetermined, "undetermined".to_string())
    } else if positives > 0 {
        (VerdictKind::AppOk, "app-ok".to_string())
    } else {
        reason = if parsed.text.is_none() {
            "response body unavailable; route without learned expectation".to_string()
        } else if parsed.truncated {
            "body truncated; route without learned expectation".to_string()
        } else {
            "no application signals or expected fields on this route".to_string()
        };
        (VerdictKind::NotAssessed, "not-assessed".to_string())
    };
    if kind == VerdictKind::Undetermined && parsed.truncated && !reason.contains("truncated") {
        reason.push_str("; body truncated");
    }

    ResponseOutcome {
        request_id: request.id.clone(),
        method: request.method.clone(),
        url: request.url.clone(),
        status: request.status,
        http_ok,
        app_signals: signals,
        verdict,
        verdict_kind: kind,
        missing_fields: missing,
        reason,
    }
}

/// Assesses all requests in the session, in order, learning first which
/// fields each route usually carries.
pub fn assess_session(
    session: &SessionV1,
    source: &dyn BodySource,
    rules: &AssessRules,
) -> Vec<ResponseOutcome> {
    let learned = learn_routes(session, source, rules);
    session
        .requests
        .iter()
        .map(|request| response_outcome_with(request, source, rules, &learned))
        .collect()
}
