//! Comparison between two captures of the same flow (`docs/09-cadeia-comparacao.md` §2).
//!
//! ```text
//! pub fn compare_sessions(a: &SessionV1, a_source: &dyn BodySource,
//!                         b: &SessionV1, b_source: &dyn BodySource,
//!                         options: &CompareOptions) -> SessionComparison
//! ```
//!
//! JSON schema (camelCase): `{ pairs: [ { a, b: {requestId, method, url}, alignedBy: model|path,
//! outOfOrder, counts, fields: [ { scope, field, occurrence, class: static|dynamic|onlyA|onlyB|redacted,
//! label (static|dynamic|only in A|only in B|redacted), dynamicKind: runtime|noOrigin|repeated|composite,
//! originLabel ("get at runtime (origin: cdp-rNNNN)" | "dynamic without origin"), a, b,
//! origin: {kind, requestId, scope, field, ambiguous}, parts: [ { class: static|dynamic, label, aOffset,
//! bOffset, a, b, dynamicKind, originLabel, origin } ] } ] } ], onlyInA[], onlyInB[], reordered: [{a, b}] (leftovers of the same model on both sides), ambiguities[],
//! counts, partsCounts, redactedFields, warnings[] }`. `counts` sums scalar fields and the excerpts
//! dynamic excerpts of composite fields (`dynamic == runtime + noOrigin`); `partsCounts` shows only the excerpt part
//! (and the static ones).
//!
//! Round 6: by default only the application is aligned (protection and static resources
//! go to `groups: [{kind: protection|static, a[], b[]}]`; `CompareOptions
//! {includeAll}` includes them). A and B are segmented into rounds by the request of
//! entry (`entryRequest`: the 1st application document that repeats); each
//! round of A pairs with the most similar round of B (`rounds: [{aRound, bRound,
//! score, aRequests, bRequests}]`) and rounds without a pair go to `unpairedRounds`
//! (not in `onlyInA/onlyInB`). `pairs[].round` indexes `rounds`. Ranges:
//! `CompareOptions {aRange, bRange: {from, to}}` (ids or 1-based numbers; CLI
//! `--a-range from:to --b-range from:to`).
//!
//! - A↔B alignment by model (method + host + normalized path +
//!   query names + body field names); requests of the same model
//!   are paired in order. Leftovers stay in `onlyInA`/`onlyInB`; those that only
//!   differ in field names are paired by path (`alignedBy: path`)
//!   and the ambiguity is listed in `ambiguities`. Never by absolute time.
//! - Per field (query, headers, cookies, body): `static`, `dynamic`, `onlyA`,
//!   `onlyB`, `redacted`. Repeated fields are paired by occurrence, in the
//!   source order (no alphabetical sorting).
//! - Dynamic + origin observed in B (earlier response of B) =
//!   `runtime`; dynamic without origin = `noOrigin`; opaque fields (>= 40
//!   characters) are compared by whole value and by differing excerpts
//!   (`parts`), each with its own origin.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flow::{
    origins_in, Confidence, ConsumedScope, Evidence, EvidenceKind, FlowContext, FlowOptions,
    OriginStatus, ProducerScope, ValueOrigin, ValueOrigins,
};
use crate::model::SessionV1;
use crate::search::BodySource;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareOptions {
    pub flow: FlowOptions,
    /// Includes protection (/TSPD/) and static resources in the alignment. By default
    /// only the application's requests are aligned; the others go to `groups`.
    #[serde(default)]
    pub include_all: bool,
    /// Range of A to compare: inclusive ends, each one a request id
    /// or a number (1 = first request of the session).
    #[serde(default)]
    pub a_range: Option<RequestRange>,
    #[serde(default)]
    pub b_range: Option<RequestRange>,
    /// Treats two hosts as the same when aligning (`--map-origin A=B`): `from` and
    /// `to` are origins (`https://host[:porta]`). Without this, if one of the sessions
    /// has the label `script-trace` and each side has a single application origin,
    /// the mapping is applied on its own, with a warning.
    #[serde(default)]
    pub map_origin: Option<OriginMap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginMap {
    pub from: String,
    pub to: String,
}

impl OriginMap {
    /// `"https://a.test=http://127.0.0.1:8791"`.
    pub fn parse(text: &str) -> Option<Self> {
        let (from, to) = text.split_once('=')?;
        let (from, to) = (from.trim(), to.trim());
        (host_of_origin(from).is_some() && host_of_origin(to).is_some()).then(|| Self {
            from: from.to_string(),
            to: to.to_string(),
        })
    }
}

/// `host[:porta]` in lowercase of an origin (or URL).
pub(crate) fn host_of_origin(origin: &str) -> Option<String> {
    let rest = origin.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRange {
    pub from: String,
    pub to: String,
}

impl RequestRange {
    /// `"har-0010:har-0050"`, `"10:50"` or `"10-50"`.
    pub fn parse(text: &str) -> Option<Self> {
        let (from, to) = text.split_once(':').or_else(|| text.split_once('-'))?;
        let (from, to) = (from.trim(), to.trim());
        (!from.is_empty() && !to.is_empty()).then(|| Self {
            from: from.to_string(),
            to: to.to_string(),
        })
    }

    /// Indices (inclusive) or the reason the range is not valid.
    fn resolve(&self, session: &SessionV1) -> std::result::Result<(usize, usize), String> {
        let index = |s: &str| -> std::result::Result<usize, String> {
            if let Some(i) = session.requests.iter().position(|q| q.id == s) {
                return Ok(i);
            }
            match s.parse::<usize>() {
                Ok(n) if (1..=session.requests.len()).contains(&n) => Ok(n - 1),
                Ok(n) => Err(format!(
                    "{n} out of bounds (the session has {} requests)",
                    session.requests.len()
                )),
                Err(_) => Err(format!("request {s:?} not found")),
            }
        };
        let (from, to) = (index(&self.from)?, index(&self.to)?);
        if from > to {
            return Err("inverted range (start after end)".to_string());
        }
        Ok((from, to))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldClass {
    Static,
    Dynamic,
    OnlyA,
    OnlyB,
    Redacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DynamicKind {
    /// "get at runtime": the origin in B is an earlier response of B.
    Runtime,
    /// "dynamic without origin": generated in the client, input constant, etc.
    NoOrigin,
    /// The value already circulated in an earlier request, without an observed producer.
    Repeated,
    /// Opaque field: see `parts`.
    Composite,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginSummary {
    pub kind: EvidenceKind,
    /// Request of B that produces the value (the oldest).
    pub request_id: String,
    pub scope: ProducerScope,
    pub field: Option<String>,
    pub ambiguous: bool,
    /// `strong` or `possible` (only medium evidence).
    pub confidence: Option<Confidence>,
    /// The producer is an HTML form control.
    #[serde(default)]
    pub html_control: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartDiff {
    /// `static` (common excerpt >= 8 bytes) or `dynamic`.
    pub class: FieldClass,
    pub label: String,
    pub a_offset: u64,
    pub b_offset: u64,
    pub a: String,
    pub b: String,
    pub dynamic_kind: DynamicKind,
    pub origin_label: String,
    pub origin: Option<OriginSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDiff {
    pub scope: ConsumedScope,
    pub field: String,
    pub occurrence: usize,
    pub class: FieldClass,
    /// Label: static, dynamic, only in A, only in B, redacted.
    pub label: String,
    pub dynamic_kind: Option<DynamicKind>,
    /// "get at runtime (origin: …)" or "dynamic without origin".
    pub origin_label: Option<String>,
    pub a: Option<String>,
    pub b: Option<String>,
    pub origin: Option<OriginSummary>,
    pub parts: Vec<PartDiff>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestRef {
    pub request_id: String,
    pub method: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairCounts {
    pub r#static: usize,
    pub dynamic: usize,
    pub runtime: usize,
    pub no_origin: usize,
    pub only_a: usize,
    pub only_b: usize,
    pub redacted: usize,
}

/// Excerpts of composite (opaque) fields. The dynamic ones are already summed in
/// `PairCounts` (`dynamic == runtime + noOrigin`); here they appear separately
/// and the static excerpts exist only here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartsCounts {
    pub r#static: usize,
    pub dynamic: usize,
    pub runtime: usize,
    pub no_origin: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairComparison {
    pub a: RequestRef,
    pub b: RequestRef,
    /// `model` (identical model) or `path` (only method + host + path).
    pub aligned_by: String,
    /// Index in `rounds` to which the pair belongs.
    pub round: usize,
    /// B does not preserve the relative order of A in this pair.
    pub out_of_order: bool,
    pub fields: Vec<FieldDiff>,
    /// Scalar fields + dynamic excerpts of composite fields (a composite field
    /// does not count by itself; the excerpts count).
    pub counts: PairCounts,
    pub parts_counts: PartsCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundInfo {
    pub a_round: usize,
    pub b_round: usize,
    /// Models in common (sum of min(count A, count B)).
    pub score: usize,
    pub a_requests: usize,
    pub b_requests: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnpairedRound {
    /// `A` or `B`.
    pub side: String,
    pub round: usize,
    pub requests: usize,
    pub first: RequestRef,
    pub last: RequestRef,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherGroup {
    /// `protection` or `static`.
    pub kind: String,
    pub a: Vec<RequestRef>,
    pub b: Vec<RequestRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReorderedPair {
    pub a: RequestRef,
    pub b: RequestRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionComparison {
    /// Paired rounds (A and B segmented by the entry request).
    pub rounds: Vec<RoundInfo>,
    /// Rounds without a pair on the other side (not in `onlyInA`/`onlyInB`).
    pub unpaired_rounds: Vec<UnpairedRound>,
    /// Requests outside the application alignment (protection, static).
    pub groups: Vec<OtherGroup>,
    /// Model of the entry request used for segmentation (`method|host|path`).
    pub entry_request: Option<String>,
    /// Leftovers on both sides with the SAME model: probably the same
    /// requests in another order (the pairing stays monotonic).
    pub reordered: Vec<ReorderedPair>,
    pub pairs: Vec<PairComparison>,
    pub only_in_a: Vec<RequestRef>,
    pub only_in_b: Vec<RequestRef>,
    pub ambiguities: Vec<String>,
    pub counts: PairCounts,
    pub parts_counts: PartsCounts,
    pub redacted_fields: usize,
    pub warnings: Vec<String>,
    /// Origin mapping applied (explicit or automatic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_origin: Option<OriginMap>,
}

const OPAQUE_MIN: usize = crate::flow::OPAQUE_CONSUMER_MIN;

fn is_redacted(value: &str) -> bool {
    value.contains("REDACTED")
}

pub(crate) fn split_url(url: &str) -> (String, String) {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let (host, path) = match no_query.split_once("://") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((host, path)) => (host, format!("/{path}")),
            None => (rest, "/".to_string()),
        },
        None => ("", no_query.to_string()),
    };
    let path = path
        .split('/')
        .map(|segment| {
            let hex =
                segment.len() >= 8 && segment.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
            if !segment.is_empty() && (segment.bytes().all(|b| b.is_ascii_digit()) || hex) {
                "{id}"
            } else {
                segment
            }
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("/");
    (
        host.to_ascii_lowercase(),
        path.trim_end_matches('/').to_string(),
    )
}

#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) index: usize,
    pub(crate) id: String,
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) base: String,
    model: String,
    pub(crate) kind: EntryKind,
    /// Application document (GET with an HTML response).
    pub(crate) document: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    App,
    Protection,
    Static,
}

pub(crate) fn entries(ctx: &FlowContext<'_>, map: Option<&OriginMap>) -> Vec<Entry> {
    let map_hosts = map.and_then(|m| Some((host_of_origin(&m.from)?, host_of_origin(&m.to)?)));
    let mut out = Vec::new();
    for (index, request) in ctx.session.requests.iter().enumerate() {
        let Some(pos) = ctx.find(&request.id) else {
            continue;
        };
        let attempt = ctx.attempt_ref(pos);
        let (mut host, path) = split_url(&attempt.url);
        if let Some((from, to)) = &map_hosts {
            if host == *from {
                host = to.clone();
            }
        }
        let base = format!("{}|{host}|{path}", attempt.method.to_ascii_uppercase());
        let mut names: Vec<String> = ctx
            .consumed_for(pos)
            .iter()
            // adapter parts are not part of the model: the alignment is the same with or without an adapter
            .filter(|c| {
                matches!(c.scope, ConsumedScope::Query | ConsumedScope::Body) && c.part_of.is_none()
            })
            .map(|c| format!("{:?}:{}", c.scope, c.field))
            .collect();
        names.sort();
        names.dedup();
        let model = format!("{base}|{}", names.join(","));
        let kind = if crate::flow::is_protection_path(&attempt.url) {
            EntryKind::Protection
        } else if ctx.is_static(pos) {
            EntryKind::Static
        } else {
            EntryKind::App
        };
        // frame started by the parser (cscform, JLIBS…) is not the entry of the round
        let document = kind == EntryKind::App
            && !attempt
                .initiator
                .as_ref()
                .is_some_and(|i| i.kind.eq_ignore_ascii_case("parser"))
            && attempt.method.eq_ignore_ascii_case("GET")
            && attempt
                .response_headers
                .first_value("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"));
        out.push(Entry {
            index,
            id: request.id.clone(),
            method: attempt.method.clone(),
            url: attempt.url.clone(),
            base,
            model,
            kind,
            document,
        });
    }
    out
}

fn request_ref(entry: &Entry) -> RequestRef {
    RequestRef {
        request_id: entry.id.clone(),
        method: entry.method.clone(),
        url: entry.url.clone(),
    }
}

fn preview(value: &str) -> String {
    let mut out: String = value.chars().take(160).collect();
    if value.chars().count() > 160 {
        out.push('…');
    }
    out
}

fn summary(value: &ValueOrigin) -> Option<OriginSummary> {
    let oldest: &Evidence = value.evidences.get(value.oldest?)?;
    Some(OriginSummary {
        kind: oldest.kind,
        request_id: oldest.request_id.clone(),
        scope: oldest.scope,
        field: oldest.field.clone(),
        ambiguous: value.status == OriginStatus::Ambiguous,
        confidence: value.confidence,
        html_control: oldest.html_control,
    })
}

fn kind_of(value: &ValueOrigin) -> DynamicKind {
    match value.status {
        OriginStatus::Origin | OriginStatus::Ambiguous => DynamicKind::Runtime,
        OriginStatus::Repeated => DynamicKind::Repeated,
        _ => DynamicKind::NoOrigin,
    }
}

/// Regions that differ (a_ini, a_fim, b_ini, b_fim) by byte LCS; above the
/// cell limit, only the common prefix/suffix is used.
fn diff_regions(a: &[u8], b: &[u8], cap: usize) -> Vec<(usize, usize, usize, usize)> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (a_mid, b_mid) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    if a_mid.is_empty() && b_mid.is_empty() {
        return Vec::new();
    }
    if a_mid.len().saturating_mul(b_mid.len()) > cap {
        return vec![(prefix, a.len() - suffix, prefix, b.len() - suffix)];
    }
    let (n, m) = (a_mid.len(), b_mid.len());
    let mut table = vec![0u16; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[at(i, j)] = if a_mid[i] == b_mid[j] {
                table[at(i + 1, j + 1)].saturating_add(1)
            } else {
                table[at(i + 1, j)].max(table[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut regions: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    while i < n || j < m {
        if i < n && j < m && a_mid[i] == b_mid[j] {
            if let Some((si, sj)) = open.take() {
                regions.push((si, i, sj, j));
            }
            i += 1;
            j += 1;
        } else {
            if open.is_none() {
                open = Some((i, j));
            }
            if j >= m || (i < n && table[at(i + 1, j)] >= table[at(i, j + 1)]) {
                i += 1;
            } else {
                j += 1;
            }
        }
    }
    if let Some((si, sj)) = open {
        regions.push((si, n, sj, m));
    }
    // joins regions separated by a few equal bytes (same token)
    let mut merged: Vec<(usize, usize, usize, usize)> = Vec::new();
    for region in regions {
        if let Some(last) = merged.last_mut() {
            if region.0.saturating_sub(last.1) <= 2 && region.2.saturating_sub(last.3) <= 2 {
                last.1 = region.1;
                last.3 = region.3;
                continue;
            }
        }
        merged.push(region);
    }
    merged
        .into_iter()
        .map(|(a0, a1, b0, b1)| (a0 + prefix, a1 + prefix, b0 + prefix, b1 + prefix))
        .collect()
}

/// `localhost`, `127.0.0.0/8`, `::1`.
pub(crate) fn is_loopback_origin(origin: &str) -> bool {
    let Some(host) = host_of_origin(origin) else {
        return false;
    };
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h),
    };
    name == "localhost" || name == "::1" || name.starts_with("127.")
}

/// Single application origin of a session (`scheme://host`), if there is only one.
pub(crate) fn single_app_origin(ctx: &FlowContext<'_>) -> Option<String> {
    let mut found: Option<String> = None;
    for e in entries(ctx, None) {
        if e.kind != EntryKind::App {
            continue;
        }
        let rest = e.url.split_once("://")?;
        let origin = format!(
            "{}://{}",
            rest.0.to_ascii_lowercase(),
            host_of_origin(&e.url)?
        );
        match &found {
            Some(prev) if *prev != origin => return None,
            _ => found = Some(origin),
        }
    }
    found
}

/// Automatic capture → trace mapping (ver [`CompareOptions::map_origin`]).
fn auto_map(ctx_a: &FlowContext<'_>, ctx_b: &FlowContext<'_>) -> Option<(OriginMap, String)> {
    let is_trace = |c: &FlowContext<'_>| {
        c.session
            .session
            .labels
            .iter()
            .any(|l| l == crate::parse::trace::TRACE_LABEL)
    };
    let (a_trace, b_trace) = (is_trace(ctx_a), is_trace(ctx_b));
    if a_trace == b_trace {
        return None;
    }
    let (oa, ob) = (single_app_origin(ctx_a)?, single_app_origin(ctx_b)?);
    if host_of_origin(&oa) == host_of_origin(&ob) {
        return None;
    }
    let (from, to) = if b_trace { (oa, ob) } else { (ob, oa) };
    // only the trace on loopback (the local sim) is mapped on its own; another host requires --map-origin
    if !is_loopback_origin(&to) {
        return None;
    }
    let why = format!(
        "different application origins ({from} × {to}); mapped automatically because there is a script-trace session (use --map-origin to control)"
    );
    Some((OriginMap { from, to }, why))
}

pub fn compare_sessions(
    a: &SessionV1,
    a_source: &dyn BodySource,
    b: &SessionV1,
    b_source: &dyn BodySource,
    options: &CompareOptions,
) -> SessionComparison {
    let ctx_a = FlowContext::new(a, a_source, &options.flow);
    let ctx_b = FlowContext::new(b, b_source, &options.flow);
    let mut result = SessionComparison {
        rounds: Vec::new(),
        unpaired_rounds: Vec::new(),
        groups: Vec::new(),
        entry_request: None,
        reordered: Vec::new(),
        pairs: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
        ambiguities: Vec::new(),
        counts: PairCounts::default(),
        parts_counts: PartsCounts::default(),
        redacted_fields: 0,
        warnings: Vec::new(),
        mapped_origin: None,
    };
    let map = options.map_origin.clone().or_else(|| {
        let note = auto_map(&ctx_a, &ctx_b);
        note.map(|(m, why)| {
            result.warnings.push(why);
            m
        })
    });
    result.mapped_origin = map.clone();
    let mut all_a = entries(&ctx_a, map.as_ref());
    let mut all_b = entries(&ctx_b, map.as_ref());
    for (list, range, session, side) in [
        (&mut all_a, &options.a_range, a, "A"),
        (&mut all_b, &options.b_range, b, "B"),
    ] {
        if let Some(range) = range {
            match range.resolve(session) {
                Ok((from, to)) => list.retain(|e| e.index >= from && e.index <= to),
                Err(why) => result.warnings.push(format!(
                    "invalid {side} range ({}..{}): {why}; comparing the whole session",
                    range.from, range.to
                )),
            }
        }
    }
    // Only the application is aligned by default; the rest become their own groups.
    let (ea, eb): (Vec<Entry>, Vec<Entry>) = if options.include_all {
        (all_a.clone(), all_b.clone())
    } else {
        for kind in [EntryKind::Protection, EntryKind::Static] {
            let pick = |list: &[Entry]| {
                list.iter()
                    .filter(|e| e.kind == kind)
                    .map(request_ref)
                    .collect::<Vec<_>>()
            };
            let (ga, gb) = (pick(&all_a), pick(&all_b));
            if !ga.is_empty() || !gb.is_empty() {
                result.groups.push(OtherGroup {
                    kind: if kind == EntryKind::Protection {
                        "protection"
                    } else {
                        "static"
                    }
                    .to_string(),
                    a: ga,
                    b: gb,
                });
            }
        }
        (
            all_a
                .iter()
                .filter(|e| e.kind == EntryKind::App)
                .cloned()
                .collect(),
            all_b
                .iter()
                .filter(|e| e.kind == EntryKind::App)
                .cloned()
                .collect(),
        )
    };

    // Rounds: segmentation by the entry request (1st application document that
    // repeats).
    let entry = entry_base(&ea, &eb);
    result.entry_request = entry.clone();
    let rounds_a = split_rounds(&ea, entry.as_deref());
    let rounds_b = split_rounds(&eb, entry.as_deref());
    // Round much smaller than the median: a reload of the entry in the middle of the application
    // (`[E,P,C1,E,C2,C3]`) opens a new round, which may end up with few steps.
    // The segmentation heuristic stays; the warning only asks for a check.
    let mut sizes: Vec<usize> = rounds_a
        .iter()
        .chain(rounds_b.iter())
        .map(Vec::len)
        .filter(|n| *n > 0)
        .collect();
    if sizes.len() >= 2 {
        sizes.sort_unstable();
        let median = sizes[sizes.len() / 2];
        for (side, rounds) in [("A", &rounds_a), ("B", &rounds_b)] {
            if rounds.len() < 2 {
                continue;
            }
            for round in rounds {
                let n = round.len();
                if n > 0 && n < median && median - n >= 2 {
                    result.warnings.push(format!(
                        "possible reload: round with {n} steps ({side} {}); check whether the entry was reloaded in the middle of the application",
                        request_ref(&round[0]).request_id
                    ));
                }
            }
        }
    }
    let mut scores: Vec<(usize, usize, usize)> = Vec::new();
    for (i, ra) in rounds_a.iter().enumerate() {
        for (j, rb) in rounds_b.iter().enumerate() {
            scores.push((round_score(ra, rb), i, j));
        }
    }
    scores.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)).then(x.2.cmp(&y.2)));
    let (mut used_a, mut used_b) = (vec![false; rounds_a.len()], vec![false; rounds_b.len()]);
    let mut matched: Vec<(usize, usize, usize)> = Vec::new();
    let single = rounds_a.len() == 1 && rounds_b.len() == 1;
    for (score, i, j) in scores {
        if used_a[i] || used_b[j] || (score == 0 && !single) {
            continue;
        }
        used_a[i] = true;
        used_b[j] = true;
        matched.push((i, j, score));
    }
    matched.sort();
    for (side, rounds, used) in [("A", &rounds_a, &used_a), ("B", &rounds_b, &used_b)] {
        for (n, round) in rounds.iter().enumerate() {
            if !used[n] && !round.is_empty() {
                result.unpaired_rounds.push(UnpairedRound {
                    side: side.to_string(),
                    round: n,
                    requests: round.len(),
                    first: request_ref(&round[0]),
                    last: request_ref(&round[round.len() - 1]),
                });
            }
        }
    }

    let mut compared: Vec<(usize, PairComparison)> = Vec::new();
    for (round_no, (i, j, score)) in matched.iter().enumerate() {
        let (ra, rb) = (&rounds_a[*i], &rounds_b[*j]);
        result.rounds.push(RoundInfo {
            a_round: *i,
            b_round: *j,
            score: *score,
            a_requests: ra.len(),
            b_requests: rb.len(),
        });
        align_round(&ctx_a, &ctx_b, ra, rb, round_no, &mut result, &mut compared);
    }
    compared.sort_by_key(|(index, _)| *index);
    for (_, pair) in compared {
        add_counts(&mut result.counts, &pair.counts);
        result.parts_counts.r#static += pair.parts_counts.r#static;
        result.parts_counts.dynamic += pair.parts_counts.dynamic;
        result.parts_counts.runtime += pair.parts_counts.runtime;
        result.parts_counts.no_origin += pair.parts_counts.no_origin;
        result.pairs.push(pair);
    }
    result.redacted_fields = result.counts.redacted;
    if result.redacted_fields > 0 {
        result.warnings.push(format!(
            "{} redacted field(s) ([REDACTED]) cannot be compared or traced",
            result.redacted_fields
        ));
    }
    result
}

/// Model (`method|host|path`) of the first application document that
/// repeats; it must exist on both sides.
pub(crate) fn entry_base(ea: &[Entry], eb: &[Entry]) -> Option<String> {
    let repeated = |list: &[Entry]| -> Vec<String> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in list.iter().filter(|e| e.document) {
            *counts.entry(&e.base).or_default() += 1;
        }
        let mut order: Vec<String> = Vec::new();
        for e in list.iter().filter(|e| e.document) {
            if counts[e.base.as_str()] >= 2 && !order.contains(&e.base) {
                order.push(e.base.clone());
            }
        }
        order
    };
    let has = |list: &[Entry], base: &str| list.iter().any(|e| e.document && e.base == base);
    repeated(ea)
        .into_iter()
        .find(|base| has(eb, base))
        .or_else(|| repeated(eb).into_iter().find(|base| has(ea, base)))
}

pub(crate) fn split_rounds(list: &[Entry], entry: Option<&str>) -> Vec<Vec<Entry>> {
    let Some(entry) = entry else {
        return vec![list.to_vec()];
    };
    let starts: Vec<usize> = list
        .iter()
        .enumerate()
        .filter(|(_, e)| e.document && e.base == entry)
        .map(|(i, _)| i)
        .collect();
    // Reload of the entry (no application step since the previous occurrence)
    // does not open a new round.
    let mut kept: Vec<usize> = Vec::new();
    for &i in &starts {
        let progressed = kept.last().map_or(true, |&prev| {
            list[prev + 1..i]
                .iter()
                .any(|e| e.kind == EntryKind::App && !(e.document && e.base == entry))
        });
        if progressed {
            kept.push(i);
        }
    }
    let starts = kept;
    if starts.len() < 2 {
        return vec![list.to_vec()];
    }
    let mut bounds: Vec<usize> = starts[1..].to_vec();
    bounds.insert(0, 0);
    bounds.push(list.len());
    bounds
        .windows(2)
        .map(|w| list[w[0]..w[1]].to_vec())
        .collect()
}

fn round_score(ra: &[Entry], rb: &[Entry]) -> usize {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in ra {
        *counts.entry(&e.model).or_default() += 1;
    }
    let mut score = 0;
    for e in rb {
        if let Some(n) = counts.get_mut(e.model.as_str()) {
            if *n > 0 {
                *n -= 1;
                score += 1;
            }
        }
    }
    score
}

/// Aligns and compares a pair of rounds.
fn align_round(
    ctx_a: &FlowContext<'_>,
    ctx_b: &FlowContext<'_>,
    ea: &[Entry],
    eb: &[Entry],
    round_no: usize,
    result: &mut SessionComparison,
    out: &mut Vec<(usize, PairComparison)>,
) {
    let (pairs, dropped) = align(ea, eb);
    let mut used_a = vec![false; ea.len()];
    let mut used_b = vec![false; eb.len()];
    for (i, j, how) in &pairs {
        used_a[*i] = true;
        used_b[*j] = true;
        if *how == "path" {
            result.ambiguities.push(format!(
                "{} ↔ {}: same method/host/path, but different field names; paired by order",
                ea[*i].id, eb[*j].id
            ));
        }
    }
    for (i, j) in dropped {
        result.ambiguities.push(format!(
            "{} ↔ {}: same model, but the pairing would cross the order; not paired",
            ea[i].id, eb[j].id
        ));
    }
    let still_a: Vec<usize> = (0..ea.len()).filter(|i| !used_a[*i]).collect();
    let left_b: Vec<usize> = (0..eb.len()).filter(|j| !used_b[*j]).collect();
    let mut count_a: HashMap<&str, usize> = HashMap::new();
    let mut count_b: HashMap<&str, usize> = HashMap::new();
    for e in ea {
        *count_a.entry(&e.model).or_default() += 1;
    }
    for e in eb {
        *count_b.entry(&e.model).or_default() += 1;
    }
    for (model, na) in &count_a {
        let nb = count_b.get(model).copied().unwrap_or(0);
        if nb > 0 && nb != *na {
            let label = model.split('|').take(3).collect::<Vec<_>>().join(" ");
            result.ambiguities.push(format!(
                "{label}: A has {na} and B has {nb} request(s) of the same model; the leftovers are positional"
            ));
        }
    }
    let mut taken_b = vec![false; left_b.len()];
    for &i in &still_a {
        if let Some(k) = left_b
            .iter()
            .enumerate()
            .position(|(k, &j)| !taken_b[k] && eb[j].model == ea[i].model)
        {
            taken_b[k] = true;
            result.reordered.push(ReorderedPair {
                a: request_ref(&ea[i]),
                b: request_ref(&eb[left_b[k]]),
            });
            result.ambiguities.push(format!(
                "{} ↔ {}: same model in the leftovers on both sides; probably reordered",
                ea[i].id, eb[left_b[k]].id
            ));
        }
    }
    for i in still_a {
        result.only_in_a.push(request_ref(&ea[i]));
    }
    for j in left_b {
        result.only_in_b.push(request_ref(&eb[j]));
    }
    let mut max_b_seen: Option<usize> = None;
    for (i, j, how) in pairs {
        let out_of_order = max_b_seen.is_some_and(|m| eb[j].index < m);
        max_b_seen = Some(max_b_seen.map_or(eb[j].index, |m| m.max(eb[j].index)));
        let mut pair = compare_pair(ctx_a, ctx_b, &ea[i], &eb[j], how, out_of_order);
        pair.round = round_no;
        out.push((ea[i].index, pair));
    }
}

/// Monotonic A↔B pairing. Returns the pairs `(i, j, "model"|"path")` in
/// order and the pairs of the same model discarded for crossing the order.
type Aligned = (Vec<(usize, usize, &'static str)>, Vec<(usize, usize)>);

fn align(ea: &[Entry], eb: &[Entry]) -> Aligned {
    let (n, m) = (ea.len(), eb.len());
    let weight = |i: usize, j: usize| -> u32 {
        if ea[i].model == eb[j].model {
            4
        } else if ea[i].base == eb[j].base {
            1
        } else {
            0
        }
    };
    if n.saturating_mul(m) <= 16_000_000 {
        let width = m + 1;
        let mut table = vec![0u32; (n + 1) * width];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                let mut best = table[(i + 1) * width + j].max(table[i * width + j + 1]);
                let w = weight(i, j);
                if w > 0 {
                    best = best.max(table[(i + 1) * width + j + 1] + w);
                }
                table[i * width + j] = best;
            }
        }
        let (mut i, mut j) = (0, 0);
        let mut pairs = Vec::new();
        while i < n && j < m {
            let w = weight(i, j);
            if w > 0 && table[i * width + j] == table[(i + 1) * width + j + 1] + w {
                pairs.push((i, j, if w == 4 { "model" } else { "path" }));
                i += 1;
                j += 1;
            } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }
        return (pairs, Vec::new());
    }
    // Huge sessions: model in order + longest increasing subsequence.
    let mut by_model: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, e) in eb.iter().enumerate() {
        by_model.entry(&e.model).or_default().push(j);
    }
    let mut cursor: HashMap<&str, usize> = HashMap::new();
    let mut greedy: Vec<(usize, usize)> = Vec::new();
    for (i, e) in ea.iter().enumerate() {
        let slot = cursor.entry(&e.model).or_default();
        if let Some(&j) = by_model.get(e.model.as_str()).and_then(|v| v.get(*slot)) {
            *slot += 1;
            greedy.push((i, j));
        }
    }
    // LIS by j
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; greedy.len()];
    let mut tail_idx: Vec<usize> = Vec::new();
    for (k, (_, j)) in greedy.iter().enumerate() {
        let pos = tails.partition_point(|t| t < j);
        if pos == tails.len() {
            tails.push(*j);
            tail_idx.push(k);
        } else {
            tails[pos] = *j;
            tail_idx[pos] = k;
        }
        prev[k] = if pos > 0 {
            Some(tail_idx[pos - 1])
        } else {
            None
        };
    }
    let mut keep = vec![false; greedy.len()];
    let mut cur = tail_idx.last().copied();
    while let Some(k) = cur {
        keep[k] = true;
        cur = prev[k];
    }
    let pairs = greedy
        .iter()
        .zip(&keep)
        .filter(|(_, k)| **k)
        .map(|((i, j), _)| (*i, *j, "model"))
        .collect();
    let dropped = greedy
        .iter()
        .zip(&keep)
        .filter(|(_, k)| !**k)
        .map(|((i, j), _)| (*i, *j))
        .collect();
    (pairs, dropped)
}

fn add_counts(total: &mut PairCounts, add: &PairCounts) {
    total.r#static += add.r#static;
    total.dynamic += add.dynamic;
    total.runtime += add.runtime;
    total.no_origin += add.no_origin;
    total.only_a += add.only_a;
    total.only_b += add.only_b;
    total.redacted += add.redacted;
}

fn field_key(scope: ConsumedScope, field: &str, occurrence: usize) -> (u8, String, usize) {
    let name = match scope {
        ConsumedScope::Header | ConsumedScope::Cookie => field.to_ascii_lowercase(),
        _ => field.to_string(),
    };
    (scope as u8, name, occurrence)
}

fn compare_pair(
    ctx_a: &FlowContext<'_>,
    ctx_b: &FlowContext<'_>,
    ea: &Entry,
    eb: &Entry,
    how: &str,
    out_of_order: bool,
) -> PairComparison {
    let pos_a = ctx_a.find(&ea.id).expect("position A");
    let pos_b = ctx_b.find(&eb.id).expect("position B");
    let ca = ctx_a.consumed_for(pos_a);
    let cb = ctx_b.consumed_for(pos_b);
    let mut index_b: HashMap<(u8, String, usize), usize> = HashMap::new();
    for (n, c) in cb.iter().enumerate() {
        index_b.insert(field_key(c.scope, &c.field, c.occurrence), n);
    }
    let mut used = vec![false; cb.len()];
    let mut fields: Vec<FieldDiff> = Vec::new();
    for c in ca.iter() {
        let key = field_key(c.scope, &c.field, c.occurrence);
        match index_b.get(&key) {
            Some(&n) => {
                used[n] = true;
                let other = &cb[n];
                let class = if is_redacted(&c.value) || is_redacted(&other.value) {
                    FieldClass::Redacted
                } else if c.value == other.value {
                    FieldClass::Static
                } else {
                    FieldClass::Dynamic
                };
                fields.push(FieldDiff {
                    scope: c.scope,
                    field: c.field.clone(),
                    occurrence: c.occurrence,
                    class,
                    label: String::new(),
                    origin_label: None,
                    dynamic_kind: None,
                    a: Some(preview(&c.value)),
                    b: Some(preview(&other.value)),
                    origin: None,
                    parts: Vec::new(),
                });
            }
            None => fields.push(FieldDiff {
                scope: c.scope,
                field: c.field.clone(),
                occurrence: c.occurrence,
                class: FieldClass::OnlyA,
                label: String::new(),
                origin_label: None,
                dynamic_kind: None,
                a: Some(preview(&c.value)),
                b: None,
                origin: None,
                parts: Vec::new(),
            }),
        }
    }
    for (n, c) in cb.iter().enumerate() {
        if !used[n] {
            fields.push(FieldDiff {
                scope: c.scope,
                field: c.field.clone(),
                occurrence: c.occurrence,
                class: FieldClass::OnlyB,
                label: String::new(),
                origin_label: None,
                dynamic_kind: None,
                a: None,
                b: Some(preview(&c.value)),
                origin: None,
                parts: Vec::new(),
            });
        }
    }

    // Origins of B, only if there is a dynamic field.
    if fields.iter().any(|f| f.class == FieldClass::Dynamic) {
        let origins: Option<ValueOrigins> = origins_in(ctx_b, &eb.id).ok();
        let origins_a: Option<ValueOrigins> = origins_in(ctx_a, &ea.id).ok();
        for diff in fields.iter_mut().filter(|f| f.class == FieldClass::Dynamic) {
            let a_value = ca
                .iter()
                .find(|c| {
                    field_key(c.scope, &c.field, c.occurrence)
                        == field_key(diff.scope, &diff.field, diff.occurrence)
                })
                .map(|c| c.value.clone())
                .unwrap_or_default();
            let b_value = cb
                .iter()
                .find(|c| {
                    field_key(c.scope, &c.field, c.occurrence)
                        == field_key(diff.scope, &diff.field, diff.occurrence)
                })
                .map(|c| c.value.clone())
                .unwrap_or_default();
            let entry = origins.as_ref().and_then(|o| {
                o.values.iter().find(|v| {
                    // an adapter part (`XML.delta`) counts; a loose excerpt of an opaque field does not
                    v.parent
                        .as_ref()
                        .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
                        && v.scope == diff.scope
                        && v.occurrence == diff.occurrence
                        && field_key(v.scope, &v.field, v.occurrence)
                            == field_key(diff.scope, &diff.field, diff.occurrence)
                })
            });
            let opaque = diff.scope == ConsumedScope::Body
                && a_value.len() >= OPAQUE_MIN
                && b_value.len() >= OPAQUE_MIN
                && !entry.is_some_and(|v| {
                    matches!(v.status, OriginStatus::Origin | OriginStatus::Ambiguous)
                });
            if opaque {
                diff.dynamic_kind = Some(DynamicKind::Composite);
                let subs_of = |o: &Option<ValueOrigins>| -> Vec<ValueOrigin> {
                    o.as_ref()
                        .map(|o| {
                            o.values
                                .iter()
                                .filter(|v| {
                                    v.parent.as_deref() == Some(diff.field.as_str())
                                        && v.occurrence == diff.occurrence
                                        && !v.evidences.is_empty()
                                })
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let (subs_a, subs_b) = (subs_of(&origins_a), subs_of(&origins));
                diff.parts = opaque_parts(&a_value, &b_value, &subs_a, &subs_b, options_cap(ctx_b));
                if !diff.parts.iter().any(|p| p.class == FieldClass::Dynamic) {
                    diff.dynamic_kind = Some(DynamicKind::NoOrigin);
                }
            } else if let Some(v) = entry {
                diff.dynamic_kind = Some(kind_of(v));
                diff.origin = summary(v);
            } else {
                diff.dynamic_kind = Some(DynamicKind::NoOrigin);
            }
        }
    }

    for f in &mut fields {
        f.label = match f.class {
            FieldClass::Static => "static",
            FieldClass::Dynamic => "dynamic",
            FieldClass::OnlyA => "only in A",
            FieldClass::OnlyB => "only in B",
            FieldClass::Redacted => "redacted",
        }
        .to_string();
        f.origin_label = origin_label(f.dynamic_kind, f.origin.as_ref());
        for part in &mut f.parts {
            if part.class == FieldClass::Dynamic {
                part.origin_label =
                    origin_label(Some(part.dynamic_kind), part.origin.as_ref()).unwrap_or_default();
            }
        }
    }
    let mut counts = PairCounts::default();
    let mut parts_counts = PartsCounts::default();
    for f in &fields {
        match f.class {
            FieldClass::Static => counts.r#static += 1,
            FieldClass::Dynamic => {
                let dynamic_parts: Vec<&PartDiff> = f
                    .parts
                    .iter()
                    .filter(|p| p.class == FieldClass::Dynamic)
                    .collect();
                if f.dynamic_kind == Some(DynamicKind::Composite) && !dynamic_parts.is_empty() {
                    for part in dynamic_parts {
                        counts.dynamic += 1;
                        parts_counts.dynamic += 1;
                        if part.dynamic_kind == DynamicKind::Runtime {
                            counts.runtime += 1;
                            parts_counts.runtime += 1;
                        } else {
                            counts.no_origin += 1;
                            parts_counts.no_origin += 1;
                        }
                    }
                } else {
                    counts.dynamic += 1;
                    if f.dynamic_kind == Some(DynamicKind::Runtime) {
                        counts.runtime += 1;
                    } else {
                        counts.no_origin += 1;
                    }
                }
                parts_counts.r#static += f
                    .parts
                    .iter()
                    .filter(|p| p.class == FieldClass::Static)
                    .count();
            }
            FieldClass::OnlyA => counts.only_a += 1,
            FieldClass::OnlyB => counts.only_b += 1,
            FieldClass::Redacted => counts.redacted += 1,
        }
    }
    PairComparison {
        a: request_ref(ea),
        b: request_ref(eb),
        aligned_by: how.to_string(),
        round: 0,
        out_of_order,
        fields,
        counts,
        parts_counts,
    }
}

fn expand_class(text: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let region = &bytes[start.min(bytes.len())..end.min(bytes.len())];
    let upper = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    let lower = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let class: fn(u8) -> bool = if !region.is_empty() && region.iter().all(|b| upper(*b)) {
        |b| b.is_ascii_uppercase() || b.is_ascii_digit()
    } else if !region.is_empty() && region.iter().all(|b| lower(*b)) {
        |b| b.is_ascii_lowercase() || b.is_ascii_digit()
    } else {
        return (start, end);
    };
    let (mut s, mut e) = (start, end);
    while s > 0 && class(bytes[s - 1]) {
        s -= 1;
    }
    while e < bytes.len() && class(bytes[e]) {
        e += 1;
    }
    (s, e)
}

fn sub_key(v: &ValueOrigin) -> Option<(String, ProducerScope, Option<String>, Option<u64>)> {
    let e = v.evidences.get(v.oldest?)?;
    Some((
        e.request_id.clone(),
        e.scope,
        e.field.clone(),
        e.producer_offset,
    ))
}

/// Excerpts of an opaque field: anchors = known values (with origin) that
/// exist on both sides, paired by the same producer; the gaps between the
/// same anchors match and the difference is computed only in them. So an
/// anchor never cuts a known value and each dynamic excerpt covers the value
/// whole (SESSIONID, processId, delta…).
fn opaque_parts(
    a: &str,
    b: &str,
    subs_a: &[ValueOrigin],
    subs_b: &[ValueOrigin],
    cap: usize,
) -> Vec<PartDiff> {
    // pairs (sub A, sub B) with the same producer key, in order
    let mut used_b = vec![false; subs_b.len()];
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (i, va) in subs_a.iter().enumerate() {
        let Some(key) = sub_key(va) else { continue };
        if let Some(j) = subs_b
            .iter()
            .enumerate()
            .position(|(j, vb)| !used_b[j] && sub_key(vb).as_ref() == Some(&key))
        {
            used_b[j] = true;
            pairs.push((i, j));
        }
    }
    pairs.sort_by_key(|(i, _)| subs_a[*i].offset);
    // keeps only monotonic pairs on both sides and without overlap
    let mut anchors: Vec<(usize, usize, usize, usize, usize)> = Vec::new(); // a0,a1,b0,b1,j
    for (i, j) in pairs {
        let (Some(ao), Some(bo)) = (subs_a[i].offset, subs_b[j].offset) else {
            continue;
        };
        let (a0, b0) = (ao as usize, bo as usize);
        let (a1, b1) = (a0 + subs_a[i].length, b0 + subs_b[j].length);
        if a1 > a.len() || b1 > b.len() {
            continue;
        }
        if anchors.last().map_or(true, |l| a0 >= l.1 && b0 >= l.3) {
            anchors.push((a0, a1, b0, b1, j));
        }
    }
    let mut parts: Vec<PartDiff> = Vec::new();
    let (mut ca, mut cb) = (0usize, 0usize);
    let unpaired_b: Vec<&ValueOrigin> = subs_b
        .iter()
        .enumerate()
        .filter(|(j, _)| !anchors.iter().any(|x| x.4 == *j))
        .map(|(_, v)| v)
        .collect();
    for (a0, a1, b0, b1, j) in anchors {
        gap_parts(a, b, (ca, a0), (cb, b0), &unpaired_b, cap, &mut parts);
        let (ta, tb) = (&a[a0..a1], &b[b0..b1]);
        let sub = &subs_b[j];
        if ta == tb {
            parts.push(static_part(a0, b0, ta));
        } else {
            parts.push(PartDiff {
                class: FieldClass::Dynamic,
                label: "dynamic".to_string(),
                a_offset: a0 as u64,
                b_offset: b0 as u64,
                a: ta.to_string(),
                b: tb.to_string(),
                dynamic_kind: kind_of(sub),
                origin_label: String::new(),
                origin: summary(sub),
            });
        }
        ca = a1;
        cb = b1;
    }
    gap_parts(
        a,
        b,
        (ca, a.len()),
        (cb, b.len()),
        &unpaired_b,
        cap,
        &mut parts,
    );
    parts.sort_by_key(|p| p.b_offset);
    parts
}

fn static_part(a_off: usize, b_off: usize, text: &str) -> PartDiff {
    PartDiff {
        class: FieldClass::Static,
        label: "static".to_string(),
        a_offset: a_off as u64,
        b_offset: b_off as u64,
        a: text.to_string(),
        b: text.to_string(),
        dynamic_kind: DynamicKind::NoOrigin,
        origin_label: String::new(),
        origin: None,
    }
}

/// Difference within a pair of matching gaps.
fn gap_parts(
    a: &str,
    b: &str,
    (a_start, a_end): (usize, usize),
    (b_start, b_end): (usize, usize),
    unpaired_b: &[&ValueOrigin],
    cap: usize,
    parts: &mut Vec<PartDiff>,
) {
    let (ga, gb) = (&a[a_start..a_end], &b[b_start..b_end]);
    if ga.is_empty() && gb.is_empty() {
        return;
    }
    if ga == gb {
        if ga.len() >= 8 {
            parts.push(static_part(a_start, b_start, ga));
        }
        return;
    }
    // regions that differ, expanded to the "token" and merged if overlapping
    let mut regions: Vec<(usize, usize, usize, usize)> = Vec::new();
    for (a0, a1, b0, b1) in diff_regions(ga.as_bytes(), gb.as_bytes(), cap) {
        let (ea0, ea1) = expand_class(ga, a0, a1);
        let (eb0, eb1) = expand_class(gb, b0, b1);
        match regions.last_mut() {
            Some(last) if ea0 <= last.1 || eb0 <= last.3 => {
                last.1 = last.1.max(ea1);
                last.3 = last.3.max(eb1);
            }
            _ => regions.push((ea0, ea1, eb0, eb1)),
        }
    }
    let (mut ca, mut cb) = (0usize, 0usize);
    let emit_static = |ca: usize, cb: usize, na: usize, nb: usize, parts: &mut Vec<PartDiff>| {
        if na - ca == nb - cb && na - ca >= 8 {
            parts.push(static_part(a_start + ca, b_start + cb, &ga[ca..na]));
        }
    };
    for (a0, a1, b0, b1) in regions {
        emit_static(ca, cb, a0, b0, parts);
        let abs_b = (b_start + b0, b_start + b1);
        let covering = unpaired_b.iter().find(|v| {
            v.offset.is_some_and(|o| {
                let (s, l) = (o as usize, v.length);
                s < abs_b.1.max(abs_b.0 + 1) && abs_b.0 < s + l
            })
        });
        parts.push(PartDiff {
            class: FieldClass::Dynamic,
            label: "dynamic".to_string(),
            a_offset: (a_start + a0) as u64,
            b_offset: (b_start + b0) as u64,
            a: ga[a0..a1].to_string(),
            b: covering.map_or_else(|| gb[b0..b1].to_string(), |v| v.value.clone()),
            dynamic_kind: covering.map_or(DynamicKind::NoOrigin, |v| kind_of(v)),
            origin_label: String::new(),
            origin: covering.and_then(|v| summary(v)),
        });
        ca = a1;
        cb = b1;
    }
    emit_static(ca, cb, ga.len(), gb.len(), parts);
}

fn origin_label(kind: Option<DynamicKind>, origin: Option<&OriginSummary>) -> Option<String> {
    match kind? {
        DynamicKind::Runtime => Some(match origin {
            Some(o) => {
                let word = if o.confidence == Some(Confidence::Possible) {
                    "possible origin"
                } else {
                    "origin"
                };
                let amb = if o.ambiguous { ", ambiguous" } else { "" };
                format!("get at runtime ({word}: {}{amb})", o.request_id)
            }
            None => "get at runtime".to_string(),
        }),
        DynamicKind::NoOrigin => Some("dynamic without origin".to_string()),
        DynamicKind::Repeated => Some("dynamic without origin (value already circulating)".to_string()),
        DynamicKind::Composite => None,
    }
}

fn options_cap(ctx: &FlowContext<'_>) -> usize {
    ctx.options.max_opaque_cells
}
