//! Application timeline (docs/13).
//!
//! `timeline(session, source, opts)` returns one entry per application request,
//! in session order, with relative time, round, type (`page`|`post`|`request`),
//! label, assess verdict and the NAMES (without values) of the key values consumed
//! and produced. Protection and static requests are collapsed into groups with a
//! count between the events.
//!
//! JSON schema (camelCase): `{ entryRequest, rounds, items: [ { type:"event",
//! requestId, round, kind, label, method, url, status, tMs, verdict, verdictKind,
//! consumed[], produced[] } | { type:"group", kind:"protection"|"static", count,
//! requestIds[] } ], counts: {events, protection, static}, warnings[] }`.
//!
//! Label: with an adapter (`FlowOptions.adapters`) that decodes the body, the
//! `event` and `page` parts give `event @ page`; without them, method + path.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::adapter::AdapterContext;
use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{entries, entry_base, split_rounds, EntryKind};
use crate::flow::{linked_field_names, FlowContext, FlowOptions};
use crate::model::SessionV1;
use crate::search::BodySource;

#[derive(Debug, Clone, Default)]
pub struct TimelineOptions {
    pub flow: FlowOptions,
    pub rules: AssessRules,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TimelineItem {
    Event(TimelineEvent),
    Group(TimelineGroup),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub request_id: String,
    /// Round (1 = first).
    pub round: usize,
    /// `page` (document GET), `post` (non-GET method) or `request`.
    pub kind: String,
    pub label: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    /// Milliseconds since the first request of the session, when timings exist.
    pub t_ms: Option<f64>,
    pub verdict: String,
    pub verdict_kind: VerdictKind,
    /// Names of consumed values with an observed origin (no values).
    pub consumed: Vec<String>,
    /// Names of values that this response produced for later requests.
    pub produced: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineGroup {
    /// `protection` or `static`.
    pub kind: String,
    pub count: usize,
    pub request_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCounts {
    pub events: usize,
    pub protection: usize,
    #[serde(rename = "static")]
    pub statics: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub entry_request: Option<String>,
    pub rounds: usize,
    pub items: Vec<TimelineItem>,
    pub counts: TimelineCounts,
    pub warnings: Vec<String>,
}

pub fn timeline(
    session: &SessionV1,
    source: &dyn BodySource,
    options: &TimelineOptions,
) -> Timeline {
    let ctx = FlowContext::new(session, source, &options.flow);
    let all = entries(&ctx, None);
    let app: Vec<_> = all
        .iter()
        .filter(|e| e.kind == EntryKind::App)
        .cloned()
        .collect();
    let entry = entry_base(&app, &app);
    let rounds = split_rounds(&app, entry.as_deref());
    let mut round_of: BTreeMap<String, usize> = BTreeMap::new();
    for (n, round) in rounds.iter().enumerate() {
        for e in round {
            round_of.insert(e.id.clone(), n + 1);
        }
    }
    let outcomes: BTreeMap<String, _> = assess_session(session, source, &options.rules)
        .into_iter()
        .map(|o| (o.request_id.clone(), o))
        .collect();

    // names consumed (per consumer) and produced (per producer): linear index
    let app_ids: std::collections::HashSet<&str> = app.iter().map(|e| e.id.as_str()).collect();
    let (consumed, produced) = linked_field_names(&ctx, &|id| app_ids.contains(id));
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    for e in &app {
        let Some(pos) = ctx.find(&e.id) else { continue };
        let (mut event, mut page, mut hint) = (None, None, None);
        let attempt = ctx.attempt_ref(pos);
        let actx = AdapterContext {
            url: &attempt.url,
            method: &attempt.method,
            request: true,
            media: None,
        };
        for c in ctx.consumed_for(pos).iter() {
            if c.part_of.is_some() {
                match c.field.rsplit('.').next() {
                    Some("event") if event.is_none() => event = Some(c.value.clone()),
                    Some("page") if page.is_none() => page = Some(c.value.clone()),
                    _ => {}
                }
            } else if c.adapted && hint.is_none() {
                // the adapter can give the operation name (e.g. `init`) when the event is empty
                hint = options
                    .flow
                    .adapters
                    .claim(&c.field, &c.value, &actx)
                    .and_then(|a| a.decode(&c.value).ok().and_then(|d| a.label_hint(&d)));
            }
        }
        let name = hint.or(event);
        match (name, page) {
            (Some(n), Some(p)) => {
                labels.insert(e.id.clone(), format!("{n} @ {p}"));
            }
            (Some(n), None) => {
                labels.insert(e.id.clone(), n);
            }
            _ => {}
        }
    }

    let first_start = all
        .iter()
        .filter_map(|e| ctx.find(&e.id))
        .filter_map(|p| ctx.attempt_ref(p).started_at)
        .fold(None::<f64>, |m, t| Some(m.map_or(t, |m| m.min(t))));
    let mut items: Vec<TimelineItem> = Vec::new();
    let mut counts = TimelineCounts::default();
    let mut round = 1;
    for e in &all {
        match e.kind {
            EntryKind::App => {
                round = round_of.get(&e.id).copied().unwrap_or(round);
                let pos = ctx.find(&e.id);
                let attempt = pos.map(|p| ctx.attempt_ref(p));
                let outcome = outcomes.get(&e.id);
                let kind = if e.document {
                    "page"
                } else if e.method.eq_ignore_ascii_case("GET") {
                    "request"
                } else {
                    "post"
                };
                counts.events += 1;
                items.push(TimelineItem::Event(TimelineEvent {
                    request_id: e.id.clone(),
                    round,
                    kind: kind.to_string(),
                    label: labels.get(&e.id).cloned().unwrap_or_else(|| {
                        format!(
                            "{} {}",
                            e.method,
                            e.url.split(['?', '#']).next().unwrap_or("")
                        )
                    }),
                    method: e.method.clone(),
                    url: e.url.clone(),
                    status: outcome.and_then(|o| o.status),
                    t_ms: attempt
                        .and_then(|a| a.started_at)
                        .zip(first_start)
                        .map(|(t, f)| ((t - f) * 1000.0 * 10.0).round() / 10.0),
                    verdict: outcome.map(|o| o.verdict.clone()).unwrap_or_default(),
                    verdict_kind: outcome.map_or(VerdictKind::NotAssessed, |o| o.verdict_kind),
                    consumed: consumed.get(&e.id).cloned().unwrap_or_default(),
                    produced: produced.get(&e.id).cloned().unwrap_or_default(),
                }));
            }
            EntryKind::Protection | EntryKind::Static => {
                let kind = if e.kind == EntryKind::Protection {
                    counts.protection += 1;
                    "protection"
                } else {
                    counts.statics += 1;
                    "static"
                };
                match items.last_mut() {
                    Some(TimelineItem::Group(g)) if g.kind == kind => {
                        g.count += 1;
                        g.request_ids.push(e.id.clone());
                    }
                    _ => items.push(TimelineItem::Group(TimelineGroup {
                        kind: kind.to_string(),
                        count: 1,
                        request_ids: vec![e.id.clone()],
                    })),
                }
            }
        }
    }
    Timeline {
        entry_request: entry,
        rounds: rounds.len(),
        items,
        counts,
        warnings: Vec::new(),
    }
}
