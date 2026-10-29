//! Linha do tempo da aplicação (docs/13).
//!
//! `timeline(session, source, opts)` devolve uma entrada por requisição da
//! aplicação, na ordem da sessão, com tempo relativo, rodada, tipo
//! (`page`|`post`|`request`), rótulo, veredito do assess e os NOMES (sem
//! valores) dos valores-chave consumidos e produzidos. Proteção e estáticos
//! entram recolhidos em grupos com contagem entre os eventos.
//!
//! Esquema JSON (camelCase): `{ entryRequest, rounds, items: [ { type:"event",
//! requestId, round, kind, label, method, url, status, tMs, verdict, verdictKind,
//! consumed[], produced[] } | { type:"group", kind:"protection"|"static", count,
//! requestIds[] } ], counts: {events, protection, static}, warnings[] }`.
//!
//! Rótulo: com adaptador (`FlowOptions.adapters`) que decodifique o corpo, as
//! partes `event` e `page` dão `event @ page`; sem elas, método + caminho.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::assess::{assess_session, AssessRules, VerdictKind};
use crate::compare::{entries, entry_base, split_rounds, EntryKind};
use crate::flow::{origins_in, FlowContext, FlowOptions, OriginStatus};
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
    /// Rodada (1 = primeira).
    pub round: usize,
    /// `page` (GET de documento), `post` (método não-GET) ou `request`.
    pub kind: String,
    pub label: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    /// Milissegundos desde a primeira requisição da sessão, quando há tempos.
    pub t_ms: Option<f64>,
    pub verdict: String,
    pub verdict_kind: VerdictKind,
    /// Nomes de valores consumidos com origem observada (sem valores).
    pub consumed: Vec<String>,
    /// Nomes de valores que esta resposta produziu para requisições seguintes.
    pub produced: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineGroup {
    /// `protection` ou `static`.
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
    let all = entries(&ctx);
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

    // nomes consumidos (por consumidor) e produzidos (por produtor)
    let mut consumed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut produced: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    for e in &app {
        let Some(pos) = ctx.find(&e.id) else { continue };
        let (mut event, mut page) = (None, None);
        for c in ctx.consumed_for(pos).iter() {
            if c.part_of.is_some() {
                match c.field.rsplit('.').next() {
                    Some("event") if event.is_none() => event = Some(c.value.clone()),
                    Some("page") if page.is_none() => page = Some(c.value.clone()),
                    _ => {}
                }
            }
        }
        if let (Some(event), Some(page)) = (event, page) {
            labels.insert(e.id.clone(), format!("{event} @ {page}"));
        }
        let Ok(origins) = origins_in(&ctx, &e.id) else {
            continue;
        };
        for v in origins.values.iter().filter(|v| {
            // partes de adaptador (`XML.delta`) entram; trechos soltos de um campo opaco não
            v.parent
                .as_ref()
                .map_or(true, |p| v.field.starts_with(&format!("{p}.")))
                && matches!(
                    v.status,
                    OriginStatus::Origin | OriginStatus::Ambiguous | OriginStatus::Composite
                )
        }) {
            push_unique(consumed.entry(e.id.clone()).or_default(), &v.field);
            for ev in &v.evidences {
                if let Some(field) = &ev.field {
                    push_unique(produced.entry(ev.request_id.clone()).or_default(), field);
                }
            }
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

fn push_unique(list: &mut Vec<String>, name: &str) {
    if !list.iter().any(|n| n == name) {
        list.push(name.to_string());
    }
}
