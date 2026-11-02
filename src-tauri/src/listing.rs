//! Contrato de sessão paginada (rodada 13, P5; docs/19-contrato-app.md).
//!
//! O app não monta `serde_json::Value` da sessão nem a manda inteira ao
//! front-end. A sessão tipada (`SessionV1`) fica no cache de `LazySession`
//! (`commands::cached_session`) e o front pede:
//! - `open_session` → cabeçalho + contagem (`SessionHeader`);
//! - `list_requests(offset, limit, filtro)` → resumos de uma página;
//! - `get_request(id)` → a requisição v1 completa, sob demanda.

use std::collections::{BTreeMap, HashMap, HashSet};

use scrapelens_core::model::{LogicalRequest, RequestLink, SessionV1, TargetProvenance, Warning};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Página máxima de `list_requests`.
pub const MAX_PAGE: usize = 2000;

/// Cabeçalho da sessão: o documento v1 sem `requests`, só com avisos de
/// sessão (sem `entity`), mais a contagem e as fontes vistas.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHeader {
    pub schema_version: u32,
    pub session: Value,
    pub requests: [(); 0],
    pub warnings: Vec<Warning>,
    pub request_count: usize,
    pub sources: Vec<Value>,
}

pub fn header_of(session: &SessionV1) -> Result<SessionHeader, String> {
    let meta = serde_json::to_value(&session.session).map_err(|error| format!("sessão inválida: {error}"))?;
    let mut seen: Vec<&'static str> = Vec::new();
    let mut push = |source: scrapelens_core::model::Source| {
        let name = source.as_str();
        if !seen.contains(&name) {
            seen.push(name);
        }
    };
    for request in &session.requests {
        push(request.provenance.source);
        for attempt in &request.attempts {
            push(attempt.provenance.source);
            for pair in &attempt.cookie.pairs {
                push(pair.provenance.source);
            }
        }
    }
    let sources: Vec<Value> = seen.into_iter().map(|s| Value::String(s.to_string())).collect();
    Ok(SessionHeader {
        schema_version: session.schema_version,
        session: meta,
        requests: [],
        warnings: session.warnings.iter().filter(|w| w.entity.is_none()).cloned().collect(),
        request_count: session.requests.len(),
        sources,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiatorSummary {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Resumo de uma requisição para a lista (~150–400 B; a URL domina).
/// Campos crus do v1: a derivação de rótulos fica no front (`v1/adapter.ts`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestSummary {
    pub id: String,
    pub url: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    /// Duração estimada pela fonte (`timings.estimated`): a lista mostra "≈".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub estimated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator: Option<InitiatorSummary>,
    /// Índice em `RequestPage.targets` (alvos repetidos vão uma vez por página).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<RequestLink>,
    pub source: Value,
    pub warning_count: usize,
}

fn initiator_of(request: &LogicalRequest) -> Option<InitiatorSummary> {
    let last = request.attempts.last().and_then(|a| a.initiator.as_ref());
    let first = request.attempts.first().and_then(|a| a.initiator.as_ref());
    last.or(first).map(|i| InitiatorSummary { kind: i.kind.clone(), url: i.url.clone() })
}

fn target_of(request: &LogicalRequest) -> Option<&TargetProvenance> {
    request.target.as_ref().filter(|t| !t.is_empty())
}

fn source_is_netlog(request: &LogicalRequest) -> bool {
    request.provenance.source == scrapelens_core::model::Source::NetLog
}

pub fn summarize(request: &LogicalRequest, warning_count: usize, target: Option<usize>) -> RequestSummary {
    RequestSummary {
        id: request.id.clone(),
        url: request.url.clone(),
        method: request.method.clone(),
        status: request.status,
        protocol: request.protocol.as_str(),
        resource_type: request.resource_type.clone(),
        wall_time: request.timings.wall_time.clone(),
        total_ms: request.timings.total_ms,
        estimated: request.timings.estimated,
        initiator: initiator_of(request),
        target,
        links: request.links.clone(),
        source: Value::String(request.provenance.source.as_str().to_string()),
        warning_count,
    }
}

/// Tipo exibido (mesma regra de `adaptSession`): só os conhecidos, senão `other`.
pub fn display_type(request: &LogicalRequest) -> &'static str {
    let lower = request.resource_type.as_deref().unwrap_or("other").to_ascii_lowercase();
    match lower.as_str() {
        "document" => "document",
        "stylesheet" => "stylesheet",
        "script" => "script",
        "xhr" => "xhr",
        "fetch" => "fetch",
        "image" => "image",
        "font" => "font",
        _ => "other",
    }
}

pub fn protocol_label(request: &LogicalRequest) -> &'static str {
    match request.protocol.as_str() {
        "h1" => "HTTP/1.1",
        "h2" => "HTTP/2",
        "h3" => "HTTP/3",
        _ => "desconhecido",
    }
}

fn netlog_only_unknown(request: &LogicalRequest) -> bool {
    target_of(request).is_none() && source_is_netlog(request)
}

fn is_popup(target: Option<&TargetProvenance>) -> bool {
    matches!(target, Some(t) if t.kind.as_str() == "page" && t.opener_id.is_some())
}

/// Filtro de alvo (mesma regra de `matchesTargetFilter` em `app/src/target.ts`).
pub fn matches_target(request: &LogicalRequest, filter: &str) -> bool {
    let target = target_of(request);
    match filter {
        "all" => true,
        "netlog_unknown" => netlog_only_unknown(request),
        "popup" => is_popup(target),
        "page" => matches!(target, Some(t) if t.kind.as_str() == "page" && t.opener_id.is_none()),
        other => target.map(|t| t.kind.as_str() == other).unwrap_or(false),
    }
}

pub const TARGET_FILTERS: [&str; 8] =
    ["all", "page", "popup", "iframe", "worker", "service_worker", "shared_worker", "netlog_unknown"];

/// Filtro da lista; os campos espelham os controles da tela.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListFilter {
    /// `all` | `fetch` | `document` | `media` | `error`.
    pub type_filter: Option<String>,
    /// `all` | `HTTP/1.1` | `HTTP/2` | `HTTP/3` | `desconhecido`.
    pub protocol: Option<String>,
    /// Ver `TARGET_FILTERS`; só vale quando a sessão mostra alvos.
    pub target: Option<String>,
    /// Texto da busca rápida (URL, id, método, status).
    pub query: Option<String>,
    /// Busca no payload ativa: a URL deixa de valer e `matchIds` (achados do
    /// `search_session`) passam.
    pub payload_search: bool,
    pub match_ids: Vec<String>,
    /// Filtros de veredito (falha/bloqueio): só estes ids passam.
    pub restrict_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct TypeCounts {
    pub all: usize,
    pub fetch: usize,
    pub document: usize,
    pub media: usize,
    pub error: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPage {
    /// Requisições na sessão.
    pub total: usize,
    /// Requisições que passam no filtro.
    pub matched: usize,
    pub offset: usize,
    pub items: Vec<RequestSummary>,
    /// Alvos distintos citados nesta página (`RequestSummary.target` é o índice).
    pub targets: Vec<TargetProvenance>,
    /// Contagens por tipo na sessão inteira (sem filtro).
    pub counts: TypeCounts,
    pub target_counts: BTreeMap<&'static str, usize>,
    /// Alguma requisição tem alvo, alvo desconhecido (só NetLog) ou ligação.
    pub has_targets: bool,
}

fn passes(request: &LogicalRequest, filter: &ListFilter, show_targets: bool, matches: &HashSet<&str>, restrict: Option<&HashSet<&str>>) -> bool {
    let kind = display_type(request);
    let status = request.status.unwrap_or(0);
    match filter.type_filter.as_deref().unwrap_or("all") {
        "fetch" if !(kind == "fetch" || kind == "xhr") => return false,
        "document" if kind != "document" => return false,
        "media" if !(kind == "image" || kind == "font") => return false,
        "error" if status < 400 => return false,
        _ => {}
    }
    if show_targets && !matches_target(request, filter.target.as_deref().unwrap_or("all")) {
        return false;
    }
    if let Some(ids) = restrict {
        if !ids.contains(request.id.as_str()) {
            return false;
        }
    }
    let protocol = filter.protocol.as_deref().unwrap_or("all");
    if protocol != "all" && protocol_label(request) != protocol {
        return false;
    }
    let q = filter.query.as_deref().unwrap_or("").trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    let common = request.id.contains(&q) || request.method.to_lowercase() == q || status.to_string().contains(&q);
    if filter.payload_search {
        matches.contains(request.id.as_str()) || common
    } else {
        request.url.to_lowercase().contains(&q) || common
    }
}

/// Avisos ligados a cada requisição (`entity`).
fn warning_counts(session: &SessionV1) -> HashMap<&str, usize> {
    let mut map = HashMap::new();
    for warning in &session.warnings {
        if let Some(entity) = warning.entity.as_deref() {
            *map.entry(entity).or_insert(0) += 1;
        }
    }
    map
}

pub fn session_shows_targets(session: &SessionV1) -> bool {
    session.requests.iter().any(|r| target_of(r).is_some() || netlog_only_unknown(r) || !r.links.is_empty())
}

pub fn list_page(session: &SessionV1, offset: usize, limit: usize, filter: &ListFilter) -> RequestPage {
    let limit = limit.clamp(1, MAX_PAGE);
    let has_targets = session_shows_targets(session);
    let show_targets = has_targets
        || session.warnings.iter().any(|w| {
            w.entity.is_none()
                && ["target_attach", "target_unknown", "target_setup", "service_worker"]
                    .iter()
                    .any(|code| w.code.contains(code))
        });
    let matches: HashSet<&str> = filter.match_ids.iter().map(String::as_str).collect();
    let restrict: Option<HashSet<&str>> = filter.restrict_ids.as_ref().map(|ids| ids.iter().map(String::as_str).collect());
    let warnings = warning_counts(session);

    let mut counts = TypeCounts::default();
    let mut target_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut matched = 0usize;
    let mut items = Vec::new();
    let mut targets: Vec<TargetProvenance> = Vec::new();
    for request in &session.requests {
        counts.all += 1;
        match display_type(request) {
            "fetch" | "xhr" => counts.fetch += 1,
            "document" => counts.document += 1,
            "image" | "font" => counts.media += 1,
            _ => {}
        }
        if request.status.unwrap_or(0) >= 400 {
            counts.error += 1;
        }
        for name in TARGET_FILTERS {
            if matches_target(request, name) {
                *target_counts.entry(name).or_insert(0) += 1;
            }
        }
        if passes(request, filter, show_targets, &matches, restrict.as_ref()) {
            if matched >= offset && items.len() < limit {
                let count = warnings.get(request.id.as_str()).copied().unwrap_or(0);
                let target = target_of(request).map(|t| match targets.iter().position(|seen| seen == t) {
                    Some(index) => index,
                    None => {
                        targets.push(t.clone());
                        targets.len() - 1
                    }
                });
                items.push(summarize(request, count, target));
            }
            matched += 1;
        }
    }
    RequestPage { total: session.requests.len(), matched, offset, items, targets, counts, target_counts, has_targets }
}

/// Detalhe sob demanda: a requisição v1 completa, os avisos dela e as
/// `streamSessions` das tentativas (para a verificação de protocolo).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetail<'a> {
    pub request: &'a LogicalRequest,
    pub warnings: Vec<&'a Warning>,
    pub stream_sessions: Vec<&'a scrapelens_core::model::StreamSession>,
}

pub fn detail<'a>(session: &'a SessionV1, id: &str) -> Option<RequestDetail<'a>> {
    let request = session.requests.iter().find(|r| r.id == id)?;
    let attempts: HashSet<&str> = request.attempts.iter().map(|a| a.id.as_str()).collect();
    Some(RequestDetail {
        request,
        warnings: session.warnings.iter().filter(|w| w.entity.as_deref() == Some(id)).collect(),
        stream_sessions: session
            .stream_sessions
            .iter()
            .filter(|s| s.attempt_id.as_deref().map(|a| attempts.contains(a)).unwrap_or(false))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrapelens_core::model::SessionMeta;

    fn session(n: usize) -> SessionV1 {
        let meta: SessionMeta = serde_json::from_value(serde_json::json!({
            "id": "s1", "startedAt": "2026-01-01T00:00:00Z",
            "browser": {"name": "Chrome"},
            "completeness": {"state": "complete", "reasons": [], "counts": {}},
            "labels": []
        }))
        .unwrap();
        let mut s = SessionV1::new(meta);
        for i in 0..n {
            let mut r = LogicalRequest::new(format!("r{i}"), format!("https://h.test/p/{i}"), if i % 2 == 0 { "GET" } else { "POST" });
            r.status = Some(if i % 5 == 0 { 404 } else { 200 });
            r.resource_type = Some(if i % 3 == 0 { "Fetch".into() } else { "Document".into() });
            s.requests.push(r);
        }
        s
    }

    #[test]
    fn page_filters_and_counts_run_in_backend() {
        let s = session(100);
        let all = list_page(&s, 0, 10, &ListFilter::default());
        assert_eq!((all.total, all.matched, all.items.len()), (100, 100, 10));
        assert_eq!(all.counts.error, 20);
        assert_eq!(all.counts.fetch, 34);
        let page2 = list_page(&s, 10, 10, &ListFilter::default());
        assert_eq!(page2.items[0].id, "r10");

        let errors = list_page(&s, 0, 500, &ListFilter { type_filter: Some("error".into()), ..Default::default() });
        assert_eq!(errors.matched, 20);
        assert!(errors.items.iter().all(|i| i.status == Some(404)));

        let q = list_page(&s, 0, 500, &ListFilter { query: Some("/p/42".into()), ..Default::default() });
        assert_eq!(q.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["r42"]);

        let payload = list_page(
            &s,
            0,
            500,
            &ListFilter { query: Some("needle".into()), payload_search: true, match_ids: vec!["r7".into()], ..Default::default() },
        );
        assert_eq!(payload.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["r7"]);

        let restricted = list_page(&s, 0, 500, &ListFilter { restrict_ids: Some(vec!["r3".into(), "r4".into()]), ..Default::default() });
        assert_eq!(restricted.matched, 2);
    }

    #[test]
    fn summary_is_small_and_detail_is_on_demand() {
        let s = session(3);
        let page = list_page(&s, 0, 3, &ListFilter::default());
        for item in &page.items {
            let bytes = serde_json::to_vec(item).unwrap().len();
            assert!(bytes < 250, "resumo grande: {bytes} B");
        }
        let header = header_of(&s).unwrap();
        let text = serde_json::to_string(&header).unwrap();
        assert!(text.contains("\"requests\":[]") && text.contains("\"requestCount\":3"), "{text}");
        assert_eq!(detail(&s, "r1").unwrap().request.method, "POST");
        assert!(detail(&s, "nope").is_none());
    }
}
