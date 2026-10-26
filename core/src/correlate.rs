//! Correlação CDP×NetLog.
//!
//! IDs das duas fontes **não são equivalentes**. A associação usa:
//! 1. par explícito fornecido pela captura (`ExplicitPair`), quando existe;
//! 2. URL + método + janela de tempo como pista.
//!
//! Quando há mais de um candidato dentro do limite, a tentativa recebe
//! `match: "ambiguous"` com a lista de candidatos. Nenhum é escolhido em
//! silêncio. Quando o NetLog comprova a sequência e o CDP não, a visão primária
//! passa a ser do NetLog, mantendo o bloco CDP original em `headerEvidence`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::{
    Attempt, AttemptOutcome, HeaderEvidence, HeaderRole, MatchCandidate, MatchState, Protocol,
    SessionV1, StreamSession, Verification, Warning,
};
use crate::parse::netlog::{NetlogAttempt, NetlogCapture, NetlogHeaderEvent, NetlogUrlRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplicitPair {
    pub cdp_request_id: String,
    pub netlog_source_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CorrelationOptions {
    pub time_window_s: f64,
    pub min_score: u8,
    /// Quando o NetLog tem bloco verificado e o CDP não, use o NetLog como
    /// visão primária (o original CDP permanece em `headerEvidence`).
    pub prefer_netlog_headers: bool,
    pub explicit_pairs: Vec<ExplicitPair>,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            time_window_s: 5.0,
            min_score: 55,
            prefer_netlog_headers: true,
            explicit_pairs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationOutcome {
    pub matched_attempts: usize,
    pub ambiguous_attempts: usize,
    pub unmatched_cdp_attempts: usize,
    pub unmatched_netlog_attempts: usize,
    pub explicit_matches: usize,
    #[serde(default)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone)]
struct Candidate<'a> {
    request: &'a NetlogUrlRequest,
    attempt: &'a NetlogAttempt,
    id: String,
    score: u8,
    reasons: Vec<String>,
    explicit: bool,
    time_delta: Option<f64>,
}

impl Candidate<'_> {
    fn match_candidate(&self) -> MatchCandidate {
        MatchCandidate::new(self.id.clone(), self.score, self.reasons.clone())
    }
}

pub fn attach_netlog(
    session: &mut SessionV1,
    netlog: &NetlogCapture,
    options: &CorrelationOptions,
) -> CorrelationOutcome {
    let mut outcome = CorrelationOutcome::default();
    let mut new_streams: Vec<StreamSession> = Vec::new();
    let mut deferred_warnings: Vec<Warning> = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let total_netlog_attempts: usize = netlog
        .requests
        .iter()
        .map(|request| request.attempts.len())
        .sum();

    for request in &mut session.requests {
        let cdp_request_id = request.cdp.as_ref().and_then(|cdp| cdp.request_id.clone());
        let mut request_has_ambiguous = false;
        let mut request_all_matched = !request.attempts.is_empty();

        for attempt in &mut request.attempts {
            let candidates =
                find_candidates(attempt, cdp_request_id.as_deref(), netlog, options, &used);

            match candidates.len() {
                0 => {
                    attempt.match_state = MatchState::Unmatched;
                    request_all_matched = false;
                    outcome.unmatched_cdp_attempts += 1;
                }
                1 => {
                    let candidate = &candidates[0];
                    if candidate.explicit {
                        outcome.explicit_matches += 1;
                    }
                    new_streams.extend(attach_candidate(attempt, candidate, options));
                    push_unique(&mut request.netlog.source_ids, candidate.request.source_id);
                    used.insert(candidate.id.clone());
                    outcome.matched_attempts += 1;
                }
                _ => {
                    request_has_ambiguous = true;
                    request_all_matched = false;
                    attempt.match_state = MatchState::Ambiguous;
                    attempt.match_candidates =
                        candidates.iter().map(Candidate::match_candidate).collect();
                    outcome.ambiguous_attempts += 1;
                    let ids: Vec<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
                    let warning = Warning::new(
                        "correlate.ambiguous",
                        format!(
                            "tentativa {} tem {} candidatos no NetLog; nenhum associado",
                            attempt.id,
                            candidates.len()
                        ),
                    )
                    .with_entity(attempt.id.clone())
                    .with_detail(serde_json::json!({
                        "candidates": candidates.iter().map(|candidate| serde_json::json!({
                            "entityId": candidate.id,
                            "score": candidate.score,
                            "reasons": candidate.reasons,
                        })).collect::<Vec<_>>(),
                        "candidateIds": ids,
                    }));
                    deferred_warnings.push(warning.clone());
                    outcome.warnings.push(warning);
                }
            }
        }

        request.match_state = if request_has_ambiguous {
            MatchState::Ambiguous
        } else if request_all_matched {
            MatchState::Matched
        } else {
            MatchState::Unmatched
        };
        if request.match_state == MatchState::Ambiguous {
            request.match_candidates = request
                .attempts
                .iter()
                .filter(|attempt| attempt.match_state == MatchState::Ambiguous)
                .flat_map(|attempt| attempt.match_candidates.clone())
                .collect();
        }
        // Reflete o resultado na visão primária (sem tocar nos originais).
        if request.match_state == MatchState::Matched {
            request.refresh_primary_from_attempt();
        }
    }

    session.stream_sessions.extend(new_streams);
    session.warnings.extend(deferred_warnings);
    outcome.unmatched_netlog_attempts = total_netlog_attempts.saturating_sub(used.len());
    if outcome.unmatched_netlog_attempts > 0 {
        let warning = Warning::info(
            "correlate.netlog_unmatched",
            format!(
                "{} tentativa(s) do NetLog (tráfego de background ou sem par CDP) não foram associadas",
                outcome.unmatched_netlog_attempts
            ),
        );
        session.warnings.push(warning.clone());
        outcome.warnings.push(warning);
    }
    if outcome.unmatched_cdp_attempts > 0 {
        let warning = Warning::new(
            "correlate.unmatched",
            format!(
                "{} tentativa(s) CDP sem correspondência no NetLog dentro da janela de {:.1}s",
                outcome.unmatched_cdp_attempts, options.time_window_s
            ),
        );
        session.warnings.push(warning.clone());
        outcome.warnings.push(warning);
    }
    // Ambiguidade é um estado explícito de `match`, não uma falha de captura:
    // não rebaixa `completeness` (que mede o flush/artefatos da sessão).
    session.recompute_completeness();
    outcome
}

fn find_candidates<'a>(
    attempt: &Attempt,
    cdp_request_id: Option<&str>,
    netlog: &'a NetlogCapture,
    options: &CorrelationOptions,
    used: &BTreeSet<String>,
) -> Vec<Candidate<'a>> {
    let explicit_source = cdp_request_id.and_then(|request_id| {
        options
            .explicit_pairs
            .iter()
            .find(|pair| pair.cdp_request_id == request_id)
            .map(|pair| pair.netlog_source_id)
    });

    let mut candidates = Vec::new();
    for (request_index, request) in netlog.requests.iter().enumerate() {
        for (attempt_index, netlog_attempt) in request.attempts.iter().enumerate() {
            let id = format!("netlog-r{:04}-a{}", request_index + 1, attempt_index + 1);
            if used.contains(&id) {
                continue;
            }
            let is_explicit = explicit_source
                .map(|source_id| source_id == request.source_id)
                .unwrap_or(false);
            if let Some((mut score, mut reasons)) =
                score_candidate(attempt, request, netlog_attempt, options)
            {
                if is_explicit {
                    score = 100;
                    reasons.push("chave explícita CDP→NetLog fornecida pela captura".to_string());
                }
                if score < options.min_score && !is_explicit {
                    continue;
                }
                candidates.push(Candidate {
                    request,
                    attempt: netlog_attempt,
                    id,
                    score,
                    reasons,
                    explicit: is_explicit,
                    time_delta: match (attempt.started_at, netlog_attempt.started_at) {
                        (Some(left), Some(right)) => Some((left - right).abs()),
                        _ => None,
                    },
                });
            } else if is_explicit {
                // Par explícito vence a heurística, mas ainda exige método e URL
                // compatíveis; se não houver, reporta em vez de inventar.
                candidates.push(Candidate {
                    request,
                    attempt: netlog_attempt,
                    id,
                    score: 100,
                    reasons: vec!["chave explícita CDP→NetLog".to_string()],
                    explicit: true,
                    time_delta: match (attempt.started_at, netlog_attempt.started_at) {
                        (Some(left), Some(right)) => Some((left - right).abs()),
                        _ => None,
                    },
                });
            }
        }
    }
    // Chave explícita vence a heurística: descarta candidatos não explícitos
    // quando existe pelo menos um par fornecido pela captura.
    if candidates.iter().any(|candidate| candidate.explicit) {
        candidates.retain(|candidate| candidate.explicit);
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.score));
    // Um candidato claramente mais próximo no tempo elimina os que estão
    // segundos depois, mas empates simultâneos continuam ambíguos.
    if let Some(best_delta) = candidates
        .first()
        .and_then(|candidate| candidate.time_delta)
    {
        candidates.retain(|candidate| {
            candidate.explicit
                || candidate
                    .time_delta
                    .map(|delta| delta <= best_delta + 1.0)
                    .unwrap_or(true)
        });
    }
    candidates
}

fn score_candidate(
    cdp: &Attempt,
    netlog_request: &NetlogUrlRequest,
    netlog_attempt: &NetlogAttempt,
    options: &CorrelationOptions,
) -> Option<(u8, Vec<String>)> {
    if !cdp.method.eq_ignore_ascii_case(&netlog_attempt.method) {
        return None;
    }
    let cdp_url = canonical_url(&cdp.url);
    let netlog_url = canonical_url(&netlog_attempt.url);
    let exact_url = cdp.url == netlog_attempt.url;
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    if exact_url {
        score += 40;
        reasons.push("URL exata".to_string());
    } else if cdp_url == netlog_url {
        score += 30;
        reasons.push("URL normalizada igual".to_string());
    } else {
        return None;
    }
    score += 15;
    reasons.push("método igual".to_string());

    match (cdp.started_at, netlog_attempt.started_at) {
        (Some(cdp_time), Some(netlog_time)) => {
            let delta = (cdp_time - netlog_time).abs();
            if delta <= 0.5 {
                score += 25;
                reasons.push(format!("tempo Δ={delta:.3}s"));
            } else if delta <= 2.0 {
                score += 15;
                reasons.push(format!("tempo Δ={delta:.3}s"));
            } else if delta <= options.time_window_s {
                score += 8;
                reasons.push(format!("tempo Δ={delta:.3}s (janela)"));
            } else {
                return None;
            }
        }
        _ => {
            score += 3;
            reasons.push("sem timestamp em uma das fontes".to_string());
        }
    }

    // Status e Content-Length distinguem requisições idênticas simultâneas.
    match (cdp.status, netlog_attempt.status) {
        (Some(cdp_status), Some(netlog_status)) if cdp_status == netlog_status => {
            score += 10;
            reasons.push("status igual".to_string());
        }
        (Some(_), Some(_)) => return None,
        _ => {}
    }
    let cdp_length = cdp.response_headers.first_value("content-length");
    let netlog_response = primary_response_view(netlog_attempt);
    let netlog_length = netlog_response.and_then(|view| view.first_value("content-length"));
    match (cdp_length, netlog_length) {
        (Some(left), Some(right)) if left.trim() == right.trim() => {
            score += 8;
            reasons.push("content-length igual".to_string());
        }
        (Some(_), Some(_)) => return None,
        _ => {}
    }

    let cdp_set_cookie = cdp.response_headers.contains("set-cookie");
    let netlog_set_cookie = netlog_response
        .map(|view| view.contains("set-cookie"))
        .unwrap_or(false);
    if cdp_set_cookie == netlog_set_cookie {
        score += 4;
        if cdp_set_cookie {
            reasons.push("presença de set-cookie igual".to_string());
        }
    }

    // Conjunto de headers do ExtraInfo (completo, sem ordem) contra o bloco do
    // NetLog. Só compara quando o CDP tem Host, para não penalizar o
    // subconjunto do Blink.
    if cdp.request_headers.contains("host") {
        if let Some(netlog_request_view) = primary_request_view(netlog_attempt) {
            match header_set_overlap(&cdp.request_headers, netlog_request_view) {
                Some(ratio) if ratio >= 0.9 => {
                    score += 10;
                    reasons.push(format!("headers coincidem ({ratio:.0}%)"));
                }
                Some(ratio) if ratio < 0.5 => {
                    score = score.saturating_sub(10);
                    reasons.push(format!("headers divergem ({ratio:.0}%)"));
                }
                Some(ratio) => {
                    reasons.push(format!("headers parcialmente coincidentes ({ratio:.0}%)"));
                }
                None => {}
            }
        }
    }

    let netlog_cookie = netlog_attempt_cookie(netlog_attempt);
    match (cdp.cookie.raw.first(), netlog_cookie.first()) {
        (Some(cdp_cookie), Some(netlog_cookie)) if cdp_cookie == netlog_cookie => {
            score += 4;
            reasons.push("Cookie igual".to_string());
        }
        (Some(_), Some(_)) => {
            score = score.saturating_sub(6);
            reasons.push("Cookie divergente".to_string());
        }
        _ => {}
    }

    if netlog_request.url == cdp.url {
        score += 1;
    }
    Some((score.min(100) as u8, reasons))
}

fn netlog_attempt_cookie(attempt: &NetlogAttempt) -> Vec<String> {
    primary_request_view(attempt)
        .map(|view| view.cookie_field_values())
        .unwrap_or_default()
}

/// Proporção de pares (nome, valor) do CDP presentes no bloco do NetLog.
fn header_set_overlap(
    cdp: &crate::model::HeaderView,
    netlog: &crate::model::HeaderView,
) -> Option<f64> {
    let cdp_pairs: BTreeSet<(String, String)> = cdp
        .iter_all()
        .map(|entry| (entry.name.to_ascii_lowercase(), entry.value.clone()))
        .collect();
    if cdp_pairs.len() < 4 {
        return None;
    }
    let netlog_pairs: BTreeSet<(String, String)> = netlog
        .iter_all()
        .map(|entry| (entry.name.to_ascii_lowercase(), entry.value.clone()))
        .collect();
    let matched = cdp_pairs.intersection(&netlog_pairs).count();
    Some((matched as f64 / cdp_pairs.len() as f64) * 100.0)
}

fn attach_candidate(
    attempt: &mut Attempt,
    candidate: &Candidate<'_>,
    options: &CorrelationOptions,
) -> Vec<StreamSession> {
    let mut created_streams = Vec::new();
    attempt.match_state = MatchState::Matched;
    attempt.match_candidates = vec![candidate.match_candidate()];
    push_unique(&mut attempt.netlog.source_ids, candidate.request.source_id);

    let netlog_request = candidate.request;
    let netlog_attempt = candidate.attempt;

    for (role, event) in [
        (
            HeaderRole::Request,
            netlog_attempt.send_transaction.as_ref(),
        ),
        (HeaderRole::Request, netlog_attempt.send_session.as_ref()),
        (
            HeaderRole::Response,
            netlog_attempt.recv_transaction.as_ref(),
        ),
        (HeaderRole::Response, netlog_attempt.recv_session.as_ref()),
    ] {
        if let Some(event) = event {
            if let Some(stream_id) = event.stream_id {
                push_unique(&mut attempt.netlog.stream_ids, stream_id);
            }
            let evidence_id = format!("corr-{}-{}", attempt.id, attempt.header_evidence.len() + 1);
            let evidence_protocol = if event.protocol == Protocol::H1
                && event.event_name == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"
                && attempt.protocol != Protocol::Unknown
            {
                attempt.protocol
            } else {
                event.protocol
            };
            attempt.header_evidence.push(HeaderEvidence {
                id: evidence_id,
                role,
                protocol: evidence_protocol,
                event: event.event_name.clone(),
                source_id: event.source_id,
                stream_id: event.stream_id,
                view: event.view.clone(),
            });
        }
    }

    let netlog_request_view = primary_request_view(netlog_attempt);
    let netlog_response_view = primary_response_view(netlog_attempt);

    if options.prefer_netlog_headers {
        if let Some(view) = netlog_request_view {
            if view.verification() >= attempt.request_headers.verification() && !view.is_empty() {
                attempt.request_headers = view.clone();
                attempt.cookie = cookie_from_netlog(netlog_attempt, view);
            }
        }
        if let Some(view) = netlog_response_view {
            if view.verification() >= attempt.response_headers.verification() && !view.is_empty() {
                attempt.response_headers = view.clone();
                attempt.set_cookies.clear();
                for header in view.get_all("set-cookie") {
                    attempt
                        .set_cookies
                        .push(crate::model::SetCookieRecord::from_raw(
                            &header.value,
                            &header.provenance,
                        ));
                }
            }
        }
    }

    if attempt.protocol == Protocol::Unknown {
        attempt.protocol = netlog_attempt.protocol;
    }
    if attempt.status.is_none() {
        attempt.status = netlog_attempt.status;
    }
    if attempt.outcome == AttemptOutcome::Unknown {
        attempt.outcome = netlog_attempt.outcome;
    }
    if attempt.failure.is_none() {
        attempt.failure = netlog_attempt
            .net_error
            .map(|error| format!("net_error {error}"));
    }
    if attempt.started_at.is_none() {
        attempt.started_at = netlog_attempt.started_at;
    }
    if attempt.ended_at.is_none() {
        attempt.ended_at = netlog_attempt.ended_at;
    }
    if let (Some(start), Some(end)) = (attempt.started_at, attempt.ended_at) {
        attempt.timings.request_time = Some(start);
        attempt.timings.total_ms = Some((end - start).max(0.0) * 1000.0);
        attempt.timings.estimated = true;
    }

    // StreamSession para eventos h2/h3 associados explicitamente.
    if let Some(event) = netlog_attempt
        .send_session
        .as_ref()
        .or(netlog_attempt.recv_session.as_ref())
    {
        if let Some(stream_id) = event.stream_id {
            let stream_id_str = format!("corr-{}-s{}", attempt.id, stream_id);
            created_streams.push(StreamSession {
                id: stream_id_str.clone(),
                connection_id: attempt.connection_id.clone(),
                protocol: attempt.protocol,
                stream_id: Some(stream_id),
                attempt_id: Some(attempt.id.clone()),
                netlog_session_id: event.source_id,
                provenance: crate::model::Provenance::new(
                    crate::model::Source::NetLog,
                    "netlog.session.headers",
                    event.view.verification(),
                ),
            });
            attempt.stream_session_id = Some(stream_id_str);
        }
    }
    let _ = netlog_request;
    created_streams
}

fn primary_request_view(attempt: &NetlogAttempt) -> Option<&crate::model::HeaderView> {
    attempt
        .send_transaction
        .as_ref()
        .or(attempt.send_session.as_ref())
        .map(|event| &event.view)
}

fn primary_response_view(attempt: &NetlogAttempt) -> Option<&crate::model::HeaderView> {
    attempt
        .recv_transaction
        .as_ref()
        .or(attempt.recv_session.as_ref())
        .map(|event| &event.view)
}

fn cookie_from_netlog(
    attempt: &NetlogAttempt,
    view: &crate::model::HeaderView,
) -> crate::model::CookieField {
    let provenance = view
        .first("cookie")
        .map(|entry| entry.provenance.clone())
        .unwrap_or_default();
    let mut cookie =
        crate::model::CookieField::from_header_values(&view.cookie_field_values(), &provenance);
    if let Some(session_view) = attempt.send_session.as_ref().map(|event| &event.view) {
        let wire = session_view.cookie_field_values();
        if !wire.is_empty() {
            cookie.wire_lines = wire;
            cookie.notes.push(
                "linhas do fio do evento de sessão; NetLog pode mostrar Cookie fundido".to_string(),
            );
        }
    }
    cookie
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Normalização usada apenas para casar URL; não altera o original.
pub fn canonical_url(url: &str) -> String {
    crate::normalize::canonical_url(url)
}

/// Garante que a evidência NetLog inclui o bloco de sessão mesmo quando o
/// chamador só quer inspecionar (usado nos testes).
pub fn netlog_header_event<'a>(
    attempt: &'a NetlogAttempt,
    role: HeaderRole,
    session: bool,
) -> Option<&'a NetlogHeaderEvent> {
    match (role, session) {
        (HeaderRole::Request, false) => attempt.send_transaction.as_ref(),
        (HeaderRole::Request, true) => attempt.send_session.as_ref(),
        (HeaderRole::Response, false) => attempt.recv_transaction.as_ref(),
        (HeaderRole::Response, true) => attempt.recv_session.as_ref(),
    }
}

/// Usado por importadores para decidir se o bloco do NetLog é mais forte.
pub fn should_prefer_netlog(current: Verification, candidate: Verification) -> bool {
    candidate > current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_removes_default_port_and_fragment() {
        assert_eq!(
            canonical_url("HTTPS://Demo.Invalid:443/a?b=2#x"),
            "https://demo.invalid/a?b=2"
        );
        assert_eq!(canonical_url("http://a.test:8080/"), "http://a.test:8080");
    }

    #[test]
    fn score_requires_method_and_url() {
        let mut cdp = Attempt::new("a", "r", 0, "https://a.test/x", "GET");
        cdp.started_at = Some(10.0);
        let request = NetlogUrlRequest {
            source_id: 7,
            url: "https://a.test/x".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };
        let mut netlog = NetlogAttempt {
            url: "https://a.test/x".to_string(),
            method: "GET".to_string(),
            started_at: Some(10.1),
            status: Some(200),
            ..Default::default()
        };
        cdp.status = Some(200);
        let options = CorrelationOptions::default();
        let (score, reasons) = score_candidate(&cdp, &request, &netlog, &options).unwrap();
        assert!(score >= 90, "{score} {reasons:?}");
        netlog.method = "POST".to_string();
        assert!(score_candidate(&cdp, &request, &netlog, &options).is_none());
        netlog.method = "GET".to_string();
        netlog.url = "https://a.test/other".to_string();
        assert!(score_candidate(&cdp, &request, &netlog, &options).is_none());
    }
}
