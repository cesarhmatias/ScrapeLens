//! Correlação CDP×NetLog: único, ambíguo e explícito.

use scrapelens_core::correlate::{attach_netlog, CorrelationOptions, ExplicitPair};
use scrapelens_core::model::{
    HeaderRole, HeaderView, MatchState, OrderState, Provenance, Protocol, Source, Verification,
};
use scrapelens_core::parse::cdp::{build_cdp_session, CdpAttempt, CdpCapture, CdpRequest};
use scrapelens_core::parse::netlog::{
    NetlogAttempt, NetlogCapture, NetlogHeaderEvent, NetlogUrlRequest,
};

fn cdp_session(request_id: &str, url: &str, method: &str, timestamp: f64) -> scrapelens_core::model::SessionV1 {
    let request_provenance = Provenance::new(Source::Cdp, "test.cdp", Verification::Unverified);
    let mut request_headers = HeaderView::new(OrderState::Reconstructed);
    request_headers.add("accept", "*/*", &request_provenance);
    request_headers.add("x-cdp-only", "keep-me", &request_provenance);
    let mut response_headers = HeaderView::new(OrderState::Reconstructed);
    response_headers.add("content-type", "text/plain", &request_provenance);

    let mut attempt = CdpAttempt {
        url: url.to_string(),
        method: method.to_string(),
        protocol: Protocol::H1,
        status: Some(200),
        request_headers,
        response_headers,
        timestamp: Some(timestamp),
        ended_at: Some(timestamp + 0.05),
        ..Default::default()
    };
    attempt.cdp.request_id = Some(request_id.to_string());
    attempt.header_evidence.push(scrapelens_core::model::HeaderEvidence {
        id: "test-cdp-request".to_string(),
        role: HeaderRole::Request,
        protocol: Protocol::H1,
        event: "Network.requestWillBeSent.request.headers".to_string(),
        source_id: None,
        stream_id: None,
        view: attempt.request_headers.clone(),
    });
    let capture = CdpCapture {
        events_total: 1,
        events_used: 1,
        requests: vec![CdpRequest {
            request_id: request_id.to_string(),
            attempts: vec![attempt],
            ..Default::default()
        }],
        ..Default::default()
    };
    let (session, _) = build_cdp_session(&capture);
    session
}

fn netlog_header_event(
    name: &str,
    role: HeaderRole,
    time: f64,
) -> NetlogHeaderEvent {
    let provenance = Provenance::new(Source::NetLog, "test.netlog", Verification::Verified);
    let mut view = HeaderView::new(OrderState::SourceOrder);
    if role == HeaderRole::Request {
        view.add("host", "demo.invalid", &provenance);
        view.add("x-rep", "a", &provenance);
        view.add("x-rep", "b", &provenance);
    } else {
        view.add(":status", "200", &provenance);
        view.add("content-type", "text/plain", &provenance);
    }
    NetlogHeaderEvent {
        event_name: name.to_string(),
        event_index: 1,
        time: Some(time),
        source_id: Some(77),
        stream_id: None,
        dependency_id: None,
        protocol: Protocol::H1,
        role,
        view,
        nul_expanded: false,
    }
}

fn netlog_attempt(url: &str, method: &str, timestamp: f64) -> NetlogAttempt {
    NetlogAttempt {
        url: url.to_string(),
        method: method.to_string(),
        started_at: Some(timestamp),
        ended_at: Some(timestamp + 0.05),
        protocol: Protocol::H1,
        status: Some(200),
        outcome: scrapelens_core::model::AttemptOutcome::Completed,
        send_transaction: Some(netlog_header_event(
            "HTTP_TRANSACTION_SEND_REQUEST_HEADERS",
            HeaderRole::Request,
            timestamp,
        )),
        recv_transaction: Some(netlog_header_event(
            "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
            HeaderRole::Response,
            timestamp + 0.05,
        )),
        ..Default::default()
    }
}

fn netlog_capture(entries: &[(u32, f64)]) -> NetlogCapture {
    let url = "https://demo.invalid/x";
    NetlogCapture {
        requests: entries
            .iter()
            .map(|(source_id, timestamp)| NetlogUrlRequest {
                source_id: *source_id,
                url: url.to_string(),
                method: "GET".to_string(),
                started_at: Some(*timestamp),
                attempts: vec![netlog_attempt(url, "GET", *timestamp)],
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn unique_match_uses_netlog_as_primary_and_keeps_cdp_evidence() {
    let mut session = cdp_session("R1", "https://demo.invalid/x", "GET", 100.0);
    let netlog = netlog_capture(&[(31, 100.1)]);
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    assert_eq!(outcome.matched_attempts, 1);
    assert_eq!(outcome.ambiguous_attempts, 0);
    assert_eq!(outcome.unmatched_cdp_attempts, 0);
    let request = &session.requests[0];
    assert_eq!(request.match_state, MatchState::Matched);
    let attempt = &request.attempts[0];
    assert_eq!(attempt.match_state, MatchState::Matched);
    assert_eq!(
        attempt
            .request_headers
            .get_all("x-rep")
            .iter()
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert_eq!(attempt.request_headers.verification(), Verification::Verified);
    assert!(attempt
        .request_headers
        .get_all("x-cdp-only")
        .is_empty());
    // O original CDP continua acessível como evidência.
    assert!(attempt.header_evidence.iter().any(|evidence| {
        evidence.role == HeaderRole::Request
            && evidence.event.contains("requestWillBeSent")
            && evidence.view.first_value("x-cdp-only") == Some("keep-me")
    }));
    assert!(attempt
        .netlog
        .source_ids
        .contains(&31));
    assert_eq!(request.netlog.source_ids, vec![31]);
    assert_eq!(request.response_headers.verification(), Verification::Verified);
}

#[test]
fn two_candidates_are_ambiguous_and_none_is_chosen() {
    let mut session = cdp_session("R1", "https://demo.invalid/x", "GET", 100.0);
    let netlog = netlog_capture(&[(31, 100.1), (32, 100.2)]);
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    assert_eq!(outcome.ambiguous_attempts, 1);
    assert_eq!(outcome.matched_attempts, 0);
    assert!(outcome
        .warnings
        .iter()
        .any(|warning| warning.code == "correlate.ambiguous"));
    let attempt = &session.requests[0].attempts[0];
    assert_eq!(attempt.match_state, MatchState::Ambiguous);
    assert_eq!(attempt.match_candidates.len(), 2);
    let ids: Vec<&str> = attempt
        .match_candidates
        .iter()
        .map(|candidate| candidate.entity_id.as_str())
        .collect();
    assert!(ids.contains(&"netlog-r0001-a1"));
    assert!(ids.contains(&"netlog-r0002-a1"));
    // A visão primária permanece a do CDP: nada foi associado.
    assert_eq!(
        attempt.request_headers.first_value("x-cdp-only"),
        Some("keep-me")
    );
    assert!(attempt.netlog.source_ids.is_empty());
    assert!(session
        .warnings
        .iter()
        .any(|warning| warning.code == "correlate.ambiguous"));
    assert!(session.requests[0]
        .match_candidates
        .iter()
        .any(|candidate| candidate.entity_id == "netlog-r0002-a1"));
}

#[test]
fn explicit_pair_resolves_ambiguity() {
    let mut session = cdp_session("R1", "https://demo.invalid/x", "GET", 100.0);
    let netlog = netlog_capture(&[(31, 100.1), (32, 100.2)]);
    let options = CorrelationOptions {
        explicit_pairs: vec![ExplicitPair {
            cdp_request_id: "R1".to_string(),
            netlog_source_id: 32,
            note: Some("fixture".to_string()),
        }],
        ..Default::default()
    };
    let outcome = attach_netlog(&mut session, &netlog, &options);
    assert_eq!(outcome.matched_attempts, 1);
    assert_eq!(outcome.explicit_matches, 1);
    assert_eq!(outcome.ambiguous_attempts, 0);
    let attempt = &session.requests[0].attempts[0];
    assert_eq!(attempt.match_state, MatchState::Matched);
    assert_eq!(attempt.netlog.source_ids, vec![32]);
    assert!(attempt
        .match_candidates
        .iter()
        .any(|candidate| candidate.reasons.iter().any(|reason| reason.contains("explícita"))));
}

#[test]
fn method_mismatch_is_unmatched_with_warning() {
    let mut session = cdp_session("R1", "https://demo.invalid/x", "GET", 100.0);
    let mut netlog = netlog_capture(&[(31, 100.1)]);
    netlog.requests[0].method = "POST".to_string();
    netlog.requests[0].attempts[0].method = "POST".to_string();
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());
    assert_eq!(outcome.unmatched_cdp_attempts, 1);
    assert_eq!(session.requests[0].match_state, MatchState::Unmatched);
    assert!(outcome
        .warnings
        .iter()
        .any(|warning| warning.code == "correlate.unmatched"));
}

#[test]
fn netlog_only_attempts_are_counted_not_silently_ignored() {
    let mut session = cdp_session("R1", "https://demo.invalid/x", "GET", 100.0);
    let mut netlog = netlog_capture(&[(31, 100.1)]);
    netlog.requests.push(NetlogUrlRequest {
        source_id: 99,
        url: "https://background.invalid/ping".to_string(),
        method: "GET".to_string(),
        started_at: Some(900.0),
        attempts: vec![netlog_attempt("https://background.invalid/ping", "GET", 900.0)],
        ..Default::default()
    });
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());
    assert_eq!(outcome.matched_attempts, 1);
    assert_eq!(outcome.unmatched_netlog_attempts, 1);
    assert!(outcome
        .warnings
        .iter()
        .any(|warning| warning.code == "correlate.netlog_unmatched"));
    // Tráfego de background não é importado para a sessão CDP.
    assert_eq!(session.requests.len(), 1);
}
