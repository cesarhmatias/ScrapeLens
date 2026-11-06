//! Not-sent requests: a URL_REQUEST cancelled before any bytes were written has no
//! protocol. It pairs with the CDP attempt only under the usual rules, and never
//! takes a request that has a response. Synthetic data only (`.invalid` hosts).

use scrapelens_core::correlate::{attach_netlog, CorrelationOptions};
use scrapelens_core::model::{
    AttemptOutcome, HeaderRole, HeaderView, MatchState, NetworkState, OrderState, Protocol,
    Provenance, Source, Verification,
};
use scrapelens_core::parse::cdp::{build_cdp_session, CdpAttempt, CdpCapture, CdpRequest};
use scrapelens_core::parse::netlog::{
    build_netlog_session, parse_netlog, NetlogAttempt, NetlogCapture, NetlogHeaderEvent,
    NetlogUrlRequest, NotSentEvidence,
};

fn fixture() -> Vec<u8> {
    include_bytes!("fixtures/netlog-not-sent.json").to_vec()
}

const URL: &str = "https://demo.invalid/x?k=1";

/// One CDP request; `status` is `None` for a cancelled request.
fn cdp_session(status: Option<u16>, timestamp: f64) -> scrapelens_core::model::SessionV1 {
    let attempt = CdpAttempt {
        url: URL.to_string(),
        method: "GET".to_string(),
        protocol: Protocol::Unknown,
        status,
        request_headers: HeaderView::new(OrderState::Reconstructed),
        response_headers: HeaderView::new(OrderState::Reconstructed),
        timestamp: Some(timestamp),
        ended_at: Some(timestamp + 0.0004),
        ..Default::default()
    };
    let capture = CdpCapture {
        events_total: 1,
        events_used: 1,
        requests: vec![CdpRequest {
            request_id: "cdp-req".to_string(),
            attempts: vec![attempt],
            ..Default::default()
        }],
        ..Default::default()
    };
    let (mut session, _) = build_cdp_session(&capture);
    if status.is_none() {
        // What the parser sets on `Network.loadingFailed` with `canceled: true`.
        session.requests[0].attempts[0].outcome = AttemptOutcome::Aborted;
    }
    session
}

fn not_sent_attempt(source_id: u32, timestamp: f64) -> NetlogAttempt {
    NetlogAttempt {
        url: URL.to_string(),
        method: "GET".to_string(),
        started_at: Some(timestamp),
        ended_at: Some(timestamp + 0.0004),
        protocol: Protocol::Unknown,
        outcome: AttemptOutcome::Aborted,
        not_sent: Some(NotSentEvidence {
            source_id,
            cancelled_at: Some(timestamp + 0.0004),
            net_error: None,
        }),
        ..Default::default()
    }
}

fn netlog_with(attempts: Vec<(u32, NetlogAttempt)>) -> NetlogCapture {
    NetlogCapture {
        requests: attempts
            .into_iter()
            .map(|(source_id, attempt)| NetlogUrlRequest {
                source_id,
                url: URL.to_string(),
                method: "GET".to_string(),
                started_at: attempt.started_at,
                attempts: vec![attempt],
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn sent_event(name: &str) -> NetlogHeaderEvent {
    let provenance = Provenance::new(Source::NetLog, "test.netlog", Verification::Verified);
    let mut view = HeaderView::new(OrderState::SourceOrder);
    view.add("host", "demo.invalid", &provenance);
    NetlogHeaderEvent {
        event_name: name.to_string(),
        event_index: 1,
        time: Some(1000.0),
        source_id: Some(77),
        protocol: Protocol::Unknown,
        role: HeaderRole::Request,
        view,
        ..Default::default()
    }
}

#[test]
fn parser_marks_a_cancelled_url_request_without_send_as_not_sent() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 77).unwrap();
    assert_eq!(request.attempts.len(), 1);
    let attempt = &request.attempts[0];
    let evidence = attempt.not_sent.as_ref().expect("not-sent evidence");
    assert_eq!(evidence.source_id, 77);
    assert!(evidence.cancelled_at.is_some());
    assert_eq!(attempt.protocol, Protocol::Unknown);
    assert_eq!(attempt.outcome, AttemptOutcome::Aborted);
    assert!(attempt.status.is_none());
    assert!(attempt.send_transaction.is_none());
    assert!(attempt.recv_transaction.is_none());
}

#[test]
fn parser_gives_no_attempt_when_headers_were_sent_before_cancel() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 78).unwrap();
    // The request wrote bytes, so it is never marked not-sent (nothing is synthesized).
    assert!(request.attempts.iter().all(|a| a.not_sent.is_none()));
}

#[test]
fn bytes_sent_is_transmission_evidence_without_headers() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 79).unwrap();
    assert!(
        request.attempts.iter().all(|attempt| attempt.not_sent.is_none()),
        "URL_REQUEST_BYTES_SENT with 123 bytes proves transmission"
    );
    let (session, _) = build_netlog_session(&capture);
    let request = session
        .requests
        .iter()
        .find(|request| request.url == "https://demo.invalid/bytes-sent")
        .expect("request built from the byte counters");
    assert!(
        request.attempts.is_empty(),
        "bytes sent: no not-sent attempt is synthesized"
    );
    assert_eq!(request.network_state, None);
}

#[test]
fn zero_byte_counter_is_not_transmission_evidence() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 80).unwrap();
    let attempt = request
        .attempts
        .iter()
        .find(|attempt| attempt.not_sent.is_some())
        .expect("a zero counter does not prove transmission");
    assert_eq!(attempt.not_sent.as_ref().unwrap().source_id, 80);
    let (session, _) = build_netlog_session(&capture);
    let request = session
        .requests
        .iter()
        .find(|request| request.url == "https://demo.invalid/zero-bytes")
        .expect("request built from the zero counter");
    assert_eq!(request.network_state, Some(NetworkState::NotSent));
}

#[test]
fn netlog_only_import_marks_the_not_sent_attempt_and_request() {
    let capture = parse_netlog(&fixture()).unwrap();
    let (session, _) = build_netlog_session(&capture);
    let request = session
        .requests
        .iter()
        .find(|r| r.url == "https://demo.invalid/cancelled?x=1")
        .expect("request built from the cancelled URL_REQUEST");
    assert_eq!(request.attempts.len(), 1);
    assert_eq!(request.attempts[0].network_state, Some(NetworkState::NotSent));
    assert_eq!(request.network_state, Some(NetworkState::NotSent));
    assert_eq!(request.attempts[0].protocol, Protocol::Unknown);
    assert!(request.attempts[0]
        .provenance
        .notes
        .iter()
        .any(|note| note.contains("not sent")));
}

#[test]
fn cancelled_cdp_request_pairs_with_its_not_sent_twin() {
    let mut session = cdp_session(None, 100.0);
    let connection_before = session.requests[0].attempts[0].connection_id.clone();
    let netlog = netlog_with(vec![(77, not_sent_attempt(77, 100.0))]);
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    let request = &session.requests[0];
    assert_eq!(request.match_state, MatchState::Matched);
    let attempt = &request.attempts[0];
    assert_eq!(attempt.match_state, MatchState::Matched);
    assert_eq!(attempt.network_state, Some(NetworkState::NotSent));
    assert_eq!(request.network_state, Some(NetworkState::NotSent));
    assert_eq!(attempt.protocol, Protocol::Unknown, "protocol never inferred");
    // NetLog adds no connection and no stream for a request that was never sent.
    assert_eq!(attempt.connection_id, connection_before);
    assert!(attempt.stream_session_id.is_none());
    assert_eq!(request.netlog.source_ids, vec![77]);
    assert_eq!(outcome.not_sent_attempts, 1);
    assert_eq!(outcome.unmatched_cdp_attempts, 0);
    assert!(session.warnings.iter().any(|w| w.code == "correlate.not_sent"));
    assert!(!session.warnings.iter().any(|w| w.code == "correlate.unmatched"));
}

#[test]
fn request_with_a_status_never_takes_a_not_sent_candidate() {
    let mut session = cdp_session(Some(200), 100.0);
    let netlog = netlog_with(vec![(77, not_sent_attempt(77, 100.0))]);
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    let attempt = &session.requests[0].attempts[0];
    assert_eq!(attempt.match_state, MatchState::Unmatched);
    assert!(attempt.network_state.is_none());
    assert!(session.requests[0].network_state.is_none());
    assert_eq!(outcome.not_sent_attempts, 0);
}

#[test]
fn twin_cancelled_candidates_stay_ambiguous_and_are_not_marked() {
    let mut session = cdp_session(None, 100.0);
    let netlog = netlog_with(vec![
        (77, not_sent_attempt(77, 100.0)),
        (78, not_sent_attempt(78, 100.0)),
    ]);
    attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    let attempt = &session.requests[0].attempts[0];
    assert_eq!(attempt.match_state, MatchState::Ambiguous);
    assert!(attempt.network_state.is_none());
    assert!(session.requests[0].network_state.is_none());
}

#[test]
fn sent_request_with_unknown_protocol_stays_unknown_and_not_marked() {
    let mut session = cdp_session(None, 100.0);
    // A real send (headers written), protocol unknown, cancelled afterwards.
    let mut attempt = not_sent_attempt(77, 100.0);
    attempt.not_sent = None;
    attempt.send_transaction = Some(sent_event("HTTP_TRANSACTION_SEND_REQUEST_HEADERS"));
    let netlog = netlog_with(vec![(77, attempt)]);
    let outcome = attach_netlog(&mut session, &netlog, &CorrelationOptions::default());

    let request = &session.requests[0];
    assert_eq!(request.attempts[0].match_state, MatchState::Matched);
    assert_eq!(request.attempts[0].protocol, Protocol::Unknown);
    assert!(request.attempts[0].network_state.is_none());
    assert!(request.network_state.is_none());
    assert_eq!(outcome.not_sent_attempts, 0);
}

#[test]
fn network_state_is_optional_and_absent_from_json_when_unset() {
    let session = cdp_session(Some(200), 100.0);
    let json = serde_json::to_value(&session.requests[0]).unwrap();
    assert!(json.get("networkState").is_none());
    assert!(json["attempts"][0].get("networkState").is_none());
}
