//! Validação contra as capturas reais h2/h3 dos experimentos de fidelidade.
//! Somente leitura; nenhuma rede.

use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::model::{Protocol, Verification};
use scrapelens_core::parse::import_capture;

fn capture(protocol: &str) -> scrapelens_core::parse::ImportedSession {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results")
        .join(protocol);
    let cdp = std::fs::read(root.join("cdp-events.jsonl")).unwrap();
    let netlog = std::fs::read(root.join("chrome-netlog.json")).unwrap();
    import_capture(&cdp, &netlog, CorrelationOptions::default()).unwrap()
}

fn assert_capture(protocol: &str, expected: Protocol) {
    let imported = capture(protocol);
    let session = &imported.bundle.session;
    assert_eq!(session.requests.len(), 12);
    assert!(
        session
            .requests
            .iter()
            .all(|request| request.match_state == scrapelens_core::model::MatchState::Matched),
        "todas as 12 requisições devem casar sem ambiguidade"
    );
    assert_eq!(
        session.session.completeness.state,
        scrapelens_core::model::CompletenessState::Complete
    );
    assert!(!session.connections.is_empty());
    assert_eq!(
        session.stream_sessions.len(),
        12,
        "cada requisição {protocol} deve ter uma StreamSession"
    );

    let page = session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/page"))
        .expect("requisição /page");
    assert_eq!(page.protocol, expected);
    assert_eq!(
        page.request_headers.verification(),
        Verification::Partial,
        "ordem do request h2/h3 é parcial (Cookie pode estar fundido no log)"
    );
    assert_eq!(
        page.response_headers.verification(),
        Verification::Verified,
        "response transacional h2/h3 é verificado"
    );
    assert_eq!(page.cookie.pairs.len(), 3);
    assert_eq!(page.cookie.raw.len(), 1);
    // O NetLog mostra 1 campo Cookie; o parser não inventa a divisão do fio.
    assert_eq!(page.cookie.wire_lines.len(), 1);
    assert!(page.attempts[0].stream_session_id.is_some());

    let evidence: Vec<&str> = page.attempts[0]
        .header_evidence
        .iter()
        .map(|evidence| evidence.event.as_str())
        .collect();
    let session_event = if expected == Protocol::H2 {
        "HTTP2_SESSION_SEND_HEADERS"
    } else {
        "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS"
    };
    assert!(
        evidence.contains(&session_event),
        "evidência de sessão ausente: {evidence:?}"
    );
}

#[test]
fn h2_real_capture_matches_and_preserves_stream_evidence() {
    assert_capture("h2-page", Protocol::H2);
}

#[test]
fn h3_real_capture_matches_and_preserves_quic_stream_evidence() {
    assert_capture("h3-page", Protocol::H3);
}

#[test]
fn h3_response_session_evidence_expands_nul_duplicates() {
    let imported = capture("h3-page");
    let request = imported
        .bundle
        .session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/setcookie"))
        .expect("/setcookie");
    let evidence = request.attempts[0]
        .header_evidence
        .iter()
        .find(|evidence| evidence.event == "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS")
        .expect("evidência QUIC recv");
    assert_eq!(evidence.protocol, Protocol::H3);
    assert_eq!(evidence.view.get_all("set-cookie").len(), 2);
    assert_eq!(evidence.view.get_all("x-resp-order").len(), 2);
}

fn contract_h1() -> scrapelens_core::parse::ImportedSession {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../experiments/results/contract-h1");
    let cdp = std::fs::read(root.join("cdp-events.jsonl")).unwrap();
    let netlog = std::fs::read(root.join("chrome-netlog.json")).unwrap();
    import_capture(&cdp, &netlog, CorrelationOptions::default()).unwrap()
}

#[test]
fn contract_h1_redirect_chain_has_three_attempts_and_two_redirects() {
    let imported = contract_h1();
    let session = &imported.bundle.session;
    assert_eq!(session.requests.len(), 12);
    assert_eq!(
        session
            .requests
            .iter()
            .map(|request| request.attempts.len())
            .sum::<usize>(),
        14
    );
    let request = session
        .requests
        .iter()
        .find(|request| request.url.contains("/redirect?n=2"))
        .expect("chain de redirect");
    assert_eq!(request.attempts.len(), 3);
    assert_eq!(
        request
            .attempts
            .iter()
            .map(|attempt| attempt.status)
            .collect::<Vec<_>>(),
        vec![Some(302), Some(302), Some(200)]
    );
    assert_eq!(request.redirects.len(), 2);
    assert!(request
        .attempts
        .iter()
        .all(|attempt| attempt.match_state == scrapelens_core::model::MatchState::Matched));
    // A resposta final não pode herdar os headers 302 do redirect anterior.
    assert_eq!(
        request.attempts[2]
            .response_headers
            .first_value("content-length"),
        Some("19")
    );
    assert_eq!(
        request.attempts[2].response_headers.first_value("location"),
        None
    );
}

#[test]
fn identical_simultaneous_requests_remain_explicitly_ambiguous() {
    let imported = contract_h1();
    let ambiguous: Vec<_> = imported
        .bundle
        .session
        .requests
        .iter()
        .filter(|request| request.match_state == scrapelens_core::model::MatchState::Ambiguous)
        .collect();
    assert_eq!(ambiguous.len(), 2);
    for request in ambiguous {
        assert!(request.url.contains("concurrent=1"));
        for attempt in &request.attempts {
            assert_eq!(
                attempt.match_candidates.len(),
                2,
                "os dois candidatos idênticos devem ser expostos"
            );
            assert!(attempt.netlog.source_ids.is_empty());
        }
    }
}
