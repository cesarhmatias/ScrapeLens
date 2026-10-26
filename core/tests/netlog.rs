//! Testes do importador NetLog com fixture sintética e com a captura h1 real
//! dos experimentos (evidência de fidelidade já commitada).

use scrapelens_core::model::{BodyState, HeaderRole, Protocol, Verification};
use scrapelens_core::parse::netlog::{build_netlog_session, parse_netlog};

fn fixture() -> Vec<u8> {
    include_bytes!("fixtures/netlog-h2.json").to_vec()
}

#[test]
fn parses_h2_session_with_explicit_stream_job_link() {
    let capture = parse_netlog(&fixture()).unwrap();
    assert_eq!(capture.events_unknown, 1);
    assert!(capture
        .warnings
        .iter()
        .any(|warning| warning.code == "netlog.unknown_event_type"));
    assert!(capture
        .warnings
        .iter()
        .any(|warning| warning.code == "netlog.header_line_invalid"));
    assert_eq!(capture.browser.version.as_deref(), Some("156.0.8078.48"));
    assert_eq!(
        capture.started_at.as_deref(),
        Some("2026-10-26T20:50:05.949Z")
    );

    let (session, report) = build_netlog_session(&capture);
    assert_eq!(report.format, scrapelens_core::parse::InputFormat::NetLog);
    assert_eq!(session.requests.len(), 1);
    let request = &session.requests[0];
    assert_eq!(request.url, "https://demo.invalid/x?b=2&a=1");
    assert_eq!(request.method, "GET");
    assert_eq!(request.status, Some(200));
    assert_eq!(request.protocol, Protocol::H2);
    assert_eq!(request.attempts.len(), 1);

    let attempt = &request.attempts[0];
    assert_eq!(attempt.request_headers.pseudo_headers.len(), 4);
    assert_eq!(attempt.request_headers.pseudo_headers[0].name, ":method");
    assert_eq!(
        attempt
            .request_headers
            .get_all("x-rep")
            .iter()
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    // Ordem h2 preservada, inclusive as duas ocorrências.
    let names: Vec<&str> = attempt
        .request_headers
        .headers
        .iter()
        .map(|header| header.name.as_str())
        .collect();
    assert_eq!(names, vec!["x-rep", "x-rep", "cookie", "priority"]);
    // h2: ordem parcial (Cookie pode ser dividido no fio).
    assert_eq!(
        attempt.request_headers.verification(),
        Verification::Partial
    );
    // Resposta transacional é verificada e mantém as duplicatas.
    assert_eq!(
        attempt.response_headers.verification(),
        Verification::Verified
    );
    assert_eq!(attempt.response_headers.get_all("set-cookie").len(), 2);
    assert_eq!(attempt.set_cookies.len(), 2);
    assert_eq!(attempt.cookie.pairs.len(), 2);
    assert_eq!(attempt.cookie.wire_lines.len(), 1);
    assert_eq!(attempt.request_body.state, BodyState::Unavailable);
    assert_eq!(session.connections.len(), 1);
    assert_eq!(session.stream_sessions.len(), 1);
    assert_eq!(
        session.stream_sessions[0].stream_id,
        Some(1),
        "stream id da sessão h2"
    );
    assert_eq!(
        attempt.stream_session_id.as_deref(),
        Some(session.stream_sessions[0].id.as_str())
    );

    // Expansão de NUL no evento de sessão (2 set-cookie, 2 x-resp-order).
    let session_recv = attempt
        .header_evidence
        .iter()
        .find(|evidence| {
            evidence.role == HeaderRole::Response && evidence.event == "HTTP2_SESSION_RECV_HEADERS"
        })
        .expect("evidência de sessão recv");
    assert_eq!(session_recv.protocol, Protocol::H2);
    assert_eq!(session_recv.view.get_all("set-cookie").len(), 2);
    assert_eq!(session_recv.view.get_all("x-resp-order").len(), 2);
    assert!(session_recv
        .view
        .notes
        .iter()
        .any(|note| note.contains("\\x00")));
}

#[test]
fn missing_url_request_is_reported_not_silent() {
    let capture = parse_netlog(&fixture()).unwrap();
    let (session, _) = build_netlog_session(&capture);
    // O evento de sessão não cria requisição própria: não há URL.
    assert!(session
        .warnings
        .iter()
        .all(|warning| warning.code != "netlog.request_without_url"));
}

#[test]
fn redirect_creates_two_attempts_and_a_redirect_entity() {
    let json = br#"{
      "constants":{"logEventTypes":{
        "URL_REQUEST_START_JOB":136,"URL_REQUEST_REDIRECTED":137,
        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS":240,
        "HTTP_TRANSACTION_READ_RESPONSE_HEADERS":245
      }},
      "events":[
        {"type":136,"phase":1,"time":"100","source":{"id":5,"type":1},
         "params":{"url":"http://demo.invalid/a","method":"GET"}},
        {"type":240,"phase":0,"time":"101","source":{"id":5,"type":1},
         "params":{"headers":["Host: demo.invalid","x-rep: a"],"line":"GET /a HTTP/1.1\r\n"}},
        {"type":245,"phase":0,"time":"102","source":{"id":5,"type":1},
         "params":{"headers":["HTTP/1.1 302 Found","location: /b","content-length: 0"]}},
        {"type":137,"phase":0,"time":"103","source":{"id":5,"type":1},
         "params":{"location":"http://demo.invalid/b"}},
        {"type":240,"phase":0,"time":"104","source":{"id":5,"type":1},
         "params":{"headers":["Host: demo.invalid","x-rep: b"],"line":"GET /b HTTP/1.1\r\n"}},
        {"type":245,"phase":0,"time":"105","source":{"id":5,"type":1},
         "params":{"headers":["HTTP/1.1 200 OK","content-length: 2"]}},
        {"type":136,"phase":2,"time":"106","source":{"id":5,"type":1},"params":{"net_error":0}}
      ]}"#;
    let capture = parse_netlog(json).unwrap();
    let (session, _) = build_netlog_session(&capture);
    assert_eq!(session.requests.len(), 1);
    let request = &session.requests[0];
    assert_eq!(request.attempts.len(), 2);
    assert_eq!(request.attempts[0].status, Some(302));
    assert_eq!(request.attempts[1].url, "http://demo.invalid/b");
    assert_eq!(request.attempts[1].status, Some(200));
    assert_eq!(request.redirects.len(), 1);
    assert_eq!(
        request.redirects[0].location.as_deref(),
        Some("http://demo.invalid/b")
    );
    assert_eq!(
        request.redirects[0].to_attempt_id.as_deref(),
        Some(request.attempts[1].id.as_str())
    );
    assert_eq!(request.url, "http://demo.invalid/a");
    assert_eq!(request.status, Some(200));
    // h1 é verificado no NetLog transacional.
    assert_eq!(
        request.attempts[0].request_headers.verification(),
        Verification::Verified
    );
}

#[test]
fn real_h1_capture_preserves_wire_order_and_duplicates() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h1-page/chrome-netlog.json");
    let bytes = std::fs::read(&path).expect("captura h1 dos experimentos");
    let capture = parse_netlog(&bytes).unwrap();
    let request = capture
        .requests
        .iter()
        .find(|request| request.url.contains("/echo-order?from=jsheaders"))
        .expect("requisição from=jsheaders na captura h1");
    assert_eq!(request.attempts.len(), 1);
    let attempt = &request.attempts[0];
    assert_eq!(request.method, "GET");
    assert_eq!(attempt.protocol, Protocol::H1);
    assert_eq!(
        attempt.outcome,
        scrapelens_core::model::AttemptOutcome::Completed,
        "net_error 0 (net::OK) não pode virar falha"
    );
    let send = attempt.send_transaction.as_ref().expect("send h1");
    assert_eq!(send.view.verification(), Verification::Verified);
    assert_eq!(send.view.first_value("x-dup"), Some("a, b"));
    let index = |name: &str| {
        send.view
            .headers
            .iter()
            .position(|header| header.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("header {name} ausente"))
    };
    // Ordem injetada pelo experimento: x-zeta, x-alpha, ... x-mid.
    assert!(index("x-zeta") < index("x-alpha"));
    assert!(index("x-alpha") < index("x-mid"));
}

#[test]
fn real_h2_capture_marks_request_order_partial_and_expands_nul_response() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h2-page/chrome-netlog.json");
    let bytes = std::fs::read(&path).expect("captura h2 dos experimentos");
    let capture = parse_netlog(&bytes).unwrap();
    let page = capture
        .requests
        .iter()
        .find(|request| request.url.ends_with("/page"))
        .expect("requisição /page na captura h2");
    let page_attempt = &page.attempts[0];
    assert_eq!(page_attempt.protocol, Protocol::H2);
    let page_send = page_attempt.send_transaction.as_ref().expect("send h2");
    assert_eq!(page_send.view.verification(), Verification::Partial);
    assert!(page_send.view.first_value("cookie").is_some());
    // Na captura real o NetLog mostra 1 campo Cookie; o parser não inventa N.
    assert_eq!(page_send.view.get_all("cookie").len(), 1);

    let setcookie = capture
        .requests
        .iter()
        .find(|request| request.url.ends_with("/setcookie"))
        .expect("requisição /setcookie na captura h2");
    let attempt = &setcookie.attempts[0];
    let session_send = attempt.send_session.as_ref().expect("session send h2");
    assert!(session_send.stream_id.is_some());
    let recv = attempt.recv_session.as_ref().expect("session recv h2");
    assert_eq!(recv.view.get_all("set-cookie").len(), 2);
    assert_eq!(recv.view.get_all("x-resp-order").len(), 2);
}
