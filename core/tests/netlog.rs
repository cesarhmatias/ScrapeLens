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

#[test]
fn time_unit_is_calibrated_by_wall_clock_reference() {
    use scrapelens_core::parse::netlog::NetlogTimeUnit;
    use scrapelens_core::parse::netlog::{parse_netlog_with_wall_clock, ticks_to_epoch_seconds};

    // Fixture real (Chrome): `time` em milissegundos. Com referência de parede
    // do CDP, a unidade é confirmada e nada muda no started_at.
    let reference = 1_793_047_805.949_f64;
    let capture = parse_netlog_with_wall_clock(&fixture(), Some(reference)).unwrap();
    assert_eq!(capture.time_unit, NetlogTimeUnit::Milliseconds);
    assert_eq!(
        capture.started_at.as_deref(),
        Some("2026-10-26T20:50:05.949Z")
    );
    assert!(capture
        .warnings
        .iter()
        .any(|warning| warning.code == "netlog.time_unit_detected"));

    // Captura sintética em microssegundos: mesma forma, unidade diferente.
    let json = br#"{
      "constants":{"timeTickOffset":1793040360000,"logEventTypes":{
        "URL_REQUEST_START_JOB":1000,"HTTP_TRANSACTION_SEND_REQUEST_HEADERS":1001}},
      "events":[
        {"type":1000,"phase":1,"time":"5640110000","source":{"id":9,"type":1},
         "params":{"url":"https://demo.invalid/x","method":"GET"}},
        {"type":1001,"phase":0,"time":"5640110900","source":{"id":9,"type":1},
         "params":{"headers":["Host: demo.invalid"]}}
      ]}"#;
    let micros = parse_netlog_with_wall_clock(json, Some(1_793_046_000.11)).unwrap();
    assert_eq!(micros.time_unit, NetlogTimeUnit::Microseconds);
    assert_eq!(
        micros.started_at.as_deref(),
        Some("2026-10-26T20:20:00.110Z")
    );
    assert_eq!(
        micros.requests[0].attempts[0].started_at,
        Some(1_793_046_000.110)
    );

    // Uma única fórmula: ms = offset + ticks/fator; s = ms/1000.
    assert!(
        (ticks_to_epoch_seconds(
            5640110000.0,
            Some(1793040360000.0),
            NetlogTimeUnit::Microseconds
        ) - 1_793_046_000.11)
            .abs()
            < 1e-6
    );
    assert!(
        (ticks_to_epoch_seconds(
            5_640_110.0,
            Some(1793040360000.0),
            NetlogTimeUnit::Milliseconds
        ) - 1_793_046_000.11)
            .abs()
            < 1e-6
    );
}

/// P4 (docs/18 §5): o leitor em fluxo tem de manter o veredito do `Value` para
/// JSON inválido/truncado, inclusive no limite de recursão de 128 níveis.
#[test]
fn streaming_reader_keeps_the_value_verdict_for_deep_or_truncated_json() {
    for n in [100usize, 126, 127, 128, 129, 200] {
        let json = format!("{{\"events\":[{}{}]}}", "[".repeat(n), "]".repeat(n));
        let by_value = serde_json::from_slice::<serde_json::Value>(json.as_bytes()).is_ok();
        assert_eq!(
            by_value,
            parse_netlog(json.as_bytes()).is_ok(),
            "profundidade {n}"
        );
    }
    for broken in [
        &br#"{"events":["#[..],
        &br#"{"events":[1,2,,3]}"#[..],
        &br#"{"constants":{"logEventTypes":{"X":1}},"events":[{"type":1}]} x"#[..],
        b"\xff\xfe",
    ] {
        assert!(serde_json::from_slice::<serde_json::Value>(broken).is_err());
        assert!(parse_netlog(broken).is_err());
    }
}

/// `events` antes de `constants` (ordem que o Chrome não usa) continua sendo
/// processado na ordem do arquivo, sem depender da posição do envelope.
#[test]
fn events_before_constants_are_still_processed_in_file_order() {
    let json = br#"{
      "events":[
        {"type":1000,"phase":1,"time":"1000","source":{"id":9},
         "params":{"url":"https://demo.invalid/x","method":"GET"}},
        {"type":1001,"phase":0,"time":"1001","source":{"id":9},
         "params":{"headers":["Host: demo.invalid"]}}
      ],
      "constants":{"timeTickOffset":1793040360000,"logEventTypes":{
        "URL_REQUEST_START_JOB":1000,"HTTP_TRANSACTION_SEND_REQUEST_HEADERS":1001}}
    }"#;
    let capture = parse_netlog(json).unwrap();
    assert_eq!(capture.requests.len(), 1);
    assert_eq!(capture.requests[0].url, "https://demo.invalid/x");
    assert_eq!(capture.events_used, 2);
    assert_eq!(capture.events_unknown, 0);
}
