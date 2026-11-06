//! Proxied captures: the NetLog shape of HTTP, HTTPS (CONNECT) and SOCKS5 traffic,
//! the proxy record, the sanitized export and the remote endpoints. Synthetic data
//! only (`.invalid` hosts, no real proxy, no credentials).

use std::collections::BTreeMap;

use scrapelens_core::correlate::{attach_netlog, CorrelationOptions};
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::model::{
    apply_proxy_facts, AttemptOutcome, CaptureMeta, Connection, HeaderView, MatchState,
    NetworkState, OrderState, Protocol, ProxyRecord, ProxyRoute, Provenance, Source,
    Verification, PROXY_CONNECTION_NOTE, PROXY_NO_HTTP3_NOTE,
};
use scrapelens_core::parse::cdp::{build_cdp_session, CdpAttempt, CdpCapture, CdpRequest};
use scrapelens_core::parse::netlog::parse_netlog;

fn fixture() -> Vec<u8> {
    include_bytes!("fixtures/netlog-proxy.json").to_vec()
}

fn proxy(route: ProxyRoute, authenticated: bool) -> ProxyRecord {
    ProxyRecord {
        scheme: "http".to_string(),
        host: Some("proxy.invalid".to_string()),
        port: Some(8080),
        authenticated,
        route: Some(route),
    }
}

fn with_proxy(session: &mut scrapelens_core::model::SessionV1, record: ProxyRecord) {
    session.session.capture = Some(CaptureMeta {
        mode: Some("cdp+netlog".to_string()),
        proxy: Some(record),
        ..Default::default()
    });
}

/// One CDP request per URL; `cancelled` marks a request that never got a response.
fn cdp_for(urls: &[(&str, &str, bool)]) -> scrapelens_core::model::SessionV1 {
    let requests = urls
        .iter()
        .enumerate()
        .map(|(index, (url, _label, cancelled))| {
            let attempt = CdpAttempt {
                url: url.to_string(),
                method: "GET".to_string(),
                protocol: Protocol::Unknown,
                status: if *cancelled { None } else { Some(200) },
                request_headers: HeaderView::new(OrderState::Reconstructed),
                response_headers: HeaderView::new(OrderState::Reconstructed),
                timestamp: Some(5640480.0 + index as f64),
                ended_at: Some(5640480.0 + index as f64 + 0.001),
                ..Default::default()
            };
            CdpRequest {
                request_id: format!("cdp-{index}"),
                attempts: vec![attempt],
                ..Default::default()
            }
        })
        .collect();
    let capture = CdpCapture {
        events_total: urls.len(),
        events_used: urls.len(),
        requests,
        ..Default::default()
    };
    let (mut session, _) = build_cdp_session(&capture);
    for (index, (_, _, cancelled)) in urls.iter().enumerate() {
        if *cancelled {
            session.requests[index].attempts[0].outcome = AttemptOutcome::Aborted;
        }
    }
    session
}

fn find<'a>(
    session: &'a scrapelens_core::model::SessionV1,
    url: &str,
) -> &'a scrapelens_core::model::LogicalRequest {
    session
        .requests
        .iter()
        .find(|request| request.url == url)
        .unwrap_or_else(|| panic!("no request for {url}"))
}

#[test]
fn plain_http_through_a_proxy_keeps_its_absolute_uri_and_h1() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture
        .requests
        .iter()
        .find(|r| r.source_id == 301)
        .unwrap();
    let attempt = &request.attempts[0];
    assert_eq!(request.url, "http://demo.invalid/a");
    assert_eq!(attempt.protocol, Protocol::H1);
    assert_eq!(attempt.method, "GET");
    assert_eq!(attempt.status, Some(200));
    assert!(attempt.not_sent.is_none());
    let line = attempt
        .send_transaction
        .as_ref()
        .and_then(|event| event.view.start_line.clone());
    assert_eq!(line.as_deref(), Some("GET http://demo.invalid/a HTTP/1.1"));
}

#[test]
fn https_through_connect_tunnel_is_the_inner_request_not_the_tunnel() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture
        .requests
        .iter()
        .find(|r| r.source_id == 302)
        .unwrap();
    assert_eq!(request.attempts.len(), 1, "tunnel events add no attempt");
    let attempt = &request.attempts[0];
    assert_eq!(attempt.method, "GET", "CONNECT is never the method of the request");
    assert_eq!(attempt.protocol, Protocol::H1, "protocol is the inner request's");
    assert_eq!(attempt.status, Some(200));
    assert!(attempt.not_sent.is_none());
    // The tunnel's CONNECT line is not a header of the request.
    let line = attempt
        .send_transaction
        .as_ref()
        .and_then(|event| event.view.start_line.clone());
    assert_eq!(line.as_deref(), Some("GET /b HTTP/1.1"));
}

#[test]
fn https_through_connect_with_h2_inside_reports_h2_from_the_inner_request() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 303).unwrap();
    assert_eq!(request.attempts[0].protocol, Protocol::H2);
    assert_eq!(request.attempts[0].method, "GET");
}

#[test]
fn socks5_request_is_origin_form_and_keeps_h1() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 304).unwrap();
    assert_eq!(request.attempts[0].protocol, Protocol::H1);
    assert_eq!(request.attempts[0].status, Some(200));
    let line = request.attempts[0]
        .send_transaction
        .as_ref()
        .and_then(|event| event.view.start_line.clone());
    assert_eq!(line.as_deref(), Some("GET /d HTTP/1.1"));
}

#[test]
fn refused_tunnel_is_not_sent_and_has_no_protocol() {
    let capture = parse_netlog(&fixture()).unwrap();
    let request = capture.requests.iter().find(|r| r.source_id == 305).unwrap();
    let attempt = &request.attempts[0];
    let evidence = attempt.not_sent.as_ref().expect("not-sent evidence");
    assert_eq!(evidence.net_error, Some(-111));
    assert_eq!(attempt.protocol, Protocol::Unknown);
    assert!(attempt.status.is_none());
    assert_eq!(attempt.outcome, AttemptOutcome::Failed);
}

#[test]
fn tunnel_events_never_create_requests_and_networkstate_follows_the_application_request() {
    let (session, _) = scrapelens_core::parse::netlog::build_netlog_session(
        &parse_netlog(&fixture()).unwrap(),
    );
    assert_eq!(session.requests.len(), 5, "one request per URL_REQUEST");
    assert!(session.requests.iter().all(|r| r.method != "CONNECT"));
    // 302 and 303 sent their request inside the tunnel: never not-sent.
    for url in ["https://demo.invalid/b", "https://demo.invalid/c"] {
        assert!(find(&session, url).network_state.is_none(), "{url}");
    }
    // 305 never reached the site: not-sent, even though a CONNECT was sent to the proxy.
    assert_eq!(
        find(&session, "https://demo.invalid/e").network_state,
        Some(NetworkState::NotSent)
    );
}

#[test]
fn connect_headers_on_a_socket_source_are_tunnel_not_a_request_without_url() {
    let capture = parse_netlog(&fixture()).unwrap();
    assert_eq!(capture.requests.len(), 5, "the socket CONNECT adds no request");
    assert!(
        capture
            .warnings
            .iter()
            .all(|warning| warning.code != "netlog.request_without_url"),
        "the tunnel is not a request lost for lack of URL: {:?}",
        capture
            .warnings
            .iter()
            .map(|warning| warning.code.as_str())
            .collect::<Vec<_>>()
    );
    assert!(capture
        .requests
        .iter()
        .all(|request| request.attempts.iter().all(|attempt| attempt.method != "CONNECT")));
}

#[test]
fn proxied_requests_pair_with_cdp_and_take_the_inner_protocol() {
    let capture = parse_netlog(&fixture()).unwrap();
    let urls = [
        ("http://demo.invalid/a", "http", false),
        ("https://demo.invalid/b", "connect-h1", false),
        ("https://demo.invalid/c", "connect-h2", false),
        ("https://demo.invalid/d", "socks5", false),
        ("https://demo.invalid/e", "refused", true),
    ];
    let mut session = cdp_for(&urls);
    let outcome = attach_netlog(&mut session, &capture, &CorrelationOptions::default());

    for (url, label, _) in urls {
        let request = find(&session, url);
        assert_eq!(request.match_state, MatchState::Matched, "{label} must pair");
    }
    assert_eq!(find(&session, "https://demo.invalid/b").attempts[0].protocol, Protocol::H1);
    assert_eq!(find(&session, "https://demo.invalid/c").attempts[0].protocol, Protocol::H2);
    assert_eq!(find(&session, "https://demo.invalid/d").attempts[0].protocol, Protocol::H1);
    assert_eq!(
        find(&session, "https://demo.invalid/e").network_state,
        Some(NetworkState::NotSent)
    );
    assert_eq!(outcome.not_sent_attempts, 1);
    assert_eq!(outcome.unmatched_cdp_attempts, 0);
}

#[test]
fn proxy_record_has_no_credential_fields_and_authentication_is_a_flag() {
    let open = serde_json::to_string(&proxy(ProxyRoute::Relay, false)).unwrap();
    let authed = serde_json::to_string(&proxy(ProxyRoute::Relay, true)).unwrap();
    for text in [&open, &authed] {
        assert!(!text.contains("pass"), "{text}");
        assert!(!text.contains("user"), "{text}");
        assert!(!text.contains("Basic"), "{text}");
    }
    assert!(authed.contains("\"authenticated\":true"));
    assert!(open.contains("\"authenticated\":false"));
}

#[test]
fn full_export_keeps_host_port_and_route_sanitized_keeps_scheme_and_flag_only() {
    let mut session = cdp_for(&[("http://demo.invalid/a", "http", false)]);
    with_proxy(&mut session, proxy(ProxyRoute::Direct, true));
    let json = serde_json::to_value(&session.session.capture).unwrap();
    assert_eq!(json["proxy"]["host"], "proxy.invalid");
    assert_eq!(json["proxy"]["port"], 8080);
    assert_eq!(json["proxy"]["route"], "direct");

    let bundle = scrapelens_core::SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: None,
        attachments: BTreeMap::new(),
    };
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    let proxy_json =
        serde_json::to_value(&export.bundle.session.session.capture.as_ref().unwrap().proxy)
            .unwrap();
    assert_eq!(proxy_json["scheme"], "http");
    assert_eq!(proxy_json["authenticated"], true);
    assert!(proxy_json.get("host").is_none(), "{proxy_json}");
    assert!(proxy_json.get("port").is_none(), "{proxy_json}");
    assert!(proxy_json.get("route").is_none(), "{proxy_json}");
    let text = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(!text.contains("proxy.invalid"), "proxy address leaked into the sanitized export");
}

#[test]
fn sanitizer_redacts_proxy_authorization_header_and_userinfo_in_urls() {
    let mut session = cdp_for(&[("https://demo.invalid/a", "x", false)]);
    let provenance = Provenance::new(Source::Cdp, "test", Verification::Unverified);
    session.requests[0].request_headers.add(
        "proxy-authorization",
        "Basic c2VjcmV0LXZhbHVl",
        &provenance,
    );
    session.requests[0].url = "https://user:hunter2@demo.invalid/a".to_string();
    let bundle = scrapelens_core::SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: None,
        attachments: BTreeMap::new(),
    };
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    let text = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(!text.contains("c2VjcmV0"), "Proxy-Authorization value leaked");
    assert!(!text.contains("hunter2"), "URL password leaked");
}

#[test]
fn proxied_session_states_the_remote_endpoint_and_no_http3_once() {
    let mut session = cdp_for(&[("https://demo.invalid/a", "x", false)]);
    session.connections.push(Connection {
        id: "cdp-conn-1".to_string(),
        netlog_id: None,
        protocol: Protocol::H1,
        host: Some("demo.invalid".to_string()),
        port: Some(8080),
        ip: Some("203.0.113.9".to_string()),
        alpn: None,
        tls_version: None,
        reused: None,
        provenance: Provenance::new(Source::Cdp, "test", Verification::Unverified),
    });
    with_proxy(&mut session, proxy(ProxyRoute::Relay, false));
    apply_proxy_facts(&mut session);
    apply_proxy_facts(&mut session);

    let connection = &session.connections[0];
    assert!(connection.ip.is_none(), "the socket peer is the proxy, not the site");
    assert!(connection.port.is_none());
    assert_eq!(connection.host.as_deref(), Some("demo.invalid"));
    assert_eq!(
        connection
            .provenance
            .notes
            .iter()
            .filter(|note| note.as_str() == PROXY_CONNECTION_NOTE)
            .count(),
        1
    );
    assert_eq!(
        session
            .session
            .notes
            .iter()
            .filter(|note| note.as_str() == PROXY_NO_HTTP3_NOTE)
            .count(),
        1,
        "idempotent"
    );
}

#[test]
fn direct_session_is_untouched_by_the_proxy_facts() {
    let mut session = cdp_for(&[("https://demo.invalid/a", "x", false)]);
    session.connections.push(Connection {
        id: "cdp-conn-1".to_string(),
        netlog_id: None,
        protocol: Protocol::H2,
        host: Some("demo.invalid".to_string()),
        port: Some(443),
        ip: Some("198.51.100.7".to_string()),
        alpn: None,
        tls_version: None,
        reused: None,
        provenance: Provenance::new(Source::Cdp, "test", Verification::Unverified),
    });
    let before = serde_json::to_string(&session).unwrap();
    apply_proxy_facts(&mut session);
    assert_eq!(before, serde_json::to_string(&session).unwrap());
}

#[test]
fn written_proxied_session_carries_the_note_and_no_remote_ip() {
    let mut session = cdp_for(&[("https://demo.invalid/a", "x", false)]);
    session.connections.push(Connection {
        id: "cdp-conn-1".to_string(),
        netlog_id: None,
        protocol: Protocol::H1,
        host: Some("demo.invalid".to_string()),
        port: Some(8080),
        ip: Some("203.0.113.9".to_string()),
        alpn: None,
        tls_version: None,
        reused: None,
        provenance: Provenance::new(Source::Cdp, "test", Verification::Unverified),
    });
    with_proxy(&mut session, proxy(ProxyRoute::Relay, false));
    let bundle = scrapelens_core::SessionBundle {
        session,
        cdp_events_jsonl: None,
        netlog_json: None,
        attachments: BTreeMap::new(),
    };
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("session");
    scrapelens_core::store::write_session_dir(&bundle, &target).unwrap();
    let text = std::fs::read_to_string(target.join("session.json")).unwrap();
    assert!(!text.contains("203.0.113.9"), "remote IP of the proxy must not be written as the site's");
    assert!(text.contains(PROXY_NO_HTTP3_NOTE));
}
