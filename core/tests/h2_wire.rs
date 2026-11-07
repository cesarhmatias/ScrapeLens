//! T26: HPACK order decoded from Chrome's plaintext SSL bytes, checked against
//! the testserver's independent decoded order.

use std::path::Path;

use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
use scrapelens_core::parse::netlog::{build_netlog_session, parse_netlog};

fn netlog() -> Vec<u8> {
    include_bytes!("../../experiments/results/h2-page/chrome-netlog.json").to_vec()
}

/// The testserver records the decoded field list in `server-h2.jsonl`; the first
/// line is the `GET /setcookie` request.
fn server_reference() -> (Vec<String>, Vec<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h2-page/server-h2.jsonl");
    let line = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    let pseudo = value["pseudoheaders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| pair[0].as_str().unwrap().to_string())
        .collect();
    let headers = value["header_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_string())
        .collect();
    (pseudo, headers)
}

#[test]
fn h2_plaintext_order_matches_the_testserver_reference() {
    let capture = parse_netlog(&netlog()).unwrap();
    let (session, _) = build_netlog_session(&capture);
    let request = session
        .requests
        .iter()
        .find(|request| request.url.ends_with("/setcookie"))
        .expect("GET /setcookie");
    let connection = session
        .h2_wire
        .iter()
        .find(|connection| {
            connection
                .streams
                .iter()
                .any(|stream| stream.request_id.as_deref() == Some(request.id.as_str()))
        })
        .expect("h2 wire for the request");
    assert!(connection.preface);
    assert!(!connection.settings.is_empty());
    assert!(!connection.window_updates.is_empty());
    let stream = connection
        .streams
        .iter()
        .find(|stream| stream.request_id.as_deref() == Some(request.id.as_str()))
        .unwrap();
    let decoded: Vec<String> = stream
        .request
        .iter()
        .map(|field| field.name.clone())
        .collect();
    let (pseudo, headers) = server_reference();
    let expected: Vec<String> = pseudo.into_iter().chain(headers).collect();
    assert_eq!(decoded, expected);

    let values: Vec<(String, String)> = stream
        .request
        .iter()
        .map(|field| (field.name.clone(), field.value.clone()))
        .collect();
    assert_eq!(
        values[0],
        (":method".to_string(), "GET".to_string()),
        "pseudoheader values are decoded too"
    );
}

#[test]
fn h2_settings_window_and_client_hello_are_recorded() {
    let capture = parse_netlog(&netlog()).unwrap();
    let (session, _) = build_netlog_session(&capture);
    let connection = session.h2_wire.first().expect("h2 connection");
    let settings: Vec<(u16, u32)> = connection
        .settings
        .iter()
        .map(|setting| (setting.id, setting.value))
        .collect();
    for expected in [(1, 65536), (2, 0), (4, 6291456), (6, 262144)] {
        assert!(
            settings.contains(&expected),
            "missing SETTINGS {expected:?}"
        );
    }
    assert!(connection
        .window_updates
        .iter()
        .any(|update| update.stream_id == 0 && update.increment == 15663105));

    let hello = session.tls_hellos.first().expect("ClientHello");
    assert_eq!(hello.version, "TLS 1.3");
    assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert!(hello.sni.is_none(), "the capture is to 127.0.0.1");
    let server = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../experiments/results/h2-page/server-h2.jsonl");
    let line = std::fs::read_to_string(server)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let server_record: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(server_record["tls"]["tls_version"], "TLSv1.3");
    assert_eq!(server_record["tls"]["alpn"], "h2");
    assert_eq!(
        hello.ja4, "t13i1516h2_8daaf6152771_cb7bf5808d99",
        "JA4 with GREASE removed"
    );
}

#[test]
fn sanitized_export_drops_the_wire_evidence() {
    let capture = parse_netlog(&netlog()).unwrap();
    let (mut session, _) = build_netlog_session(&capture);
    assert!(!session.h2_wire.is_empty(), "precondition");
    session.h2_wire[0].streams[0]
        .request
        .push(scrapelens_core::model::H2Field {
            name: "authorization".to_string(),
            value: "Bearer H2-SECRET-VALUE".to_string(),
        });
    let bundle = scrapelens_core::SessionBundle::new(session);
    let export = sanitize_bundle(&bundle, &SanitizeOptions::default());
    assert!(export.bundle.session.h2_wire.is_empty());
    assert!(export.bundle.session.tls_hellos.is_empty());
    assert!(export.redactions.contains_key("wireEvidence"));
    let text = serde_json::to_string(&export.bundle.session).unwrap();
    assert!(!text.contains("H2-SECRET-VALUE"), "wire bytes leaked");
}
