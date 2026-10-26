//! Exportadores cURL/Python: escaping de dados não confiáveis.

use scrapelens_core::export::curl::to_curl;
use scrapelens_core::export::python::to_python;
use scrapelens_core::export::ExportOptions;
use scrapelens_core::model::{
    HeaderView, LogicalRequest, OrderState, Provenance, Source, Verification,
};

fn provenance() -> Provenance {
    Provenance::new(Source::NetLog, "test", Verification::Verified)
}

fn request() -> LogicalRequest {
    let mut request = LogicalRequest::new("r1", "https://demo.invalid/a?x=1&y=';id", "POST");
    let mut headers = HeaderView::new(OrderState::SourceOrder);
    headers.add("Host", "demo.invalid", &provenance());
    headers.add("x-rep", "a", &provenance());
    headers.add("X-Rep", "b", &provenance());
    headers.add("Content-Type", "text/plain", &provenance());
    headers.add("Content-Length", "11", &provenance());
    headers.add("x-quote", "a'b\\c", &provenance());
    request.request_headers = headers;
    request
}

#[test]
fn curl_preserves_order_duplicates_and_escapes_untrusted_data() {
    let request = request();
    let output = to_curl(&request, Some(b"hello\nworld"), &ExportOptions::default()).unwrap();
    let text = &output.text;
    assert!(text.contains("--request 'POST'"));
    assert!(text.contains("--url 'https://demo.invalid/a?x=1&y='\\'';id'"));
    assert!(text.contains("--header 'x-rep: a'"));
    assert!(text.contains("--header 'X-Rep: b'"));
    assert!(text.contains("--header 'x-quote: a'\\''b\\c'"));
    assert!(text.contains("--data-binary $'hello\\nworld'"));
    assert!(text.contains("NÃO reproduz TLS"));
    assert!(output.body_included);
}

#[test]
fn curl_refuses_header_injection_and_omits_unsafe_header() {
    let mut request = request();
    request
        .request_headers
        .add("x-bad", "a\r\nX-Evil: 1", &provenance());
    let output = to_curl(&request, None, &ExportOptions::default()).unwrap();
    assert!(!output.text.contains("X-Evil"));
    assert!(output
        .warnings
        .iter()
        .any(|warning| warning.code == "export.header_injection"));
    assert!(output
        .skipped_headers
        .iter()
        .any(|header| header.contains("x-bad")));
}

#[test]
fn curl_drops_content_length_when_body_is_not_exported() {
    let request = request();
    let output = to_curl(&request, None, &ExportOptions::default()).unwrap();
    assert!(!output.text.contains("Content-Length"));
    assert!(output
        .warnings
        .iter()
        .any(|warning| warning.code == "export.content_length_without_body"));
    assert!(!output.body_included);
}

#[test]
fn curl_marks_unverified_sequence_and_pseudoheaders() {
    let mut request = request();
    let provenance = Provenance::new(Source::Cdp, "test", Verification::Unverified);
    request.request_headers.add(":method", "POST", &provenance);
    let output = to_curl(&request, None, &ExportOptions::default()).unwrap();
    assert!(output.text.contains("NÃO verificada"));
    assert!(output.text.contains(":method: pseudoheader não replicável"));
}

#[test]
fn python_uses_http_client_and_preserves_header_duplicates() {
    let mut request = request();
    request.method = "POST".to_string();
    let output = to_python(&request, Some(b"hello\nworld"), &ExportOptions::default()).unwrap();
    let text = &output.text;
    assert!(text.contains("import http.client"));
    assert!(text.contains("HTTPSConnection(\"demo.invalid\", 443"));
    assert!(text.contains("ssl.create_default_context()"));
    assert!(!text.contains("_create_unverified_context"));
    assert!(!text.contains("verify=False"));
    let first = text.find("conn.putheader(\"x-rep\", \"a\")").unwrap();
    let second = text.find("conn.putheader(\"X-Rep\", \"b\")").unwrap();
    assert!(first < second);
    assert!(text.contains("conn.send(b\"hello\\nworld\")"));
    assert!(text.contains("putrequest(\"POST\", \"/a?x=1&y=';id\", skip_host=True"));
    assert!(text.contains("NÃO reproduz TLS"));
}

#[test]
fn python_maps_authority_to_host_for_http11() {
    let mut request = LogicalRequest::new("r1", "https://demo.invalid/path?q=1", "GET");
    request.request_headers = HeaderView::new(OrderState::SourceOrder);
    request
        .request_headers
        .add(":authority", "demo.invalid", &provenance());
    request
        .request_headers
        .add(":path", "/path?q=1", &provenance());
    request.request_headers.add("x-rep", "a", &provenance());
    let output = to_python(&request, None, &ExportOptions::default()).unwrap();
    assert!(output
        .text
        .contains("conn.putheader(\"Host\", \"demo.invalid\")"));
    assert!(output.text.contains(":authority convertido para Host"));
    assert!(!output.text.contains("conn.putheader(\":path\""));
}

#[test]
fn python_string_and_bytes_escaping() {
    use scrapelens_core::export::python::{python_bytes, python_str};
    assert_eq!(python_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    assert_eq!(
        python_bytes(&[0, 1, b'a', b'\n', b'"']),
        "b\"\\x00\\x01a\\n\\\"\""
    );
}
