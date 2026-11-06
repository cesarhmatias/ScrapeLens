//! T12/T13: neutral-name and value-format secrets in the sanitized export.
//!
//! MCP masking uses the same core entry point (`sanitize_bundle_owned` in
//! `mcp/src/registry.rs`), so the export matrix is also the MCP view matrix.
//! The synthetic values are fake; no real credential.

use std::collections::BTreeMap;

use scrapelens_core::export::sanitize::{sanitize_bundle, sanitize_text, SanitizeOptions};
use scrapelens_core::model::{
    Body, BrowserInfo, CookieField, LogicalRequest, Provenance, SessionBundle, SessionMeta,
    SessionV1, Source, Verification,
};

const ACCESS_URL: &str = "atk_url_9f3aQ2mN8vB4xR6tY1uP0sD5gH2jK7w";
const ACCESS_HDR: &str = "atk_hdr_8e2bP1lM7uA3wQ5zX9cV4nB6mK0jH2g";
const ACCESS_FORM: &str = "atk_form_7d1cO0kN6tZ2vP4yW8bU3mA5lJ9iG1f";
const ACCESS_JSON: &str = "atk_json_6c0bN9jM5sY1uO3xV7aT2lZ4kI8hF0e";
const REFRESH_FORM: &str = "rtk_form_5b9aM8iL4rX0tN2wU6zS1kY3jH7gE9d";
const JWT_QUERY: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJxdWVyeSIsIm5hbWUiOiJRIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const JWT_JSON: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqc29uIiwibmFtZSI6IkoifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const VIEWSTATE_QUERY: &str = "/wEPDwUKMTIzNDU2Nzg5MGRkYQ9kFgICAw9kFgICAQ8PFgIeBFRleHQFB3F1ZXJ5";
const VIEWSTATE_FORM: &str = "/wEPDwUKMTIzNDU2Nzg5MGRkYQ9kFgICAw9kFgICAQ8PFgIeBFRleHQFBmZvcm0";
const VIEWSTATE_JSON: &str = "/wEPDwUKMTIzNDU2Nzg5MGRkYQ9kFgICAw9kFgICAQ8PFgIeBFRleHQFBGpzb24";
const EVENTVALIDATION_FORM: &str = "7f3a9Q2mN8vB4xR6tY1uP0sD5gH2jK9wZ3pL5nM7qR9sT1uV3xY5zA7bC9dE1fG3";
const EVENTVALIDATION_JSON: &str = "8g4b0R3nO9wC5yS7uZ2vQ6tA8dF1hJ4kL6mN0pQ2rS4tU6vW8xY0zA2bC4dE6f";
const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASC-----END PRIVATE KEY-----";
const GHP: &str = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const STRIPE: &str = concat!("sk_live_", "51H8xyzABCDEFGHIJKLMNOPQRSTUV");
const SLACK: &str = concat!("xoxb-", "123456789012-123456789012-abcdefghijklmnopqrstuvwx");
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
const GOOGLE: &str = "AIzaSyD-EXAMPLE_1234567890abcdefghijklmno";
const ENTROPY: &str = "Zx9Qm2Lp7Rv4Tn8Ws3Yb6Hc1Kd5Fg0Jh2Mk9Nq4Pt7Ux3Za8Bc6Vd1Ef5Gh0Ij";
const COOKIE: &str = "cookie_4a9zM2nB7vC1xL5kJ8hG3fD6sA0pQ";

const PAGE: &str = "2";
const ARQUIVO: &str = "page.html";
const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const BUILD: &str = "2026.10.26-build-42";
const ETAG: &str = "W/\"abcdef1234567890\"";
const SRI: &str = "sha384-oqVuAfXRKap7fdgcCY5uykM6R9GqQ8Kuxy9rx7HNQl7fMpW5vV5vV5vV5vV5";

fn provenance() -> Provenance {
    Provenance::new(Source::NetLog, "t12", Verification::Verified)
}

fn bundle() -> SessionBundle {
    let mut session = SessionV1::new(SessionMeta::new(
        "t12",
        "2026-11-06T00:00:00Z",
        BrowserInfo::default(),
    ));
    let mut request = LogicalRequest::new(
        "r1",
        &format!(
            "https://demo.invalid/x?access={ACCESS_URL}&refresh={JWT_QUERY}&__VIEWSTATE={VIEWSTATE_QUERY}&page={PAGE}&sha={SHA256}"
        ),
        "POST",
    );
    for (name, value) in [
        ("X-Access", ACCESS_HDR),
        ("X-Neutral-Ghp", GHP),
        ("Authorization", "Bearer AUTH-SCHEME-CONTROL"),
        ("ETag", ETAG),
        ("X-Sri", SRI),
    ] {
        request.request_headers.add(name, value, &provenance());
    }
    request.cookie =
        CookieField::from_header_values(&[format!("access={COOKIE}; theme=dark")], &provenance());
    request.request_body = Body::captured("t12.form.bin", 64, &provenance())
        .with_content_type("application/x-www-form-urlencoded");
    request.response_body = Body::captured("t12.json.bin", 512, &provenance())
        .with_content_type("application/json");
    session.requests.push(request);

    let mut bundle = SessionBundle::new(session);
    bundle.insert_attachment(
        "t12.form.bin",
        format!(
            "access={ACCESS_FORM}&refresh={REFRESH_FORM}&__VIEWSTATE={VIEWSTATE_FORM}&__EVENTVALIDATION={EVENTVALIDATION_FORM}&page={PAGE}&sha={SHA256}"
        )
        .into_bytes(),
    );
    bundle.insert_attachment(
        "t12.json.bin",
        format!(
            concat!(
                "{{\"access\":\"{}\",\"refresh\":\"{}\",\"payload\":\"{}\",",
                "\"__VIEWSTATE\":\"{}\",\"__EVENTVALIDATION\":\"{}\",",
                "\"private_key\":\"{}\",\"ghp\":\"{}\",\"stripe\":\"{}\",",
                "\"slack\":\"{}\",\"aws\":\"{}\",\"google\":\"{}\",\"entropy\":\"{}\",",
                "\"page\":{},\"nome_arquivo\":\"{}\",\"sha256\":\"{}\",",
                "\"uuid\":\"{}\",\"build\":\"{}\"}}"
            ),
            ACCESS_JSON,
            JWT_JSON,
            JWT_JSON,
            VIEWSTATE_JSON,
            EVENTVALIDATION_JSON,
            PRIVATE_KEY,
            GHP,
            STRIPE,
            SLACK,
            AWS,
            GOOGLE,
            ENTROPY,
            PAGE,
            ARQUIVO,
            SHA256,
            UUID,
            BUILD
        )
        .into_bytes(),
    );
    bundle
}

/// `true` means the value is still readable in the sanitized output.
fn leak_matrix() -> BTreeMap<&'static str, bool> {
    let export = sanitize_bundle(&bundle(), &SanitizeOptions::default());
    let session = serde_json::to_string(&export.bundle.session).unwrap();
    let body = export
        .bundle
        .attachments
        .values()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let text = format!("{session}\n{body}");

    let mut matrix = BTreeMap::new();
    for (name, value) in [
        ("access-url", ACCESS_URL),
        ("access-header", ACCESS_HDR),
        ("access-form", ACCESS_FORM),
        ("access-json", ACCESS_JSON),
        ("refresh-form", REFRESH_FORM),
        ("jwt-query", JWT_QUERY),
        ("jwt-json", JWT_JSON),
        ("viewstate-query", VIEWSTATE_QUERY),
        ("viewstate-form", VIEWSTATE_FORM),
        ("viewstate-json", VIEWSTATE_JSON),
        ("eventvalidation-form", EVENTVALIDATION_FORM),
        ("eventvalidation-json", EVENTVALIDATION_JSON),
        ("private-key", PRIVATE_KEY),
        ("ghp", GHP),
        ("stripe", STRIPE),
        ("slack", SLACK),
        ("aws", AWS),
        ("google", GOOGLE),
        ("entropy", ENTROPY),
        ("cookie", COOKIE),
        ("page", PAGE),
        ("nome-arquivo", ARQUIVO),
        ("sha256", SHA256),
        ("uuid", UUID),
        ("build", BUILD),
        ("etag", ETAG),
        ("sri", SRI),
    ] {
        matrix.insert(name, text.contains(value));
    }
    matrix
}

#[test]
fn t12_matrix_is_recorded_case_by_case() {
    let matrix = leak_matrix();
    println!("{matrix:#?}");
    assert_eq!(matrix.len(), 27);
    // The snapshot is asserted in T13, after the value-format detector exists.
}

#[test]
fn t12_mcp_string_mask_uses_the_same_core_rule() {
    // `scrub_output` calls `sanitize_text` on each string value of the MCP
    // response. This is the same entry point; T12 only records what it does
    // with and without the name context.
    let options = SanitizeOptions::default();
    println!(
        "masked-with-name={}",
        sanitize_text(&format!("access={ACCESS_URL}"), &options)
    );
    println!("bare-access={}", sanitize_text(ACCESS_URL, &options));
}
