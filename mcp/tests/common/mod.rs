//! Test support: synthetic HAR with a cookie/token/CSRF flow, and helpers.
#![allow(dead_code)]

pub mod client;

use std::path::{Path, PathBuf};

use scrapelens_mcp::{Config, Ctx};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

pub const SID: &str = "SIDVALUE-abcdef0123456789";
pub const TOKEN: &str = "TOKEN-ABCDEFGH-0123";
pub const PASSWORD: &str = "PW-SECRET-1";
pub const REFRESH: &str = "REFRESH-9999999999";
pub const CSRF: &str = "CSRF-VALUE-123456789";
/// Secrets that the core's masking policy must hide.
pub const MASKED_SECRETS: [&str; 4] = [SID, TOKEN, PASSWORD, REFRESH];

pub fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path)
}

fn headers(list: &[(&str, &str)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(n, v)| json!({"name": n, "value": v}))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn entry(
    when: &str,
    method: &str,
    url: &str,
    req_headers: &[(&str, &str)],
    post: Option<(&str, &str)>,
    status: u16,
    resp_headers: &[(&str, &str)],
    content: Option<(&str, &str, Option<&str>)>,
) -> Value {
    let mut request = json!({
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": headers(req_headers), "queryString": [], "cookies": [],
        "headersSize": -1, "bodySize": 0,
    });
    if let Some((mime, text)) = post {
        request["postData"] = json!({"mimeType": mime, "text": text});
        request["bodySize"] = json!(text.len());
    }
    let mut response = json!({
        "status": status, "statusText": "", "httpVersion": "HTTP/1.1",
        "headers": headers(resp_headers), "cookies": [], "redirectURL": "",
        "headersSize": -1, "bodySize": 0,
        "content": {"mimeType": "", "size": 0},
    });
    if let Some((mime, text, encoding)) = content {
        response["content"] = json!({"mimeType": mime, "size": text.len(), "text": text});
        if let Some(encoding) = encoding {
            response["content"]["encoding"] = json!(encoding);
        }
    }
    json!({
        "startedDateTime": when, "time": 20.0, "request": request, "response": response,
        "cache": {}, "timings": {"send": 0, "wait": 15, "receive": 5},
    })
}

/// Synthetic HAR (made-up data, `.invalid` domains). `variant` changes the
/// token so `diff_sessions` has something to compare.
pub fn flow_har(variant: &str) -> String {
    let token = format!("{TOKEN}{variant}");
    let html = format!(
        "<html><body><form><input type=\"hidden\" name=\"csrf\" value=\"{CSRF}\"></form></body></html>"
    );
    let login_body = format!("{{\"user\":\"u\",\"password\":\"{PASSWORD}\"}}");
    let login_resp = format!("{{\"access_token\":\"{token}\"}}");
    let sid_cookie = format!("sid={SID}");
    let set_sid = format!("sid={SID}; Path=/; HttpOnly");
    let set_refresh = format!("refresh={REFRESH}; Path=/; Secure");
    let bearer = format!("Bearer {token}");
    let big = "A".repeat(100_000);
    // 300 non-UTF-8 bytes (fake PNG).
    let mut png = vec![0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe];
    png.extend((0..290).map(|i| (i % 251) as u8 | 0x80));
    let png_b64 = base64_encode(&png);
    let entries = vec![
        entry(
            "2026-10-26T20:00:00.000Z",
            "GET",
            "https://app.fixture.invalid/",
            &[("Host", "app.fixture.invalid"), ("Accept", "text/html")],
            None,
            200,
            &[("content-type", "text/html"), ("set-cookie", &set_sid)],
            Some(("text/html", &html, None)),
        ),
        entry(
            "2026-10-26T20:00:01.000Z",
            "POST",
            "https://app.fixture.invalid/api/login",
            &[
                ("Content-Type", "application/json"),
                ("Cookie", &sid_cookie),
                ("X-CSRF", CSRF),
            ],
            Some(("application/json", &login_body)),
            200,
            &[
                ("content-type", "application/json"),
                ("set-cookie", &set_refresh),
            ],
            Some(("application/json", &login_resp, None)),
        ),
        entry(
            "2026-10-26T20:00:02.000Z",
            "GET",
            "https://api.fixture.invalid/data?key=1",
            &[
                ("X-Dup", "a"),
                ("Authorization", &bearer),
                ("x-dup", "b"),
                ("Cookie", &sid_cookie),
                ("X-Dup", "c"),
            ],
            None,
            200,
            &[("content-type", "text/plain")],
            Some(("text/plain", &big, None)),
        ),
        entry(
            "2026-10-26T20:00:03.000Z",
            "GET",
            "https://api.fixture.invalid/img.png",
            &[("Accept", "image/png")],
            None,
            200,
            &[("content-type", "image/png")],
            Some(("image/png", &png_b64, Some("base64"))),
        ),
        entry(
            "2026-10-26T20:00:04.000Z",
            "GET",
            "https://app.fixture.invalid/missing",
            &[("Accept", "*/*")],
            None,
            404,
            &[("content-type", "text/plain")],
            None,
        ),
    ];
    json!({"log": {"version": "1.2", "creator": {"name": "mcp-test", "version": "1"}, "pages": [], "entries": entries}})
        .to_string()
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_of(text: &str) -> String {
    base64_encode(text.as_bytes())
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub ctx: Ctx,
}

impl Env {
    pub fn new(allow_reveal: bool) -> Self {
        Self::with_extra(allow_reveal, &[])
    }

    pub fn with_extra(allow_reveal: bool, extra: &[PathBuf]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::new(
            &dir.path().join("sessions"),
            Some(&dir.path().join("out")),
            extra,
            allow_reveal,
            64 * 1024 * 1024,
        )
        .unwrap();
        Self {
            ctx: Ctx::new(cfg),
            dir,
        }
    }

    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Imports the flow HAR and returns the session_id.
    pub fn import_flow(&self, name: &str, variant: &str) -> String {
        let path = self.write(&format!("{name}.har"), &flow_har(variant));
        let out = scrapelens_mcp::tools::import_session(
            &self.ctx,
            p(json!({"path": path.to_str().unwrap(), "name": name})),
        )
        .unwrap();
        out["sessionId"].as_str().unwrap().to_string()
    }
}

pub fn p<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

pub fn text(value: &Value) -> String {
    value.to_string()
}

/// No known secret may appear in the masked output.
pub fn assert_no_secrets(value: &Value, what: &str) {
    let text = text(value);
    for secret in MASKED_SECRETS {
        assert!(!text.contains(secret), "{what}: leaked {secret}\n{text}");
    }
}

/// Synthetic HAR with invented Cloudflare signals (`.invalid` domain).
pub const CF_SECRET: &str = "SEGREDO-BM-1";

pub fn cf_har() -> String {
    let entry = |when: &str, url: &str, status: u16, resp: Vec<(&str, &str)>| {
        json!({
            "startedDateTime": when, "time": 10.0,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Accept", "value": "text/html"}],
                "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": resp.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>(),
                "cookies": [], "redirectURL": "", "headersSize": -1, "bodySize": 0,
                "content": {"mimeType": "text/html", "size": 2, "text": "ok"}},
            "cache": {}, "timings": {"send": 0, "wait": 8, "receive": 2},
        })
    };
    let set_cookie = format!("__cf_bm={CF_SECRET}; Path=/; HttpOnly");
    let entries = vec![
        entry(
            "2026-10-31T10:00:00.000Z",
            "http://site.invalid.test/?utm=SEGREDO-QUERY-1",
            200,
            vec![
                ("content-type", "text/html"),
                ("cf-ray", "abc-GRU"),
                ("set-cookie", &set_cookie),
            ],
        ),
        entry(
            "2026-10-31T10:00:01.000Z",
            "http://site.invalid.test/area",
            403,
            vec![("content-type", "text/html"), ("cf-mitigated", "challenge")],
        ),
    ];
    json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "pages": [], "entries": entries}}).to_string()
}
