//! Shared endpoint contract used identically by the HTTP/1.1, h2 and h3 servers.
//!
//! Endpoints:
//!
//! * `GET  /echo-order` — JSON with the request headers in decoded order.
//! * `GET  /setcookie`  — two distinct `Set-Cookie` fields, interleaved with
//!   `x-scrapelens-order` markers, plus a duplicate-name pair.
//! * `POST /echo`       — verbatim echo of the request body.
//! * `GET  /page`       — synthetic HTML page that issues fetch() calls with
//!   repeated headers, duplicate cookies, concurrent identical requests, a
//!   redirect and a POST.
//! * `GET  /redirect?n=`— `n` redirects (302) then a small body.
//! * `GET  /healthz`    — liveness probe.
//!
//! Body-capture routes (round 4, docs/08-corpos-busca.md §3.2-3.3):
//!
//! * `POST /sink`       — writes the received body bytes to `<body-dir>/sink-NNNN-<sha256[..12]>.bin`
//!   and answers JSON `{len, sha256, file, content_type}` (compare with what CDP stored).
//! * `GET  /json`       — fixed synthetic JSON (`application/json`).
//! * `GET  /binary`     — 4096 deterministic bytes, not valid UTF-8 (`application/octet-stream`).
//! * `GET  /big[?mib=N]`— N MiB (default 6) of deterministic text, `Content-Length` known.
//! * `GET  /gzip`       — fixed synthetic text, `Content-Encoding: gzip`.
//! * `GET  /redirect302`— 302 to `/json`.
//! * `ANY  /redirect307`— 307 to `/sink`; method and body are re-sent by the client.
//! * `GET  /empty`      — 204 without body.
//! * `GET  /zero`       — 200 with `Content-Length: 0`.

use crate::http::{Req, Resp};
use serde_json::{Value, json};

pub const MAX_BODY: usize = 5 * 1024 * 1024;

pub const GZIP_TEXT: &str = "synthetic gzip body for ScrapeLens: cmd_consultar_placa TST0T00\n";

static BODY_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
static SINK_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Directory where `/sink` stores received bodies (set once by `serve`).
pub fn set_body_dir(dir: std::path::PathBuf) {
    let _ = BODY_DIR.set(dir);
}

/// 4096 bytes that are not valid UTF-8 (contain 0xFF, 0xC0 and NUL).
pub fn binary_bytes() -> Vec<u8> {
    (0..4096u32).map(|i| ((i * 7 + 0xA5) & 0xFF) as u8).chain([0xFF, 0xC0, 0x00]).collect()
}

fn big(req: &Req) -> Resp {
    let mib: usize = req
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("mib=")).and_then(|v| v.parse().ok()))
        .unwrap_or(6)
        .min(64);
    let line = b"scrapelens-big-body 0123456789abcdef synthetic line\n";
    let total = mib * 1024 * 1024;
    let mut body = Vec::with_capacity(total);
    while body.len() < total {
        let take = line.len().min(total - body.len());
        body.extend_from_slice(&line[..take]);
    }
    Resp::new(200, body)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-scrapelens-endpoint", "big")
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Valid gzip member using one stored (uncompressed) deflate block; data < 64 KiB.
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let n = data.len() as u16;
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 0x01];
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(!n).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn sink(req: &Req) -> Resp {
    use sha2::{Digest, Sha256};
    if req.method == "GET" {
        return Resp::text(405, "use POST/PUT\n");
    }
    let sha: String = Sha256::digest(&req.body).iter().map(|b| format!("{b:02x}")).collect();
    let mut file = serde_json::Value::Null;
    if let Some(dir) = BODY_DIR.get() {
        let seq = SINK_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = dir.join(format!("sink-{seq:04}-{}.bin", &sha[..12]));
        if std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&path, &req.body)).is_ok() {
            file = json!(path.display().to_string());
        }
    }
    Resp::json(200, &json!({
        "schema": "scrapelens.testserver.sink/1",
        "method": req.method,
        "len": req.body.len(),
        "truncated": req.body_truncated,
        "sha256": sha,
        "file": file,
        "content_type": req.header("content-type"),
    }))
    .header("x-scrapelens-endpoint", "sink")
}

pub fn handle(req: &Req) -> Resp {
    let mut resp = match req.path() {
        "/echo-order" => echo_order(req),
        "/setcookie" => setcookie(req),
        "/echo" => echo(req),
        "/page" => page(req),
        "/redirect" => redirect(req),
        "/healthz" => Resp::text(200, "ok\n"),
        "/sink" => sink(req),
        "/json" => Resp::json(200, &json!({"schema": "scrapelens.testserver.json/1", "plate": "TST0T00", "items": [1, 2, 3], "nested": {"ok": true}}))
            .header("x-scrapelens-endpoint", "json"),
        "/binary" => Resp::new(200, binary_bytes())
            .header("content-type", "application/octet-stream")
            .header("x-scrapelens-endpoint", "binary"),
        "/big" => big(req),
        "/gzip" => Resp::new(200, gzip_stored(GZIP_TEXT.as_bytes()))
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-encoding", "gzip")
            .header("x-scrapelens-endpoint", "gzip"),
        "/redirect302" => Resp::text(302, "")
            .header("location", "/json")
            .header("x-scrapelens-endpoint", "redirect302"),
        "/redirect307" => Resp::text(307, "redirecting with body preserved\n")
            .header("location", "/sink")
            .header("x-scrapelens-endpoint", "redirect307"),
        "/empty" => Resp::new(204, Vec::new()).header("x-scrapelens-endpoint", "empty"),
        "/zero" => Resp::new(200, Vec::new())
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-scrapelens-endpoint", "zero"),
        other => Resp::text(404, format!("no such endpoint: {other}\n")),
    };
    // No caching: repeated/concurrent requests must reach the server.
    resp.headers.push((
        "cache-control".to_string(),
        "no-store, no-cache, must-revalidate".to_string(),
    ));
    resp
}

fn echo_order(req: &Req) -> Resp {
    let headers: Vec<Value> = req.headers.iter().map(|(n, v)| json!([n, v])).collect();
    let pseudo: Vec<Value> = req
        .pseudoheaders()
        .iter()
        .map(|(n, v)| json!([n, v]))
        .collect();
    let body = json!({
        "schema": "scrapelens.testserver.echo-order/1",
        "proto": req.proto.id(),
        "proto_wire": req.proto.wire(),
        "decode_point": req.proto.decode_point(),
        "conn": req.conn,
        "stream": req.stream,
        "method": req.method,
        "target": req.target,
        "authority": req.authority,
        "headers": headers,
        "pseudoheaders": pseudo,
        "header_count": req.headers.len(),
        "body_len": req.body.len(),
        "notes": req.notes,
        "note": "headers are listed in decoded order; duplicates are preserved and not merged",
    });
    Resp::json(200, &body)
        .header("x-scrapelens-proto", req.proto.id())
        .header("x-scrapelens-endpoint", "echo-order")
}

fn setcookie(_req: &Req) -> Resp {
    // Deliberate order: marker, cookie, marker, cookie ... so a client that
    // reorders or merges Set-Cookie is visible immediately.
    Resp::text(200, "setcookie: sc_a, sc_b, sc_dup x2\n")
        .header("x-scrapelens-order", "0")
        .header("set-cookie", "sc_a=alpha; Path=/; SameSite=Lax")
        .header("x-scrapelens-order", "1")
        .header("set-cookie", "sc_b=beta; Path=/; SameSite=Lax")
        .header("x-scrapelens-order", "2")
        .header("set-cookie", "sc_dup=one; Path=/; SameSite=Lax")
        .header("x-scrapelens-order", "3")
        .header("set-cookie", "sc_dup=two; Path=/; SameSite=Lax")
        .header("x-scrapelens-order", "4")
        .header("x-scrapelens-endpoint", "setcookie")
}

fn echo(req: &Req) -> Resp {
    if req.method != "POST" && req.method != "PUT" {
        return Resp::text(405, "use POST\n");
    }
    let ctype = req
        .header("content-type")
        .unwrap_or("application/octet-stream")
        .to_string();
    let len = req.body.len();
    Resp::new(200, req.body.clone())
        .header("content-type", ctype)
        .header("x-scrapelens-echo-len", len.to_string())
        .header(
            "x-scrapelens-body-truncated",
            if req.body_truncated { "true" } else { "false" },
        )
        .header("x-scrapelens-endpoint", "echo")
}

fn redirect(req: &Req) -> Resp {
    let n: u32 = req
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("n="))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0);
    if n == 0 {
        Resp::text(200, "redirect chain end\n")
            .header("x-scrapelens-redirects", "0")
            .header("x-scrapelens-endpoint", "redirect")
    } else {
        Resp::text(302, "")
            .header("location", format!("/redirect?n={}", n - 1))
            .header("x-scrapelens-redirects", n.to_string())
            .header("x-scrapelens-endpoint", "redirect")
    }
}

fn page(_req: &Req) -> Resp {
    Resp::new(200, PAGE_HTML.as_bytes().to_vec())
        .header("content-type", "text/html; charset=utf-8")
        .header("x-scrapelens-endpoint", "page")
}

/// Synthetic page. Deliberately includes:
/// - repeated request headers (`x-order` twice, `x-dup` twice with equal value),
/// - cookies created by JS plus cookies set by `/setcookie` (including a
///   duplicate-name pair),
/// - two bytes-identical concurrent GETs,
/// - a redirect chain,
/// - a small POST and a 128 KiB POST,
/// - a second-phase GET that carries whatever cookies the browser stored.
const PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>scrapelens-testserver page</title>
<style>body{font:13px ui-monospace,Menlo,monospace;margin:1.2rem;max-width:60rem}pre{white-space:pre-wrap}</style>
</head>
<body>
<h1>ScrapeLens reference page</h1>
<p>All data is synthetic and local. Results below are fetched from this origin.</p>
<pre id="log">running...</pre>
<script>
const log = [];
const out = document.getElementById('log');

function record(label, status, extra) {
  log.push(label + ': ' + status + (extra ? ' ' + extra : ''));
  out.textContent = log.join('\n');
  document.title = 'scrapelens page done ' + log.length;
}

async function step(label, url, init) {
  try {
    const r = await fetch(url, init);
    const t = await r.text();
    record(label, r.status, '(' + t.length + ' bytes, ' + (r.headers.get('x-scrapelens-proto') || '?') + ')');
    return t;
  } catch (e) {
    record(label, 'ERR', String(e));
    return null;
  }
}

(async () => {
  // 1. Cookies written by the page itself, then by the server.
  document.cookie = 'sc_page=fromjs; path=/; samesite=lax';
  await step('setcookie', '/setcookie');
  await step('setcookie-img', '/setcookie?via=img');

  // 2. Repeated request headers in a fetch() header list (order as written).
  await step('echo-order-repeated', '/echo-order?repeated=1', {
    headers: [
      ['x-order', 'first'],
      ['x-order', 'second'],
      ['x-dup', 'same'],
      ['x-dup', 'same'],
      ['x-scrapelens-tag', 'page']
    ]
  });

  // 3. Two bytes-identical concurrent requests.
  await Promise.all([
    step('concurrent-a', '/echo-order?concurrent=1'),
    step('concurrent-b', '/echo-order?concurrent=1')
  ]);

  // 4. Second phase: browser-generated Cookie header after storage.
  await step('echo-order-after-cookies', '/echo-order?after=cookies');

  // 5. Redirect chain.
  await step('redirect', '/redirect?n=2');

  // 6. Small and large POST echoes.
  await step('post-small', '/echo', {
    method: 'POST',
    headers: [['content-type', 'application/json'], ['x-order', 'a'], ['x-order', 'b']],
    body: JSON.stringify({hello: 'scrapelens', n: 1})
  });
  await step('post-large', '/echo', {
    method: 'POST',
    headers: [['content-type', 'application/octet-stream']],
    body: 'x'.repeat(128 * 1024)
  });

  record('done', 200, 'requests completed');
})();
</script>
</body>
</html>
"#;
