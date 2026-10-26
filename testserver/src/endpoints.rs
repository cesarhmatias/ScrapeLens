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

use crate::http::{Req, Resp};
use serde_json::{Value, json};

pub const MAX_BODY: usize = 5 * 1024 * 1024;

pub fn handle(req: &Req) -> Resp {
    let mut resp = match req.path() {
        "/echo-order" => echo_order(req),
        "/setcookie" => setcookie(req),
        "/echo" => echo(req),
        "/page" => page(req),
        "/redirect" => redirect(req),
        "/healthz" => Resp::text(200, "ok\n"),
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
