# testserver — reference servers for header order

Local servers of the ScrapeLens project that observe the **decoded order**
of headers at the first available point of each protocol, before any
normalization into a dictionary. All evidence is synthetic, local JSONL.

| Port | Protocol | Observation point |
|---|---|---|
| `127.0.0.1:8781` | HTTP/1.1 (TCP) | raw socket bytes: request line + header lines as they arrived (order, case, duplicates) |
| `127.0.0.1:8782` | HTTP/2 (TLS, ALPN `h2`) | list emitted by the HPACK decoder (`httlib-hpack 0.1.3`) in decode order, pseudoheaders included |
| `127.0.0.1:8783` | HTTP/3 (QUIC, ALPN `h3`) | `Vec<Header>` list returned by `quiche 0.30` in `h3::Event::Headers` (QPACK decode order) |

h3 also listens on UDP `127.0.0.1:8782` by default. QUIC uses UDP and h2 uses
TCP, so the two stacks share the port number: that is what allows
`chrome --origin-to-force-quic-on=127.0.0.1:8782` to measure h3 on the same
origin as h2. Disable it with `--no-h3-on-h2-port`.

## Commands

```sh
cd testserver
cargo build                      # Rust 1.98.1; Cargo.lock committed
cargo test                       # 8 integration tests (h1, h2, h3)
cargo run -- gen-cert            # only if fixtures/tls/ is missing (generated, not tracked)
cargo run -- serve               # three servers, default ports
cargo run -- serve --only h1,h2  # subset
./run-demo.sh                    # starts up, sends ordered requests, summarizes the evidence
./scripts/chrome-probe.sh        # Chrome 156 headless: /page over h2 and h3
```

Ports busy? `./run-demo.sh 9781` (h1 9781, h2 9782, h3 9783) and
`./scripts/chrome-probe.sh 9781`.

Evidence: `fixtures/evidence/<run-id>/{h1,h2,h3}.jsonl` + `run.json` (run
metadata: ports, certificate, SPKI pin, `decode_points`, QPACK capacity).
Each request is one record, with an immediate `flush`: the file can be
inspected while the servers are still running.

## Endpoints (identical across the three protocols)

| Endpoint | Behavior |
|---|---|
| `GET /echo-order` | JSON with the list of headers in decoded order, duplicates preserved, `pseudoheaders` separated |
| `GET /setcookie` | two distinct `Set-Cookie` headers (`sc_a`, `sc_b`) + a same-name pair (`sc_dup=one`, `sc_dup=two`), interleaved with `x-scrapelens-order: 0..4` markers |
| `POST /echo` | byte-for-byte echo of the body (up to 5 MiB; above that it marks `body_truncated`) |
| `GET /page` | synthetic HTML that triggers: cookies via JS + server, fetch with repeated headers, two identical simultaneous requests, redirect chain, small POST and 128 KiB POST, and a second fetch that already carries cookies |
| `GET /redirect?n=N` | `N` 302 responses (`location: /redirect?n=N-1`) and then 200 |
| `GET /multi/` | multi-target page (popup, `target=_blank`, OOPIF, worker, service worker); see its own section below |
| `GET /healthz` | `ok` |

Responses also carry `server`, `content-length`, `cache-control: no-store`
and, on h2, `alt-svc: h3=":<h3-port>"; ma=86400`. The order of response
headers is recorded in the evidence exactly as it was sent.

## JSONL evidence (`scrapelens.testserver.evidence/1`)

```json
{"schema":"scrapelens.testserver.evidence/1","seq":0,"ts_rfc3339":"2026-10-26T20:29:07.813Z",
 "ts_unix_ms":1793046547813,"proto":"h2","proto_wire":"HTTP/2 over TLS (ALPN h2)",
 "decode_point":"HPACK decoded field list (httlib-hpack 0.1.3), recorded in decode order before any map is built",
 "server":"127.0.0.1:8782","conn":"c1","stream":1,"method":"GET",
 "target":"/echo-order?probe=demo-h2","authority":"127.0.0.1:8782",
 "headers":[[":method","GET"],[":scheme","https"],[":authority","127.0.0.1:8782"],
            [":path","/echo-order?probe=demo-h2"],["user-agent","curl/8.7.1"],["accept","*/*"],
            ["x-order","first"],["x-order","second"],["x-dup","same"]],
 "pseudoheaders":[[":method","GET"],[":scheme","https"],[":authority","127.0.0.1:8782"],
                  [":path","/echo-order?probe=demo-h2"]],
 "header_count":9,"raw_head_b64":null,"header_block_b64":"godBigidXAuBcNx914UEkmCkn...",
 "body_b64":null,"body_len":0,"body_truncated":false,"body_framing":null,
 "response":{"status":200,"headers":[["content-type","application/json; charset=utf-8"],["..."],["content-length","1143"]],
             "header_count":8,"body_len":1143},
 "notes":[]}
```

Complete, real examples of one record per protocol:
`fixtures/evidence-sample/{h1,h2,h3}.jsonl`.

Main fields:

- `headers`: ordered array of `[name, value]` pairs, pseudoheaders at their
  decoded position (h2/h3) and names in their original case (h1). **Never** an object.
- `pseudoheaders`: ordered subset of the `:` fields.
- `raw_head_b64` (h1): exact bytes of the request head, with CRLF.
- `header_block_b64` (h2): raw HPACK block received (HEADERS + CONTINUATION),
  alongside the decoded list.
- `body_b64`, `body_len`, `body_truncated`, `body_framing` (`content-length`,
  `chunked`, `none`).
- `response.headers`: response headers in the order sent (includes transport headers).
- `conn`/`stream`: **server-side** identifiers (`h3-3`, `c1`, h2/h3 stream). Two
  identical simultaneous requests appear as two records with distinct
  `conn`/`stream`; nothing is associated by URL or time.
- `decode_point`: exact wording of that protocol's observation point.
- `marker`: value of `?m=` in the target, when present (`/multi/` pages); in
  other records it is `null`. The same record also goes to the compact
  `multi.jsonl` — see "Multi-target pages".

## Certificate (fixtures/tls/)

Synthetic test PKI: CA (`scrapelens-test-ca.crt.pem`) + leaf for
`localhost`, `127.0.0.1` and `::1`. The leaf pin is in
`fixtures/tls/spki-sha256-base64.txt`. The files are **generated and not tracked**:
run `cargo run -- gen-cert` once (the scripts below do it when the files are missing).
The test suites generate their own certificates in the system temp folder.

```sh
curl --cacert fixtures/tls/scrapelens-test-ca.crt.pem https://127.0.0.1:8782/echo-order
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PIN=$(grep -m1 -E '^[A-Za-z0-9+/=]+$' fixtures/tls/spki-sha256-base64.txt)
"$CHROME" --headless=new --user-data-dir=$(mktemp -d) \
  --ignore-certificate-errors-spki-list="$PIN" --enable-quic \
  --origin-to-force-quic-on=127.0.0.1:8782 \
  --dump-dom https://127.0.0.1:8782/page
```

Do not install the CA in the system keychain: the SPKI pin lets Chrome trust
the server, and the Rust clients use the CA explicitly. The CA key is in the
repository because it is disposable test material — never use it outside here.

## What the Chrome 156 experiment has already shown

Headless Chrome 156.0.8078.48, `/page`, server evidence (synthetic):

- Repeated headers passed to `fetch()` as a list of arrays reach the server
  **merged into a single comma-separated field**: `x-order: first, second`
  and `x-dup: same, same` — on h2 and on h3. In other words, the list handed to
  the encoder no longer contains the duplicates; whoever wants to prove real
  duplicates needs a source that has them before that point.
- Cookies are sent as **four separate `cookie` fields** (one per cookie:
  `sc_page`, `sc_a`, `sc_b`, `sc_dup`), not as one field with commas, on both h2
  and h3. The order of the `cookie` fields followed the creation/storage order observed.
- `Set-Cookie: sc_dup=one` followed by `sc_dup=two` (same name and Path) resulted
  in only `sc_dup=two` in the next request; `sc_a` and `sc_b` survived.
- Decoded pseudoheader order: h2 `:method,:scheme,:authority,:path`;
  h3 `:method,:authority,:scheme,:path`. The server preserved the order in both.
- Two identical simultaneous requests (`/echo-order?concurrent=1`) become
  two records with distinct streams on a single connection, with no automatic
  association between them.
- With the QPACK dynamic table disabled on the server, Chrome kept **one h3
  connection for 13 sequential requests**, including a 128 KiB POST.

`/favicon.ico` is also recorded (404), as real browser noise.

## Known limits

- **QPACK with dynamic table**: the server advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY=0`
  by default. This keeps each field section self-contained (static table +
  literals) and does not affect order or duplicates. With capacity > 0
  (`--h3-qpack-table 4096`), Chrome 156 opens the dynamic table and quiche 0.30
  fails the **second** request on the connection with `QpackDecompressionFailed`
  (reproducible; Chrome then opens another connection). Recorded as a limitation
  of the reference tool, not a conclusion about the browser.
- quiche does not expose the raw QPACK bytes: the h3 reference is the list
  already decoded (it is the decode point, which is what the matrix requires).
- The h1 server is plain-text HTTP (port 8781) on purpose: it is the raw reading
  of the bytes. For TLS/HTTP1.1, use h2 and force ALPN if needed (not implemented here).
- `Alt-Svc` with an IP-literal origin was not honored by headless Chrome in the
  runs; use `--origin-to-force-quic-on`. h2 keeps advertising h3.
- Bodies above 5 MiB are truncated and marked (`body_truncated: true`);
  the remainder is drained to keep the framing.
- 100% synthetic data, no telemetry, nothing leaves `127.0.0.1`.

## Why Rust (and not Go)

Kept in Rust: the three servers were already implemented, tested (8
integration tests) and validated with Chrome 156 on h1/h2/h3 — h2 at the frame
level with the HPACK decoder exposed, and h3 via quiche with `Vec<Header>` in
decoded order. Go 1.27.3 (`net/http2` + `quic-go`) would have been viable, but
the switch would discard an already verified path with no gain in fidelity (the
observation point would be the same); the port, endpoint and JSONL contract
does not change with the language.

## Dependencies (committed lockfile)

Rust 1.98.1 · `httlib-hpack 0.1.3` (HPACK) · `quiche 0.30.0` (QUIC/h3/QPACK,
BoringSSL via cmake) · `rustls 0.23` + `rustls-pemfile` · `rcgen 0.14` ·
`serde`/`serde_json` · `base64` · `chrono` · `sha2`.
The quiche build requires `cmake` (installed via Homebrew) and network access
only for the first compilation of the embedded BoringSSL.

## Routes for body capture (round 4, docs/08-body-search.md §3.2–3.3)

Identical on h1/h2/h3. `serve` writes the bodies received at `/sink` to
`<evidence>/<run>/bodies/sink-NNNN-<sha256[..12]>.bin` (in addition to the full
`body_b64` already present in the JSONL evidence), so they can be compared byte
by byte with `cdp-bodies.jsonl`.

| Route | Response |
|---|---|
| `POST /sink` | writes the body; JSON `{len, truncated, sha256, file, content_type}` (read limit 5 MiB, `truncated` if exceeded) |
| `GET /json` | fixed `application/json` |
| `GET /binary` | 4099 non-UTF-8 bytes (`octet-stream`) |
| `GET /big[?mib=N]` | N MiB (default 6) of deterministic text |
| `GET /gzip` | fixed text with `Content-Encoding: gzip` (decoded: `endpoints::GZIP_TEXT`) |
| `GET /redirect302` | 302 → `/json` |
| `POST /redirect307` | 307 → `/sink` (Chrome resends method and body) |
| `GET /empty` | 204 with no body (evidence for `empty`) |
| `GET /zero` | 200 with `Content-Length: 0` |

Test: `cargo test h1_body_routes` (binary/6 MiB/gzip/302/307/204/sink).

## Multi-target pages (round 10, docs/14-multi-target-capture.md)

Reference page for the CDP multi-target capture experiment. Each action fires
requests with a unique `?m=` marker; the server writes the marker to the normal
JSONL and to a compact `multi.jsonl` log per run.

```sh
cargo run --release -- serve --only h1 --h1 127.0.0.1:8781
# open http://127.0.0.1:8781/multi/ in a Chrome (popup blocked? use
# --disable-popup-blocking, or call window.__scrapelensMulti.openPopup() via CDP)
./scripts/multi-probe.sh            # starts h1, opens /multi/ in headless Chrome
                                    # and checks the 16 markers; fails if any is missing
```

URLs (all under `testserver/`, loopback only):

| URL | Target it exercises |
|---|---|
| `GET /multi/` | main page (top-level) |
| `GET /multi/popup.html?m=popup-1` | popup opened with `window.open` |
| `GET /multi/blank.html?m=blank-1` | `target=_blank` link (auto-clicked at 200 ms; also clickable via CDP) |
| `GET /multi/iframe.html?m=oopif-1` | iframe from a **different origin** (`http://localhost:<port>` × `http://127.0.0.1:<port>`), OOPIF |
| `GET /multi/worker.js` | dedicated worker (`Worker`) |
| `GET /multi/sw.js` | service worker scoped to `/multi/` |
| `GET /multi/beacon?m=...` | probe GET; deterministic JSON with marker, headers and body |
| `POST /multi/ping?m=...` | probe POST (known body); JSON with `body_text` and `body_sha256` |
| `GET /multi/sw-fetch?m=sw-intercept-1` | request intercepted by the service worker (it makes the network `fetch`) |

Markers that `multi.jsonl` shows when `/multi/` is opened (`?auto=0` turns off
automatic firing):

| Target type | Markers | Known POST body |
|---|---|---|
| main page | `main-1`, `main-post-1` | `main-post-body-1` |
| popup (`window.open`) | `popup-1` (navigation), `popup-get-1`, `popup-post-1` | `popup-post-body-1` |
| `target=_blank` | `blank-1` (navigation), `blank-get-1`, `blank-post-1` | `blank-post-body-1` |
| iframe OOPIF (different origin) | `oopif-1` (navigation), `oopif-get-1`, `oopif-post-1` | `oopif-post-body-1` |
| dedicated worker | `worker-get-1`, `worker-post-1` | `worker-post-body-1` |
| service worker | `sw-intercept-1` (forwarded), `sw-own-1`, `sw-own-post-1` | `sw-own-post-body-1` |

The iframe uses `http://localhost:<port>` by default (same port as the server,
different origin and site, which forces an OOPIF). To point it at another
origin, use `/multi/?oopif=http://127.0.0.1:PORT`. The page is only practical on
the h1 server (plain-text HTTP); on h2/h3 the iframe needs an explicit `?oopif=`.

The service worker intercepts `/multi/sw-fetch`, makes its own `fetch`
(`sw-own-1`, `sw-own-post-1`) and forwards the intercepted request to the network
as `/multi/sw-fetch?m=sw-intercept-1&passthrough=1`. Note: the first load is not
controlled until `clients.claim()`; the page waits for the controller before the
fetch, and a reload also resolves it.

`multi.jsonl` (`scrapelens.testserver.multi/1`), one line per request to
`/multi/...`:

```json
{"schema":"scrapelens.testserver.multi/1","ts_rfc3339":"...","marker":"worker-post-1",
 "server":"127.0.0.1:8781","conn":"c7","method":"POST","target":"/multi/ping?m=worker-post-1",
 "headers":[["Host","127.0.0.1:8781"],["Content-Length","20"],["..."],["..."],
 "body_b64":"d29ya2VyLXBvc3QtYm9keS0x","body_text":"worker-post-body-1","body_len":20,
 "response":{"status":200,"body_len":1255,"body":"{...}"}}
```

`headers` is the ordered list as received (duplicates preserved, never a map);
the line also goes to the normal `h1.jsonl`/`h2.jsonl`/`h3.jsonl`, with the
`marker` field. Test: `cargo test multi_target_page_marks_every_request_kind`.

## Local proxies (`proxy`)

Loopback-only test proxies for the proxy-link contract. Synthetic credentials
only; never a real proxy. Each connection appends one JSON line to the evidence
file. The proxy writes no credentials anywhere.

| Kind | Default port | Protocol |
|---|---|---|
| `http` | 8791 | `CONNECT host:port` and absolute-URI `GET http://…`; optional `Basic` auth |
| `https` | 8792 | the same HTTP proxy, reached over TLS (fixture certificate, trusted via `fixtures/tls/scrapelens-test-ca.crt.pem`) |
| `socks5` | 8793 | SOCKS5 `CONNECT`: no auth, or RFC 1929 username/password; domains resolved by the proxy |

```sh
cd testserver
# no auth, evidence and tunnel dump
cargo run -- proxy --kind http --port 8791 --evidence /path/http.jsonl --tunnel-dump /path/tunnel
# with auth: the value comes from the environment, never from argv
SCRAPELENS_TESTPROXY_AUTH=user:pass cargo run -- proxy --kind http --port 8791 \
  --evidence /path/http.jsonl --auth-env SCRAPELENS_TESTPROXY_AUTH
cargo run -- proxy --kind https --port 8792 --evidence /path/https.jsonl --auth-env SCRAPELENS_TESTPROXY_AUTH
cargo run -- proxy --kind socks5 --port 8793 --evidence /path/socks5.jsonl --auth-env SCRAPELENS_TESTPROXY_AUTH
# forced failures
cargo run -- proxy --kind http --evidence /path/f.jsonl --reject-auth          # 407 for every client
cargo run -- proxy --kind http --evidence /path/f.jsonl --deny 127.0.0.1:8801  # 403 / SOCKS 02
cargo run -- proxy --kind http --evidence /path/f.jsonl --drop before-reply     # close, no reply
cargo run -- proxy --kind http --evidence /path/f.jsonl --drop after-reply      # 200 then close
```

Clients (curl, independent of the Rust tests):

```sh
curl -x http://127.0.0.1:8791 --proxy-user user:pass http://127.0.0.1:8801/
curl --proxy https://127.0.0.1:8792 --proxy-cacert fixtures/tls/scrapelens-test-ca.crt.pem \
  --proxy-user user:pass -p http://127.0.0.1:8801/
curl --socks5-hostname 127.0.0.1:8793 --proxy-user user:pass http://localhost:8801/
```

Tests: `cargo test --test proxy` (24 tests: relay bytes, 407 / SOCKS auth failures,
deny, drops, HTTPS, absolute-URI, dump, redaction).

Evidence (`scrapelens.testproxy.evidence/1`, one line per connection):

```json
{"schema":"scrapelens.testproxy.evidence/1","seq":2,"ts_rfc3339":"2026-11-06T01:15:03.120Z",
 "ts_unix_ms":1793000000000,"conn":"c3","kind":"http","listen":"127.0.0.1:8791",
 "protocol":"CONNECT","target":"127.0.0.1:8801","target_kind":"host-port",
 "auth":{"required":true,"presented":true,"method":"basic","ok":true},
 "result":"relayed","reply_code":200,"bytes_up":86,"bytes_down":196,
 "sha256_up":"…","sha256_down":"…","duration_ms":41,"notes":[]}
```

- `target_kind`: `host-port`, `absolute-uri`, `socks-domain`, `socks-ipv4`, `socks-ipv6`.
- `result`: `relayed`, `auth_failed`, `target_refused`, `dropped_before_reply`,
  `dropped_after_reply`, `upstream_failed`, `relay_error`, `bad_request`,
  `no_acceptable_method`, `unsupported`, `client_error`, `io_error`.
- `reply_code`: HTTP status, or the SOCKS5 reply code for `socks5` (`0` = success).
- `auth.method`: `none`, `basic`, `socks5-userpass`. The username is never recorded.
- Absolute-URI requests: `Proxy-Authorization` is removed and `Connection: close`
  is added; the forwarded head is the first `up` bytes (counted and dumped).

`--tunnel-dump DIR` writes `<conn>.up.bin` and `<conn>.down.bin`: the exact bytes
that crossed the relay, so they can be compared with what the client sent and what
the origin answered.
