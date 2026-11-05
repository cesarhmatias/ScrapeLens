# Fidelity matrix — header order and repetition

Central question: **which sources and events preserve which header sequence in
each protocol and browser version?**

Fill in by controlled experiment. Each row requires evidence (experiment file +
capture). No evidence = "not verified".

## Measured environment

| Item | Value |
|---|---|
| Browser | Chrome `156.0.8078.48` (headless=new, dedicated temporary profile) |
| OS | macOS `26.5.2` (25F84), arm64 |
| Date | 2026-10-26 |
| Protocols | HTTP/1.1 (`127.0.0.1:8781`), h2/TLS+ALPN (`:8782`), h3/QUIC (`:8783`) |
| Reference (layer c) | local server that writes the decoded pairs to JSONL, without a dictionary |
| Sample | 15 experiments, **60 requests** analyzed (20 per protocol) |
| Reproduction | `cd experiments && .venv/bin/python run_experiment.py --all && .venv/bin/python compare.py` |

h3 worked in this environment against the mock's `aioquic` server (QUIC enabled,
`--origin-to-force-quic-on=127.0.0.1:8783`, self-signed certificate waived
by SPKI hash — nothing installed). Against the contract server (`quiche`) h3
is blocked: see "Cross-check" below.

## Quick verdict

`✓` preserves · `~` preserves with partial loss · `—` does not preserve

| Source / event | h1 order | h1 duplicates | h2 order | h2 duplicates | h3 order | h3 duplicates |
|---|---|---|---|---|---|---|
| CDP `requestWillBeSent.request.headers` | — (subset) | — | — (subset) | — | — (subset) | — |
| CDP `requestWillBeSentExtraInfo.headers` | — | — | — | — | — | — |
| CDP `responseReceivedExtraInfo.headersText` | ✓ | ✓ | n/a | n/a | n/a | n/a |
| CDP `responseReceivedExtraInfo.headers` | — | — | — | — | — | — |
| NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | ✓ | ✓ | n/a | n/a | n/a | n/a |
| NetLog `HTTP2_SESSION_SEND_HEADERS` | n/a | n/a | ~ (1 swap) | ~ (`cookie` may be split) | n/a | n/a |
| NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | n/a | n/a | n/a | n/a | ✓ | — (`cookie` field split on the wire) |
| NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NetLog `HTTP2_SESSION_RECV_HEADERS` | n/a | n/a | ✓ | ~ (`\x00`) | n/a | n/a |
| NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | n/a | n/a | n/a | n/a | ✓ | ~ (`\x00`) |
| HAR (DevTools exporter) | not verified | not verified | not verified | not verified | not verified | not verified |

`n/a` = does not apply to the protocol. Detail and evidence per row below.

Two caveats that apply to the table above:
`cookie` and `priority` swap position on the h2 wire (the log shows `cookie` first);
and the fragmentation of `Cookie` into several fields in h2 is **conditional** — 1 field
with 2–3 cookies on the mock, N fields with 3–4 cookies on the contract.

## Main matrix

Orders separated into three columns, as required:
**(a)** order presented by the source · **(b)** order delivered to the encoder
(HPACK/QPACK/HTTP line) · **(c)** decoded order observed on the server.

| Browser | Protocol | Source/event | (a) source order | (b) to the encoder | (c) decoded | Preserves | Observed transformations | Limits | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| 156.0.8078.48 | h1 | CDP `Network.requestWillBeSent` → `request.headers` | JSON object with **5 to 9 headers** depending on the case (5 in 16/20; 6 in the 2 POSTs; 9 in the 2 fetches with `Headers`): in the plain GET `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | not the entry point | `Host, Connection, Pragma, Cache-Control, sec-ch-ua*, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-*, Accept-Encoding, Accept-Language[, Cookie]` | only the set of these headers | **omits** `Host`, `Accept`, `Cookie`, `Accept-Encoding`, `Accept-Language`; and the enumeration **does not follow the wire** (on the wire `sec-ch-ua*` comes before `Upgrade-Insecure-Requests`/`User-Agent`; here it comes after) | not usable for sequence; only to know which headers Blink injected | `results/h1-page/layers.json`, `results/h1-plain/cdp-events.jsonl` |
| 156.0.8078.48 | h1 | CDP `Network.requestWillBeSentExtraInfo` → `headers` | **ASCII/case-sensitive order** (20/20 `sorted_ascii=true`): `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Sec-Fetch-Dest, …, User-Agent, x-mixed-Case, x-rep, x-seq` | not the entry point | actual wire order (above) | complete set of names | sorts by byte; **collapses duplicates** in `net::HttpRequestHeaders` before exposing; surviving value = last | unusable order; duplicate already lost at the origin | `results/h1-ordered/layers.json` (see `cdp_extra.verdict=reordenada`) |
| 156.0.8078.48 | h1 | CDP `Network.responseReceivedExtraInfo` → `headersText` | `HTTP/1.1 200 OK\r\ncontent-type: …\r\nset-cookie: sl_a=1\r\nset-cookie: sl_b=2\r\n…` | — | `content-type, cache-control, x-resp-order×2, set-cookie×2, content-length, connection` | **exact order and duplicates**, original case | none (raw block) | h1 only; response only; text, not structure | `results/h1-page/layers.json` → `response.cdp_headersText.verdict=idêntica` |
| 156.0.8078.48 | h1 | CDP `Network.responseReceivedExtraInfo` → `headers` | object with sorted keys: `cache-control, connection, content-length, content-type, set-cookie, x-resp-order` | — | 2× `set-cookie`, 2× `x-resp-order` | set of names | sorts ASCII; merges duplicates with `\n` (`"sl_a=1; Path=/\nsl_b=2; Path=/"`) | loses order **and** repetition; requires re-splitting on `\n` (loss if the value contains `\n`) | `results/h1-page/layers.json` → `response.cdp_object` |
| 156.0.8078.48 | h1 | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | list `["Host: …", "Connection: …", …, "x-rep: c", …]` | **identical to the wire** (20/20, name and case) | identical | order, case and duplicates | none | per-request event; does not carry the CDP request id (correlation only by URL/method/time) | `results/h1-ordered/chrome-netlog.json`, `results/h1-page/layers.json` |
| 156.0.8078.48 | h1 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | list with status line + pairs | — | identical (20/20), including 2× `set-cookie` and 2× `x-resp-order` | order and duplicates | none | no `requestId`; match by URL/`content-length`/time | `results/h1-page/chrome-netlog.json` |
| 156.0.8078.48 | h2 | CDP `requestWillBeSent.request.headers` | 5–9 Blink headers (same distribution as h1), own order | not the entry point | `:method, :authority, :scheme, :path` + 15–16 fields | only the set | **does not expose pseudoheaders**; omits `Host`/`Cookie`/`Accept`; order ≠ wire | not usable for sequence | `results/h2-page/layers.json` |
| 156.0.8078.48 | h2 | CDP `requestWillBeSentExtraInfo` → `headers` | ASCII (20/20); lowercase names | not the entry point | wire order | set of names | sorts ASCII; collapses duplicates; does **not** represent pseudoheaders | unusable order | `results/h2-page/layers.json` |
| 156.0.8078.48 | h2 | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | list with pseudoheaders `":method", ":authority", ":scheme", ":path"` + fields | same as the session event | wire order, except the `cookie`/`priority` pair | order and duplicates | pseudoheaders appear as text `":path: /x"` | same position swap as the session event | `results/h2-page/chrome-netlog.json` |
| 156.0.8078.48 | h2 | NetLog `HTTP2_SESSION_SEND_HEADERS` | list of pairs in the order sent to HPACK | **layer (b) reference** | **20/20: 7 identical, 13 with `cookie` before `priority`**; the wire has `priority` before `cookie` | order (with 1 exception), case, duplicates | pseudoheaders included; `cookie`/`priority` swap position in the encoding | 1 divergent position when there is a `Cookie` | `results/h2-page/layers.json` (`b_netlog.verdict=reordenada`) |
| 156.0.8078.48 | h2 | NetLog `HTTP2_SESSION_RECV_HEADERS` | list **with duplicates merged by `\x00`**: `"x-resp-order: 1\u00002"`, `"set-cookie: sl_a=1…\u0000sl_b=2…"` | — | 2× `set-cookie`, 2× `x-resp-order`, correct order | order | merges repetitions into a single NUL-separated pair; after expanding, 20/20 identical | a parser that only splits on `\n` loses the 2nd occurrence | `results/h2-page/layers.json` → `response.netlog_session.nul_joined=true` |
| 156.0.8078.48 | h2 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | synthetic `"HTTP/1.1 200"` + **separate** pairs | — | identical (20/20) | order and duplicates | invents an HTTP/1.1 status line for an h2 response | status comes from `HTTP2_SESSION_RECV_HEADERS` (`:status`) | `results/h2-page/layers.json` → `response.netlog_other` |
| 156.0.8078.48 | h3 | CDP `requestWillBeSent.request.headers` | 5–9 Blink headers (same distribution as h1), own order | not the entry point | `:method, :authority, :scheme, :path` + 14–16 fields | only the set | same as h2: no pseudoheaders, order ≠ wire | not usable for sequence | `results/h3-page/layers.json` |
| 156.0.8078.48 | h3 | CDP `requestWillBeSentExtraInfo` → `headers` | ASCII (20/20) | not the entry point | wire order | set of names | sorts; **merges the `cookie` fields into 1** (13/20 diverge only because of this) | order and repetition lost | `results/h3-page/layers.json` (`cdp_extra.verdict=duplicatas fundidas` in 13/20) |
| 156.0.8078.48 | h3 | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | list with `":method" …` and **1** `cookie: sl_a=1; sl_b=2; sl_c=3` | same list as the session event | **3** `cookie` fields (1 per cookie) | overall order | **cookie "crumble"**: QPACK splits the Cookie field into N fields; NetLog shows the unsplit form | `Cookie` count in NetLog ≠ wire; position relative to `priority` preserved | `results/h3-page/layers.json` (`b_netlog.verdict=duplicatas fundidas` 13/20) |
| 156.0.8078.48 | h3 | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | list of pairs + `quic_stream_id`, urgency | **layer (b) reference** | as above | order, case; **not** the cookie split | 1 `cookie` in the log → N on the wire; `priority` at the end | requires cross-checking with the server to know the actual number of Cookie fields | `results/h3-page/chrome-netlog.json` |
| 156.0.8078.48 | h3 | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | pairs with `\x00` on repetitions (`:status` included) | — | 2× `set-cookie` in the written order | order, duplicates after expanding NUL | merges repetitions with `\x00` | same as h2 | `results/h3-page/layers.json` |
| 156.0.8078.48 | h3 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | synthetic status + separate pairs | — | identical (20/20) | order and duplicates | fabricated status | same as h2 | `results/h3-page/layers.json` |
| 156.0.8078.48 | all | **HAR (DevTools exporter)** | **not verified** | — | — | — | `Network.getHAR` does not exist in the CDP of this version; the DevTools HAR exporter is frontend code and was not instrumented | HAR order not proven; any inherited order would be that of `ExtraInfo` (ASCII), with duplicates merged | see "HAR" below; `results/*/har-derived.json` is a labeled reconstruction |

### Cookie: one field in the log, N fields on the wire

| Observation | h1 | h2 (mock) | h2 (contract) | h3 |
|---|---|---|---|---|
| 2 cookies → `cookie` fields on the wire | 1 | 1 | — | 2 |
| 3 cookies (JS) → fields on the wire | 1 | 1 | — | 3 |
| 3 cookies (Set-Cookie + `SameSite=Lax`, same names/values as the contract) → fields on the wire | 1 | 1 | 3 | 3 |
| 4 cookies on the contract → fields on the wire | 1 | — | 4 | — |
| NetLog / CDP show | 1 | 1 | 1 | 1 |

- h1 **never** fragments (1 field with pairs separated by `; `).
- h3 **always** fragments (1 field per cookie).
- h2 is **dependent on the (server/configuration) pair**, not on the set of cookies:
  the *same* 3 cookies (`sc_a=alpha; sc_b=beta; sc_dup=two`, `Path=/;
  SameSite=Lax`) went out as **1 field** against the mock and as **3 fields** against
  the contract server, in the same Chrome. Experiments `*-set3`.
  The server-side factor (the pair's SETTINGS/HPACK) was **not isolated**.
- Proof that the fragmentation happens after the log point: the raw HPACK
  block from the contract (`header_block_b64`) decoded separately contains 3–4
  `cookie` fields, while `requestWillBeSentExtraInfo.headers` carries only **one**.
- Consequence for the product: `Cookie` must be read as a **list of fields**
  (0..N) and joined by name when comparing with what the scraper sent.

### Pseudoheaders: stable order, the same in h2 and h3

Measured in three independent decoders (my `h2`/`aioquic` server,
Chrome's NetLog and the contract's raw HPACK block decoded separately):
`:method, :authority, :scheme, :path` — **the same order in h2 and in h3**, in
all 60 requests. There is no `:scheme`/`:authority` inversion between protocols;
what changes is where each source exposes them (CDP exposes no pseudoheader at all; NetLog
shows `":path: /x"` as text).

Note: the README/message of `testserver/` describes h2 as
`:method, :scheme, :authority, :path`; the JSONL and the `header_block_b64` of
`testserver/` itself show `:method, :authority, :scheme, :path`. The recorded
evidence prevails, not the description.

### Layer (b) ≠ layer (c): concrete examples

h1 — `GET /echo-order?case=ordered`, header list delivered by
`Fetch.continueRequest` (`results/h1-ordered/fetch-decisions.jsonl`):

| (b) list supplied (6 pairs) | (c) decoded on the server (3 pairs) |
|---|---|
| `x-rep: a`, `x-seq: 1`, `X-Rep: b`, `x-seq: 2`, `x-mixed-Case: V`, `x-rep: c` | `x-rep: c`, `x-seq: 2`, `x-mixed-Case: V` |

Chrome deduplicates by case-insensitive name (last value wins) and keeps the
order of first appearance. In other words: **a header supplied to an API is not sent
without transformation** — neither in order nor in repetition.

h1 — `GET /echo-order?from=jsheaders`, Fetch API `Headers` with
`append('x-dup','a')` + `append('x-dup','b')`:
`(c)` shows **one** header `x-dup: a, b`. In addition the insertion order
(`x-zeta, x-alpha, x-mid`) does not survive: the three appear interleaved with
Chrome's headers (`x-zeta, x-alpha, sec-ch-ua*, x-mid, …`).

h2 — `GET /page` with cookies: `(b)` `…, accept-language, cookie, priority`;
`(c)` `…, accept-language, priority, cookie`.

h3 — `GET /page` with 3 cookies: `(b)` `…, cookie: sl_a=1; sl_b=2; sl_c=3, priority`;
`(c)` `…, cookie: sl_a=1, cookie: sl_b=2, cookie: sl_c=3, priority`.

## Counts (60 requests)

| Protocol | NetLog send vs server | CDP `ExtraInfo` vs server |
|---|---|---|
| h1 | 20/20 identical (name and case), duplicates preserved | 20/20 reordered (ASCII) |
| h2 | 7/20 identical; 13/20 reordered (`cookie`/`priority`) | 20/20 reordered (ASCII) |
| h3 | 7/20 identical; 13/20 with merged `cookie` field | 20/20 reordered; 13/20 also with merged `cookie` |

Response (20 per protocol): identical order in 60/60 in the transactional NetLog
event; repetitions merged by `\x00` in 100% of the h2/h3 session events
and preserved in 100% of the transactional events.

## Cross-check against the contract servers

The same pipeline (launcher + CDP + NetLog) was run against `testserver/`
(Rust, `httlib-hpack` for h2 and `quiche` for h3), an implementation
independent of my Python mock. Evidence:
`experiments/results/contract-{h1,h2}/layers.json`; reproducer:
`experiments/crosscheck_contract.py --proto all`.

| Protocol | Requests | NetLog vs server | Note |
|---|---|---|---|
| h1 | 14 | **14/14 identical** (name and case) | confirms the mock row, including duplicated `Set-Cookie` and redirects |
| h2 | 14 | 13/14 with merged `cookie`; 1/14 identical | confirms that NetLog shows **1** `cookie` field and the wire receives 3–4; also confirms the `cookie`/`priority` swap |
| h3 | 0 | **not verified** | Chrome aborts with `ERR_QUIC_PROTOCOL_ERROR`; NetLog shows `TLS handshake failure … CERTIFICATE_VERIFY_FAILED` and an independent `aioquic` client also fails (`h3 poll error: StreamCreationError`) → defect of the contract server, not of the capture |

The 14 contract requests include cases the mock does not have (chained redirects,
two identical simultaneous requests, 128 KiB POST) and NetLog remained
faithful in h1 and faithful-except-cookie in h2.

## HAR

`Network.getHAR` **does not exist** in the CDP of Chrome 156.0.8078.48
(`results/h1-plain/cdp-meta.json` → `harAvailable=false`). The DevTools HAR exporter
runs in the frontend, over the same CDP events; it was not instrumented
in this milestone. Therefore: **order in HAR = not verified**, and the rows above already
show that the raw material the exporter consumes (`requestWillBeSentExtraInfo`)
comes sorted in ASCII and with duplicates already collapsed.

`har_from_cdp.mjs` generates a HAR 1.2 **labeled as a reconstruction** to serve as a
fixture for the importer (`results/h1-page/har-derived.json`). Do not use this file
as proof of order.

## Is the order DevTools shows the one transmitted?

**No, and it cannot be assumed to be.** The DevTools network panel and the HAR
exporter are built on the same CDP events measured here
(`requestWillBeSent` + `requestWillBeSentExtraInfo`). In those events the order is
that of a byte-sorted map (ASCII) and the duplicates have already arrived collapsed in
`net::HttpRequestHeaders` — that is, the list that appears on screen **is not** the
list delivered to the encoder nor the one decoded on the server (h1/h2/h3 rows
above, 60 requests).

For the reference case (WebInspector order of Chromium 141, reproduced
manually with `curl_cffi`):

- Replicating the DevTools order and the call working **does not prove** that the order
  was transmitted: most servers ignore field order, and the
  case itself documents that what was breaking was a dynamic value (SESSIONID/
  STAMP/delta), not header order.
- In h1 the proof exists and is cheap: `HTTP_TRANSACTION_SEND_REQUEST_HEADERS`
  (NetLog) carries the exact order, case and duplicates; in h2/h3 the session
  event carries the list delivered to HPACK/QPACK.
- Without these events, the correct state in the interface and in the export is
  **"transmitted order: not verified"** — never "order preserved".
- Measured in this matrix on Chrome **156**; the case used **141**. The mechanism
  (sorted map in `HttpRequestHeaders`) is the same kind of structure, but 141
  was not measured here — if something must be asserted about 141, run this same
  harness with that build.

2-minute check for the real case, once attribution is available: open the
capture with NetLog, take the application's request (POST Connector) and compare
`HTTP_TRANSACTION_SEND_REQUEST_HEADERS` with the order HAR/DevTools shows.
Order divergence in the HAR is expected; what matters is what NetLog says.

## Multi-target capture (CDP auto-attach × NetLog)

Contract: `docs/14-multi-target-capture.md`. Harness: `experiments/multi_target/`. Page: `testserver` `/multi/` (`7308053`, 16 markers via `./scripts/multi-probe.sh`).

| Item | Value |
|---|---|
| Browser | Chrome `156.0.8078.74`, `headless=new`, temporary profile, `--disable-popup-blocking`, `EXCLUDE localhost` in the resolver |
| CDP | `Target.setDiscoverTargets` + `setAutoAttach` on the **browser connection**, again on the **page session** and **recursive** in each child (`iframe`/`worker`/`service_worker`/`page`) on `Target.attachedToTarget`; **pipeline** `Network.enable` → `Page`/`Runtime` → child `setAutoAttach` → `runIfWaitingForDebugger` when `waitingForDebugger` (resume **after** `Network.enable`; no `Page.enable` in worker/SW; skip `browser_ui`; **one CDP session per `targetId`**, duplicate sessions detached) |
| Aggregated evidence (commit) | `experiments/results/multi-target-official/{analysis,summary}.json` |
| Raw (gitignore) | `cdp-events.jsonl`, `chrome-netlog.json`, `cdp-bodies.jsonl`, `server.jsonl` |

Minimal proof (only `/multi/`, no popup/blank): `python3 multi_target/run_attach_probe.py` → `results/multi-target-attach-probe/compare.json` (Chrome **156.0.8078.74**, headless **and** headful). With `setAutoAttach` on the page session + recursive in the children: `attachedToTarget` **iframe** and **worker**; `oopif-get/post` on the iframe's `sessionId`; `worker-get/post` on the worker's `sessionId` (`commands.jsonl` + `cdp-events.jsonl` local).

Official run `fa1a5a2` (11/16 CDP) used only `setAutoAttach` on the browser root — which explains iframe/worker without attach. Tauri product (`capture.rs`, pipeline `00a9a33`+): **16/16 CDP** in `check_multi_target` (NetLog 16/16, types, POST, SW page+target). Cause of the historical `blank-1`: resuming (`runIfWaitingForDebugger`) **before** `Network.enable` on the `_blank` document session; with the pipeline inverted, `blank-1` has `requestWillBeSent` on the child session.

Historical causes (~33 s / timeout): (1) recursive autoAttach **without** filtering `browser_ui`; (2) `Runtime.evaluate` in the wait loop; (3) paused target without resume; (4) headless `_blank` + `createTarget`; (5) second `openIframe()` after attach.

### Table by target type — variant **with** `waitForDebuggerOnStart`

16/16 markers in the server's `multi.jsonl`. CDP (`requestWillBeSent` + `?m=`): **16/16** (Tauri capture Round 10, post-`00a9a33` pipeline). Legacy diagnosis: `experiments/multi_target/diagnose_gaps.py` → `gap-diagnosis.json` (old runs 11/16). Bodies: POST via `body_text`/`body_b64` in `multi.jsonl`.

#### CDP gaps (with wait) — hypothesis tested

| Marker | Verdict | Evidence (official run, Chrome 156.0.8078.74) |
|---|---|---|
| `blank-1` (document) | **Closed (Tauri product)** | With the Network→resume pipeline on the child session (`00a9a33`), `requestWillBeSent` of the document on the `_blank` session; `blank-get/post` on the same session. Old runs (resume before Network) only had `responseReceived` without `requestWillBeSent`. |
| `oopif-get-1` / `oopif-post-1` | **Closed (harness)** | Official run: no iframe attach. Recursive proof: `attachedToTarget` type=iframe (`parentSession`=page); `Network.requestWillBeSent` get/post on the **same sessionId** (headless + headful). |
| `worker-get-1` / `worker-post-1` | **Closed (harness)** | Official run: 0 worker attach. Recursive proof: worker attach; get/post on the worker session after `Network.enable` + `runIfWaitingForDebugger` (headless + headful). |
| Header order (targets with CDP) | **No new finding** | Same as the general matrix: ExtraInfo does **not** preserve wire order; transmitted order → NetLog / `headersText` (h1). Set of names aligned with the server. |
| Run metadata (`cdp-sessions`, `plan`, `run-meta`) | **Closed** | Execution output → `experiments/.gitignore`; removed from the git index (commit aggregates only `analysis.json`, `summary.json`, `gap-diagnosis.json`). |

| Type | Server | NetLog | CDP | ExtraInfo × server | Bodies |
|---|---|---|---|---|---|
| Main (`main-*`) | ✓ | ✓ | ✓ | same set; ExtraInfo order ≠ wire | ✓ POST (server) |
| Popup | ✓ | ✓ | ✓ child `page` session | same set; order ≠ wire | ✓ POST |
| `_blank` | ✓ | ✓ | ✓ (`blank-1` doc + GET/POST on the child session) | GET/POST: set ok | ✓ POST |
| OOPIF | ✓ | ✓ | ✓ get/post on the `iframe` session | doc: n/a | ✓ POST (server) |
| Worker | ✓ | ✓ | ✓ get/post on the `worker` session | n/a | server |
| SW intercept (`sw-intercept-1`) | ✓ | ✓ | ✓ **page + SW** | n/a (SW path) | server |
| SW own fetch (`sw-own-*`) | ✓ | ✓ | ✓ `service_worker` session | set ok | ✓ POST (server) |

**Service worker (detail):** `sw-intercept-1` appears on the **page** (`fromServiceWorker: true`, `serviceWorkerResponseSource: fallback-code`) and on the **service_worker** target (forwarded fetch). `sw-own-1` / `sw-own-post-1` only on the **service_worker** target (`fromServiceWorker: false`). Dedupe by `targetId`: one session records network; auto-attach re-attaches detach the extra session (avoids 3–4 copies per marker).

### Variant **without** `waitForDebuggerOnStart`

Server: **8/16** (popup/worker/SW missing). CDP: main + `_blank` + OOPIF doc; popups and worker/SW do not attach in time. Loss of the isolated "first request" per marker: **not verified** (compare popup-1 between variants manually in the raw files).

### `requestId` collision

Several `(requestId)` pairs repeated across sessions → key **`(sessionId, requestId)`**.

### Cost (with wait, official run)

~12 CDP sessions, ~170 s of capture (waiting for up to 16 markers in `multi.jsonl`).

Reproduction: `cd experiments && python3 multi_target/run_multi.py --testserver --port 8781 --out results/multi-target-official`.

**Recommendation:** auto-attach with wait on the **page** + recursive in iframe/worker/SW; **`Network.enable` before `runIfWaitingForDebugger`** on the child session; one session per `targetId`; key `(sessionId, requestId)`; header order → NetLog, not ExtraInfo.

## Limits

- Everything in `headless=new`. Chrome's header behavior is the same in headed
  in the project's earlier tests, but **was not measured here** with a visible window.
- h3 required `--origin-to-force-quic-on`; Alt-Svc was not used (avoids silent
  h2→h3 migration in the middle of the experiment). Without this flag Chrome would use h2.
- Each session uses an isolated NetLog (`--host-resolver-rules` blocks external DNS),
  but the browser's own background events still appear in the file; the
  comparator filters by URL/`content-length`.
- CDP↔NetLog correlation is done by URL+method+`content-length`(+presence of
  `set-cookie`); the IDs are not equivalent. In the 60 cases the answer was
  unambiguous, but the tool
  must treat ambiguity as ambiguous (see `b_netlog.candidates`).
- `Fetch.continueRequest` was used only to *inject* order/duplicates, it is not a
  capture mechanism of the product.
- `QUIC` with 0-RTT or retry was not measured. Identical simultaneous requests
  were exercised only on the contract server (h1/h2), where correlation
  by URL+method+order of occurrence remained unambiguous.
- h3 against the contract server is blocked (see above); the h3 row of this
  matrix comes from the mock's `aioquic` server.
- The trigger of `Cookie` fragmentation in h2 was not isolated.

## Rules

- Do not assume: HAR preserves order; CDP enumeration = transmitted sequence;
  NetLog event = final sequence; library headers are sent without
  transformation; 403 comes from header order.
- A server reference must observe the raw order at the decoding point
  (a normalized dictionary does not work).
- Distinguish request header order from the order of packets/frames/
  concurrent requests.
- If the transmitted sequence cannot be proven: record "not
  verified" and proceed with independent features.
