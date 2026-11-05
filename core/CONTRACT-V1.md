# ScrapeLens — session format v1 (core implementation)

This document describes the JSON produced/consumed by `core/`. It follows
`docs/03-contracts.md` and the matrix `docs/02-fidelity-matrix.md`; in case of
divergence, the official docs prevail.

## Directory

```
<session>/
  session.json        # full document (metadata + requests + entities + warnings)
  cdp-events.jsonl    # raw CDP events, one JSON per line (optional)
  netlog.json         # original Chrome NetLog (optional)
  attachments/        # bodies, relative names cited in body.attachment
```

`session.json` is self-sufficient for the UI. The raw artifacts are kept
alongside for auditing and are never rewritten by the importer. Core writes:
directory `0700`, files `0600`, atomic rename.

## Document

```json
{
  "schemaVersion": 1,
  "session": {
    "id": "cdp-6f...",
    "browser": { "name": "Chrome", "version": "156.0.8078.48", "platform": "macOS arm64" },
    "startedAt": "2026-10-26T20:50:05.949Z",
    "endedAt": null,
    "completeness": {
      "state": "complete",
      "reasons": [],
      "counts": {
        "requests": 12, "attempts": 12, "redirects": 0,
        "connections": 1, "streamSessions": 2,
        "sourceEvents": 1845, "sourceEventsUsed": 122,
        "sourceEventsUnknown": 0, "warnings": 1
      }
    },
    "capture": { "mode": "cdp+netlog", "headless": true },
    "labels": [],
    "notes": []
  },
  "requests": [ /* LogicalRequest */ ],
  "connections": [ /* Connection */ ],
  "streamSessions": [ /* StreamSession */ ],
  "warnings": [ /* Warning */ ]
}
```

- `completeness.state`: `complete | partial`. `partial` means an interrupted
  capture, a missing/invalid artifact, or a parse error. Correlation ambiguity
  is a `match` state, it does not downgrade `completeness`.
  `reasons` explains each case; completeness inference is never silent.
- `labels`: `synthetic-fixture` in fixtures; `sanitized` in sanitized export;
  `har-import`/`netlog-import` in the corresponding importers.
- `completeness.counts.sourceEvents*` is persisted by HAR/NetLog/CDP and
  survives closing and reopening the session; it is not just an import warning.
- `warnings`: persisted list of everything that was unknown, omitted or
  truncated. `severity` is `info | warning | error`.

## HeaderView

Headers are **ordered arrays of pairs**, never a dictionary. Duplicates and the
original casing are preserved. Pseudoheaders are kept in a separate list.

```json
{
  "pseudoHeaders": [
    { "name": ":method", "value": "GET", "source": "netlog", "method": "netlog.headers", "verification": "partial", "event": "HTTP2_SESSION_SEND_HEADERS" }
  ],
  "headers": [
    { "name": "x-rep", "value": "a", "source": "netlog", "method": "netlog.headers", "verification": "partial" },
    { "name": "X-Rep", "value": "b", "source": "netlog", "method": "netlog.headers", "verification": "partial" }
  ],
  "startLine": "GET /x HTTP/1.1",
  "rawBlock": "GET /x HTTP/1.1\r\nx-rep: a\r\n...",
  "orderState": "sourceOrder",
  "notes": []
}
```

- `orderState`: `sourceOrder | reconstructed | normalized | unknown`.
- `rawBlock` is the original text when the source provides it (h1 `headersText` of
  CDP or the h1 request line of NetLog); in the other events the ordered pairs
  already are the original and are not duplicated. Normalized views **do not**
  replace this block.
- Each header carries `provenance` (fields flattened into the object itself):
  `source`, `event?`, `sourceId?`, `timestamp?` (seconds), `wallTime?`,
  `browserVersion?`, `method`, `verification`, `notes?`.
- `verification` is **per piece of information**: `verified | partial | unverified`.
  There is never a session-wide seal. The policy lives in
  `core/src/model/provenance.rs::policy` and reproduces D2.

## Cookie and Set-Cookie

```json
"cookie": {
  "raw": ["sl_a=1; sl_b=2; sl_c=3"],
  "pairs": [
    { "name": "sl_a", "value": "1", "raw": "sl_a=1", "source": "netlog", "method": "netlog.headers", "verification": "partial" }
  ],
  "wireLines": ["sl_a=1"],
  "unparsed": [],
  "notes": ["linhas do fio ..."],
  "provenance": { "source": "netlog", "method": "netlog.headers", "verification": "partial" }
}
```

- `raw` preserves the source field (0..N fields).
- `pairs` are the internally parsed pairs, with the original text of each pair.
- `wireLines` are the `Cookie` lines observed in the source. NetLog may show
  1 field while the h3 wire carries N (cookie crumble); the core **does not invent**
  the fields the source does not show — it records the limitation in `notes`.
- `Set-Cookie`: `{ "raw": "...", "parsed": { name, value, domain?, path?,
  expires?, maxAge?, secure, httpOnly, sameSite?, partitioned, extensions?,
  notes? }, "parseError?", ...provenance }`. Repeated raw lines are
  separate records, in order.

## Entities

### LogicalRequest

```json
{
  "id": "cdp-r0001",
  "url": "https://demo.invalid/x",
  "method": "GET",
  "protocol": "h2",
  "status": 200,
  "resourceType": "document",
  "cdp": { "requestId": "95631.6", "loaderId": "...", "frameId": "..." },
  "netlog": { "sourceIds": [77], "streamIds": [1], "dependencyIds": [84] },
  "attempts": [ /* Attempt */ ],
  "redirects": [ /* Redirect */ ],
  "requestHeaders": { /* HeaderView of the final attempt */ },
  "responseHeaders": { /* HeaderView */ },
  "cookie": { /* CookieField */ },
  "setCookies": [ /* SetCookieRecord */ ],
  "requestBody": { /* Body */ },
  "responseBody": { /* Body */ },
  "timings": { "requestTime": 5640473.315, "totalMs": 120.0, "estimated": false },
  "match": "matched",
  "matchCandidates": [],
  "provenance": { /* Provenance */ }
}
```

`match`: `matched | ambiguous | unmatched`. `ambiguous` always carries
`matchCandidates` with `entityId`, `score` and `reasons`; no candidate is
chosen silently. `requestHeaders`/`responseHeaders` at the logical level are the
**selected primary view**; every original stays in `attempts[].headerEvidence`.

`networkState` (optional, additive; `schemaVersion` stays 1): `not-sent`. Set on a
request and on its attempt only when the NetLog proves that the request never
reached the network: the URL_REQUEST was cancelled (or failed) and no
`HTTP_TRANSACTION_SEND_REQUEST` and no stream binding was recorded for its source.
Absent otherwise, and absent in sessions saved before this field. A not-sent
attempt has no protocol: `protocol` stays `unknown` and is never copied from a
neighbouring request or from the same host. Its `provenance.notes` line names the
NetLog source id, the cancel time and the absence of a send event. A CDP attempt
pairs with a not-sent NetLog attempt only under the usual rules (method, URL,
time window, uniqueness) and only when it has no status and ended `aborted` or
`failed`; a request with a status never takes it. Such pairs are counted in the
`correlate.not_sent` info warning, not in `correlate.unmatched`.

### Attempt

Fields of `LogicalRequest` that vary per attempt (`url`, `method`,
`protocol`, `status`, `requestHeaders`, `responseHeaders`, `cookie`,
`setCookies`, `requestBody`, `responseBody`, bodies, `timings`,
`headerEvidence`, `connectionId`, `streamSessionId`, `failure`, `outcome`,
`match`). `outcome`: `completed | failed | aborted | pending | unknown`.

### Redirect / Connection / StreamSession

- `Redirect`: `{ id, logicalId, fromAttemptId, toAttemptId?, status?, location?,
  fromUrl, toUrl?, provenance }`.
- `Connection`: `{ id, netlogId?, protocol, host?, port?, ip?, alpn?,
  tlsVersion?, reused?, provenance }`.
- `StreamSession`: `{ id, connectionId?, protocol, streamId?, attemptId?,
  netlogSessionId?, provenance }`.

`headerEvidence[]`: `{ id, role: "request"|"response", protocol, event,
sourceId?, streamId?, view }`. It keeps the block from each source (CDP Blink,
CDP ExtraInfo, NetLog transactional, NetLog session) even after the primary
view moves from one source to another.

## Body

```json
{ "state": "captured", "attachment": "req-1.request.bin", "bytes": 42,
  "truncatedAt": null, "contentType": "application/json",
  "contentEncoding": null, "note": null, "provenance": { ... } }
```

`state`: `captured | empty | truncated | unavailable | discarded`. Absence of a
body **does not** mean empty: use `empty` only when the source states 0 bytes;
`unavailable` and `discarded` have a `note`. `attachment` is relative to
`attachments/` and is validated against path traversal on read.

## Verification rules (D2 summary)

| Information | Source | State |
|---|---|---|
| request h1 order+duplicates | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | verified |
| response h1/h2/h3 order+duplicates | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | verified |
| request h2/h3 order | NetLog session/transaction | partial (Cookie may be merged in the log) |
| response h2/h3 repetitions | NetLog session, NUL expanded | partial |
| response h1 `headersText` | CDP ExtraInfo | verified |
| CDP `headers` objects | CDP | unverified (ASCII, duplicates collapsed) |
| HAR | HAR 1.2 | unverified (order not proven) |

The core expands the `\x00` repetitions of h2/h3 session events and re-splits
`Set-Cookie` merged by `\n` in the CDP object only for parsing, preserving the
original raw value in the `HeaderView`.

## Rust API

```rust
use scrapelens_core::{import_har, import_netlog, import_session_dir};
use scrapelens_core::parse::import_capture;
use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::store::write_session_dir;
use scrapelens_core::normalize::normalize_request;
use scrapelens_core::diff::{diff_requests, DiffOptions};
use scrapelens_core::export::curl::to_curl;
use scrapelens_core::export::python::to_python;
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
```

Each importer returns `ImportedSession { bundle, report }`; `bundle.session` is
`SessionV1`, `bundle.attachments` are the loaded bytes, and `report` carries the
import counts/warnings. No function opens a network connection.

## CLI

```
scrapelens-core inspect <session>
scrapelens-core import-har <har> --out <session>
scrapelens-core import-netlog <netlog> --out <session>
scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <session>
scrapelens-core export-curl <session> <requestId> [--out file]
scrapelens-core export-python <session> <requestId> [--out file]
scrapelens-core sanitize <session> <output>
scrapelens-core diff <session> <requestIdA> <requestIdB>
```

## Explicit limits

- cURL/Python exporters reproduce the HTTP request, **not** TLS, JA3/JA4,
  frame order, HPACK/QPACK or the browser fingerprint.
- cURL uses bash/POSIX quoting (`$'...'` for control bytes). Headers with
  CR/LF/NUL are discarded with a warning; `Content-Length` is removed when the
  body does not accompany the export.
- Sanitization is **heuristic**: it covers known parameter/header names
  (`token`, `sid`, `jsessionid`, `phpsessid`, ...), authentication prefixes
  (`Bearer`, `Basic`, `Digest`, `Token`) and structured bodies. It does not detect
  tokens embedded in path segments, free-form HTML/JS or unstructured text; these
  bodies are omitted with a warning. Header/cookie names and counts are preserved
  for auditing. Session notes and connection metadata are preserved; review them
  before sharing.
- HAR does not prove order/duplicates; NetLog h3 shows a merged Cookie, although
  the wire may carry N fields.
- The standalone NetLog does not prove CDP session coverage; the resulting session
  stays `partial` until it is correlated with a CDP capture.
