# 19 — App session contract (P5)

Round 13, wave 1. Applies proposal P5 of `docs/18-large-session-memory.md` §5:
the App stops building the session's `serde_json::Value` and sending it whole to the front end.

## Principle

- The backend reads `session.json` **typed** (`SessionV1`) through the core's `open_session_dir_lazy` and
  keeps it in the `cached_session` cache (up to two sessions; the same cache as search,
  origins, chain, comparison and export). Bodies and raw CDP/NetLog stay
  on disk.
- The front end receives only the **header**, asks for the list in **pages of summaries** and the
  **detail** of a request when it is opened.
- Quick search, filters and counts run in the backend (`src-tauri/src/listing.rs`).
  Payload search remains in `search_session`; the ids found enter the filter.

## Commands

### `open_session(path)` → `SessionPayload`

`path` is a folder with `session.json` or a session file with any name
(absolute path, regular file, no symlink in any component). In the file case,
`sessionDir` is the file itself and the attachments are read from its folder.

Also returned by `import_har`, `import_netlog` and `stop_session`.

```jsonc
{
  "session": {               // SessionHeader
    "schemaVersion": 1,
    "session": { /* SessionMeta v1: id, startedAt, browser, completeness, labels, capture… */ },
    "requests": [],          // always empty in the paginated contract
    "warnings": [ /* session warnings only (without `entity`) */ ],
    "requestCount": 20002,   // presence of this field = paginated session
    "sources": ["cdp", "netlog"]
  },
  "sessionDir": "/…/sessions/capture-…",
  "synthetic": false,
  "notice": "Session opened: 20002 request(s).",
  "pending": false
}
```

`demo_session` and `start_session` (capture in progress) keep returning the
in-memory v1 document, without `requestCount`: the front end treats them as in-memory sessions.

### `list_requests(sessionDir, offset, limit, filter?)` → `RequestPage`

`limit` ranges from 1 to 2000. `filter` (all optional):

| Field | Values | Rule |
|---|---|---|
| `typeFilter` | `all` `fetch` `document` `media` `error` | `fetch` = fetch+xhr; `media` = image+font; `error` = status ≥ 400 |
| `protocol` | `all` `HTTP/1.1` `HTTP/2` `HTTP/3` `unknown` (legacy `desconhecido`, still accepted) | label of `protocol` (h1/h2/h3) |
| `target` | `all` `page` `popup` `iframe` `worker` `service_worker` `shared_worker` `netlog_unknown` | only applies when the session shows targets |
| `query` | text | URL, id, method (equal) or status; lowercase |
| `payloadSearch` + `matchIds` | bool + ids | with payload search active, the URL no longer applies and the ids found by `search_session` pass |
| `restrictIds` | ids or `null` | verdict filters (application failure / possible block) |

```jsonc
{
  "total": 20002, "matched": 20002, "offset": 0,
  "items": [
    { "id": "cdp-r0001", "url": "http://localhost:58304/r/8?v=1", "method": "GET",
      "status": 200, "protocol": "h1", "resourceType": "Fetch",
      "wallTime": "2026-11-02T18:40:35.707Z", "totalMs": 10.008,
      "initiator": { "kind": "script" }, "target": 0, "source": "cdp", "warningCount": 0 }
  ],
  "targets": [ { "targetId": "…", "kind": "page", "url": "http://localhost:58304/", "attached": true } ],
  "counts": { "all": 20002, "fetch": 20002, "document": 0, "media": 0, "error": 0 },
  "targetCounts": { "all": 20002, "page": 20002, "…": 0 },
  "hasTargets": true
}
```

- The summary fields are **raw** from v1. Labels (domain, path, type, protocol,
  target, "unknown target (NetLog only)") are derived in the front end by `summaryFromRaw`
  (`app/src/v1/adapter.ts`), with the same rules as `adaptSession`.
- `target` is the index into `targets`: the repeated target goes once per page.
- `estimated: true` appears when `timings.estimated`; the list shows "≈".
- `counts`, `targetCounts` and `hasTargets` are for the whole session, unfiltered.

### `get_request(sessionDir, id)` → `RequestDetail`

```jsonc
{ "request": { /* complete v1 LogicalRequest */ },
  "warnings": [ /* warnings with entity = id */ ],
  "streamSessions": [ /* StreamSessions of the attempts, for protocol verification */ ] }
```

The front end adapts with `adaptRequestDetail(header, detail)`, which calls the same
`adaptSession` on a one-request session. The `npm run test:paged` test
checks, on the demonstration fixture, that the detail and the summary are equal to the
result of the whole-session adapter.

## Front end

- The existing virtualized list (34 px rows, overscan 6) now renders
  the summaries. The front end loads all the session's summaries in pages of 2000 for
  selectors, timeline and "Limits" (~5 MiB at 20 thousand requests) and asks the backend for the filtered
  list on every filter change (120 ms debounce).
- Detail, export and side-by-side comparison use the complete `RequestRecord`,
  loaded by `get_request` (the comparison loads A and B).
- In-memory sessions (demonstration, browser mode, `?demo=large`) use the same
  summaries, derived locally by `summaryOfRecord`, and the equivalent local filter.

## Memory (session of 20.002 captured requests, docs/18)

Measured with `src-tauri/examples/mem_open.rs` (one mode per process, `--release`,
macOS arm64, RSS peak by `getrusage`), on `/tmp/big20k` (`session.json` of 1,19 GB):

| Path | RSS peak | Sent to the front end |
|---|---:|---:|
| old (`read_to_string` + `Value` + serialization) | **7.108 MiB** | 681 MB |
| new: open typed + header + all pages + one detail | **1.161 MiB** | 1,4 KB + 5,4 MB (all pages) + 32 KB |

- Goal of the round: open the 20-thousand session with a peak below 1,5 GiB. Met
  in the backend (1.161 MiB, −84 %).
- Summary: 268 B per row on average, with the page overhead; a single row is
  ~240 B (URL and `wallTime` dominate). It is above the 100 to 200 B estimate of docs/18.
- Time: the typed read takes ~9,9 s, against ~4,4 s for the old path, which uses more
  memory. The 11 pages of `list_requests`, with header and detail, take ~70 ms.
  `open_session`, `import_*` and `stop_session` run in `spawn_blocking`, and the interface
  does not freeze. Open and import use the `loading` signal, which refuses a second
  one in parallel; the screen shows an indicator during the read and the list load.
- What dominates is the typed `SessionV1` (~1.160 MiB, like the `lazy` of docs/18). P6/P8
  would reduce that in the core.
- Not measured: the WebView memory. The summaries of 20 thousand requests add up to ~5 MB of
  JSON in the transfer.

Reproduce:

```
cd src-tauri && cargo build --release --example mem_open
./target/release/examples/mem_open paged  /tmp/big20k
./target/release/examples/mem_open legacy /tmp/big20k
```
