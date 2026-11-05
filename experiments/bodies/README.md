# Bodies in the live capture (`cdp-bodies.jsonl`)

Checks `src-tauri/src/capture.rs` against the local `testserver` h1 (Chrome 156,
127.0.0.1, synthetic data, no external network).

```bash
cd experiments/bodies && python3 run_bodies.py        # port 9781; ~15 s
```

`run_bodies.py` starts the testserver, runs `cargo test live_bodies_cycle --ignored`
(real capture), drives the same-origin page through a second CDP client
(`drive.mjs`) and compares three independent sources: what the page sent/received
(sha256), what the server recorded (`/sink`) or serves (bytes regenerated in the
verifier) and `cdp-bodies.jsonl`. Output goes to `../results/bodies/`
(`verification.json`, `report.md`, `sample-lines.jsonl`; with `--keep` the session and the NetLog,
hundreds of MB, stay in `session/` and `server/`, ignored by git; without `--keep` they are deleted at the end).

## Result (Chrome 156.0.8078.73, h1)

| case | recorded state | bytes |
|---|---|---|
| POST form-urlencoded | req `captured` utf8 (postDataEntries) | = sent = server |
| POST JSON | req `captured` utf8 | = sent = server |
| POST binary (0xFF 0xC0 0x00…) | req `captured` base64 | = sent = server |
| binary echo | response `captured` base64 | = served |
| POST 6 MiB text / binary | req `truncated`, `originalSize` 6291456, 5242880 recorded | prefix = sent |
| GET 6 MiB | response `truncated`, same sizes | prefix = served |
| gzip | response `captured` utf8 | = served, already decoded by Chrome |
| 302 | attempt 0 `unavailable` ("redirect response…" (legacy: "resposta de redirect…")); attempt 1 `captured` | attempt 1 = served |
| 307 with body | request body `captured` in both attempts; response 0 `unavailable` | equal to each other and to the sent bytes |
| 204 / Content-Length: 0 | `empty` with the evidence in `reason` | — |
| refused connection | `unavailable` "loadingFailed: net::ERR_CONNECTION_REFUSED" | — |

## What CDP does not provide (observed)

- **`request.postData` is lossy for binary**: Chrome converts it to a string and
  invalid bytes become U+FFFD (4099 bytes sent → 6149 in UTF-8). That is why
  `postDataEntries` (exact bytes) takes priority; `postData` is only used without entries.
- **6 MiB body is not in the event (exact threshold not measured)**: only `hasPostData`; the bytes come from
  `Network.getRequestPostData` (binary came back with `base64Encoded:true`, exact).
- **Redirect response body**: does not exist (`getResponseBody` does not serve it).
- **gzip**: only the already decoded body; the wire bytes are not accessible.
- **`empty`** requires 204/205/304, HEAD or `Content-Length: 0` seen in the CDP headers;
  0 bytes without that becomes `unavailable`.
- Not exercised live (the testserver does not have the endpoint): SSE, WebSocket,
  `Blob`/request-stream bodies, h2 and h3. SSE/WebSocket, the 256 MiB budget
  and command failures have unit tests (`cargo test capture::`).

## `transformed` field (review 4a)

- Response body that does not come in base64 → `"transformed":["chrome-decoded"]`: the
  `getResponseBody` delivers text already decoded by Chrome. With a declared charset
  other than UTF-8 it adds `"charset:<x>->utf-8"`. Live case
  `latin1`: wire `53 e3 6f` ("São", ISO-8859-1) → CDP `53 c3 a3 6f`, marked.
  The wire bytes are not reconstructed.
- Incomplete `postDataEntries` → tries `Network.getRequestPostData`; if only the event's
  `postData` remains, it is recorded marked `"lossy-postData"` (unit test; Chrome 156
  did not produce incomplete entries in the live cases).
- Bytes identical to the wire only hold for lines without `transformed`.

## Stability note

In 1 of ~6 runs the live cycle failed on import: "invalid JSON in NetLog … line 3661"
(legacy: "JSON inválido em NetLog … line 3661"; NetLog not finalized when Chrome shut down). Not
reproduced in the next 5 runs; not fixed here.

## Truncated NetLog (diagnosis and fix)

- **Original failure**: 1 cycle ("invalid JSON in NetLog … line 3661"; legacy: "JSON inválido em NetLog … line 3661"); the NetLog ended at a complete event plus a comma, without `]}`. That cycle came right after a run in which the
  driver failed and left the capture (test + Chrome) alive, writing to the same directory.
  **Not reproduced**: 12 diagnostic cycles and 20 final cycles, all with
  `Browser.close` ok and graceful Chrome exit (0.2–2.4 s). The likely cause is that orphan
  capture (harness), but it is not proven.
- **Defense**: `run_bodies.py` terminates its own capture in the `finally`, refuses to run if
  a `live_bodies_cycle` is already running, and `capture.rs` records how Chrome exited.
- **In `capture.rs`**: `cdp-events.jsonl` is written before any step that can fail.
  A truncated NetLog is repaired (cut at the last complete event, close with `]}`; the original is kept in
  `netlog.original.json`); unrepairable/absent → imports only CDP+bodies. In both cases:
  partial `completeness` + warning `capture.netlog_incomplete` / `capture.netlog_unusable`;
  Chrome forcibly killed → `capture.chrome_killed`. It never discards the session silently.
  Proven by unit tests with a real Chrome NetLog cut at 6 points (the core imports the
  repaired one); there is no live proof of the repair because the failure did not reproduce.
- `python3 loop_bodies.py 20` → `results/bodies/cycles.json` (20 cycles, 0 failures).
