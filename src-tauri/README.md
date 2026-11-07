# src-tauri — Tauri 2 shell

The UI in `app/` is embedded in the binary; no Node/Rust/Python is required of the
end user. The data contract is the v1 of `docs/03-contracts.md`.

## Build and tests

```sh
# at the repository root
./app/node_modules/.bin/tauri dev
./app/node_modules/.bin/tauri build --bundles app

cd src-tauri && cargo test
```

Local build output: `target/release/bundle/macos/ScrapeLens.app` (root workspace target)
(arm64, ad-hoc signature `linker-signed`, **no Apple certificate** and no
notarization). Distribution/signing are not part of this delivery.

## Commands (stable bridge to core/)

All session commands return `SessionPayload`:

```
session      JSON v1 (schemaVersion=1)
sessionDir   session folder (for attachments), when it exists
synthetic    true if the fixture/label is synthetic
notice       actionable text for the UI
pending      true when core/ has not run this step yet
```

| Command | Status | Notes |
|---|---|---|
| `app_info` | ready | version, arch, schema v1 |
| `demo_session` | ready | embedded synthetic v1 fixture |
| `open_session(path)` | **real** | reads a `session.json` folder/file, validates `schemaVersion`, marks partial and synthetic; keeps the folder for attachments |
| `import_har(path)` | **real** | core `import_har` + `store::write_session_dir` |
| `import_netlog(path)` | **real** | core `import_netlog` + persistence |
| `start_session` | **real** | external Chrome with a dedicated profile + CDP + NetLog |
| `stop_session` | **real** | NetLog flush, correlation in core, v1 session |
| `capture_status` | ready | events, Chrome PID, URL and capture error |
| `detect_chrome` | ready | detects `/Applications` + saved preference |
| `set_chrome_path(path)` | ready | accepts `.app`, `Contents/MacOS` or the binary; persists to `app_config_dir/preferences.json` |
| `read_attachment(sessionDir, name)` | ready | text preview ≤ 1 MiB, no `..`/separators |
| `reveal_path(path)` | ready | Finder (macOS) |

## Real integration with core/

1. `scrapelens-core` is a Rust dependency (`path = "../core"`); single binary.
2. `import_har`/`import_netlog` call `scrapelens_core::import_har/netlog` and
   write with `store::write_session_dir`.
3. `capture.rs` implements the Chrome launcher and the CDP client (the core did not
   bring a launcher), writes `cdp-events.jsonl` + `netlog.json` and hands them to the
   core's `import_capture`.
4. `open_session` reads the v1 `session.json`; `read_attachment` reads
   `<session>/attachments/<name>` with a 1 MiB limit and no traversal.
5. Sessions live in `app_data_dir()/sessions/<id>` (0700/0600 via core).

## Known limitations

- `--remote-allow-origins=*` in the launcher: the CDP endpoint at
  `127.0.0.1:<ephemeral port>` accepts any Origin during capture. The risk is
  limited to loopback, the random port and the session window; even so, do not browse
  untrusted pages in the inspected Chrome while recording.
- CDP bodies are written to `cdp-bodies.jsonl` and imported into the live session:
  request payload (`Network.getRequestPostData`) and response body
  (`Network.getResponseBody` at `loadingFinished`), in `attachments/`. Each body is
  cut at **5 MiB** (`truncated`, with the original size and only the prefix); the
  session has a budget of **256 MiB** (`discarded` above that). `Network.enable`
  requests `maxTotalBufferSize` 100 MB, `maxResourceBufferSize` 50 MB and
  `maxPostDataSize` 5 MiB. These are left `unavailable` with a note: SSE/streaming and
  WebSocket (no HTTP body), redirect responses, responses without
  `loadingFinished`/`loadingFailed` before shutdown (3 s drain), errors from
  `getResponseBody`/`getRequestPostData`, invalid base64, and 0 bytes without evidence
  of emptiness. Text comes decoded by Chrome (`chrome-decoded`, with
  `charset:x->utf-8` when it is not UTF-8) and `lossy-postData` marks a payload with no
  proof that the bytes were preserved; those bodies keep a partial verification.
  A body with no matching line becomes a warning, never an association by URL.
- The capture follows the page, popup, `target=_blank` tab, cross-origin iframe (OOPIF),
  worker and service worker (recursive auto-attach). A `_blank` tab document may come
  only from the NetLog (Chrome limitation). A target that fails to attach is recorded
  as a warning, without invented CDP headers/bodies.
- No Apple signing/notarization; arm64 built and tested, Intel not.
- A capture with zero CDP events fails with an explicit error instead of writing an
  empty session; sessions with partial events are kept as `partial`.

## Shortcuts

Native menu: ⌘O open, ⌘F find, ⌘⇧C copy the URL of the selected request,
⌘C copy native text, ⌘⇧D load the demo. The UI also handles ⌘O/⌘F/⌘C
as a fallback in the WebView.
