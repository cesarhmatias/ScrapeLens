# ScrapeLens — macOS app (Tauri 2) + React interface

Implementation of the desktop shell and the interface over the **v1 contract**
(`docs/03-contracts.md`). The UI has no contract of its own: it consumes
`session.json` v1 via `core/` and via Tauri commands.

## Current status (wave 2)

- **Tauri 2** with a single window, native macOS menu and native dialogs.
- **Shortcuts**: ⌘O (open capture), ⌘F (find), ⌘C (copy the URL of the selected
  request when no text is selected). The Edit menu keeps native copy/paste.
- **Light/dark theme** with the choice persisted in `localStorage` and the
  system default.
- **Chrome**: automatic detection in `/Applications` and manual selection through
  a native dialog (`Select Chrome…` in the File menu or in the screen's warning).
- **Real integration with core/** (`scrapelens-core` as a crate dependency,
  single binary, no sidecar):
  - `start_session` opens external Chrome with a dedicated temporary profile,
    debugging only on `127.0.0.1` (ephemeral port), records CDP + NetLog and
    navigates to the start URL (default `about:blank`);
  - `stop_session` closes Chrome, waits for the NetLog flush, correlates
    CDP×NetLog in the core, writes the v1 session and returns the ready session;
  - `import_har` and `import_netlog` read the real file, import it through the
    core and write the v1 session (labels `har-import`/`netlog-import`);
  - `open_session` reads a v1 folder/file, validates `schemaVersion` and keeps
    the folder for attachments; `read_attachment` loads a text preview.
- **Capture validated end to end** on macOS: external Chrome 156, a page from
  the local testserver, 11 real requests, h1 headers `verified` from NetLog,
  cookies/`Set-Cookie` preserved, `matched` and `ambiguous` correlation exposed.
  Detailed evidence in `src-tauri/REAL-CYCLE.md`; screenshots 17–21 in
  `docs/screenshots/`.
- **Explicit open items**: signing/notarization and the Intel build; CDP body
  capture is not yet downloaded for attachments (`unavailable` state), so the
  real body preview appears as unavailable.
- **Virtualized list** (34 px row, overscan): 12,000 requests render 24 rows and
  437 DOM nodes; see `docs/perf/virtualization.json`.

## v1 contract in the UI

`src/v1/types.ts` projects `core/src/model/*.rs`; `src/v1/adapter.ts` converts
it into the screen model:

- headers as ordered arrays (`pseudoHeaders` + `headers`), duplicates preserved
  and order never redone;
- the normalized view is derived and marked as partial;
- `verification` per piece of information (verified/partial/unverified) with
  source, event, time, method and note; "not verified" appears literally;
- `Cookie` shows the raw field, the pairs and the wire lines separately;
- raw `Set-Cookie` + parsed attributes, with visible parse errors;
- bodies use `Body.state` (`captured`, `empty`, `truncated`, `unavailable`,
  `discarded`) with an explicit reason and the attachment indicated;
- `attempts`, `redirects` and `match` (matched/ambiguous/unmatched) with
  candidates shown when ambiguous;
- captured HTML is always text, never interface.

`CONTRACT-DRAFT.md` stays as the history of wave 1 and is marked as superseded.

## Run

Development prerequisites: Node + Rust + Xcode Command Line Tools.
The packaged app does not require Node, Python or Rust.

```sh
# at the repository root
./app/node_modules/.bin/tauri dev
./app/node_modules/.bin/tauri build --bundles app
# output: src-tauri/target/release/bundle/macos/ScrapeLens.app
```

Or through the scripts in `app/`:

```sh
cd app
npm install
npm run dev            # UI in the browser (demo mode, no commands)
npm run build
npm run shots          # screenshots in ../docs/screenshots
npm run perf           # measures virtualization (docs/perf)
npm run desktop:dev    # Tauri dev (from app/)
npm run desktop:build  # local .app, without an Apple certificate
```

> The local build is **unsigned** (no Apple certificate). Distribution requires
> signing and notarization — neither was done and nothing was published.

## Commands and payload

All session commands return the same envelope:

```json
{
  "session": { "schemaVersion": 1, "session": {...}, "requests": [...] },
  "sessionDir": "/path/to/the/session",
  "synthetic": false,
  "notice": "Session opened: 13 request(s).",
  "pending": false
}
```

`pending: true` means "the core has not run this step yet"; the UI shows the
warning and keeps the labeled demo session. When the core is plugged in, only
the body of `start_session`/`import_har`/`import_netlog` changes.

## Limits of this delivery

- The native dialog exists to open a session and choose Chrome; there is no
  "Save as"/export in the UI yet.
- The Chrome launcher and the CDP client live in `src-tauri/src/capture.rs`
  (the core did not bring a launcher; the parsers/correlation are its).
- `SCRAPELENS_CAPTURE_URL`, `SCRAPELENS_CAPTURE_HEADLESS=1` and
  `SCRAPELENS_CAPTURE_IGNORE_CERT=1` are development/test hooks; they do not
  appear in the interface.
- The theme follows the system on first run; there is no sync with the macOS
  WebView theme beyond the app class.
- Signing/notarization and Intel builds were neither done nor tested; the
  machine is Apple Silicon (arm64). Compiled architectures ≠ tested.
- The body preview of real sessions is loaded by `read_attachment` (1 MiB
  limit); binaries are not converted to text.
- `--remote-allow-origins=*` on CDP: the local endpoint accepts any Origin
  during capture (loopback + ephemeral port + session window); do not browse
  untrusted pages in the inspected Chrome while recording.
- No telemetry, no network at runtime.
