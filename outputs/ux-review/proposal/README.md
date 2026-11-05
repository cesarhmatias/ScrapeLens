# Navigable prototype — ScrapeLens

Isolated prototype in HTML/CSS/JavaScript, with synthetic data. It does not change `app/src`, `core/src` or `src-tauri/src`. The design can be integrated into the existing React components; this demonstration's JavaScript is not a substitute for the production adapter, diff or exporters.

## Open

At the repository root:

```sh
python3 -m http.server 4174 --bind 127.0.0.1 --directory outputs/ux-review/proposal
```

Open **http://127.0.0.1:4174/?view=entry**. Do not open `index.html` via `file://`: the fixture is loaded with a local `fetch`.

Direct links:

- [Entry](http://127.0.0.1:4174/?view=entry)
- [Session](http://127.0.0.1:4174/?view=session)
- [Detail](http://127.0.0.1:4174/?view=detail&id=18&tab=headers)
- [Cookies](http://127.0.0.1:4174/?view=detail&id=18&tab=cookies)
- [Comparison](http://127.0.0.1:4174/?view=compare)

It uses no CDN, remote fonts, external service or AI API. The `.invalid` domains are displayed data and are never accessed.

## Recommended walkthrough

1. On the entry screen, open the demonstration. There are 64 requests with assets and APIs mixed together.
2. Filter Fetch/XHR and search `produtos` (products). See #18 (browser, 200/h2) and #64 (scraper, 403/h1).
3. Select the call with a click or ↑/↓; Enter or “Inspect call” opens the detail.
4. In the Headers tab, search `text/plain`. Occurrence 2 of 2 keeps index 5. Copy the value.
5. Expand pseudo-headers or switch to “Normalized · alphabetical”. “Understand” explains the limits of the sequence.
6. See Cookies: sent pairs, Cookie field and two independent Set-Cookie lines. Storage and wire lines are unavailable in the fixture.
7. Compare A/B. Switch Headers, Cookies, Payload, Protocol and Response; uncheck “Differences only”; swap A/B.
8. “Code…” opens a synthetic cURL example. The copy contains the full value and repeated headers.
9. “New capture” opens a **simulated** flow, without starting Chrome or traffic. End the simulation to return to the demo.

Keyboard: Tab/Shift+Tab, ↑/↓ in the list, Enter, Escape, ←/→ in the tabs, ⌘F/Ctrl+F and ⌘O/Ctrl+O. Dialogs use `<dialog>` and visible focus. There is no command to run the exported code.

## Save and import in this demonstration

“Save copy…” downloads `scrapelens-demo-ux.json`, a demonstration-specific format, **not** the product's v1 bundle. “Open session…” recognizes that JSON and the included HAR fixture; the scope is deliberately limited to this same demonstration. It is not a generic importer and does not read NetLog.

The downloaded copy was checked on disk and is identical to the fixture (64 calls). The browser automation's file picker timed out; reopening the JSON through the prototype was not validated end to end. HAR import, persistence and v1 reopening were validated in the **current native application**, separately.

The proposal's Fetch/XHR classification comes from the fixture JSON. The production HAR importer currently loses `_resourceType`; this is documented as P0, with a Rust dependency, and was not fixed here.

## Data and sources

- `fixtures/session.json`: the proposal's presentation data, generated locally.
- `fixtures/catalogo-synthetic.har`: HAR 1.2 of the same fictitious navigation, used to test the native importer.
- `fixtures/invalido.har`: invalid fixture to test error recovery.
- `fixtures/session-v1-imported/`: output of the existing CLI importer. The `synthetic-fixture` label was added to the metadata to identify it on reopening. A HAR imported directly in the app does not receive that label automatically; the “REAL SESSION” capture documents this problem.
- `generate-fixture.py`: regenerates the JSON/HAR/invalid fixture. The CLI import to v1 is a separate step, described below.

The proposal JSON assigns a NetLog + CDP source to #18 to demonstrate the UX for partial evidence, and HAR to #64. **This is not an executed correlation.** When the generated HAR is imported into the core, the source becomes HAR for all calls. These are controlled representations of the same scenario, with different limits, deliberately made explicit.

To regenerate v1:

```sh
python3 outputs/ux-review/proposal/generate-fixture.py
./core/target/debug/scrapelens-core import-har \
  outputs/ux-review/proposal/fixtures/catalogo-synthetic.har \
  --out /tmp/scrapelens-ux-session-v1
```

If you want to reopen that output as a demonstration in the app, add `synthetic-fixture` to `session.labels`. This identifies the fixture; it does not change the HTTP evidence. Do not reclassify real captures this way.

## Reproduce the isolated desktop instance

At the repository root, with existing dependencies:

```sh
./app/node_modules/.bin/tauri build --debug --bundles app \
  --config outputs/ux-review/proposal/desktop-review.conf.json
```

Open `src-tauri/target/debug/bundle/macos/ScrapeLens UX Review.app`. Data identifier: `app.scrapelens.uxreview`. The override changes only the name, identifier and window geometry. Do not start recording in the original instance during the evaluation. The isolated build does not need to be distributed or versioned.

## Screenshots and visual verification

The screenshots delivered in `../after/` were taken in the real browser and examined individually. The four main views exist at 1440 × 900 and 1280 × 800. `viewport-checks-*.json` records the observed dimensions and the absence of page overflow. The data regions scroll internally; the intent is not to show 64 rows or every long value at once.

To repeat the four main screenshots with the Playwright already installed in the project, keep the server above running and execute, from the root:

```sh
node outputs/ux-review/proposal/capture.mjs
```

The script writes to `../after/recapture/`, preserving the reviewed images. It waits for the component to render before photographing, avoiding an empty capture before the fixture's `fetch`. **Reopening and reviewing the images is mandatory** after any change; running the script by itself does not constitute visual review.

Limits: 64-item prototype without virtualization; one theme; it is not a new implementation of the capturer, a generic parser, the production diff, the Python exporter, cookie storage or the v1 format. It does not replace accessibility testing with VoiceOver or evaluation with users.
