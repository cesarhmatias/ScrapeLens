# Local delivery and packaging recovery — 2026-10-27

## Result and scope

Local packaging complete. The arm64 bundle was rebuilt with the current core,
the ad-hoc signature is valid, and opening it and a new capture through the UI are proven.
Automated battery: 10/10 criteria and 282/282 assertions, no SKIP.
New HAR/NetLog imports through the UI of the same bundle are also confirmed:
manual selection by the user in the native panel, followed by independent verification
by Tests of the persisted files, origin, counts, permissions and re-reading.
The picker's automation block was recorded as an environment limitation;
there is no pending import verification in this delivery.

This closes the package recovery and records the real state. It does not amount
to full completion of all the product requirements of the specification:
export/sanitization are still CLI, and the DETRAN-derived requirements
listed below were not integrated into the UI. No production code was
changed in this recovery; no UX proposal was integrated.

## State preserved and work resumed

At the start, HEAD `30d78c6`, clean tree. LICENSE, CONTRIBUTING, the commands
comment and the Origin CDP note were already in `375d6b5`; they were not redone.
The old bundle predated the NetLog clock calibration (`4468a81`).

App resumed only the build/validation and contribution commands:
`bbfc82e`, `5d62880`, `bdf5230`. Source build `30d78c6`, core up to `0adff48`,
including `ac6a7c8` (sanitization) and `4468a81` (NetLog).

The leader's re-run revealed three failures in criterion 3. Tests showed
that the fixture declared a wallTime incompatible with the monotonic timestamp;
it fixed the equation without reducing the ambiguity requirements. Commits
`00d1ab1` and `0527e56`; original failure preserved in
`tests/results/acceptance-criterion3-leader-failure.json` and the corresponding report.
No additional core fix or new product build was needed.

## Artifact and installation

- Package: `target/release/bundle/macos/ScrapeLens.app`.
- Approximate size: 13.2 MiB; one Mach-O arm64 executable, 13,119,296 bytes.
- SHA-256 of the signed executable:
  `a7004d4e95e86e2d53750a76b0579d345cabf6e53cb25c3b15c446d25ec522c0`.
- Ad-hoc signature verified with `codesign --verify --deep --strict` by
  App and again by the leader; no Developer ID/notarization. Gatekeeper rejects
  normal distribution of this artifact. Intel and other macOS versions not tested.
- Open it from Finder or `open target/release/bundle/macos/ScrapeLens.app`
  from the root. You may copy the bundle to `/Applications`.
- External Chrome required for capture; Node/Python/Rust not required
  to run the app. The export CLI is a separate tool.

Build/signing commands and environment in `src-tauri/PACKAGING.md`.
The hash identifies this artifact; it does not guarantee a byte-for-byte reproducible build.

## Confirmed validation

| Check | Result and origin |
|---|---|
| Core `cargo test --offline` | App: 88 pass, 1 benchmark ignored |
| Shell `cargo test` | App: 6 pass, 1 live test ignored; capture exercised separately through the UI |
| TypeScript and Vite | App: typecheck and build pass |
| Tauri build | App: exit 0, core recompiled as a crate dependency |
| Signature/hash/architecture | App + leader: valid codesign, SHA-256 above, arm64 |
| Acceptance battery | Tests: 282/282, 10/10, commit 38c08f0; promoted to docs/05-acceptance.md |
| New capture in the final bundle | Tests: Start/Stop through the UI, session capture-1793085113332 |
| New HAR/NetLog | Final bundle UI: HAR 24 and NetLog 32 requests, sources checked |
| Visual inspection | App: screenshots 22/23; leader inspected screenshot 23; Tests recorded screenshot-app-live.png and screenshot-app-imports.png |

New session: 11 requests, complete, cdp+netlog, 154 header entries
verified via NetLog h1, 9 matched, 2 ambiguous (2 candidates each), zero
unmatched, 2 redirects, 8 Set-Cookie lines, Cookie sc_dup preserved.
Directory 0700, files 0600. CDP bodies unavailable with a note (build
prior to live body recording).

New harness capture: 27 requests, h1/h2/h3, stable evidence in
`tests/results/capture-latest/run.json`. The historical matrix measures Chrome
156.0.8078.48, 15 experiments and 60 requests, with h3 observed on aioquic and
the quiche scenario blocked. Full HTTP/3 coverage is not claimed.

Current large import: 20,000 requests, HAR 16.6 MiB in 0.96 s;
20,000 small attachments in 3.30 s. Inspect reaches 2,415 MiB RSS when serializing
the full JSON; responsiveness/memory profile still deserves attention.

## Available features

Dedicated Chrome capture, stop/flush, saving and reopening a v1 session,
HAR/NetLog importers, list with filters and search, detail and comparison of
requests with duplicates. Headers in the source sequence; provenance and
verification per item. HAR/CDP objects do not prove transmitted order;
NetLog and h1 headersText provide specific evidence. Ties stay
ambiguous. cURL/Python export and sanitization work in the core/CLI and, since
the following round, also through the interface (result in `docs/07-ui-export.md`).

## Limitations and remaining priorities

1. Export/sanitization in the UI: completed in the following round (`docs/07`).
   Body search, priming chain,
   dynamic fields and cross-session comparison of the DETRAN case remain pending;
   fixtures and 13/13 correlation do not prove these interface functions.
2. Complete the transitive notices/licenses for redistribution. Own code
   MIT and lockfiles present; full inventory not audited.
3. Capture covers only one target/page (multi-target is round 10); request and
   response bodies are recorded in `cdp-bodies.jsonl` with a limit of
   5 MiB per body and 256 MiB per session, and are marked `unavailable` with a note in
   cases without a body (SSE/WebSocket, redirect, CDP error, capture ended
   before `loadingFinished`); zero events produces an error instead
   of an empty session; Origin CDP opened by --remote-allow-origins=* during the
   local session. Sanitization remains heuristic, omitting attachments/events
   that cannot be sanitized; export does not guarantee fingerprint/transport.
4. Developer ID signing/notarization and Intel testing before wide
   distribution. Nothing published, no push/release in this task.

The folder `~/Projects/scrapelens-import-tmp/` and the duplicate sessions were
preserved; no deletion was performed. Usage/build instructions in the README.

## Closing the manual imports

The macOS permission was granted by the user. The picker remained inaccessible
to automation (empty AX and keys with no effect); historical record in
`docs/validation/import-picker-blocker.json`. No permission was bypassed.
After an attempt with a JSON lacking the HAR structure, Tests confirmed that the
prepared file was valid. The user selected the two exact paths and confirmed
the import. Tests verified the new sessions before approving (38c08f0):

- HAR `har-3dbc391c02a985c5-2`: 24 h1/h2 requests, complete, 24 sourceEvents,
  no DEMO and zero headers classified as verified. Method/URL sequence
  identical to the 24 entries of the prepared HAR.
- NetLog `netlog-1704043c442dcbd1-2`: 32 h1/h2/h3 requests, 36 attempts,
  9 connections, 4 redirects, 15 StreamSessions and 5,354 sourceEvents. Partial with
  explicit reason for the absence of CDP; warning about assumed time unit.
  Persisted NetLog artifact byte-for-byte identical to the prepared source.
- Directories 0700 and files 0600; inspect re-reads 24/32 requests without modifying
  session.json. Duplicate copies preserved.
- Screenshot `tests/results/app-latest/screenshot-app-imports.png`: imported
  NetLog session, 32 requests and h1/h2/h3 rows. Metadata and verification in
  `tests/results/app-latest/run.json`.

Consolidated battery re-run: 282/282 (criterion 9: 118/118). Capture and build
were not repeated in that last pass. The bundle hash remained the same.

## Delivery of rounds 4 to 7 (2026-10-29)

Package: `target/release/bundle/macos/ScrapeLens.app`, built at
HEAD bc935eb (build commit b2ba81b), ad-hoc signed
(`codesign --verify --deep --strict` OK), executable SHA-256
`6e301e70161c314c4475923a91182edd26bcf009ec2a5f3ddd90106b6e91cce9`. Nothing was
published.

New features:
- Round 4 (docs/08): CDP bodies recorded live, with explicit state and
  `transformed`; search across 6 scopes with decoded view and exact range;
  sanitization by value propagation.
- Round 5 (docs/09): origin of values with type and evidence strength,
  priming chain and per-field comparison between captures.
- Round 6 (docs/10): fidelity to the real DETRAN-PB case (HTML controls,
  rounds, context pages, auxiliary frames, business fields).
- Round 7 (docs/11): Python priming script (runtime extraction, no captured
  values or PII, no cross-origin redirect, stop at the bad step) and the
  application success verdict × HTTP.

Acceptance: `tests/REPORT-FINAL.md` (bc935eb). 10/10 criteria with a new live
capture (criterion 9), all batteries green, cargo test core 250 and
src-tauri 42. On the user's 3 real HARs (aggregate): STAMP and delta 100%,
script with 11 steps in the order of the manual flow, only plate and SESSIONID suffix
as parameters and 0 plates after sanitize. Each round was approved by independent
review.

Known limits: the script does not recalculate the length prefixes of
Natural for Ajax (it warns); PII in free text with no format (name, address,
obfuscated e-mail, date) is not detected in query/header/path; the
`--allow-literal-body` freezes the rest of the body (warned); DevTools HAR
does not carry cookies (warned).

Pending with the user: test of the real `.app` with the native folder picker
(not automatable). The synthetic sessions already imported are in
`tests/.work/teste-manual-final/` (outside git): `1-detran-uma-rodada`,
`2-detran-duas-rodadas` and `3-detran-bloqueio`.

## Delivery of round 8 (2026-10-29)

Package: the same path, built at HEAD f548c63, ad-hoc signed, with
executable SHA-256 `bda06a2db30c4b4315247f78fa728c967b946d7850641f4ab161995983f1e052`.
Nothing was published.

New: the Natural for Ajax adapter (`adapters/natural-ajax`, outside the core,
CLI `natural-core --adapter natural-ajax`). It brings:
- exact decoding and re-encoding of the `XML` field, with limits and linear
  cost;
- internal names (`XML.delta`, `XML.p.v_placa`) in origins and compare;
- structured view in the app;
- priming script that recalculates the UTF-16 prefixes (proven on detran-sim
  strict, with the control without the adapter failing).

The adapter's parts follow strict mode by default (`--lenient-parts`
optional). Acceptance: tests/REPORT-FINAL.md, section "Round 8", all green
(core 259, src-tauri 45, natural-ajax 28; 3 real HARs with and without adapter).
Independent review approved, with the accepted residuals recorded in
docs/12.

Pending with the user: the manual test of the `.app` with the native picker. The
synthetic sessions are in tests/.work/teste-manual-final/.
