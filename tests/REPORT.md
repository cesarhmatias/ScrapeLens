# Acceptance report — ScrapeLens MVP

Run: 2026-11-02T20:30:26Z · core binary `c695ceb63355` (3898528 bytes) · commit `cb831c0`

Environment: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Spec criterion | Status | Assertions |
|---|---|---|---|
| 1 | Repeated headers and cookies preserved in the fixtures | **passed** | 29/29 |
| 2 | HAR and NetLog valid, incomplete and with unknown events | **passed** | 26/26 |
| 3 | Simultaneous identical requests without false association | **passed** | 19/19 |
| 4 | Redirects and multiple attempts | **passed** | 12/12 |
| 5 | Missing/truncated/discarded bodies made explicit | **passed** | 16/16 |
| 6 | Diff without losing duplicates | **passed** | 14/14 |
| 7 | cURL/Python export with special characters | **passed** | 23/23 |
| 8 | Sanitization including raw events | **passed** | 19/19 |
| 9 | Real capture cycle on macOS | **passed** | 123/123 |
| 10 | Large import with documented size | **passed** | 7/7 |
| 11 | MCP: crate tests, live tests and full flow over stdio | **passed** | 39/39 |

Summary: 11/11 criteria passed; 327/327 assertions passed.

Criteria of the request: (1) repeated headers/cookies, (2) HAR/NetLog valid/incomplete/unknown, (3) simultaneous identical requests without false association, (4) redirects/retries, (5) explicit bodies, (6) diff with duplicates, (7) cURL/Python escaping, (8) sanitization with raw events, (9) real macOS cycle, (10) large import measured.

Scope of the evidence:

- New in this round: CLI capture `tests/capture/runs/live-final` (2026-10-29T04:20:57Z), with both legs (h1h2 and h3) and the HAR derived from CDP.
- New in this round: live session `capture-1793651039927` started and stopped by the final bundle (`2691f1528a6b`).
- New in this round: HAR/NetLog imports in the final bundle through the test CLI (`SCRAPELENS_TEST_MODE=1 --import-har` / `--import-netlog`), from the copies in `tests/.work/r12-import` (har `har-3dbc391c02a985c5-13`, netlog `netlog-1704043c442dcbd1-13`), with independent verification by SHA-256 and sequence against `har-derived.json` and `h1h2h3.chrome-netlog.json`.

## 1. Repeated headers and cookies preserved in the fixtures — passed

Evidence:

- `scrapelens-core import-har fixtures/acceptance/headers-cookies/headers-cookies.har --out tests/.work/run/item1/har`
- `scrapelens-core import-netlog fixtures/acceptance/headers-cookies/headers-cookies.netlog.json --out tests/.work/run/item1/netlog`
- assertions: sequence/case/duplicates, raw Cookie + pairs, raw Set-Cookie + parsed, verification by source

Assertions: 29 passed, 0 failed (0.07 s).

## 2. HAR and NetLog valid, incomplete and with unknown events — passed

Evidence:

- `scrapelens-core import-har fixtures/acceptance/parsers/incomplete.har --out tests/.work/run/item2/incomplete-har`
- `scrapelens-core import-netlog fixtures/acceptance/parsers/unknown-events.netlog.json --out tests/.work/run/item2/unknown`
- `scrapelens-core import-netlog fixtures/acceptance/parsers/no-constants.netlog.json --out tests/.work/run/item2/no-constants`
- invalid cases: return ≠ 0 with `erro:` (legacy) on stderr (HAR without entries, truncated NetLog)

> HAR does not prove order/duplicates: imported entries stay `unverified`, as in the contract.

> The `completeness.counts.sourceEvents*` counts are now persisted and survive re-reading (core fix in this wave); the warnings still carry samples of the unknown types.

Assertions: 26 passed, 0 failed (0.15 s).

## 3. Simultaneous identical requests without false association — passed

Evidence:

- `scrapelens-core import-capture fixtures/acceptance/ambiguous/cdp-ambiguous.jsonl fixtures/acceptance/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

> The NetLog order/duplication is preserved, but it does not become the primary view while there is ambiguity.

> Leader's failure diagnosis: the fixture declared `wallTime` without the monotonic `timestamp` (`1793046000.0`), and the core of `4468a81` calibrated `time` as microseconds; the NetLog ran 2 s ahead and the two requests became `unmatched`. Real Chrome satisfies `wallTime = timeTickOffset/1000 + timestamp` (measured deviation < 1 ms), an equation now used in the fixture. It was a defect of the fixture, not of the core; the original failure is preserved in `tests/results/acceptance-criterion3-leader-failure.json` and `REPORT-criterion3-leader-failure.md`.

> New assertions in this round: clock coherence of the fixture (CDP×NetLog) and calibrated unit `milliseconds`. The ambiguity test remains strict: the two requests at 20 ms are still ambiguous, each with the same 2 candidates and 2 `correlate.ambiguous` warnings.

Assertions: 19 passed, 0 failed (0.05 s).

## 4. Redirects and multiple attempts — passed

Evidence:

- `scrapelens-core import-netlog fixtures/acceptance/redirects/redirect-chain.netlog.json --out tests/.work/run/item4/netlog`
- `scrapelens-core import-har fixtures/acceptance/redirects/redirect-chain.har --out tests/.work/run/item4/har`

> The redirect is a link between attempts, not a separate request.

Assertions: 12 passed, 0 failed (0.05 s).

## 5. Missing/truncated/discarded bodies made explicit — passed

Evidence:

- `scrapelens-core inspect fixtures/acceptance/bodies/session`

> `empty` is only used when the source asserts zero bytes; absence becomes `unavailable` with a note.

Assertions: 16 passed, 0 failed (0.01 s).

## 6. Diff without losing duplicates — passed

Evidence:

- `scrapelens-core diff fixtures/acceptance/diff/session har-0001 har-0002`

> The diff compares occurrences; `reordered` uses the original indices of A and B.

Assertions: 14 passed, 0 failed (0.01 s).

## 7. cURL/Python export with special characters — passed

Evidence:

- `scrapelens-core export-curl fixtures/acceptance/export-special/session har-0001` → `bash -n` + execution with a stub that records argv
- `scrapelens-core export-python fixtures/acceptance/export-special/session har-0001` → `python3 -m py_compile` + AST with literals
- generated commands: tests/.work/run/item7/export.sh, tests/.work/run/item7/export.py

> The exporters promise the HTTP request, not TLS/fingerprint (JA3/JA4, frames, HPACK).

Assertions: 23 passed, 0 failed (0.14 s).

## 8. Sanitization including raw events — passed

Evidence:

- `scrapelens-core sanitize fixtures/acceptance/sanitize/session tests/.work/run/item8/sanitized`
- permissions: `0o700` on the directory and `0o600` on session.json
- recursive scan for 10 SECRET-* markers + e-mail: no occurrences

> Sanitization does not promise to detect tokens in path/free HTML; those bodies are omitted with a warning.

Assertions: 19 passed, 0 failed (0.04 s).

## 9. Real capture cycle on macOS — passed

Evidence:

- real run: `tests/capture/runs/live-final` (generated by `tests/capture/run-cycle.sh`); stable copy at `tests/results/capture-latest/run.json`
- packaged app: `ScrapeLens.app` 17.07 MiB, arm64, local-identity signature, single binary, executable `2691f1528a6b5b6009d8cc29c049f1e500093d6aab9f2163bcc4aad60df18156`; live capture capture-1793651039927 (11 req, 154 headers verified, 2 ambiguous); HAR import through the test CLI `har-3dbc391c02a985c5-13` (24 req, ['h1', 'h2'], 24 sourceEvents); NetLog import through the test CLI `netlog-1704043c442dcbd1-13` (32 req, ['h1', 'h2', 'h3', 'unknown'], 15 StreamSessions, 5354 sourceEvents).
- real app sessions: `/Users/cesar/Library/Application Support/app.scrapelens.desktop/sessions` · screenshots `tests/results/app-latest/screenshot-app-live.png` and `tests/results/app-latest/screenshot-app-imports.png`
- CLI: Chrome 156.0.8078.73; 27 requests; 14 StreamSessions h3; 2 ambiguous; redirects=6

> The real page `/page` exercised redirects and POSTs.

> The HAR of the cycle is rebuilt from CDP (`experiments/har_from_cdp.mjs`), because Chrome 156 does not expose `Network.getHAR`; the creator declares the origin and the order is not proven (unverified).

> The real cycle uses CDP, which does not fetch bodies: all bodies stay `unavailable` with a note. Body capture (Network.getResponseBody) is not yet on the live path.

> In this round the Start/Stop cycle was redone in the final bundle `2691f1528a6b` (HEAD `782718f`, record in `6bbc9fb`; multi-target capture); the live session above is new, not reused.

> The HAR and NetLog imports were also redone in the final bundle (`har-3dbc391c02a985c5-13` and `netlog-1704043c442dcbd1-13`), now through the test CLI (`SCRAPELENS_TEST_MODE=1 --import-har` / `--import-netlog`), with the files copied to `tests/.work/r12-import`; no native dialog, click or key was used. Verification does not depend on human confirmation: the saved HAR reproduces the method/URL sequence of `har-derived.json` (24 entries) and the persisted `netlog.json` is byte-identical to `h1h2h3.chrome-netlog.json` (SHA-256). Repeated imports of the same files (`-N` suffixes on `har-3dbc391c02a985c5` and `netlog-1704043c442dcbd1`) have an identical `session.json`, with no effect on validation. The isolated NetLog warns `netlog.time_unit_assumed` because, without CDP, the NetLog clock unit cannot be calibrated — the limitation is made explicit in the session.

Assertions: 123 passed, 0 failed (0.13 s).

## 10. Large import with documented size — passed

Evidence:

- `/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` → HAR 16.6 MiB, 20,000 requests, 0.97 s, peak 822 MiB RSS
- session written: session.json 236.3 MiB
- `/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` → 2.74 s, peak 1598 MiB RSS
- complementary, 20,000 attachments of 20 B: import 3.72 s, peak 795 MiB, session 228.9 MiB

> Main HAR: 20,000 requests, 16.6 MiB, no bodies (the pathological case with 20 thousand attachments is measured separately).

> `inspect` materializes the pretty JSON of the whole session (236.3 MiB); the 1598 MiB peak comes from the serialization, not from the parser.

> Core fix confirmed: above 256 attachments, `fsync` becomes batched per directory — 20,000 attachments of 20 B import in 3.72 s (they took 128 s in the previous battery). Small sessions keep `fsync` per file.

Assertions: 7 passed, 0 failed (8.90 s).

## 11. MCP: crate tests, live tests and full flow over stdio — passed

Evidence:

- `tests/results/mcp/run.json` and `tests/results/mcp/flow.json` (outputs of the commands and of the flow)

> Flow client: `tests/acceptance/mcp_flow.py`, JSON-RPC over stdio in Python, without the Rust harness; local HTTP server on 127.0.0.1, real headless Chrome, nothing external.

Assertions: 39 passed, 0 failed (249.92 s).

## How to reproduce

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/acceptance/run_acceptance.py --build-fixtures
python3 tests/acceptance/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/acceptance/run_acceptance.py   # uses the last recorded capture
```

All offline: synthetic fixtures in `fixtures/acceptance/`, `.invalid` domains; criterion 9 uses Chrome with a dedicated temporary profile and local servers. Nothing is published and no telemetry is generated.
