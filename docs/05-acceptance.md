# Acceptance report — ScrapeLens MVP

Run: 2026-10-27T14:00:22Z · core binary `10f3b76b637b` (2176608 bytes) · commit `7956b5e`

Environment: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Spec criterion | Status | Assertions |
|---|---|---|---|
| 1 | Repeated headers and cookies preserved in the fixtures | **approved** | 29/29 |
| 2 | Valid, incomplete HAR and NetLog and with unknown events | **approved** | 26/26 |
| 3 | Simultaneous identical requests without false association | **approved** | 18/18 |
| 4 | Redirects and multiple attempts | **approved** | 12/12 |
| 5 | Missing/truncated/discarded bodies made explicit | **approved** | 16/16 |
| 6 | Diff without losing duplicates | **approved** | 14/14 |
| 7 | cURL/Python export with special characters | **approved** | 23/23 |
| 8 | Sanitization including raw events | **approved** | 19/19 |
| 9 | Real capture cycle on macOS | **approved** | 118/118 |
| 10 | Large import with documented size | **approved** | 7/7 |

Summary: 10/10 criteria approved; 282/282 assertions passed.

Criteria of the request: (1) repeated headers/cookies, (2) valid/incomplete/unknown HAR/NetLog, (3) simultaneous identical requests without false association, (4) redirects/attempts, (5) explicit bodies, (6) diff with duplicates, (7) cURL/Python escaping, (8) sanitization with raw events, (9) real macOS cycle, (10) measured large import.

Scope of the evidence:

- New in this round: CLI capture `tests/capture/runs/20261027T0730Z` (2026-10-27T07:11:07Z), with both legs (h1h2 and h3) and the HAR derived from the CDP.
- New in this round: live session `capture-1793085113332` started and ended by the final bundle (`a7004d4e95e8`).
- New in this round: HAR/NetLog imports through the UI of the final bundle (har `har-3dbc391c02a985c5-2`, netlog `netlog-1704043c442dcbd1-2`), with manual selection by the user and verification by SHA-256/sequence against the files prepared in `~/Projects/scrapelens-import-tmp`.

## 1. Repeated headers and cookies preserved in the fixtures — approved

Evidence:

- `scrapelens-core import-har fixtures/acceptance/headers-cookies/headers-cookies.har --out tests/.work/run/item1/har`
- `scrapelens-core import-netlog fixtures/acceptance/headers-cookies/headers-cookies.netlog.json --out tests/.work/run/item1/netlog`
- assertions: sequence/case/duplicates, raw Cookie + pairs, raw + parsed Set-Cookie, verification by source

Assertions: 29 passed, 0 failed (0.19 s).

## 2. Valid, incomplete HAR and NetLog and with unknown events — approved

Evidence:

- `scrapelens-core import-har fixtures/acceptance/parsers/incomplete.har --out tests/.work/run/item2/incomplete-har`
- `scrapelens-core import-netlog fixtures/acceptance/parsers/unknown-events.netlog.json --out tests/.work/run/item2/unknown`
- `scrapelens-core import-netlog fixtures/acceptance/parsers/no-constants.netlog.json --out tests/.work/run/item2/no-constants`
- invalid cases: return ≠ 0 with `erro:` on stderr (HAR without entries, truncated NetLog)

> HAR does not prove order/duplicates: imported entries stay `unverified`, as in the contract.

> The `completeness.counts.sourceEvents*` counts are now persisted and survive re-reading (core fix in this wave); the warnings still carry samples of the unknown types.

Assertions: 26 passed, 0 failed (0.27 s).

## 3. Simultaneous identical requests without false association — approved

Evidence:

- `scrapelens-core import-capture fixtures/acceptance/ambiguous/cdp-ambiguous.jsonl fixtures/acceptance/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

> The NetLog order/duplicates are preserved, but they do not become the primary view while there is ambiguity.

> Diagnosis of the leader's failure: the fixture declared `wallTime` without the monotonic `timestamp` (`1793046000.0`), and the core of `4468a81` calibrated `time` as microseconds; the NetLog ended up 2 s ahead and the two requests became `unmatched`. Real Chrome satisfies `wallTime = timeTickOffset/1000 + timestamp` (measured deviation < 1 ms), an equation now used in the fixture. It was a fixture defect, not a core one; the original failure is preserved in `tests/results/acceptance-criterion3-leader-failure.json` and `REPORT-criterion3-leader-failure.md`.

> New assertions in this round: clock coherence of the fixture (CDP×NetLog) and calibrated unit `milliseconds`. The ambiguity test remains strict: the two requests 20 ms apart are still ambiguous, each with the same 2 candidates and 2 `correlate.ambiguous` warnings.

Assertions: 18 passed, 0 failed (0.09 s).

## 4. Redirects and multiple attempts — approved

Evidence:

- `scrapelens-core import-netlog fixtures/acceptance/redirects/redirect-chain.netlog.json --out tests/.work/run/item4/netlog`
- `scrapelens-core import-har fixtures/acceptance/redirects/redirect-chain.har --out tests/.work/run/item4/har`

> The redirect is a link between attempts, not a separate request.

Assertions: 12 passed, 0 failed (0.06 s).

## 5. Missing/truncated/discarded bodies made explicit — approved

Evidence:

- `scrapelens-core inspect fixtures/acceptance/bodies/session`

> `empty` is only used when the source states zero bytes; absence becomes `unavailable` with a note.

Assertions: 16 passed, 0 failed (0.01 s).

## 6. Diff without losing duplicates — approved

Evidence:

- `scrapelens-core diff fixtures/acceptance/diff/session har-0001 har-0002`

> The diff compares occurrences; `reordered` uses the original indices of A and B.

Assertions: 14 passed, 0 failed (0.01 s).

## 7. cURL/Python export with special characters — approved

Evidence:

- `scrapelens-core export-curl fixtures/acceptance/export-special/session har-0001` → `bash -n` + execution with a stub that records argv
- `scrapelens-core export-python fixtures/acceptance/export-special/session har-0001` → `python3 -m py_compile` + AST with literals
- generated commands: tests/.work/run/item7/export.sh, tests/.work/run/item7/export.py

> The exporters promise the HTTP request, not TLS/fingerprint (JA3/JA4, frames, HPACK).

Assertions: 23 passed, 0 failed (0.13 s).

## 8. Sanitization including raw events — approved

Evidence:

- `scrapelens-core sanitize fixtures/acceptance/sanitize/session tests/.work/run/item8/sanitized`
- permissions: `0o700` on the directory and `0o600` on session.json
- recursive scan for 10 SECRET-* markers + email: no occurrence

> Sanitization does not promise to detect tokens in path/free HTML; those bodies are omitted with a warning.

Assertions: 19 passed, 0 failed (0.05 s).

## 9. Real capture cycle on macOS — approved

Evidence:

- real run: `tests/capture/runs/20261027T0730Z` (generated by `tests/capture/run-cycle.sh`); stable copy in `tests/results/capture-latest/run.json`
- packaged app: `ScrapeLens.app` 13.23 MiB, arm64, ad-hoc, single binary, executable `a7004d4e95e86e2d53750a76b0579d345cabf6e53cb25c3b15c446d25ec522c0`; live capture capture-1793085113332 (11 req, 154 verified headers, 2 ambiguous); HAR import through the UI `har-3dbc391c02a985c5-2` (24 req, ['h1', 'h2'], 24 sourceEvents); NetLog import through the UI `netlog-1704043c442dcbd1-2` (32 req, ['h1', 'h2', 'h3', 'unknown'], 15 StreamSessions, 5354 sourceEvents).
- real app sessions: `/Users/cesar/Library/Application Support/app.scrapelens.desktop/sessions` · screenshots `tests/results/app-latest/screenshot-app-live.png` and `tests/results/app-latest/screenshot-app-imports.png`
- CLI: Chrome 156.0.8078.48; 27 requests; 14 h3 StreamSessions; 2 ambiguous; redirects=6

> The real `/page` page exercised redirects and POSTs.

> The cycle's HAR is rebuilt from the CDP (`experiments/har_from_cdp.mjs`), because Chrome 156 does not expose `Network.getHAR`; the creator declares the origin and the order is not proven (unverified).

> The real cycle uses CDP, which does not fetch bodies: all bodies stay `unavailable` with a note. Body capture (Network.getResponseBody) is not yet on the live path.

> In this round the Start session/Stop session cycle was redone on the final bundle (`a7004d4e95e8`, built on 2026-10-27 04:00 UTC−03 with the core up to `0adff48`, including `4468a81`); the live session above is new, not reused.

> The HAR and NetLog imports were also redone on the final bundle (`har-3dbc391c02a985c5-2` and `netlog-1704043c442dcbd1-2`), now through the UI: the user selected the files manually because the native file panel cannot be reached by a synthetic click in this environment (TCC was granted; the limitation is the picker's). The verification is independent of the user's confirmation: the recorded HAR reproduces the method/URL sequence of `har-derived.json` (24 entries) and the persisted `netlog.json` is byte-identical to `h1h2h3.chrome-netlog.json` (SHA-256). The user imported each file twice; the repeated copies have an identical `session.json` and sit in `har-3dbc391c02a985c5` and `netlog-1704043c442dcbd1`, with no effect on the validation. The isolated NetLog warns `netlog.time_unit_assumed` because, without CDP, the NetLog clock unit cannot be calibrated — the limitation is made explicit in the session.

Assertions: 118 passed, 0 failed (0.10 s).

## 10. Large import with documented size — approved

Evidence:

- `/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` → HAR 16.6 MiB, 20,000 requests, 0.97 s, peak 783 MiB RSS
- recorded session: session.json 225.8 MiB
- `/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` → 2.64 s, peak 2822 MiB RSS
- complementary, 20,000 attachments of 20 B: import 3.72 s, peak 795 MiB, session 228.9 MiB

> Main HAR: 20,000 requests, 16.6 MiB, no bodies (the pathological path with 20 thousand attachments is measured separately).

> `inspect` materializes the pretty JSON of the whole session (225.8 MiB); the 2822 MiB peak comes from serialization, not from the parser.

> Core fix confirmed: above 256 attachments the `fsync` is batched per directory — 20,000 attachments of 20 B import in 3.72 s (they took 128 s in the previous battery). Small sessions keep `fsync` per file.

Assertions: 7 passed, 0 failed (13.91 s).

## How to reproduce

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/acceptance/run_acceptance.py --build-fixtures
python3 tests/acceptance/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/acceptance/run_acceptance.py   # uses the last recorded capture
```

Everything offline: synthetic fixtures in `fixtures/acceptance/`, `.invalid` domains; criterion 9 uses Chrome with a dedicated temporary profile and local servers. Nothing is published and no telemetry is generated.
