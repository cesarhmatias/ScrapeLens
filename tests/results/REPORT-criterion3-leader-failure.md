# Acceptance report — ScrapeLens MVP

Run: 2026-10-27T07:08:05Z · core binary `10f3b76b637b` (2176608 bytes) · commit `453d717`

Environment: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Spec criterion | Status | Assertions |
|---|---|---|---|
| 3 | Simultaneous identical requests without false association | **failed** | 4/7 |

Criteria of the request: (1) repeated headers/cookies, (2) HAR/NetLog valid/incomplete/unknown, (3) simultaneous identical requests without false association, (4) redirects/retries, (5) explicit bodies, (6) diff with duplicates, (7) cURL/Python escaping, (8) sanitization with raw events, (9) real macOS cycle, (10) large import measured.

## 3. Simultaneous identical requests without false association — failed

Evidence:

- `scrapelens-core import-capture fixtures/acceptance/ambiguous/cdp-ambiguous.jsonl fixtures/acceptance/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

Failures:

- both marked match=ambiguous (no silent association): expected 2, got 0
- the two requests see the same set of candidates (no cross choice): expected 1, got 0
- two correlate.ambiguous warnings persisted: expected 2, got 0

> The NetLog order/duplication is preserved, but it does not become the primary view while there is ambiguity.

Assertions: 4 passed, 3 failed (0.06 s).

## How to reproduce

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/acceptance/run_acceptance.py --build-fixtures
python3 tests/acceptance/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/acceptance/run_acceptance.py   # uses the last recorded capture
```

All offline: synthetic fixtures in `fixtures/acceptance/`, `.invalid` domains; criterion 9 uses Chrome with a dedicated temporary profile and local servers. Nothing is published and no telemetry is generated.
