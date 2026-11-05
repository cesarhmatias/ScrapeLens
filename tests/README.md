# tests/ — ScrapeLens MVP acceptance

Suite that consumes the **core CLI** (`core/target/release/scrapelens-core`), the
synthetic fixtures in `fixtures/acceptance/` and, for criterion 9, a real Chrome
capture on macOS orchestrated by `tests/capture/run-cycle.sh`.

## Commands

```sh
python3 tests/acceptance/fixtures.py              # regenerates fixtures/acceptance (deterministic)
python3 tests/acceptance/run_acceptance.py       # 10 criteria; uses the last recorded capture
tests/capture/run-cycle.sh                   # real Chrome/CDP/NetLog cycle, h1+h2+h3
python3 tests/capture/app_validate.py --run-dir tests/capture/runs/app-<id> \
  --capture-id capture-<ts> --har-id har-<id> --netlog-id netlog-<id> \
  --screenshot tests/results/app-latest/screenshot-app-live.png
python3 tests/acceptance/run_acceptance.py --capture tests/capture/runs/<id>
python3 tests/acceptance/check_multi_target.py        # real multi-target capture (popup, blank, OOPIF, worker, SW)
```

Results: `tests/results/acceptance.json` and the report `tests/REPORT.md`
(promotable to `docs/05-acceptance.md`). Exit code ≠ 0 if any criterion fails.

## Structure

| Path | Content |
|---|---|
| `acceptance/fixtures.py` | generator of the synthetic fixtures (HAR, NetLog, CDP and v1 sessions) |
| `acceptance/run_acceptance.py` | the 10 criteria, assertions and report generation |
| `acceptance/check_multi_target.py` | acceptance of the multi-target capture (round 10): real capture against `testserver /multi/`, 16 markers, target types, bodies and service worker |
| `capture/capture_cycle.mjs` | dedicated Chrome + CDP + NetLog; no certificate installed, QUIC intact |
| `capture/run-cycle.sh` | starts testserver, captures h1/h2/h3, imports with the core and summarizes |
| `capture/summarize.py` | metrics of the real capture in `run.json` |
| `capture/app_validate.py` | validates the live cycle through `ScrapeLens.app` and the HAR/NetLog sessions it recorded |
| `.work/` | small sessions of the current run (not committed) |
| `capture/runs/` | raw sessions of the real capture (not committed; regenerable) |

Criterion 9 covers two legs: (a) the harness's own capture on h1/h2/h3 and
(b) the packaged app (`src-tauri/target/release/bundle/macos/ScrapeLens.app`),
with Start session/Stop through the UI, the session recorded by the app and real
HAR/NetLog imports. The summary of leg (b) is in `tests/results/app-latest/run.json`;
the harness reads it by default (or via `--app-run`).

Everything is offline: `.invalid` domains, servers on `127.0.0.1`, Chrome with
`--host-resolver-rules` blocking the rest. No telemetry; nothing published.
The fixtures are 100% synthetic and each directory carries `fixture.json` with
`label: synthetic-fixture`.
