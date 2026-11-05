# Multi-target capture (Round 10, wave 1)

Contract: [`docs/14-captura-multi-alvo.md`](../../docs/14-captura-multi-alvo.md).

Chrome + NetLog + CDP harness with `Target.setDiscoverTargets`, `Target.setAutoAttach`
(flatten, configurable `waitForDebuggerOnStart`) and `Network.enable` before
`Runtime.runIfWaitingForDebugger` in each child session.

## Reproduce

Local smoke (until `testserver` exposes `GET /multi/`):

```bash
cd experiments
python3 multi_target/run_multi.py --smoke --out results/multi-target-smoke
python3 multi_target/analyze_multi.py \
  --run results/multi-target-smoke/with-wait \
  --run-no-wait results/multi-target-smoke/no-wait \
  --out results/multi-target-smoke/analysis.json
```

Once the tests publish `/multi/`:

```bash
python3 multi_target/run_multi.py --testserver --port 8781 --out results/multi-target
```

Outputs per variant (`with-wait`, `no-wait`):

- `cdp-events.jsonl`, `cdp-sessions.json`, `cdp-bodies.jsonl`
- `chrome-netlog.json`, `plan.json`, `server.jsonl`
- `analysis.json` (comparison)
