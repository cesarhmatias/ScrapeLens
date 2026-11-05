## Multi-target capture (CDP auto-attach × NetLog)

Contract: `docs/14-capture-multi-target.md`. Harness: `experiments/multi_target/`.

| Item | Value |
|---|---|
| Browser | Chrome headless=new (see `cdp-sessions.json`) |
| CDP | `Target.setDiscoverTargets` + `setAutoAttach` (flatten, `waitForDebuggerOnStart` true/false) |
| Preliminary evidence | `experiments/results/multi-target-smoke/` (local smoke; **repeat** with `testserver` `GET /multi/` once the tests are published) |

### Table by target type (marker `?m=`, **with** `waitForDebuggerOnStart` variant)

| Target type | Server (JSONL) | NetLog | CDP (child session) | ExtraInfo (order) | CDP bodies | SW `fromServiceWorker` |
|---|---|---|---|---|---|---|
| Popup (`window.open`) | yes | yes | yes | yes | yes | — |
| New tab (`target=_blank`) | not verified | not verified | not verified | not verified | not verified | not verified |
| OOPIF iframe (other port) | yes | yes | yes | yes | yes | — |
| Dedicated worker | not verified | not verified | not verified | not verified | not verified | not verified |
| Service worker (intercept + own fetch) | not verified | not verified | not verified | not verified | not verified | not verified |
| Main document | not verified | not verified | not verified | not verified | not verified | not verified |

### Variant **without** `waitForDebuggerOnStart`

- First request lost in CDP (markers `popup-first` / `blank-first` / `oophif-first`): not verified (smoke incomplete in this run)
- CDP sessions: 5; Network events: 15

### `requestId` collision across sessions

With wait: **3** pairs `(requestId)` seen in more than one session (correct correlation requires `(sessionId, requestId)`). Without wait: **1**.

### Cost (with-wait variant, smoke)

| CDP sessions | Total events | Network.* events | Capture time |
|---:|---:|---:|---:|
| 11 | 135 | 50 | 32999 ms |

**Recommendation (1 line):** use auto-attach with `waitForDebuggerOnStart` and key `(sessionId, requestId)`; targets without a CDP session stay NetLog-only; repeat the official measurement against `testserver` `/multi/` before fixing the product.

