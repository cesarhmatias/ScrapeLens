# Round 10 — multi-target capture (initial contract)

Date: 2026-10-29. Owner: leader. Principle: prove fidelity before
implementing.

## Problem

Live capture follows a single CDP target. NetLog sees the whole browser's
traffic, but requests from popups, new tabs (`window.open`,
`target=_blank`), out-of-process iframes (OOPIF, other origin), dedicated
workers and service workers are left without CDP headers/bodies. This affects
correlation (specification: "consider ... service workers").

## Wave 1 — experiment (no production code)

Test server (Tests, `testserver/`): a page that opens a popup
(`window.open`), a `target=_blank` link, an iframe from ANOTHER origin (another
port on 127.0.0.1 and a name in /etc/hosts no; use `localhost` × `127.0.0.1`
or two ports), a dedicated worker that does `fetch`, and a service worker that
intercepts and does its own `fetch`. Each request with a unique marker in the URL.

Experiment (Capture, `experiments/`): Chrome with NetLog + CDP via
`Target.setDiscoverTargets` and `Target.setAutoAttach {autoAttach, flatten:
true, waitForDebuggerOnStart: true}` (with `Runtime.runIfWaitingForDebugger`
after `Network.enable` in each child session), also applied
recursively in the child sessions. Measure, per target type:
- requests seen by NetLog × by CDP (per marker);
- whether the new target's first request is lost without `waitForDebuggerOnStart`;
- transmitted headers (`requestWillBeSentExtraInfo`) and bodies
  (`getResponseBody`) available per child session;
- does `requestId` collide between sessions? (key = sessionId + requestId);
- service worker requests: do they appear in the SW's target, on the page, or in
  both? `fromServiceWorker`/`serviceWorkerResponseSource` in the response;
- cost: number of sessions, events and time.

Output: a table in `docs/02-fidelity-matrix.md` (new section) and evidence
in `experiments/`. No change in `src-tauri/` or `core/` in this wave.

## Decisions already made

- The CDP request key becomes (CDP sessionId, requestId); the targetId
  and the target type are recorded as provenance.
- An untracked target remains visible only through NetLog, marked as such,
  never with invented headers.
- The final design (core/app) is only fixed after the wave 1 table.

## Wave 1 result (Capture, 9a6021d/5d46a8a)

Chrome 156.0.8078.74, headless and headful, recipe: `Target.setAutoAttach
{autoAttach, waitForDebuggerOnStart, flatten}` on the page session AND on each
child session received in `Target.attachedToTarget`, then `Network.enable`
on it and `Runtime.runIfWaitingForDebugger`. Result: page, popup, OOPIF,
dedicated worker and service worker with CDP network on the target's `sessionId`. Chrome
limit: the document of a tab opened by `target=_blank` only has
`responseReceived` on the child session (no `requestWillBeSent`); NetLog covers it.
Without `waitForDebuggerOnStart` half of the markers are lost. `requestId`
collides between sessions. ExtraInfo order is not wire order (no change in the
matrix).

## Wave 2 — implementation contract (leader's decision)

Recording (`src-tauri/src/capture.rs`, owner: Capture):
- The recipe above, recursive, with a command queue per session; `browser_ui` and
  non-network targets ignored. A target that fails to attach is recorded as such.
- `cdp-events.jsonl`: every line gains `sessionId` (string; the initial
  page's session has its own too). The events `Target.attachedToTarget`,
  `Target.detachedFromTarget` and `Target.targetInfoChanged` are recorded.
- `cdp-bodies.jsonl`: each line gains `sessionId`.
- A capture with no events from any target remains an error; a target that failed to attach
  becomes a warning, not an error.

Model and import (`core/`, owner: Core):
- CDP request key: (`sessionId`, `requestId`); bodies mapped by
  (`sessionId`, `requestId`, `attemptIndex`). An old file without `sessionId`
  = one implicit session (compatible with the sessions already recorded).
- Provenance per request: `targetId`, type (`page`, `iframe`, `worker`,
  `service_worker`, `shared_worker`, other), target URL and `openerId`
  /parent session, from the Target events.
- A request intercepted by the service worker appears in two sessions: the
  two observations are linked as the same logical request only with
  explicit evidence (e.g.: `fromServiceWorker`, same URL/method and
  time window as a hint, never proof); without sufficient evidence,
  ambiguity is recorded.
- Correlation with NetLog: a NetLog request with no CDP pair remains
  NetLog-only, with the target type unknown; the `_blank` document
  (only `responseReceived`) links to NetLog if the evidence allows, otherwise
  it stays partial with a note.

Acceptance (`tests/`, owner: Tests), on `testserver /multi/` with the product's
REAL capture (not the experiment harness):
- 16/16 markers in NetLog; ≥ 15/16 with CDP (expected exception: document
  `blank-1`), each with the right target type;
- POSTs with request and response body equal to the server's `body_sha256`,
  per target type;
- no request merged between sessions through an equal `requestId`;
- sw-intercept: two linked observations or explicit ambiguity, never a silent
  duplicate;
- old live sessions and current fixtures import with no change of
  result (existing acceptance runs green).

Interface (App) is left for wave 3: target filter/column and limit warning.

## User manual test (2026-10-30)

Multi-tab capture on the final bundle 02e6ef30… (HEAD 8cfe828, commit 18cbb01): APPROVED by the user ("aprovado" (approved)).

## Round 10 closing (2026-10-31)

APPROVED WITH LOW CAVEATS (reviewer, HEAD 9f4003b; /tmp/rev24/VEREDITO.md).
Reference bundle: 7a46fa4c52ca90d2d720edcd1fe6b39da8bf390968bbd667952bb376005d2b7c
(commit 0d98615). Multi-target acceptance 5/5 (Tests) and 3/3 (reviewer): 16/16 NetLog
and CDP, 0 setup warnings, SW without copies, link to the SW always "unconfirmed"
and only to the candidate with the same method/path; 9 self-test mutations are rejected.
Final decisions:
- Primary = first session per targetId; duplicates: resume + detach.
- Setup in a non-blocking pipeline; a command without a response only becomes a warning at
  shutdown, in any session; an essential command error = warning
  `cdp.target_setup_error`; a target that ended = note, no warning.
- Page↔SW link: always `ambiguous`, same method, preference for same
  path; `linked` only with explicit CDP evidence.
- A file without Target.* events = no target provenance (old sessions).
Low caveats CLOSED: run_acceptance recomputes the bundle hash on disk (05f586b); cleanup of orphan Chrome/profile at startup (8fd4f6d, b684c1a). Final bundle b3e12edcfecd78ec703fa31ba2a53096a21a2e440617b148a8ce34b05c6b5157 (0be3bc0). Original text: run_acceptance does not recompute the
bundle hash on disk; orphan Chrome/profile when the parent process is killed by SIGKILL
(no cleanup at startup).
