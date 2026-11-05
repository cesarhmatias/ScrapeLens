# Round 9 — application timeline and execution validation

## Motivation

DETRAN-PB case, requirements 8 and 10 (`docs/05-detran-reference-case.md`):
- see the application's event cycle (init, on_interceptor, cmd_filtro,
  cmd_consultar_placa, cmd_nova…) on a timeline, without the protection
  noise;
- validate the exported script by comparing, side by side, a run of it with
  the capture.

ScrapeLens never runs the script and never touches the network. The one who runs it is the user
(or the Tests agent, against detran-sim on 127.0.0.1).

## Waves and ownership

| Owner | Paths |
|---|---|
| Core | `core/` (timeline, trace importer) |
| Capture | `core/src/export/priming.rs`, `adapters/natural-ajax/` (`--trace` option in the script) |
| Tests | `testserver/`, `tests/`, `fixtures/` |
| App | `app/`, `src-tauri/src/commands.rs`, `lib.rs` |

## 1. Timeline (core)

`timeline(session, body_source, opts) -> Timeline`, with one entry per
application request, in session order:
- relative time and round;
- kind: page, application POST, static resource or protection;
- label: with an adapter, the `event` and the `page` of the `XML` parts
  (`cmd_consultar_placa @ VES0009X`); without an adapter, method + path;
- assess verdict;
- key values consumed/produced, names only (`STAMP`, `XML.delta`).
Protection and static resources come in collapsed into groups with a count, between the
application events. CLI: `timeline <session>` (JSON) and, in natural-core,
`timeline --adapter natural-ajax`.

## 2. Execution trace (script) and import

- The priming script gains `--trace <file>`. It writes a JSON
  `scrapelens.trace/1` with, per step: method, URL, headers and body
  sent, status, headers and body received (with a size limit and a
  truncated state), timings and the result of the step's checks. The
  file is created with 0600 and a warning: "contains data from your session; do not
  share without sanitizing".
- Core: `import-trace <trace.json> --out <session>` imports it as a session
  (label `script-trace`, source "script execution", headers with no guarantee
  of wire order), with bodies and assess. Sanitization works on it
  as on any session.

## 3. Side-by-side validation (app and CLI)

- `compare <capture> <trace-session>` already works. The "Validate
  execution" screen pairs step by step and shows:
  - what changed (expected dynamic: STAMP, delta, SESSIONID);
  - what should be equal and is not (constants, step order);
  - the assess verdict on each side.
  Summary: "execution equivalent to capture" or "diverges at step N
  (<reason>)".
- The timeline of the two sessions sits side by side.

## Acceptance

1. Timeline of the real-shape fixture (1 and 2 rounds) and of the 3 real HARs
   (aggregate): the application events appear in the order of the manual flow,
   with `event @ page` labels via the adapter, and the protection stays collapsed.
2. Script against detran-sim with `--trace`; import-trace; compare with the
   capture (real-shape): steps paired 1:1, only the expected dynamic ones
   differ, assess app-ok on all; summary "equivalent".
3. The sim's error/nocontrols/403 modes: the trace ends at the bad step, and the
   validation points to "diverges at step N" with the right verdict.
4. The trace has 0600 and the warning; sanitize on the trace session removes
   SESSIONID/cookies/plate.
5. Test battery without regression.

## Round 9 review (2026-10-29) — decisions

Review verdict: rejected for closing; the trace is safe, but `validate` gives a
false "equivalent". Principles of validate:
- Equivalent provenance: for each field that in the capture had an origin in
  response R_k, the value in the trace must be in the paired response of R_k
  within the trace. A value equal to the captured one with a different producer in the trace
  → "diverges (frozen value)". A value coming from another response → "diverges
  (different origin)".
- Completeness: the script writes `target` (the target's requestId in the capture)
  and `complete` (bool). Validate requires the target paired and `complete=true`; otherwise
  it gives "incomplete".
- `parameters` only counts for fields WITHOUT an origin in the capture and that are not
  constants. A field with an origin, or a constant, declared as a parameter is
  ignored and generates the warning "invalid parameter". The script also writes the
  plan fingerprint (hash of the steps and parameter names); validate
  recomputes it from the capture and warns when it does not match.
- "Identifier generated on the client" only when the capture marks the field as
  without origin with composition/client; a constant (repeated in the capture or
  static) that changes is a divergence.
- Automatic origin mapping only for loopback (127.0.0.1, ::1,
  localhost). Another host requires an explicit `--map-origin`, and the summary cites the
  mapping.
Others:
- Timeline with O(n log n) cost: 4 thousand requests < 2 s, and the large
  20 thousand session finishes.
- Script: a transport error writes the trace with `error` on the step; `--trace ""`
  is an error; invalid argv fails before running.
- import-trace: limit of 20 thousand steps and of headers per step, and reduced
  memory. A base64 request body is accepted. URL/`startedAt` are
  validated.
- App: the session imported from the trace lives in a temporary folder deleted
  when the validation is closed, unless the user asks to keep it.
- check_priming_injection requires rc and POSTs > 0 per variant (or the
  expected failure at the declared step).
- Final decision on `plan.hash` (2026-10-29): a single implementation, in the
  core (`validate::plan_hash`, FNV-1a 64 over the `priming_chain` without host, the
  target and the parameter names in lowercase, sorted). The script generator
  calls it AT GENERATION and writes the constant, with no runtime calculation or
  `hashlib`. Validate recomputes it and warns "plan does not match". Earlier
  messages with different definitions are void.

## Round 9 re-review (2026-10-29)

APPROVED WITH CAVEATS (5ea75c3), no critical or high failure. Final adjustments
decided by the leader:
- M1: a `plan.hash` that does not match now gives `diverges`, reason "plan
  differs from the one generated from this capture", and not only a warning. So as not to
  punish the user who overrides an optional parameter, the hash uses only
  `plan.parameters`: the names of the plan's REQUIRED parameters, written
  by the generator. The top-level `parameters` still holds all the ones used, for the
  "user parameter" classification.
- L2: a trace without `plan` generates the warning "plan missing: execution
  not verified against the plan".
- L4: the app cleans old temporary validation folders at
  startup (confirm through the code and a test).
Accepted residuals: M2 (a short constant in a one-round capture is
indistinguishable from a parameter) and L1 (automatic map_origin to another service
on loopback, with a warning and the mapping cited in the summary).

## Round 9 closing (2026-10-29)

APPROVED (reviewer, 3b97bcc; verdict in /tmp/rev21/VEREDITO.md). Decisions
since the re-review:
- `plan.version` (integer), current = `validate::PLAN_VERSION` = 2. The hash is only
  compared with the current version; a missing or lower version warns "plan of
  an earlier version (vN)", a higher one warns "plan of a different version (vN)", without
  diverging. A plan without a hash warns "plan without fingerprint".
- Parameter exemption: only the (name, part) pair that the plan REGENERATED
  FROM THE CAPTURE produces (`priming::plan_parameter_uses`), never what the trace
  declares. Another item under a plan name goes through all the checks
  and warns "parameter does not match the plan".
- The trace's `plan.parameters` only become user parameters with the plan
  verified (current version, hash matched, target paired). An old plan or one
  without a hash exempts nothing.
- Faithful trace from the current generator: equivalent, with no warnings besides the mapped origin.
Reference bundle: d1136cbbedf32a3a9d73504196be35db1aa8885b4e6f9250a197672d477b7c1f
(HEAD 5431c5e). Accepted residuals: a frozen sid/SESSIONID only detected at
execution; an old plan or one without a hash equivalent with a warning; M2; L1.

User manual test (2026-10-29), bundle d1136cbb…: a 7-step walkthrough
(HAR through the native picker, search/Payload/adapter, priming script, timeline
and back to the session, validate ok/403/incomplete, keep run,
reopen, compare, live capture, cleanup at startup): APPROVED ("all ok").
