# ScrapeLens — Plan (living)

Open-source macOS app for inspecting HTTP sessions, aimed at scraping
developers. Full specification:
`/Users/cesar/Documents/Codex/2026-10-26/meu-x20/outputs/ScrapeLens-especificacao.txt`

## Status

- Phase: 9 — local arm64 package rebuilt and validated; final documentation.
- Export round in the UI (docs/07) completed: F1/F2 (links in ancestors)
  fixed in 16015a1, tolerant adapter in 0d4dbab, bridge 16/16. Native proof
  on bundle 9c04b98b (save/cancel, copy, sanitize and reopen) done by the
  leader with dialogs in the foreground and verified by Tests (adc56ab).
- Round 4 (docs/08), CDP bodies and payload search: completed and approved in
  the independent re-review (up to 71eef98; bundle 0e2754f4…). Bodies recorded
  live with explicit state and `transformed`; search over 6 scopes with decoded
  view and exact range; sanitization by value propagation (fail-closed);
  origin labels; truncated NetLog repaired; search with attachments on demand
  (peak 1.75 GB → 257 MB). Non-blocking polish in progress.
- Round 5 (docs/09), origin of values, priming chain and comparison between
  captures: completed and approved in the re-review (bundle ac7213b2…). Next:
  validation on the real DETRAN case (local HARs, no data in the repository)
  and round 6 (priming script and application success × HTTP).
- Round 6 (docs/10), fidelity to the real DETRAN-PB case: APPROVED (7a11441).
  The case is identifiable and analyzable in the user's 3 real HARs.
- Round 7 (docs/11), priming script and application success × HTTP:
  APPROVED (1bdd8b9); detector polish in 6a85676.
- Final package: bundle 6e301e70… (c5d1f61), final acceptance green
  (tests/REPORT-FINAL.md, 4b16b0e), delivery in docs/06-delivery.md.
  Pending: manual test of the .app with the native picker (user).
- Round 8 (docs/12), Natural for Ajax adapter outside the core: APPROVED
  (c07b514, polish in progress). UTF-16 prefixes recalculated in the priming
  script (proof on detran-sim strict), structured view in the app and internal
  names (XML.delta, XML.p.v_placa) in origins/compare. On the 3 real HARs: 11 steps in the order
  of the manual flow, only the plate and the SESSIONID suffix as parameters, 0 values
  captured in the code; proof on detran-sim in the 4 modes.
- Automated acceptance: 10/10 criteria (283 checks in 229b623).
- New capture and HAR/NetLog imports through the UI of the final bundle validated.
  Manual selection by the user and independent check of the persisted files.
- Closing report: `docs/06-delivery.md`; nothing published.
- Repository created at `/Users/cesar/Projects/scrapelens`.

## Models in use

On 2026-10-28, by user decision, all agents in the channel, except the
leader, use Claude Sonnet 5.5 (`claude-sonnet-5-5`, low effort), with automatic
fallback `opencode/deepseek-v4.1-flash-free` if the quota runs out. History:
GLM-5.3/DeepSeek V4.1 Flash (OpenCode Go) → gpt-6.1-sol (leader/reviewer/docs) →
Sonnet 5.5 low. On 2026-10-28, by user decision, all non-decision agents
(Documentation, Capture, Core, Tests and App) moved to
`opencode-go/deepseek-v4.1-flash` (OpenCode Go, high effort), with automatic
fallback `opencode/deepseek-v4.1-flash-free` when the quota runs out. The
decision makers (Leader and Independent reviewer) did not change model. On 2026-10-29 the
`opencode-go/deepseek-v4.1-flash` failed: tasks were ended in ~1 s,
with no work done, and the direct call through the CLI did not respond in 3 min. The
executors went back temporarily to Sonnet 5.5 low until DeepSeek was
diagnosed. Diagnosis (OpenCode log): "Go usage limit exceeded"
(OpenCode Go subscription quota exhausted), and the automatic fallback did not
kick in. On 2026-10-29, at the user's request, the non-decision agents (Core, Tests,
App, Capture and Documentation) moved to `opencode/deepseek-v4.1-flash-free`
(high effort), tested and responding. In force from the next task of each
one. Reviewer and Leader unchanged. On 2026-10-29 03:14 the free quota also
ran out ("Free usage limit reached"); the executors went back to Sonnet 5.5 low,
and the lost tasks were resent. On 2026-10-29 ~17h, at the user's request, the Leader moved from Claude Opus 5.5
to Grok 4.7 (high), and the 6 agents on Sonnet (Core, Tests, App, Capture,
Documentation and Reviewer) moved to `opencode-go/deepseek-v4.1-flash`
(high), which is responding again (quota renewed; the free tier still has no quota). The
automatic fallback is Claude Sonnet 5.5. No silent model substitution.

Team (OpenBot section "ScrapeLens"):

| Agent | ID |
|---|---|
| Leader and architecture | `agent-88cccd6b…a41` |
| Capture and protocols | `agent-05db9236…4c23` |
| Tests and integration | `agent-e9324ddd…4b1f` |
| Core and importers | `agent-d66aa8db…8d71` |
| macOS app and interface | `agent-466e334c…66b9` |
| Independent reviewer | `agent-ffb4d60c…ad63` |
| Obsidian documentation | `agent-636cf76c…cde3` (daily routine 09:00, America/Sao_Paulo) |

## Waves (max. 3 simultaneous executors)

- Wave 1 (completed): Capture/protocols + Tests/servers — fidelity
  experiments for HTTP/1.1, h2, h3; matrix `docs/02-fidelity-matrix.md`.
- Wave 2 (completed): consolidated contracts → Core/importers +
  App/interface + Tests (full slice: launch Chrome → capture → UI).
- Wave 3 (implementation/review completed; caveats in the final report): comparison, export, sanitization; independent review;
  packaging and documentation.

## Acceptance criteria

Per the specification (10 items). See `docs/05-acceptance.md` when created.
