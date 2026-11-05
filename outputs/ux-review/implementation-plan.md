# ScrapeLens — implementation plan for the UX proposal

This plan describes future changes. **None was applied to the production frontend in this review.** Diagnosis, evidence and images: [review.md](review.md). Prototype and limitations: [proposal/README.md](proposal/README.md).

## Recommended order

| Order | Priority | Concrete delivery | Affected components/files | Dependency | Relative size |
|---|---|---|---|---|---|
| 1 | P0 | Separate origin, session state and sequence confirmation | `App.tsx`: banners, `HeaderBlock`, `VerificationPanel`, `CompareView`; `types.ts`; `v1/adapter.ts` | Audit of the v1 provenance semantics and the existing matrix | M |
| 2 | P0 | Do not hide HAR APIs because of a missing type | Filters in `App.tsx`, `v1/adapter.ts`; optionally `core/src/parse/har.rs` | Unknown-type UI is independent; `_resourceType` depends on the importer | S in the UI / M in the integration |
| 3 | P1 | Empty entry, persistent list, focus and keyboard selection | `App.tsx`: session state, table, `DetailView`; `styles.css`; Tauri menu | Preserve virtualization and existing commands | M–L |
| 4 | P1 | Local header search, cookies in a table and copy with feedback | `HeaderBlock`, Cookies content, `BodyPanel`, `VerificationPanel`; styles and clipboard | Layout and evidence policy from step 1 | M |
| 5 | P1 | Comparison from the selection, categories and “differences only” | `CompareView`, `diff.ts`, A/B state, reuse of the selector table | Stable occurrence identity and A→B direction | M |
| 6 | P1 | Expose existing exporters in “Code…” | `bridge.ts`, `src-tauri/src/commands.rs`, command registration, existing core export | Error/warning contract and attachment resolution | M |
| 7 | P2 | Saved locally, Show in Finder, import recovery | Header, notices, `bridge.revealPath`, native menu | `sessionDir` already provided | S |
| 8 | P2 | Save a bundle copy and reopen from history, if prioritized | Commands, destination dialog and recents storage | Additional shell operations; not needed by the new inspector | M–L |

S/M/L represent effort comparison between items, not schedule estimates.

## 1. Fix the fidelity language before the design

Reuse the existing per-piece provenance, keeping arrays intact. Expose a small presentation model for each header direction:

```ts
// Example of a future UI contract; it is not a new capture contract.
type HeaderSequencePresentation = {
  view: 'source' | 'normalized';
  transmission: 'confirmed' | 'unverified' | 'unavailable';
  sourceLabel: string;
  explanation: string;
  evidenceRef?: string;
};
```

“Source sequence” is a viewing mode; not an intermediate level between confirmed and not verified. `partial` must remain visible in the “not verified” explanation. Normalized is derived and needs an indication whenever it is selected.

Do not map `HeaderPair.verification === 'verified'` directly to “transmitted order confirmed”. The verification must explicitly refer to the sequence, in the supported direction/protocol and to the approved evidence. The current fixture contains CDP verification that must not become a promise of wire order. If this distinction cannot be recovered from the available provenance, present “not verified” with a reason; do not block the inspector or enrich the backend just to support the design.

The adapter already receives the raw v1. Provenance fields that are available but currently discarded for display can be exposed in the advanced panel without changing the persisted format. A new attribute that specifically certifies the transmitted order, if needed, is a contract/core evolution and must be approved in separate work.

Replace `SESSÃO REAL` (REAL SESSION) with a factual origin: “Imported HAR”, “Imported NetLog” or “Local capture”. A “ended/partial/recording” state does not use the same treatment as the HTTP status. The demonstration has a single, persistent indication. Update old messages/tooltips that still say the import is a demo until the core is integrated: it is already integrated.

**Acceptance:** a synthetic HAR is not certified as real; a partial h2/h3 request does not appear as confirmed transmission; no array is sorted to fabricate a sequence; sent and received can have different certainty; missing data does not appear as legitimate absence.

## 2. Recover the discovery of imported calls

The UI must present “type not provided” when `request.resourceType` is absent. The Fetch/XHR filter must not lead the person to conclude there was no API. When the whole session has no type, show a contextual explanation and an action to clear that filter.

An improvement available with the existing data is a MIME filter: “JSON”, counting responses with a compatible Content-Type. Do not classify JSON as Fetch, nor infer the loading mechanism just from `/api/` in the URL. Search by URL/domain remains independent.

**Dependency outside the frontend:** preserve the HAR extension `_resourceType` in the `LogicalRequest.resource_type` field. The synthetic test already provides the extension; the current parser does not carry it. It is not a requirement of the basic HAR specification and does not solve files that legitimately do not contain this field.

In the proposal, the classification already comes from `proposal/fixtures/session.json`. The working Fetch/XHR filter in the prototype **does not demonstrate that the production import was fixed**. The JSON filter and the missing-type state are documented recommendations, not yet implemented in the prototype.

**Acceptance:** the test HAR preserves types when provided; a HAR without types does not fabricate Fetch/XHR; missing type and MIME can be filtered separately; clearing filters always recovers the 64 records.

## 3. Turn the three views into an inspection space

Keep the App and the v1 contract. Extract, if needed, local components such as `RequestList`, `RequestPreview`, `HeaderSequenceNote` and `CopyStatus`; these are presentation splits, not an architecture change.

On the entry screen, use the no-session state. The demonstration becomes an explicit choice. Reuse `start_session`, `import_har`, `import_netlog` and `open_session`; preserve native dialogs and menus.

In daily work:

- Wide list + preview to locate the call; selection does not navigate immediately.
- Narrow list + detail for inspection. Search/filters stay in the list column.
- Comparison occupies the data area, keeping the session identification, the A/B references and the return to the previous selection.
- Filter/selection/tab state and list position survive the switches. Focus must be restored to an existing control, especially after filtering and going back.

Preserve the virtualized list. The prototype uses 43 px with the path and domain on two lines; **changing the height in the production CSS is not enough**, since `ROW_HEIGHT` and the start/end calculations depend on it. Choose 41–43 px according to the final layout and update a single constant used by both the calculation and the style. Do not add variable height to the virtualized rows unless necessary.

Keyboard: a single Tab stop on the selection, arrows to move through and update the preview, Enter for the detail, Escape for the preview, ←/→ in the tabs, visible focus. Respect text selection and keep native ⌘C; an explicit URL shortcut can be ⌘⇧C, as in the current menu. ⌘F focuses the list search without unmounting the detail.

**Acceptance:** repeat the two-neighboring-calls task without going back to a previous screen; selection is never lost outside the visible region; 12 thousand items keep virtualization; an empty search has recovery; full mouse/keyboard navigation at 1440 × 900 and 1280 × 800.

## 4. Make the detail readable without reducing data

Reuse `HeaderBlock`, `BodyPanel` and the cookie logic. The proposal keeps:

| Region | Presentation change | Data preserved |
|---|---|---|
| Header | Path highlighted, full URL selectable and copyable, protocol per call | Exact URL, method, status, duration and protocol |
| Headers | Search by name/value; sent/received; source/normalized selector | Original index and multiplicity; pseudo-headers in their own group |
| Evidence | One contextual line + explanation when opened | Source, event, time, method, limit and per-piece verification |
| Cookies | Sent table + raw Cookie + independent Set-Cookie | Repeated pairs, attributes, parse error, wire lines when available |
| Bodies | State and reason next to the preview | Captured/empty/truncated/discarded/unavailable and attachments |
| Advanced | Evidence/Attempts/Redirects/candidates on demand | Current data, including ambiguity and important warnings |

In the header search, keep the index and the occurrence **from before the filter**. Fixture example: searching `text/plain` keeps showing `#5`, accept, occurrence 2 of 2. The normalized view can sort a derived copy; do not mutate the source array.

Pseudo-headers can start collapsed, with “4 pseudo-headers · indices 0–3 · show”. Searching for a pseudo-header must find it without requiring manual expansion. The indication prevents the user from reading index 4 as the original start of the sequence.

Move the copy `notice` to a global status, outside the `view === 'session'` condition. Import errors belong to the session/operation, HTTP failures belong to the row. The explanation of a clipboard failure offers manual selection.

**Acceptance:** duplicates, Cookie and Set-Cookie are not merged; no value is cut in the copied data; do not infer storage from Set-Cookie; do not derive protocol from Alt-Svc; captured HTML remains text.

## 5. Compare the task, keeping the diff's precision

Reuse `diffHeaders` and `diffCookies`. Matching by name/value/multiplicity is a useful base. Audit cases of the same repeated key with identical values; an occurrence's index cannot be recovered with just a name/value `findIndex` in production. Preserve the occurrence identity during matching.

The current selection fills A; select B by searching the session list, with method/domain/status. The proposal uses a native select because it is a small fixture; do not bring a list of 12 thousand URLs into a production select.

Count differences per category, instead of a partial global total. The Headers category receives sent/received, or the response gets its own category. Payload compares fields when JSON content is captured and parseable, with the raw one available and an indication of a derived view. Missing/truncated/inaccessible payload does not become an empty object. Non-JSON content can start with a textual diff, without trying to infer structure.

Display positions as differences in the source when transmission is not confirmed on both sides. Compare relative order between stable pairs; inserting an earlier header must not mark all the following ones as reordered. Distinguish value change from position change when both occur, without erasing information. Avoid equating h1 Host and h2 pseudo-headers as common regular fields.

**Acceptance:** +added, −removed, ~value, ↕position recognizable without color; equal ones can be consulted; long URLs/values do not shift the columns; removed Cookie, changed page and different protocol have visible categories; raw data is a complement; no text asserts the cause of the 403.

## 6. Complete the path to code

Add thin commands over `core::export` and a corresponding entry in the bridge; reuse `read_attachment`/bundle to resolve bodies. Do not create another production exporter in React.

“Code…” opens format, preview, exporter warnings and copy/save actions. Do not generate pseudo-headers as regular headers. Preserve repeated headers when the format allows it, report necessary removals and body absence/truncation. Warn that the client may choose another protocol/reorder headers. The order of the arguments is not a guarantee of the transmission sequence.

The demonstration only shows cURL with synthetic data. Python and bundle export are future integration dependencies already identified, not completed features.

**Acceptance:** behavior consistent with the current core; no missing body is fabricated; attachments are not interpreted as UI; copied code matches the chosen call and the warnings presented.

## Recommended tokens and visual rules

Reuse the CSS variables of `.app`. Prototype reference values, adjustable at integration:

| Role | Reference |
|---|---|
| Data area | `#ffffff` |
| Auxiliary background | `#f6f7f9` |
| Sidebar | `#eef0f3` |
| Text | `#202a38` |
| Secondary text | `#5d6b7e` |
| Divider | `#dce1e7` |
| Action/focus | `#245bdd` |
| Selection | `#e9f0ff`, side bar and `aria-selected` |
| Success/addition | `#17704e` + text/symbol |
| Failure/removal | `#b32632` + text/symbol |
| Changed value | `#8d5c0c` + `~ Value` |
| Typography | macOS system font for UI; SF Mono/Menlo for names/values/URLs |
| Sizes | UI 13 px; priority data 12 px; metadata 11 px; only indices and auxiliary labels 10 px |
| Geometry | 1 px dividers; 5–6 px radius; avoid cards wrapping each field |

In Tauri, use native controls and title bar, without duplicated decorative HTML circles. The web prototype draws an illustrative shell for evaluation. Keep the existing light/dark; resolve one theme first, without erasing the user's preference.

## New dependencies, separate from the frontend

| Item | Requires new backend/data? | Handling in this delivery |
|---|---|---|
| List/detail, header search, focus, banners, diff by category | No; uses v1 and local computation | Demonstrated with fixture |
| MIME/JSON filter | No, when Content-Type already exists | Recommended in the plan; not prototyped |
| Preserve HAR `_resourceType` | Yes, adjustment to the existing parser | Problem reproduced, not fixed |
| Confirm order when provenance does not distinguish the semantics | Maybe, explicit metadata/contract | Always conservative; do not invent certainty |
| Export cURL/Python in the UI | New Tauri integration, exporter already exists | Synthetic cURL preview in the prototype |
| Show in Finder | Command already exists | Recommendation, no new service |
| Save v1 bundle copy | Operation/dialog in the shell | Own demonstration JSON, not a v1 bundle |
| Recents history | Persistence of references and handling of a missing path | Not designed as a ready feature |
| Stored cookies | Additional snapshot, absent from this screen model | Unavailable; do not infer from sent/received |
| Real CDP bodies | Capture/download still incomplete per README | Proposal respects unavailable; does not promise to solve it |
| Compare independent sessions/import only B | New flow/state and cross selection | Outside the prototype; #64 is already part of the fixture |

## Verification in the future implementation

Use synthetic/sanitized fixtures: h1 confirmed when supported by the matrix, h2/h3 partial, HAR without type, identical/different repeated headers, split Cookie, two Set-Cookie, ambiguous correlation and unavailable body. Verify each step's criterion before widening the scope.

Priority tests are semantic and integration tests: evidence limit, loss of `_resourceType`, preservation of occurrences in the diff, virtualized list navigation and body/header export. There is no reason to create CSS snapshots as proof of HTTP fidelity.

Repeat the visual inspection at both dimensions, with keyboard, active filter and long values. For performance, repeat the 12 thousand row scenario after integrating the two-text-line rows. Perform the full capture validation later against `testserver/`, without personal profiles or real credentials.
