# ScrapeLens — Official contracts (wave 2)

They replace `app/CONTRACT-DRAFT.md` (provisional). Provenance and verdicts: `docs/02-fidelity-matrix.md`; decisions: `docs/01-decisions.md`.

## 1. Own session format (v1)

Session directory:
```
<session>/
  session.json        # metadata: schemaVersion=1, browser, startedAt/endedAt, completeness
  cdp-events.jsonl    # raw CDP events (one per line)
  netlog.json         # original NetLog recorded by Chrome
  attachments/        # bodies (request/response) by requestId
```

Rules:
- `session.json.completeness`: `complete | partial` (partial = failure before the flush).
- Headers are **ordered arrays of pairs** `[name, value][]`; never a dictionary. Duplicates preserved.
- Pseudo-headers separated (`:method`, `:path`, etc.), never mixed with regular headers.
- `Cookie` field: preserve (a) the original value from the source, (b) the parsed inner pairs, (c) the split lines observed on the wire (h2/h3). `Set-Cookie`: raw lines + parsed.
- Each unit of information carries `provenance`: `{source, event, timestamp, browserVersion, method, verification}`.
- `verification` per piece of information: `verified | partial | unverified` (matrix D2 in `docs/01-decisions.md`). "unverified" = the UI shows "not verified".
- Normalized views (for search/diff) are derived, and never replace the original.

## 2. Correlation

Entities: `LogicalRequest`, `Attempt`, `Redirect`, `Connection`, `StreamSession`. Explicit keys when the source provides them (e.g. `loaderId`+`requestId` CDP, `source_dependency` NetLog). The URL+method+time heuristic yields `match: "ambiguous"` when there is >1 candidate — never a silent association.

## 3. Modules and ownership (wave 2)

| Owner | Paths | Delivery |
|---|---|---|
| Core/importers | `core/` | v1 model, HAR/NetLog/own parsers, correlation, persistence, diff, cURL/Python exporters, sanitization |
| App/interface | `app/`, `src-tauri/` | Tauri 2, shortcuts ⌘O/F/C, native dialogs, integration with real capture |
| Tests/integration | `testserver/`, `fixtures/`, `tests/` | synthetic fixtures of the spec cases, acceptance tests |
| Capture/protocols | `experiments/`, Rust launcher in `core/capture` if delegated | Chrome/CDP/NetLog launcher as a library usable by Tauri |

## 4. Cross-cutting rules

- Continuous Conventional Commits; nothing is done without a commit.
- Synthetic fixtures identified; zero telemetry/network; nothing published.
- Unavailable/truncated/discarded bodies: explicit state in the contract (`body: {state, bytes?, truncatedAt?}`).
- Captured HTML is data, never an executable interface.
