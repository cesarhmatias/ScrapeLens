# scrapelens-core

ScrapeLens's Rust core: session model v1, importers, CDP×NetLog correlation,
normalized views, diff and exporters. No network, no telemetry, no sidecar:
it compiles as a library for Tauri and as an inspection binary.

## Quick start

```bash
cd core
cargo test --offline

# experiment captures -> session v1
cargo run --offline -- import-capture \
  ../experiments/results/h1-page/cdp-events.jsonl \
  ../experiments/results/h1-page/chrome-netlog.json \
  --out /tmp/sl-demo

cargo run --offline -- inspect /tmp/sl-demo | head
cargo run --offline -- export-curl /tmp/sl-demo cdp-r0001
cargo run --offline -- export-python /tmp/sl-demo cdp-r0001
cargo run --offline -- sanitize /tmp/sl-demo /tmp/sl-sanitized
cargo run --offline -- diff /tmp/sl-demo cdp-r0001 cdp-r0002
```

## Modules

| Module | Contents |
|---|---|
| `model` | `SessionV1`, headers/pseudoheaders, cookies, bodies, provenance, entities |
| `parse::own` | v1 directory (`session.json` + artifacts), limits and attachments |
| `parse::har` | tolerant HAR 1.2, redirects, base64 bodies |
| `parse::netlog` | NetLog: NUL, session/transaction, unknown events, `HTTP_STREAM_JOB_BOUND_TO_REQUEST` chain |
| `parse::cdp` | CDP events, `ExtraInfo`, `headersText`, redirects, evidence |
| `correlate` | explicit/heuristic matching, `match: ambiguous` |
| `normalize` | derived views for search (never replace the original) |
| `diff` | added/removed/changed/reordered per occurrence |
| `export` | cURL, Python `http.client`, sanitization |
| `store` | atomic write with `0700/0600`, attachment validation |

JSON contract and verification rules: [`CONTRACT-V1.md`](CONTRACT-V1.md).
Project decisions: `../docs/01-decisions.md`; matrix: `../docs/02-matrix-fidelity.md`.

## Tested guarantees

- order/duplicates/pseudoheaders preserved; raw Cookie + pairs + wire lines;
- provenance and verification per piece of information (D2), not per session;
- unknown events and invalid lines always produce a `Warning`;
- real h1/h2/h3 correlation of the experiments: 12/12 matched, 0 ambiguous;
- redirect chain of the h1 contract: 3 attempts and 2 redirects preserved;
- real h1/h2 captures check order and NUL expansion;
- diff neither loses duplicates nor sorts alphabetically;
- cURL/Python escape untrusted data and refuse header injection;
- sanitization redacts secrets and omits non-sanitizable attachments with a warning;
- write/read round-trip with private permissions;
- batch attachments for large captures (one directory fsync), with fsync
  per file in small sessions; `sourceEvents*` counts persisted in
  HAR/NetLog/CDP.

## Fixtures

`tests/fixtures/` contains only synthetic data, marked `SYNTHETIC FIXTURE`,
in `.invalid` domains. The tests against `experiments/results/` use the real
captures already committed (read-only).

## Tauri integration

The app's commands can call directly:

```rust
let imported = scrapelens_core::import_har(&bytes)?;
scrapelens_core::store::write_session_dir(&imported.bundle, &session_dir)?;
// return imported.bundle.session (SessionV1 serializes in camelCase)
```

`import_netlog` and `import_capture(cdp, netlog, CorrelationOptions::default())`
follow the same shape. Errors are `CoreError` (implements `Display`), suitable
for actionable messages in the UI. To open a session, use
`import_session_dir` — it validates `schemaVersion`, loads attachments and returns
incompleteness warnings.
