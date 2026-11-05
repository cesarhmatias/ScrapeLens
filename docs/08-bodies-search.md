# Round 4 — CDP bodies and payload search

## Motivation

Live capture does not record bodies. `core/src/parse/cdp.rs` marks every
request and response as `unavailable` ("CDP body not loaded"). The UI search
filters metadata only. The DETRAN-PB reference case
(`docs/05-case-reference-detran.md`) needs to find `cmd_consultar_placa` in
the form-urlencoded body and tell apart two POSTs with the same URL and the
same method. Specification: "Payload and bodies when available", "Search and
filters" and "Show unavailable, truncated or discarded bodies explicitly".

Out of scope: Natural for Ajax decoder, dynamic × static comparison between
captures, replay, external network and publication.

## Waves (max. 3 executors)

- 4a, in parallel: Capture (record bodies), Core (import bodies + search) and
  Tests (fixtures with bodies), all on the format in §1.
- 4b, after 4a is green: App (search and bodies in the UI) and independent
  review.

## Ownership in this round

| Owner | Paths |
|---|---|
| Capture | `src-tauri/src/capture.rs`, `experiments/` (body evidence) |
| Core | `core/` |
| Tests | `fixtures/`, `testserver/`, `tests/` |
| App (4b) | `app/`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs` |
| Leader | `docs/` |

If anyone needs a file that belongs to another owner, they must report before
editing. Preserve `tests/results/app-latest/testserver/app-20261027/h1.jsonl`
(pre-existing modification, outside the commits).

## 1. `cdp-bodies.jsonl` format (contract between Capture, Core and Tests)

Sibling file of `cdp-events.jsonl` in the capture directory, with permission
0600 and one JSON object per line:

```json
{"v":1,"requestId":"1234.5","attemptIndex":0,"kind":"request|response",
 "state":"captured|truncated|empty|unavailable|discarded",
 "encoding":"utf8|base64|null","data":"…|null",
 "originalSize":123,"capturedSize":123,
 "source":"requestWillBeSent.postData|requestWillBeSent.postDataEntries|Network.getRequestPostData|Network.getResponseBody",
 "reason":"text|null","timestamp":12345.678}
```

Rules:
- `requestId` and `attemptIndex` follow the attempt numbering that the core
  already uses (`attemptIndex` 0 = first `requestWillBeSent`; each redirect
  adds 1).
- Request body: per attempt, taken from the `postData`/`postDataEntries` of
  the respective `requestWillBeSent`; if `hasPostData` with no data, use
  `Network.getRequestPostData`.
- Response body: final attempt only, via `Network.getResponseBody`
  after `loadingFinished`. Redirect responses get `unavailable` with the
  reason "redirect response: CDP provides no body". `loadingFailed`,
  an evicted resource or a CDP error also become `unavailable`, with the
  real error message.
- Limit per body: default 5 MiB of decoded bytes. Above that, record the
  prefix with `truncated` and `originalSize` when known. Total session
  budget: default 256 MiB. Once exceeded, the following bodies are `discarded`
  with the reason "session body budget exceeded".
- `base64` if the CDP says `base64Encoded` or if the bytes are not valid
  UTF-8. Never decode, reinterpret or normalize `data`: the bytes are
  the ones delivered by the CDP.
- Streaming, WebSocket and SSE are `unavailable` with a reason, never empty.
- Collection must not delay navigation or lose events. Collection failures
  become `unavailable` lines, never silence.

## 2. Core

- `import-capture` reads `cdp-bodies.jsonl` next to the events `.jsonl`,
  or takes `--bodies <file>`. Without the file, it keeps the current behavior,
  with one warning per session (not per request).
- Each `captured`/`truncated` body becomes an attachment in `attachments/`
  with the state and the provenance (`Source::Cdp`, event = `source`,
  `requestId`). The `unavailable`/`discarded` lines carry the reason. An
  orphan line (nonexistent request) generates a warning, never an association
  by URL or time.
- Search lives in the core: `search(session, query) -> Vec<Match>`.
  - Scopes: `url`, `requestHeaders`, `responseHeaders`, `cookies`,
    `requestBody`, `responseBody`. The default is all.
  - Match: `requestId`, `attemptId`, `scope`, `field` (header name, form
    key, JSON path or null), `byteOffset` in the original, `snippet`
    and `decoded: bool`.
  - Optional, marked decoded view: percent-decoding of
    form-urlencoded and unescaped JSON strings. A match in it carries
    `decoded=true` and the `field`.
  - Binary or base64 bodies that are not text are counted as
    `skippedBinary`, not searched. `truncated` bodies are searched and the
    result says "partial search".
  - CLI: `scrapelens-core search <session> <text> [--scope …] [--case-sensitive]`
    with JSON output.
- The export (cURL/Python) now includes the `captured` body of the correct
  attempt, without changing the current guarantees.

## 3. Round acceptance

1. DETRAN-PB (fixtures with synthetic bodies from Tests): `search
   cmd_consultar_placa` finds exactly the 2 POSTs by `requestBody`
   (`decoded=true`, correct `field`) and none by URL. The synthetic plate of
   the 1st lookup finds only the 1st. `cmd_nova` finds the right POST.
2. Live capture against the local `testserver`: form-urlencoded POST, JSON and
   binary. The recorded bytes are identical to those received by the server.
   The response is identical to the bytes served (text and gzip decoded by
   Chrome).
3. A body > limit becomes `truncated` with `originalSize`; a 302 redirect has
   an `unavailable` response with a reason; a 307 with a body has the request
   body in each attempt.
4. No missing body appears as empty. `empty` only with evidence (e.g.:
   204, `Content-Length: 0`).
5. Sanitization: bodies are still redacted by the current policy. Search
   in a sanitized session does not find the sensitive markers.
6. Green test suite: `cargo test` (core, src-tauri), `tests/export`,
   acceptance `tests/acceptance/run_acceptance.py` with no regression.

Conventional Commits per owner, no push or publication, no execution of
exported code and no external network.

## Decisions during the round

- 2026-10-28: `Match.requestId` is the session's logical ID (`cdp-rNNNN`). The
  CDP ID stays in the provenance (`source_id`). The API receives `SessionBundle`,
  because the bodies live in attachments, and returns `SearchResult { matches,
  skipped_binary, partial, partial_attempts, limit_reached }` (core 0c924a8).
- Known risk, non-blocking: `LogicalRequest.url` is the URL of the 1st
  attempt and body/headers are from the last. On a 307, the export combines the
  initial URL with the final body. This is equivalent to a replay that follows
  the redirect, but the export must flag it; left for review in 4b.
- Sanitization by value propagation: a value that the policy already classifies
  as sensitive (sensitive key, header or cookie) is redacted in all
  occurrences in the sanitized session, in literal, percent-encoded and
  JSON-escaped forms, including inside opaque fields (e.g.: `XML` of Natural
  for Ajax). There is a minimum length and trivial values are not propagated.
  Binary bodies are not scanned and this is declared. Delta (`DLTA…`) and
  `STAMP` are protocol state, not credentials, and stay visible.

## Review of wave 4a (2026-10-28) — decisions

Reviewer: partial, with 1 high failure. Fixes:
- Value propagation: apply only to value fields (URLs, header/cookie/Set-Cookie
  values, bodies and attachments, notes), never to enums, IDs or attachment
  names. Any error in propagation makes the sanitization fail closed;
  never return partial success.
- Variants: percent-encoded hex without distinguishing upper and lower case, and
  `+` as space in form-urlencoded.
- Custom headers: classify by name (auth, token, jwt, secret,
  session, signature, api-key, password, credential). They propagate.
- Propagation source: only high-confidence classes (authentication headers,
  cookies, keys session/token/password/secret/jwt/auth/cpf).
  Generic keys (`key`, `code`, `state`) are redacted in place, without
  propagating. Digit-only values coming from a sensitive key propagate from
  10 digits on (CPF and phone).
- Search: the decoded view undoes JSON escaping (`\uXXXX`, `\"`) and the
  URL percent-encoding. `byteOffset` points to the exact span in the original.
- Transformed bodies: format v1 gains the optional field
  `"transformed": [..]`, for example `"chrome-decoded"`,
  `"charset:iso-8859-1->utf-8"` or `"lossy-postData"`. The core exposes the
  marking as a body not identical to the wire, and the UI displays it. The
  identical-bytes criterion applies only to bodies without `transformed`.
- GET/HEAD with no body line and no `hasPostData`: `empty` with the reason
  "CDP: request without body". The current misleading message is removed.
- The cURL/Python export flags in the code itself when the initial URL of
  a 307/308 differs from the final one.

## Closing (2026-10-28)

Independent re-review up to 71eef98: Part A (core, capture, fixtures)
APPROVED; Part B (app) APPROVED, with a caveat: live app not opened by the
reviewer. No critical or high failures. Test suite: cargo test core and src-tauri
(36 ok/3 ignored), tests/export 18/18, run_acceptance 10/10,
check_bodies_search detran 5/5 / edge 2/2 / sanitized OK, run_bodies 20/20
live. Search memory on the large session: peak 1,75 GB → 257 MB. Bundle
0e2754f4….

Finishing touches (non-blocking), delegated:
- Core: cURL/Python export warns when the body has `transformed` (medium);
  double percent-encoding variant in propagation; provenance of GET
  `empty`.
- App: highlight legend consistent with the visible highlight; remove
  `evidence/bodies-search/debug.png`; less noisy `chrome-decoded` warning
  (discreet summary and emphasis only for charset/lossy).

Accepted as a limitation: raw HAR/CDP files imported without `--label`
appear as a real import. The file carries no label, and the app must not
guess. The repository fixtures are always imported with
`--label synthetic-fixture`.
