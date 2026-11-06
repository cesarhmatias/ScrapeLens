# ScrapeLens MCP contract (round 11, wave 1)

Owner: Core and importers. Code: `mcp/` (crate `scrapelens-mcp`, binary
`scrapelens-mcp`). Basis: `docs/15a-mcp-market.md` (tools section). This
document comes before the code; contract changes go through the leader.

## 1. What it is

A **local** MCP server over already-captured sessions (read) and, since wave 2,
with controlled browser capture (§6b). An AI agent
uses it to understand a site's setup (request chain,
headers in original order, cookies, tokens, bodies) from ScrapeLens
sessions. Out of scope: acting in the browser (`act`), running scripts,
CloakBrowser (postponed by user decision), HTTP/streamable (stdio only in this
wave).

Principles:

- Reuses the core (`scrapelens-core`): no parser, correlation, diff or
  search is reimplemented. The crate only translates parameters, applies the
  security policy and formats outputs.
- Opens no network connections on its own (the core does not either; the crate does not
  depend on an HTTP client). The only traffic is that of the controlled-capture Chrome,
  restricted to the confirmed allowlist (§6b), and the CDP port on loopback. No telemetry.
- Fidelity above convenience: headers come back as **ordered arrays of
  pairs** with duplicates, pseudo-headers separated and `orderState`; they never become
  a map nor get sorted. Each view carries the source and the verification state.
- Heuristics are never presented as fact: ambiguous links, `possible`,
  `unobservable` and core warnings are passed along with the same labels.

## 2. Execution and directories

```
scrapelens-mcp --sessions-dir <dir> [--out-dir <dir>] [--extra-sessions-dir <dir>]...
               [--allow-reveal] [--max-import-bytes <n>]
```

| Option | Meaning |
|---|---|
| `--sessions-dir` | Required. Where `import_session` writes and where `list_sessions` reads from. Created 0700 if it does not exist. |
| `--out-dir` | Where the large body files go. Default: `<sessions-dir>/.mcp-out` (0700). |
| `--extra-sessions-dir` | Zero or more. Directories with **read-only** sessions (e.g.: fixtures). They never receive writes. |
| `--allow-reveal` | Without this option `reveal=true` is refused (`reveal_disabled`). |
| `--max-import-bytes` | Limit per input file of `import_session` (default 512 MiB). |

Stdout is the JSON-RPC channel; all logging goes to stderr. Transport: stdio.

### Read and write limits

- **Writes** only to: `<sessions-dir>/<session_id>/` (import) and `<out-dir>/`
  (large bodies and `export_session`) or to the validated absolute `destination` of the
  export (new/empty, 0700, outside the source session). Every write
  path is built by the server from validated names
  (`[A-Za-z0-9._-]`, no `..`, no `/`) and checked after being canonicalized: if it
  leaves the directory, the call fails with `outside_allowed_dir`. Directories 0700,
  files 0600, atomic writes.
- **Session reads**: only `--sessions-dir` and `--extra-sessions-dir`.
  `session_id` parameters are handles, never paths.
- **Import input reads**: the `path` can be any file/directory
  the user points to (the server runs with their permissions), but only a regular
  file or directory; a symlink at the root is resolved, the size limit
  applies, nothing is executed and the content is treated as untrusted data.
- Strings coming from sessions (URLs, headers, bodies) are **untrusted data**:
  the server never interprets them as instructions nor uses them as paths.

## 3. Secrets: masked by default

`reveal` (boolean, default `false`) exists in every tool that returns
values. `reveal=true` requires `--allow-reveal` on the server.
**Leader decision (round 11):** the lock is double — a per-call parameter
*and* `--allow-reveal` when starting the server; the agent cannot reveal on its own.
**Explicit exception (round 17):** `export_session` with `include_sensitive:true`
writes the values to the local 0700/0600 directory at the user's request, but the response JSON
returns no value at all (see §5.10).

With `reveal=false`:

- The session is run through the same sanitizer as `export::sanitize` (the one for
  the sanitized export), once per session, in memory, and the tools
  `list_requests`, `get_request`, `get_body`, `search_bodies`, `diff_requests` and
  `diff_sessions` operate on that copy. This covers `Authorization`,
  `Cookie`/`Set-Cookie`, tokens in URLs (query and fragment), credential
  headers, sensitive business fields and sensitive values propagated to
  other places. Placeholder: `[REDACTED]`.
- **Bodies**: only JSON and forms pass, with the sensitive fields
  redacted. HTML, JS, free text and binary **cannot be sanitized
  safely** (core policy): `get_body` returns the descriptor with
  `masked: "unsupported"` and no content; `search_bodies` does not scan them and counts
  them in `skippedMasked`. To read them, `reveal=true` is needed.
- **Body metadata** (`state`, `bytes`, `contentType`, `hasRequestBody`/
  `hasResponseBody`) comes from the original session even in the masked view, so
  the mask does not hide that a body exists; only the content is withheld.
- **`target` and `initiator`**: the core sanitizer masks `target.url`,
  `initiator.url` and the URL at the top of the stack (query and fragment) in every
  sanitized export. The server applies `sanitize_url` again to those
  fields and to the URLs of `trace_value` (defense in depth, covered by its own
  test).
- **URL forms and names** (review, docs/17): the sanitizer also covers
  fragment (`#access_token=`), matrix parameters (`;jsessionid=`), userinfo
  (`user:password@`), `name=value` without `?` (Refresh, Location, free text), `%3D`,
  authentication schemes with inexact case (`bearer`, `ApiKey`, `OAuth`…), the
  names `jwt`, `senha` (Portuguese for password), `pwd`, `otp`, `passcode`, `pin`, `ticket`,
  `SAMLResponse`, `*-api-key`, `*-appkey`, `*-secret`, `*-token`,
  `*-subscription-key`, `*csrf*`/`*xsrf*`, and the Set-Cookie `parseError` does not
  repeat the raw value.
- **Sensitive value in a path (accepted limitation, A7-B5/A8-M1):** the value of a
  sensitive name in a PATH (`/a;jsessionid=X/b`, `/s/token=X/y`) extends to the next `?`
  (or `#`, or the end of the path) and is redacted whole, `/` included, because a
  credential (base64) can contain `/`. It costs the rest of the path after it:
  `/a;v=2/session=keep/b` comes out `/a;v=2/session=[REDACTED]`. It applies equally to text
  (request line, headers, JSON) and to the URL. Non-sensitive names
  change nothing. Security prevails over fidelity. Exception (A9-B1): `,` or `|`
  followed by `/` ends the value (a list without spaces `/a/token=x/b,/c/keep` preserves the
  next item); a credential that contains `,/` or `|/` leaks what comes after.
- **Raw text with a query** (round 11, leak fix): the core
  sanitizer redacts the value of a query parameter with a sensitive name also in
  a request `startLine` (`GET /p?token=… HTTP/1.1`), in any header
  value that is not a known URL (`Refresh`, `X-Original-Url`,
  `Content-Security-Policy` `report-uri`…), in `view.notes`, provenance
  notes, `failure`, link evidence, correlation reasons and
  warning messages; propagation by value also scans `startLine`, notes,
  `target.url` and `initiator.url`. In addition, **every output without `revealed: true`
  from any tool** goes through a final scan of the entire JSON
  (`scrub_output`), not just the known fields. Limit inherited from the core:
  parameters whose **name** is not sensitive (e.g.: `k=…`) are not redacted in
  URLs; in capture outputs the entire query is dropped (`?…`).
- **Cost**: the first masked call for a session loads it whole into
  memory to sanitize it (copy kept in cache). Very large sessions
  can take seconds and answer `too_large` if the core refuses the load.
- **Secret values never appear in `trace_value`** without `reveal`: the
  tool computes over the original session (it needs the real values to
  match producer and consumer) and returns only names, lengths,
  equality booleans and positions.
- `diff_requests` and `diff_sessions` compare the masked copy: two different
  masked values appear equal (`[REDACTED]`). The output carries
  `masked: true` and the corresponding note; the core's `diff_sessions` classifies
  those fields as `redacted`, not as `static`.
- A masked `search_bodies` does not serve as an oracle: querying a secret value
  finds nothing, because it is already redacted in the searched copy.

With `reveal=true` the same tools read the original session. Each response
carries `revealed: true`.

## 4. Conventions

- Output: `structuredContent` (JSON object, camelCase, same vocabulary as the
  core's `session.json`) and the same JSON as text. All tools have
  `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`
  (`import_session` is the exception: it writes to `--sessions-dir`; it gets
  `readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`).
- IDs: `session_id` = session directory name; `request_id` = logical `id`
  of `session.json` (e.g.: `har-0003`, `cdp-r0007`).
- Pagination: `limit` (default 50, maximum 200), opaque `cursor` returned in
  `nextCursor` (absent when finished). Paginated outputs carry `total` and
  `hasMore`.
- Errors: result with `isError: true` and `structuredContent`
  `{"error":{"code","message"}}`. Parameters that do not match the schema
  (missing required field, wrong type) are refused by the SDK with
  `isError: true` and free text naming the field, without `structuredContent`. Codes: `invalid_argument`, `not_found`
  (session or request), `outside_allowed_dir`, `reveal_disabled`,
  `import_failed`, `too_large`, `exists`, `io`.
- Bodies: never giant text in the response. Inline limit `maxInlineBytes`
  (default 32 KiB, maximum 256 KiB). Above that, or if it is not UTF-8, the content
  goes to a file in `--out-dir` and the response carries `path`.

## 5. Tools

Notation: `?` = optional. All `session_id`/`request_id` are strings.

### 5.1 `list_sessions`

Input: `{ cursor?, limit? }`.
Output: `{ total, hasMore, nextCursor?, sessions: [ { sessionId, readOnly,
startedAt, browser: {name, version?}, captureMode?, requests, attempts,
completeness: {state, reasons[]}, warnings, labels[] } ] }` — sorted by
`startedAt` descending, then by `sessionId`.

### 5.2 `import_session`

Input: `{ path, format?, name? }`.
`format`: `auto` (default) | `har` | `netlog` | `session` | `capture`.
`capture` = directory with `cdp-events.jsonl` and a NetLog (`netlog.json` or
`chrome-netlog.json`), optionally `cdp-bodies.jsonl`: CDP×NetLog correlation
by the core. `session` = directory with `session.json` (native session) copied
to `--sessions-dir`. `name`: handle name (validated); without it, it is derived from the
file name and the session id. If the handle already exists: if it comes from the same
content (same `meta.id`) it returns `alreadyImported: true` without rewriting; with an
explicit `name` and different content, `exists`.
Output: `{ sessionId, alreadyImported, format, requests, warnings: [{code,
message, severity}] (up to 50), report: {sourceEvents, unknown, ...} }`.
Writes only to `<sessions-dir>/<sessionId>/` via `store::write_session_dir`.

### 5.3 `list_requests`

Input: `{ session_id, host?, method?, status?, resource_type?, text?,
cursor?, limit?, reveal? }`.

- `host`: equal (case-insensitive) to the URL's `host[:port]`.
- `method`: equal, case-insensitive.
- `status`: `"200"`, `"2xx"`, `"4xx"`, `"none"` (no response) or a number.
- `resource_type`: equal (case-insensitive) to the request type (CDP/HAR).
- `text`: substring (case-insensitive) in the **presented** URL (masked
  if `reveal=false`). For bodies use `search_bodies`.

Output: `{ sessionId, total, hasMore, nextCursor?, items: [ { requestId, method,
url, host, status?, resourceType?, protocol, totalMs?, attempts, redirects,
sources[] ("cdp"|"netlog"|"har"|...), match, targetType? , hasRequestBody,
hasResponseBody, startedAt?, warnings? } ] }` in **session order, which is not
chronological** in real captures (measured: the list comes by id; `cdp-r0004` may be the
first request in time). `startedAt` (seconds from the source, lowest time among
the attempts) allows sorting. Summary only: no headers or bodies.

### 5.4 `get_request`

Input: `{ session_id, request_id, attempt?, verbose?, reveal? }`.
`attempt`: attempt id or index (default: primary view of the logical
request, which is the last attempt). `verbose`: also returns the provenance per
entry (default: per view only).

Output:

```
{ sessionId, requestId, method, url, status?, protocol, resourceType?,
  target?, links[], attempts: [{id,index,url,status?,outcome,connectionId?,streamSessionId?,match}],
  redirects[], 
  request:  { startLine?, orderState, source, verification, pseudoHeaders: [[n,v]],
              headers: [[n,v]], rawBlock?, notes[] },
  response: { ...idem... },
  cookies:   { raw[], pairs: [{name,value}], wireLines[], unparsed[] },
  setCookies:[{ raw, name?, attributes{domain,path,expires,maxAge,secure,httpOnly,sameSite,partitioned}, parseError? }],
  headerEvidence: [{ id, role, protocol, event, sourceId?, order, count }],
  requestBody:  { state, bytes?, contentType?, contentEncoding?, transformed[], note?, hasContent },
  responseBody: { ... },
  timings: { totalMs?, tls?, send?, wait?, receive?, estimated },
  initiator?: { kind, url?, line?, stackTop? ... },
  origin: { logical: "cdp"|"netlog"|"har"|..., cdp?: {sessionId,requestId,loaderId,frameId}, netlog?: {sourceIds[],streamIds[]}, match, matchCandidates[] },
  warnings[], revealed }
```

Headers come **in original order** (`headers` and `pseudoHeaders` separate),
duplicates preserved. `source`/`verification` come from the view's provenance
(`cdp`, `netlog`, `har`; `verified` | `unverified` | ...), `orderState` says whether
the order is proven. When there are several pieces of evidence (e.g.: transaction + h2 session)
they appear in `headerEvidence` without merging; the content of a specific
piece of evidence comes out with `attempt` and `verbose`.

### 5.5 `get_body`

Input: `{ session_id, request_id, part?, offset?, length?, max_inline_bytes?,
reveal? }`. `part`: `response` (default) | `request`. `offset`/`length` in bytes
of the stored body (core read limit 5 MiB; above that
`readTruncated: true`).

Output: `{ sessionId, requestId, part, state, bytes?, contentType?,
contentEncoding?, transformed[], note?, masked?: "unsupported"|"redacted",
revealed, range: {offset,length,total}, inline: bool, text?, path?,
encoding: "utf8"|"binary" }`.

- Captured, UTF-8 and within the inline limit: `inline: true`, `text`.
- Larger than the limit or binary: writes `<out-dir>/bodies/<sessionId>/<requestId>-<part>-<offset>-<length>[.masked].bin|txt`
  and returns `path` (`inline: false`). The file is the exact slice returned.
- Body `empty`/`unavailable`/`discarded`/`truncated`: the core's state and note
  are returned without inventing content. `truncated` indicates `truncatedAt`.
- The bytes are those stored in the session; the server does not decode
  `Content-Encoding` (the core already records `transformed` when it decoded).

### 5.6 `search_bodies`

Input: `{ session_id, query, scopes?, case_sensitive?, cursor?, limit?,
reveal? }`. `scopes` ⊂ {`url`, `requestHeaders`, `responseHeaders`, `cookies`,
`requestBody`, `responseBody`}; empty = all. **Literal text** search
(regex is out of this wave).
Output: `{ sessionId, total, hasMore, nextCursor?, matches: [ { requestId,
attemptId, scope, field?, byteOffset?, byteLength?, exact, snippet, decoded,
htmlControl } ], partial, partialAttempts[], skippedBinary, skippedMasked,
limitReached, revealed }`. `snippet` is short (core limit); never the whole
body. `partial: true` = some truncated body was searched (partial search).

### 5.7 `diff_requests`

Input: `{ session_id, request_a, request_b, other_session_id?, ignore?,
reveal? }`. `other_session_id`: session of `request_b` (default: the same).
`ignore`: header/cookie names (case-insensitive) removed from the
`added/removed/changed/reordered` lists and from the cookies before returning; the total
removed comes in `ignored`.
Output: the core's `RequestDiff` (`diff::diff_requests`) + `{ sessionId,
otherSessionId, masked, ignored, notes[] }`. Duplicates and the original order are
preserved (`reordered` separates a position change from a value change). There is never
silent alphabetical sorting.

### 5.8 `diff_sessions`

Input: `{ session_id_a, session_id_b, map_origin?: {from,to}, a_range?,
b_range?, include_all?, only_changed?, cursor?, limit?, reveal? }`.
`a_range`/`b_range`: `"from:to"` (ids or 1-based numbers).
`only_changed` (default `true`): in each pair, only the fields that are not
`static`. `cursor`/`limit` paginate `pairs` (default 10, maximum 50).
Output: the core's `SessionComparison` (`compare::compare_sessions`) with
paginated `pairs` + `{ masked, totalPairs, hasMore, nextCursor? }`. Warnings,
ambiguities, unpaired rounds and origin mapping pass through as they came.

### 5.9 `trace_value`

Where a cookie or token comes from and where it is used. Three modes (exactly one):

- `{ session_id, cookie }` — **cookie by name**: responses that set it
  (`Set-Cookie`, in time order), requests that send it.
- `{ session_id, value, reveal:true }` — **value** (token, id): where it appears, with
  the oldest producer and later consumers. **The `value` mode REQUIRES
  `reveal`** (double lock: `reveal:true` and a server with `--allow-reveal`). Without
  that it answers `reveal_required`, whatever the value: finding or not finding
  a value supplied by the agent would be an oracle over masked content
  (substring, brute force, re-importing the session to reset counters,
  known structure such as `Basic base64("admin:PIN")`). The search is by
  literal substring (evidence `literal-match`). The `cookie` and
  `request_id` modes remain without `reveal`, with no `valueLength` or other data derived
  from the value (with `reveal`, `valueLength` comes back).
- `{ session_id, request_id, field? }` — **origin of the values consumed by
  a request** (the core's `flow::value_origins`, with the same
  `evidences`, `strength`, `confidence`, `unobservable`, `context`).

Common: `limit?` (default 50, maximum 200 per list), `reveal?`.
The `cookie` and `value` modes sort requests by `startedAt` (lowest time
among the attempts) when all have a time; otherwise they use session order and
that goes in `notes`. "First" and "later" always refer to that order.

Output (cookie): `{ mode:"cookie", cookie, firstSetter?: {requestId, attemptId,
url, startedAt?, source, attributes{...}}, setters[], users: [ {requestId,
attemptId, url, startedAt?, sentValueEqualsFirstSetter: true|false|null} ],
truncated, notes[], evidence }`. Without an observed response that sets the cookie,
`firstSetter` is null and `notes` says it may come from `document.cookie`, from the browser
profile or from an incomplete capture — the origin is never asserted.
`sentValueEqualsFirstSetter` compares in the original session and returns only the boolean
(`null` = no setter to compare).

Output (value, only with reveal): `{ mode:"value", length, firstProducer?, producers[],
consumers[], truncated, warnings[] }` where each occurrence is `{requestId,
attemptId, scope, field?, byteOffset?, position}`. Producer = occurrence in a
response (headers, `Set-Cookie`, body); consumer = URL, request headers,
sent cookies, request body, after the producer. Values shorter than
8 characters produce a warning (the coincidence may be chance). The relation is substring
equality (`"literal-match"`); it does not prove causality.

Output (request): the core's `ValueOrigins`; the `value` preview of each entry
is `"[REDACTED]"` unless `reveal=true` (length, field, scope and evidence
remain).

A `value` supplied by the agent is never echoed without `reveal`.

### 5.10 `export_session`

Writes a copy of the session to a private directory. It does **not** reveal values in the response
JSON: it returns only path and counts.

```json
{ "session_id": "...", "destination": "my-export", "include_sensitive": false }
```

- **Sanitized (default, `include_sensitive: false`):** applies
  `export::sanitize::sanitize_bundle` with the default options, writes with
  `store::write_session_dir` and does **not** carry the raw `cdp-events.jsonl` or `netlog.json`.
  Output: `{sessionId, path, includeSensitive:false, requests,
  attachmentsWritten, rawArtifactsWritten:[], totalRedactions, report
  {redactions, warnings, omittedAttachments}}`.
- **Full (`include_sensitive: true`):** writes the original bundle **without
  redaction** and copies the raw artifacts that exist at the source
  (`cdp-events.jsonl`, `netlog.json`, `cdp-bodies.jsonl`), refusing symlinks and
  applying 0600. Output without `report` and with `totalRedactions: 0`. It does not require
  `--allow-reveal`: it is a local, explicit action, requested by the user of the LLM;
  the secrets stay in the 0700/0600 directory, never on stdout.
- **Destination:** `destination` omitted → `<out-dir>/<session_id>-sanitized` (with
  `-2`, `-3`… if it exists) or `<out-dir>/<session_id>-full` (refuses if it already
  exists). A simple name without `/` resolves inside `--out-dir`; an absolute path
  is accepted if it is not the source session nor inside it (nor inside another
  session/reserved root), if no existing ancestor is a symlink (except the macOS
  system aliases `/var`, `/tmp`, `/etc` → `/private/...`) and if the
  directory does not exist or is empty (the parent directory must exist). The
  destination is created 0700; the files, 0600.

## 6. Required tests

- Unit tests per tool, against the existing fixtures
  (`fixtures/acceptance/*`, HARs from `fixtures/`, captures from `experiments/results/`),
  without editing them.
- Masking: secrets from `fixtures/acceptance/sanitize` do not appear in any
  output without `reveal`; `reveal` refused without `--allow-reveal`.
- Path limits: `name` with `..`/`/`, `session_id` with a path, write outside
  the directory.
- End to end: the real binary over stdio (`initialize`, `tools/list`,
  `tools/call` for each tool), with an assertion that stdout carries only
  JSON-RPC.
- `export_session`: sanitized redacts the secrets and carries no raw artifacts;
  `include_sensitive:true` preserves headers/cookies/bodies and the files
  `cdp-events.jsonl`/`netlog.json`/`cdp-bodies.jsonl` with 0700/0600, and the returned
  JSON does not contain the values; dangerous destinations (inside the source, another
  session, reserved root, symlink, non-empty directory) are refused.

## 6b. Browser and site profile (round 11, wave 2)

Five tools connect `scrapelens-capture` (`capture/`) and `scrapelens-recon`
(`recon/`) to the server, with the schemas of `docs/16b-mcp-browser.md` (§3, §4,
§5). Dependencies by path; the server reimplements nothing of the capture.

- `start_capture {allowed_hosts[], third_party_hosts?[], start_url?,
  binary_path?, headless?, expose_cdp?, proxy?}` → `StartInfo` (no paths) +
  `captureId`, `sessionId` (the directory name the session will have in
  `--sessions-dir`) and `confirmation` (`elicited` | `unconfirmed-flag`).
- **`proxy`** (optional string): `http://`, `https://`, `socks5://`, `socks5h://`,
  `host:port` (same as `http://`), `user:pass@host:port`, or `host:port:user:pass`.
  Credentials are percent-decoded; IPv6 goes in brackets; socks4, paths, queries and
  fragments are refused. `"env"` reads the server's `SCRAPELENS_PROXY_URL` and is the
  recommended way when the proxy has credentials: the password then never passes
  through the model. The variable is applied only when `"env"` is requested.
  The confirmation shows `scheme://host:port` and whether the link is authenticated,
  never the credentials. Refusals: `proxy_invalid` (the message never echoes the link),
  `proxy_env_missing`, and `proxy_unavailable` (the proxy cannot be reached, or its TLS
  certificate is not trusted; the message gives the next step and never a credential).
  Route: no credentials and no allowlist → Chrome gets `--proxy-server=scheme://host:port`
  directly. Credentials, or any allowlist (always, for `start_capture`) → Chrome talks to
  a local relay on `127.0.0.1` (random port, no auth); the relay adds the credentials and
  refuses, before contacting the upstream, any host:port the allowlist does not permit.
  An `https://` proxy on that path is TLS to the proxy (rustls, system trust store, checks
  always on). A certificate failure is `proxy_unavailable` with that reason. The test-only
  environment variable `SCRAPELENS_TEST_PROXY_CA` (a PEM path) adds one extra root for the
  fixture CA; it is not an MCP parameter and it does not disable checks.
  On the direct route, Chrome's `ERR_PROXY_CONNECTION_FAILED`, `ERR_TUNNEL_CONNECTION_FAILED`,
  `ERR_PROXY_AUTH_REQUESTED` and the related proxy errors become the same `; proxy: <reason>`
  notice as the relay, a `capture.proxy_failure` warning, and the request reason. They are
  not left as a generic page failure.
  With a proxy, WebRTC is kept behind it (`disable_non_proxied_udp`); a proxied capture
  has no HTTP/3 (the session says so). Session: `capture.proxy` (`scheme`,
  `authenticated`, and in the full export `host`, `port`, `route`); no credential is
  ever stored there, in an export, or in the output.
  Out of scope: rotating proxies, lists, PAC, socks4, Keychain storage; the proxy is not
  used by the exported cURL, Python or priming scripts.
- `navigate {capture_id, url, wait?=load|none, timeout_ms?}` → `NavigateResult`.
  The allowlist refuses before sending (`url_not_allowed`).
- `capture_status {capture_id}` → `recording`, `events`, `pageUrl`, `lastError`.
- `stop_capture {capture_id}` → `StopReport` (no paths) + `sessionId`
  readable by the read tools (`readable: true`), with
  `allowlist.blockedHosts` and `violations`.
- `site_profile {session_id, target_request_id?}` → `scrapelens.site-profile/1`
  (findings with evidence, recommendation). The evidence ids resolve in
  `get_request`. It runs over the original session (it needs the values to
  trace tokens); `recon` already redacts values (`[redacted, N bytes]`) and strips the
  query from URLs, and the server passes the URLs through the filter anyway.

Server rules:

- **Confirmation**: `start_capture` ALWAYS asks for an MCP elicitation (form with the
  `confirmo` checkbox), showing `allowed_hosts`, `third_party_hosts`, start URL,
  `expose_cdp`, mode, the Chrome binary and `SENSITIVE_NOTICE`. No
  `confirmed` parameter exists in the schema. Only `accept` with the box checked opens
  Chrome; refusal, cancellation, JSON-RPC error, malformed response, `confirmo` that is not
  the boolean `true`, timeout (5 min) or a dropped connection → `confirmation_denied`,
  and **nothing is opened**, even with the flag. Only when the client **does not declare**
  elicitation support → `confirmation_unavailable`, unless the server
  was started with `--allow-unconfirmed-capture` (double lock, like
  reveal). Cancelling the request, letting the timeout expire or disconnecting abandons the
  confirmation: a late acceptance is ignored, nothing opens and the slot is always
  released; if Chrome was already coming up, it is stopped when it becomes ready. The
  confirmation text follows the official semantics of 16b §2.2: the browser
  enforces the HOST on all ports, the **port is only enforced in `navigate`**, and
  approving `localhost:8080` approves `localhost` on any port for the page.
  Invalid requests (empty/broad/invalid allowlist, `start_url` outside) are
  refused **before** the confirmation, without bothering the user.
- **Capture map**: `capture_id` → capture, in memory; opaque ids
  (`cap-<16 hex>`), never paths. **One active capture at a time**
  (`capture_already_running`, including while the confirmation is pending).
  After `stop_capture` the id ceases to exist (`capture_not_found`).
- **Shutdown**: stdin closed, SIGTERM or SIGINT stop all active captures
  gracefully (the session is written) before exiting. A Chrome that
  is still coming up (`start_capture` in progress) is awaited and stopped as soon
  as it is ready (up to 120 s); the server only exits afterwards. On startup, the server
  calls `cleanup_orphans` (orphans from runs that died).
- **Session directory**: `--sessions-dir/capture-<ms>`; Chrome writes only
  there (its own temporary profile stays with `capture/`).
- **Session writes** (`core::store::write_session_dir`/`write_atomic`):
  a destination that is a symlink is refused; temporary file with a unique name and `create_new`
  (a symlink planted at the predictable name is never followed); an `attachments/` that
  is a symlink is refused before any `mkdir`/`chmod`; everything is written under
  the canonicalized directory.
- **Body spill** (`get_body`): unique directories and temporary file
  created without following symlinks (`create_new`); a component that is a symlink is
  refused (`outside_allowed_dir`) before any `mkdir`/`chmod`; the file
  comes out 0600; handles that `slug` would merge (`x.y`, `x-y`) use
  distinct directories (hash in the name); a `session.json` that is a symlink does not list the session.
- **No paths in outputs** (`sessionDir` removed). In capture outputs
  (`pageUrl`, `exampleUrl`, `violations[].url`) and in any text in them
  (`warnings[]`) the **query, fragment and matrix parameters are dropped**
  (`…`): there is no way to know which parameter is a secret.
- Annotations: `start_capture` and `navigate` have `readOnlyHint: false` and
  `openWorldHint: true` (traffic to the listed hosts); `stop_capture`
  `readOnlyHint: false` (writes the session); `capture_status` and `site_profile` are
  read-only.
- `expose_cdp=true` hands the loopback CDP address to the agent (after the
  `16b` §4.1 gate). The agent's actions through that CDP do **not** go through this
  confirmation; what limits them is the network allowlist enforced by Chrome.

Tests: `mcp/tests/live.rs` (policy and map, counted backend),
`mcp/tests/e2e_capture.rs` (real server with the fake browser from the example
`fake_server`: elicitation accepted/declined/absent, navigate outside the allowlist,
stop → `list_requests`/`site_profile`, shutdown by EOF and SIGTERM) and
`mcp/tests/e2e_live.rs` (`#[ignore]`, real Chrome + loopback server). The
`fake_server` example is only built by `cargo test` (without a filter) or
`cargo build --examples`.

## 7. Out of this wave

Local HTTP, resources (`scrapelens://...`), regex in `search_bodies`,
browser agent-action tool (`act`; the agent uses the exposed CDP),
`generate_priming_script`, `validate_run`. They enter in their own wave, with the leader.
