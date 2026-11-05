# Round 5 — value origin (priming) and comparison between captures

## Motivation

DETRAN-PB case (`docs/05-detran-reference-case.md`), derived requirements 2,
3 and 4: you cannot start from the lookup. You need to know where each POST
value came from (SESSIONID, STAMP, delta, cookies) and which values change
between two captures of the same flow, so as not to freeze HAR values.

Out of scope: decoding Natural for Ajax, bypassing /TSPD/ or CAPTCHA,
replay, external network, generating an executable priming script (left for
round 6) and publication.

## Waves (max. 3 executors)

- 5a: Core (value origin + comparison between captures) and Tests (2nd
  synthetic capture of the DETRAN flow + expectations + acceptance script).
- 5b: App (chain and comparison UI), then independent review.

## Ownership

| Owner | Paths |
|---|---|
| Core | `core/` |
| Tests | `fixtures/`, `testserver/`, `tests/` |
| App (5b) | `app/`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs` |
| Leader | `docs/` |

## 1. Value origin (core, `provenance` or `flow`)

API: `value_origins(session, request_id, options) -> ValueOrigins`. For the
target request, extract the consumed values: query parameters, header values
(except protocol ones: host, content-length, accept-*,
user-agent, sec-*), sent cookies and body fields (form and JSON leaves).
In opaque fields (e.g.: `XML`), the values are searched as a substring (§1.2).

1.1 Producer candidates. Only values observed BEFORE the target request
(attempt start time, with explicit ties) in:
- `Set-Cookie` of responses and cookies in the redirect URL;
- response headers (Location and custom headers);
- response bodies: form-urlencoded fields, JSON leaves and quoted
  string literals in text/HTML/JS, with length ≥ 8;
- earlier requests (a value that was already circulating: origin "repeated
  from cdp-rNNNN", not "produced").

1.2 Evidence, without mixing up the types:
- `cookie-jar`: sent cookie whose value was set by an earlier Set-Cookie
  (same name + value). Strong.
- `same-field`: same field name and same value between a response field and
  a request field (e.g.: STAMP). Strong. Applies to short values (≥ 1),
  because the name ties them together.
- `value-match`: response value with ≥ 8 characters found in the
  request (whole or as a substring of an opaque field). Medium. Record where
  it appeared (field, offset).
- `initiator`: CDP initiator (script/parser) pointing to an earlier
  resource. Complementary, never proof of the origin of a value.
- No candidate: `no observed origin`. It may be a constant, user input
  (plate) or a value generated on the client (JS). Never invent the origin.
- Several candidates: list them all, mark `ambiguous` and indicate the oldest,
  without choosing silently.

1.3 Priming chain: `priming_chain(session, request_id)` = transitive
closure of the strong and medium origins (each producer brings its own
dependencies). It returns the minimal ordered list of required requests,
with the reason for each one (which value it supplies), and separates the
protection requests (`/TSPD/`, TS* cookies) from the application ones by an
explicit rule (domain/path/cookie), marked as `protection` and not as
`irrelevant`.

1.4 CLI: `scrapelens-core origins <session> <requestId>` and
`scrapelens-core chain <session> <requestId>`, with JSON output. It works with
LazySession (bodies on demand) and with sanitized sessions (`[REDACTED]`
values do not match each other; declare this).

## 2. Comparison between two captures (core)

API: `compare_sessions(a, b, options) -> SessionComparison`.
- A↔B request alignment: method + host + normalized path + set of body
  field names + relative order within the same model. Requests with the
  same model are paired in order. Leftovers stay `only in A` or `only in B`.
  Ambiguity is explicit, with no pairing by absolute time.
- Per pair and per field (query, headers, cookies, body fields; opaque
  fields are compared by whole value and by differing tokens of ≥ 8
  characters): `static` (equal), `dynamic` (differs), `only in A` or
  `only in B`. Repeated fields are paired by occurrence, with no silent
  alphabetical sorting (specification rule).
- Useful classification: a dynamic field whose origin (§1) in B is an
  earlier response of B becomes `get at runtime (origin: …)`. Dynamic with no
  observed origin becomes `dynamic without origin` (generated on the client or input).
- CLI: `scrapelens-core compare <sessionA> <sessionB>`, with JSON output.

## 3. Export

cURL/Python now annotate, in a comment next to the value, the
`get at runtime` fields (with the origin) when the session has that analysis
available. The values are still the captured ones. No invented
value, and the generated code does not change behavior.

## 4. Round acceptance

1. DETRAN fixture (A): for the 1st `cmd_consultar_placa`, the origins are
   SESSIONID → HTML response of easynat-app (`value-match`, literal
   `m_currentSessionId`); STAMP → response of the previous POST (`same-field`);
   delta `DLTA…` in the XML → previous response (`value-match` in the XML);
   TS*/JSESSIONID cookies → Set-Cookie (`cookie-jar`); plate → `no observed origin`.
   The chain lists the minimal application requests in flow order, and
   /TSPD/ appears separately as `protection`.
2. Comparison A × B (2nd synthetic capture with different SESSIONID, STAMP,
   delta and cookies, and equal pages and constants): SESSIONID, STAMP, delta
   and cookies `dynamic` + `get at runtime` with the right origin; `cmd`,
   empty PAGEINITPARAM and the XML constants `static`; plate `dynamic without
   origin`; the two lookups with the same URL/method paired by order, without
   crossing.
3. No invented origin: negative case in which a short value coincides by
   chance (< 8 without the same name) does not become an origin.
4. Sanitized session: the analysis runs, declares that redacted values cannot
   be traced and does not leak values.
5. Test suite with no regression (cargo test, tests/export, run_acceptance,
   check_bodies_search) and acceptable performance on the large session (measured).

Conventional Commits per owner, no push or publication, no external
network. Preserve `tests/results/app-latest/testserver/app-20261027/h1.jsonl`.

## Decisions during the round

- 2026-10-28, `reissued`: a value that appears in later responses after
  already having circulated in requests (e.g.: SESSIONID repeated in the HTML of
  SIM1000X/VES0009X) is not a competing producer. The origin is the 1st response
  (`produced`), and the others are marked `reissued`. `ambiguous` is kept for
  truly competing candidates before the 1st use. The fixture manifest was
  adjusted to this rule.
- The CDP `initiator` is not available in the session model, and this is
  declared in `warnings`. Preserving the initiator is a candidate for a future
  round.
- `unobservable`: "no observed origin" lists the earlier responses
  without an observable body (core 0c0c331).
- The `unavailable` case of fixture A moved from the response of 1010.10 (producer
  of STAMP and delta) to that of 1013.13 (Tests 2128d4d).

## Review of round 5 (2026-10-28) — decisions

Verdict: rejected until 2 high failures are fixed.
- Generated comments (annotated export and any other cURL/Python
  comment) use a single escape function: it removes CR, LF, U+2028/U+2029 and
  the other control characters, and prefixes each line with `# `. Captured content never
  leaves a comment. The regression test is a field name with a newline
  that tries to run a command.
- Temporal causality: a producer only counts if its response was received
  (responseReceived/end) by the start of the target attempt. A response that
  ends after the target's start is not a producer. Ties stay as
  they are today.
- `reissued` only when the value circulated in a request between the 1st producer
  and the next one. With no use between them, the producers are competing: `ambiguous`.
- Strong `same-field` requires a non-generic name and a value ≥ 4 characters. Generic
  names (id, value, data, page, type, lang, name, key, code, state, status,
  action, op, mode, format, limit, offset, q, query, v, t, ts) or short values
  downgrade to medium.
- Label: with only medium evidence, the status is "possible origin (<type>)" in
  the core and the UI. "Observed origin" requires strong evidence. The chain marks the
  confidence of each step (`strong` | `possible`).
- `unresolved` does not include values consumed only by protection steps. Fields
  do not appear duplicated as an input and as a fragment. The compare pairing
  within the same model is monotonic, without crossing the order.
- App: compare uses pagination/virtualization, and "dynamic only" is on by default in
  large comparisons. Paths are canonicalized, and comparing the same
  session with itself is refused or warned about.

## Closing (2026-10-28)

Independent re-review: APPROVED (core 37e413f, tests 35af662, app eb4953c and
4b92c6c; bundle ac7213b2…). Injection closed: `export::comment` is the single
gate, and the probes of header, 307 URL, `transformed`, bidi, zero-width,
NUL and 5000-character names do not escape the comment. Causality by response
end, including 2-level redirects and ties. Confidence: strong only
with cookie-jar or non-generic same-field. Monotonic compare, with pagination
in the app consistent with the CLI. Test suite green.

Finishing touches (low), delegated: L1 common prefix of 8 characters in a named
field becomes a possible fragment; L2 unique requests reordered without the
`outOfOrder` hint; L3 long chip cut off in print 15. Validation on the real case
(user's local HARs, without copying data into the repository) delegated to the
Tests agent.
