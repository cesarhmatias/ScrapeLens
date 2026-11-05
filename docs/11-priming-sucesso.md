# Round 7 — priming script and application success × HTTP

## Motivation

DETRAN-PB case (`docs/05-caso-referencia-detran.md`), derived requirements 4
and 5. The user needs a starting point that recreates the new session, without
freezing values from the HAR, and needs to know when an HTTP 200 is not
application success (response without XML/STAMP, with ERRORMESSAGE, or a
block page).
Prerequisite: round 6 approved.

Out of scope: running the script, replay, network, bypassing /TSPD/ or
CAPTCHA, decoding Natural for Ajax in the core, and publishing.

## Waves and ownership

- 7a: Core (`core/`): script generator and success evaluator. Tests
  (`fixtures/`, `tests/`): expectations and acceptance.
- 7b: App (`app/`, `commands.rs`, `lib.rs`): UI. Then an independent review
  and aggregate validation on the real HARs.

## 1. Priming script (Python, maintained client)

`export::priming::to_python(session, body_source, target_request_id, opts)`
uses `priming_chain` + `value_origins`:
- Steps in chain order (only `steps`, never `protection`, context `pages`
  or static resources). Each step is a function with the captured request
  (method, URL, supported headers, body) and a comment with the reason and the
  confidence (`strong`/`possible`), going through `export::comment`.
- Values with an observed/possible origin are extracted at runtime from the
  producer's response, by the same kind of evidence: Set-Cookie (via the
  client's cookie jar), HTML control (name), form/JSON field (key/path), literal
  (the captured context before and after, generated as an escaped regex) or
  opaque field excerpt (substitution of the captured excerpt by the extracted
  value, with the context bounds). Each extraction checks that it found the
  value and, if it did not, fails with a clear message. It never silently falls
  back to the captured value.
- Values without an observed origin (plate, user input, constants) become
  script parameters, with the captured value as an example only if it is not
  sensitive. Sensitive/redacted ones become required parameters, with no default.
  `partialComposition` becomes the comment "assembled on the client: complete here".
- Client: `requests.Session` (cookie jar). Script header: "semantic
  reproduction; header order and transport fidelity (TLS, HTTP/2,
  fingerprint) are NOT guaranteed"; "not executed by ScrapeLens";
  "steps that change state require `--confirmar`". Non-idempotent requests
  (POST/PUT/PATCH/DELETE) only run with the explicit flag;
  without it, the script prints the plan and exits.
- Escaping: Python strings via `repr`; captured data never enters
  code outside escaped literals or comments. The generated script is
  validated by `ast.parse` in the tests.
- CLI: `scrapelens-core export-priming <session> <requestId> [--out f]`.

## 2. Application success × HTTP

`assess::response_outcome(request, body_source, rules)` returns, per response:
`httpOk` (2xx/3xx), `appSignals[]` (e.g.: `XML` control present and not
empty, `STAMP` present, `ERRORMESSAGE` not empty, page without the expected
controls, protection marker) and `verdict`: `app-ok`,
`app-error (<signal>)`, `blocked? (<signal>)` or `undetermined`.
- Default rules are generic and conservative. A non-empty ERRORMESSAGE/error
  in a control or field gives `app-error`. An application response that comes
  without the fields that the same route carried in other responses (learned
  within the session itself) gives `undetermined`, with the list of missing fields.
- `blocked?` only with explicit evidence (protection page known by the
  /TSPD/ rule, 403/429, or an HTML response that replaces the expected one with
  another without the controls). Always with "?", never asserted.
- Rules configurable by a JSON file in the session (field name → signal),
  with no executable code.
- In the chain and in compare, each step/pair shows the verdict.
- CLI: `scrapelens-core assess <session> [requestId]`.

## Acceptance

1. Real-shape fixture (1 round): the priming script for the 1st
   cmd_consultar_placa has only the application steps in order and extracts STAMP
   from the HTML control, delta from the textarea excerpt, SESSIONID with the
   partial-composition comment, and the plate as a parameter. `ast.parse` passes.
   Without `--confirmar`, it only prints the plan. No sensitive value captured
   as a default.
2. Offline simulation: a fictional local server (testserver) that emits the
   same controls with new values. The script, run by the Tests agent
   (not by ScrapeLens) against 127.0.0.1 with `--confirmar`, completes the
   chain using the new values, never the captured ones. No external network.
3. assess: on the DETRAN block fixture (200 without XML/STAMP, Connector without
   model, 403), the verdicts are consistent `app-error`/`undetermined`/`blocked?`.
   Normal responses give `app-ok`.
4. Injection: hostile names and values (newline, triple quotes, `\`, bidi) in the
   script do not escape from literals or comments. Test with `ast` and
   execution against the local server showing that nothing besides the requests is
   executed.
5. Aggregate validation on the real HARs: the script for the 1st cmd_consultar_placa
   is generated. The steps and extractions match the user's manual flow. The
   assess verdicts (counts) are consistent. No real value in the
   report.
6. Test battery without regression.

## Progress (2026-10-29)

- assess (Capture, c28533b). The decision to add `not-assessed`
  for responses with no application signal and no expectation on the
  route removes the noise from pages, static resources and /TSPD/.
- Priming generator (Capture, f858b17). Offline proof on detran-sim: the
  13-step chain (6 POSTs) completed 2× with new values, and the negative control
  with the captured values received ERRORMESSAGE.
- Known limit: Natural for Ajax uses length prefixes. When the extracted
  excerpt changes size, the script warns on stderr, but does not recompute
  the prefix. A real server may reject it. Recomputing requires knowing the
  protocol (outside the core; candidate for an extension/plugin).

## Round 7 review (2026-10-29) — decisions

Review verdict: partial, with 1 high failure.
- Redirect: the script uses `allow_redirects=False`. A 3xx is only followed if the
  Location is of the SAME origin as the base (scheme+host+port), and the redirect
  counts as a verified step. A Location to another origin becomes
  `fail("priming: step N: redirect to another origin (<host>) refused")`.
  No body, parameter or header goes out to another origin.
- Origins: with `--base-url`, every step whose captured origin differs from the
  target's origin is refused at generation (with a list) or requires an explicit
  `--allow-origin <host>`. The rewrite compares the exact origin, with no
  `startswith` without a boundary.
- Session data/PII never becomes a literal or a default: path parameters
  (`;name=value`) are treated as data; the list of sensitive names includes
  name, email, phone/mobile, address, birth, rg, token, sid,
  session and callback (JSONP). A structural constant only for the path and the
  navigation query value that are not PII and do not look like a
  dynamic ID (long digits, hex or base64).
- Linear runtime extraction: `str.find` of the before/after contexts, never
  a regex with `.+?` over the response.
- assess: rejection (F5) only with absence of the route's expected controls (or
  with no expectation and no controls). A 200 with XML/STAMP present is app-ok,
  even if it quotes "Request Rejected". On the protection route, 403/429 remain
  `blocked?` (explicit evidence); a handshake 200 is `not-assessed`.
- Script error output: text coming from the response is sanitized (controls,
  ESC, bidi), with `repr` or a filter.
- JSON rules: `schema` mandatory, unknown keys refused, and a
  warning when the rules turn off all detections or mark `/` as
  protection.
- App: `blocked?` is not an "application failure". The count and the filter stay
  separate ("application failures" × "possible blocks").

## Round 7 re-review (2026-10-29) — decisions

Redirect, origins, ReDoS, terminal error, F5, /TSPD/ and strict rules were
approved. 2 high failures remain.
- Headers: the generator reuses `is_sensitive_header` from the sanitization, plus
  the names with key, token, csrf, xsrf, session, sess, jwt, secret, auth,
  signature, user and device. Such a header never goes out literal: if it has an
  origin, it is extracted at runtime (CSRF/XSRF); otherwise, it becomes a
  required parameter with no default; the rest is omitted with a note. The Referer is built
  at runtime with the real URL of the corresponding previous step (same
  origin+path); without a match, it is omitted. The captured query never goes out.
- Non-form body: JSON is decomposed into fields and gets the same treatment as
  the form (extraction, parameters, constants, sensitive). Other types
  (text/XML/binary) are refused by default; `--allow-literal-body`
  includes the body, but the values detected as sensitive/business become
  required parameters, and the script warns that the rest was frozen.
- Dynamic IDs are never a structural constant: JWT (`eyJ…`), ULID/KSUID,
  ISO dates/timestamps, numbers of 5+ digits, alphanumerics of 6+ with
  mixed letters and digits, and names that contain sess/token/key/sid.
  Short navigation values (e.g.: `op=S37`) remain allowed.
- assess rules: empty marker refused; `blockedStatuses` only 4xx/5xx.
- Script: `S.trust_env = False` by default (no proxy/.netrc from the environment);
  `--usar-proxy-do-ambiente` enables it. Warning when Python is < 3.13
  (HTMLParser with known quadratic cases).
- Final re-review (732f6b5): the 2 previous high failures were approved;
  1 new high remained. Decisions: (1) the body is classified by its content and
  not only by the Content-Type. Valid JSON under a form content-type gets
  the JSON treatment, and a form field without `=` longer than 40 characters
  never goes out literal (refusal). (2) Detection by value of the
  `Bearer`/`Basic`/`Digest`/`Negotiate` schemes in any header; the names hmac,
  bearer, digest and nonce enter the list; `x-forwarded-for` is omitted (light
  PII). (3) A Referer to another origin (`--allow-origin`) carries only the origin,
  as in the browser. (4) assess rules: empty names/paths
  are refused.
- Re-review at e74ecb0: 1 high is missing, JSON as a field VALUE (form or
  JSON string). Decision of principle, to stop patching case by case: (a)
  field values that are valid JSON, including JSON inside a JSON string,
  are decomposed recursively (limited depth); (b) a single FINAL
  literal filter: every string literal the generator is going to emit
  (body, fields, opaque excerpts, headers and query) passes through the
  PII/secret detectors (e-mail, CPF, CNPJ, card with Luhn, Brazilian phone, plate, JWT,
  Bearer/Basic schemes, long digits and business/PII names in the context).
  A detected excerpt becomes a required parameter in the exact place. If it cannot
  be mapped, generation is refused with the list of what was found. The
  rules warnings also cover "no detection configured". The app reads
  `assess-rules.json` as a regular file, without symlink, with a size
  limit.

## Closing (2026-10-29)

Final review at 1bdd8b9: APPROVED with caveats. Priming script:
- no redirect to another origin;
- exact origin, injection closed and linear extraction;
- credentials and PII never literal in JSON, named form or opaque field;
- final literal filter;
- Referer at runtime;
- stop at the step of the bad response;
- refusal of an incomplete chain.

Assess: consistent verdicts, strict rules with warnings, no false block
on the protection handshake. On the 3 real HARs: 11 steps in the order of the manual
flow, only the plate and the SESSIONID suffix as parameters, 0 literals and no
false positive from the filter. detran-sim approved in the 4 modes.

Delegated finishing work: detectors for a plate with a hyphen (ABC-1234), 17-character VIN/chassis,
+55 phone with 12–13 digits, series-2 card (2221–2720)
and 19-digit card, and fullwidth digits; filter also applied to path
segments, form keys and header values. Accepted limit: free text without a
format (name, address, obfuscated e-mail) in query, header and path, and
any content under `--allow-literal-body` (warned in the script).
