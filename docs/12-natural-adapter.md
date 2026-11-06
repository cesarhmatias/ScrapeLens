# Round 8 — Natural for Ajax protocol adapter (outside the core)

## Motivation

The priming script (round 7) swaps fragments of the `XML` field for values
extracted at runtime, but does not recompute the length prefixes of the
Natural for Ajax protocol. When the new value has a different size (delta,
SESSIONID, plate), the real server may reject the request. The
specification says to keep protocol decoders out of the core, as an
extension. The user already has the grammar implemented by hand in a personal script,
kept outside the repository (`serialize`, `decode_stream`, `jslen`: lengths in
UTF-16 units). Use that file only as a read-only reference for the grammar,
without copying data.

## Architecture

- core: only the extension point. Trait `ProtocolAdapter { id(); detect(field,
  context) -> bool; decode(&str) -> Result<Structure>; encode(&Structure) ->
  Result<String> }` and a registry passed as an option to origins/priming/app. No
  knowledge of Natural in the core.
- `adapters/natural-ajax/` (new crate in the workspace): implements the trait for
  the Connector's `XML` field.
  - Request: header `i`/`v` with fixed widths; operations `p` (name and
    value with widths 2/5); `x` (delta with width 2).
  - Response: operations l/p/q/z/b/c/s/k/x of `decode_stream`.
  - Lengths in UTF-16 units (`jslen`).
  - Exact round-trip: encode(decode(x)) == x on all the XMLs of the fixtures and
    of the real HARs (aggregated).
- Structured view: the app shows the decoded field (session, process,
  model, page, event, name→value properties, delta), marked as
  "Natural adapter view (derived)", with the raw one as primary.
- Priming: when an adapter claims the field, the script does not swap
  fragments. It builds the structure with the values (constants + values extracted at
  runtime + parameters) and calls a generated Python encoder (equivalent to
  `encode`, with UTF-16 `jslen`), recomputing all the prefixes. The values
  go through the same PII/literals filter as round 7.
- Origins: the adapter exposes the inner fields (e.g.: `XML.p.v_placa`,
  `XML.delta`) with offsets in the original, so origins/compare use names
  instead of fragments.

## Ownership

| Owner | Paths |
|---|---|
| Core | `core/` (trait, registry, integration in origins/compare) |
| Capture | `adapters/natural-ajax/`, `core/src/export/priming.rs` (integration) |
| Tests | `fixtures/`, `testserver/` (detran-sim validates prefixes), `tests/` |
| App | `app/`, `src-tauri/src/commands.rs`, `lib.rs` |

## Acceptance

1. Exact adapter round-trip on all the fixtures and on the 3 real HARs
   (aggregated: N fields, 0 divergences).
2. detran-sim in strict mode (rejects a wrong length prefix): the generated
   script completes the chain with values of sizes different from the captured
   ones (longer delta and SESSIONID, Mercosul plate). The round 7 script,
   without the adapter, fails in this mode; record that as a control.
3. Origins/compare show inner names (`XML.delta`, `XML.p.v_placa`).
4. App shows the structured view; the raw one remains primary.
5. No regression: full test suite and check_real_priming (only plate and SESSIONID
   suffix; 0 literals).

## Review of round 8 (2026-10-29) — decisions

Verdict: partial (2 high failures). The grammar is correct and the round-trip is
exact.
- Adapter limits (Rust and generated Python): scope depth ≤ 32,
  dictionary keys ≤ 10 thousand, path kept as an index stack and
  assembled on demand, names in a map. Linear cost: `b01a`×40 thousand in < 1 s and
  < 100 MB. `detect` is cheap (header and at most one short parse, with the
  result reused); the app limits the size of the decoded field.
- Priming with an adapter applies `is_sensitive_name`/`is_pii_name` to the last
  component of the part's name (`XML.p.v_senha` → password (senha)) and to the same lists as the
  path without an adapter. A sensitive part becomes a required parameter or
  a refusal.
- Generic names (id, type, lang, q, page, flag, …) are evaluated by the
  last component of the inner names, and strong same-field is downgraded.
- The adapter must not worsen coverage: when the origin of a part is
  in a response with no body, the generator follows the round 7 rule (refuses only
  when the chain is truly incomplete, and the alternative target with a captured
  previous response must generate). The check requires the generator WITH adapter
  on that target.
- The generated Python decoder is as strict as the Rust one (scope left open
  at the end, truncated surrogate pair → error).
- Re-review at d50d243: the 2 previous highs were approved. New decisions:
  (1) no value with an observed origin (strong or possible) may
  become a literal. If an adapter part has a producer outside the plan, the
  producer enters the plan (same round, in session order, together with the base
  chain); if the producer is outside the round or has no body, generation follows the
  incompleteness rule. (2) Operations-per-field limit (≤ 200 thousand) and
  compact `Item`: `l`×8 MiB < 500 MB. The app cuts the view at 2 000 parts
  per field ("N parts omitted"). (3) The sensitive/PII name lists
  now include abbreviations: pwd, pass, psw, pswd, pin, otp, passcode,
  seguranca (security), cookie, nm_*, aniversario (birthday), filiacao (parentage), logradouro (street),
  bairro (neighborhood), titular (holder), proprietario (owner), razaosocial (company name), conta (account), sexo (sex).
  The same lists apply on both paths. (4) The wrapper counts the re-execution depth by
  environment variable and refuses when the fallback is itself.
  (5) `flag` enters the generics list.
- Re-review at 9094555: hid2, cost, abbreviations and wrapper approved.
  Principle decisions for the adapter parts:
  (1) Producer outside the plan, in any round: with strong evidence, the
  producer rises into the plan (as in the chain); with possible evidence, or a
  producer without a body, the part becomes a required parameter with a note. Never a
  silent literal.
  (2) A literal in an adapter part only for: role Structure; proven constant
  value (the same value in ≥ 2 occurrences in the session, including
  across rounds, or present in static context); or navigation value
  (page/resource name of the chain itself). Any other part becomes a required
  parameter. Measure on the 3 real HARs: repeated values (e.g.:
  timeZoneOffset, #f12_selected) remain constants; only unique values with no
  origin become parameters.
  (3) Name list: add pw, pswrd, passw, pwrd, 2fa, mfa, totp,
  salt, hash, assinatura (signature), login, usuario (user), uid, pai (father), responsavel (guardian),
  beneficiario (beneficiary), agencia (branch), banco (bank), iban, whatsapp, rua (street), complemento (address complement), municipio (municipality),
  documento (document). Name false positives (e.g.: conta_corrente) are accepted
  as an error on the safe side: they become a parameter, never leak.
  (4) A producer step that supplies no referenced value leaves the plan.
- Leader's decision on principle (2), measured by Capture at 22583ff: strict
  by default would turn UI state (`v_filtro_sel`,
  `interceptor_is_active`, `#f12_selected`, `pagePixelHeight/Width`) into
  required parameters on the real HARs, with no security gain. Default:
  intermediate mode. Every part with no origin and no proof that looks like an
  identifier, secret or timestamp (UUID, hex, ULID/KSUID, base64,
  timestamp, mixed alphanumeric, default password) becomes a required parameter.
  UI constants stay literal, explicitly defined: booleans,
  numbers of up to 4 characters (with sign and decimal) and repeated/navigation
  values. Sensitive names and PII detectors still apply.
  Strict mode stays available through `--strict-parts`. A producer from another
  round only rises into the plan with a strong ValueMatch; SameField of a
  repeated field does not rise, so as not to pull in the previous round.

## Closing (2026-10-29)

Final re-review at 4f9031c: APPROVED with caveats, no critical or high
failure. Decision revised by the leader with the reviewer's data: with `is_ui_constant`,
`--strict-parts` generates on the 3 real HARs exactly the same parameters as
the intermediate mode. Therefore STRICT becomes the default, and intermediate
stays as the `--lenient-parts` option. Finishing touches: a part with SameField from
another round becomes a required parameter with the note "origin in another round
(cdp-rNNNN)"; the names sen, snh, nip, ticket, voucher, chv and doc enter the
list; pruning covers the case of the two producers with different values.
Accepted residual: free text (name, address, login) and a 4-digit PIN under a
neutral name are indistinguishable from UI state; a value repeated in 2
requests counts as a constant, except under a sensitive name.
