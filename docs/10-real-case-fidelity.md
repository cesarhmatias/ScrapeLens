# Round 6 — fidelity to the real DETRAN-PB case

## Motivation

Validation on the user's real HARs (`tests/results/real-case-detran/REPORT.md`,
fa54020) gave a partial verdict: the case is identifiable, but only partly
analyzable. The synthetic fixtures had form-urlencoded responses, and the
real ones bring HTML with form controls. The green of rounds 4 and 5 did not
prove the real case. This round closes gaps L1–L8 of the report.

Out of scope: Natural for Ajax decoder, bypassing /TSPD/ or CAPTCHA,
replay, external network and publication.

## Waves and ownership

- 6a: Core (`core/`) and Tests (`fixtures/`, `tests/`): fixtures with the real
  shape and acceptance.
- 6b: App (`app/`, `commands.rs`, `lib.rs`), revalidation on the real HARs
  (Tests) and independent review.

## Decisions

L1 — HTML form controls as response fields. A tolerant HTML tokenizer
(executing nothing and with no full DOM) extracts from text/html responses:
`<input name value>` (all types; checkbox/radio only if
`checked`), `<textarea name>content</textarea>` and `<select name>` with the
`<option selected>`. HTML entities are decoded in the decoded view, with
offsets mapped back to the original. These controls become `responseBody`
fields with `field` = name, `htmlControl: true`, and feed
same-field (STAMP) and value-match (including fragments of the textarea `XML`
≥ 40 bytes, which is where the delta lives). Search also starts to see these
fields by name.

L2 — HAR without cookies: on import, if no entry carries Cookie,
Set-Cookie or `cookies[]`, the session warning is `har.cookies_absent`: "the HAR does
not contain cookies (DevTools export removes them); cookie origin cannot be
assessed — use live capture (CDP/NetLog)". The origins and the chain repeat the
warning.

L3 — Static resources (script, stylesheet, font, image and media, by resource
type or MIME) are not producers in the chain. A value-match evidence coming from
them becomes `context` ("value also present in a static resource: probable
protocol constant") and does not create a step. A value present in a static
resource and in dynamic responses keeps only the dynamic producers.

L4 — Context pages: the chain gains the `pages` group, with the document
requests that loaded the page from which each step was emitted (by
Referer or initiator). The label is "context page"; they are not
value producers. With L1, the Connector POSTs (init, on_interceptor,
cmd_filtro) must enter as steps by STAMP/delta.

L5 — Sensitive business fields: the configurable list defaults to
placa (plate), v_placa, plate, renavam, cpf, cnpj, chassi (chassis) and vin (case-insensitive,
including as a name suffix). In named fields, the value is redacted and
propagated. In opaque fields, each occurrence of one of these names followed by
a value in the type's format is redacted: plate `[A-Z]{3}[0-9][A-Z0-9][0-9]{2}`,
11-digit CPF, 14-digit CNPJ, RENAVAM of 9 to 11 and 17-character chassis
alphanumeric without I/O/Q. The values found enter the session-wide value
propagation. The report counts redactions by type, without showing the
values. A value that does not follow the format is not silently redacted:
it generates the warning `sanitize.business_field_unmatched`.

L6 — Compare by rounds: the default option is to align only the application
requests (no protection or static resources), which enter later as their own
groups. Rounds: automatic segmentation by the entry request
(the 1st application document that repeats, e.g.: easynat-app). Each round of
A is aligned to the most similar round of B, and unpaired rounds are listed.
Explicit range option (`--a-range`, `--b-range`). Ambiguities should
drop drastically in H1×H2.

L7 — Request body of a bodiless method (GET/HEAD/OPTIONS) with no postData
in the HAR stays `empty`, with the reason "not applicable: method without body".
`unavailable` only when a body was expected and did not come.

L8 — When the origin of a value depends on an `unavailable` response, the
`unobservable` points to the equivalent occurrence in the next round, if there is one
(same model), as a suggestion.

## Acceptance

1. Fixtures with the real shape (Tests): Connector responses in HTML with
   script first, `<textarea name="XML">`, `<textarea name="ERRORMESSAGE">` and
   `<input type="hidden" name="STAMP">`, with entities; DevTools HAR variant
   without cookies; capture with 2 rounds. Origins: STAMP strong same-field
   (previous response); delta value-match in the XML fragment coming from the
   previous textarea; SESSIONID possible; static scripts without a step. Chain
   with the Connector POSTs (init, on_interceptor, init, cmd_filtro), the
   pages NatLogon/SIM1000X/VES0009X in `pages` and /TSPD/ in protection.
2. Sanitize: fictitious plates and CPF inside the XML disappear in all files;
   the warnings appear for values outside the format.
3. Compare A(1 round) × B(2 rounds): the round of A pairs with one round of
   B, the other round appears as an unpaired round, and there are few ambiguities.
4. HAR without cookies → warning `har.cookies_absent`.
5. Revalidation on the 3 real HARs (aggregated, without values): STAMP and delta with
   origin in the previous Connector response in ≥ 95% of the POSTs with an available
   response; chain with the Connector POSTs; 0 plates after sanitize.
6. Test suite with no regression.

## Review of round 6 (2026-10-28) — decisions

Verdict: partial. Fidelity on the real case was proven (3 HARs,
aggregated); there is 1 high failure.
- HTML tokenizer with linear cost: an unclosed quote cannot scan the
  document at every `<`. Comments follow HTML5: `<!-->`/`<!--->` close
  immediately; `<![CDATA[`, `<!x` and `<?` are bogus comments up to the 1st `>`.
  Strict numeric entities (no `+`). Regression: `<a b="` × 50 thousand in
  < 1 s.
- Duplicate evidence from the same response (HTML control + `value="…"`
  literal, control + context) is deduplicated by (attempt, overlapping byte
  range) before counting producers. A single producer never generates
  `ambiguous` by itself.
- Controls: submit/button/image/reset types are not producers.
  `hidden` with a non-generic name can give strong same-field. The other
  prefilled controls (text, password, email, select etc.) give at most
  medium evidence.
- Business fields: the name matches exactly or as a suffix after a
  separator (`_ - .`). `template`, `kevin` and similar are left out. In opaque
  fields, after the name, also accept the formatted variants
  (plate with hyphen, CPF with dots/hyphen, formatted CNPJ) and redact them. A
  recognized name without a value in the format generates the warning; HTML entities
  in the name are decoded before matching.
- "Static" resources: scripts with a query string, Cache-Control
  no-store/no-cache or JSON/JSONP body can be dynamic producers. Context
  label: "also present in a static resource (may be a protocol constant)".
  Object literals in JS (`{"k":"v"}`) enter as candidates.
- Compare: an inverted or out-of-bounds range generates an explicit error/warning.
  A repeated entry with no application step between the occurrences (reload) does not
  open a new round.
- The "initiator not preserved" warning is dropped when the attempt has an initiator.
  `pages` uses Referer OR initiator.url.

## Closing (2026-10-29)

Final re-review (at 4206ae5): the reviewer said "almost approved" and
conditioned approval on a single item, the quadratic cost of scan_business
in sanitization. Fixed in 7a11441 (interval BTreeMap; the same pattern
was removed in `changed` of the Propagator). The leader checked with the
reviewer's own probe (/tmp/rev6/p/sz.py) at HEAD: `placa1` ×200 thousand in 0.22 s,
`"cpf 123"` ×200 thousand in 0.18 s, linear scaling (before, 26.7 s and 31.6 s).
Round 6 APPROVED.

Result on the real case (3 user HARs, aggregated): STAMP and delta resolved
in 100%; chain with the Connector POSTs and 4 context pages; SESSIONID
with the composition hint (server prefix + client-assembled part);
no plate after sanitize; compare H1×H2 with 21 pairs and 0 ambiguities;
tokenizer and sanitization linear on hostile inputs of several MB.
