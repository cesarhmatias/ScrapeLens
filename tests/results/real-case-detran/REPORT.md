# DETRAN-PB real case with ScrapeLens — validation (HEAD 7e4cc9b, core release)

Aggregate data only: no real values (SESSIONID, cookies, STAMP, delta, license plates), no raw HAR.
Temporary working directory `/tmp/sl-real` (0700), deleted at the end. No network, replay or execution of
exported code. Labels of the imported sessions: `har-import` (no `synthetic-fixture`). The HARs are
`WebInspector` (DevTools).

Abbreviations: **H1** = `sem_captcha.har` (1 page); **H2** = `wsdetran.pb.gov.br.har.txt.har` (3 pages);
**H3** = `wsdetran.fluxo.captcha.solve…har.txt.har` (5 pages). Logical IDs of the core: `har-NNNN`.

## 1. Import (`import-har`)

| HAR | Size | Requests | GET/POST | Warnings | Response bodies | postData (POSTs) | Time | Peak memory |
|---|---|---|---|---|---|---|---|---|
| H1 | 12.6 MiB | 135 | 127/8 | 0 | 126 captured, 9 empty | 8/8 captured | 1.26 s | 50 MiB |
| H2 | 19.2 MiB | 209 | 190/19 | 0 | 182 captured, 12 empty, 15 unavailable | 19/19 captured | 1.55 s | 76 MiB |
| H3 | 31.8 MiB | 346 | 323/23 | 0 | 313 captured, 16 empty, 17 unavailable | 23/23 captured | 0.35 s | 125 MiB |

- None truncated/discarded. Completeness `complete` for all three. A single attempt per request (no redirects).
- `unavailable` in the responses = HAR without `content.text` ("response.content without text" (legacy: "response.content sem text")): 4 Connector POSTs in H2/H3
  (first round of `cmd_filtro`, `cmd_consultar_placa` ×2 and `cmd_nova`) and protection GETs.
- GET `requestBody` appears as `unavailable` ("HAR does not provide postData" (legacy: "HAR não fornece postData")) in 127/190/323 requests, without being
  a body that is actually absent (see gap L7).
- H3 contains the first 209 requests of H2 (same IDs, methods and paths; `compare H2 H3` = 209 pairs
  100% static) plus 137 requests from new rounds: H3 **is not an independent 2nd capture**.
- The HARs come from DevTools "Export HAR": **0 `Cookie`/`Set-Cookie` headers and 0 `cookies[]` in every
  entry** (removed by the export). That is why no `cookie-jar` origin is possible (L2).

## 2. Search `cmd_consultar_placa` (requestBody scope)

| HAR | POSTs found | field | exact | decoded | url |
|---|---|---|---|---|---|
| H1 | 2 (`har-0127`, `har-0133`) | `XML` | yes (19 B) | yes | 0 |
| H2 | 5 (`har-0093/0096/0192/0198/0207`) | `XML` | yes (19 B) | yes | 0 |
| H3 | 5 (same IDs as H2) | `XML` | yes (19 B) | yes | 0 |

Searches for `on_interceptor`, `cmd_filtro`, `cmd_nova` and `m_currentSessionId` also find the right requests.
Each search command: ~0.10 s, 8–14 MiB. **Meets requirement 1 of the case** (find the query by its body, not by its URL).

## 3. Origins and chain of the 1st `cmd_consultar_placa`

Targets: H1 `har-0127`; H2/H3 `har-0093` (response of the previous `cmd_filtro` unavailable in the HAR) and `har-0192`
(2nd round, complete). Times: origins 0.24 s/17 MiB (H1), 0.63 s/26 MiB (H2), 1.27 s/35 MiB (H3);
chain 0.08 s, 0.29 s, 0.21 s (≤ 37 MiB).

**Flow recognized?** Yes, in the sequence of events in the body: `easynat-app?op=S37` (har-0001) → `NatLogon.html` →
`init` NatLogon → `SIM1000X.html` → `init` → `on_interceptor` → `VES0009X.html` → `init` → `cmd_filtro` →
`cmd_consultar_placa` (→ `cmd_nova` → 2nd query). The **chain returned by the core does NOT match** this flow:

| Item | Result | Assessment |
|---|---|---|
| SESSIONID | `possible origin (value-match)` (legacy: "possível origem (value-match)"), producer `har-0001` (easynat-app, literal `m_currentSessionId`) in H1 and H2 (`har-0104` = easynat-app of the 2nd round in H2/H3); composite with a fragment in the XML also `possible` (legacy: "possível") | correct, medium strength by design |
| STAMP | **`no observed origin`** (legacy: "sem origem observada") (H1) / `repeated` (H2, H3) | **COVERAGE ERROR (L1)**: the STAMP of the POST == the STAMP of the previous POST's response in 100% of the POSTs with an available response (H1 5/5, H2 10/10; first row = non-`init` POSTs) |
| delta (fragment `x…` of the XML) | no producer (no XML fragment points to the Connector's previous response); `possible` (legacy: "possível") fragments point to pages/JS (`har-0001`, `har-0098`, `har-0007`) and 1 `ambiguous` (legacy: "ambíguo") (`har-0029`, jquery-ui) | **ERROR (L1)** + noise (L3): continuity of the delta previous→response confirmed outside the tool (same 5/5 and 10/10) |
| cookies TS*/JSESSIONID | **do not appear** (HAR without cookies) | data limit (L2) |
| PAGEINITPARAM, ERRORMESSAGE | `none` (empty) | correct |
| license plate (`v_placa` in the XML) | no origin (user input) | correct |
| `/TSPD/` and F5 scripts | 70 (H1) and 85 (H2) steps classified `protection` (reason only `initiator`/`complement`) and none in the application list | **correct**: the protection × application separation worked; but without cookies (L2) there is no strong proof |

Application chain returned: H1 = 5 steps (`easynat-app`, 2 scripts `ciscentral/cisadvanced…`, `jquery-ui.min.js`,
`VES0009X.html`), H2 = 6 (plus the 2nd `easynat-app`). **Missing** NatLogon, SIM1000X and, mainly, the 4–5 Connector POSTs
(`init`, `on_interceptor`, `init`, `cmd_filtro`) that provide STAMP and delta (the user's "priming of 9 requests"). **Excess**: static scripts (`jquery-ui`, `cis*`) enter via value-match of short constants/templates
inside the XML (confidence `possible`). `unresolved`: 4–5 fields (SESSIONID `repeated`, STAMP `none`, `If-Modified-Since`,
`If-None-Match`, query `op`).

Root cause of L1: in the real Connector responses the payload does not come as `application/x-www-form-urlencoded` but as
**HTML (10–15 KB, with an F5 script first) containing `<textarea name="XML">`, `<textarea name="ERRORMESSAGE">` and
`<input type="hidden" name="STAMP" value="…">`**. The origin extractor only reads form-urlencoded/JSON fields and literals from scripts;
HTML form controls are not read. The synthetic fixtures of R5 used a form-urlencoded response (a different shape from the real one):
the green fixtures did **not** prove the real case.

## 4. Compare between HARs

Compatible: H1×H2 (same flow, distinct captures). H2×H3 is not usable (H3 ⊃ H2).
H1×H2: 108 pairs, `alignedBy=model`, 0 out of order, 20 reordered, **27 only in A, 101 only in B, 51 ambiguities**
(H2 has 2 complete rounds; the monotonic pairing matches H1 with the **2nd round of H2** starting from the SIM1000X `init` and
leaves the 1st round as "only in B" (legacy: "só em B"); field count: 70 static, 61 dynamic (17 runtime, 44 no origin), 1 only in B.
Time 0.25 s / 36 MiB.

Per paired Connector POST (7 pairs):

| Field | Result | Assessment |
|---|---|---|
| SESSIONID | `dynamic` (legacy: "dinâmico") + `dynamic without origin (value already circulating)` (legacy: "dinâmico sem origem (valor já circulava)") in 6 of 7 pairs; in the 1st pair `dynamic without origin` (legacy: "dinâmico sem origem") | dynamic: correct. Origin: **incomplete** — should be `get at runtime (possible origin: har-0001/0104)` (legacy: "obter em runtime (origem possível: har-0001/0104)") |
| STAMP | `static` (legacy: "estático") in the `init` pairs (both `INIT`), `dynamic` (legacy: "dinâmico") + `without origin` (legacy: "sem origem") in the others | dynamic: correct. "no origin": ERROR (L1) |
| delta / XML fragments | parts `dynamic` (legacy: "dinâmico") with `get at runtime (possible origin…)` (legacy: "obter em runtime (origem possível…)") (e.g. 2–4 per pair) and parts `dynamic without origin` (legacy: "dinâmico sem origem") (1–4 per pair) | mixed: correct parts (model/page) and delta/plate without origin (plate correct; delta ERROR L1) |
| PAGEINITPARAM / ERRORMESSAGE | `static` (legacy: "estático") (empty), except 1 pair with PAGEINITPARAM `dynamic` (legacy: "dinâmico") `possible` (legacy: "possível") | correct |
| plate | inside the XML: part `dynamic without origin` (legacy: "dinâmico sem origem") | correct |
| cookies | absent (HAR) | data limit |

## 5. Sanitize

`sanitize` of H1 (0.16 s, 26 MiB) and H2 (0.34 s, 39 MiB); verification done by me over the whole
sanitized directory (session.json + attachments), without quoting values:

| Value | H1 before → after | H2 before → after |
|---|---|---|
| SESSIONID (1 and 2 distinct values) | 32 → **0** occurrences | 76 → **0** |
| plates (2 distinct values) | 8 → **4** (2 of 2 still present) | 16 → **10** (2 of 2 still present) |

The remaining plates are in the **request body attachments** (`*.request.bin`), inside the opaque field `XML`
(`v_placa`); the responses no longer contain the plate. Output labels: `har-import`, `sanitized`. SESSIONID disappears
(propagation by value works); **third-party plates do not disappear** (L5).

## 6. Times and memory (macOS arm64, core release)

| Command | H1 | H2 | H3 |
|---|---|---|---|
| import-har | 1.26 s / 50 MiB | 1.55 s / 76 MiB | 0.35 s / 125 MiB |
| search | 0.10 s / 8 MiB | 0.10 s / 11 MiB | 0.11 s / 14 MiB |
| origins | 0.24 s / 17 MiB | 0.63 s / 26 MiB (0.14 s on the target `har-0192`) | 1.27 s / 35 MiB (0.22 s) |
| chain | 0.08 s / 19 MiB | 0.29 s / 24 MiB (0.08 s) | 0.21 s / 37 MiB (0.11 s) |
| compare | H1×H2: 0.25 s / 36 MiB | H2×H3: 0.12 s / 20 MiB | — |
| sanitize | 0.16 s / 26 MiB | 0.34 s / 39 MiB | not run |

All below 1.6 s and 130 MiB; no performance problem.

## Verdict

**Partial: the case is identifiable, but only partially analyzable with the tool.**
- ✔ Imports the three HARs without warning, finds the queries by body (`XML`, exact, decoded, 0 by URL), separates
  `/TSPD/` and F5 scripts as protection, resolves SESSIONID (possible) and compares dynamic × static.
- ✘ Does not rebuild the chain the user did by hand: **the Connector POSTs are missing** (STAMP/delta) and static scripts enter; STAMP and delta come out "no origin", although the response→request continuity is 100% in the data.
- ✘ Sanitization leaves third-party plates.

## Gaps → requirements

| ID | Gap | Proposed requirement |
|---|---|---|
| L1 | HTML responses with form controls (`<input name=STAMP value>`, `<textarea name=XML>`) do not generate origin candidates | Extract name/value pairs from `<input>`, `<textarea>` and `<select>` of HTML responses as response fields (same-field for STAMP; value-match inside the XML for the delta); support HTML entities; synthetic fixtures must use this real shape |
| L2 | DevTools HAR does not carry Cookie/Set-Cookie (export without cookies) | Declare at import/UI that the HAR contains no cookies and the cookie origin is not evaluable; suggest CDP/NetLog capture |
| L3 | Excess: static scripts (`jquery-ui`, `cis*`) as `possible`/ambiguous producers because of constants/templates in the XML | Filter producers that are static resources (JS/CSS/images) or downgrade/group them; separate "protocol constant" from "session value" |
| L4 | Chain without the Connector POSTs and without NatLogon/SIM1000X | Depends on L1; add page steps (`html`) by initiator/Referer when the POST is "loaded" by it |
| L5 | Sanitization does not cover plates (business fields in the opaque XML) | Configurable list of sensitive protocol fields (`v_placa`, etc.) with propagation by value inside the XML; redaction report |
| L6 | Compare pairing with 2-round captures leaves the 1st round "only in B" (legacy: "só em B") and yields 51 ambiguities | Align by model phase/occurrence (round) and show rounds as groups; allow choosing the range of requests to compare |
| L7 | GET `requestBody` appears as `unavailable` ("HAR does not provide postData" (legacy: "HAR não fornece postData")) | A GET without a body must be `none/not applicable`, reserving `unavailable` for a body that is really unavailable |
| L8 | Unavailable responses of the Connector in H2/H3 (1st round) block the origin of the 1st `cmd_consultar_placa` | In the UI, indicate which producer is unavailable and suggest the equivalent occurrence in the following round |

## Round 6 — revalidation (core fc4aa29, `check_real_detran.py`, aggregates only)

Rerun on the same 3 HARs with `python3 tests/acceptance/check_real_detran.py <H1> <H2> <H3>` (temporary directory
0700, deleted; no value printed). Core release rebuilt from HEAD.

| Metric | Before (fa54020) | After (fc4aa29) |
|---|---|---|
| STAMP resolved (strong same-field, POSTs with STAMP≠INIT and previous response available) | 0 of 5 (H1); 0 of 10 (H2) | **5/5 (H1), 10/10 (H2), 11/11 (H3) = 100%** |
| delta resolved (value-match in the previous textarea, producer = Connector POST) | 0 of 5; 1 of 10 | **5/5, 10/10, 11/11 = 100%** |
| Steps of the chain of the 1st `cmd_consultar_placa` | 5 (H1), 6 (H2), no Connector POST | 10 (H1), 9 (H2/H3), **5 / 4 / 4 Connector POSTs** |
| `pages` group | absent | 11 (see analysis) |
| `protection` | 70 / 85 | 70 / 41 / 41 (the pages and scripts left the protection group) |
| Plates after sanitize | 4 of 2 (H1), 10 of 2 (H2) | **0 / 0 / 0** |
| `har.cookies_absent` warning in origins/chain | no | **yes** |
| compare H1×H2 | 108 pairs, 27 only in A, 101 only in B, 51 ambiguities | **21 pairs, 0 only in A, 5 only in B, 0 ambiguities, 2 rounds without a pair** |

Acceptance 5 criteria (≥ 95% STAMP/delta, chain with the Connector POSTs, 0 plates): **met**.

The count difference with the Core (7/7 in H1 and 14/14 in H2): my denominator is stricter (POSTs with
STAMP ≠ `INIT` and captured previous response = 5, 10 and 11); the Core also counts the `init`s, whose STAMP is the constant
`INIT` and whose delta does not come from the previous response in the real case. I did not reproduce 7/7 and 14/14 as defined, but the
result that matters (100% on the POSTs where STAMP/delta depend on the previous response) checks out.

**The "11 context pages" are excessive.** Expected: easynat-app + NatLogon + SIM1000X + VES0009X = 4.
Obtained per HAR: 1 easynat-app, 3 application pages and **7 documents that are not steps of the flow**:
3× `*_JLIBS.html` (auxiliary frames of NatLogon/SIM1000X/VES0009X), 3× `cscform.html` and 1× `aboutBlank.html`.
All enter because they are the Referer/initiator of **protection** requests (the `/TSPD/…` GETs), not of application steps
(the reasons cite protection GETs). Requirement L4b: `pages` must be derived only from the Referers of the **steps**
(Connector POSTs and producers), never from protection or static requests, and auxiliary frames (`*_JLIBS`, `cscform`, `aboutBlank`)
must be grouped as sub-documents or omitted.
`unresolved` remains with 13–15 fields (conditional headers, `op`, parts of the XML without source).

### Round 6: synthetic acceptance
`check_real_shape.py` OK; `check_chain_compare.py` OK (now 12 application pairs + 1 in `groups.protection`, and
`compare --all` = 13); `check_bodies_search.py` OK (5 + 2 cases); `run_acceptance.py` 10/10;
`validate.py` on the fixtures OK; `cargo test` of the core: 161 pass, 0 fail.

### Updated verdict
**The case is now identifiable and analyzable with the tool.** The Connector POSTs enter the chain via STAMP and delta, `/TSPD/` stays in protection, absent cookies are declared, plates disappear in sanitize and the compare between captures is usable (0 ambiguities, rounds without a pair made explicit). Remaining items: the excess of context pages (L4b), the `partialComposition` of SESSIONID (hint still to come from the Core), and the cookie origin, which only exists with live capture (CDP/NetLog).

## Round 7 — priming script and assess on the real HARs (generator f858b17, assess c28533b)

`python3 tests/acceptance/check_real_priming.py <H1> <H2> <H3>` (HARs read-only; session and scripts in `/tmp` 0700,
deleted; aggregates only; the generated script was **not** executed: only the plan mode, without `--confirmar`, and no network).
Captured values were used only in memory to count literal occurrences.

### Script of the 1st `cmd_consultar_placa`
| Metric | H1 | H2 | H3 |
|---|---|---|---|
| `ast.parse` | OK | OK | OK |
| Plan mode (rc, lines = steps, "Nothing was sent" (legacy: "Nada foi enviado")) | 0 / 11 / yes | 0 / 10 / yes | 0 / 10 / yes |
| Steps / Connector POSTs in the script (POSTs in the HAR) | 11 / 6 (8) | 10 / 5 (19) | 10 / 5 (23) |
| Order = manual flow (easynat-app → NatLogon → init → SIM1000X → init → on_interceptor → VES0009X → init → cmd_filtro → consultar) | **yes** | **no** (without `cmd_filtro`) | **no** (without `cmd_filtro`) |
| Previous POST response captured in the HAR | yes | **no** (4 Connector responses without body) | **no** (same) |
| STAMP | HTML control | **parameter `stamp` (default = captured value)** | same as H2 |
| delta (XML fragment) | fragment extracted at runtime | same | same |
| SESSIONID | prefix extracted from easynat-app + parameter `sessionid_cliente` | same | same |
| plate | required parameter | required | required |
| Required / default parameters | `placa` / `op`, `sessionid_cliente` | `placa` / `op`, `sessionid_cliente`, `stamp` | same as H2 |
| **Captured values literal in the code (count)** | **1** (SESSIONID suffix, in `PARAMS`) | **2** (SESSIONID suffix + STAMP, both in `PARAMS`) | **2** (same) |

Alternative target in H2/H3 (1st `cmd_consultar_placa` whose previous response was captured, 2nd round): STAMP via HTML control,
plate required, but the script has **16 steps / 10 POSTs** and **repeats round 1 in full** (2× easynat-app, 2 sequences of
`init`) before `cmd_filtro`; 2 literal SESSIONID suffixes in `PARAMS` (one per session).
False positive handled: a short "delta" (≤ 8) coincides with the header constant of the XML of the `init`s; counted separately, not as a leak.

### assess
| Verdict (all requests) | H1 | H2 | H3 |
|---|---|---|---|
| app-ok / blocked? / undetermined (legacy: "indeterminado") | 11 / 13 / 111 | 21 / 14 / 174 | 28 / 31 / 287 |
| Connector POSTs | **8 app-ok** | 15 app-ok + 4 undetermined (legacy: "indeterminado") | 19 app-ok + 4 undetermined (legacy: "indeterminado") |
| `blocked?` on a 200 from the Connector | 0 | 0 | 0 |
| `blocked?` without explicit signal | 0 | 0 | 0 |

The 4 `undetermined` (legacy: "indeterminado") in H2/H3 are exactly the Connector POSTs without a captured response body (consistent: without a body, app-ok is not asserted).
Normal Connector responses come out `app-ok`. The `blocked?` are all GETs, with the `/TSPD/` marker as the explicit signal;
however **some of them are pages of the application itself** (easynat-app: 1/2/3, SIM1000X and VES0009X: 1/2/3 per HAR) that merely
reference the `/TSPD/` script: probable false positive (reason `html-without-controls` (legacy: "HTML sem controles com o marcador /TSPD/") on an entry/template page).

### Round 7 verdict
The generator works and the flow **matches the manual one when the bodies exist** (H1: `ast` OK, exact order, STAMP via HTML control,
delta via fragment, plate required, plan mode without sending). Failures that become requirements:
1. **Captured session value as a parameter default** (`sessionid_cliente = '_<12 digits>'`, and `stamp` in H2/H3): contradicts Acceptance 1
   ("no sensitive captured value as a default"). The SESSIONID suffix, STAMP and similar must be required with no default
   (or at least redacted); `op` (public protocol constant) may have a default.
2. **Without the previous response body, the `cmd_filtro` step disappears and STAMP becomes a parameter** instead of failing clearly: the script should warn
   that the chain is incomplete (Connector responses without body in the HAR) instead of generating a plan that does not match the flow.
3. **The script for the 1st query of the 2nd round repeats the previous round** (16 steps, 2 sessions): the generator must restrict the producers to the target's round
   (same cause as the INIT crossing rounds already reported in the fixtures).
4. **assess**: do not mark application pages that only cite `/TSPD/` as `blocked?`; require a protection response (short body / without application markers) or status.
Pending: the proof against `detran-sim` with `--confirmar` (Acceptance 2) and the injection proof (Acceptance 4) are not part of this round of real HARs.
