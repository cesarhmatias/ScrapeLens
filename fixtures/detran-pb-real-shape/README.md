# detran-pb-real-shape — real shape of the DETRAN-PB case (round 6)

Label: **sanitized from a real case** (real shape, 100% fictitious values). The *structure* was taken from the real HARs (read-only, without copying values or bytes); no raw HAR enters the repository.

| File | Contents |
|---|---|
| `real-shape-1round.har` | A: 1 complete round (23 entries, 8 Connector POSTs) |
| `real-shape-2rounds.har` | B: 2 complete rounds (46 entries, 16 POSTs), SESSIONID/STAMP/delta/plates differ per round |
| `manifest.json` | logical IDs (`har-NNNN`) per role and the expectations of Acceptance 1–4 of `docs/10-fidelity-case-real.md` |
| `build_real_shape.py` / `validate.py` | deterministic generator / shape validation |

Shape reproduced: Connector = HTML (~9.8 KB) with a fictitious script before it (`<SYNTHETIC_GUARD_DO_NOT_TOUCH>`, in place of F5), `<textarea name="XML">` with HTML entities, `<textarea name="ERRORMESSAGE">` and `<input type="hidden" name="STAMP" value>`; HAR creator `WebInspector` without Cookie/Set-Cookie/`cookies[]`; `/TSPD/…` noise between the steps; `jquery-ui.min.js` and `CIS_V1_SYNTH.js` with protocol constants (L3); fictitious plate (`TST0T1x`) and CPF (`000000001xx`) inside the XML; `v_renavam=12` out of format (L5); GETs without postData (L7).

Acceptance: `python3 tests/acceptance/check_real_shape.py` (fails until Core closes L1–L8). Revalidation on the user's real HARs (aggregates only): `python3 tests/acceptance/check_real_detran.py <har>…`.
