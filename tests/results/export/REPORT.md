# Independent validation — export/sanitization in the UI

Status: **APPROVED (final addendum below)**. Original body = round 1, partial; see "Addendum". No production code
was edited. Observed bundle: `a58db574771fcd6058bc63a8080e0ba2f9bdf1aeb671bf9c56d4bf221fab26cf`,
13.969.728 bytes, ad-hoc signature verified (exit 0). Source audited: `2c6765e`.

## Executed result

| Check | Result | Evidence |
|---|---|---|
| Independent tests compiling the real bridge | **14 pass, 2 fail** (9 internal tests + 7 new) | independent-bridge.log |
| Shell unit tests | 15 pass, 1 live ignored | tauri-tests.log |
| Core | 91 pass, 1 benchmark ignored | core-tests.log |
| TypeScript | passes | typecheck.log |
| Preview/core/cURL and Python file | identical in bytes, file 0600 | preview_matches_core_and_saved_file_for_both_formats |
| Captured/truncated/unavailable/discarded/empty bodies | state preserved; stale attachment not exported | states_are_explicit_and_do_not_export_stale_attachment |
| Invalid ID/format/folder | refused without writing | invalid_request_format_and_source_fail_without_writes |
| Sanitization | own URL/Auth/Cookie/body/raw markers absent, raw events omitted, source byte-identical and output re-read | sanitized_output_removes_markers_raw_events_and_preserves_original |
| Source/occupied destination/direct link | refused; existing content intact | occupied_source_descendant_and_direct_symlinks_are_refused |
| Link in an ancestor of the destination | **wrongly accepted in both operations** | two regressions below |
| GUI bundle | window rendered, DEMO labeled and Sanitize disabled | bundle-observed.png |
| Native Save/Cancel dialog and real clipboard | **not tested independently** | known earlier blocker, not repeated |
| App UI harness | artifact reviewed; uses Tauri stub, simulated dialog/clipboard and has 3 unregisterListener errors | not rerun nor promoted to native proof |

No generated cURL/Python code was executed, no HTTP call was repeated and no certificate/permission was changed.
The production build was not repeated: the executable/hash and signature were verified directly.
The historical battery 282/282 remains intact; it does not prove this new feature nor the new bundle. I did not
rerun the h1/h2/h3 matrix without need.

## Confirmed failures — target contract (round blockers)

**F1 — exported file follows a link in an ancestor.**
`src-tauri/src/export.rs:215` only calls reject_symlink on the immediate parent, and l.225
on the file. With `alias -> real`, existing `real/sub`, the call
`write_text_file(alias/sub/out.sh, "SYNTHETIC")` returns Ok and writes to
`real/sub/out.sh`. It violates the refusal of symbolic links in contract §5 and the promise of the doc-comment not to follow links. Medium severity: it writes a new private file to a path resolved through the link; there was no overwrite.

**F2 — sanitization follows a link in an ancestor.**
`src-tauri/src/export.rs:318-321` checks only the immediate parent before canonicalizing it. `sanitize_to(source, alias/sub/output)` returns Ok and creates
`real/sub/output`. The source remained intact, but the destination through the link was not refused as contracted. Medium severity, same mechanism as F1.

Reproduction without GUI/network, in their own temporary folders:

```sh
cargo test --manifest-path tests/exportacao/Cargo.toml --offline --test bridge export_rejects_symlink_in_ancestor
cargo test --manifest-path tests/exportacao/Cargo.toml --offline --test bridge sanitization_rejects_symlink_in_ancestor
```

Both fail at 2c6765e because they received Ok. They were not ignored and their asserts were not loosened. Fix the path validation across the whole chosen chain,
with an explicit policy for known macOS aliases, without simply removing the guarantee. Retest the normal, occupied, direct-link and ancestor paths. This report does not claim full resistance to directory-swap races: they were not exercised.

## Native flow and next steps

1. App fixes F1/F2, runs the regressions, rebuilds and records the new hash/bundle.
2. Run the single script in `tests/exportacao/README.md`. The private fixture with a captured body and fictitious markers has already been prepared in
   `tests/.work/exportacao-manual/source`. Saved code and the sanitized session can be checked by `verify_manual.py` without running exports.
3. Check the native clipboard after the Copy action (UI label `Copiar` (legacy)) and compare it with the preview. Separately, prove Save, Cancel and Open the sanitized session (UI labels `Salvar` (legacy), `Cancelar` (legacy), `Abrir sessão sanitizada` (legacy)) in the corrected bundle.
   Do not repeat the already blocked NSSavePanel automation; request human selection if there is no accessible route. There is still no proof of this cycle in this validation.

## Preservation

The pre-existing modified file
`tests/results/app-latest/testserver/app-20261027/h1.jsonl` remains outside this round's commits (39 additional lines). No sessions were deleted, no temporaries of other agents were removed, no changes were made to app/, src-tauri/ or core/, and nothing was published or pushed. Run metadata in result.json. The bundle screenshot was captured via computer_use in a specific window; there was no foreground action.

## Addendum — closing with native proof (final bundle)

Bundle: executable SHA-256 `9c04b98b30b3d6451ee53fa5eee589aaba0cd4e5d3185894e39facb0335bdbe5`
(HEAD b226f9b; fixes `16015a1` ancestor symlink and `0d4dbab` adapter tolerates omitted fields),
`codesign --verify --deep --strict` ok. The bundle `5934556c…` failed to open the fixture (`TypeError s.attempts.map`); fixed in `0d4dbab`.

Native proof: operated by the leader via computer_use (NSOpenPanel/NSSavePanel in the foreground, ⌘⇧G), 23:27–23:30. File verification: Tests, independently (without running native.sh/native.py, no network).

| Item previously "not tested" | Status |
|---|---|
| NSOpenPanel open capture (fixture without attempts/redirects/cookie) | **passed** (native proof by the leader) |
| NSSavePanel save cURL (`native.sh`, 753 B) | **passed**; 0600, `cmp` identical to `expected.sh` (Tests) |
| NSSavePanel save Python (`native.py`, 1157 B) | **passed**; 0600, `cmp` identical to `expected.py` (Tests) |
| Cancel Save | **passed**: UI "Salvamento cancelado; nada foi gravado" (legacy); no `captured.sh/.py` exists (Tests) |
| Native clipboard (Copy) | **passed** by the leader: `pbpaste` with UTF-8 identical to `expected.py`. Without LANG UTF-8 `pbpaste` differs in the em dash: a pbpaste artifact. Not re-verified by Tests (volatile clipboard) |
| Sanitize → save → reopen | **passed**: folder 0700; `session.json` and `attachments/sanitized-request.json` 0600; no `cdp-events.jsonl`/`netlog.json`; no `ONLY_SYNTHETIC`; URL reopened `https://fixture.invalid/echo?sid=%5BREDACTED%5D` (Tests read session.json). Screenshot `docs/screenshots/24-exportacao-sanitizada-aberta.png` |
| Source intact | **passed**: SHA of the 3 manifest files identical |

Regressions: `cargo test --manifest-path tests/exportacao/Cargo.toml --offline`
→ **16/16 pass** after `16015a1` (F1/F2 closed).

`verify_manual.py` now explicitly ignores only files named `.DS_Store` in the source
(Finder metadata created at 23:18 by the user's navigation, before the app ran; the app does not write there). Any other new/changed/missing file
still fails. Result: PASSED. No `.DS_Store` was deleted.

Cosmetic observation (leader, non-blocking): sessions with label `synthetic-fixture`
show the title "Demonstração — vitrine sintética" (legacy) and the bar "sessão de demonstração" (legacy) instead of the session id.

Limits: export does not run/replay requests; clipboard and dialogs depend on foreground operation; no notarization/Intel.

## Round 3 — independent revalidation at HEAD 387d799

**Tested (rerun by Tests, offline):**

| Check | Result |
|---|---|
| Bridge (`tests/exportacao`) | **18/18** (16 previous + 2 new alias-policy tests) |
| src-tauri | 15 ok, 1 ignored |
| core | 91 ok, 1 ignored |
| typecheck (`tsc --noEmit`) | passes |
| Bundle `…/macos/ScrapeLens.app` | executable SHA-256 `9c04b98b…bdbe5` (the same as the final native proof; the `5934556c…` cited by the leader predates `0d4dbab`); `codesign --verify --deep --strict` exit 0 |

New regressions: `symlink_policy_final_file_dangling_and_relative_aliases` (link in the destination file itself to an existing and to a pending target, link to a file as parent folder, pending link as sanitization destination, relative ancestor `../rel/`, control `../real/` accepted) and `symlink_policy_macos_system_aliases_only_at_root` (real `/private/var/tmp` and `/var/tmp` accepted; a link created by the user inside `/var/tmp` refused). All pass: **no new bug** in the policy of `16015a1`. A link under `/Users/...` is covered by the existing ancestor regression
(same mechanism: any ancestor other than `/var`, `/tmp`, `/etc`).

**Not tested in this round:**
- GUI/clipboard via computer_use: opening the fixture depends on NSOpenPanel (`bridge.ts` `openDialog`), so that part was interrupted as instructed; clipboard not read. The native clipboard proof remains the one in the addendum (operated by the leader, `pbpaste` UTF-8 identical).
- Native Save/Cancel: recorded as **pending human selection** in this round (already passed in the leader's proof in the addendum); it does not block the automated closing.
- Directory-swap races (TOCTOU) between the check and the write: not exercised; validation is by a prior check, not by `openat`/`O_NOFOLLOW` across the whole chain.
