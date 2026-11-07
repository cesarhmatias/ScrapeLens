# Merge of origin/main into main: where each GitHub-only commit lives

Hashes of local commits below are from before the literal rewrite; `docs/history-rewrite-map-t21.tsv` maps them to the published hashes.

Merge commit 157ed89 (parents 7b86738 = main, 572f30f = origin/main). Tree vs main: only
core/src/export/secret.rs and core/tests/sanitize_hardening.rs (origin's concat! literals).
"empty" = cherry-picking the origin commit onto main gives no change (already present).
"port" = main has the fix in its own commit(s); the mapped commit is the main commit that carries it.
Evidence key: P = cherry-pick onto main empty; T = same test name present on main; L = file:line checked in merged tree; C = cargo test (see verification).

| # | origin commit | subject | where it lives in the merge | evidence |
|---|---|---|---|---|
| 1 | 63501a7 | test(core): record neutral-name and format leaks | main 83c3799 (same subject); core/tests/sanitize_hardening.rs | content identical to main except concat! (merge) |
| 2 | 4d86067 | feat(core): detect credentials by value format | main 13c8d76 + 1e48e7b; core/src/export/secret.rs | identical to main except concat! (merge) |
| 3 | 10b07c8 | fix(capture): admit a client only when its whole connection is the browser's | main ad86ab4 (port: "Same changes as fix/relay-013"); capture/src/relay.rs:514-528 | port by commit message; T: no origin-only test names; L; C |
| 4 | bc16179 | fix(capture): a local flood cannot take the browser's tunnel slots | main ad86ab4; capture/src/relay.rs:128 (MAX_PENDING_CHECKS), relay_peer.rs:63 (Gate) | port; L; C |
| 5 | 2a33f00 | test(capture): retry the port check in the drop test | empty on main (P) | P |
| 6 | 6de3526 | fix(capture): socket with no owner is closed, not a stranger | main ad86ab4; capture/src/relay_peer.rs:435-436 (`row.inode == 0 => Err(ALREADY_CLOSED)`) | port; L; text differs from origin, behaviour checked by C |
| 7 | c7e8799 | fix(capture): close the relay as soon as the browser exits | main ad86ab4; capture/src/lib.rs / relay.rs | port; L (origin's test assertion not byte-identical) |
| 8 | 92b8fd3 | fix(capture): check the owner tree once per generation | main ad86ab4; capture/src/relay_peer.rs (GENERATIONS, check per generation) | port; origin's constant 4 was replaced by 1 in origin's own d25ef55, final value 1 on both sides (relay_peer.rs:59) |
| 9 | 80ef2fc | fix(capture): bound the owner-tree check by one 3 s window | main ad86ab4; capture/src/relay_peer.rs | port; L (window logic) ; C |
| 10 | 52937ed | fix(core): walk ancestor directories with search rights | main f4f54d0 (fix(core): open ancestors for search only); core/src/store.rs (main version) | port; origin's store.rs has no later fixes; main superset by fn names (T) |
| 11 | 49237d0 | fix(core): open a copied source with O_NONBLOCK, refuse non-files | empty on main (P); core/src/store.rs:694 (O_NONBLOCK) | P, L |
| 12 | 31cb2b2 | fix(core): clean up exports through the directory descriptor | core: main f4f54d0; mcp: main 36626bc and d902b3d (mcp/src/tools.rs); tests: core/tests/store_race.rs (main d8f2f6d, b8e115d) | port; T (origin's store_race fn names subset of main's) |
| 13 | d25ef55 | fix(capture): a miss is final after one complete generation | empty on main (P); capture/src/relay_peer.rs:59 (GENERATIONS = 1) | P, L |
| 14 | 9bbf214 | fix(capture): cancel oldest waiter at the limit, size from RLIMIT_NOFILE | main ac0a652; capture/src/relay.rs:128-145 (pending_limit) | port; L |
| 15 | 1594646 | test(capture): retry copied binary's validation on ETXTBSY | empty on main (P); capture/src/chrome.rs | P |
| 16 | 6507bfa | fix(capture): read macOS libproc counts and errors correctly | empty on main (P); main ac0a652 (review L6, L7) | P |
| 17 | b247601 | fix(app): keep a validation run through descriptors; open-files limit at start | validation: main 5e54361; src-tauri/src/validation.rs:97-130 (core PrivateDir::copy_tree_from). open-files: src-tauri/src/hardening.rs:40 (harden_process calls raise_open_files_limit) | port; L; origin's own copy_tree_at/remove_path not needed (core covers) |
| 18 | 69e58ad | fix(app): write text exports and clean up failed exports through descriptors | main 7708ca8, 5e54361; src-tauri/src/export.rs:290 (open_dir_nofollow + create_file_at), :523 (PrivateDir::open_existing cleanup) | port; L |
| 19 | e804fb3 | fix(mcp): raise the open-files limit at start | main mcp/src/harden.rs:23 (harden_process calls raise_open_files_limit), :27 | port; L |
| 20 | 0c5b8bf | test(app): remove two unused imports from swap race tests | empty on main (P) | P |
| 21 | d68860f | fix(app): no-follow walk takes .. from descriptor, system links only | main 56351ad + 045302d; src-tauri/src/fsfd.rs (search_flags, 0311 handling, ENOTDIR vs link) | port; origin's fsfd.rs DROPPED search_flags (review-013c L-2) — main's kept, so nothing lost; main's l2_tests kept |
| 22 | 572f30f | test(export): compile export harness with fsfd module and rustix | tests/export (main) — Cargo.toml and bridge.rs identical to main; main's tests/export/Cargo.lock removed (T19) | identical; C (cargo test workspace includes tests/export) |
| 23 | 9505ae2 | test(capture): failed check-thread start refuses its connection; waiting limit | main ac0a652 tests: capture/src/relay.rs:2813 (same name) and :2848 | T (same test names identical); origin-added duplicate removed during merge |

Not in the 23 but resolved in the merge (origin-side conflicts):
- src-tauri/src/commands.rs (origin modified, main moved to commands/): origin's ChromeStatus/notice logic is in main's src-tauri/src/commands/browser.rs:6-33 and :73. commands.rs deleted.
- sub-crate Cargo.lock (mcp, recon, tests/export, capture, adapters/natural-ajax): deleted (main T19). Root Cargo.lock = main.
- capture/Cargo.toml: main's security-framework (T09) kept; origin's standalone [workspace] dropped (single workspace).
- .gitignore, experiments/proxy/followup.sh, src-tauri/linux/build.sh, tests/linux/README.md, testserver/README.md, src-tauri/PACKAGING.md: main's version (root target, single workspace). Origin's release-record text in PACKAGING.md is in main's src-tauri/PACKAGING-HISTORY.md (English, all sections present: 0.1.3, 0.1.2, 0.1.1, bundle, cookie selector, round 16, ...).
- fsfd.rs (add/add): main's version.
- capture/src/relay.rs: origin's auto-merged test duplicated main's tests; reverted to main.

Other differences: none. `git diff --cached main` before commit = 2 files.

## Verification (merge 157ed89)
- macOS (agent worktree, root workspace): cargo test EXIT 0: passed=915 failed=0 ignored=36 (79 result lines); cargo clippy --workspace --all-targets --exclude scrapelens-testserver -- -D warnings EXIT 0.
- npm ci, typecheck, test (13 scripts ok), build: all EXIT 0.
- Linux (linux/arm64, debian:12, chromium, experiments/linux/run.sh label merge-arm64, snapshot of 157ed89):
  - workspace --no-fail-fast (excl. scrapelens/Tauri): passed=813 failed=1 ignored=27 (76 binaries). The one failure: adapters/natural-ajax tests/roundtrip.rs:216 `operation_limit_bounds_time_and_memory`: "CPU time 4.19s" > 2.0 s bound (debug build, under parallel load). The same test passes 3/3 when run alone on the same image (1.45–1.65 s). The crate is identical to main, so the merge does not cause it. Load-sensitive; owner: Testes/adapters.
  - clippy workspace -D warnings: EXIT 0.
  - capture live tests (`inside.sh live`, --ignored, Xvfb): 18 passed, 0 failed, 192 filtered.
- Not run: Linux amd64 (Ubuntu), the Tauri crate `scrapelens` on Linux (no WebKitGTK in the image), npm on Linux, Intel macOS.

## Token-format literal scan (push protection)
Range origin/main..merge/origin-main (all local-only commits + merge): added lines scanned for ghp_, github_pat_, sk_live_, xox[bpoa]-, AKIA, AIza, JWT, private key headers.
Hits (all in test fixtures of the sanitizer):
- 13c8d76 (feat(core): detect credentials by value format): core/src/export/secret.rs (7 patterns), core/tests/sanitize_hardening.rs (private key header)
- 83c3799 (test(core): record the neutral-name and format leaks): core/tests/sanitize_hardening.rs (6 patterns)
Merge tree: clean (concat! form, from origin's 4d86067/63501a7). The history is not: rewriting 13c8d76 and 83c3799 (and descendants) is needed before a push passes push protection. Needs leader approval.
origin/main contains none of these literals.
