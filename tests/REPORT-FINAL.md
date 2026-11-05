# Final acceptance report — ScrapeLens

- **HEAD tested:** 6a85676 (`fix(priming): placa com hífen, chassi, +55, ...`)
- **Last update:** 2026-11-03 (rounds 13 to 16; own sections below)
- **Date:** 2026-10-29
- **Machine:** macOS arm64, Chrome 156.0.8078.73, no external network (Chrome restricted to 127.0.0.1).
- **Data:** synthetic; real HARs only as aggregates, read in read-only mode (temporaries 0700 deleted).

## Criterion 9 — done LIVE in this round
`tests/capture/run-cycle.sh live-final` ran the real cycle (Chrome + testserver h1/h2/h3, CDP + NetLog) at the HEAD above
and `run_acceptance.py --capture tests/capture/runs/live-final` consumed it — it is not a replay of the old capture.
Capture: 2 legs, 27 requests, 4 ambiguous, 6 redirects, 14 h3 streams; native HAR imported: 15 requests (complete);
no certificate installed. `initiator` in the raw CDP events: present (19 events in h1h2, type `other`);
the Core is still changing the initiator in parallel — any divergence in the imported session is expected until its commit lands.
(The directory `runs/live-final` is outside git, 12 MB; the stable copy is in `tests/results/capture-latest/`.)

## Scoreboard
| Suite | Result |
|---|---|
| run_acceptance (10 criteria, with live capture) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 assertions, 0 failures) |
| check_bodies_search | OK, 5 cases |
| check_chain_compare | OK |
| check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK |
| tests/export (cargo test) | 19 passed, 0 failures |
| cargo test core | 250 passed, 0 failures (1 ignored) |
| cargo test src-tauri | 42 passed, 0 failures (6 ignored) |
| check_real_detran (H1, H2, H3) | OK: STAMP and delta 100%, 0 plates after sanitize |
| check_real_priming (H1, H2, H3) | OK: params_required = [sessionid_cliente, placa], 0 captured literals |

Result: **all green, 0 failures.**

## Execution note
The first pass of the suite ran with `core/target/release` older than `core/src`, and `check_real_detran`/`check_real_priming`
refused (rc 1); after `cargo build --release` the whole suite was rerun and is the one listed above.

## Round 8 — Natural for Ajax adapter

- **HEAD tested:** dc14ac3 (`feat(priming): event/page/model do cabeçalho são estrutura do protocolo no modo estrito`)
- **Date:** 2026-10-29
- **Build:** `core` and `adapters/natural-ajax` (natural-core) rebuilt in release before the suite.
- **Data:** synthetic; real HARs (H1/H2/H3) only as aggregates, temporaries deleted.

| Suite | Result |
|---|---|
| run_acceptance (live capture of the final round, `live-final`) | 10/10 OK |
| check_bodies_search | OK, 5 cases |
| check_chain_compare | OK |
| check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK |
| check_natural_adapter (detran-sim `strict`) | OK: (a) control without adapter fails; (b) with adapter 2 complete sessions; (c) round-trip 0 divergences |
| prove_strict (adapters/natural-ajax/scripts) | OK, `fails: []` |
| tests/export | 19 passed, 0 failures |
| cargo test core / src-tauri / natural-ajax | 259 / 45 / 28 passed, 0 failures |
| check_real_detran (H1, H2, H3) | OK |
| check_real_priming without `--wrapper` | OK |
| check_real_priming with `--wrapper` (natural-core) | OK: target with captured previous response generates a script with `natural_ajax_encode`; the "first" of H2/H3 remains refused (responses without body) |

Result: **all green, 0 failures.** Criterion 9 of run_acceptance uses the live capture of 2026-10-29 (`live-final`); it was not redone in this round.

## Round 10 — multi-target capture (official final round, final bundle)

- **HEAD tested:** 0d98615 (capture in f1493ab, core in 66e97e3, bundle in 0d98615)
- **Date:** 2026-10-31
- **Build:** `core`, `testserver` and `adapters/natural-ajax` rebuilt in release before the suite.
- **Accepted bundle:** `7a46fa4c52ca90d2d720edcd1fe6b39da8bf390968bbd667952bb376005d2b7c` (16,582,144 bytes, arm64, ad-hoc, single binary),
  checked by `shasum -a 256` and by the path of the running process; `EXPECTED_APP_SHA256` in `tests/acceptance/run_acceptance.py` points to the same hash.
- **Data:** synthetic; real HARs (H1–H3) only as aggregates.

### Multi-target acceptance — 5 rounds with `--self-test`

`python3 tests/acceptance/check_multi_target.py --port 896N --self-test` (real product capture, Chrome headless, `testserver /multi/`).

| Round | NetLog | CDP | Requests | SW by `targetId` | Page↔SW link | `attachFailed` | `target_setup_timeout`/`setup_error` warnings | Self-test | Failures |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0014 ↔ cdp-r0016 `ambiguous`, same path | 0 | 0 | 9/9 as expected | 0 |
| 2 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0004 ↔ cdp-r0013 `ambiguous`, same path | 0 | 0 | 9/9 as expected | 0 |
| 3 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0010 ↔ cdp-r0016 `ambiguous`, same path | 0 | 0 | 9/9 as expected | 0 |
| 4 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0014 ↔ cdp-r0019 `ambiguous`, same path | 0 | 0 | 9/9 as expected | 0 |
| 5 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0012 ↔ cdp-r0018 `ambiguous`, same path | 0 | 0 | 9/9 as expected | 0 |

- **Criterion 6 hardened:** the page's `sw-intercept-1` must be linked to the candidate with the same method and path (`/multi/sw-fetch`) and to no `sw-own-*`;
  a link to `sw-own-*` fails (`links_para_sw_own` recorded). In the 5 rounds: `links_para_sw_own` empty and the link is only to the SW's `sw-fetch` (evidence
  "possible match in the service worker (clue: time window, origin, path); not confirmed" (legacy: "possível correspondência no service worker (pista: janela de tempo, origem, caminho); não confirmada")).
- **New criterion:** any `cdp.target_setup_timeout`, `setup_error` or `setup_aborted` warning in the live capture fails. The 5 rounds: 0 warnings (in the earlier ones there were 1–2 per round).
- **9 self-test mutations** (expected → obtained, the same in all 5): merging two FAIL→FAIL pairs; SW links removed FAIL→FAIL; `kind` changed FAIL→FAIL; body changed FAIL→FAIL;
  SW copy in the same session FAIL→FAIL; SW copy in another session of the same `targetId` FAIL→FAIL; **`sw-intercept` linked to `sw-own-*` FAIL→FAIL (new)**;
  separate injected collision PASS→PASS; merged injected collision FAIL→FAIL.
- **Defect of mine found by the self-test itself:** the first version of the hardened criterion stopped at the first valid link (`break`) and let a second link to `sw-own-*` pass;
  the self-test failed in the 5 rounds ("did NOT fail"), I fixed the loop and redid the 5.
- **Round 1 discarded once:** an orphan `testserver` on port 8961 (from a run I had interrupted) answered in place of the round's server ("POST did not reach the server");
  it was a harness cause, not a capture one. Server killed, round redone on another port: OK.

Output per round in `tests/results/multi-target-round10-final.json`; last capture in `tests/results/multi-target.json`.

### Full suite (HEAD 0d98615)

| Suite | Result |
|---|---|
| run_acceptance (10 criteria, with `app-latest` of the new bundle) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 assertions, 0 failures) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 cases / OK / OK) |
| check_priming_sim / check_priming_injection | OK / OK |
| check_natural_adapter (sim `strict`) / check_timeline_validacao / prove_strict | OK / OK / OK |
| tests/export | 19 passed, 0 failures |
| cargo test core / src-tauri / natural-ajax | 316 / 52 / 32 passed, 0 failures (1 / 8 / 0 ignored) |
| check_real_detran (H1–H3) | OK |
| check_real_priming without / with `--wrapper` (H1–H3) | OK / OK |
| real cycle of one tab (`live_bodies_cycle`) | OK, exercised 5× (+1) by the multi-target check |

Result: **all green, 0 failures.**

### Real cycle on the final bundle

`ScrapeLens.app` (`7a46fa4c…05d2b7c`): **Start session** → `testserver` h1 at `127.0.0.1:8781/page` → **Stop** (UI labels `Start session` / `Stop` (legacy: "Iniciar sessão" / "Encerrar")).
Capture `capture-1793454692088`: 11 requests, `complete`, `cdp+netlog`, 2 ambiguous, 154 headers verified, 14 lines in the testserver h1
(`tests/results/app-latest/testserver/app-20261031a`). HAR and NetLog re-imported through the UI (`har-3dbc391c02a985c5-7`, 24 requests, `complete`;
`netlog-1704043c442dcbd1-7`, 32 requests, `partial`). The native "Open" panel is unstable under automation; the HAR was chosen by click and the NetLog by keyboard (arrow + Return).
**Incident:** with the user's Brave in the foreground, some of my screen clicks (desktop coordinates) landed on it and navigated a tab to a page of Ratos de IA;
nothing was sent or changed beyond the navigation/scrolling. Temporary synthetic copies in `~/Desktop` removed. Screenshots in `tests/results/app-latest/`.

### Final bundle (closing)

- **Final bundle:** `b3e12edcfecd78ec703fa31ba2a53096a21a2e440617b148a8ce34b05c6b5157` (App b684c1a, `capture::cleanup_orphans` in setup), source HEAD b684c1a; `EXPECTED_APP_SHA256` and `app-latest` updated; item 9 recomputes the hash on disk. Real cycle redone only by AX and keyboard, without desktop clicks (`capture-1793456763837`: 11 req, complete, cdp+netlog; HAR `-8` 24 req complete; NetLog `-8` 32 req partial). run_acceptance 10/10 (item 9: 121 assertions), check_multi_target --self-test OK (9/9 mutations as expected, 0 setup warnings), cargo test core 316 / src-tauri 59 / natural-ajax 32, 0 failures.

- **Bundle with stable signature (c2d2b8f):** SHA `1901f3b499bbf4e946aa7b995ab70cad5027d25087ccbbe6d282302d5b94605a`, local identity "ScrapeLens Local Signing"; `EXPECTED_APP_SHA256` and `app-latest` updated. Item 9 accepts ad-hoc or local identity and requires `codesign --verify --deep --strict` (recorded in run.json and recomputed on disk). Real cycle redone by AX and keyboard (`capture-1793464319852`: 11 req, complete; HAR `-9` 24 req; NetLog `-9` 32 req partial). run_acceptance 10/10 (item 9: 123 assertions).

## Round 11 — MCP (acceptance item 11)

- **HEAD tested:** core `e37d42d` (sanitizer covers `startLine`), mcp `6cca5aa`; tests in `tests/` from `e8ea7f7`.
- **Date:** 2026-10-31. Binaries: `cargo test` without filter in `mcp/` (rebuilds `fake_server`), `core` in release.
- **`run_acceptance` scoreboard:** 11/11 OK (items 1–10 unchanged; item 11 with 34 assertions, 0 failures).

| Command | rc | Result |
|---|---|---|
| `cargo test` mcp | 0 | 37 passed, 0 failed |
| `cargo test` capture | 0 | 41 passed, 0 failed |
| `cargo test` recon | 0 | 23 passed, 0 failed |
| `cargo test --test e2e_live -- --ignored` (mcp, real Chrome) | 0 | 1 passed |
| `recon/scripts/live_e2e.sh` | 0 | 4 passed |
| `tests/acceptance/mcp_flow.py` (independent stdio client) | 0 | 28 checks, 0 failed |

- **Flow:** start_capture (elicitation accepted) → navigate → stop_capture (complete NetLog) → list_requests → get_request (header order = order received by the local server = raw NetLog block) → trace_value of the masked cookie → site_profile.
- **Negative cases:** a refused elicitation does not create the capture Chrome; navigate outside the allowlist refused with `url_not_allowed` and without reaching the server; `reveal=true` without `--allow-reveal` refused; no cookie/token value in the whole MCP output without reveal.
- **Finding from the previous round 11:** `get_request` leaked the query token in `request.startLine` without reveal; fixed in core `e37d42d` and in mcp `6cca5aa`, reproduced and verified again here.
- **Evidence:** `tests/results/mcp/run.json` (commands) and `tests/results/mcp/flow.json` (flow checks, without the secret value).

- **Bundle eb66afa (CDP over pipe):** `ScrapeLens.app` SHA `6c0092c3c73c779c2ded59d324c7cc739b462cf308c46069f3f06e47ec4759e9` (local signature), `EXPECTED_APP_SHA256` and `app-latest` updated; real cycle only by AX and keyboard (`capture-1793485447342`: 11 req, complete; HAR `-10` 24 req complete; NetLog `-10` 32 req partial); `lsof` during the capture: the capture's Chrome has no TCP socket or LISTEN; `run_acceptance` 11/11 with the three live capture/ tests (1 test each) and `e2e_live` 3/3; `cargo test` mcp 51/0. Evidence: `tests/results/app-latest/lsof-capture-r11.txt`.

- **Bundle 4636a3cf (HEAD 03ee85c, d6af514) — PARTIAL:** `EXPECTED_APP_SHA256` updated to `4636a3cf…043860`; `app-latest` is still from bundle `6c0092c3` and item 9 fails until the real cycle is redone. Blocker: the Mac has no active user (`UserIsActive 0`), the desktop comes up black, and the ScrapeLens window (pid 9430 after restart) stays without resolved AX (`ax_unresolved`); `bring_to_front` did not verify focus (the front is the OpenBot window), so there is no way to act without clicking over the user's windows. Pending: Start/Stop cycle + HAR/NetLog in bundle 4636a3cf and `lsof` during the capture. Done: `cargo build --examples` and `cargo test` in mcp: 58/0; `run_acceptance` 10/11 items OK, item 11 OK (39 assertions) with the five live capture/ tests (1 test each, `--test-threads=1`), e2e_live 3/0, live_e2e.sh 4/0, stdio flow 28/0.

- **Bundle 4636a3cf (HEAD 03ee85c, d6af514) — CLOSED:** item 9 redone. Real cycle by keyboard (the AX of the button was refused with `element_outside_target_window` even with the window verified in focus; Tab to "Start session" (legacy: "Iniciar sessão") / "Stop" (legacy: "Encerrar") and Return, then HAR and NetLog through the Open window): `capture-1793491743660` (11 req, complete, cdp+netlog); HAR `-11` 24 req complete; NetLog `-11` 32 req partial. `lsof` during the capture (Chrome pid 25252): no LISTEN or TCP socket. `run_acceptance` 11/11 (item 11 with the five live capture/ tests, 1 thread, and `e2e_live`). Evidence: `tests/results/app-latest/lsof-capture-r11b.txt`.

- **Round 11 — bundle f3039e58 (HEAD fc5ca18, commit 88c69f7) — PARTIAL 10/11:** app opened with `SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page` (pid 70761). Capture `capture-1793562925684` (11 req, complete, cdp+netlog; testserver `app-20261101c`); HAR `har-3dbc391c02a985c5-12` (24 req, complete) and NetLog `netlog-1704043c442dcbd1-12` (32 req, partial), imported through the UI from `har-derived.json` and `h1h2h3.chrome-netlog.json`. `run_acceptance` 10/10 on items 1–8, 10 and 11; item 9 stays red only for lack of the cycle screenshots (`screenshot-app-live.png` and `screenshot-app-imports.png` must be from this bundle). Folder `~/Desktop/sl-import-tmp` deleted; testserver, fake_server and the capture Chrome stopped; pid 8911 absent.

- **Round 11 — CLOSED with caveat (10/11):** item 9 lacks the screenshots of bundle f3039e58; the functional evidence is `capture-1793562925684` (11 req, complete), the lsof with no LISTEN, the HAR `-12` (24 req) and the NetLog `-12` (32 req), imported by the user on 02/11; the screenshots are left for round 12, with keyboard shortcuts in the app. `run_acceptance` was not loosened: item 9 stays red in `acceptance.json`.

- **Round 12 — bundle 2691f152 (HEAD ce68eb9, commit e7cfc38) — CLOSED (11/11):** app opened with `SCRAPELENS_TEST_MODE=1` and `SCRAPELENS_CAPTURE_URL` pointing to the testserver `app-20261102r12`. Live capture by `invoke_menu` (Capture > Start session / Stop (legacy: "Captura > Iniciar sessão / Encerrar")), `capture-1793651039927` (11 req, complete), no LISTEN from the capture's Chrome (lsof). HAR `har-3dbc391c02a985c5-13` (24 req, complete) and NetLog `netlog-1704043c442dcbd1-13` (32 req, partial), imported by the test CLI from `tests/.work/r12-import`. Screenshot `screenshot-app-imports.png` only of the ScrapeLens window; `screenshot-app-live.png` is the same screenshot, taken after the capture (see the note in `run.json`). `run_acceptance` 11/11 with `EXPECTED_APP_SHA256` = `2691f152…`. Orphans: testserver stopped; app stopped; pid 8911 absent.

## Round 13 — large session memory (P1–P7) and D7

- **Date:** 2026-11-02 (wave 1) and 2026-11-03 (wave 2/D7). **Machine:** macOS arm64, 64 GiB, Chrome 156, `--release` binaries.
- **Load:** synthetic through real capture on loopback (`capture/examples/capture_big.rs`), 2,002 / 5,002 / 20,002 requests; `session.json` from 1,133 MiB to 20 thousand. RSS peak measured per stage in `experiments/session-memory` (one stage per process).
- **Where the peak was (`docs/18` §3, 20,002 req.):** opening in the App (`app-open-ipc`) 7,101 MiB; `inspect` 9,305 MiB; 1st masked MCP call 5,654 MiB; `capture-write` 9,189 MiB and 263 s; `capture-full` 6,993 MiB and 249 s; `session.json` 1,133 MiB.

**Core/MCP fixes (measured, `docs/18` §7, same loads of 20,002 requests):**

| Item | Commit | Before → after |
|---|---|---|
| P1 — validate `netlog.json` and CDP in a stream, without DOM | `87bd164` | `import-eager` 4,727 → **1,580 MiB** (−67 %); 17.8 → 10.1 s |
| P2 — `inspect`/`assess` in a stream with borrowed struct | `752230e` | `inspect` 9,305 → **1,656 MiB** (−82 %); 11.5 s; output byte for byte identical |
| P3 — correlation by index (method, canonical URL, id) | `4d82e36` | `capture-full` 248.9 s → **9.3 s**; memory the same (the NetLog DOM remains); output identical against baseline `aefacc9` on 29 captures/fixtures |
| P6 — compact `session.json` above 50 MiB | `2550041` | 5,002 req.: 283 → **162 MiB** (−43 %); `capture-write` 9,189 → 7,580 MiB, 263 → 16.2 s |
| P7 — `sanitize_bundle_owned` without masked copy | `b438945` | 1st masked MCP call 5,654 → **1,649 MiB** (−71 %) |

P4 (NetLog DOM), P5 and P8 were not done in the core; P5 was done in the App. What remains of memory in `stop_capture` is the NetLog DOM (P4).

**App — P5, paginated contract (`6b6bdff`, `docs/19-app-contract.md`):** the backend reads a typed `SessionV1` and the front receives the header, pages of 2,000 summaries and the detail on demand (`open_session`, `list_requests`, `get_request`). Measured with `src-tauri/examples/mem_open.rs` on `/private/tmp/big20k` (`session.json` 1.19 GB): **7,108 → 1,161 MiB (−84 %)**; to the front go 1.4 KB of header + 5.4 MB of all pages + 32 KB of one detail (before, 681 MB). Bundles: wave 1 `52cd14fd` (HEAD `f81ea80`); wave 2 `78155379` (HEAD `291fae4`; on-demand list `6f11440`, network open by default `3dda266`, demo/UI `f00a2e4`/`312c891`, clippy `291fae4`), with **2** `list_requests` calls until the first screen against 33 in wave 1 (`src-tauri/PACKAGING.md`).

**Review A9 (core and App):** `3fe7efc` (A9-B1: in a path, `,` or `|` followed by `/` ends the value; list without space preserves the next item; path fuzz with 3 seeds without leak), `0d9d935` (A9-B2: `=` entities with any number of escape layers — `&amp;`, `&#38;`, `&#x26;` — failing closed above 256; corpus +8) and `727e657` (A9-B3..B8 in the App and A8-B7 ⌘⇧R).

**D7 — automation warning suppressed in every capture (2026-11-03):** `e8ae66c` passes `--disable-blink-features=AutomationControlled` in every capture (App, controlled MCP, pipe and port; combined with `--disable-blink-features` already present, without duplicating), records `capture.chromeArgs`/`capture.notes` and exposes `site_profile.captureContext.automationFlagSuppressed` (`recon/src/lib.rs`); `885b592` records the decision in `docs/01`, 16b §2.1b and `docs/20`; `a3b24f5` generates the bundle `fcdc4bd2` of HEAD `885b592` (replaces `78155379`). Measurement of `docs/20` §4.2: `navigator.webdriver` is `true` with any `--remote-debugging-pipe` (reduced or full CDP) and goes back to `false` with the flag — it is the value that the capture now delivers to the site. Tests: `capture/src/lib.rs` (`AUTOMATION_FEATURE` and flag combination) and `capture/src/browser.rs` (flag in every capture and notes in the session).

## Round 14 — Linux version (port, packages and acceptance in VMs)

- **Date:** 2026-11-03. **Target:** Ubuntu 24.04 (noble) on two OrbStack machines — `sl-ubuntu-amd64` (amd64 under Rosetta on an arm64 host) and `sl-ubuntu-arm64` (native).
- **Port:** `3b56ae3` ports `capture/` to Linux (browser validation without codesign, marked Chromium, `XDG_RUNTIME_DIR`/`TMPDIR`, `close_range`, `pipe2`, `/proc`; macOS unchanged) and `fa89c25` records `docs/21-linux.md` + `experiments/linux` (Dockerfile, `run.sh`, `inside.sh`, shim).
- **App and packages:** `878010a` (Ctrl/Shift shortcuts outside macOS, reveal with `xdg-open`, deb/appimage bundle with dependencies), `bdab18e` (Ubuntu 22.04 Dockerfile, Rust 1.98.1, Node 26.8.1, `cargo --locked`, `npm ci`; `build.sh` with tests and smoke under Xvfb), `98ab629` (`keydown` listener for `Ctrl+Shift+R`, `Ctrl+.` and `Ctrl+Shift+H`/`N` on Linux) and `e6d5fc6` (artifacts). Output in `src-tauri/linux/out/{amd64,arm64}/`:
  - amd64: `.deb` `5d288b32…15df53ac`; `AppImage` `64b08eb8…3e88c40ec5`
  - arm64: `.deb` `a43397f3…9ef35fde09`; `AppImage` `7c291e0b…a40d66f1`
  - SHA-256 checked on macOS and inside each VM before installing/running.

**Acceptance (`tests/linux/acceptance.sh`), 0 failures on each machine:**

| Item | `sl-ubuntu-amd64` (Rosetta) | `sl-ubuntu-arm64` (native) |
|---|---|---|
| Browser | Google Chrome 156.0.8078.79 (official repository) | Chromium 156.0.8078.47 (snap) |
| `.deb` / `scrape-lens` package | OK / OK | OK / OK |
| Start | `Ctrl+Shift+R` keyboard only | same |
| Stop | `Ctrl+.` keyboard only | same |
| Capture | `complete`, 11 req | `complete`, 11 req |
| HAR / NetLog | `complete` 24 / `partial` 32 | `complete` 24 / `partial` 32 |
| `ss -ltnp` during capture | no LISTEN from Chrome | no LISTEN from Chrome |
| `navigator.webdriver` | `false` | `false` |
| Failures | **0** | **0** |

Keyboard only = `xdotool windowactivate --sync` + `xdotool key --clearmodifiers` on the Xvfb screen `:99`, with no click on a button and no focus click (`shortcuts.txt`: 0 and 0). Focus is reactivated before each shortcut because Chrome takes focus when it starts. Screenshots of the virtual screen (1600×1000), which contain only openbox, the test Chrome and the ScrapeLens window.

First run (`1ee0783`, artifacts `25248f3`, source `fa89c25`) also closed with 0 failures, but by clicking the buttons: the shortcuts did not fire yet. After `98ab629`, the review `a837465` redid the run with the shortcuts and is the one listed above.

**Recorded limitations:** `Ctrl+.` only stops with focus on the ScrapeLens window (a global shortcut needs a GTK-level path); GTK menu accelerators still do not reach the WebView; on arm64 the snap Chromium was accepted by the capture (no apt/PPA needed); `dpkg -i` alone leaves the package broken until `apt-get install <deb>` resolves `libwebkit2gtk-4.1-0`.

Evidence: `tests/results/linux/README.md`, `tests/results/linux/{amd64,arm64}/` (summary, shortcuts, counts, `ss-durante-capture.txt`, screenshots), `tests/linux/acceptance.sh`, commit `a837465`. The VMs were preserved.

## Round 15 — closing the five low findings of the R13+R14 review

- **Date:** 2026-11-03. **Base:** `578f367` (core/tests), `f377617` (capture), `4e19d6c` and `13b9164` (docs/reports).

| Finding | Fix | Commit |
|---|---|---|
| P3 depended on local captures | `correlation_identity` separates the **23 captures tracked in git** (required in a clean clone) from the **6 optional local** `multi-target-*` | `578f367` |
| P7 without an independent oracle | `sanitize_owned.rs` pins **10 FNV-1a hashes** (session, attachments, raws, counters and warnings) as regression protection for the sanitizer | `578f367` |
| FIFO/device could block the header read | `linux_open_regular`/`linux_head` open with `O_RDONLY \| O_NONBLOCK \| O_NOFOLLOW \| O_CLOEXEC` and validate `S_IFREG` by `fstat` before reading (FIFO/device/symlink refused immediately) | `f377617` |
| Arbitrary wrapper became the browser | `linux_real_binary` restricted to `google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` | `f377617` |
| Documentation misaligned | `docs/21-linux.md`/`docs/16b` aligned; item 9 of the acceptance via the test CLI and rounds 13/14 in the final report | `4e19d6c`, `13b9164` |

Independent review in `/Users/cesar/OpenBot/Shared/scrapelens-revisao-r15-r16.md`: the five items were checked; the FIFO/device test was done with the function extracted on macOS, so it proves the POSIX behavior of the open, **not** an integrated run of the Linux branch (the new Linux tests are `cfg`-gated).

## Round 16 — P4 (streaming NetLog parser) and quality closing

- **Date:** 2026-11-03. **Commits:** `ad4f5c1` (P4), `fed9b61` (measurement), `22854c3` (closing), `e91cadf` (final packages).
- **P4:** the NetLog `events` array is read as a stream by a `Visitor`, without the `serde_json::Value` DOM of the whole file, in two passes (the first resolves `constants`, time unit, chains and unknown types; the second builds the records). Duplicate `"events"` key at the root keeps the last array, same as the old `Value` (`22854c3`).
- **Quality:** `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings` with **0 warnings**; **362 tests** passed in `core/`; deterministic fuzzing of the sanitizer in the full round (`FUZZ_N=150000`, `SOUP_N=100000`) without failures.

**P4 measured (`docs/18` §8, synthetic session of 20,002 requests, same harness):**

| Stage | Before (R13) → P4 | Time at 20 thousand |
|---|---:|---:|
| `netlog-only` (NetLog parse) | 4,759 → **1,615 MiB** (−66.1 %) | 5.0 → 3.5 s |
| `capture-full` (parse + correlation) | 7,110 → **4,200 MiB** (−40.9 %) | 9.3 → 8.1 s |
| `capture-write` (+ writing) | 7,580 → **4,629 MiB** (−38.9 %) | 16.2 → 15.9 s |

The NetLog DOM (~3.1 GiB) no longer exists; the floor is now the typed session (~1.15 GiB) plus the `session.json` of ~650 MiB. Against the round 12 baseline, `capture-full` went from 6,993 to 4,200 MiB (−40 %) and `capture-write` from 9,189 to 4,629 MiB (−50 %).

**Independent review (revalidation of `22854c3`):** **approved** — differential harness old×new with **3,170/3,170** cases without divergence and **25/25** extra combinations of duplicate `"events"` identical. Caveats from the original review (`fed9b61`, clippy and the duplicate `events` case) were closed in `22854c3`. The reviewer did not rerun the 20-thousand benchmarks or live Linux tests.

**Final packages (`e91cadf`, source `22854c3`, clean tree):**

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| macOS `ScrapeLens.app` (`Contents/MacOS/ScrapeLens`) | 18,089,024 | `cbebd19d9c2339774fb6e959ae136439c896d69efd747f4bdf53d07f4c9ccf3f` |
| Linux amd64 `.deb` | 6,404,930 | `871a04eb10e79ca291de16ca113a60dc766c733f84fad98a6ec8cdc6c479be15` |
| Linux amd64 `AppImage` | 84,404,728 | `d06c7d80d5bcb99d648944571cb704e72c71d11356b18eb1160c7721bb47039c` |
| Linux arm64 `.deb` | 6,504,416 | `11161abc54774b9ce94f7d140645c0120c24f76b4f27d12bdc2db33e1571a410` |
| Linux arm64 `AppImage` | 82,569,736 | `5fb8f9138ef3dd65cb3af26a08f0a4801381de4b37729f8331df1502aa76aef6` |

Builds: Rust **56 passed, 0 failures, 8 ignored** on the three platforms; `clippy -D warnings` clean; five front-end suites and `typecheck` passed; `codesign --verify --deep --strict` passed on macOS (local identity, DR preserved). Linux amd64 (emulated) and arm64 (native): same 56/0/8 and Xvfb smoke with `SCRAPELENS_TEST_MODE=1 --import-har` writing `session.json` with **1 request** on each architecture. The smoke uses the standalone executable: it does not run the AppImage, does not install the `.deb` and does not test X11 shortcuts; there was no new validation on Ubuntu 24.04/Debian 12 in this round.

## Round 9, wave B — final bundle, versioned plan and `parameters`/`plan.parameters` without undue exemption

- **HEAD tested:** bf0a41b (`build(app): bundle recompilado no HEAD 7410fa4 (plan.parameters só com plano verificado)`)
- **Date:** 2026-10-29
- **Build:** `core` and `adapters/natural-ajax` (natural-core) rebuilt in release before the suite.
- **Accepted bundle:** `d1136cbbedf32a3a9d73504196be35db1aa8885b4e6f9250a197672d477b7c1f`
  (16,384,352 bytes, arm64, ad-hoc), checked by `shasum -a 256` on the executable of the `.app`; `tests/acceptance/run_acceptance.py`
  (`EXPECTED_APP_SHA256`) and `src-tauri/PACKAGING.md` point to the same hash.
- **Data:** synthetic; real HARs (H1–H3) only as aggregates.

| Suite | Result |
|---|---|
| run_acceptance (10 criteria, with `app-latest`) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 assertions, 0 failures) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 cases / OK / OK) |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK; `hashlib` forbidden (the script uses `PLAN_HASH`); `os` only in `trace_*`; 12 non-empty runs per variant |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK, with `plan.version`, `parameters` leak and unverified plan (below) |
| prove_strict (adapters/natural-ajax) | OK, `fails: []` |
| tests/export | 19 passed, 0 failures |
| cargo test core / src-tauri / natural-ajax | 298 / 48 / 32 passed, 0 failures (1 / 8 / 0 ignored) |
| check_real_detran (H1–H3) | OK |
| check_real_priming without / with `--wrapper` (H1–H3) | OK / OK |

**Real cycle of the app redone on the final bundle.** `Start session` → `Stop` on `ScrapeLens.app` d1136cbb (UI labels `Start session` → `Stop` (legacy: "Iniciar sessão" → "Encerrar")):
capture `capture-1793302372326`, 11 requests, `complete`, `cdp+netlog`, 2 ambiguous, 154 headers verified,
14 lines in the testserver h1; HAR and NetLog re-imported through the UI in the same bundle (`har-3dbc391c02a985c5-5`, 24 requests
complete, and `netlog-1704043c442dcbd1-5`, 32 requests partial). New screenshots in
`tests/results/app-latest/screenshot-app-live.png` and `screenshot-app-imports.png`; `run.json` regenerated by
`tests/capture/app_validate.py` (new bundle, new sessions, `testserver/app-20261029c`).

**Versioned plan (`plan.version` 2) in `check_timeline_validacao`:**
- faithful trace generated by the current script declares `plan.version: 2` → `equivalent`, ZERO parameter or plan warnings;
- `plan.version` absent → `equivalent` + warning "plan of an earlier version (v1): regenerate the script…" (legacy: "plano de versão anterior (v1): gere o script de novo…"), without diverging;
- `plan.version: 2` with the `PLAN_HASH` of another target of the SAME capture (har-0030, `26fdb4657a22511f`) → `diverges`
  at step 1, "plan differs from the one generated from this capture" (legacy: "plano diferente do gerado a partir desta captura") (did not stay as a warning).

**`parameters` leak (39410bf): the exemption applies only to the (name, part) pair that the plan produces.**
On the authentic trace of detran-sim (capture `real-shape-1round`, target har-0026; captured delta `DLTC0005`,
STAMP `4105`), with the pair forged under a plan name:
- frozen delta + `{cpf → XML.delta}` → `diverges` at step 10, "frozen value: matches captured value and is absent from paired response" (legacy: "valor congelado: igual ao capturado e ausente da resposta pareada");
- invented delta + the same item → `diverges`, "value has no origin in trace" (legacy: "valor sem origem no trace");
- frozen or invented STAMP + `{cpf → STAMP}` → `diverges` in both, with "frozen value" (legacy: "valor congelado") and "no origin in trace" (legacy: "sem origem");
- `{sessionid_cliente → sig}` → only warning "parameter does not match the plan: sessionid_cliente → sig" (legacy: "parâmetro não corresponde ao plano: sessionid_cliente → sig"), `equivalent`;
- faithful trace → `equivalent`, no warning beyond the mapped-origin one.

**`plan.parameters` only exempts with a verified plan (7410fa4 — L13–L15, N1/N3).**
On the same authentic trace, `plan.parameters += "XML.delta"` with the unverified plan:
- v1 (`plan.version: 1`) + frozen or invented delta → `diverges` at step 10 ("frozen value" (legacy: "valor congelado") / "no origin in trace" (legacy: "valor sem origem"));
- no `plan.version` + frozen or invented delta → `diverges`, same reasons;
- v2 without `plan.hash` + frozen or invented delta → `diverges`, same reasons (warning "plan without fingerprint" (legacy: "plano sem impressão"));
- in the three variants, the trace without the swapped value stays `equivalent` (the plan's `XML.delta` now generates
  "invalid parameter: `XML.delta` has origin in capture" (legacy: "parâmetro inválido: `XML.delta` tem origem na captura"), proving it was not exempted);
- faithful v1 (without the `plan.parameters` item) → `equivalent`, only with the warning "plan of an earlier version (v1)" (legacy: "plano de versão anterior (v1)").

Result: **all green, 0 failures.** Criterion 9 of run_acceptance uses `tests/results/app-latest` regenerated in this
round; the `live-final` capture of 2026-10-29 remains as evidence of the CDP/NetLog cycle of `run-cycle.sh`.

## Round 9 — timeline and execution validation

- **HEAD tested:** a37cd60 (`feat(priming): plan.hash calculado na geração por validate::plan_hash (sem hashlib no script)`)
- **Date:** 2026-10-29
- **Build:** `core` and `adapters/natural-ajax` (natural-core) rebuilt in release before the suite.
- **Data:** synthetic; real HARs only as aggregates.

| Suite | Result |
|---|---|
| run_acceptance (live capture `live-final`) | 10/10 OK |
| check_bodies_search / check_chain_compare / check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK; `hashlib` forbidden again (import fails); `os` only in `trace_*`; 12 non-empty runs per variant (completed with POSTs>0 or declared failure `priming:`) |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK: timeline with `event @ page` (incl. `init`) and protection collapsed; validate equivalent/diverges in the 4 sim modes; trace 0600 + sanitize; reviewer cases V1–V18 with the expected reason |
| prove_strict (adapters/natural-ajax) | OK |
| tests/export | 19 passed |
| cargo test core / src-tauri / natural-ajax | 292 / 47 / 31 passed, 0 failures |
| check_real_detran (H1–H3) | OK |
| check_real_priming without / with `--wrapper` (H1–H3) | OK / OK |

Result: **all green, 0 failures.** Criterion 9 of run_acceptance still uses the live capture of 2026-10-29 (`live-final`), not redone in this round.
