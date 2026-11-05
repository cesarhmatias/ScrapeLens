# Round 14 — Linux validation (ScrapeLens)

Artifacts: `src-tauri/linux/out/` (commit `e6d5fc6`, source `98ab629`). SHA-256 checked on macOS and
inside each machine before running:
- amd64: `ScrapeLens_0.1.0_amd64.deb` `5d288b32…15df53ac`; `ScrapeLens_0.1.0_amd64.AppImage` `64b08eb8…3e88c40ec5`
- arm64: `ScrapeLens_0.1.0_arm64.deb` `a43397f3…9ef35fde09`; `ScrapeLens_0.1.0_aarch64.AppImage` `7c291e0b…a40d66f1`

## Final scoreboard (script `tests/linux/acceptance.sh`, review with keyboard shortcuts)

| Machine | Run | Browser | Failures | Start | Stop | Capture | HAR | NetLog | `navigator.webdriver` | Chrome LISTEN |
|---|---|---|---|---|---|---|---|---|---|---|
| `sl-ubuntu-amd64` (x86_64) | **ROSETTA** (arm64 host) | Google Chrome 156.0.8078.79 (official repository) | **0** | `Ctrl+Shift+R`, keyboard only | `Ctrl+.`, keyboard only | complete, 11 req | complete, 24 | partial, 32 | `false` | none (`ss -ltnp` without the Chrome pid) |
| `sl-ubuntu-arm64` (aarch64) | **NATIVE** | Chromium 156.0.8078.47 (snap) | **0** | `Ctrl+Shift+R`, keyboard only | `Ctrl+.`, keyboard only | complete, 11 req | complete, 24 | partial, 32 | `false` | none (`ss -ltnp` without the Chrome pid) |

Folder of each run: `amd64/` and `arm64/` (summary.txt, shortcuts.txt, counts.txt,
ss-durante-capture.txt, print-capture.png, print-final.png, probe.jsonl, logs).

## Keyboard shortcuts (what this review proves)

- Start and Stop fired with **keyboard only**: `xdotool windowactivate --sync` on the main window
  and `xdotool key --clearmodifiers`, with no click on a button and no neutral focus click
  (`shortcuts.txt`: `cliques em coordenadas de botão …: 0`, `cliques neutros de foco …: 0`).
- On both machines and in both captures of the script (the main one and the `navigator.webdriver` probe).
- Focus must be reactivated before each shortcut: when the capture starts, the X focus moves to the
  Chrome window. Without `windowactivate`, `Ctrl+.` goes to Chrome and stops nothing — this is what happened in the
  manual check that prompted this review.
- Virtual display `:99` (Xvfb 1600x1000 + openbox) inside the VM; no key or click on macOS.

Script steps (all `OK` on both): install the `.deb`; `scrape-lens` package installed; testserver
answers `/page`; ScrapeLens window; Start via shortcut; no LISTEN from the capture's Chrome;
screenshot during the capture; Stop via shortcut; session on disk with 11 requests; imports
`--import-har` and `--import-netlog`; HAR complete 24; NetLog partial 32; `navigator.webdriver === false`;
no clicks on buttons; start and stop shortcuts confirmed.

## How it was measured
- **Rosetta vs native:** amd64 runs under Rosetta (uname x86_64 on an arm64 host); arm64 runs natively (aarch64).
  The results come from different machines and are not mixed.
- **Start and end of capture:** WebView shortcuts (`ctrl+shift+r`, `ctrl+period`) via XTEST. The script
  identifies the app's real window (largest area), not the 10x10 `InputOnly` helper that is also called
  "ScrapeLens".
- **`ss -ltnp` during the capture:** the only listening port is the testserver's (127.0.0.1:8781), from the
  script itself; on arm64 `:631` (system cups) also appears. No listening socket belongs to the capture's Chrome.
- **`navigator.webdriver`:** read by `tests/linux/probe_server.py`, a page at 127.0.0.1:8791 that sends the
  value to the server itself. The capture uses CDP over a pipe, so there is no debugging port to query.
- **Screenshots:** the whole virtual screen (1600x1000), because X reports the client window as 10x10 (the
  openbox frame has no geometry of its own). The screen contains only openbox and the app windows (test Chrome and
  the ScrapeLens window).

## History
1. Original round 14 (artifacts `25248f3`, source `fa89c25`): shortcuts `Ctrl+Shift+R` / `Ctrl+.` did not
   start or stop; the script used clicks on the buttons and closed with 0 failures on both machines.
2. The app fixed the `keydown` listener for Linux (`98ab629`) and regenerated the packages (`e6d5fc6`).
3. This review: shortcuts redone in the script and **both fire**. Two run observations:
   the initial screenshot can come out black if taken before the WebView paints (the wait is now for the
   real window, not the 10x10 helper); and `Ctrl+.` only works with ScrapeLens focused, because Chrome takes
   focus when it opens.
4. Earlier runs: imports take ~16 s to write `session.json` (wait up to 60 s); `import -window`
   hung on a stale window (the screenshot is now of the whole screen); on amd64 there was one start failure from a
   window not yet ready (20 s wait + 3 attempts).

## Product observations (for the App)
- `Ctrl+Shift+R` and `Ctrl+.` work on Linux through the WebView listener, but **only with focus on the app window**.
  When the capture starts, Chrome takes focus; the user has to click the ScrapeLens window (or use the
  Stop button) before `Ctrl+.`. For a global `Ctrl+.`, a GTK/window-level shortcut is missing.
- Menu shortcuts declared as GTK accelerators still do not reach the WebView.
- Chromium via snap on arm64 works for the capture (accepted; no PPA or apt needed).
- The `scrape-lens` package depends on `libwebkit2gtk-4.1-0`; `dpkg -i` alone leaves the package broken until
  `apt-get install <deb>` resolves the dependencies.

## Machines
- `sl-ubuntu-amd64` (192.168.139.105) and `sl-ubuntu-arm64` (192.168.139.230): running, **not deleted**.
- Inside the machines, Xvfb `:99` and openbox (virtual desktop) are left running, by choice of the script; no app,
  capture Chrome, testserver or probe was left running after the run.
- New artifacts copied to `~/artifacts-r14b/` on both machines.
