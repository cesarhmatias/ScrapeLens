# Linux validation (round 14)

OrbStack machines (`orb`), Ubuntu 24.04 (noble). Everything runs inside the machines;
nothing is installed on macOS and no click is made in the user's windows.

| Machine | Architecture | Execution | Capture browser |
|---|---|---|---|
| `sl-ubuntu-amd64` | amd64 (`--arch amd64`) | **Rosetta** (arm64 host translates x86_64) | Google Chrome stable (Google's official repository) |
| `sl-ubuntu-arm64` | arm64 | **native** (aarch64) | Chromium (Google does not publish Chrome for Linux arm64) |

Always record which result came from Rosetta and which from native execution:
the script's output folder has `host:` and `execution type:` in its first lines.

## Setup (already done)
1. `orbctl create -a amd64 ubuntu:24.04 sl-ubuntu-amd64` and `orbctl create -a arm64 ubuntu:24.04 sl-ubuntu-arm64`.
2. Run `tests/linux/setup-vm.sh` inside each machine (Xvfb, openbox, xdotool, scrot/imagemagick,
   Chrome or Chromium). Local logs in `tests/.work/linux/` (git-ignored).
   Run: `orb -m <machine> bash -s < tests/linux/setup-vm.sh`.

## Artifacts
- `.deb` and AppImage in `src-tauri/linux/out/` (read-only; copied to `~/artifacts-r14b/` on the machine,
  with SHA-256 checked on both sides before running).
- `scrapelens-testserver` binary compiled for Linux (built inside the machine from `testserver/`),
  in `~/scrapelens/testserver/target/release/`.
- Import fixtures in `~/fixtures-r14/`: `har-derived.json` and `h1h2h3.chrome-netlog.json`.

## Script
`tests/linux/acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]`
1. Installs the `.deb` for the machine's architecture (amd64 and arm64) and confirms the installed package.
2. Starts the testserver on 127.0.0.1:8781 (`/page`).
3. Opens the AppImage with `SCRAPELENS_TEST_MODE=1`, `SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page`,
   `SCRAPELENS_CAPTURE_NETWORK=loopback`.
4. Start and Stop through the app's **keyboard shortcuts**, sent with `xdotool key --clearmodifiers`
   (XTEST) on the virtual screen `:99`, with the main window focused by `xdotool windowactivate --sync`:
   `ctrl+shift+r` (Start session) and `ctrl+period` (Stop). Focus must be re-activated before each
   shortcut, because when the capture starts the focus moves to the Chrome window. The buttons (1044,178) and (1138,178)
   are not clicked in any step; if the key does not reach the WebView, the script retries with a single neutral click at (700,900) — an empty area, far from any control — only to give focus, and records the case in `shortcuts.txt`.
   During capture: `ss -ltnp` and confirmation that no LISTEN socket belongs to the capture Chrome.
5. Checks the session on disk (`~/.local/share/app.scrapelens.desktop/sessions`).
6. Imports with `--import-har` and `--import-netlog` through the test CLI.
7. Checks the counts: HAR complete 24, NetLog partial 32.
8. `navigator.webdriver`: capture with the probe page `tests/linux/probe_server.py` (loopback);
   the recorded value must be `false`.
9. Window screenshots (`import -window`), saved in the output folder.

Output: `~/sl-acceptance-<arch>-<timestamp>/summary.txt` on the machine; `FAILURES=0` when everything passes.

## Known limits
- The script sends keys via `xdotool` on the machine's virtual screen (nothing on macOS). Shortcuts only work
  with focus on the WebView; that is why each shortcut is preceded by `windowactivate --sync`. The neutral focus click
  at (700,900) is the last resort and is recorded in `shortcuts.txt`.
- The app window only appears with a usable area ≥ 100 px a few seconds after launch; the wait is for the
  real window (not the 10x10 `InputOnly` helper), up to 60 s.
- X reports the app's client window as 10x10 (the openbox frame has no geometry of its own),
  so the screenshots are of the whole virtual screen (1600x1000), which contains only openbox and the app windows.
- The capture uses CDP over a pipe (no TCP port), so `navigator.webdriver` is read by the probe page
  and not by CDP in the browser.
- This README does not record results: they go to `tests/REPORT-FINAL.md` when the suite runs.
