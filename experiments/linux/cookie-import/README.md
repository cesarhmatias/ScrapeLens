# Cookie import: end-to-end check on a desktop-like Linux user

Checks the browser cookie import (`capture/src/cookies.rs`) through the packaged App,
the way a user runs it: a Chromium profile with a real cookie under the Secret Service
(gnome-keyring), the App's preferences that select that profile, the App's own start
shortcut, and a loopback page server that records the `Cookie` header it receives.

## What it proves

- The image has no `sqlite3` command and no `libsecret-tools` package (a default desktop).
- The App imports the cookie from the Chromium profile (`v11` key from the keyring).
- The page receives `sid=…` on its first navigation.
- The session records `Capture.cookiesImported` with `importedCount: 1`.

## Browsers and keyring states

- `BROWSER=chromium|chrome|edge|brave|firefox` (default `chromium`): the browser that makes the
  cookie. Chromium-family browsers store it under the Secret Service; Firefox stores it in
  `cookies.sqlite`. Non-Chrome images also install Google Chrome, which the App captures with.
  Brave comes from its apt repository (`brave-browser`, profile under
  `.config/BraveSoftware/Brave-Browser`, cookie source `brave:Default`).
- `KEYRING=unlocked|locked|absent` (default `unlocked`): the keyring state when the App starts.
  `locked` restarts gnome-keyring without its password; `absent` runs the App without a D-Bus
  session. Both should show the real keyring error in the App, not a timeout.

## Run

    experiments/linux/cookie-import/run.sh linux/arm64 path/to/ScrapeLens_0.1.0_arm64.deb out/arm64-deb
    BROWSER=firefox experiments/linux/cookie-import/run.sh linux/amd64 path/to/ScrapeLens_0.1.0_amd64.AppImage out/ff
    BROWSER=chrome KEYRING=locked experiments/linux/cookie-import/run.sh linux/amd64 path/to/ScrapeLens_0.1.0_amd64.deb out/locked

Use `linux/amd64` for the amd64 packages. The `out` directory receives `e2e-raw.txt`
(the report), `after-start.png` and `end.png` (screenshots of the App), `srv.log` and
`app.log`. The App runs in a private HOME; no real browser profile or cookie is read.

## Expected report

    cookie sid prefix: b'v11'
    app-running: yes …
    … "/" with cookie=sid=…
    cookiesImported … "importedCount":1,"skippedCount":0

The run needs Docker, and `--security-opt seccomp=unconfined` so Chromium's sandbox can start
in the container. Use the `--platform` that matches the package's architecture.
