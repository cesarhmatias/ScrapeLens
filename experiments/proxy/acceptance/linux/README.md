# experiments/proxy/acceptance/linux/ — the packaged App with a proxy (Linux)

Drives a packaged ScrapeLens (`.deb` or AppImage) in a container under Xvfb, with no user window:
it types the proxy link into the Proxy field, starts a capture, stops it, opens **Export /
Sanitize…**, and keeps screenshots, the app data and the logs. The origin and the test proxy run
on this machine (`testserver/`), with synthetic credentials and `--resolve site-a.test=127.0.0.1`.

| File | What it is |
|---|---|
| `run-app-proxy.sh` | Host side: starts the origin and the test proxy, builds the image for the package, runs the container |
| `in-container.sh` | Container side: launches the App under Xvfb and drives it with xdotool |

```sh
# arch: amd64 or arm64; mode: ok (right password) or wrong (refused)
sh run-app-proxy.sh amd64 /path/ScrapeLens_0.1.2_amd64.deb /durable/folder/amd64-deb-ok ok
```

Requirements: Docker, the image `sl-cookie-import:<arch>-chrome` (see `experiments/linux/cookie-import/`),
and the testserver built. The output folder must be outside the repository.

Checks made on the outputs (see `RESULTS.md`): `app-data/sessions/*/session.json` has `capture.proxy`
(`authenticated: true`, `route: relay`) and no credential; the proxy evidence has the relayed
connections; the notice `relay peer check: N connections … refused 0` is in the session; the
screenshots show the header line and the Proxy field; the password, its percent-encoded form and
their Base64 are searched in every non-image file.
