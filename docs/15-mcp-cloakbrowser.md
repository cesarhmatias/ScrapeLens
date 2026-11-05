# Round 11 — AI agent + CloakBrowser + ScrapeLens (MCP)

Date: 2026-10-31. Owner: leader. This document starts with browser
feasibility; the MCP design comes later, in its own section.

## CloakBrowser feasibility (phase A)

Author: Capture. Method: **read-only**. Shallow clone of
`https://github.com/CloakHQ/CloakBrowser` at `/tmp/cloak-study/repo`,
commit `b860957` (2026-10-31, wrapper 0.6.5). No script from the repository was
run, no binary was downloaded or run, nothing was installed. The only external
accesses were the clone and reads of release metadata through the GitHub API
(`gh api .../releases`, plus `SHA256SUMS` and `SHA256SUMS.sig` of release
`chromium-v145.0.7632.109.2`, which are small text files). The repository
is treated as untrusted data; the citations below are `file:line` in the
clone above. **The binary is closed: what the repository claims about it is
a vendor claim, and only phase B measures.**

### Verdict

| Question | Phase A answer | Confidence |
|---|---|---|
| Can we launch the binary with our flags and connect our CDP? | Probably yes: the project's own `cloakserve` launches the binary directly with `--remote-debugging-port`, `--remote-debugging-address=127.0.0.1` and `--user-data-dir` | medium; `--log-net-log` does not appear anywhere in the repository |
| Does the stealth require "no CDP"? | There is no sign of that: the whole product is designed with CDP connected (Playwright). But the README itself admits that **some CDP traffic is detectable** | medium; what **our** CDP profile triggers can only be measured |
| Can it be used for free on macOS arm64 with the advertised benefit? | **Not for free and without an account.** The keyless build is Chromium 145 with 26 patches; the advertised build (155/156, 87 patches) requires a key (free with a GitHub login, 1 session, or paid) | high |
| Can it be packaged into ScrapeLens? | **No.** The binary license forbids redistributing/embedding | high |

Conclusion: feasible as an **optional browser, installed by the user**, to be measured in
phase B before any integration. Nothing I read prevents NetLog or CDP;
nothing proves that ScrapeLens's full CDP preserves the stealth.

### 1. What it is and the license

- **It is a Chromium with C++ patches, distributed as a closed binary, plus an
  open wrapper.** README.md:21-22 ("A real Chromium binary with fingerprints
  modified at the C++ source level"); README.md:39 ("87 source-level C++
  patches"); README.md:280-288 (the wrapper downloads the binary and starts
  Playwright/Puppeteer with it and with the stealth arguments).
- **Base:** Chromium + ungoogled-chromium components (BINARY-LICENSE.md:15 and
  :142). It is not an extension or a JavaScript injection (README.md:288-289).
- **Parts of the repository:** Python wrapper (`cloakbrowser/`), JS
  (`js/src/`), .NET (`dotnet/`), `bin/cloakserve` (CDP multiplexer in
  Python), `bin/cloaktest`, Dockerfile. Python dependencies: `playwright`,
  `httpx`, `cryptography` (pyproject.toml, `dependencies` block).
- **Licenses on two levels.**
  - Wrapper: **MIT** (LICENSE; pyproject `license = "MIT"`).
  - Binary: **proprietary, "all rights reserved"**, `BINARY-LICENSE.md` v1.3
    (Jul/2026). Points that affect ScrapeLens:
    - forbids redistributing, reselling, packaging, modifying and reverse
      engineering (BINARY-LICENSE.md:69-72);
    - internal scraping/automation use is allowed without an OEM license
      (BINARY-LICENSE.md:79-81), but an **OEM/SaaS license is required** if the binary
      is embedded, "exposed through an API" or gives third parties control over the
      browser (BINARY-LICENSE.md:93-97);
    - listing CloakBrowser as a dependency is not redistribution, because the
      user downloads the binary from the official channels (BINARY-LICENSE.md:91);
    - the newest build requires a subscription (BINARY-LICENSE.md:25);
    - prohibited uses: unauthorized access to financial, health or
      government systems, brute force, automatic account creation, fraud,
      bypassing authentication on a system that is not yours (BINARY-LICENSE.md:113-122).
  - Product consequence: ScrapeLens is open source, so it **can only
    point to a binary that the user installed themselves** (as we already do with
    Chrome). An MCP that offers the browser to third parties falls under the OEM/SaaS clause.
    For our use (synthetic sessions or sessions on own/authorized systems) the
    unauthorized-access clause is compatible, but it is recorded here.

### 2. Platforms and builds for macOS arm64

README.md:850-858 ("Platforms" table) and `cloakbrowser/config.py:20-31`:

| | Without key | With key (free via GitHub login, or paid) |
|---|---|---|
| macOS arm64 | **Chromium 145.0.7632.109.2, 26 patches** | **Chromium 155 (README.md:155, 87 patches); the README says the free "latest" build is already 156 (README.md:189, :219)** |

- Keyless release, macOS arm64: tag `chromium-v145.0.7632.109.2` (2026-03-04),
  `cloakbrowser-darwin-arm64.tar.gz`, **147.384.149 bytes**, SHA-256
  `505582aa1bd3971c577f70e0cbbe016431702bdb693529abfd943b5bd9120c1c` (from the
  `SHA256SUMS` published in the release; consulted, not downloaded).
- The Pro releases on GitHub only have `SHA256SUMS`/`.sig`; the Pro binary comes from
  `https://cloakbrowser.dev/api/download/<version>` with the key
  (`cloakbrowser/download.py:540-560`).
- The keyless build is **~11 major versions behind** the stable Chrome on this
  machine (156.0.8078.74). A closed binary without security fixes for
  months is a risk, and an old version is by itself a signal for anti-bot. So the
  keyless test serves for **technical feasibility** (flags, CDP, NetLog), not
  for measuring the advertised stealth benefit.
- **macOS signature:** "ad-hoc signed"; Gatekeeper blocks the first
  run (README.md:860). The wrapper works around this with `xattr -cr` on the
  extracted directory (`cloakbrowser/download.py:1045-1056`). We will not do
  that. Files downloaded with `curl`/`gh` do not receive the quarantine attribute and
  run from the command line without a prompt.
- The app lives at `~/.cloakbrowser/chromium-<version>/Chromium.app/Contents/MacOS/Chromium`
  (`cloakbrowser/config.py:280-286`), with `CLOAKBROWSER_BINARY_PATH` to
  point to your own binary (`config.py:414-419`).

### 3. How it is launched; does it accept our flags?

- **In the wrapper:** Playwright launches the executable (`executable_path=binary_path`,
  `cloakbrowser/browser.py:395`, `:530`, `:697`) with `ignore_default_args`
  = `--enable-automation` and `--enable-unsafe-swiftshader`
  (`cloakbrowser/config.py:52`) and these stealth arguments
  (`config.py:155-177`): **`--no-sandbox`**, `--fingerprint=<seed>`,
  `--fingerprint-platform=macos` (on macOS). The README mentions others:
  `--fingerprint-timezone`, `--fingerprint-locale`, `--fingerprint-webrtc-ip`,
  `--proxy-server` (`browser.py:1117-1500`).
  - Playwright (Playwright behavior, not the repository's) talks to the
    browser over a **pipe**, with no port: there is no `--remote-debugging-port` on that
    path. For ScrapeLens we need to launch the binary ourselves.
- **Direct launch with a port, in the project itself:** `bin/cloakserve:380-397`
  does `subprocess.Popen([binary] + base args + stealth + ["--remote-debugging-port=<p>",
  "--remote-debugging-address=127.0.0.1", "--user-data-dir=<dir>"])`. The base
  args (`bin/cloakserve:54-63`) include `--disable-background-networking`,
  `--disable-extensions`, `--disable-popup-blocking`, `--metrics-recording-only`.
  The README documents the same path: "launch with `--remote-debugging-port=9242`
  and connect the framework" (README.md:816-821). The CHANGELOG records a binary
  patch for `--remote-debugging-address` (CHANGELOG.md, `[binary]` entries
  about `cloakserve`).
- **ScrapeLens flags** (`src-tauri/src/capture.rs`, `spawn_chrome`):
  - `--remote-debugging-port=0`, `--remote-debugging-address=127.0.0.1`,
    `--user-data-dir`, `--disable-component-update`,
    `--disable-background-networking` and `--no-first-run`: Chromium defaults, with no
    visible conflict with what `cloakserve` already passes.
  - **`--log-net-log` and `--net-log-capture-mode=Everything`: there is no
    mention anywhere in the repository.** The binary is Chromium and NetLog lives in the
    network code, which does not appear in any described patch; but it is **not proven**. Phase
    B must check that the file is generated and complete (socket bytes,
    `Everything`).
  - **Conflict:** our `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE
    127.0.0.1, EXCLUDE localhost` blocks every host outside loopback.
    That breaks any test against real sites and **would block the license
    validation** of the keyed build (item 7). The real integration needs a
    capture mode without that rule.
  - **`--no-sandbox` in the wrapper's default arguments (config.py:165),
    including on macOS.** We must not repeat it: without the Chromium sandbox, a
    renderer failure on a hostile page would compromise the user's
    account. Phase B checks whether the binary works without that flag on macOS
    (the macOS sandbox is seatbelt, it does not need setuid).

### 4. Is the CDP complete?

Nothing in the repository removes or restricts CDP domains. Evidence:

- The whole product runs on top of CDP: Playwright, `Page.createIsolatedWorld`,
  `Input.dispatchKeyEvent`, `DOM.getFrameOwner`, `Page.getFrameTree`
  (`cloakbrowser/human/world.py:1-12`, `human/keyboard.py:3-8`).
- `connect_over_cdp` with a browser launched by us is documented (README.md:816-821,
  :901-935); `cloakserve` forwards the CDP WebSocket and rewrites only the URL
  (`README.md:928-946`).
- The CHANGELOG lists "CDP input stealth" (4 input-event patches) and
  "CDP detection vector audit and hardening" (CHANGELOG.md, `[binary]` entries
  from 0.3.x); these are signal fixes, not domain removal.
- About `Network.*` (incl. `ExtraInfo`), `Network.getResponseBody`,
  `Target.setAutoAttach {flatten, waitForDebuggerOnStart}` and
  `Runtime.runIfWaitingForDebugger`: **no evidence for or against**, the
  repository does not test these methods. What exists is indirect: Playwright uses
  `Target.setAutoAttach` with `flatten` and `waitForDebuggerOnStart` and
  `humanize` maps OOPIF frames per session (`human/world.py:432-475`), which
  only works if child auto-attach works. It is the Chromium 145/155 base,
  but **ScrapeLens needs the full battery**: `check_multi_target` (16/16
  markers), POST bodies and header order.
- **Differences that may affect fidelity** (README.md:166 and CHANGELOG.md,
  `[binary]` proxy entries): with **an active proxy**, the binary "zeroes" the DNS/connection/SSL
  timings, removes the proxy's cache headers and the leak of
  `Proxy-Connection`, and normalizes network metadata. Without a proxy there is no sign of
  altered timings or headers, but **nobody has compared the order and
  capitalization of the binary's headers with Chrome's**: it is a phase B measurement
  (HTTP/1.1, h2, h3 against the `experiments/` we already have). The README also claims
  TLS/ja3/ja4/akamai "identical to Chrome" (README.md:236), which, if true,
  indicates that the network stack was not altered.

### 5. Does the "stealth" depend on there being no CDP? **Critical**

Short answer: **the repository does not say that the stealth requires the absence of CDP,
and it does not hide CDP; on the contrary, it says the protection holds with Playwright's CDP
connected. But it admits that CDP traffic can be detected, and
our connection is much more intrusive than that of a typical Playwright script.**

In favor of "connected CDP works":

- Test table: "CDP detection | Detected | **Not detected** |
  `isAutomatedWithCDP: false`", measuring connected Playwright (README.md:235).
- The declared approach is a patch in the binary, not a dependence on the absence of
  the protocol: "automation signals, CDP input behavior" (README.md:39, :288).

Against, or unproven:

- **README.md:1265-1300** (reCAPTCHA): `page.wait_for_timeout()` and
  `page.evaluate()` "send CDP traffic that reCAPTCHA detects"; Puppeteer
  "leaks CDP automation signals" (README.md:533); the recommendation is to minimize
  CDP calls before the challenge. In other words, **the stealth degrades according to what the
  CDP client does**.
- The project's test for "CDP not detected" is weak: it only looks for
  `cdc_*`/`__webdriver` keys in `window` (`tests/test_stealth.py:65-80`). There is no
  test of the classic `Runtime.enable` vector (error with a `stack` getter /
  `console.*` serialization), nor of `Network.enable`, `Page.enable` or
  auto-attach with `waitForDebuggerOnStart`.
- ScrapeLens's profile, which differs from the typical script: on each target we send
  `Network.enable`, `Page.enable`, **`Runtime.enable`**,
  `Target.setAutoAttach {flatten, waitForDebuggerOnStart}` and
  `Runtime.runIfWaitingForDebugger` (`capture.rs`, `setup_attached_target`),
  plus `Target.setDiscoverTargets` at the root, **on all targets including
  workers and iframes**. `Runtime.enable` and the debugger pause are classic
  signals. Playwright also sends `Runtime.enable`, and the vendor claims
  it passes; there is no proof that the rest of our profile passes too.

Consequence for the design (only hypotheses to measure, in order of preference):

1. **Reduced CDP** when the target is protected: `Network.enable` +
   `Target.setAutoAttach` only (without `Runtime.enable`/`Page.enable`; 
   `Network.*` and the bodies do not depend on them). It still preserves events, bodies and
   `ExtraInfo`.
2. **Full CDP** if the measurement shows that the binary tolerates it.
3. **NetLog only** (no debugging port): preserves bytes and header order at the
   network level and the correlation by time, but loses bodies via CDP,
   per-request `ExtraInfo` and per-target attribution (see
   `docs/02-matriz-fidelidade.md`). An AI agent still needs **a control
   channel** for the browser; if it uses CDP (Playwright/MCP), CDP will already be
   connected anyway, and the question becomes only whether our second
   client adds signals.
4. **Proxy**: outside our scope, which forbids MITM and our own certificates
   (`docs/01-decisoes.md`, line 9). A proxy that does not decrypt TLS does not see HTTPS headers.
   Only the leader can change that decision.

### 6. Version, update, telemetry and risks

- **Cadence (GitHub Releases):** Pro ships weekly, each release with an incremental
  suffix. Observed: `155.0.8059.39.2` (27/Oct), `155.0.8059.39.1` (20/Oct),
  `154.0.8037.57.2` (13/Oct), `154.0.8037.57.1` (6/Oct), `152.0.7977.82.1`
  (23/Sep), `151.0.7922.108.6` (12/Sep). The keyless line (145 on macOS)
  has been stalled since 04/03/2026.
- **Version divergence in the repository's own documents:** `config.py:23`
  sets the default to 146, macOS to 145; the README talks about 155 (Pro, 87 patches)
  and 156 (free with key). Treat all the numbers as claims until phase B
  prints the real `--version` and UA.
- **Automatic download:** the wrapper downloads the binary on first use
  (README.md:127; `download.py:194-348`) and **updates in the background**
  (daemon thread every hour: `download.py:1319-1330`), besides querying PyPI
  (`download.py:1256-1283`) and the GitHub API (`download.py:1202-1222`).
  It can be turned off with `CLOAKBROWSER_AUTO_UPDATE=false`. If we do not use the wrapper,
  none of this runs.
- **Integrity verification:** Ed25519 over `SHA256SUMS`, with the public key
  fixed in `config.py:42-44`
  (`MKFKwIhUcKWq5xTuNA0Ovg99njcDEcEJvmWYYhApvaU=`), mandatory verification and no
  bypass on the official path (README.md:292; `download.py:578-640`,
  `:758-800`). Good: phase B can verify this way, by hand, without the wrapper.
- **Telemetry:** the binary license says there is no telemetry, **except
  "license validation and concurrent session counting"**
  (BINARY-LICENSE.md:140). This is outbound traffic from the binary itself:
  `cloakbrowser.dev/api/license/validate` and `.../license/session/count`
  (`cloakbrowser/license.py:26-28`; the key goes in the POST: `license.py:404-409`),
  and the binary **exits with code 76-79 if the license is denied or the server does not
  respond** (`license.py:102-123`). The keyless build should not have this
  check, but **only the phase B NetLog will tell**. Risks for us:
  - the capture's NetLog will record this traffic from the browser itself
    (noise and user data: the key) — it needs to be labeled/filtered as
    "browser traffic, not site traffic";
  - the keyed build requires an account (GitHub login for the free key, personal
    data) and limits sessions; the key can never go into the repository, into the
    exported session or into command-line arguments (the wrapper passes it
    through an environment variable, `license.py:299-349`).
- **Closed binary on macOS, ad-hoc signed, with the sandbox off by
  default** (`--no-sandbox`), downloaded from two hosts (`cloakbrowser.dev` and
  GitHub). Mitigation: verify the manifest signature, run with a
  disposable profile, without `--no-sandbox` if it works, and **without network** in the local
  tests.
- **Dependency risk:** the project has ~1 week of heavy releases and was born
  on 22/02/2026; the free tier for macOS does not receive the current build. ScrapeLens
  must not depend on it: an **optional** browser, with Chrome as the default.

### 7. Confirmation of the points in `docs/15a-mercado-mcp.md`

Complement requested by the leader. Each point of the market research was checked
against clone `b860957` (and, for the issues, against the public GitHub API, read-only). The
maintainer statements below are from the **vendor**, unverified.

| Research point | Verdict | Evidence |
|---|---|---|
| The README says CDP commands leak signals that reCAPTCHA detects | **Confirmed, with a smaller scope**: it talks about `page.wait_for_timeout()`, `page.evaluate()` before the challenge and Puppeteer, not `Network.enable` or auto-attach | README.md:533, :1265-1300; CHANGELOG.md:603 ("replace `page.wait_for_timeout()` … to avoid timing leak") |
| Free build on macOS = Chromium 145 | **Confirmed** (without key) | README.md:854-855; `config.py:28-29`; release `chromium-v145.0.7632.109.2` (04/03/2026) |
| From v148 on, license key | **Confirmed, with an important caveat**: the **free** key (GitHub login, 1 session) delivers the newest build; only **version pinning** is paid | CHANGELOG.md:227, :259, :264 ("Pro license required; v146 stays free"); README.md:189; `download.py:236-241` ("Free tier always gets the latest build"); issue #614 (reply: pinning a version is a paid feature) |
| Validation at cloakbrowser.dev | **Confirmed** | `license.py:26-28`, `:404-409`; BINARY-LICENSE.md:140; exit 76-79 (`license.py:102-123`) |
| Automatic update check | **Confirmed**; can be turned off | `download.py:1319-1330` (hourly thread), `:1182-1200`, `:1256-1283`; `CLOAKBROWSER_AUTO_UPDATE=false` (README.md:648). Without the wrapper it does not run |
| Own license, no redistribution | **Confirmed** | BINARY-LICENSE.md:69-72, :93 |
| Ad-hoc signature on macOS | **Confirmed** | README.md:860 ("ad-hoc signed … Gatekeeper will block it"); the wrapper runs `xattr -cr` (`download.py:1045-1056`) |
| `--log-net-log` with byte capture works via args | **Not verified, no evidence for or against**: no file in the repository contains `net-log`/`netlog` (search returned nothing). What exists is passing of arbitrary arguments: `build_args` forwards `args=` (`browser.py:1461-1466`) and `cloakserve` appends them to the binary's command line (`bin/cloakserve:380-390`). It is a Chromium flag and no network patch is described, so it is likely, but only B1 proves it | phase B, item B1.1 |
| Issues #575, #614, #598, #611, #602, #632 | see table below | public GitHub API, consulted on 31/10 |

Issues (all open on 31/10; maintainer text = vendor claim):

| # | Subject | What the issue and the maintainer say | Impact for ScrapeLens |
|---|---|---|---|
| 575 | **Crash on macOS arm64** | Build `154.0.8037.57.1` (Pro, free key): the renderer crashes in ~1,5 s on every Google Maps page (GPU path); `--disable-gpu` avoids it. Maintainer (06/10): "bug in our 154 build"; fix "in the next macOS release". The report confirms that the wrapper passes `--no-sandbox --fingerprint=… --fingerprint-platform=macos` | The macOS manifest lists `155.0.8059.39.1` (20/10), but `…39.2` (27/10) shipped only for Linux. **Nobody confirmed in the issue that 155 fixes it.** B1 must include a GPU/WebGL-heavy page, besides loopback |
| 614 | **Detection** (Fingerprint.com: `ChromiumAutomation`) | Reproduced on `155.0.8059.39.1`. Maintainer: fixed in `…39.3`, "no release yet, about a week"; subscribers can pin; the free tier receives it automatically. A user got a 404 when requesting `…39.3` (22/10) | Detection is a continuous race and the free tier trails the paid one. The advertised benefit has a short shelf life |
| 598 | **Detection** (Outlook, GitHub, Facebook) | It was account registration. Maintainer: "not a supported use case", forbidden by the license (automatic account creation) | Nothing technical. Reinforces that use stays restricted to own or authorized targets (BINARY-LICENSE.md:113-122) |
| 611 | **Detection** (Cloudflare) | Report without content (empty template). Maintainer asked for the "best-flow" with key, proxy and `preview` channel | No technical evidence |
| 602 | **Detection** (pixelscan "Masking detected") | Maintainer: it comes with the noise feature (`--fingerprint-noise`); with `--fingerprint-noise=false` it goes away; fix "in the next Preview" (18/10). The flag is documented (README.md:708; CHANGELOG.md:409) | Fingerprint noise changes canvas/WebGL/audio, not network. For capture, `--fingerprint-noise=false` is advisable so as not to add variables |
| 632 | **`Runtime.addBinding` does not persist after navigation** | In Chrome for Testing 155 the binding survives `reload`; in CloakBrowser (155 and 146) it disappears. Maintainer (29/10): "not a bug, it's a feature … removes automation signals at the engine level; **on purpose and will not change**, because keeping CDP-injected hooks across navigations makes the browser easier to detect". Workaround: add it again after each navigation | **The binary's CDP diverges from Chrome by design.** ScrapeLens does not use `Runtime.addBinding` (no occurrence in `capture.rs`), but this proves that each domain we use (`Network.*`, `Target.*`, `Page.*`, bodies) needs to be measured against Chrome, and that an agent/MCP that depends on bindings breaks |

#### What is lost when capturing only through NetLog (passive)

The research hypothesis is reasonable **as a mode for protected targets**, with
two caveats: (a) the AI agent itself will already speak CDP with the browser (that is
how Playwright/MCP drives it), so "no CDP" only removes **our**
client, not the control channel; (b) without `Browser.close` the NetLog is only
finalized if Chrome exits gracefully (`cloakserve` uses SIGINT
for this reason, CHANGELOG.md:17); partial captures are already marked incomplete.
Comparison, based on `docs/02-matriz-fidelidade.md` and `docs/14`:

| Item | With CDP (today) | NetLog only |
|---|---|---|
| Order, case and duplicates of headers | NetLog is the official source; ExtraInfo does **not** preserve wire order (matrix, lines 63-76 and 244) | **same**: nothing is lost |
| Multi-target reach | CDP per `sessionId` (recursive auto-attach), 16/16 | NetLog sees the traffic of all processes (`docs/14`, line 8), but **without target type, frame or initiator** |
| Request and response bodies | `Network.getResponseBody` / `getRequestPostData` (`cdp-bodies.jsonl`) | **lost** in the current product. In theory the socket bytes of `Everything` mode carry the content, but decoding h2/h3 frames and decompressing is new work, currently out of scope |
| `requestId` and redirect chain | present | **absent** (the NetLog event does not carry the CDP id, matrix line 63); matching by URL, method and time becomes a lead, not proof, and the ambiguity grows |
| `ExtraInfo` (associated/blocked cookies, IP address, `resourceIPAddressSpace`) | present | **lost** (part comes in NetLog as a wire header) |
| Resource type, `frameId`, `loaderId`, `initiator`, failures with reason | present | network reason exists in NetLog; the rest is **lost** |
| Service workers: page × worker | two linked observations | only what goes through the network, with no attribution |

Recommendation: the protected mode must be **tiered**, not binary: (1) NetLog
only when the target cannot be touched; (2) reduced CDP (`Network.enable` +
`Target.setAutoAttach`, without `Runtime.enable` or `Page.enable`) when
possible; (3) full CDP for the rest. B1 decides under which conditions the binary
tolerates each level.

## Phase B — measurement proposal (NOT executed; depends on user authorization)

Phase B runs a **third-party binary** and downloads data from the internet; for that reason
it stays on hold until express authorization. Everything below is local, disposable and reversible.

### B0. What would be downloaded (and only this)

| # | Artifact | Source | Size | Verification |
|---|---|---|---|---|
| 1 | `cloakbrowser-darwin-arm64.tar.gz` | `https://github.com/CloakHQ/cloakbrowser/releases/download/chromium-v145.0.7632.109.2/cloakbrowser-darwin-arm64.tar.gz` | 147.384.149 bytes | SHA-256 `505582aa…120c1c` checked against the release's `SHA256SUMS`; **Ed25519 signature of `SHA256SUMS.sig`** against the key in `config.py:42` (Python `cryptography` with `python3 -I`, or `openssl` 3) |
| 2 | `SHA256SUMS` and `SHA256SUMS.sig` | same release | 412 and 88 bytes | already read in phase A |

- Download with `gh release download` or `curl`, **not** with `pip install
  cloakbrowser`/`npm install` (which would bring the wrapper, the update
  scheduling and the `xattr -cr`).
- Destination: new, empty folder, outside the project (e.g.:
  `/tmp/cloak-study/bin/`). Before extracting: `tar -tzf` to check for absolute
  paths and `..`; afterwards `codesign -dv --verbose=4` and `spctl -a -vv` only to
  record the signature (no attribute changes).
- **Do not** use a license key in B1. Build 155/156 (the one that actually shows the
  benefit) goes into a B2, which requires a user decision about the GitHub login
  (personal data) and about the terms of item 1.

### B1. What would be run

Always with a new `--user-data-dir` in `/tmp`, without `--no-sandbox` on the first
attempt, `CLOAKBROWSER_AUTO_UPDATE=false` (irrelevant without the wrapper, but
recorded), and **without credentials**. Each run of the binary under
`sandbox-exec` with network only on loopback and writes only to `/tmp/cloak-study`
(to be validated; if the sandbox profile prevents the browser, record it and fall back
to a plain run with the monitoring of item 5):

1. **Sanity and telemetry:** `Chromium --version`; open `about:blank` with
   `--log-net-log` and `--net-log-capture-mode=Everything`, with no external network,
   for 60 s. Deliver: is the NetLog complete? Is there any outbound attempt (license,
   update, telemetry)? Cross-check with `nettop`/`lsof -i` in parallel.
2. **Header-order `experiments/`** (already existing) against the binary, over
   local HTTP/1.1, h2 and h3: are the wire order and capitalization those of Chrome?
   Difference = fidelity finding.
3. **`tests/aceite/check_multi_target.py`** with `CaptureConfig.chrome` pointing
   to the binary (today the capture accepts any Chrome-like executable):
   16/16 NetLog, ≥15/16 CDP, target types, POST bodies, service worker. Runs only
   on loopback, like the current test.
4. **CDP detection, local and without third parties:** a synthetic page in the
   `testserver/` style (ask Tests) with the known probes: `navigator.webdriver`,
   `window.chrome`, the `stack` getter on `Error` + `console.debug` (a
   `Runtime.enable` signal), `debugger` duration, `Notification.permission`/plugins.
   Run the same page under **five conditions**, each with stable Chrome
   as the control:
   - A: no CDP (NetLog only; `--remote-debugging-port` absent);
   - B: minimal CDP (`Network.enable` + `Target.setAutoAttach`);
   - C: full CDP, as ScrapeLens does today;
   - D: C with `waitForDebuggerOnStart: false`;
   - E: plain Playwright (`connect_over_cdp`), only as a reference for "what the
     vendor tests".
   Output: probe × condition × (CloakBrowser, Chrome) table.
5. **Containment:** run in a user account/environment with no access to the
   real Keychain (`--use-mock-keychain`, `--password-store=basic` as we already
   pass), without the personal profile folders, and terminate only the PID started,
   through `cleanup_orphans` if anything is left over.

### B2. Optional, only with separate authorization

- Public third-party detectors (sannysoft, incolumitas,
  deviceandbrowserinfo, browserscan) with and without CDP, to compare with the
  README table. These are **third-party sites receiving the user's traffic**;
  read-only, no login, and without the `--host-resolver-rules` of item 3.
- Build 155/156 with the free key (GitHub login), repeating B1.
- Any protected real site (Cloudflare, reCAPTCHA): **out of scope**
  without authorization from the site owner; the binary license forbids unauthorized use.

### B3. Decision criteria

| Result | Suggested decision |
|---|---|
| NetLog complete, CDP 16/16, headers equal to Chrome, no extra probes under conditions A–C | integrate as an optional browser (full CDP) |
| Everything equal, but condition C is flagged and B is not | integrate with **reduced CDP** for the protected mode |
| Only A passes | **NetLog-only** mode for this browser; warn about the loss of bodies/attribution |
| Headers differ from Chrome or the NetLog comes out incomplete | **do not** use as a fidelity source; record it in the matrix as a limit |
| Undeclared outbound traffic from the binary | do not adopt without a user decision |

## Decisions and questions for the leader

1. **Scope of B1:** authorize the user to download the 145 build (147 MB) and run it
   under containment? I recommend yes: it is the only way to know whether flags, NetLog and
   CDP work, with no login or key.
2. **B2/new build:** the real benefit only exists in 155/156, which requires a key
   (GitHub login). Only the user decides this. I recommend postponing until B1 passes.
3. **Proxy:** the request mentioned "NetLog or a proxy". The current scope forbids
   MITM. Keep it? I recommend keeping it: HTTPS header fidelity comes from NetLog.
4. **Bundling:** ScrapeLens points to the user's binary (as with Chrome)
   and never embeds it; the MCP must not be offered to third parties as a service without
   an OEM license. I recommend recording this in `docs/01-decisoes.md`.
5. **Two CDP clients:** the AI agent (Playwright/MCP) and ScrapeLens will
   need the same browser. That forces `--remote-debugging-port` (default
   Playwright uses a pipe). The MCP design must decide who launches the
   browser (I recommend: ScrapeLens launches it and exposes the port to the agent) and how to
   prevent both from requesting `waitForDebuggerOnStart`.
