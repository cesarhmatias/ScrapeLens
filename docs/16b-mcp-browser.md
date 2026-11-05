# Round 11, wave 1 — browser tools and site reconnaissance (contract)

Date: 2026-10-31. Owner: Capture. Complements `docs/16-mcp-contract.md` (Core:
read tools) and part of decision D6 (`docs/01-decisions.md`) and of phase
A (`docs/15-mcp-cloakbrowser.md`). **The contract is written before the code.**
This document does not define the MCP server (transport, rmcp, elicitation): that
is not assigned to Capture. It defines what the MCP server will call.

## 1. Flow and limits

An AI agent uses the ScrapeLens MCP with **regular Chrome** to understand the
configuration of a site. CloakBrowser only comes back on the agenda if `site_profile`
recommends "CloakBrowser candidate" (D6, item 6). Out of scope for this wave:
downloading or running CloakBrowser, MITM proxy, `--no-sandbox`, any workaround of
Gatekeeper, solving a CAPTCHA or challenge.

Tools in this section: `start_capture`, `navigate`, `capture_status`,
`stop_capture` and `site_profile`. **`act` does not exist in this wave**: following D6
(item 3), ScrapeLens opens Chrome and **hands over CDP access on loopback**; the
agent acts with its own tool (for example the Playwright
MCP `--cdp-endpoint` or the Chrome DevTools MCP). Reasons: (a) we do not reimplement an input
API; (b) ScrapeLens stays only an observer. Accepted consequence: the
agent's actions in the browser **do not go through ScrapeLens confirmation**; what
limits them is the network allowlist (§2.2), enforced by Chrome itself.

## 2. Security model

### 2.1 Profile and process

Dedicated, temporary profile: never the personal profile; debugging only on
`127.0.0.1`; terminates only the process that ScrapeLens started
(`ChromeProcess` + orphan marker). `--no-sandbox` is never passed.

**Only Google's stable Chrome** (security review, finding M3). The agent's
`binary_path` never becomes the executable without going through
`chrome::validate_chrome`, which **does not execute the binary**: `start` refuses with
`browser_invalid` everything that is not an `.app` with
(1) `CFBundleIdentifier = com.google.Chrome`, (2) the bundle executable as
`Contents/MacOS/<CFBundleExecutable>` (symlinks resolved, execute bit),
(3) `CFBundleShortVersionString` present (the version read), and
(4) `codesign --verify --deep -R='anchor apple generic and identifier
"com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'` with
**exit code 0** (`chrome::CHROME_REQUIREMENT`). Nothing in the text output of
`codesign` is interpreted (the `-dv` parse was fooled by a line break
in the path, R1 of the review). `--deep` covers the nested bundles (Helpers,
frameworks): a Google-signed copy with a swapped Helper is refused
(R2) and the Helper never runs. The requirement demands the Apple anchor and Google's Team ID
in the leaf certificate, so an ad hoc bundle with Chrome's identifier
is also refused. **It does not use `--strict`**: the Chrome installed on this
machine has Finder attributes ("resource fork, Finder information, or similar
detritus not allowed") that `--strict` rejects; without it, `--deep` with the explicit
requirement passes on the real Chrome (exit 0, about 9 s). **No cache**:
each `validate_chrome` redoes the check. A path with a control character
(`\n`, `\r`, TAB, NUL, DEL, C1) or non-UTF-8 is refused (`UnsafePath`, code
`browser_invalid`) before any read, for the given path and for the
canonical one. Read by the system `plutil` and `codesign`, by absolute path.
Refused (tests): `/bin/echo`, `/bin/sh`, an executable script named `chrome`,
a fake `.app` with a lying `Info.plist`, an ad hoc bundle with Chrome's
identity, a path with a line break (the review PoC), a Chrome copy with the
Helper swapped, a bundle of another product, a nonexistent path.

**Execution of the validated path (R11).** `BrowserCapture::start` validates and passes
to the launcher exactly `ValidatedChrome.binary` (canonical path, symlinks
resolved), never the path the agent gave. **Remaining gap:** between the
check and the `exec` there is a window in which a process of the same user, with
write access to the bundle, could swap a file (TOCTOU). In `/Applications` the
bundle belongs to the `admin` group; a copy in a user folder belongs to the user himself,
who could already execute anything as himself. `--deep` makes the window
small, but does not close it; closing it would require executing by file descriptor,
which macOS does not offer for `.app`.
Outside macOS the error is `UnsupportedPlatform`. The App's `chrome::detect`
(user's choice in the interface) did not change. The `StartInfo.browser` path
is the already resolved one. The MCP server must choose and show the browser in the
confirmation with `chrome::resolve_stable_chrome(explicit)` (validates the agent's
path and never replaces it), not with `normalize_binary_path`/`detect`, which
accept any file; until then `start` still refuses with `browser_invalid`,
but only after the elicitation.

**Inherited descriptors (R9).** Chrome is launched with every descriptor `>= 3`
marked `FD_CLOEXEC` in the child (`fcntl` between the fork and the exec; with pipe, only 3
and 4 of the CDP stay open). A log or socket that the server launcher
inherited without CLOEXEC does not reach Chrome or the helpers. The sweep goes up to
`min(getdtablesize(), 65536)`; an fd above that is not covered (no
practical value). Live test `live_inherited_fds_do_not_leak_into_chrome` (pipe and port,
main process and helpers; without the fix the fd leaks). The pipe descriptors
are created with `F_DUPFD_CLOEXEC`, but between the `pipe()` and the duplication there is a
minimal window without CLOEXEC (macOS has no `pipe2`): a `plutil`/`codesign`
launched by another thread at that instant could inherit one end of the pipe. I did not
measure or reproduce it; the child is short-lived and only holds the end until it exits.
Informational, no fix.

**Linux (round 14).** The validation above is the macOS one (`codesign`). On Linux there is no
code signature on the binary; `chrome::validate_chrome_linux` applies the equivalent
(regular ELF binary owned by root, not writable by group/others or by the user, directories
above it owned by root and not writable, only then `--version`, and the owning package by `dpkg -S`/`rpm -qf`
only as information) and accepts **Chromium** as a marked alternative (the only one on arm64). The
private paths (profile, NetLog, state root) respect `$TMPDIR` and `$XDG_RUNTIME_DIR`. See
`docs/21-linux.md`.

### 2.1b Regular App capture: open network by default (`NetworkMode`)

Defect found by the user: in the App, `Start session` with `https://google.com.br`
opened Chrome with `DNS_PROBE_FINISHED_NXDOMAIN`. The regular capture carried
`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost` and
`--allow-insecure-localhost`: only loopback resolved, no real site loaded.
Now `CaptureConfig.network` chooses:
- `NetworkMode::Open` (**default**): without `--host-resolver-rules` and without
  `--allow-insecure-localhost`; Chrome resolves and reaches the network normally;
- `NetworkMode::LoopbackOnly`: the old behavior, **for tests only**
  (nothing beyond `127.0.0.1`/`localhost` resolves). The suites enable it with
  `SCRAPELENS_CAPTURE_NETWORK=loopback` (the App reads this via `NetworkMode::from_env()`)
  or, in Rust tests, `network: NetworkMode::LoopbackOnly`.
The MCP **controlled** capture (allowlist) did not change: the allowlist
(`resolver_rules`) applies in place of the mode, without certificate relaxation; the
`BrowserCapture` passes `LoopbackOnly` only as a fail-closed in case the allowlist were missing.
Tests: `network_mode_defaults_to_open`, `open_mode_passes_no_dns_rules_and_no_localhost_relaxation`,
`loopback_only_mode_keeps_the_lab_restrictions`,
`the_controlled_capture_allowlist_overrides_the_network_mode`,
`ignore_cert_is_the_only_certificate_relaxation_in_open_mode` and the live
`live_open_mode_resolves_a_local_name_and_loopback_only_does_not` (a local server
reached through `sl-open-mode.localhost`, which Chrome resolves on its own: in open mode the
server sees the request and the session has status 200; in `LoopbackOnly` the server sees
nothing). No real site was accessed.

**Review of the remaining launcher arguments on real sites** (none prevents
loading a site; these are the ones that change what the server sees):

| Argument | Effect on a real site |
|---|---|
| `--ignore-certificate-errors` (only with `ignore_cert`/`SCRAPELENS_CAPTURE_IGNORE_CERT=1`) | hides TLS errors: Chrome stops showing the interstitial and the capture of a site with a bad certificate looks normal. **For the lab only**; the default is off |
| `--allow-insecure-localhost` | only affects `localhost`; removed from open mode |
| `--no-pings` | turns off the `ping` of `<a ping>` (hyperlink auditing): the beacon the site would expect is not sent. Rare; **changes the traffic** |
| `--disable-popup-blocking` | lets `window.open` without a gesture open tabs (ads, OAuth). Good for capturing multi-target; the user may see more popups |
| `--disable-features=OptimizationHints,Translate,MediaRouter,InterestFeedContentSuggestions` | avoids requests from Chrome itself (hints, translator); does not change the page resources |
| `--disable-background-networking`, `--disable-component-update`, `--disable-sync`, `--metrics-recording-only`, `--disable-domain-reliability`, `--disable-client-side-phishing-detection`, `--disable-breakpad`, `--no-service-autorun` | silence browser traffic (not the page's) so the NetLog holds only what matters; no effect on what the site sees |
| `--enable-quic` | QUIC is already the default; kept for h3 (the project rule is not to disable QUIC) |
| `--disable-extensions`, `--disable-default-apps`, `--password-store=basic`, `--use-mock-keychain`, `--no-first-run`, `--no-default-browser-check`, `--disable-search-engine-choice-screen`, `--disable-component-extensions-with-background-pages` | UI/profile/keychain; no network effect |
| `--net-log-capture-mode=Everything`, `--log-net-log` | only record (cookies and headers in the NetLog: see §2.4) |
| `--remote-debugging-pipe` (or port with `expose_cdp`) | **turns on `navigator.webdriver = true`** in the page (measured, `docs/20-captcha-google.md` §4.2); D7 passes the flag on the next line to undo this |
| `--disable-blink-features=AutomationControlled` (**D7, always**) | `navigator.webdriver` goes back to `false`, even with the CDP on. It does not touch the network or what is captured. See the paragraph below |
| `--headless=new` (only with `headless`) | the User-Agent and the browser fingerprint change (`HeadlessChrome`); the App default is a visible window. **Relevant to `site_profile`**: an anti-bot challenge under headless may not occur with regular Chrome |

**Automation notice suppressed by default (D7, 2026-11-03).** By user decision
(`docs/01-decisions.md` D7), **every** capture carries `--disable-blink-features=AutomationControlled`:
the App's regular one and the MCP's controlled one, on pipe and on port (`expose_cdp`), in any
`NetworkMode`, with or without `headless`. The flag goes into `chrome_args()`; if there is already
a `--disable-blink-features` with other values, the values are **merged into a single flag**
(`merge_blink_features`, without duplicating the flag or the values). Measured: without it the page reads
`navigator.webdriver === true` with the CDP over pipe; with it, `false` in the full capture and
in the controlled one, on both transports. The `session.json` records the context for whoever reads it:
`capture.chromeArgs` carries the launch arguments (without the temporary paths and without
the start URL, with the flag) and `capture.notes` says in text that the notice was suppressed; the
`site_profile` exposes this in `captureContext.automationFlagSuppressed` (`true`, `false`,
or `null` when the session does not say, like those imported from HAR/NetLog), so that an
anti-bot challenge is read knowing that the site did NOT see the automation notice. **Solving a CAPTCHA
remains out of scope**, and **no other anti-detection technique** (fake User-Agent,
fingerprint patching, hiding the CDP, etc.) is added without a new decision.
Tests: `automation_flag_is_always_present_exactly_once_in_every_mode` (network, allowlist,
headless, `ignore_cert`, pipe and port), `merge_blink_features_combines_without_duplicating_the_flag_or_the_values`,
`recorded_args_keep_the_automation_flag_and_drop_temp_paths_and_the_url`, the live
`live_full_capture_hides_navigator_webdriver_on_both_transports` and
`live_controlled_capture_hides_navigator_webdriver_on_both_transports` (loopback page
that records `navigator.webdriver` on the server) and, in `recon`,
`capture_context_reports_whether_the_automation_flag_was_suppressed`.

### 2.1c Cookies imported from an installed browser (`capture::cookies`)

The capture can start already logged in without touching the personal profile: `CaptureConfig.cookie_source`
takes the `id` of a source from `list_browser_cookie_sources()` (Chrome, Brave, Arc, Edge,
Chromium, Firefox and Safari, profiles `Default`/`Profile *`), and
`load_cookies_for_url(id, start_url)` returns the cookies of the **same registrable site** as the
start host (includes login/SSO subdomains; `localhost`/IP only match exactly) and discards the
expired ones. `CaptureConfig.initial_cookies` lets the caller supply the ready list; when
non-empty, it wins over the source.

- **The user's database is never opened in place.** `cookies.rs` copies `Cookies`/`cookies.sqlite`
  (with `-wal`/`-shm`/`-journal`) to a temporary 0700 folder and deletes it on `Drop`. A copy that
  cannot take a sidecar is reported in the notes. Copies left by a killed or rebooted import
  (a process that is gone, or older than a day) are removed at the start of the next import; only
  this user's directories with mode 0700 and not symlinks are touched. The read is by the system
  SQLite library, loaded at run time (`dlopen` of `libsqlite3.so.0`; macOS uses the `sqlite3`
  command); no package has to be installed, and an AppImage's own libraries cannot break it.
- **Decryption:** pure Rust (`SHA-1`/`SHA-256`/`PBKDF2-HMAC-SHA1`/`AES-128-CBC`), without
  OpenSSL. Chromium `v10` on macOS uses the Keychain password `"<Product> Safe Storage"` (one
  call per capture; macOS may ask for authorization) with PBKDF2 1003 iterations and salt
  `"saltysalt"`; on Linux `v10` uses `"peanuts"` with 1 iteration and `v11` takes the password from the
  keyring (libsecret, see below). On Chrome 130+ (`meta.version >= 24`)
  the 32-byte prefix `SHA-256(host_key)` is removed. Firefox (`moz_cookies`) and Safari
  (`Cookies.binarycookies`) are plain text/without Keychain.
- **Linux keys (`v10` and `v11`):** each value is decrypted with the key of its own prefix, cached
  per prefix, so a profile that mixes `v10` and `v11` rows keeps both readable. On Linux `v11`
  takes the password from the Secret Service through libsecret (`dlopen` of `libsecret-1.so.0`),
  bounded to 20 s; `secret-tool` is only the fallback when libsecret is missing, and it is bounded
  the same way. When the keyring is locked, or has no entry for the browser, the cookies of that
  key cannot be read and the message says `keyring is locked or has no entry for this browser:
  unlock it and try again`. If the site has encrypted cookies and none can be read, the import
  fails with that reason; if some can, they are imported and the rest are counted in
  `undecryptable` with the reason (in the notice and in `Capture.cookiesImported`).
- **Injection:** in `Cdp::setup_inner`, `Network.setCookies` on the page session **before**
  `Page.navigate`; the first request already carries `Cookie`. A
  `Capture.cookiesImported` event in `cdp-events.jsonl` records `source`, `domain`, `importedCount`,
  `skippedCount`, `undecryptableCount` and `undecryptableReason` (`null` when everything was read)
  — **without the values**. The capture's `notice` gains ` · N cookie(s) imported from <source>` and,
  when some could not be decrypted, `; M cookie(s) could not be decrypted: <reason>`.
- **Privacy:** the imported values appear in the CDP/NetLog `Cookie` headers like
  any session cookie; the sensitive-data notice applies (`browser::SENSITIVE_NOTICE`).
  The import is opt-in (`cookie_source`/`initial_cookies`), only for the start site, and does not write
  values to the summary or to any log.
- **Tests:** official vectors for SHA-1/SHA-256/PBKDF2 (RFC 6070)/AES-128-CBC (NIST SP 800-38A);
  Chrome 130+ prefix; a committed synthetic Chromium database read without the `sqlite3` command;
  mixed `v10`/`v11` rows with their own keys; a locked `v11` key with the readable `v10` cookies
  imported and the rest reported; a one- or two-byte encrypted value counted, not a panic; the
  "nothing readable" failure with its reason; the 20 s bound on keyring lookups (including the
  `secret-tool` command, killed at the deadline); the sweep of stale copies; the sidecar note;
  the notice text; the Chrome 130+ prefix; synthetic Chromium and Firefox SQLite databases
  (`sqlite_roundtrip` fails without the `sqlite3` command, it does not pass empty); site filter
  (`.example.com.br` and `login.example.com.br` are included for `app.example.com.br`,
  `other.com.br` is not); synthetic `Cookies.binarycookies`; `Network.setCookies` payload; and the
  live `live_imported_cookies_are_sent_with_the_first_navigation` (loopback: the server sees
  `Cookie: sid=abc123` on the first request, the audit event exists and does not contain the value).

### 2.2 Mandatory allowlist, in two layers

`start_capture` **without a non-empty `allowed_hosts` is an error** (`allowlist_required`).

**Official semantics (leader's decision after the security review, finding M2):
the browser enforces the HOST (all ports); the PORT is only enforced in
`navigate`.** We do not intercept the network (`Fetch`) to enforce the port, because that
alters the capture fidelity. Whoever approves `localhost:P1` approves, for the
page, `localhost` on any port (local Redis, admin, other services): the MCP
server must say this in the elicitation.

| Layer | Mechanism | What it covers | What it does not cover |
|---|---|---|---|
| 1. Browser | `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE h1, EXCLUDE h2…"` with `allowed_hosts` + `third_party_hosts` (a literal IPv4 in the list also gets `EXCLUDE`) | any host by name **and literal IP** (measured: `127.0.0.1`, `127.1`, `2130706433` and `[::1]` failed with `ERR_NAME_NOT_RESOLVED` on Chrome 156), in any tab, iframe, worker or CDP client, including redirects | **the port**: the rule only knows the name |
| 2. API | `navigate` refuses before sending; same decision function (`Allowlist::permits_url`) | scheme, host, **port**, userinfo (`http://allowed@other/`) | navigation done by script or click of the page/agent |

Measured with the review PoC (`live_port_gap_is_reported_on_all_paths`, Chrome
156): with `localhost:P1` approved, the page reached `localhost:P2` through **8
paths**: top-level 302, `location=`, meta refresh, `window.open`, iframe,
fetch, WebSocket and uppercase host. **All 8 appear in
`stop_capture.allowlist.violations`** (and as the warning `capture.allowlist_violation`
in the session), because the report comes from the **CDP events** (`Network.requestWillBeSent`
of each redirect hop, of each iframe and popup, and `Network.webSocketCreated`),
not from the imported session, which loses the WebSocket. A top-level navigation
to a host approved only in `third_party_hosts` is also a violation (approved for subresources,
not as a destination). Violation rule: host outside both lists without a resolution
failure, or a port different from the one written in the pattern (`host:port`); a pattern without
a port accepts any port. What is reported is not blocked. The URLs of
violations, blocked hosts and warnings come out **without query, fragment,
path `;parameters` or userinfo**.

Rules for `allowed_hosts` and `third_party_hosts` (strings):
- exact name (`example.com`), subdomain wildcard (`*.example.com`, does not match
  `example.com`), literal IPv4 written explicitly (`127.0.0.1:8080`);
  **literal IPv6 is refused** (`allowlist_unsupported`): the resolver does not
  handle it reliably; optional port (`example.com:8443`; no port =
  any port of the host; the port only applies in `navigate` and in the report);
- no scheme, no path; uppercase normalized; an entry with a trailing dot,
  `%`, space, backslash or non-ASCII is **invalid** (`allowlist_invalid`;
  punycode only in ASCII); `*` alone, `*.com` and IPs with a wildcard are
  `allowlist_too_broad`; an empty list is `allowlist_required`. IPv4 only in the canonical
  `a.b.c.d` form (`127.1`, `2130706433`, `0x7f.0.0.1` are refused). There is no
  public suffix list: `*.co.uk` passes, and the operator answers for that;
- only `http` and `https` navigate; `file:`, `data:`, `javascript:`, `chrome:`,
  `blob:`, `view-source:`, `about:` (except `about:blank`) are refused. The
  URL parser is **stricter than Chrome's on purpose** (refuses
  backslash, control, non-ASCII, `%` in the host, host with a trailing dot,
  any `@` in the authority, IPv4 outside the canonical form) so that what passes
  is read the same way by Chrome.

`allowed_hosts` = targets where the agent may **navigate/act** (consented to by the
user in the `start_capture` confirmation). `third_party_hosts` = additional hosts
that the page needs to load (script CDN, protection
challenges). Everything that is in neither list **does not resolve**.

**Consequence to know (leader's decision if it changes):** with the strict
allowlist, third-party protection scripts (`challenges.cloudflare.com`,
`js.datadome.co`, `js.hcaptcha.com`…) do not load until they are
declared. Chrome records `net::ERR_NAME_NOT_RESOLVED` for them, and this
**becomes evidence**: `site_profile` lists `blocked_hosts` ("the page tried to
load X; blocked by the allowlist; the protection may be hidden") and
recommends restarting with those hosts in `third_party_hosts` (new
confirmation). Default recommendation: first pass strict; second pass
with the third parties that `site_profile` itself pointed out.

### 2.3 Confirmation

The confirmation (MCP elicitation) happens **in the MCP server layer**, not in this
Rust API, which receives the already confirmed request. No `confirmed:true` parameter
exists (the model could fill it in). Effect classes, for the MCP server to
apply:

| Tool | Effect | Confirmation |
|---|---|---|
| `start_capture` | starts a Chrome process; outbound traffic to the listed hosts; optionally opens the CDP port to the agent | **always**; the text must show `allowed_hosts`, `third_party_hosts`, `expose_cdp`, the binary and the notice from §2.4 |
| `navigate` | top-level GET to an allowlist host | **not per call** (covered by the start confirmation); refuses outside the allowlist |
| `stop_capture` | terminates the started Chrome and writes the session | no |
| `capture_status`, `site_profile` | read | no |

### 2.4 Sensitive data

The NetLog (`--net-log-capture-mode=Everything`) and the CDP hold **cookies,
authorization headers and bodies**. Therefore: temporary profile discarded at the
end (except the rescue of capture files described below, which is NOT the profile); `start_capture` returns `sensitive_notice` (fixed text) that the MCP server
must show; **the agent never types credentials** (there is no `act`; if the agent
uses the exposed CDP to type, the value appears in the captured POST body);
the read tools and `site_profile` **redact by default** cookie and header
values (names, URLs, status and sizes appear; values become
`[redacted, N bytes]`), with explicit opt-in by the Core.

Writes in the session folder **do not follow symlinks** (review, finding F2): the
files that the capture writes (`cdp-bodies.jsonl`, `netlog.json`,
`cdp-events.jsonl`, `netlog.original.json`, orphan marker) use
`O_NOFOLLOW` + `create_new` (0600); a name that already exists, including a planted
symlink, has the **name** removed and recreated, never the target written;
`cdp-events.jsonl` and the marker are written to a new temporary and swapped in by
`rename`, which replaces the link itself; a session folder that is a symlink is
refused, and after `ensure_private_dir` it is checked **already open**
(`O_NOFOLLOW|O_DIRECTORY`, owner = our user, mode exactly 0700).

**NetLog (R3).** Chrome opens `--log-net-log` by path, following
symlinks; pre-creating the file in the session folder left a window for a
process of the same user to swap it for a link (PoC `poc_netlog_race.py`: 236 KB
of full NetLog, with cookies, in a file outside). Now the NetLog is written
**inside the temporary profile**, which we create 0700 from creation
(`DirBuilder`, without `recursive`, fails if the name exists) and check once open
(owner, 0700, not a link), with the name `scrapelens-chrome-<pid>-<ns>` in `$TMPDIR`
(per user on macOS). Only after Chrome exits does ScrapeLens read it with
`O_NOFOLLOW` (only a regular file of our user, checked on the descriptor) and
write it to `<session>/netlog.json` by `write_private` (temporary `create_new` +
`rename`, which replaces a planted link without writing to the target). Live test
`live_netlog_swap_race_does_not_write_through_a_symlink`: an attacker plants or
swaps `netlog.json` for a link during the capture and the target stays intact. **Remaining
gap:** a process of the **same user** that finds the profile by name can still
tamper with it (same uid; outside the model, like the `expose_cdp` port). A
`SIGKILL` of the server leaves the partial NetLog only in the profile, which the orphan cleanup
deletes: no partial `netlog.json` is left in the session folder.

**Session write relative to the descriptor (A3-B3, A4-B3, A4-B4, A6-B5).** At the
start we open the session folder (`O_NOFOLLOW|O_DIRECTORY`, ours, 0700) and
keep the **descriptor** and the identity (device + inode, which does not appear in
any output). After Chrome exits, NO write resolves the
folder path again:
- `cdp-bodies.jsonl` is **created** relative to the descriptor, at the start of the capture
  (`fdio::create_replacing_at`: `openat(O_EXCL|O_NOFOLLOW)`; a name already taken,
  including by a planted symlink, has the NAME removed and is recreated, never the target),
  so a swap of the folder name right after the check does not send the bodies
  to the attacker's folder (A7-B7: before it was `open_private(path)`); during the
  capture it is written through the descriptor itself and, at the end, read back through it (not
  by path). Test `fdio::tests::create_replacing_at_never_writes_through_a_planted_link_nor_into_a_swapped_dir`
  and the live `live_planted_symlinks_are_not_followed`;
- `cdp-events.jsonl`, `netlog.json` and `netlog.original.json` are written with
  `openat(O_EXCL|O_NOFOLLOW)` + `renameat` relative to the descriptor
  (`fdio::write_private_at`);
- the core writes the rest (`session.json`, `attachments/`) in a new 0700 **staging
  directory** inside the temporary profile (`write_session_fd`), and each
  item is moved to the session folder with `renameat` relative to the descriptor
  (`attachments/`, `cdp-events.jsonl`, `netlog.json` and `session.json` last). Across different file systems (EXDEV) it copies through the same
  descriptor. When the Core exposes `write_session_dir_at(dirfd, …)` this staging
  can be replaced by it, without changing the contract.
Effects: (1) a symlink planted at `cdp-events.jsonl`, `netlog.json`,
`session.json` or `attachments` is **replaced** by the `renameat` (the NAME changes,
the target is never written) and becomes the warning `capture.planted_symlink_removed` in the
session and a line in `warnings` of the stop; (2) the loop that replants the link (formerly
A4-B4, which won the 3 attempts and brought down the stop) no longer matters,
because there are no attempts: the `rename` is atomic; (3) if the folder NAME is
swapped during the write, everything keeps going to the ORIGINAL folder (the one the
descriptor represents) and nothing lands in the attacker's folder. Tests
`fdio::tests::*` (invalid names, write after moving the folder, replaced link,
`attachments` as a link or already populated, moved folder, directory in place of a file),
`a3_b3_planted_symlinks_after_the_copy_do_not_fail_the_stop` (4 names, including
`attachments`) and `a4_b5_swapped_session_dir_is_detected_and_nothing_is_written_or_removed`
(the whole session goes to the original folder, nothing in OUT, OUT links intact).

**Session folder rechecked (A4-B5, A6-B5).** `recheck_session_dir` reopens the
folder by NAME (`O_NOFOLLOW|O_DIRECTORY`) and requires a directory, ours, 0700 and the
SAME identity, **before writing and after writing**. If it was swapped for a link,
for another directory (same 0700 and ours) or has a loosened mode, the stop **fails**:
**before** writing with "The session directory was swapped or stopped being ours
during the capture (…); nothing was written to it and nothing outside it was deleted."; **after**
writing (the swap happened DURING the write) with its own message, which
does not repeat the "nothing was written": "The session directory was swapped during the
write (…). The session was written in full to the ORIGINAL directory, now at
`<path.moved>`; nothing was written to the directory that took its place and nothing outside the
original directory was deleted." The path comes from `F_GETPATH` on the descriptor opened
at the start (the CURRENT place of the original folder, even if moved); if the system does not
report it, the message says "which we could not locate". In both cases the
capture files also go to the rescue. It never returns OK with the folder
swapped during the write. Test
`a7_message_after_a_swap_during_the_write_names_the_moved_dir_and_does_not_contradict_itself`.

**Rescue when the session could not be written (A5-B2, A5-B3, A6-B6, A6-B7).**
*Every* failure after Chrome exits (swapped folder, the core refusing a
file, `rename` with ENOENT, import failure) rescues the capture files
**before** the temporary profile is deleted:
- **What is kept:** only `cdp-events.jsonl`, `cdp-bodies.jsonl` (read back through the
  descriptor, even with the folder swapped), `netlog.json` and `motivo.txt` (the error
  message, which may contain the session path), in a **new 0700** folder
  `scrapelens-capture-state/rescue-<pid>-<ns>/` inside `TMPDIR`, with a
  marker `rescue-<pid>-<ns>.json` next to it. The `stop_capture` error names the
  folder. These files **contain cookies, headers and bodies** (the raw capture,
  like the `Everything` NetLog): treat the folder as sensitive.
- **What is NOT kept:** the rest of the Chrome profile (Cookies, Login Data, History,
  Local State...) is deleted as always.
- **Cleanup and deadline (A6-B7):** `cleanup_orphans` (at the start of the App and of the MCP
  server) deletes the rescue folder and the marker when the **directory itself** is
  more than **7 days** old (the directory's mtime, which only changes when entries are
  created or removed in it). The age does **not** come from the marker: a forged marker
  (with an old `createdMs` or with the `dir` of another rescue) does not make a recent
  rescue look expired. The marker only counts if the file name is `<dir>.json`,
  with `dir` a direct child of `state_root`, prefix `rescue-`, without `/` or `..`, and the
  directory is not a symlink. `OrphanCleanup.rescues_removed` counts. A user
  who rewrites the directory's mtime (same user) can bring the cleanup forward:
  outside the model, he could delete the folder directly. Test
  `a6_b7_forged_marker_cannot_delete_a_recent_rescue`.
- **Plan B (A6-B6):** if the normal rescue folder cannot be created (ENOSPC,
  `TMPDIR` full), the profile ITSELF becomes the rescue: everything that is not from the capture
  (Cookies, Login Data, History, which also frees space) is deleted, the
  CDP events, the bodies and the reason are written into it, and it is moved to
  `state_root` with a marker, entering the same 7-day deadline. If it cannot even be moved or
  marked, the profile stays where it is, ALREADY CLEANED and WITH the events, and the
  error says "WITHOUT an automatic deadline … delete them when you recover"; only if even that
  fails does the error warn that the kept profile may be incomplete and that it contains
  Chrome data. Tests `a6_b6_fallback_adopts_the_profile_with_events_and_a_ttl_marker`
  and `a6_b6_fallback_keeps_events_in_place_when_it_cannot_be_moved`.
- **`.tmp-*`:** the temporary that a write leaves behind (`.session.json.tmp-…`…) is
  removed through the descriptor of the ORIGINAL folder, whether it is in place or moved.
Tests `a5_b3_rescue_keeps_only_the_capture_files_in_a_private_dir_with_a_marker`,
`a5_b3_cleanup_removes_only_expired_rescues_that_the_marker_really_names`,
`a5_b2_remove_stale_tmp_cleans_the_original_dir_even_after_it_was_moved` and the
live `live_swapped_session_dir_fails_the_stop_without_touching_outside` (the PoC:
the folder becomes a link to OUT; OUT keeps the same 3 names, links intact and
target equal) and `live_any_write_failure_rescues_the_capture_files` (a directory in the
name of `session.json`: rescue with the 4 files, without `.tmp-*`, with a marker).

**Result of the window PoC (`a5b2_toctou.py`, Reviewer).** Against the current
mcp binary, 8 rounds with the swap fired as soon as `attachments/` appears
(delay 0) and 9 with delays from 2 to 30 ms: nothing landed in OUT in any (only the empty
`attachments/` that the attacker himself created). With delay 0 the swap catches the
write in the middle: the stop **fails** with a rescue (the files already moved are in the
original folder, the rest of the data in the rescue); with 2 ms or more the write (now
a few `renameat`) has already finished and the stop returns OK, with the whole session in the original
folder, and the swap happens afterwards. Before (c9a78f3): 3 of 20 rounds wrote
`session.json` and bodies in OUT and the stop said OK.

**Remaining gap.** Between the `recheck` after the write and the return to the
caller the folder can still be swapped by whoever has the same user; the stop
reported the truth at the instant of the check and the session is in the original folder.
It is the same limit as any user file (he can move the folder whenever
he wants) and outside the model.

**Links planted before the capture (F2).** Live test
`live_planted_symlinks_are_not_followed` (the review PoC: links to
`netlog.json`, `cdp-bodies.jsonl` and `cdp-events.jsonl`; no target receives data
or changes mode). The predictable temporary of the core's `write_atomic`, which was the
second vector of that PoC, was fixed by the Core (commit ad2aad2).

### 2.5 Debugging port: pipe by default, port only with `expose_cdp`

**Pipe message cap (R12).** A Chrome message (NUL-terminated JSON) above
`transport::MAX_PIPE_MESSAGE_BYTES` (128 MiB; the old WebSocket had 64 MiB and a legitimate body fits, `maxResourceBufferSize` ≈ 67 MB) ends
the transport without ever keeping more than the cap. Chrome then exits gracefully
and the NetLog looks complete, so the abnormal close is recorded
separately (A3-B2): `stop_capture` returns `graceful:false` and the warning
`cdp_transport_closed: frame_too_large: …`; the session gets the warning
`capture.cdp_transport_closed` and the reason `capture.cdp_transport_closed:
cdp_transport_closed: frame_too_large: …` in `completeness.reasons`, and
`completeness.state` stops being `complete`. A `navigate` waiting for load
notices the closed channel and returns right away with `navigate_failed` ("the CDP closed
during navigate (frame_too_large)"), instead of spinning until the deadline (it was 60 s).
**Port mode (A4-B2).** The WebSocket has the same cap (`max_message_size` and
`max_frame_size` = 128 MiB; the library default was 64/16 MiB). The capacity error
becomes the same `frame_too_large` and the same incomplete capture; after
any read error the socket is **never read again** (tungstenite leaves the input
buffer full and a new read brought the thread down in debug builds,
with `stop_failed` and `recording:true`). Tests
`a4_b2_websocket_message_cap_closes_with_a_reason_and_never_panics` and the live
`live_oversized_websocket_message_marks_the_capture_incomplete`.
Tests `r12_read_frame_enforces_the_message_cap_without_buffering_past_it`,
`r12_oversized_pipe_message_closes_the_transport_and_smaller_ones_still_pass`,
`a3_b2_closed_transport_marks_the_session_incomplete_with_an_explicit_reason` and the
live `live_oversized_pipe_message_marks_the_capture_incomplete` (the PoC of the
140 MB `console.log`: `navigate` in 2.7 s, `graceful:false`, state ≠ complete).
The queue between the reader thread and the loop remains **without a count limit**
on purpose: limiting it would block the read and deadlock both sides of the pipe
(the loop writes, Chrome writes), so memory follows the pace of the loop.

Security review (docs/17, finding F3): the DevTools port accepted connections
from any local process since launch, before `Network.enable`.
Leader's decision and current state:

- **Without `expose_cdp` (default): `--remote-debugging-pipe`.** Chrome inherits two
  descriptors (reads commands on fd 3, writes on fd 4, JSON messages terminated
  by NUL) and **opens no port at all**: no other process, of the same user
  or not, can talk to it; there is no `DevToolsActivePort`. Test
  `live_pipe_opens_no_port_and_exposed_port_is_loopback_only`: the command
  line has `--remote-debugging-pipe` and does not have `--remote-debugging-port`, and
  `lsof -iTCP -sTCP:LISTEN` on the browser process lists nothing. It also applies
  to `BrowserCapture::start` and to the App's `run()` (see below).
- **Fidelity measured before switching** (`tests/acceptance/check_multi_target.py`,
  which runs the App's real capture against `testserver /multi/`; Chrome 156,
  macOS arm64; the choice goes through `SCRAPELENS_CDP_TRANSPORT=pipe|port`):

  | Transport | Runs | NetLog | CDP | Targets per marker | Service worker | Setup warnings |
  |---|---|---|---|---|---|---|
  | port (before) | 2 | 16/16 | 16/16 | page, iframe, worker, service_worker | page + SW attached, no duplicate | 0 |
  | **pipe** | **6** | **16/16** | **16/16** | **identical** (13 sessions; same types per marker) | **page + SW attached, no duplicate** | **0** |

  All runs passed the full acceptance (16/16 NetLog, ≥15/16 CDP, types,
  bodies, no merge, SW attached). With no loss of fidelity, **the App's `run()`
  now uses the pipe by default** (`SCRAPELENS_CDP_TRANSPORT=port` goes back to the
  WebSocket); the rest of the App did not change, and the `src-tauri` tests stay
  green. The live tests of `capture/` without `expose_cdp` (allowlist by events,
  8 port paths, symlinks, `site_profile` scenarios) also run
  on pipe.
- **With `expose_cdp: true` the port is inherent to the feature.** It stays like this:
  ephemeral port, `--remote-debugging-address=127.0.0.1` and **without
  `--remote-allow-origins`**. The `lsof` of the same test shows the `LISTEN` only on
  `127.0.0.1:<port>` (nothing on `*` or `[::]`). A WebSocket with
  `Origin: https://evil.example` gets **403**; without `Origin` (us, Playwright,
  Chrome DevTools MCP) it gets **101**. Web pages, therefore, do not reach the
  port.
- **Risk that remains with `expose_cdp:true` (documented, not mitigable here).** The
  port has no authentication. Any process that reaches
  `127.0.0.1:<port>`, **of the same user or of another user of the same
  machine**, reads `GET /json/version` (which returns the browser's WebSocket
  URL) and takes control of the whole Chrome: executing JavaScript in the
  pages, reading cookies and bodies of the session, navigating within the allowlist (the network
  stays limited to the approved hosts, but the process acts with the open
  session). The window goes from launch to `stop_capture`; the port number is
  visible in `ps`, in port scans and in the `DevToolsActivePort` of the temporary
  profile (0700). The gate in §4.1 protects against the agent, not against
  local third parties. Recommendation: `expose_cdp:true` only on a single-user
  machine, for short captures, and the elicitation must show this warning. Without
  `expose_cdp` there is no port and the risk does not exist.

## 3. Tools

Conventions: JSON; errors `{ "error": { "code", "message", "details"? } }`;
`capture_id` is the handle (one active capture at a time in this wave, error
`capture_already_running`).

### 3.1 `start_capture`

Input (snake_case, like the Core tools):

```json
{
  "allowed_hosts": ["example.local:8080"],      // required, >= 1
  "third_party_hosts": ["js.example-cdn.net"],  // optional
  "start_url": "http://example.local:8080/",    // optional, must pass the allowlist
  "binary_path": null,                           // optional; otherwise automatic detection
  "headless": false,                             // default false (real mode); true for tests
  "expose_cdp": false                            // default false
}
```

Output (`StartInfo`, camelCase like the Core outputs; the `capture_id` belongs to the
MCP server, which keeps the `BrowserCapture` in a map):

```json
{
  "sessionDir": "/…/session",
  "chromePid": 1234,
  "browser": { "path": "…", "version": "Chrome/156.0.…", "userAgent": "…" },
  "allowlist": { "allowedHosts": [], "thirdPartyHosts": [], "resolverRules": "MAP * ~NOTFOUND, EXCLUDE …" },
  "cdp": null | { "http": "http://127.0.0.1:PORT", "browserWs": "ws://127.0.0.1:PORT/devtools/browser/…", "pageTargetId": "…" },
  "sensitiveNotice": "…",
  "warnings": []
}
```

Errors (`code`): `allowlist_required`, `allowlist_too_broad`, `allowlist_invalid`,
`allowlist_unsupported` (IPv6), `start_url_not_allowed`, `browser_invalid` (the
`binary_path` is not the stable Chrome, §2.1), `browser_start_failed`,
`session_dir`; `capture_already_running` belongs to the MCP server.

`cdp` only appears with `expose_cdp:true` and only after the gate in §4.1. Without
`expose_cdp` Chrome does not even open the port (pipe, §2.5); with it the port listens only
on `127.0.0.1` and has the risk described in §2.5. `pageTargetId` is the capture tab (the one
`navigate` uses): the agent attaches to it.

### 3.2 `navigate`

```json
{ "url": "http://example.local:8080/p", "wait": "load", "timeout_ms": 15000 }
```

Navigates the capture's **main tab** (`Page.navigate`). `wait`: `"load"`
(default; waits for `Page.loadEventFired` or the deadline) or `"none"`. Output
(`NavigateResult`): `{ "frameId", "loaderId", "loaded": true|false, "errorText": null|"net::ERR_…" }`.
Errors: `url_not_allowed` (with the reason), `capture_stopped`, `navigate_failed`,
`navigate_timeout` (the browser did not respond within the deadline; the capture continues).
`loaded:false` is not an error (deadline or navigation without a load event).

**Deadline (R12).** `timeout_ms` applies to the whole `navigate` (the
`Page.navigate` command and the load wait share a single deadline), with a floor of 2 s and
a 5 s margin for the caller. With Chrome stopped (`SIGSTOP`), the
`navigate(timeout_ms=3000)` that took 30.4 s now returns in 3.3 s with
`navigate_timeout` (the `Page.navigate` without a response within the deadline); `navigate_timeout`
also covers the case in which the capture loop itself does not respond. Live test
`live_navigate_honours_its_timeout_when_chrome_is_frozen`. Side effect: the
load wait counts the time that `Page.navigate` already spent.

### 3.3 `capture_status`

`BrowserCapture::status() → CaptureStatus` (`recording`, `events`, `pageUrl`,
`lastError`): reuse of the App's type.

### 3.4 `stop_capture`

Output (`StopReport`):

```json
{
  "sessionDir": "…",
  "requests": 31,
  "netlog": "complete" | "repaired" | "unusable",
  "graceful": true,
  "waitedMs": 105,
  "allowlist": {
    "blockedHosts": [ { "host": "challenges.example.net", "requests": 2, "exampleUrl": "…" } ],
    "violations": [ { "requestId": "cdp-r0007", "url": "…", "host": "…", "reason": "port 9000 outside the allowlist" } ]
  },
  "warnings": ["…"]
}
```

Graceful shutdown (`Browser.close` + wait + NetLog closed); if it is not
graceful, the session comes out marked incomplete (current behavior).
`allowlist.violations[].requestId` is the logical id of the imported session when the
request exists in it, otherwise `cdp:<session>/<requestId>` (e.g.: WebSocket, which
the import does not keep). The imported session stays in `sessionDir`, with `capture.third_party_blocked` (informational)
and `capture.allowlist_violation` (warning) in the `warnings` of `session.json`, for
the Core tools and for `site_profile`. If the caller drops the
`BrowserCapture` without `stop`, the `Drop` terminates Chrome in the same way.

### 3.5 Second CDP client

With `expose_cdp:true`, the agent will connect its own client to the same Chrome.
Our dedupe by `targetId` only applies to our connection. Measured on loopback
(ignored tests `second_cdp_client_cooperative` and
`second_cdp_client_never_resumes`, Chrome 156, headless): the second client
connects in the middle of the session, attaches to the tab, does `Target.setAutoAttach
{flatten:true, waitForDebuggerOnStart:true}` and the page creates a worker.

| Scenario | Result |
|---|---|
| A. second client resumes the target (`runIfWaitingForDebugger`) | worker received by **both** with `waitingForDebugger:true`; full load; worker reaches the server and enters our session; graceful shutdown |
| B. second client asks for `waitForDebuggerOnStart` and **never** resumes | identical: **our** `runIfWaitingForDebugger` releases the target (the resume applies to the target, not to the session); nothing hangs |

Limits of the measurement: one run of each (repeated 3× without divergence), one type
of target (dedicated worker), a client written by us. **Closed by
design (§4.1):** the agent only receives the address after our
`Network.enable` and the auto-attach are active on the initial tab; targets created
later (workers, popups) follow the setup pipeline measured above. **Not
measured:** clients that use `Fetch` or paused debugging, and the race on
child targets created *afterwards*, in which the agent resumes before our
`Network.enable` arrives (it stayed inside in the tests). Product consequence: our
resume also releases targets that the agent wanted to keep paused.

## 4. Crate `scrapelens-capture` and public API (for the MCP server)

The capture lives in **`capture/`** (crate `scrapelens-capture`, **without Tauri**:
`cargo tree` shows only `scrapelens-core`, `serde`, `serde_json` and `tungstenite`;
0 occurrences of `tauri`). `src-tauri/src/capture.rs` and `chrome.rs` are
thin adapters of the App (`SessionPayload`, `CaptureSession`, `run()` with the
same behavior and the same `CaptureConfig`). The MCP server depends on
`capture/` without pulling in the window.

Public API (`use scrapelens_capture::…`):

```text
// regular capture (the App's)
CaptureConfig { chrome, session_dir, start_url, headless, ignore_cert, network: NetworkMode }
NetworkMode { Open /* default */, LoopbackOnly }   // from_env(): SCRAPELENS_CAPTURE_NETWORK=loopback
CaptureStatus { recording, events, chrome_pid, session_id, session_dir, started_at, page_url, last_error }
CaptureOutcome { session: Value, session_dir: PathBuf, notice: String }
run(config, status: Arc<Mutex<CaptureStatus>>, stop: Receiver<()>, ready: Sender<Result<(),String>>)
    -> Result<CaptureOutcome, String>
default_state_root() -> PathBuf          // capture markers (orphans)
cleanup_orphans(&Path) -> OrphanCleanup  // called by the App at startup
chrome::{detect, normalize_binary_path, candidates, ChromeInfo}   // from the App, permissive
chrome::{validate_chrome, resolve_stable_chrome, ValidatedChrome, ChromeError}  // strict (§2.1)
transport::CdpTransport { Port, Pipe }     // pipe by default; SCRAPELENS_CDP_TRANSPORT=port|pipe

// controlled capture (MCP)
allowlist::Allowlist                      // new(allowed, third_party) -> Result<_, AllowlistError>
  permits_url(&str) -> Result<AllowedUrl, UrlDenied>
  host_allowed(&str) -> bool
  resolver_rules() -> String
  report(&SessionV1) -> AllowlistReport   // blockedHosts + violations
browser::BrowserCaptureConfig { chrome, session_dir, start_url, headless,
                                allowed_hosts, third_party_hosts, expose_cdp }
browser::BrowserCapture
  start(config) -> Result<(BrowserCapture, StartInfo), StartError>
  navigate(&self, url, wait_load, timeout) -> Result<NavigateResult, NavigateError>
  status(&self) -> CaptureStatus
  stop(self) -> Result<StopReport, String>     // StopReport.outcome: Option<CaptureOutcome>
browser::{StartInfo, CdpAccess, NavigateResult, StopReport, StartError, NavigateError, SENSITIVE_NOTICE}
```

The capture thread remains the owner of the CDP socket; `navigate` and `stop` are
messages on a channel consumed by the recording loop (latency ≤ ~250 ms).

### 4.1 Exposed CDP gate

`start` with `expose_cdp:true` only returns `cdp` (`http`, `browserWs`,
`pageTargetId`) **after** our client is attached to the initial tab:
`Network.enable` and `Target.setAutoAttach` with a **success ACK**, session
configured and no setup command pending on it. If that does not happen within
15 s, `start` fails (`browser_start_failed`) and Chrome is terminated; the
address is never handed over. This way the agent cannot act (nor resume paused
targets) before we do. Coverage: unit tests of the gate
(`initial_target_gate_*`), live test `agent_first_action_is_captured` (the
agent's first action, attaching to the capture tab and navigating without waiting, shows up
in `Network.requestWillBeSent` in our session) and a mutation control (with the
gate forced closed, `start` fails and nothing is handed over). Limit: with
`expose_cdp:true` the port exists since launch (also in the
`DevToolsActivePort` of the temporary profile, 0700); a local process that
finds it bypasses the gate. The risk is the one in §2.5 and is outside the model; without
`expose_cdp` there is no port (pipe).

## 5. `site_profile`

Independent crate `recon/` (`scrapelens-recon`, depends only on
`scrapelens-core`), with the signatures as **data** (`recon/signatures.json`) and
tests without network. Input: a captured session (`SessionV1` + `BodySource`
for HTML/JS bodies) and options. Output (camelCase, like the Core):

```json
{
  "schema": "scrapelens.site-profile/1",
  "sessionId": "…",
  "captureContext": { "automationFlagSuppressed": true | false | null, "headless": false | true | null },
  "sample": { "requests": 31, "documents": 3, "appRequests": 12, "partial": false,
              "protocols": { "https://example.test": ["h2"] } },
  "findings": [
    {
      "id": "F001",
      "category": "protection" | "challenge" | "captcha" | "block" | "cookie" | "token" | "protocol" | "third-party-blocked",
      "vendor": "cloudflare" | null,
      "kind": "cookie" | "response-header" | "request-header" | "script-host" | "form-field" | "path" | "status" | "protocol" | "cookie-flow" | "token-origin" | "blocked-host",
      "signatureId": "cf-005" | null,
      "summary": "English text",
      "confidence": "high" | "medium" | "low",
      "occurrences": 3,
      "evidence": [ { "requestId": "cdp-r0004", "attemptId": "cdp-r0004-a1", "scope": "response-header",
                      "field": "cf-mitigated", "value": "challenge", "url": "…", "status": 403, "source": "netlog",
                      "thirdParty": false } ],
      "source": { "kind": "vendor" | "secondary" | "project", "url": "…" } | null,
      "resolvedLater": true | false | null,
      "limits": ["…"]
    }
  ],
  "recommendation": {
    "value": "regular-chrome-suffices" | "needs-priming" | "cloakbrowser-candidate" | "undetermined",
    "confidence": "high" | "medium" | "low",
    "reasons": ["…"], "limits": ["…"], "basedOn": ["F002"]
  },
  "warnings": []
}
```

- `evidence[].requestId`/`attemptId` are the Core ids (`LogicalRequest.id`,
  `Attempt.id`) and resolve in `get_request`. Values: names and URLs always;
  **cookie/header values redacted** (`"[redacted, 32 bytes]"`), except
  documented enumeration values (`challenge`, `captcha`, `protected`,
  `403`), which are the signal.
- `undetermined` is an addition to the leader's request (three values): partial/empty
  session, no main document, or insufficient evidence. Saying that
  "regular Chrome suffices" without evidence would be inventing.

### 5.1 Confidence of a finding

Follows the model of `core/src/assess.rs`: **a marker alone is never a
block**.

| Level | Rule |
|---|---|
| `high` | signature from a **vendor source** that, by its own documentation, indicates a protection action in the response, **on the target site** and **with the documented status** (e.g.: `cf-mitigated: challenge`; `x-amzn-waf-action: challenge` with **202** or `captcha` with **405**; `x-datadomeresponse` ≠ 200) |
| `medium` | vendor signature that shows the product **is present** (`Set-Cookie` cookie, script, header) on the target site, without proof of a block; or two independent indications from a secondary source; or a form field corroborated by a script/header/cookie of the same vendor |
| `low` | a single indication from a secondary source (e.g.: `bm_sz`, `incap_ses_*`); **presence only in a body, query or request cookie** (reflected text, `?g-recaptcha-response=1`, cookie created by `document.cookie`); **block value with a status different from the documented one** (e.g.: AWS WAF `challenge` on 200: presence of the product, not a challenge); **cookie, header or block seen only on a resource of another host** |

Rules from the security review (docs/17, R1 to R4), each with a test in
`recon/tests/profile.rs` (`r1_…` to `r4_…`):

- **Target site** = hosts of the session's top-level documents (third-party
  iframes do not count). A host belongs to the target if it is equal to, or a subdomain (or parent domain) of,
  one of those; there is no public suffix list. Evidence from another host comes out with
  `thirdParty: true`, the finding stays `low` with the limit written, and it **does not enter
  the recommendation**. Script (`script-host`) and form field are
  references embedded by the page itself and are outside this rule.
- **Challenge resolved** only by a later **2xx** response on the same route (a 3xx
  may lead to the challenge itself), or by a clearance cookie (`cf_clearance`,
  `aws-waf-token`) set later **by the same site**; a cookie from another host does not
  clear it.

### 5.2 Generic findings (without a vendor name)

- **Block status**: 403, 429 and 503 on application routes (document or
  XHR/fetch); with `Retry-After` when present (RFC 9110). `high` only when the
  route has no successful response afterwards; otherwise `medium`.
- **Observed protocol** (`h1`/`h2`/`h3` per origin, with the Core's verification
  state): "**observed**", not "required". Proving a requirement
  would need an h1 attempt that failed; a single capture does not prove it.
- **Cookies set by the server and sent back** (`Set-Cookie` in response N
  and `Cookie` with the same name afterwards): "session/guard cookie **observed**"
  (up to 10, the most resent). "Mandatory" is **not** assertable from one
  capture (it requires removing and testing, `validate_run`): the finding says so in `limits`.
- **Dynamic tokens and origin**: for the last successful XHR/fetch requests
  (up to 5, or the given `target_request_id`), it uses `flow::value_origins`
  (Core) and reports header, query and body values (≥ 8 bytes) with an origin
  in an earlier response: `strong` → confidence `medium`; `possible` (same value,
  field with another name) → `low`. Cookie values are left out (they are already the
  cookies finding). Nothing is re-derived here and the value never leaves.
- **Order in time**: `session.requests` is **not chronological** (the Core sorts
  by id; measured on a real session: `cdp-r0004` was the first request). "Before"
  and "after" use the attempt start (`startedAt`) when all have a time, and the
  session order only as a fallback. Suggestion to the Core: document this in
  `docs/16-mcp-contract.md` for whoever reads `list_requests`.
- **Third-party hosts blocked by the allowlist** (`ERR_NAME_NOT_RESOLVED`):
  `third-party-blocked` finding (§2.2).

### 5.3 Recommendation

Deterministic, by rules (evaluation order):

1. `undetermined`: session marked partial/incomplete by the Core, or no
   main HTML document with a response, or fewer than 2 requests.
2. `cloakbrowser-candidate`: **regular Chrome was blocked** on the main
   navigation or on an application route **and there was no later successful
   response on the same route** (not even after a challenge), with at least one
   block finding of `high` confidence (vendor challenge/captcha/403, or
   403/429/503 on the main document). When there is only a CAPTCHA script
   present and the page loaded, it is **not** a candidate. The text says: "regular
   Chrome was turned away; this **does not prove** that CloakBrowser would get through".
3. `needs-priming`: nothing blocked Chrome, but (a) a challenge was served and
   **resolved in the browser itself** (a later successful response on the same
   route, or a clearance cookie after it: `cf_clearance`, `aws-waf-token`) →
   confidence `high`; (b) a **clearance cookie** set by a request
   was sent back in the following ones; (c) there is a **dynamic token** with an origin in an
   earlier response (`token-origin`). Confidence `medium` with (b) or a `strong` token;
   `low` if the only indication is a "possible origin". A **presence** cookie
   (`__cf_bm`, `datadome`, `_px3`, `bm_sv`…) sent back does **not** trigger priming
   (any client with a cookie jar sends it back): it becomes a line in `reasons`.
4. `regular-chrome-suffices`: main document responded, no block
   on the application routes, no resolved challenge and no token. Passive protection
   present (cookie/script) does not change this, but shows up in the findings.
   Confidence `medium` with ≥ 5 requests, otherwise `low`; **never `high`** (one
   navigation does not prove it).

Limits always declared in `recommendation.limits`: sample (one navigation),
site seen only with the allowlist used, absence of human interaction, and that
"blocked" is about this capture.

## 6. Signatures (mandatory source)

Rule: **only a signature with a consulted source enters the delivered table**
(vendor documentation, or a citable secondary source, or a project
fixture). Without a confirmed source: out, listed in §6.2. Sources consulted on
2026-10-31 (reading of public documentation, each page opened directly; no third-party site was
tested or contacted to detect protection).

### 6.1 Delivered

`kind`: **F** = vendor documentation; **S** = secondary source (limits
confidence to `low`/`medium`); **P** = project fixture.

| id | Vendor | Signal | Role | Source | Quote |
|---|---|---|---|---|---|
| cf-001 | Cloudflare | cookie `__cf_bm` | bot management (presence) | F https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/ | "`__cf_bm` … Bot Management, Bot Fight Mode" |
| cf-002 | Cloudflare | cookie `cf_clearance` | challenge resolved | F (same) | "Records that a visitor completed a challenge" |
| cf-003 | Cloudflare | cookie `__cfseq` | order/timing of requests (bot products) | F (same) | "Tracks the order and timing of a user's requests" |
| cf-004 | Cloudflare | cookies `cf_chl_rc_i`, `cf_chl_rc_ni`, `cf_chl_rc_m` | challenge platform | F (same) | "Challenge Platform" |
| cf-005 | Cloudflare | response `cf-mitigated: challenge` | **challenge served** | F https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/ | "present and set to `challenge`" |
| cf-006 | Cloudflare | response `cf-ray` | goes through Cloudflare (weak) | F https://developers.cloudflare.com/fundamentals/reference/http-headers/ | "`Cf-Ray` … Added response headers" |
| cf-007 | Cloudflare | script `challenges.cloudflare.com/turnstile/v0/api.js` | Turnstile widget | F https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/ | "https://challenges.cloudflare.com/turnstile/v0/api.js" |
| cf-008 | Cloudflare | field `cf-turnstile-response` | Turnstile token | F (same) | "`cf-turnstile-response`" |
| aw-001 | AWS WAF | response `x-amzn-waf-action: challenge` with 202, or `captcha` with 405 | **challenge/CAPTCHA served** | F https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html | "header `x-amzn-waf-action` with a value of `challenge` … `202`"; "`captcha` … `405 Method Not Allowed`" |
| aw-002 | AWS WAF | cookie `aws-waf-token` | challenge token | F https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-details.html | "stored in a cookie named `aws-waf-token`" |
| dd-001 | DataDome | cookie `datadome` | identifier/token | F https://docs.datadome.co/reference/validate-request | "`Set-Cookie: datadome=…`" |
| dd-002 | DataDome | response `x-datadome: protected` | goes through DataDome | F (same) | "`X-DataDome: protected`" |
| dd-003 | DataDome | response `x-datadomeresponse: 403` | **block/challenge decision** | F (same) | "`X-DataDomeResponse: 403` … allow (200) or challenge (any other status)" |
| dd-004 | DataDome | request `x-datadome-clientid` | client id sent by the browser/module | F (same) | "request header checked first … ClientID" |
| dd-005 | DataDome | script `js.datadome.co/tags.js` | JS tag | F https://docs.datadome.co/docs/javascript-tag | "`<script src=\"https://js.datadome.co/tags.js\" async>`" |
| dd-006 | DataDome | request `api-js.datadome.co/js/` | signal collection | F (same) | "`api-js.datadome.co/js/` … fingerprint endpoint, POST" |
| dd-007 | DataDome | host `*.captcha-delivery.com` | block page/iframe | F (same) | "`ct.captcha-delivery.com` … `frame-src … *.captcha-delivery.com`" |
| hm-001 | HUMAN (PerimeterX) | cookies `_px`, `_px2`, `_px3`, `_pxhd`, `_pxvid`, `pxcts`, `_pxde`, `_pxac`, `_pxttld`, prefix `_pxff_` | bot detection sensor/session | F https://docs.humansecurity.com/applications-and-accounts/docs/use-of-cookies-web-storage | "Browser cookies" table |
| ak-001 | Akamai | cookie `bm_sv` | Bot Manager (presence) | F https://techdocs.akamai.com/identity-cloud/docs/hosted-login-cookies-and-local-storage-1 | "Cookie used by Akamai Bot Manager to help differentiate … humans and … bots" |
| ak-002 | Akamai | cookie `_abck` | probable Bot Manager | S (Akamai's own cookie list: https://www.akamai.com/legal/manage-cookie-preferences confirms the cookie exists, does **not** describe the function; function at https://scrapfly.io/blog/posts/akamai-bot-manager-understanding-abck-cookies-and-sensor-data) | "_abck … First Party … Strictly necessary" |
| ak-003 | Akamai | cookie `bm_sz` | probable Bot Manager | S https://www.mayoclinic.org/es/about-this-site/privacy-policy/cookie-list | "bm_sz … bot/human analysis" |
| im-001 | Imperva | cookies `incap_ses_*`, `visid_incap_*` | session/visitor (Incapsula) | S https://www.fundacionbancosantander.com/en/cookies | "incap_ses_* … maintain current sessions"; "Visid_incap_# … tracks the HTTP request" |
| rc-001 | Google reCAPTCHA | script `www.google.com/recaptcha/api.js` | v2/v3 widget | F https://developers.google.com/recaptcha/docs/display | "https://www.google.com/recaptcha/api.js" |
| rc-002 | Google reCAPTCHA | script `www.google.com/recaptcha/enterprise.js` | Enterprise widget | F https://docs.cloud.google.com/recaptcha/docs/instrument-web-pages | "https://www.google.com/recaptcha/enterprise.js?render=KEY_ID" |
| rc-003 | Google reCAPTCHA | field `g-recaptcha-response` | token | F https://developers.google.com/recaptcha/docs/display | "g-recaptcha-response POST parameter" |
| hc-001 | hCaptcha | script `js.hcaptcha.com/1/api.js` | widget | F https://docs.hcaptcha.com/ | "https://js.hcaptcha.com/1/api.js" |
| hc-002 | hCaptcha | field `h-captcha-response` | token | F (same) | "adds an `h-captcha-response` token to the form submission" |
| f5-001 | F5 | path `/TSPD/` | protection (a reference alone does not block) | P `core/src/assess.rs` (rules `marker("/TSPD/")`) and `docs/05-detran-reference-case.md` (capture of the reference case) | "Separar proteção (/TSPD/, cookies TS*) da aplicação" (Separate protection (/TSPD/, TS* cookies) from the application) |

Synthetic fixtures (loopback) that **imitate** each signal above for the tests
are labeled as such (`synthetic`): they prove the detector, not the existence
of the protection on any real site.

### 6.2 Outside the table (unconfirmed source)

They do not enter until there is a vendor source or an authorized capture of our own:
Kasada (`x-kpsdk-ct`, `x-kpsdk-cd`, `x-kpsdk-v`, `ips.js`: only third-party
sources that sell workarounds); Imperva `reese84`, `X-Iinfo`, `nlbi_*`; Akamai
`ak_bmsc` (sources diverge on the owner of the cookie); PerimeterX/HUMAN
collector hosts (`*.px-cdn.net`, `client.perimeterx.net`: unconfirmed);
Cloudflare `/cdn-cgi/challenge-platform/` and `server: cloudflare` (they do not appear
in the documentation consulted); AWS WAF `challenge.js` (the host is per customer);
HUMAN/PerimeterX with `_px3` alone is already covered by hm-001.

## 7. Interface with the Core

Only the interface is agreed; the Core does not need to change the model:

1. `site_profile` consumes `SessionV1` + `&dyn BodySource` (already existing,
   `core/src/model`, `core/src/search.rs`) and `core::flow::value_origins`.
2. The evidence ids are those of `LogicalRequest.id`/`Attempt.id`.
3. Value redaction follows the Core policy (redacted by default).
4. Request to the Core: expose `site_profile` as a read tool in
   `docs/16-mcp-contract.md` (`site_profile(session_id, target_request_id?)`),
   calling `scrapelens_recon::site_profile`. Capture delivers the function; the
   registration of the tool in the MCP server belongs to the Core/server.

## 8. Tests and acceptance criteria

Only loopback and synthetic fixtures; no real third-party site.

- Unit (`capture.rs`): `Allowlist` (wildcards, ports, literal IP,
  userinfo, schemes, broad lists), resolver rules, `start` without an
  allowlist, effect classes.
- `recon/`: one test per delivered signature (in-memory synthetic session),
  rule "a marker alone does not block", recommendation in the four values,
  redaction, partial sessions.
- Live (`#[ignore]`, headless Chrome, the test's own loopback server):
  `live_allowlist_cycle` (allowed/refused `navigate`, subresource of an unlisted host
  and literal IP in `blockedHosts`, another port in `violations`,
  graceful shutdown with a complete NetLog), `second_cdp_client_cooperative` and
  `second_cdp_client_never_resumes`, `agent_first_action_is_captured`, and the chain capture → import →
  `site_profile` (`recon/scripts/live_e2e.sh`: three loopback servers
  that imitate documented Cloudflare signals: ordinary site, unsolved challenge,
  challenge resolved in the browser).

## 9. Results and open decisions

Scoreboard (2026-10-31, macOS arm64, Chrome 156.0.8078.74), after the extraction of the
`capture/` crate, the exposed-CDP gate and the fix of the security
review findings (M2, M3, R1 to R4):

| Suite | Result |
|---|---|
| `capture/` `cargo test` | 53 passed, 8 ignored (live); `clippy --all-targets -D warnings` clean; `cargo tree`: only `scrapelens-core`, `serde`, `serde_json`, `tungstenite` and `libc` (0 `tauri`) |
| `capture/` live (`--ignored`, headless Chrome) | `live_allowlist_cycle`, `live_port_gap_is_reported_on_all_paths` (the 8 PoC paths), `live_planted_symlinks_are_not_followed` (symlink PoC), `live_netlog_swap_race_does_not_write_through_a_symlink` (R3), `live_swapped_session_dir_fails_the_stop_without_touching_outside` (A4-B5, A6-B5), `live_any_write_failure_rescues_the_capture_files` (A5-B2), `live_inherited_fds_do_not_leak_into_chrome` (R9), `live_navigate_honours_its_timeout_when_chrome_is_frozen` (R12), `live_oversized_pipe_message_marks_the_capture_incomplete` and `live_oversized_websocket_message_marks_the_capture_incomplete` (A3-B2, A4-B2), `live_pipe_opens_no_port_and_exposed_port_is_loopback_only`, `second_cdp_client_*`, `agent_first_action_is_captured`: 8/8 pass; `live_recon_scenarios` only runs with `SL_RECON_E2E_DIR` (it is the `live_e2e.sh` step) |
| `recon/` `cargo test` | 26 passed (table = §6.1, one fixture per signature, confidence, recommendation in the 4 values, redaction, order in time, R1 to R4); clippy clean |
| `recon/scripts/live_e2e.sh` | 3/3: ordinary site → `regular-chrome-suffices`; unsolved challenge → `cloakbrowser-candidate` (high); challenge resolved → `needs-priming` (high) |
| `src-tauri` `cargo test --lib` | 31 passed, 8 ignored; clippy clean (thin adapter of the App) |
| `tests/acceptance/check_multi_target.py` (regular capture, via the App's `live_bodies_cycle`) | OK: 16/16 NetLog, ≥15/16 CDP |

The numbers above are from the 2026-10-31 closing. The current scoreboards of `capture`, `recon` and
`src-tauri` on the platforms (macOS and Linux) are in `docs/21-linux.md` §1 and §7.1.

Findings that changed the contract: (1) the Chrome 156 resolver **also denies literal
IP** (§2.2); (2) the real gap is the **port**; (3) `session.requests` is not
chronological (§5.2); (4) a reused presence cookie is not priming
(§5.3); (5) the resume of the target by any client releases the target (§3.5).

Limits of this delivery: the `live_e2e` sessions come from servers that **imitate**
the signals; they prove the detector, not the presence of protection on any site.
No real third-party site was accessed: the servers are loopback and the third-party script of the "unsolved challenge" scenario points to a fictitious host (`turnstile.blocked.invalid.test`), which the allowlist denies. The vendor signatures come from
documentation read on 2026-10-31; vendors change signals without notice. The
The limits above are about the detector, not the transport. `site_profile` **is** a tool of the
MCP server (`mcp/src/server.rs`, `site_profile`), and the chaining
`start_capture`→`navigate`→`capture_status`→`stop_capture` is in the same server: it keeps the
`capture_id`, requires user confirmation on `start_capture` and returns the `session_id` that
`list_requests`, `get_request`, `get_body`, `search_bodies`, `diff_requests`, `diff_sessions`,
`trace_value` and `site_profile` itself accept. This section describes the detector and what it
proves; the tool list and the confirmation belong to `mcp/`.

Questions to the leader, with Capture's recommendation:

1. **Strict allowlist vs. third parties** (§2.2): keep it strict with 2 passes
   (`third-party-blocked` indicates what to release).
2. **`act`** out of this wave (§1): keep it so; the agent acts through the CDP port.
3. **`undetermined`** as the fourth value of the recommendation: accept.
4. **New crate `recon/`** outside `src-tauri` and `core`: accept (fast tests,
   reusable by the MCP server without pulling in Tauri).
5. **Who keeps the `capture_id` and confirms `start_capture`**: the MCP server
   (Core or another agent to be defined); Capture delivers `BrowserCapture`.
