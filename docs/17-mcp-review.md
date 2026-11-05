# 17 — Independent security review of the MCP (Round 11)

- **HEAD reviewed:** `3c49b4d`, in a clone at `/tmp/rev25/repo`. The original repository was not changed, except for this file.
- **Scope:**
  - `mcp/`, from `c6bc508` to `6cca5aa`;
  - `capture/src/{allowlist,browser}.rs`, plus `capture/src/{lib,chrome}.rs` when the flow goes through them;
  - `recon/`;
  - the sanitizer in `core/src/export/sanitize.rs`, commits `85e7c13` and `e37d42d`.
- **Contracts:** `docs/16-mcp-contract.md` and `docs/16b-mcp-browser.md`.
- **Method:** code reading and executed PoCs.
  - The PoCs run through the real stdio server (`fake_server`), going through `reply()` and `scrub_output`.
  - To run some tests, they were temporarily copied into the clone and deleted afterwards. The clone's `git status` ended clean.
  - Chrome ran only against 127.0.0.1/localhost. No real site was accessed and nothing was downloaded.
- **Evidence:**
  - `/tmp/rev25/poc-secrets/`: `poc_secrets.rs`, `poc_oracle2.rs`, `poc_secrets_live.rs` and the `*.out` outputs;
  - `/tmp/rev25/poc-fs/`: `poc_orphan.py`, `poc_fs.py`, `poc_race.py` and the `*.out` outputs;
  - `/tmp/rev25/poc-allow/`: `elicit_poc.py` and the allowlist and recon tests.
  - The partial reports are in `/tmp/rev25/{secrets,fs-cdp-chrome,allow-recon}.md`.

**Legend:**
- **CONFIRMED:** reproduced by execution.
- **PLAUSIBLE:** seen only by reading the code.

## Verdict

**REJECTED for closing:** there is one confirmed critical flaw (C1), which defeats the reveal's "double lock" for any session value. The main gates are correct:
- the `expose_cdp` gate;
- the single capture slot;
- the allowlist parser;
- the limits on `session_id` and `name`.

The remaining findings are high, medium or low.

## The 5 most serious

| # | Severity | State | Finding |
|---|---|---|---|
| C1 | Critical | CONFIRMED | `trace_value(value=…)` works as a substring oracle over the original session |
| A1 | High | CONFIRMED | With `--allow-unconfirmed-capture`, an elicitation that errors or is malformed opens the capture |
| A2 | High | CONFIRMED | The final scan and the sanitizer only recognize `?name=value`. The `e37d42d` fix is incomplete for fragment, `;jsessionid`, userinfo and `name=` without `?` |
| M1 | Medium | CONFIRMED | Chrome is orphaned if stdin EOF or SIGTERM arrives during `start_capture` |
| M2 | Medium | CONFIRMED | The browser does not enforce the allowlist port: the tab reaches `localhost:<another port>` through 8 vectors |

## Confirmed findings

### Critical

**C1. `trace_value` is an oracle without reveal.**
- **Location:** `mcp/src/tools.rs:1112-1118`, where the computation always uses `View::original`, and `tools.rs:1277-1299`, with a literal `case_sensitive` search over URL, headers and bodies.
- **Scenario:** the agent calls `trace_value(value="Bearer O")`, `"Bearer OR"` and so on, and reads `producersTotal`/`consumersTotal`. With that it reconstructs, without reveal:
  - `Authorization: Bearer ORACLE16SECRETxyz`, which `get_request` shows as `[REDACTED]`, in 452 calls;
  - a value inside a retained HTML body, in 364 calls;
  - the value of the `sid` cookie from a Set-Cookie, in 352 calls.
- **Contrast:** `search_bodies` already closes this oracle (total=0 in the control); `trace_value` does not.
- **Evidence:** `poc-secrets/poc_secrets.out`, line "ORÁCULO trace_value: reconstruído … em 452 chamadas (sem reveal)" (ORACLE trace_value: reconstructed … in 452 calls (without reveal)), and `poc_oracle2.out`.

### High

**A1. The `start_capture` confirmation is bypassed with the flag.**
- **Location:** `mcp/src/server.rs:74` (`Err(other) => Unavailable`) and `mcp/src/live.rs:184`.
- **Scenario:** the server runs with `--allow-unconfirmed-capture` and the client supports elicitation. The client answers with:
  - a JSON-RPC error ("User rejected"); or
  - `accept` with `{}`, `{"confirmo":"false"}` or `0`.

  Any of these answers is treated as "unavailable", and the capture opens with `confirmation=unconfirmed-flag`.
- **Contract violated:** contract 16 says that a refusal or an unchecked box opens nothing, "even with the flag". Without the flag, all the cases give `confirmation_unavailable`, as expected.
- **Evidence:** `python3 -I poc-allow/elicit_poc.py …/fake_server` → `flag=True JSON-RPC error -> captureId=cap-d141… unconfirmed-flag`.

**A2. The sanitizer and the final scan only recognize `?sensitive_name=value`.**
- **Location:** `core/src/export/sanitize.rs`:
  - `sanitize_text`, lines 739-799, which feeds `scrub_output` in `mcp/src/tools.rs:1459`;
  - `sanitize_url`, lines 692-725, which does not handle the path;
  - `sanitize_url_reference`/`sanitize_path_and_query`, lines 684-690 and 727-732, which ignore `#`;
  - `collect_query`, line 1448, which cuts at `#`.
- **Items that pass without redaction** in `list_requests`, `get_request` and `diff_requests`:
  - `Location: /cb#access_token=X` (fragment in a relative URL);
  - `…/home;jsessionid=MATRIXSID01?x=1` (matrix parameter in the path);
  - `X-Original-Url: https://admin:SEGREDO@…` (userinfo);
  - `Refresh: 0; url=…#access_token=…`;
  - `token=…` without `?`, `token%3D…` and base64.
- **About `e37d42d`:** the fix covers the `startLine` with `?token=`, verified on the request and response lines. The formats above still leak.
- **Regression test:** the test from `6cca5aa` uses only `?token=MARK`, which is the only format the scan recognizes, and so it detects none of these cases.
- **Evidence:** `poc-secrets/poc_secrets.out`.

### Medium

**M1. Orphaned Chrome when EOF or SIGTERM arrives during `start_capture`.**
- **Location:** `mcp/src/app.rs:63-74`, `mcp/src/live.rs:472-478` and `mcp/src/main.rs:15`.
- **Cause:** `stop_all` only stops `Slot::Running`. In the `Starting` slot, Chrome has already been created inside the `spawn_blocking`, but `process::exit` runs without going through `ChromeProcess::drop` or `OrphanMarker::drop`. The MCP server also never calls `cleanup_orphans`.
- **What is left behind:**
  - Chrome, with CDP open on 127.0.0.1, writing the NetLog to `capture-<ms>`;
  - the profile and the marker.
- **Evidence:** `poc-fs/orphan_eof.out` and `orphan_sigterm.out` record "chrome procs left after server exit: 8 / 7", and `/json/version` of the orphan returned `webSocketDebuggerUrl`. The control, with EOF after the start, recorded 0 processes.

**M2. The port is not enforced in the browser.**
- **Location:** `capture/src/lib.rs:466` and `capture/src/allowlist.rs:215`.
- **Scenario:** with `allowed_hosts=["localhost:P1"]`, the page reached `localhost:P2` through 8 vectors: top-level 302, `location=`, meta refresh, `window.open`, iframe, fetch, WebSocket and uppercase. The tab ends up on an unapproved host:port, under the agent's control.
- **Notice to the user:** the elicitation shows only "localhost:P1", without warning that the other local ports (Redis, admin) remain reachable.
- **Status in the contract:** it is a declared gap, but with no notice to the user.

**M3. `binary_path` executes any file.**
- **Location:** `capture/src/chrome.rs:48` and `:80`, which only check `is_file()`.
- **Scenario:** `normalize_binary_path("/bin/echo")` returns `Some`, and `detect` gives `found=true`.
- **Contract violated:** §2.1 says "stable Chrome only".
- **Mitigating factor:** the path appears in the elicitation, but without escaping. With A1, or without elicitation, not even that gets seen.

**M4. The `get_body` spill writes outside `--out-dir` through a symlink.**
- **Location:** `mcp/src/tools.rs:778-795`. The temporary name is fixed (`.tmp-<pid>`) and opens with `create|truncate`, without `O_NOFOLLOW` or `O_EXCL`.
- **Scenario:** a process of the same user with write access to the out-dir plants the symlink. The body is written to the external target with mode 0644, and the `rename` moves the symlink itself to the returned `path`.
- **Evidence:** `poc-fs/poc_fs.py` T2.

**M5. Obvious credential names are left out of the sensitive-name lists.**
- **Location:** `sanitize.rs:892-940` (`is_sensitive_header`) and `949-1020` (`is_sensitive_key`).
- **What leaks:**
  - in the query, `jwt`, `auth_key`, `ticket` and `SAMLResponse`;
  - in the form, `senha` and `pwd`, with `search_bodies` returning `snippet:"SENHAFORM03"`;
  - in JSON, `pin`, `otp` and `auth_key`;
  - in headers, `Ocp-Apim-Subscription-Key` and `X-VTEX-API-AppKey`.

**M6. The Set-Cookie `parseError` repeats the raw value.**
- **Location:** `sanitize.rs:426-445`, which does not touch `parse_error`; the message comes from `core/src/model/cookies.rs:219-222` and is emitted in `mcp/src/project.rs:128-130`.
- **Scenario:** `Set-Cookie: NAMELESS29xx; Path=/` produces `"raw":"[REDACTED]","parseError":"…\"NAMELESS29xx\""`.

**M7. The site_profile gives `medium` for presence only in the body or the query.**
- **Location:** `recon/src/detect.rs:358-400` and `:442`.
- **Scenario:**
  - reflected text `name="cf-turnstile-response"` on a search page gives `cf-008 captcha Media [response-body]`;
  - `?g-recaptcha-response=1` gives `rc-003 Media`.

  Both are attacker-controllable.
- **Contract violated:** §5.1 requires `low`.

**M8. `x-amzn-waf-action: challenge` with status 200 gives `Alta` and `CandidatoACloakbrowser`.**
- **Location:** `detect.rs:490-502`.
- **Contract violated:** §5.1 requires 202 or 405. The divergence becomes only a text in `limits`.

**M9. A block on a subresource from another host decides the recommendation.**
- **Location:** `detect.rs:220` and `recon/src/recommend.rs:67-74`.
- **Scenario:** `cf-mitigated: challenge` on an image at `cdn.other.test/pixel.png`, with the document and the XHR at 200, generates `CandidatoACloakbrowser`.
- **Contract violated:** §5.3 requires the block on the main navigation or on an application route.

**M10. "Challenge solved" with `Alta` from weak evidence.**
- **Location:** `detect.rs:413`, where `is_success` accepts 3xx, and `:419-440`.
- **Scenarios:**
  - (a) a 403 followed by `302 Location: /__challenge` produces `PrecisaDePriming Alta`;
  - (b) `cf_clearance` set by another host marks the `app.test` challenge as solved.

### Low

- **B1. `ensure_private_dir` acts before `is_within`.** Location: `tools.rs:758-769` and `core/src/store.rs:52-57`. With `bodies/` as a symlink, it does `create_dir_all` and chmod 0700 on the external target before returning `outside_allowed_dir` (`poc_fs.py` T1).
- **B2. Race on the `.tmp-<pid>` shared between concurrent `get_body` calls.** In 400 concurrent spills, 390 gave ENOENT and 10 returned files with the content of another slice (`poc_race.py`). It can mix bytes from a call with reveal into a `.masked` file.
- **B3. `session.json` as a symlink reads outside the roots.** Location: `mcp/src/registry.rs:159-168`; only the directory is canonicalized (T3).
- **B4. `slug` collides handle names.** Location: `mcp/src/config.rs:74-91`. `x.y` and `x-y` share the spill directory and one overwrites the file returned to the other (T5).
- **B5. The authentication scheme is only recognized with the exact case.** Location: `sanitize.rs:672-681`. `"bearer …"` in JSON leaked in `get_body`; `ApiKey`, `OAuth` and `SharedKey` are not recognized.
- **B6. `--remote-allow-origins=*`.** Location: `capture/src/lib.rs:437`. A WS handshake with `Origin: https://evil.example` received 101. `/json/version` does not send ACAO, so this is only defense in depth. In addition:
  - the port listens on 127.0.0.1, within reach of other users of the system;
  - `chromePid` is output even with `expose_cdp=false`, and the contract accepts that.
- **B7. WebSocket outside `session.json`.** The WS shows up in the NetLog and in CDP, but is lost on import and therefore stays out of the `violations`.
- **B8. A literal IP in the allowlist is accepted, but never loads.** `resolver_rules` skips IPs (`allowlist.rs:219`) and `MAP * ~NOTFOUND` denies access, which gives `ERR_NAME_NOT_RESOLVED`. It contradicts §2.2.
- **B9. A cookie only on the request gives `medium`.** A cookie that appears only on the request, and that can come from `document.cookie`, gives `medium` for DataDome and HUMAN.

## Addendum: late confirmations from the filesystem and CDP front

These results arrived after commit `f7cb0fa`.

- **M4 became broader (Medium, CONFIRMED):**
  - **Locations:** the same pattern appears in `core/src/store.rs:59-78` (`write_atomic`) and in `capture/src/lib.rs:1903-1917` (`open_private`). Both open a fixed name with create+truncate, without `O_NOFOLLOW`/`O_EXCL`.
  - **Effect:** with a symlink planted in the session directory, the live capture's CDP events (4745 B) and the full `session.json` were written outside `--sessions-dir`.
  - **Evidence:** `poc-fs/poc_capture_symlink.py`.
- **B6 rises to Low/Medium (CONFIRMED):** the DevTools port is reachable from launch, before the gate (`capture/src/lib.rs:435-437`).
  - **Test:** `curl 127.0.0.1:<port>/json/version` returned `webSocketDebuggerUrl` before `Network.enable`/autoAttach.
  - **Effect:** any local process, including one from another user of the system, can sweep the ephemeral port and control the browser. The gate only stops the *MCP* from handing out the address early; it does not stop direct access to the port.
  - **Contract:** §4.1 of 16b relies on the 0700 profile, which does not protect the port.
- **P2 confirmed (Low):** the test in `poc-fs/poc_cancel.py` cancels the confirmation and then accepts. The capture opens, the client never receives `capture_id` and every following `start_capture` returns `capture_already_running`. The comment at `server.rs:44-46` says the slot is released on cancellation, but rmcp 3.8 does not drop the handler.

## Plausible findings (reading only)

- **P1 (Medium).** `stop_capture.warnings` carries the raw URL of the violation.
  - The message is built in `capture/src/lib.rs:381-391` and uses `allowlist.rs:321-323`.
  - `mask_urls`, in `mcp/src/live.rs:504-519`, only handles the keys `url`, `exampleUrl` and `pageUrl`.
  - So `violations[].url` comes out masked, but `warnings[]` keeps the query, `;jsessionid` and fragment.
  - Already confirmed: `scrub_output` leaves this string intact. The end-to-end test was missing, because the fake_server does not generate violations.
- **P2 (Low).** If the client gives up on `start_capture` (up to 5 min of elicitation plus 90 s of start), the future is not cancelled and Chrome opens anyway.
  - The client never receives the `capture_id`, and there is no tool to list captures.
  - Until the server restarts, every `start_capture` returns `capture_already_running`, and the capture keeps recording for up to 30 min.
  - Location: `mcp/src/server.rs:241-289`.
- **P3 (Medium).** A script can take the top-level tab to a host in `third_party_hosts`, which the user approved only as a subresource origin. It is the same class as M2.
- **P4 (Low).** On APFS, `name:"VICTIMSESS"` collides with an existing `victimsess`, which leads to `exists` or to a handle that does not open.
- **P5 (Low).** A token in a path segment (`/reset/<token>`) or in a neutral JSON key gets through. It is a limit of the heuristic.

## Verified and clean

- **`expose_cdp` gate** (`capture/src/lib.rs:206-250`):
  - the endpoint is only filled in after `wait_initial_target_ready`, and the `StartInfo` is only built with the target ready;
  - on the error, timeout and stop paths, Chrome is killed without the WS URL moving forward;
  - `CaptureStatus`, `StopReport` and stderr do not carry the endpoint;
  - `cargo test --offline --lib initial_target_gate`: 2 passed.
- **One capture at a time:** `prepare` checks and inserts under the mutex, and cancellation does not release the slot. Errors in `stop` and `navigate` and panics in the thread kill Chrome; on a panic, only the profile is left behind.
- **Paths:**
  - `valid_name` only accepts ASCII, refuses a leading `.` and limits the length to 128, which blocks `..`, `/`, absolute path, NUL and Unicode;
  - the `sessions-dir` and `out-dir` symlinks are canonicalized at startup;
  - a session directory that is a symlink to the outside is refused;
  - attachments have a validated name, refuse symlinks and check ino/dev again;
  - import uses a temporary file plus rename and never overwrites.
- **Permissions:** directories 0700 and files 0600; the Chrome profile is 0700, in the user's TMPDIR.
- **Allowlist (parser, 49 URLs):** refuses:
  - userinfo, `%40` and `\`;
  - trailing dot and non-ASCII hosts;
  - decimal, octal, hex and short IPv4;
  - the schemes `ws`, `blob`, `filesystem`, `javascript`, `data`, `file`, `chrome`, `view-source` and `about:` (except `about:blank`).

  The wildcard does not match the base, `evil-allowed.com` or `allowed.com.evil.com`. In Chrome, layer 1 denies `0.0.0.0`, `[::]`, `[::ffff:7f00:1]`, `foo.localhost` and `localhost.`. `navigate` and `start_url` go through `permits_url`.
- **Elicitation:**
  - the hosts are strict ASCII, so the text cannot be forged with Unicode or userinfo;
  - extra fields in `accept` are ignored;
  - `cancel`, `decline` and timeout give `denied`.
- **Secrets:**
  - `Authorization`, `Cookie` and `Set-Cookie` (`raw`/`pairs`/`wireLines`);
  - request and response `startLine` with `?token=`;
  - `api%5Fkey` and case variations;
  - absolute `Location`, `Referer` and `Origin`;
  - `target`, `initiator`, notes, `failure` and warnings;
  - HTML, text and multipart bodies;
  - `search_bodies` does not work as an oracle;
  - `site_profile` comes out with `[redigido, N bytes]` ([redacted, N bytes]);
  - `start_url` with userinfo is refused;
  - `revealed:true` requires `--allow-reveal`.

## Not verified

- System proxy and WebRTC bypassing Chrome's resolver.
- Whether the site_profile confidence takes the provenance of the evidence into account (HAR × CDP/NetLog).
- The end-to-end test of P1 with a real violation.

---

## Addendum 2: confirmation of the fixes (Round 11)

- **HEAD:** the review was done in the new clone `/tmp/rev26/repo`, at `eb66afa`, which includes the fixes:
  - core: `3bcbd20`, `7637bac`, `b0c0596`, `dd6cf7a`, `6840670`, `3939881`, `071d132`;
  - capture: `485f6a3`, `d3f194f`, `3e6ad05`, `3c7e4af`, `8e0e575`, `eb66afa`.
- **Evidence:**
  - reproduction tests and outputs in `/tmp/rev26/poc-secrets`, `/tmp/rev26/poc-fs` and `/tmp/rev26/poc-allow`;
  - partial reports in `/tmp/rev26/{secrets,fs-cdp-chrome,allow-recon}.md`.
- **Restrictions respected:** Chrome only ran against 127.0.0.1 and localhost. The Chrome.app copies stayed in `/tmp`, and `/Applications` was not changed.

### Verdict: REJECTED

All the earlier findings are fixed or are now reported as the contract foresees. Even so, the new "stable Chrome only" validation has **two confirmed high bypasses**, and the elicitation text does not carry the §2.5 warning that 16b requires.

### State of the earlier reproduction tests

| Finding | State | Evidence |
|---|---|---|
| C1 `trace_value` oracle | Fixed | The prefix stops after 62 calls and the output says `exact-value-match`. The substring oracle is closed: JWT parts, items of `a=b; c=d` and case variation do not match. |
| A1 elicitation with error or malformed | Fixed | With and without the flag, only `confirmo:true` opens; the rest gives `confirmation_denied`. |
| A2 fragment, matrix, userinfo, `token=` without `?`, `%3D` | Fixed | The markers come out masked (e.g. `;JSESSIONID=%5BREDACTED%5D`). |
| M5 credential names | Fixed | The 20 markers come out masked. |
| M6 Set-Cookie `parseError` | Fixed | Comes out masked. |
| B5 authentication schemes | Fixed, with an exception | A TAB after the scheme still escapes (R6). |
| P1 `stop_capture` warnings | Fixed | The warning comes out without the query. |
| M1 Chrome orphaned by EOF or SIGTERM at start | Fixed | No process, profile or marker is left. |
| M4 write through symlink (spill, `write_atomic`, `open_private`) | Fixed | The outside files stay intact; the NetLog still leaks (R3). |
| B1–B4 (chmod before `is_within`, race, `session.json` through symlink, slug collision) | Fixed | 400 concurrent calls with no error; the slug gained a hash suffix. |
| B6 DevTools port and `remote-allow-origins=*` | Fixed with the pipe | With `expose_cdp=false` there is no port. With `expose_cdp=true`, the port answers before the gate (at 0,78 s; the start returns at 6,52 s), an accepted risk. A forged Origin gets 403. |
| P2 cancel and then accept | Fixed | The slot is released and the late accept is ignored. |
| SIGKILL of the server | Fixed with the pipe | Chrome exits in under 1 s. In port mode, it stays alive until the next start cleans it up. |
| M3 `binary_path=/bin/echo` | Fixed | `NotABundle`. The new bypasses are in R1 and R2. |
| M7–M10 and B9 (site_profile confidence) | Fixed | The weak signals come out as `Baixa`, and `resolvedLater=false` in cases (a) and (b). |
| B7 WebSocket outside the session | Fixed | It now goes into `violations`. |
| B8 literal IP | Fixed | `EXCLUDE 127.0.0.1` is in the rules and the navigate loads. |
| M2 port (8 vectors) and P3 | Allowed by the contract and reported | The 8 vectors, including WS, iframe, fetch and `window.open`, and the top-level navigation to a third party appear in `violations`. |

### Remaining findings

#### High

**R1. The signature validation is fooled by a line break in the path (CONFIRMED end to end).**
- **Location:** `capture/src/chrome.rs:287-306` reads `Identifier=` and `TeamIdentifier=` from the first matching line in the `codesign -dv` output, and the `Executable=<path>` line comes before them. `codesign --verify` does not check any requirement (`-R`).
- **Scenario:** an ad hoc signed bundle at `inj\nIdentifier=com.google.Chrome\nTeamIdentifier=EQHXZ8M8AV\nx/Google Chrome.app` passes `validate_chrome`. Through the real `scrapelens-mcp`, after the confirmation, the marker binary executed (`PWNED-inj argc=28`).
- **In the elicitation:** the path also appears without escaping (`mcp/src/live.rs:327/343`), and the line break injects fake lines into the text.
- **PLAUSIBLE:** a self-signed certificate with OU=EQHXZ8M8AV would pass even without the line break. I did not test it, because it would require changing the keychain.
- **Suggestion:** `codesign --verify --deep --strict -R='anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'`, without parsing the `-dv`, and refuse control characters in the path.

**R2. A signed copy with a swapped helper passes, and the helper executes (CONFIRMED).**
- **Location:** `chrome.rs:277-281` verifies without `--deep`, as 16b §2.1 (line 43) prescribes.
- **Scenario:** a copy of Chrome.app in `/tmp` with `Helpers/Google Chrome Helper.app/.../Google Chrome Helper` replaced by a script passes the validation, and the script runs as the network service process (marker `PWNED-helper`). With `--deep --strict`, the swap is detected.
- **Contract:** the statement in 16b (line 47) that the script never runs is false in this case.
- **Side effect:** the copy's crashpad pointed to the real Crashpad folder of the user's Chrome.

#### Medium

**R3. Chrome writes the NetLog through a symlink (CONFIRMED).**
- **Location:** `capture/src/lib.rs:173` creates and closes `netlog.json`, then Chrome opens the file by path (`lib.rs:479`, following the symlink); `lib.rs:366` rereads it by path.
- **Scenario:** with `poc_netlog_race.py`, a process of the same user swapped the file for a symlink. An outside file, with mode 0644, received 236.913 bytes of full NetLog, with cookies and headers. It is the M4 class again, through another path.

**R4. The elicitation text does not warn about the lack of authentication with `expose_cdp=true`.**
- **What the contract requires:** 16b §2.5 says "The port has no authentication…" and "the elicitation must show this warning" (line 209).
- **What appears:** the real text only shows "CDP entregue ao agente (controle do navegador): SIM" (CDP handed to the agent (browser control): YES), and there is no equivalent warning in `mcp/src`.
- **Other gaps:** line 417 of 16 omits the lack of authentication, and the table in 16b §2.3 cites the §2.4 warning, but not the §2.5 one.
- **Port:** it is clear in 16b §2.2, in 16 (line 384) and in the elicitation text (`live.rs:328`, "aprova, para a página, esse host em QUALQUER porta…" (approves, for the page, this host on ANY port…)). It only lacks saying that the violations are reported, not blocked, and that top-level navigation to a third party is allowed.

**R5. Brute force of the whole value in `trace_value` (CONFIRMED).**
- **Location:** `mcp/src/tools.rs:1458` (`trace_exact`). There is no rate limit, and a hit names the field.
- **Scenario:** 10.000 guesses of 4 digits took 10,8 s (debug build) and found `4821@requestBody:pin` and `7351@cookies:sid`. A 6-digit code takes about 18 min.
- **Aggravating factor:** `trace_value(cookie)` also exposes `valueLength` (`tools.rs:1272/1295`).

**R6. Nested percent-encoded URL is not redacted (CONFIRMED; old gap).**
- **Location:** `core/src/export/sanitize.rs:818` and `:916`.
- **Scenario:** `?next=%2Fcb%3Ftoken%3DNESTED01x` and `redirect_uri=…%23access_token%3DNESTED05x` leak in `list_requests` and `get_request`; the same holds for Location and `X-Note`. This is the normal format of redirect_uri and returnTo in OAuth.

#### Low

- **R7. UTF-8 panic introduced by the fix (CONFIRMED).**
  - **Location:** `mcp/src/tools.rs:1479` slices `text[..scheme.len()]` by byte.
  - **Scenario:** a header with a multibyte character between bytes 6 and 7 (e.g. an accent in pt-BR) makes every `trace_value(value)` fail on that session. The panic message exposes 1 raw character.
- **R8. TAB after the authentication scheme escapes (CONFIRMED).** Location: `sanitize.rs:694`. Example: `Bearer\t…` in JSON or in a header.
- **R9. File descriptor usage (CONFIRMED).** Location: `lib.rs:540-555`. The descriptors the server inherits from whoever launched it leak into Chrome; for example, an fd 7 for `launcher-secret.log` appears open in Chrome. The server's own fds do not leak, and Chrome only has the pipes on 3 and 4.
- **R10. SIGTERM during `stop_capture` loses the session (CONFIRMED 3/3).**
  - **Location:** `mcp/src/live.rs:559` removes the slot beforehand, so `stop_all` (`:588`) does not wait. Only `cdp-bodies.jsonl` and `netlog.json` are left, without `session.json`.
  - **Same gap:** the stop thread of `abandon()` (`live.rs:379`).
  - **PLAUSIBLE:** an orphaned Chrome in port mode.
- **R11. Race between validating and executing the binary (CONFIRMED, 1 in 60).** Location: `browser.rs:212` and `lib.rs:534`. R2 makes the race unnecessary.
- **R12. Pipe messages without a size limit, and navigate timeout not enforced.**
  - **Pipe:** `transport.rs:154` has no ceiling; the old WebSocket had 64 MiB.
  - **Navigate:** with Chrome frozen, `navigate(timeout_ms=3000)` took 30,4 s.
- **R13. Too much redaction (CONFIRMED).** Location: `sanitize.rs:1136-1142`. A whole support `ticket` object, `pin: true`, `jwtExpiresIn` and `shotp` are redacted.
- **R14. The final `scrub_output` scan fell behind.** Location: `tools.rs:1809`; it only looks at strings with `?`. No real output depends on it today.
- **Informational:**
  - the pipe descriptors are left without CLOEXEC before the dup2 (`transport.rs:242-258`). This can leak to a concurrent `codesign`, but it is PLAUSIBLE and not confirmed on macOS;
  - `ps` and `kill` are still found through the PATH (`lib.rs:715-741`).

### Verified and clean

- **Starting, Opening and Running states:**
  - a concurrent start receives `capture_already_running`;
  - cancelling while Chrome is coming up releases the slot after the open without leaving Chrome behind;
  - the shutdown flag and the in-flight starts counter are correctly ordered.
- **Pipe transport:**
  - a message without a terminator or a Chrome that dies in the middle of a message end the capture cleanly;
  - with Chrome stopped by SIGSTOP, the stop finishes in 22,5 s by killing the process;
  - Chrome's helper processes do not inherit the pipes.
- **Chrome accepted in the validation:**
  - a symlink to the `.app` or to the binary resolves to `/Applications`;
  - a path starting with `-` becomes absolute and does not inject an argument;
  - `codesign` and `plutil` are called by absolute path;
  - altered Info.plist, swapped main executable and extra file in MacOS are refused;
  - Beta, Canary, Chromium and Chrome for Testing are refused by the exact bundle ID (by code reading only, because they are not installed).
- **`--remote-allow-origins=*` removed:** a forged Origin, `127.0.0.1` and `localhost` get 403, and `/json` does not send ACAO.

---

## Addendum 3: confirmation of addendum 2 (Round 11)

- **HEAD:** the review was done in the new clone `/tmp/rev27/repo`, at `03ee85c`, which includes the fixes:
  - core: `5cdac78`, `f4f5c63`, `f276ba8`, `e5e45c1`;
  - capture: `f437051`, `288b2d3`, `03ee85c`.
- **Evidence:**
  - reproduction tests and outputs in `/tmp/rev27/poc-secrets` and `/tmp/rev27/poc-cap`;
  - partial reports in `/tmp/rev27/{secrets,cap}.md`.
- **Restrictions respected:** Chrome only ran against loopback. The Chrome.app copies stayed in `/tmp`, and `/Applications` was not changed.

### Verdict: REJECTED

There are two **confirmed medium** findings, and one of them is a regression introduced by `5cdac78`. There is no high finding. The accepted risks did not weigh on the verdict.

### R1–R14

| Item | State | Evidence |
|---|---|---|
| R1 line break in codesign and in the elicitation | Fixed | The path is refused before the elicitation (`browser_invalid … inj\nIdentifier=…`) and the marker does not run. |
| R2 swapped Helper | Fixed | `codesign --verify --deep -R='anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'` (`chrome.rs:314-318`) returns `BadSignature`. The decision uses only the exit code, with no text parsing. |
| R3 NetLog through symlink | Fixed | The NetLog stays in the 0700 profile and the copy uses `create_new` + `O_NOFOLLOW` + rename. The victim file stayed intact and the destination comes out 0600. |
| R4 CDP-without-authentication warning | Fixed | Real text: "SIM — ATENÇÃO: a porta CDP não tem autenticação; qualquer processo local pode controlar o Chrome inteiro (todas as abas, cookies, sessões abertas)" (YES — WARNING: the CDP port has no authentication; any local process can control the whole Chrome (all tabs, cookies, open sessions)). |
| R5 brute force on `trace_value` | Partial | `value_too_short` below 16 characters and `value_query_limit` at query 51 work, but the ceiling can be bypassed (A3-M1). |
| R6 nested percent-encoded URL | Fixed at one level | NESTED01–05 come out masked. A3-M2 and A3-B1 remain open. |
| R7 UTF-8 panic | Fixed | `abcdé€€€€` returns an error, without a panic. |
| R8 TAB after the scheme | Fixed in headers and JSON | In free text, `bearer SEC4` and `Basic\tSEC9` still get through (Low). |
| R9 inherited fds | Fixed | `launcher-secret` does not appear in any Chrome pid; in pipe mode, fds 3 and 4 are still pipes. |
| R10 SIGTERM during the stop | Fixed | With pipe, with port and with EOF, the `session.json` is written and no Chrome is left. The wait has a ceiling of 120 s (`live.rs:617`), with no deadlock. |
| R11 TOCTOU between the check and the exec | Still reproduces (accepted risk) | Won 2 of 5 attempts. It is documented in 16b, lines 64-70. |
| R12 pipe and navigate | Fixed | Navigate with Chrome stopped fails in 3,3 s (before, 30,4 s). A 140 MB message hits the ceiling. |
| R13 too much redaction | Partial | `pin:true`, `jwtExpiresIn` and `shotp:1` now appear. The `ticket:{id,title}` object is still entirely redacted (Low). |
| R14 `scrub_output` | Fixed | `#id_token=`, `token=` without `?` and userinfo come out masked. |

### Remaining findings

#### Medium

**A3-M1. The 50-query ceiling of `trace_value` resets to zero when the session is reimported (CONFIRMED).**
- **Cause:** the counter lives in memory, per handle (`mcp/src/registry.rs:137`), and `import_session` (`mcp/src/tools.rs:243`) accepts reimporting `sessions_dir/<handle>` with any new `name`.
- **Why the 16-character minimum is not enough:** when a short secret comes inside a known structure, the guess includes that known part, for example:
  - `Basic base64("admin:PIN")`, which has exactly 16 characters;
  - an id with a fixed prefix, such as `acct-000000000000-NNNN`.
- **Evidence:** 11.064 queries and 222 reimports in 34,8 s recovered `4821` from the Authorization and `5531` from X-Session.
- **Side effects:**
  - each reimport writes a full copy of the session to disk;
  - `trace_value(cookie)` still exposes `valueLength` without reveal (`tools.rs:1282/1305`).

**A3-M2. Regression from `5cdac78`: a non-sensitive `name=value` without `%` is copied whole (CONFIRMED).**
- **Location:** `core/src/export/sanitize.rs:952-965`. The `?token=` or `pin=` that sits inside the value is never examined.
- **Before `5cdac78`** (binary r26): `Refresh: 0;url=/d?pin=%5BREDACTED%5D&…&shotp=%5BREDACTED%5D`.
- **Now:** `Refresh: 0;url=/d?pin=1234&page=2&opinion=good&shotp=1&ticket_type=vip`.
- **Also leaking now:**
  - `X-Note: redirect=https://h/cb?access_token=RAWNEST09x`;
  - `go next=/cb?token=RAWNEST10x`;
  - the JSON string `"note":"next=/cb?token=RAWNEST01x"`.
- **Already leaked before, in `sanitize_query` (`:1024-1034`):** `?next=/cb?token=URL1x` and `Location: /cb?next=/x?access_token=RAWNEST11x`.
- **Evidence:** `/tmp/rev27/poc-secrets/zz_sec27_r27.out` (current) compared with `zz_sec27_r26b.out` (before).

#### Low

- **A3-B1. Double-encoded value at the first level is not redacted (CONFIRMED).**
  - **Location:** `sanitize.rs:896`.
  - **Examples:** `c=%2Fcb%253Ftoken%253DX`, `X-Dbl: x%253D1%2526token%253DX` and `token+%3DX`.
  - **Works:** lowercase `%3d` and 4-level nesting.
- **A3-B2. A message above 128 MiB on the pipe ends the capture as `complete` (CONFIRMED).**
  - **Scenario:** `console.log("x".repeat(140e6))`. `TooLarge` is handled as `Close` (`capture/src/transport.rs:238`), Chrome exits with `Graceful(0)` and `mark_incomplete` returns early (`lib.rs:1946`), which gives `completeness.state="complete"` with `reasons=[]`. The only signal is `graceful:false` in the StopReport.
  - **Contract:** contradicts 16b, line 222 ("the session comes out marked as incomplete").
  - **Also:** the navigate wait loop (`browser.rs:440-446`) does not exit when the transport closes; it waited 60 s and returned Ok with `loaded:false`.
- **A3-B3. A symlink planted at `netlog.json` after the copy makes `stop_capture` fail (CONFIRMED, same user).**
  - **Cause:** core rewrites the file with `write_atomic` (`core/src/store.rs:197`), which refuses symlinks.
  - **Result:** `stop_failed … recusado` (refused) and no `session.json`. The victim file stays intact; the effect is only denial of service.
- **A3-B4. Bearer and Basic with TAB or lowercase in free text still get through (CONFIRMED).**
- **A3-B5. The `ticket:{id:42,title:"Suporte"}` object is still entirely redacted (CONFIRMED).**

#### Informational

- **Invisible characters in `escape_display`** (`mcp/src/live.rs:666`): U+061C, U+180E, U+00AD, U+206A-206F, U+3164, U+2800, the U+E00xx tags, U+00A0/U+3000 and combining marks get through.
  - Only the `binary_path` can carry them, and it has to be a valid signed Chrome.
  - There is no line injection; the risk is only limited visual spoofing (PLAUSIBLE).
- **Bidi and zero width in the path:** they pass through `chrome.rs:233`, the elicitation escapes them, but the `NotFound` message (`chrome.rs:246`) does not.
- **Navigate error code:** with Chrome frozen, `navigate_failed` comes out, not `navigate_timeout`.
- **Validation time:** codesign takes 9–13 s per verification.

### Accepted risks: the documentation is clear

16b describes all of them, with one exception:

| Risk | Where | Text |
|---|---|---|
| TOCTOU | lines 64-70 | "`--deep` makes the window small, but does not close it" |
| Same user with the temporary profile | lines 204-206 | "a process of the same user that finds the profile by name can still tamper with it" |
| Pipe queue | line 225 | "with no count limit on purpose" |
| Window without CLOEXEC | lines 86-89 | "I did not measure or reproduce it" |
| Partial NetLog after SIGKILL | line 207 | confirmed: the 208 KB were deleted at the next start |

The exception is **line 222**, which is inexact (see A3-B2).

### Verified and clean

- **codesign:**
  - accepts the Chrome in `/Applications` and an intact copy;
  - refuses an extra file (Frameworks, MacOS or root), new symlink, resource swapped for a symlink, edited Info.plist, swapped executable and edited framework;
  - the `-R` is actually applied (wrong OU gives rc=3);
  - refuses `\n`, `\r`, `\t`, NUL, ESC, DEL and C1 in the path.
- **CLOEXEC:** fds from 5 onward close on exec.
- **stops_in_flight:**
  - a second stop gives `capture_not_found`;
  - SIGTERM, SIGTERM and SIGINT during the stop wait for the session to be written.
- **Profile:** it is removed after the stop.
- **Performance:** the sanitizer stays linear with 1 MB of adversarial input (worst case 715 ms).

---

## Addendum 4: confirmation of addendum 3 (Round 11)

- **HEAD reviewed:** `61ad875`, in a new clone at `/tmp/rev28/repo`.
- **Fixes checked:** `419c207`, `d2a0ca6`, `4c5aed0`, `61ad875` and `62afa63`.
- **Evidence:**
  - PoCs and outputs in `/tmp/rev28/poc-secrets` and `/tmp/rev28/poc-cap`;
  - partial reports in `/tmp/rev28/{secrets,cap}.md`.
- **Restrictions respected:** Chrome only on loopback; `/Applications` intact.

### Verdict: REJECTED

There is one **confirmed medium regression** (A4-M1), introduced by `d2a0ca6`. The other items are fixed or were accepted. A3-B5, the `"device":"dev-…-7319"` and the 16b risks were not reevaluated, because they were accepted.

### Addendum 3 items

| Item | State | Evidence |
|---|---|---|
| A3-M1 (brute force on `trace_value`) | Fixed | Without reveal, `trace_value(value)` always returns `reveal_required`, including after reimporting; the r27 brute force (10.000 queries, 200 reimports) found nothing. With `reveal=true` without `--allow-reveal`, it returns `reveal_disabled`. Cookie mode no longer carries `valueLength`. |
| A3-M2 (regression from `5cdac78`) | Fixed in the reported cases | `Refresh: 0;url=/d?pin=%5BREDACTED%5D&page=2` comes out. The X-Note redirect, `next=/cb?token=` in JSON and in free text, `?next=/cb?token=URL1x` and the Location also come out masked. |
| A3-B1 (double encoding) | Fixed | `%253F`, triple and quadruple encoding, `token+%3D`, `token%20%3D` and `token%2B%3D` come out masked. With 5 levels of encoding it still gets through, because the ceiling is 4 rounds (informational). |
| A3-B2 (large message on the pipe) | Fixed in pipe mode | Navigate fails in 2,6 s with `frame_too_large`, the session comes out `partial` and the reason is `capture.cdp_transport_closed`. |
| A3-B3 (symlink at `netlog.json`) | Fixed for the 3 names | The stop finishes with the warning "havia um link simbólico" (there was a symbolic link), writes `netlog.json` as a regular 0600 file from memory, and the victim file stays intact. |
| A3-B4 (Bearer/Basic in free text) | Fixed | `bearer\t`, `BEARER  x`, `Basic` followed by U+3000 and lowercase `basic` come out masked. |
| navigate_timeout | Fixed | With Chrome stopped by SIGSTOP, it returns `navigate_timeout` in 3,3 s. |
| escape_display | Partial | See A4-I1. |
| Regressions of r25/r26/r26b and R1–R12 | No regression | Outputs compared with r27; R1, R2, R3, R4, R9, R10 and R12 pass. There is no excess redaction in `page`, `opinion`, `ticket_type`, `sort` and `q`. |

### Cost of the new recursion

Growth is linear on the 25 adversarial inputs: with 4× the input, the time is about 4×. There was no panic or stack overflow, because there is a ceiling of 4 nesting levels and 4 decoding rounds. Times on the release build:

| Input | 1 MB | 4 MB |
|---|---|---|
| `a=%3Fb%3Dc&` (worst case) | 147 ms | 602 ms |
| `a=/?a=` | 144 ms | 528 ms |
| nested `%253F` | 89 ms | 352 ms |
| nesting of 10k levels | 5 ms | — |

### Remaining findings

#### Medium

**A4-M1. Regression from `d2a0ca6`: a value with mixed encoding leaks (CONFIRMED).**
- **Location:** `core/src/export/sanitize.rs:1061` and `:1074`.
- **Cause:**
  - The value now ends at the first raw `=`, so only `%2Fcb%3Ftoken` is decoded, and it has nothing to redact.
  - The new scan restarts in the middle of the word, and `%3F` does not count as a boundary. As a result, `token=` is never recognized.
- **Before, in core `35a8a62`:** `next=%2Fcb%3Ftoken%3D%255BREDACTED%255D`.
- **Now:** `next=%2Fcb%3Ftoken=MIX1x`.
- **Where it leaks end to end:**
  - header `X-Note3`;
  - JSON fields `mix1`/`mix2`, for example `redirect=https%3A%2F%2Fh%2Fcb%3Faccess_token=MIXED02x`.
  - The URL query stays masked.
- **Evidence:** `/tmp/rev28/poc-secrets/zz_sec28_poc_r28.out` ("MARK MIXED02x: VAZA" (LEAKS)) and the same input run on core `35a8a62`.

#### Low

**A4-B1. `trace_value(request_id)` without reveal still returns `"length":N` (CONFIRMED).**
- **Location:** `mcp/src/tools.rs:1440-1466`, which masks only the `value`; the `length` comes from `core/src/flow.rs:253`.
- **Examples:** `sid` appears with 4 and `X-Session` with 22.
- It is the same leak that `419c207` removed from cookie mode.

**A4-B2. In port mode (`expose_cdp=true`), the large message loses the reason (CONFIRMED).**
- **Location:** `abnormal_close_reason` only handles the pipe (`capture/src/transport.rs:132-134`), so `transport_closed` stays `None` (`capture/src/lib.rs:339`).
- **In release:** the session comes out `partial`, but only through `chrome_killed`, with `warnings:[]`.
- **In debug:** a `debug_assert` in tungstenite 0.28 panics in the capture thread, the stop gives `stop_failed`, no session is written and `recording` stays `true`.

**A4-B3. A symlink planted at `session/attachments` still brings the stop down (CONFIRMED, same user).**
- **Location:** `write_session_resilient` cleans only the 3 names (`capture/src/lib.rs:2001`), and `core/src/store.rs:168-176` refuses the link.
- **Result:** `stop_failed` and no `session.json`. It is only denial of service; the target stays intact.

**A4-B4. A process that replants the `session.json` in a loop beats the 3 attempts (CONFIRMED 3/3, same user).**
- **Location:** `capture/src/lib.rs:2028-2045`.
- It is only denial of service; the target stays intact.

**A4-B5. The session directory is not rechecked at the stop (CONFIRMED, same user).**
- **Location:** the directory symlink check only runs at the start (`capture/src/lib.rs:151`).
- **Scenario:** with `capture-X` swapped for a symlink to another directory, the session is written there with 0600, and the new cleanup deletes a `session.json` symlink outside the session folder.
- **Mitigating factors:** nothing is written through a link, and writing through the swapped directory was already possible before `62afa63`; what is new is the removal.

#### Informational

- **A4-I1. `escape_display` (`mcp/src/live.rs:674-676`) does not cover the variation selectors U+E0100–E01EF**, although `61ad875` says it does; the range `0xE0000..=0xE007F` only catches tags.
  - Also passing raw: U+05B4, U+064B, U+0489, U+115F/1160, U+FFA0, U+1680, U+17B4, U+0600, U+070F, U+1D173, U+13430 and U+1BCA0.
  - Suggestion: filter by the Unicode categories Mn/Me/Cf/Zs instead of ranges.
- **Already existed before:**
  - `a=b=token=X` and the matrix parameter `;next=/cb%3Ftoken=X` get through;
  - a JSON value that starts with "Basic …" is redacted whole;
  - values with multiple encoding come out normalized, not matching the original bytes (not a leak).
- **New texts:** the reasons and the incompleteness warnings use only fixed strings, without URL, query or content.

---

## Addendum 5: confirmation of addendum 4 (Round 11)

- **HEAD:** `d8ad643`, in a new clone at `/tmp/rev29/repo`, which includes the fixes:
  - core: `d12158b`, `d8ad643`, `c441634`;
  - capture: `23bcba6`, `0997a3b`.
- **Comparison:** the earlier behavior is that of core `bacdc30`, compiled separately (the `*_bacdc30.out` files). The cached `fake_server` was outdated and was rebuilt before any end-to-end test.
- **Evidence:**
  - reproduction tests and outputs in `/tmp/rev29/poc-secrets` and `/tmp/rev29/poc-cap`;
  - partial reports in `/tmp/rev29/{secrets,cap}.md`.

### Verdict: REJECTED

There are two **confirmed medium** findings and no high one:
- **A5-M1:** a fidelity regression introduced by `d12158b`.
- **A5-M2:** a partial leak that already existed before these fixes and that no earlier review had found.

All the addendum 4 items are fixed.

### Addendum 4 items

| Item | State | Evidence |
|---|---|---|
| A4-M1 (mixed encoding) | Fixed | `X-Note3`, `mix1`, `mix2` and `next=%2Fcb%3Ftoken=MIX1x` come out as `…token=%5BREDACTED%5D`. |
| `a=b=token=X`, `;next=/cb%3Ftoken=X` and 5 to 8 levels of encoding | Fixed | They come out masked. From 9 levels on it still gets through, because the ceiling is 8 rounds (Info). |
| A4-B1 (`length` in `trace_value`) | Fixed | `length`, `offset`, `consumedOffset`, `consumedLength` and `start` were removed. `evidences[].producerOffset` remained: the difference between two positions in the same HTML reveals the length of a value (Info). |
| A4-I1 (`escape_display`) | Fixed | All the code points of both lists come out escaped. Info: escaping all the `Mn` marks makes Hebrew, Arabic and Indic-language text unreadable. |
| A4-B2 (large message in port mode) | Fixed | Debug and release: `navigate_failed …(frame_too_large)`; the stop finishes with the `cdp_transport_closed` warning; the session comes out `partial`, without a panic; the next status returns `capture_not_found`. The ceiling acts before allocating: 140 MB do not go beyond 18 MB of RSS. |
| A4-B3 (symlink at `attachments`) | Fixed | The stop finishes with a warning; `attachments` becomes a 0700 directory; the `session.json` comes out 0600; the victim stays intact. |
| A4-B5 (session folder swapped) | Fixed | `stop_failed` reports the path of the rescue profile. Nothing is written to the swap target, the links are not touched and the victim stays at 0644. |
| A4-B4 (link replanted in a loop) | Accepted risk, still happens | The stop fails in 3 of 3 attempts and the victim stays intact. Documented in 16b, line 224. |
| R1, R2, R3, R4, R9, R10, R12, A3-B2, A3-B3 and `navigate_timeout` | Pass | — |
| Forms r25 to r28 | No previously masked value leaks now | See A5-M1 about fidelity. |

### Cost of the 8 decoding rounds (release, 4 MB input)

| Input | HEAD | bacdc30 |
|---|---|---|
| matrix `;a=%3Fb%3D` (worst case) | 3,0 s | 204 ms |
| matrix `;a=b=c` | 2,2 s | 348 ms |
| nested `%25` | 1,4 s | 42 ms |
| `a=%3Fb%3Dc&` | 1,2 s | 593 ms |
| repeated `a=` | 1,0 s | 8,4 ms |
| encoding with 4, 8 and 9 levels | 457 / 315 / 172 ms | 250 / 88 / 84 ms |
| nesting of 100 thousand levels | 50 ms | — |

The cost grows linearly on all inputs, with no panic and no stack overflow. The worst case is about 3,6× that of r28. The 8 rounds are not the cause of the increase; it comes from three points:
- the scan restarts at every `=` (`sanitize.rs:1110`);
- `effective_name` allocates memory for each candidate;
- the matrix goes over the text twice.

Severity: Low.

### Remaining findings

#### Medium

**A5-M1. Regression from `d12158b`: the path segments after a sensitive matrix parameter vanish (CONFIRMED).**
- **Location:** `core/src/export/sanitize.rs:874-875`. `sanitize_matrix` runs `sanitize_text` again over the whole path, and the sensitive value goes up to a terminator or `&` (`:1122`). The slash `/` is neither.
- **Examples:**

  | Input | Output |
  |---|---|
  | `/a;jsessionid=X/b/c?x=1` | `/a;jsessionid=%5BREDACTED%5D?x=1` (in `bacdc30`, `/b/c` stayed) |
  | `/users;token=abc/profile/123` | loses `/profile/123` |
  | `/a;v=2/session=keep/b` | loses `session=keep` and `/b` |

- **Effect:** nothing leaks, but the URLs the tools return lose segments without any warning. This hurts the fidelity of what is displayed.

**A5-M2. Partial leak of a secret with encoded `+`, space, `&` or `#` inside a nested URL (CONFIRMED; already existed in `bacdc30`).**
- **Location:** `sanitize.rs:1216` and `:977`. `percent_decode` turns `+` into a space at each round, and the decoding repeats until it stabilizes. The space then starts to end the value.
- **Example:** `?redirect_uri=…%3Faccess_token%3DAAA%2BQPLUS2x` comes out as `…%255BREDACTED%255D%20QPLUS2x`.
- **Reach:**
  - in a base64 token, everything after the first `+` leaks;
  - the same happens with `%2520`, `%2526` and `%2523`;
  - confirmed end to end in a header (`HDRPLUS6x`) and in a body (`BODYPLUS9x`).

#### Low

- **A5-B1. Value that starts with a terminator (CONFIRMED; already existed).** In `token="X"`, `token='X'`, `token=(X)` and `token= X`, only the empty value is masked. Confirmed end to end (`HDRQUOT5x`, `BODYQUOT10x`).
- **A5-B2. Folder swap during the final write loses the rescue (CONFIRMED, 9 of 13).**
  - The core write after the last recheck takes 10 to 16 ms, not microseconds.
  - The swap in that window makes the rename fail with ENOENT, and the error follows the generic path (`capture/src/lib.rs:479`). As a result:
    - the profile is deleted;
    - the message points to no rescue;
    - a `.tmp-*` is left behind.
  - Nothing was written to the swap target in 13 attempts.
- **A5-B3. The rescue keeps the whole Chrome profile without cleanup (CONFIRMED).**
  - It is 8,7 MB, including Cookies, Login Data and History.
  - The permissions are correct (0700/0600), and the path cannot be planted beforehand because the directory is created new.
  - The orphan marker is removed at the end of the capture, so `cleanup_orphans` never deletes this profile. The only clue to it is the error message.
  - `cdp-bodies.jsonl` is not rescued.
- **A5-B4. The empty `cdp-events.jsonl` is created following a symlink (PLAUSIBLE; already existed).** Location: `capture/src/lib.rs:377`. It only happens when the capture ends with zero CDP events; in that case, it would truncate the link's target.
- **A5-B5. Excess redaction (already existed).** `key=`, `tokens=5` and `{token=X}` are redacted; in the last one, the closing `}` vanishes with it.
- **Attempts to bypass the new boundary logic:**
  - correctly masked: `token%3d`, `t%6Fken=`, `tok%00en=` and `token =x`;
  - outside the `name=value` contract: `token\t=X`, `token:=X` and `token&#61;X` get through;
  - inconsistent with the text rule: `;token%3DX` without another `=` in the path, and `&token%3DX` in the query;
  - a hidden-input CSRF reused in a header with a neutral name (`X-Form`) is not propagated.

#### Informational

- On the port, with the socket dead, Chrome waits 20 s until it is killed.
- A fragmented message can reach about 2× the ceiling.

### 16b §2.4 documentation

| Item | Situation |
|---|---|
| A4-B4 | Clear at line 224. |
| TOCTOU between the recheck and the rename | Inexact. Lines 245-248 speak of a "microsecond window", which holds for writing to the swap target, but the rescue-loss window is about 15 ms (A5-B2). The claim that `canonicalize` reduces the window also does not hold: it resolves a string, and the following writes resolve the path again. |
| Profile | Contradictory. Line 174 says "temporary profile discarded at the end", and line 237 says "0700 profile, which is not deleted". Neither says that the cookies stay stored, that no cleanup removes it, or that the bodies are not rescued. |
| `device` field | Accepted, as requested. It is the `"device":"dev-…-7319"` value that stays visible in the JSON body. |

---

## Addendum 6: confirmation of addendum 5 (Round 11)

- **HEAD reviewed:** `d50a19f`, in a new clone at `/tmp/rev30/repo`.
- **Fixes checked:**
  - core: `e6a9edd`, `952921a`, `d50a19f`;
  - capture: `daa3414`.
- **Comparison baseline:** core `49f79ef`, compiled separately. The `fake_server` was rebuilt.
- **Evidence:**
  - reproduction tests and outputs in `/tmp/rev30/poc-secrets` (pairs `*_head.out` / `*_49f.out`, `confirm_*.out`, `zz_sec30_*`) and `/tmp/rev30/poc-cap`;
  - partial reports in `/tmp/rev30/{secrets,cap}.md`.

### Verdict: REJECTED

There is one **confirmed medium regression** (A6-M1) and one **confirmed medium fidelity loss** (A6-M2). A6-M2 is the remainder of A5-M1 on the text path. All the addendum 5 items are fixed in URLs.

### Addendum 5 items

| Item | State | Evidence |
|---|---|---|
| A5-M1 (path truncated after matrix) | Fixed in URLs | `/b/c?x=1`, `/profile/123` and `session=keep/b` are preserved. The text path still truncates (A6-M2). |
| A5-M2 (`%2B`, `%2520`, `%2526`, `%2523`) | Fixed | Masked whole; `HDRPLUS6x` and `BODYPLUS9x` too, end to end. |
| A5-B1 (quotes, parentheses, `= X`) | Fixed | The value is masked and the delimiters stay. |
| A5-B5 (excess redaction) | Fixed | `key=` and `{token=X}` are preserved. |
| Earlier informationals | Fixed | 9 or more levels, `;token%3DX`, `&token%3DX`, `token\t=`, `token:=`, `&#61;`, CSRF in `X-Form`, `nonce`, `sessionKey`. |
| A5-B2 (folder swap at the final write) | Partial | In 20 attempts, 16 were rescued with no `.tmp-*` left. In the other 3, the data was written to the swap target (A6-B5). |
| A5-B3 (what the rescue keeps) | Fixed | The rescue keeps only `cdp-bodies`, `cdp-events`, `netlog` and `motivo.txt`, with 0700/0600 and a marker. The 7-day deadline uses `createdMs`: at 6 days it stays, at 7 days and 1 s it goes. The cleanup runs at MCP startup (`live.rs:82`) and at App startup. |
| A5-B4 (empty `cdp-events`) | Fixed | Checked in the code and in the unit test; the path with 0 events was not reached live. |
| A4-B4 (replanted link) | Accepted | It now goes to the rescue, and the victim stays intact. |
| R1–R4, R9, R10, R12, A3-B2, A3-B3, A4-B2 (debug and release), A4-B3, A4-B5, `navigate_timeout` | Pass | — |

### New tokenizer (`core/src/export/scrub.rs`)

**Fuzz, in release:**
- **150 thousand structured cases:** 0 panics, 0 fidelity losses, 0 non-idempotent outputs. There were 14.417 leaks, all with exactly 8 levels of encoding (A6-B1). `49f` had 89.757 leaks at all depths.
- **300 thousand random inputs:** 0 panics, 0 leaks and 5 non-idempotent outputs (Info: two adjacent placeholders).

**Boundaries:** clean for split UTF-8, `%FF`, overlong encodings, escapes that form new escapes, truncated escapes, end of string, Unicode spaces and placeholder forms.

**Cost, in release:**

| Input | HEAD | 49f |
|---|---|---|
| matrix `;a=%3Fb%3D`, 4 MB | 0,32 s | 3,0 s |
| repeated `a=`, 4 MB | 0,04 s | 1,0 s |
| nested `%25`, 16 MB | 1,2 s | 5,7 s |
| `%25`×8 with `3D`, `=` and `&` in URL, 4 MB | **0,95 s** | 0,30 s |
| chain `%`+`25`×n, 16 MB | **1,4 s** | 0,44 s |

The announced ceiling of 324 ms does not hold for URL inputs of 4 MB. The probable cause, not verified, is `sanitize_query` (`sanitize.rs:903`) calling `scrub()` once per `&` pair.

### Remaining findings

#### Medium

**A6-M1. Regression from `e6a9edd`: a `token=X` segment in the path leaks when the path has `;` (CONFIRMED).**
- **Location:** `core/src/export/sanitize.rs:852-856`. `sanitize_matrix` only examines segments that contain `%`.
- **End-to-end scenario:**
  - the request URL `https://h.invalid/x;v=1/token=SEGURL3x/next?page=2` comes out in the clear in `list_requests` and `get_request`;
  - the Link header `</p;a=1/token=LNK6x>` also comes out in the clear.
- **Before:** `49f` masked both (`confirm_49f.out`: "MARK SEGURL3x: mascarado" (masked); `confirm_head.out`: "VAZA" (LEAKS)).
- **Note:** paths without `;`, such as `/x/token=X`, already leaked in `49f`.

**A6-M2. The text path truncates URLs (CONFIRMED; remainder of A5-M1).**
- **What happens:**
  1. the URL step gets it right and produces `…jsessionid=%5BREDACTED%5D/b/c?x=1`;
  2. then `sanitize_text` (`sanitize.rs:688`) consumes `/b/c?x=1`.
- **Cause:** the value goes to the end of the group (`scrub.rs:439`), and `is_placeholder` (`scrub.rs:190`) only recognizes the exact placeholder.
- **Where it appears:** JSON bodies, the request line (`:381`) and headers that are not URLs (`:362`).
- **Effect:** the displayed URL loses segments without warning, and the idempotence announced in `952921a` no longer holds.

#### Low

- **A6-B1. Low-probability regression (CONFIRMED).** With exactly 8 levels of encoding, the tail after an encoded separator leaks (`…%20CDLEAK8x`); `49f` masked it. Location: `scrub.rs:290-300`.
- **A6-B2. Low-probability regression (CONFIRMED).** Raw `|`, `[` or `{` inside the value let the tail leak: `token=AB|X`, `AB[X]`, `AB{X}` and `token=[abc]TAIL`. Location: `scrub.rs:113-133`. `49f` masked it; base64 and JWT tokens do not use these characters.
- **A6-B3. Memory with deep encoding (CONFIRMED).** Locations: `scrub.rs:140-165` and `281-304`.

  | 16 MB input | HEAD | 49f |
  |---|---|---|
  | `%2525…` | 1,31 GB | 197 MB |
  | nested construction | 2,19 GB | 1,05 GB |

  Bodies have a ceiling of 8 MB (about 0,65 GB); headers and URLs are limited only by the size of the HAR.
- **A6-B4. Forms that already leaked before:**
  - HTML entities of `=`: `&#0061;`, `&#x003D;`, `&#61` without `;`, `&amp;#61;` and `token &#61; X` (`scrub.rs:542`);
  - the full-width `＝`;
  - `Bearer ab%2B…`;
  - `//user:pass@host`.
- **A6-B5. The folder swap between writes writes to the target, and the stop says OK (CONFIRMED, 3 of 20, same user only).**
  - **Location:** each `write_atomic` resolves the path again (`core/src/store.rs:194-213`), and nothing rechecks the identity after `write_session_resilient` (`capture/src/lib.rs:476`).
  - **Scenario:** with the swap at 8, 12 and 15 ms, the `session.json` or the bodies were written to the attacker's directory. This replaces a regular file of the same name there, and the split session is reported as OK.
  - **Suggestion:** recheck the identity after the write, or write relative to a directory descriptor.
- **A6-B6. When the rescue itself fails, the CDP events are lost (CONFIRMED).**
  - **Location:** the fallback (`capture/src/lib.rs:536-544`) only calls `keep()` on the profile, which has Cookies, History and Login Data and does not expire.
  - **Message:** "os dados ficaram no perfil temporário" (the data stayed in the temporary profile), without warning that the CDP events are missing.
  - **Realistic trigger:** full disk. The test used the state root swapped for a file.
- **A6-B7. The marker file name is not tied to the `dir` (CONFIRMED, same user only).**
  - **Location:** `capture/src/lib.rs:986-1018`.
  - **Scenario:** a forged `rescue-evil.json` with `dir:"rescue-111-222"` and `createdMs:0` deletes a recent rescue.
  - **Limit:** nothing outside the state root was deleted. Symlinks, `..`, `/` and names without the prefix were tested.
- **Info:**
  - each failure keeps one more copy, with no total ceiling;
  - the MCP startup does not log `rescues_removed`;
  - 5 non-idempotent outputs with two adjacent placeholders.

### 16b §2.4 documentation

| Lines | Situation | What it says and why |
|---|---|---|
| 224-227 | Outdated | They speak of a "symbolic link replanted repeatedly". The real message is different, and the data now goes to the rescue. |
| 274-275 | Wrong | They say that "at 12 ms the `rename` has already passed". At 12 ms, the `session.json` was written to the swap target. |
| 280-282 | False | They say "0/13 from the Reviewer" and "microseconds". There were 3 of 20 with a write to the target (A6-B5). |
| 258 | False against a forged marker | Says that "the rescue does not vanish before the deadline" (A6-B7). |
| 259-260 | Incomplete | They do not say that the fallback loses the CDP events (A6-B6). |
| 174-175 and 241-256 | Correct | — |

---

## Addendum 7: confirmation of addendum 6 (Round 11)

- **HEAD reviewed:** `868127b`, in a new clone at `/tmp/rev31/repo`, with the fixes:
  - core: `0b94424`, `39826a3` and `868127b`;
  - capture: `93361b8` and `e6fc955`.
- **Comparison:** core `d50a19f`, compiled separately in `/tmp/rev31/before`.
- **Evidence:**
  - reproduction tests in `/tmp/rev31/poc-secrets` and `/tmp/rev31/poc-cap`;
  - reports in `/tmp/rev31/{secrets,cap}.md`.
- **Restrictions:** Chrome only on loopback; `/Applications` intact.

### Verdict: APPROVED, with low caveats

There is no confirmed high or medium finding. The leader's decisions do not count as findings:
- `session=[REDACTED]/b`, because `session` is a sensitive name;
- the redaction of a sibling when there are 8 levels of encoding, by fail-closed.

The accepted risks do not count either: the gap after the final recheck, the `device` field and the extra redaction by fail-closed.

### Addendum 6 items

| Item | State | Evidence |
|---|---|---|
| A6-M1 (`token=X` in the path with `;`) | Fixed | End to end, `SEGURL3x`, `LNK6x`, `LNKA1x`, `LNKB2x` and `LNKUI3x` come out masked and `/next?page=2` is preserved. `d50` leaked. |
| A6-M2 (truncation in the text path) | Partial | The text no longer alters an already sanitized URL, and idempotence is back. Raw text still loses `/b/c?x=1` (A7-B5). |
| A6-B1 (8 levels of encoding) | Fixed | From the 8th to the 10th level it comes out masked, with the suffix and the outer `&page` preserved. |
| A6-B2 (`\|`, `[`, `{` in the value) | Fixed | `AB\|X`, `AB[X]`, `AB{X}` and `[abc]TAIL` come out masked. |
| A6-B3 (memory) | Fixed | RSS peak with 16 MB: 34 MB on the chain, 34 MB on the construction and 125 MB on the groups of about 1 MB. Part of the 2,19 GB of r30 came from the input generator. |
| A6-B4 (entities and variants of `=`) | Partial | 6 forms fixed; `&amp;#61;` and a lone `＝` still leak (A7-B1, A7-B2). |
| A6-B5 (folder swap) | Fixed | In 32 swaps (16 debug, 16 release, from 0 to 30 ms), **nothing was written to the target**. In 31 the stop fails and the content goes to `.moved` and to the rescue. 1 got through after the final recheck, which is the accepted gap. |
| A6-B6 (rescue failure) | Fixed | Real ENOSPC on a 64 MB RAM disk. Plan B deletes Cookies, History, Login Data and Local State and keeps events, bodies, NetLog and `motivo.txt` (0700/0600) with a marker. At 8 days, the next startup deletes the folder. |
| A6-B7 (forged marker) | Fixed | Forged markers do not delete a recent rescue. `touch -t` on the folder deletes, but this requires the same user and is documented (16b, l.269-271). |
| Cost | OK | Linear growth. Worst case: 438 ms with 4 MB (the promise was under 400 ms; `d50` gave 433 ms) and 1,7 s with 16 MB. |
| Capture regressions | All pass | R1–R4, R9, R10, R12, A3-B2, A3-B3, A4-B2 to A4-B5, A5-B2 to A5-B4 and `navigate_timeout`. |

### Fuzz (release, 4 seeds)

Each seed ran 150 thousand structured cases and 900 thousand random inputs:
- 0 leaks and 0 panics;
- 0 non-idempotent outputs in the structured cases;
- about 18,3 thousand fidelity losses per seed, all within the accepted fail-closed: only the inner sibling is lost with 8 levels (7 with redirect context);
- between 76 and 104 non-idempotent outputs per seed on the random inputs (under 0,1 %).

For comparison, `d50` had 14.417 leaks on seed 1.

### Corpus coverage

- `cargo test --offline --release --test corpus --test corpus_fuzz` passes 4/4.
- `cases.jsonl` has 309 lines and `benign.jsonl` has 49; the announcement said 320.
- **About 45 entries from the PoCs are missing:**
  - the r30 set B4 (`token&#0061;E1x` to `E8x`, `token＝FW1x` and `Bearer ab%2B…`);
  - `/a;v=2/session=keep/b`;
  - `https://h/a;token=AB,CD/e`;
  - the placeholder cases.
- **Limits of the verification:**
  - on URL-shaped inputs, the `keep` is only verified on the URL output (`corpus.rs:97`), so truncation in text is not tested;
  - the 8-level cases are stored already decoded, and only the fuzz exercises them.

### Remaining findings (all low)

- **A7-B1. `token＝X` leaks (CONFIRMED end to end; already existed).** Location: `scrub.rs:104`. The early return only looks at `= % @ &`. It leaks in the `X-FW` header and in `search_bodies`.
- **A7-B2. HTML entity of `=` with `&amp;` leaks (CONFIRMED end to end).** Location: `scrub.rs:827-835`. Only `&amp;&#61;` is handled; `&amp;#61;`, `&amp;#x3D;` and `&amp;equals;` leak.
- **A7-B3. A value that starts with a strong delimiter is not redacted (CONFIRMED; already existed).** Location: `scrub.rs:449-450`. Examples: `token=\X`, `token="X` and `token=&#61;X`.
- **A7-B4. Text stuck on after closing quotes or brackets leaks, if it starts with another opening (CONFIRMED; already existed).** Location: `scrub.rs:347`. Examples: `token='a'"X`, `"a"(X)`, `[a][X]` and `(token=AB(c)X)`.
- **A7-B5. Fidelity: raw text still loses segments (CONFIRMED; same as `d50`).**
  - **Location:** `scrub.rs:479-515` and `sanitize.rs:362/381/688`.
  - **Examples:** loses `/b/c?x=1` on the request line, in headers that are not URLs and in relative paths inside JSON. Also `/a;v=2/session=keep/b` loses the `/b`, unlike the leader's decision, which foresaw `session=[REDACTED]/b`.
- **A7-B6. Fidelity: a group above 1 MiB with `%XX` is deleted whole, including the parameter name (CONFIRMED; new).**
  - **Location:** `scrub.rs:527-531`.
  - **Example:** a 4 MB `a=%3Fb%3D…` becomes 14 B, with nothing sensitive in it; `d50` kept the content.
  - **Suggestion:** apply this only when there is a sensitive name.
- **A7-B7. `cdp-bodies.jsonl` is still opened by path (PLAUSIBLE; 0 in 6 attempts).**
  - **Location:** `capture/src/lib.rs:166`, followed by `177-179`, right after the descriptor check.
  - **Scenario:** a swap in that microsecond window would send the bodies to the attacker's folder.
  - **Suggestion:** use `fdio::create_new_at`.
- **Informational:**
  - **Plan B:** a leftover orphan marker can delete the kept profile, which is the only copy of the events (`lib.rs:939-977`). The setup is artificial.
  - **Rescue folders never cleaned:** one with an mtime in the future (`lib.rs:1017-1023`) and another without a marker after a SIGKILL.
  - **Lockfile:** `868127b` did not update `capture/Cargo.lock` for rustix, and the offline build rewrites the file.
  - **JSON with `\ud800`:** the body is omitted whole, as in `d50`.

### `fdio.rs`

It is clean:
- each call uses a single name, with O_NOFOLLOW, O_DIRECTORY and O_CLOEXEC;
- the permissions are set at creation (0600/0700);
- `unlinkat` does not follow links;
- the temporary is removed on errors;
- after 20 captures, 5 of them with forced failure, the fd count stays at 12 and no `.tmp-*` is left.

### 16b §2.4 documentation

| Lines | Situation |
|---|---|
| 224-225 | Outdated. The core already exposes `write_session_dir_at`, but the capture does not use it (`lib.rs:2151`). |
| 213-218 | They omit that the bodies file is created by path (A7-B7). |
| 244-247 | The error message contradicts itself ("nothing was written to it" and "the session was written to the original folder") and does not give the `.moved` path. |
| 269-271, 278-281, 293-301, 303-307 | Correct. |

---

## Addendum 8 — Round 12: confirmation of addendum 7 and review of the app (395cf8e)

**Base reviewed.** New clone at `/tmp/rev32/repo`, at commit `737290a`. The comparison is with `a7087f4`, compiled separately in `/tmp/rev32/poc-secrets/before`. The `fake_server` was rebuilt on both commits.

**Commits reviewed:**
- core: `3607179`, `16da1c2`, `93cbf1d`, `dfe7ea8` and `c7dab11`;
- capture: `f6e1cc1`, `611c63d` and `737290a`;
- app: `395cf8e`.

**Evidence:**
- `/tmp/rev32/poc-secrets`: `cases-{head,before}.tsv`, `fuzz-*.txt`, `perf*.txt` and `e2e-*.json`;
- `/tmp/rev32/poc-app`;
- reports in `/tmp/rev32/{secrets,app}.md`.

The user's real preferences were not touched, and no real site was accessed.

### Verdict: REJECTED

There are three **confirmed medium** findings and no high one:
- **A8-M1:** a leak regression caused by the new path rule;
- **A8-M2:** quadratic cost of the same rule;
- **A8-M3:** the start URL is written in the clear to the preferences.

### Addendum 7 items

| Item | HEAD | a7087f4 | State |
|---|---|---|---|
| A7-B1 `token＝FW1x` | masked | leaks | Fixed |
| A7-B2 `&amp;#61;`, `&amp;#x3D;`, `&amp;equals;` | masked | leaks | Fixed; `&amp;amp;#61;` still leaks (A8-B1) |
| A7-B3 `\X`, `"X`, `&#61;X` | masked | leaks | Fixed |
| A7-B4 `'a'"X`, `"a"(X)`, `[a][X]`, `(token=AB(c)X)` | masked | leaks | Fixed |
| A7-B5 `;jsessionid=X/b/c?x=1` (request line, header, JSON) and `/a;v=2/session=keep/b` | `/b/c?x=1` and `/b` preserved | lost | Fixed |
| A7-B6 4 MB group without sensitive name / with sensitive name | preserved whole (4,2 MB in `get_body`) / redacted | 14 B / redacted | Fixed |
| A7-B7 `cdp-bodies.jsonl` | `capture/src/lib.rs:179` uses `fdio::create_replacing_at` (O_EXCL, O_NOFOLLOW, 0600); the 8 `fdio` tests pass | — | Fixed by code reading, with no live race |
| 16b §2.4 | lines 213-225 describe A7-B7; the message at lines 244-256 became coherent and carries the `.moved` path | — | Fixed |

### Corpus

- **Size:** 401 lines (309 + 45 + 47). Four of the `added.jsonl` lines were just moved out of `benign.jsonl`.
- **Tests:** `cargo test --offline --release --test corpus --test corpus_fuzz` passes 4/4.
- **Covers, with the right expectation:**
  - the r30 B4;
  - `＝` and `Bearer ab%2B`;
  - `,CD/e`;
  - the placeholders;
  - the forms from B1 to B5.
- **Missing:**
  - `&amp;amp;#61;`;
  - cases that must be masked by the new path rule, that is, a secret with `/`;
  - a cost test for values with many `/`.

### Remaining findings

#### Medium

**A8-M1. Regression from `93cbf1d`: the tail of a secret that contains `/` leaks (CONFIRMED).**

- **Location:** `core/src/export/scrub.rs:572-580` and `929-941`.
- **Cause:** the base64 heuristic only accepts the slash if the following segment has 16 or more characters, or contains `+` or `=`.

| Input | HEAD | a7087f4 |
|---|---|---|
| `GET /s;token=Zm9vYmFy/YmF6cXV4 HTTP/1.1` | `…token=%5BREDACTED%5D/YmF6cXV4` | `…token=%5BREDACTED%5D` |
| `{"p":"/s/token=…/YmF6cXV4"}` | leaks `YmF6cXV4` | masked |
| `Refresh: 0; url=/a;token=…/YmF6cXV4` | leaks `YmF6cXV4` | masked |
| `/api/token=/secret1/value2` (text) | leaks the whole value | masked |

- **Also leaking**, and `a7087f4` masked them:
  - `?next=%2Fa%3Btoken%3DAbCdEfGh%2FIjKlMnOp`;
  - `/p?x=1/token=abc/def`.
- **End to end:** confirmed in `get_request`, `get_body` and `search_bodies`.
- **Differential fuzz in release, 150 thousand cases per seed:**

  | | Seed 1 | Seed 2 |
  |---|---|---|
  | Leaks at HEAD | 45,6 thousand | 45,1 thousand |
  | Leaks at a7087f4 | 17,9 thousand | 17,5 thousand |
  | Fidelity losses at HEAD | 10,6 thousand | 10,6 thousand |
  | Fidelity losses at a7087f4 | 107 thousand | 107 thousand |

  The new rule greatly improved fidelity, but opened leaks:
  - the new ones are in headers, JSON, request lines and encoded redirects;
  - a base64 secret with a slash leaks in about 78 % of the cases, and a path-shaped secret in 100 %.
- **Evidence:** `cases-{head,before}.tsv` (cases R02, R17, R18 and R21) and `fuzz-{head,before}-{1,2}.txt`.

**A8-M2. The path rule has quadratic cost (CONFIRMED).**

- **Location:** `scrub.rs:930`. The `contains(&b'+')` goes over the whole accumulated value at every `/`.

| Input | HEAD | a7087f4 |
|---|---|---|
| 1 MB of `/a;token=` + (`A`×16 + `/`)… | 1,4 s | 8 ms |
| 4 MB of the same input | 21 s | 23 ms |
| 4 MB of repeated `A=/` | 121 s | 18 ms |
| 4 MB JSON body via MCP `get_body` | **22,05 s** | 0,10 s |

- **Extrapolation, not measured:** 16 MB would take 6 to 30 min.
- **Outside the problem:** the inputs `/a;token=x/` and `/t=x/` remain linear (at most 468 ms with 16 MB).
- **Suggestion:** keep an "already saw `+`" flag during the scan.
- **Evidence:** `perf.txt`, `perf2.txt` and `e2e-dos-{head,before}.json`.

**A8-M3. The start URL is written in the clear, with credentials and query, with default permissions and following a symlink (CONFIRMED).**

- **Location:** `src-tauri/src/prefs.rs:63-82` and `src-tauri/src/commands.rs:278-285`.
  - `set_capture_start_url` only calls `cli::validate_http_url` (`cli.rs:25-43`), which does not refuse userinfo.
  - It then writes the whole URL to `preferences.json` with `fs::create_dir_all` + `fs::write`, without temp + rename and without O_NOFOLLOW.
- **Scenario:** `http://user:s3cret@h/?token=x` goes to disk in the clear.
- **Test (PoC identical to `prefs.rs`):**
  - the directory comes out 0755 and the file 0644;
  - a symlink planted in the path is followed, and the target is overwritten.
- **Contract:** violates "no secret persisted" and "0700/0600".
- **Mitigating factor:** `~/Library` is 0700.
- **Side effect:** the same credential reaches Chrome through CDP and appears in the warning and in the banner.

#### Low

- **A8-B1. `token&amp;amp;#61;X` and `&amp;amp;amp;#x3d;X` still leak (CONFIRMED).**
  - **Location:** `scrub.rs:1052`. The loop looks for a repeated `&amp;`, but not `&amp;amp;`.
  - **Context:** `3607179` declared "repeated &amp;" as fixed.
- **A8-B2. `sanitize_url("/s;token＝X/…")` leaks the value (CONFIRMED; already existed).** The browser encodes the `＝`, and the encoded form comes out masked.
- **A8-B3. The "tests-only" CLI is active in release (PLAUSIBLE).**
  - **Location:** `src-tauri/src/lib.rs:64-77` reads `env::args()` without `cfg(debug_assertions)` or an environment variable.
  - **Scenario:** `open -a ScrapeLens --args --import-har /abs` imports without going through the dialog.
  - **Limit:** there is no URL scheme, so it requires local execution.
- **A8-B4. TOCTOU on the import file, and a FIFO hangs (CONFIRMED).**
  - **Location:** `cli.rs:90-103` validates the file, but `import_har` (`commands.rs:237-249`) rereads the path with `fs::metadata`, which follows symlinks.
  - **Scenario:** a symlink swapped for a FIFO blocked `fs::read` for more than 3 s, and the command is synchronous.
  - **Plausible:** a symlink to `/dev/zero` (size 0) passes the 256 MiB ceiling. The interface dialog has the same problem, from before `395cf8e`.
- **A8-B5. Loose URL validation, the same in TS and in Rust (CONFIRMED).**
  - **Location:** `cli.rs:25-43` and `captureUrl.ts:16-28`.
  - **Accepts:** NUL, control characters, DEL, U+200B, `http:///`, `http://@`, backslash and a 2 MB URL.
  - **Divergence:** a U+FEFF in the middle is refused in TS and accepted in Rust.
  - **Mitigation:** `start_session` revalidates the URL, and non-http(s) schemes are refused.
- **A8-B6. CLI details (CONFIRMED).**
  - Only the last component is checked, so `..` and a parent that is a symlink get through.
  - `--open-capture /` is accepted.
  - `--open-capture=/x` and unknown flags are silently ignored.
  - The `cli://error` is emitted before the interface listens and only shows up on stderr.
- **A8-B7. Menu shortcuts ignore the disabled state.**
  - ⌘⇧H and ⌘⇧N import during a recording and switch the view.
  - ⌘⇧R ignores the disabled button, but the JS and the Rust refuse the second session.

### What is clean in `395cf8e`

- **Start URL:**
  - it only goes to Chrome as CDP JSON, never to the shell;
  - Rust revalidates it in `start_session` (`commands.rs:339`);
  - the schemes `javascript`, `data`, `file`, `chrome`, `about`, `view-source`, `blob` and `ws` are refused.
- **CLI:** refuses a relative path, FIFO and `/dev/zero` at startup, symlink, directory, a value starting with `-`, a repeated flag and two actions.
- **`--open-capture`:** read-only, without writing to the folder.
- **Imports:** go to `sessions/` with 0700.
- **Corrupted `preferences.json`:** goes back to the default without hanging.
- **Tests:**
  - `cargo test --offline --lib` in `src-tauri`: 37 pass, 8 ignored (`cli::` 6/6);
  - `capture-url.test.ts`: ok.

---

## Addendum 9: confirmation of addendum 8 (Round 12)

Review done in a new clone, at `/tmp/rev33/repo`, at `ce68eb9`. Commits checked:
- core: `27fb212` and `ce68eb9`;
- app: `a7e2495`.

The HEAD (H) was compared with `737290a` (P) and `a7087f4` (B).

Evidence:
- PoCs and outputs in `/tmp/rev33/poc-secrets`: `cases-*.tsv`, `fuzz-*.txt`, `perf3-*.txt`, `e2e-*.json` and `corp-diff-class.txt`;
- app PoCs in `/tmp/rev33/poc-app`: `rev33_app_poc.rs`, `url-table.json` and `compare.mjs`;
- partial reports in `/tmp/rev33/{secrets,app}.md`.

The user's real preferences were not touched, and no real site was accessed.

### Verdict: APPROVED, with low caveats

There is no confirmed high or medium finding.

Left out, by decision of the leader:
- `/a;v=2/session=keep/b` → `/a;v=2/session=[REDACTED]`, accepted limitation A7-B5;
- case R06, text after the `?` without a name.

### Addendum 8 items

| Item | State | Evidence |
|---|---|---|
| A8-M1 (secret with `/`) | Fixed | R01–R30: H leaks in 1 case (R06, out of scope); P leaks in 21 and B in 15. In the MCP (`get_request`, `get_body`, `search_bodies`, `list_requests`), H leaks none of the 60 markers; P leaks 25 and B leaks 21. Query, ` HTTP/1.1` and `&z=1` are preserved. |
| A8-M2 (quadratic cost) | Fixed | Linear cost: `/a;token=`+(16A+`/`) takes 7, 26 and 69 ms with 1, 4 and 16 MB (P: 1,4 s with 1 MB); `A=/` with 16 MB takes 77 ms (P: 7,9 s with 1 MB); a 4 MB `get_body` takes 0,12 s (P: 21,8 s). |
| A8-M3 (start URL in the clear) | Fixed, with residues | The preferences do not store userinfo, query or fragment. An already existing directory with 0755 goes to 0700, and the file comes out 0600. The temporary is born with 0600 and O_NOFOLLOW, with no window at 0644. A symlink and a directory at the destination are refused. Residues: A9-B3 and A9-B4. |
| A8-B1 (`&amp;amp;#61;`) | Fixed | `&amp;amp;#61;`, `&amp;amp;amp;#x3d;`, `equals;`, `&AMP;Amp;` and `#0061` come out masked, including end to end. |
| A8-B2 (`＝` inside URL) | Fixed | `sanitize_url("/s;token＝X/…")` comes out masked, including end to end. |
| A8-B3 (CLI active in release) | Fixed | The CLI only turns on with `SCRAPELENS_TEST_MODE` exactly equal to `"1"`. Values such as `"1 "`, `"true"` and `"01"` are ignored, and no `LSEnvironment` or script sets the variable. |
| A8-B4 (TOCTOU and FIFO on import) | Fixed, with residue | The FIFO is refused in about 50 µs. The symlink to `/dev/zero` gives ELOOP. `/dev/null`, a directory and a 300 MiB sparse file are refused. Residue: A9-B5. |
| A8-B5 (loose URL validation) | Fixed | Refuses NUL, controls, DEL, Cf, bidi, `http:///`, `http://@`, userinfo, `:99999`, `\` and 2 MB. 4 small divergences remain between TS and Rust (A9-B6). |
| A8-B6 (CLI details) | Fixed | Refuses `..`, a parent that is a symlink, `/`, `--open-capture=/x`, an unknown flag and a positional argument. Side effect: `/tmp`, `/var` and `/etc` are refused, because they are symlinks on macOS. |
| A8-B7 (menu shortcuts) | Partial | Plausible: the imports are blocked in the menu, in the commands and in the interface. ⌘⇧R still has no disabled state in the menu; only the backend refuses the second session. |

### Path fuzz (release, 150 thousand cases per seed)

| Seed | H: leaks | H: losses A7-B5 / others | P: leaks / losses | B: leaks / losses |
|---|---|---|---|---|
| 1 | **0** | 107.352 / **0** | 45.596 / 10.578 | 17.870 / 107.352 |
| 2 | **0** | 107.136 / **0** | 45.086 / 10.721 | 17.471 / 107.136 |
| 3 | **0** | 107.253 / **0** | 45.604 / 10.778 | 17.883 / 107.253 |
| 4 | **0** | 107.209 / **0** | 45.170 / 10.656 | 17.699 / 107.209 |

- **Extra variants:** Link, JSON with two keys and a comma-plus-space list (about 107 thousand each) had no leaks, and the following item was always preserved.
- **Repository tests:** `cargo test --offline --release --test corpus --test corpus_fuzz --test corpus_fuzz_path` passes 5/5.
- **App tests:** `cargo test --offline --lib` in `src-tauri` gives 44 passed and 8 ignored; `capture-url.test.ts` passes.

### Regressions

I compared the 440 corpus lines between H and P, as text and as URL:
- 0 new leaks;
- 37 leaks fixed;
- 59 outputs changed, all through the path tail accepted in A7-B5.

They remain equal to P: matrix and non-sensitive segments, query values, JSON, Link items, href, markdown, Set-Cookie and Cookie.

### Remaining findings (all low)

- **A9-B1. In a list without a space and without `?`, the redaction invades the next item (CONFIRMED, end to end).**
  - Example: `X-Urls: /a/token=x/b,/c/keep` and `…/b|/c/keep` come out as `/a/token=[REDACTED]`.
  - Location: `core/src/export/scrub.rs:577`, where only `?` ends the value in the path.
  - P preserved the next item; B lost it the same way.
  - It does not affect a comma followed by a space or items between `<…>` or `"…"`.
- **A9-B2. Nested entity and more than 16 layers of `amp;` leak (CONFIRMED; same in H, P and B).**
  - Example: `token&#38;#61;X` leaks.
  - Location: the 16-layer ceiling at `scrub.rs:1051`.
- **A9-B3. The secret written by the previous version is not cleaned (CONFIRMED).**
  - Location: `src-tauri/src/prefs.rs:43-57`.
  - A `preferences.json` from `395cf8e` stays at 0644 until the first write.
  - After that, `save_chrome_path` rewrites `user:pw@…?token=SECRET#f` intact, now with 0600.
  - Suggestion: apply `persistable_url` on read and rewrite the file.
- **A9-B4. The start URL path is written unsanitized (CONFIRMED).**
  - Values such as `/reset/SECRETTOKEN123`, `;jsessionid=ABC` and `user%3Apw%40h` stay on disk.
  - Suggestion: pass the path through the core sanitizer or keep only origin and path without matrix parameters.
- **A9-B5. The import accepts the swap of a parent directory for a symlink (CONFIRMED, same user only).**
  - Location: `src-tauri/src/commands.rs:240-245`, where `O_NOFOLLOW` only protects the last component.
  - After the CLI validation, swapping the parent made the read return the content of another file.
- **A9-B6. Small divergences between TS and Rust in URL validation (CONFIRMED, 4 of 66 inputs).**
  - With `\u0085` at the ends, Rust accepts and TS refuses.
  - With `﻿` (U+FEFF) at the ends, Rust refuses and TS accepts.
  - Cause: each language's `trim` treats these characters differently.
  - Effect: the `onBlur` (`App.tsx:2201`) sends the raw value; with a BOM, the interface shows the field as valid and Rust returns an error.
- **A9-B7. Private writing of the preferences (CONFIRMED).**
  - Location: `prefs.rs:98-108` only checks the immediate parent, so an ancestor that is a symlink gets through and the write lands on the real target.
  - A directory fsync after the `rename` is missing.
  - The temporary's name is predictable, but `create_new` reduces the effect to an error.
- **A9-B8. Lock in the menu handler during the Chrome start (PLAUSIBLE).**
  - The handler does `capture.lock()`, and `start_session` holds that lock for up to 35 s.
  - Suggestion: `try_lock`.
