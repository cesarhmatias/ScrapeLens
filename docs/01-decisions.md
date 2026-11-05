# ScrapeLens — Architecture decisions

Source of the facts: `docs/02-fidelity-matrix.md` (evidence in `experiments/results/`, Chrome 156.0.8078.48, macOS arm64, 60 requests).

## D1 — Stack (after the fidelity proof)

- UI: React 19 + TypeScript + Vite (already validated in `app/`, commit `05bdaf1`).
- Desktop shell: Tauri 2 (original decision kept — no wave 1 result argues against it).
- Capture: external Chrome launcher + CDP (WebSocket 127.0.0.1) + NetLog (`--log-net-log`). No MITM proxy, no certificates, no disabling QUIC.
- Reference tests/servers: Rust (commits `130dbc7`, `f3b049c`).
- Core language: to be defined by the Core agent between Rust (preference: same runtime as Tauri, zero sidecar) or Go (allowed by the user, but it would require a sidecar in the package). Leader's default: **Rust**, so the packaged binary does not depend on any installation.

## D2 — Header provenance by protocol (verdict of the matrix)

| Information | Recommended source | State |
|---|---|---|
| Order+duplicates of h1 request | CDP `responseReceivedExtraInfo.headersText` (response) / NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | verified (Chrome 156) |
| Order of h2 request | NetLog `HTTP2_SESSION_SEND_HEADERS` (~: 1 exchange observed; `cookie` may be split) | partial |
| Order of h3 request | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` (✓ order; `cookie` duplicates split on the wire) | partial |
| Order+duplicates of response (h1/h2/h3) | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | verified |
| "Easy" headers (CDP `request.headers` / `ExtraInfo.headers`) | never treat as a transmitted sequence; unordered subset | verified: does NOT preserve |

Product rule: when the transmitted sequence cannot be proven for a piece of information, the UI shows **"not verified"** — it never guesses.

## D3 — CDP×NetLog correlation

IDs are not equivalent. Model with separate entities: logical request, attempt, redirect, connection, session/stream. Explicit relations when they exist; URL+method+time are hints with **explicit ambiguity** when there is more than one match.

## D4 — Splitting of `Cookie` in h2/h3

The splitting of the `cookie` field on the wire is an observed fact; the data model preserves the original CDP field and the transmitted NetLog lines, without silently merging them.

## D5 — Commits

Continuous Conventional Commits, user rule recorded in the channel.

## D6 — Third-party browsers (CloakBrowser) and AI agent

Date: 2026-10-31. Leader's decision, after feasibility phase A
(`docs/15-mcp-cloakbrowser.md`, section "CloakBrowser feasibility (phase A)").

1. **MITM proxy remains vetoed.** It applies to any browser, including
   CloakBrowser. HTTPS header fidelity comes from the NetLog; no certificate
   of our own is installed and QUIC is not disabled (D1).
2. **ScrapeLens never embeds or redistributes the CloakBrowser binary.** It only
   points to a binary that the user installed themselves, as it already does with
   Chrome. The binary's license forbids redistribution and requires an OEM/SaaS license
   to offer it to third parties (`BINARY-LICENSE.md`; summary in doc 15, item 1).
3. **Browser shared between the AI agent and ScrapeLens:** ScrapeLens
   launches the browser and exposes the debugging port **on loopback only**
   (`127.0.0.1`). The agent connects to that port; ScrapeLens does not depend on
   the agent launching the browser.
4. **Vetoed at launch and at installation of any third-party browser:**
   - `--no-sandbox` (the CloakBrowser wrapper passes it by default, including on
     macOS);
   - `xattr -cr` or any other workaround of Gatekeeper/quarantine;
   - the CloakBrowser `pip`/`npm` wrapper (it would bring background updates,
     license validation and the Gatekeeper workaround above).
5. **State:** download and execution of CloakBrowser (phases B1 and B2 of doc 15)
   **are not authorized**. They depend on the user's express authorization,
   relayed by the leader.
6. **B1 postponed; CloakBrowser only comes in if reconnaissance shows it is
   needed.** The flow is: an AI agent uses the ScrapeLens MCP with regular Chrome
   to understand a site's configuration (`site_profile`,
   `docs/16b-mcp-browser.md`); the "CloakBrowser candidate" recommendation is the
   trigger to revisit the subject.

## D7 — Automation notice suppressed by default in every capture

Date: 2026-11-03. User's decision, after the measurement in
`docs/20-captcha-google.md` (§4.2: with `--remote-debugging-pipe`,
`navigator.webdriver` is `true`; with the flag below, `false`).

1. **`--disable-blink-features=AutomationControlled` becomes the DEFAULT in every
   capture**: the regular App one, the controlled MCP one (allowlist), pipe and port
   (`expose_cdp`), any network mode. It is always present in `chrome_args()`;
   if a `--disable-blink-features` with other values already exists, they are
   combined into a single flag, without duplicating.
2. **The session records the context**: `capture.chromeArgs` (launch
   arguments, without temporary paths) and `capture.notes` state that the notice was
   suppressed, and `site_profile` exposes `captureContext.automationFlagSuppressed`
   so the site reconnaissance knows what the site saw.
3. **Solving CAPTCHA remains out of scope** for ScrapeLens.
4. **No other anti-detection technique without a new decision:** fake User-Agent,
   fingerprint patching, "stealth" plugins, hiding the CDP, avoiding
   `Runtime.enable` or the debugger pause to "look like" a regular
   browser, and the same goes for the lab arguments (`docs/20` §6, item 4).
   The staged discreet mode (NetLog only, reduced CDP, full) remains a
   recommendation of `docs/20`, not a decision.
