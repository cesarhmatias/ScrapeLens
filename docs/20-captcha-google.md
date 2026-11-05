# 20. Google CAPTCHA in the App capture: what we measured

Round 13. **Measurement only**: no production code was changed. The flags
tested below were applied only on a disposable snapshot outside the repository.

## 1. Question

In the App, `Start session` with `https://google.com.br` showed a Google CAPTCHA.
In an incognito Brave tab, on the same machine and the same network, it does not appear. The
hypothesis: our instrumentation would be detected (CDP, `Runtime.enable`, the
`waitForDebuggerOnStart` pause), plus the empty profile and the lab arguments. Which
piece, if any, causes the CAPTCHA?

## 2. Authorization and limits (met, with one deviation: §5)

The user authorized actually loading `https://www.google.com.br/`, only for this:

- at most 2 rounds of 4 conditions (up to 8 loads), **home page only**;
- at least 60 s between loads; no search, no login, no solving the CAPTCHA,
  no other sites;
- a new temporary profile per load, Chrome with a visible window (no
  `--headless`), without the wrapper;
- STOP and warn if Google showed "unusual traffic" or blocked the IP.

**8 loads** of Google were made (two rounds of A, B, C, D), plus loopback-only
loads to read `navigator.webdriver`. No search, no login. Google
did not show `/sorry/`, 429 or reCAPTCHA on any load; the stop rule
never fired.

## 3. Method

Chrome 156 stable, macOS, NetLog on in all conditions. The launcher
arguments are those of `capture/src/lib.rs` `chrome_args` in `Open` mode (HEAD `3dda266`),
without `--headless`.

| Cond. | What it is |
|---|---|
| **A** | Chrome **with no CDP client** (no `--remote-debugging-*`), with **the same launcher arguments** (including the lab ones). The URL goes on the command line |
| **B** | Like A, but **without the lab arguments**: only `--user-data-dir`, `--log-net-log`, **plus `--no-first-run --no-default-browser-check`** (see deviation below). The URL goes on the command line |
| **C** | **Reduced CDP** over a pipe: `Target.setDiscoverTargets`, `Target.setAutoAttach` **without** `waitForDebuggerOnStart`, `Target.createTarget about:blank`, `Network.enable` and `Target.setAutoAttach` (no wait) on the tab, `Page.navigate`. **No** `Page.enable`, **no** `Runtime.enable`, no `Network.setCacheDisabled`. Launcher arguments |
| **D** | Today's **full capture** (`scrapelens_capture::run`, open network): `Network.enable` + `Page.enable` + `Runtime.enable`, `setAutoAttach` with `waitForDebuggerOnStart`, `Network.setCacheDisabled`, bodies. Launcher arguments |

Deviation in B: the literal "only user-data-dir and NetLog" **does not load the URL**. Without
`--no-first-run`, Chrome shows the welcome flow and ignores the command-line
URL (measured: no request to the local probe). The two flags only affect the
interface.

**How each result was read** (no screenshots and no personal data): from the NetLog, only the URL
without query and the status. CAPTCHA = any request to `/sorry/` or status 429 or a
`recaptcha` URL. Main page status = the statuses of the request for
`https://www.google.com.br/` (the 301 → 200 chain).
**`navigator.webdriver`** was read **without `Runtime.evaluate`** and **without touching
Google**: a local loopback page does `fetch('/wd?webdriver='+navigator.webdriver)`,
loaded with the same arguments as each condition (in D, through the full capture).

## 4. Results

### 4.1 What Google did (8 loads)

| Round | Order | Cond. | Start | Main page | `/sorry/` | 429 | reCAPTCHA | Requests in NetLog |
|---:|---:|---|---|---|---|---|---|---:|
| 1 | 1st | A | 23:02:24 | 301 → 200 | no | no | no | 50 |
| 1 | 2nd | B | 23:04:18 | 301 → 200 | no | no | no | 73 |
| 1 | 3rd | C | 23:05:54 | 301, page rendered (¹) | no | no | no | 59 |
| 1 | 4th | D | 23:07:32 | 301 → 200 | no | no | no | 56 |
| 2 | 1st | D | 23:08:16 | 301 → 200 | no | no | no | 55 |
| 2 | 2nd | C | 23:10:04 | 301, page rendered (¹) | no | no | no | 57 |
| 2 | 3rd | B | 23:11:41 | 301 → 200 | no | no | no | 71 |
| 2 | 4th | A | 23:13:17 | 301 → 200 | no | no | no | 50 |

(¹) In C the NetLog shows the page request with only the 301 (it ends in
`ERR_ABORTED`); the page rendered anyway, with dozens of `/xjs/` scripts and
Google resources returning 200 in both rounds.

**No condition, in either round, showed a CAPTCHA.** Including D, today's full
capture. The CAPTCHA the user saw **did not reproduce** with 8 loads.

### 4.2 `navigator.webdriver` (local, without Google)

| Cond. | CDP | `navigator.webdriver` |
|---|---|---|
| A | none | **false** |
| B | none | **false** |
| C | pipe, reduced | **true** |
| D | pipe, full | **true** |
| C + `--disable-blink-features=AutomationControlled` | pipe, reduced | **false** |
| D + `--disable-blink-features=AutomationControlled` | pipe, full | **false** |

`webdriver` is `true` **with any `--remote-debugging-pipe`**, reduced or
full: it does not depend on `Runtime.enable` or `waitForDebuggerOnStart`. The flag
`--disable-blink-features=AutomationControlled` undoes it even with full CDP
(measured on the full capture on a local snapshot, outside the repository). In C and D the
`User-Agent` is the same as in A and B (`Chrome/156.0.0.0`, no `HeadlessChrome`), with 5
plugins and 4 languages.

### 4.3 Other observations

- **B generates more Google traffic** (71 to 73 requests against 50): without
  `--disable-background-networking` and company, Chrome queries
  `accounts.google.com/ListAccounts`, updates, `clientservices` etc. The lab
  arguments reduce browser noise; they **did not change what the main
  page received**.
- With NetLog, shutdown by `SIGTERM` (A and B, without CDP) closes the file; a
  NetLog without CDP is viable.
- In all conditions the NetLog records the complete load of the home page
  (301 → 200 chain, scripts, fonts and `gen_204`).

## 5. Limits of this measurement (read before concluding)

1. **The CAPTCHA did not reproduce**, so **the piece that causes it cannot be pointed out**.
   In 8 loads, not even the full capture (D) provoked it. There is no evidence that
   `Runtime.enable`, the debugger pause, the empty profile or the lab arguments
   are the cause; there is also no evidence that they are not: the sample is
   small (2 per condition) and Google decides by risk (IP, history, time of day), not
   by an isolated piece.
2. The user's CAPTCHA may have occurred at a moment when the IP had already been
   flagged (several automated loads in a row, repeated by the project's tests);
   this was not tested, and testing would require forcing the block, which the
   authorization forbids.
3. **Deviation in the minimum interval.** The request was ≥ 60 s between loads. Between the
   end of round 1 (D, 23:07:32) and the start of round 2 (D, 23:08:16) the interval
   between starts was **44 s**; the others were between 96 and 114 s. It was a failure of my
   chaining (round 2 started without waiting). There was no visible effect (no
   `/sorry/`, 429 or reCAPTCHA), but the limit was violated once.
4. A demonstrably different signal exists and is detectable by any script of the
   site: `navigator.webdriver === true` in the capture (C and D), against `false` in a Chrome
   without CDP (A and B). Whether Google uses this for the CAPTCHA was not measured.

## 6. Recommendation

> **Update (2026-11-03):** item 1 became decision **D7** (`docs/01-decisions.md`):
> `--disable-blink-features=AutomationControlled` is the DEFAULT in every capture (App, controlled
> MCP, pipe and port), recorded in `capture.chromeArgs`/`notes` and
> `captureContext` in the `site_profile`. Measured again on loopback with the full capture and the
> controlled one: `navigator.webdriver === false`. Items 2 to 4 remain as a recommendation.

What the measurements support, in order of cost:

1. **Add `--disable-blink-features=AutomationControlled` to the launcher**
   (regular and controlled capture). Measured: `navigator.webdriver` goes back to `false`,
   even with the full capture, and the flag does not touch the network or what is captured.
   It is the cheapest visible difference between the capture and a normal Chrome, and removes
   a signal that any site reads. It does not prove that it cures the CAPTCHA (§5.1).
2. **Tiered discreet mode** (per-capture option), from least to most intrusive:
   - **level 1, NetLog only** (condition A): no CDP client, the browser is the normal
     Chrome with profile and NetLog; loses CDP (bodies, ExtraInfo, targets) and the
     CDP×NetLog correlation, and navigation is done by the user;
   - **level 2, reduced CDP** (condition C + the flag from item 1): `Network.enable` and
     `setAutoAttach` without `waitForDebuggerOnStart`, without `Page` or `Runtime.enable`;
     keeps bodies and ExtraInfo; loses the guarantee of attaching to workers and iframes
     before the first request goes out;
   - **level 3, full** (D, today): the total fidelity the project requires.
   Use the lowest level that meets the goal; go up only when the `site_profile`
   (or the user) needs what it does not give.
3. **If the CAPTCHA reappears in the App**, repeat once with the flag from item 1 and
   compare with the NetLog (`/sorry/`, 429); only then is it worth testing `Runtime.enable`
   and `waitForDebuggerOnStart` in isolation, taking care not to exhaust the IP.
4. **Do not change** the lab arguments because of this: A and B (with and without them)
   behaved the same for Google; they serve to reduce NetLog noise.

Open items for whoever implements it (outside this round): where the level is chosen
(`CaptureConfig` or a parameter of `start_capture`), and how capture without CDP (level 1)
generates the session (importing the NetLog alone, with `import_netlog`).

## 7. Data

The NetLogs (with `--net-log-capture-mode=Everything` in conditions A, C and D, which
includes Google cookies), the temporary profiles and the sessions stayed in `/tmp` outside
the repository and **were deleted** at the end. No Google session or NetLog was
committed. The scripts (a minimal CDP client over a pipe, the local probe server and the
NetLog reader) stayed outside the repository by instruction; the method above is enough to
repeat them.
