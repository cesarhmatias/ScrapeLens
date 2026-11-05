#!/usr/bin/env node
/**
 * Real ScrapeLens capture cycle on macOS.
 *
 * Opens Chrome with a dedicated temporary profile, network blocked except loopback,
 * full NetLog and debugging only on 127.0.0.1; navigates the requested URLs,
 * writes `cdp-events.jsonl`, `chrome-netlog.json` and the native HAR; shuts down the
 * browser gracefully so the NetLog is finalized.
 *
 * No certificate installed: the test certificate is waived by SPKI
 * (`--ignore-certificate-errors-spki-list`). QUIC is not disabled; in h3 mode
 * the origin is forced to QUIC.
 *
 * Usage:
 *   node capture_cycle.mjs --outdir RUN --name h1h2 \
 *     --spki-file fixtures/tls/spki-sha256-base64.txt \
 *     --urls http://127.0.0.1:9781/setcookie,https://127.0.0.1:9782/page \
 *     [--force-quic 127.0.0.1:9782] [--port 9333] [--har]
 *
 * Output: RUN/<name>.cdp-events.jsonl, RUN/<name>.chrome-netlog.json,
 *        RUN/<name>.meta.json e, com --har, RUN/<name>.native-har.json.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const CHROME = process.env.CHROME_BIN || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

function parseArgs(argv) {
  const out = { port: "9333", urls: "", har: false, settleMs: 1200, headless: true };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--har") { out.har = true; continue; }
    if (key === "--headed") { out.headless = false; continue; }
    const value = argv[i + 1];
    i += 1;
    const name = key.replace(/^--/, "").replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
    out[name] = value;
  }
  return out;
}

const args = parseArgs(process.argv);
if (!args.outdir || !args.name || !args.spkiFile || !args.urls) {
  console.error("missing --outdir, --name, --spki-file or --urls");
  process.exit(2);
}
const outdir = path.resolve(args.outdir);
fs.mkdirSync(outdir, { recursive: true });
const profile = path.join(outdir, `profile-${args.name}`);
fs.mkdirSync(profile, { recursive: true });
const netlog = path.join(outdir, `${args.name}.chrome-netlog.json`);
const cdpPath = path.join(outdir, `${args.name}.cdp-events.jsonl`);
const spki = fs.readFileSync(path.resolve(args.spkiFile), "utf8").trim().split(/\s+/)[0];
const urls = args.urls.split(",").map((url) => url.trim()).filter(Boolean);
const port = String(args.port);

const chromeArgs = [
  `--user-data-dir=${profile}`,
  `--remote-debugging-port=${port}`,
  "--remote-debugging-address=127.0.0.1",
  `--log-net-log=${netlog}`,
  "--net-log-capture-mode=Everything",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-sync",
  "--disable-default-apps",
  "--disable-extensions",
  "--disable-breakpad",
  "--disable-domain-reliability",
  "--disable-client-side-phishing-detection",
  "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions",
  "--metrics-recording-only",
  "--no-service-autorun",
  "--no-pings",
  "--password-store=basic",
  "--use-mock-keychain",
  "--disable-search-engine-choice-screen",
  `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`,
  `--ignore-certificate-errors-spki-list=${spki}`,
  "--enable-quic",
  "--allow-insecure-localhost",
  "about:blank",
];
if (args.forceQuic) chromeArgs.unshift(`--origin-to-force-quic-on=${args.forceQuic}`);
if (args.headless !== false) chromeArgs.unshift("--headless=new");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForDebugger(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (response.ok) return await response.json();
    } catch (error) {
      last = error;
    }
    await sleep(150);
  }
  throw new Error(`DevTools did not respond: ${last}`);
}

async function waitForExit(child, timeoutMs) {
  const wait = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  const timer = sleep(timeoutMs).then(() => "timeout");
  return Promise.race([wait, timer]);
}

function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  try { process.kill(-child.pid, "SIGTERM"); } catch { /* already exited */ }
}

async function main() {
  const startedAt = new Date().toISOString();
  const child = spawn(CHROME, chromeArgs, {
    stdio: ["ignore", "ignore", "ignore"],
    detached: true,
    env: { ...process.env, CHROME_USER_DATA_DIR: undefined },
  });
  let version = null;
  let events = 0;
  let error = null;
  const navigations = [];
  let harWritten = false;
  let harError = null;
  try {
    version = await waitForDebugger();
    const ws = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", reject, { once: true });
    });

    let nextId = 0;
    const pending = new Map();
    const listeners = new Set();
    const cdpStream = fs.createWriteStream(cdpPath, { flags: "w" });

    ws.addEventListener("message", (event) => {
      const message = JSON.parse(typeof event.data === "string" ? event.data : event.data.toString());
      if (message.id !== undefined && pending.has(message.id)) {
        const { resolve, reject } = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
        return;
      }
      if (message.method) {
        const row = { session: message.sessionId ?? null, method: message.method, params: message.params };
        cdpStream.write(JSON.stringify(row) + "\n");
        events += 1;
        for (const listener of listeners) listener(message);
      }
    });

    const send = (method, params = {}, sessionId) => {
      const id = ++nextId;
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        ws.send(JSON.stringify(payload));
      });
    };

    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const S = (method, params) => send(method, params, sessionId);

    let loaded = null;
    listeners.add((message) => {
      if (message.sessionId !== sessionId) return;
      if (message.method === "Page.loadEventFired") {
        loaded?.();
        loaded = null;
      }
    });

    await S("Page.enable");
    await S("Runtime.enable");
    await S("Network.enable", {
      maxTotalBufferSize: 100_000_000,
      maxResourceBufferSize: 50_000_000,
      maxPostDataSize: 5_000_000,
    });
    await S("Network.setCacheDisabled", { cacheDisabled: true });
    await S("Network.setBypassServiceWorker", { bypass: true });
    await S("Network.clearBrowserCache");
    await S("Network.clearBrowserCookies");

    for (const url of urls) {
      const waitLoad = new Promise((resolve) => {
        loaded = resolve;
        setTimeout(resolve, 20000);
      });
      const navigation = await S("Page.navigate", { url });
      await waitLoad;
      await sleep(Number(args.settleMs));
      let probe = null;
      try {
        const evaluated = await S("Runtime.evaluate", {
          expression: "JSON.stringify({done: window.__done ?? null, loc: location.href})",
          returnByValue: true,
        });
        probe = evaluated?.result?.value ?? null;
      } catch { /* page without script */ }
      navigations.push({ url, errorText: navigation?.errorText ?? null, probe });
    }

    if (args.har) {
      try {
        const har = await S("Network.getHAR", {});
        fs.writeFileSync(path.join(outdir, `${args.name}.native-har.json`), JSON.stringify(har));
        harWritten = true;
      } catch (failure) {
        harError = `Network.getHAR unavailable: ${failure.message}`;
      }
    }

    await send("Browser.close", {}).catch(() => {});
    ws.close();
    cdpStream.end();
    const exited = await waitForExit(child, 15000);
    if (exited === "timeout") {
      stopChild(child);
      await waitForExit(child, 5000);
    }
  } catch (failure) {
    error = failure.stack || String(failure);
  } finally {
    stopChild(child);
    await waitForExit(child, 5000).catch(() => {});
    // Wait for the NetLog to settle after shutdown.
    let previous = -1;
    for (let i = 0; i < 40; i += 1) {
      const size = fs.existsSync(netlog) ? fs.statSync(netlog).size : 0;
      if (size > 0 && size === previous) break;
      previous = size;
      await sleep(100);
    }
    fs.rmSync(profile, { recursive: true, force: true });
  }

  const meta = {
    name: args.name,
    startedAt,
    finishedAt: new Date().toISOString(),
    browser: { name: "Chrome", version: version?.Browser ?? "unknown", protocol: version?.["Protocol-Version"] ?? null },
    profile,
    chromeArgs,
    urls,
    navigations,
    cdpEvents: events,
    harWritten,
    harError,
    netlogBytes: fs.existsSync(netlog) ? fs.statSync(netlog).size : 0,
    cdpBytes: fs.existsSync(cdpPath) ? fs.statSync(cdpPath).size : 0,
    error,
  };
  fs.writeFileSync(path.join(outdir, `${args.name}.meta.json`), JSON.stringify(meta, null, 1));
  if (error) {
    console.error(error);
    process.exit(1);
  }
  console.log(JSON.stringify({ name: args.name, browser: meta.browser, events, netlogBytes: meta.netlogBytes }));
}

main().catch((failure) => {
  console.error(failure.stack || String(failure));
  process.exit(1);
});
