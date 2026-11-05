#!/usr/bin/env node
/**
 * Minimal CDP client (no dependencies) for the fidelity experiments.
 *
 * Records all Network.* events (and Fetch.requestPaused) to cdp-events.jsonl,
 * in the order Chrome emitted them, without normalizing params.headers.
 *
 * Usage:
 *   node cdp_capture.mjs --port 9222 --outdir results/exp1 --plan plan.json
 */
import fs from "node:fs";
import path from "node:path";

function parseArgs(argv) {
  const out = { port: 9222, outdir: ".", plan: "plan.json" };
  for (let i = 2; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, "");
    out[k] = argv[i + 1];
  }
  return out;
}

const args = parseArgs(process.argv);
const outdir = path.resolve(args.outdir);
fs.mkdirSync(outdir, { recursive: true });
const plan = JSON.parse(fs.readFileSync(path.resolve(args.plan), "utf8"));
const eventsPath = path.join(outdir, "cdp-events.jsonl");
fs.writeFileSync(eventsPath, "");

const WANTED = new Set(
  (
    plan.events || [
      "Network.requestWillBeSent",
      "Network.requestWillBeSentExtraInfo",
      "Network.responseReceived",
      "Network.responseReceivedExtraInfo",
      "Network.loadingFinished",
      "Network.loadingFailed",
      "Network.requestServedFromCache",
      "Network.dataReceived",
    ]
  ).map(String)
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const version = await fetch(`http://127.0.0.1:${args.port}/json/version`).then((r) => r.json());
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", rej, { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const listeners = new Set();
  const allEvents = [];

  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`${msg.error.message} (${JSON.stringify(msg.error.data ?? "")})`));
      else resolve(msg.result);
      return;
    }
    if (msg.method) {
      allEvents.push(msg);
      for (const fn of listeners) fn(msg);
    }
  });

  function send(method, params = {}, sessionId) {
    const id = ++nextId;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify(payload));
    });
  }

  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const S = (m, p) => send(m, p, sessionId);

  const log = (row) => fs.appendFileSync(eventsPath, JSON.stringify(row) + "\n");

  let loaded = null;
  listeners.add((msg) => {
    if (msg.sessionId !== sessionId) return;
    if (msg.method === "Page.loadEventFired") {
      loaded?.();
      loaded = null;
      return;
    }
    if (!WANTED.has(msg.method)) return;
    log({ session: sessionId, method: msg.method, params: msg.params });
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
  const uaInitial = (await S("Runtime.evaluate", { expression: "navigator.userAgent" })).result.value;
  if (plan.userAgent) await S("Network.setUserAgentOverride", { userAgent: plan.userAgent });

  // Native HAR, if this Chrome version exposes Network.getHAR.
  let harNote = null;
  let harAvailable = false;
  try {
    const probe = await S("Network.getHAR", {});
    harAvailable = true;
    fs.writeFileSync(path.join(outdir, "chrome-native-har.json"), JSON.stringify(probe, null, 2));
    harNote = "Network.getHAR disponível";
  } catch (err) {
    harNote = `Network.getHAR indisponível: ${err.message}`;
  }

  const decisions = fs.createWriteStream(path.join(outdir, "fetch-decisions.jsonl"), { flags: "w" });
  if (plan.mode === "ordered") {
    listeners.add(async (msg) => {
      if (msg.sessionId !== sessionId || msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      const match = plan.match ?? "/echo";
      const headers = request.url.includes(match)
        ? plan.extraHeaders.map(([name, value]) => ({ name, value }))
        : null;
      decisions.write(
        JSON.stringify({
          url: request.url,
          intercepted: Boolean(headers),
          sent_headers: headers ? headers.map((h) => [h.name, h.value]) : null,
          original_headers: request.headers,
          original_header_order: Object.keys(request.headers),
        }) + "\n"
      );
      try {
        await S("Fetch.continueRequest", headers ? { requestId, headers } : { requestId });
      } catch (err) {
        decisions.write(JSON.stringify({ url: request.url, error: err.message }) + "\n");
      }
    });
    await S("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] });
  }

  const navigations = [];
  for (const url of plan.urls) {
    loaded = null;
    const waitLoad = new Promise((res) => {
      loaded = res;
      setTimeout(res, plan.navTimeoutMs ?? 20000);
    });
    const res = await S("Page.navigate", { url });
    await waitLoad;
    await sleep(plan.settleMs ?? 1200);
    let probe = null;
    try {
      probe = await S("Runtime.evaluate", {
        expression: "JSON.stringify({done: window.__done ?? null, result: window.__result ?? null, loc: location.href})",
        awaitPromise: true,
        returnByValue: true,
      });
    } catch {
      /* page without script */
    }
    navigations.push({ url, navigate: res, probe: probe?.result?.value ?? null });
  }

  if (harAvailable) {
    try {
      const har = await S("Network.getHAR", {});
      fs.writeFileSync(path.join(outdir, "chrome-native-har.json"), JSON.stringify(har, null, 2));
    } catch {
      /* ignore */
    }
  }

  const ua = await S("Runtime.evaluate", { expression: "navigator.userAgent" });
  fs.writeFileSync(
    path.join(outdir, "cdp-meta.json"),
    JSON.stringify(
      {
        protocolVersion: version["Protocol-Version"],
        browser: version.Browser,
        userAgent: ua.result.value,
        webSocketDebuggerUrl: version.webSocketDebuggerUrl,
        harAvailable,
        harNote,
        plan,
        navigations,
        events: allEvents.length,
      },
      null,
      2
    )
  );
  decisions.end();

  await send("Browser.close", {}).catch(() => {});
  await sleep(500);
  ws.close();
}

main().catch((err) => {
  console.error(err.stack || String(err));
  process.exitCode = 1;
});
