#!/usr/bin/env node
/**
 * CDP multi-alvo: Target.setDiscoverTargets + setAutoAttach recursivo,
 * Network.enable antes de Runtime.runIfWaitingForDebugger em cada sessão.
 *
 * Uso:
 *   node cdp_multi_capture.mjs --port 9222 --outdir results/multi/wait \
 *     --plan plan.json [--no-wait-debugger]
 */
import fs from "node:fs";
import path from "node:path";

function parseArgs(argv) {
  const out = { port: "9222", outdir: ".", plan: "plan.json", waitDebugger: true };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--no-wait-debugger") {
      out.waitDebugger = false;
      continue;
    }
    const value = argv[i + 1];
    i += 1;
    out[key.replace(/^--/, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  return out;
}

const args = parseArgs(process.argv);
const outdir = path.resolve(args.outdir);
fs.mkdirSync(outdir, { recursive: true });
const plan = JSON.parse(fs.readFileSync(path.resolve(args.plan), "utf8"));
const waitDebugger = args.waitDebugger !== false && plan.waitForDebuggerOnStart !== false;

const eventsPath = path.join(outdir, "cdp-events.jsonl");
const sessionsPath = path.join(outdir, "cdp-sessions.json");
const bodiesPath = path.join(outdir, "cdp-bodies.jsonl");
fs.writeFileSync(eventsPath, "");
fs.writeFileSync(bodiesPath, "");

const NETWORK_METHODS = new Set([
  "Network.requestWillBeSent",
  "Network.requestWillBeSentExtraInfo",
  "Network.responseReceived",
  "Network.responseReceivedExtraInfo",
  "Network.loadingFinished",
  "Network.loadingFailed",
  "Network.requestServedFromCache",
  "Network.dataReceived",
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const t0 = Date.now();
  const version = await fetch(`http://127.0.0.1:${args.port}/json/version`).then((r) => r.json());
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res, { once: true });
    ws.addEventListener("error", rej, { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const sessions = new Map();
  const requestKeys = new Map();
  let eventCount = 0;
  let networkEventCount = 0;

  const logEvent = (row) => {
    fs.appendFileSync(eventsPath, `${JSON.stringify(row)}\n`);
    eventCount += 1;
    if (NETWORK_METHODS.has(row.method)) networkEventCount += 1;
  };

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
      logEvent({ session: msg.sessionId ?? null, method: msg.method, params: msg.params });
      if (msg.method === "Target.attachedToTarget") {
        onAttached(msg.params, msg.sessionId ?? null).catch((err) => {
          logEvent({ session: null, method: "__error", params: { phase: "attached", message: String(err) } });
        });
      }
      if (msg.method === "Target.targetInfoChanged" && msg.params?.targetInfo) {
        const info = msg.params.targetInfo;
        for (const rec of sessions.values()) {
          if (rec.targetId === info.targetId) {
            rec.url = info.url;
            rec.title = info.title;
          }
        }
      }
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

  const setupChild = async (sessionId, targetInfo) => {
    if (sessions.has(sessionId)) return;
    sessions.set(sessionId, {
      sessionId,
      targetId: targetInfo.targetId,
      type: targetInfo.type,
      url: targetInfo.url ?? "",
      title: targetInfo.title ?? "",
      attachedAt: Date.now() - t0,
    });
    await send(
      "Target.setAutoAttach",
      { autoAttach: true, flatten: true, waitForDebuggerOnStart: waitDebugger },
      sessionId
    );
    await send(
      "Network.enable",
      {
        maxTotalBufferSize: 100_000_000,
        maxResourceBufferSize: 50_000_000,
        maxPostDataSize: 5_000_000,
      },
      sessionId
    );
    await send("Page.enable", {}, sessionId);
    await send("Runtime.enable", {}, sessionId);
    if (waitDebugger) {
      await send("Runtime.runIfWaitingForDebugger", {}, sessionId);
    }
  };

  const onAttached = async (params, parentSession) => {
    const { sessionId, waitingForDebugger, targetInfo } = params;
    await setupChild(sessionId, targetInfo);
    logEvent({
      session: sessionId,
      method: "__session_attached",
      params: {
        parentSession,
        waitingForDebugger,
        targetId: targetInfo.targetId,
        type: targetInfo.type,
        url: targetInfo.url,
      },
    });
  };

  await send("Target.setDiscoverTargets", { discover: true });
  await send("Target.setAutoAttach", {
    autoAttach: true,
    flatten: true,
    waitForDebuggerOnStart: waitDebugger,
  });

  const targets = await fetch(`http://127.0.0.1:${args.port}/json/list`).then((r) => r.json());
  let pageTarget = targets.find((t) => t.type === "page" && !t.url.startsWith("chrome-extension"));
  if (!pageTarget) {
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    pageTarget = { id: targetId };
  }
  const { sessionId: rootSession } = await send("Target.attachToTarget", {
    targetId: pageTarget.id ?? pageTarget.targetId,
    flatten: true,
  });
  await setupChild(rootSession, {
    targetId: pageTarget.id ?? pageTarget.targetId,
    type: "page",
    url: pageTarget.url ?? "about:blank",
    title: pageTarget.title ?? "",
  });

  const S = (method, params) => send(method, params, rootSession);

  await S("Network.setCacheDisabled", { cacheDisabled: true });
  if (plan.bypassServiceWorker) {
    await S("Network.setBypassServiceWorker", { bypass: true });
  }
  await S("Network.clearBrowserCache");
  await S("Network.clearBrowserCookies");

  let loaded = null;
  const waitLoad = () =>
    new Promise((resolve) => {
      loaded = resolve;
      setTimeout(resolve, plan.navTimeoutMs ?? 45000);
    });

  const navListener = (msg) => {
    if (msg.sessionId !== rootSession) return;
    if (msg.method === "Page.loadEventFired") {
      loaded?.();
      loaded = null;
    }
  };
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
    if (msg.method) navListener(msg);
  });

  const pageUrl = plan.pageUrl;
  await S("Page.navigate", { url: pageUrl });
  await waitLoad();
  const doneDeadline = Date.now() + (plan.waitForDoneMs ?? 20000);
  while (Date.now() < doneDeadline) {
    try {
      const probe = await S("Runtime.evaluate", {
        expression: "Boolean(window.__multiDone)",
        returnByValue: true,
      });
      if (probe.result.value === true) break;
    } catch {
      /* ignore */
    }
    await sleep(400);
  }
  await sleep(plan.settleMs ?? 4000);

  if (plan.triggerScript) {
    try {
      await S("Runtime.evaluate", { expression: plan.triggerScript, awaitPromise: true, returnByValue: true });
      await sleep(plan.postTriggerMs ?? 3000);
    } catch {
      /* optional */
    }
  }

  const requests = [];
  for (const line of fs.readFileSync(eventsPath, "utf8").split("\n")) {
    if (!line) continue;
    const row = JSON.parse(line);
    if (row.method !== "Network.requestWillBeSent") continue;
    const p = row.params;
    const rid = p.requestId;
    const sid = row.session;
    const key = `${sid}\0${rid}`;
    requestKeys.set(rid, (requestKeys.get(rid) ?? 0) + 1);
    requests.push({
      sessionId: sid,
      requestId: rid,
      url: p.request?.url,
      method: p.request?.method,
      key,
    });
  }

  const bodyRows = [];
  for (const req of requests) {
    if (!req.url?.includes("m=") && !plan.fetchAllBodies) continue;
    const sid = req.sessionId;
    let postData = null;
    let responseBody = null;
    let postErr = null;
    let respErr = null;
    try {
      const r = await send("Network.getRequestPostData", { requestId: req.requestId }, sid);
      postData = r.postData ?? null;
    } catch (err) {
      postErr = err.message;
    }
    try {
      const r = await send("Network.getResponseBody", { requestId: req.requestId }, sid);
      responseBody = { base64Encoded: r.base64Encoded, len: (r.body ?? "").length };
    } catch (err) {
      respErr = err.message;
    }
    bodyRows.push({
      sessionId: sid,
      requestId: req.requestId,
      url: req.url,
      postDataAvailable: postData !== null,
      postDataLen: postData?.length ?? 0,
      postErr,
      responseBodyAvailable: responseBody !== null,
      responseBodyLen: responseBody?.len ?? 0,
      respErr,
    });
  }
  fs.writeFileSync(bodiesPath, `${bodyRows.map((r) => JSON.stringify(r)).join("\n")}\n`);

  const ridCollisions = [...requestKeys.entries()].filter(([, n]) => n > 1).map(([rid, n]) => ({ requestId: rid, sessions: n }));

  fs.writeFileSync(
    sessionsPath,
    JSON.stringify(
      {
        waitForDebuggerOnStart: waitDebugger,
        sessions: [...sessions.values()],
        sessionCount: sessions.size,
        eventCount,
        networkEventCount,
        requestIdCollisions: ridCollisions,
        requestIdCollisionPairs: ridCollisions.length,
        elapsedMs: Date.now() - t0,
        pageUrl,
        browser: version.Browser,
        protocolVersion: version["Protocol-Version"],
      },
      null,
      2
    )
  );

  await send("Browser.close", {}).catch(() => {});
  await sleep(500);
  ws.close();
}

main().catch((err) => {
  console.error(err.stack || String(err));
  process.exitCode = 1;
});
