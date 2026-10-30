#!/usr/bin/env node
/**
 * CDP multi-alvo: Target.setDiscoverTargets + setAutoAttach recursivo,
 * Network.enable antes de Runtime.runIfWaitingForDebugger em cada sessão.
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
  const sessionsByTarget = new Map();
  const requestKeys = new Map();
  let eventCount = 0;
  let networkEventCount = 0;
  let pendingSetups = 0;

  const logEvent = (row) => {
    fs.appendFileSync(eventsPath, `${JSON.stringify(row)}\n`);
    eventCount += 1;
    if (NETWORK_METHODS.has(row.method)) networkEventCount += 1;
  };

  function send(method, params = {}, sessionId) {
    const id = ++nextId;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify(payload));
    });
  }

  const autoAttachParams = {
    autoAttach: true,
    flatten: true,
    waitForDebuggerOnStart: waitDebugger,
  };
  const RECURSE_TYPES = new Set(["page", "iframe", "worker", "service_worker"]);
  const SKIP_SETUP_TYPES = new Set(["browser_ui", "other"]);

  const setupChild = async (sessionId, targetInfo, waitingForDebugger) => {
    const existing = [...sessions.values()].find((s) => s.targetId === targetInfo.targetId);
    if (existing && existing.sessionId !== sessionId) {
      if (waitingForDebugger && waitDebugger) {
        await send("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => {});
      }
      return;
    }
    if (sessions.has(sessionId)) {
      if (waitingForDebugger && waitDebugger) {
        await send("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => {});
      }
      return;
    }
    const type = targetInfo.type ?? "unknown";
    sessions.set(sessionId, {
      sessionId,
      targetId: targetInfo.targetId,
      type,
      url: targetInfo.url ?? "",
      title: targetInfo.title ?? "",
      attachedAt: Date.now() - t0,
      resumedDebugger: false,
    });
    sessionsByTarget.set(targetInfo.targetId, sessionId);

    if (SKIP_SETUP_TYPES.has(type)) {
      if (waitDebugger && waitingForDebugger) {
        await send("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => {});
      }
      return;
    }
    if (RECURSE_TYPES.has(type)) {
      await send("Target.setAutoAttach", autoAttachParams, sessionId);
    }
    await send(
      "Network.enable",
      {
        maxTotalBufferSize: 100_000_000,
        maxResourceBufferSize: 50_000_000,
        maxPostDataSize: 5_000_000,
      },
      sessionId
    );
    if (type === "page" || type === "iframe") {
      await send("Page.enable", {}, sessionId).catch(() => {});
    }
    await send("Runtime.enable", {}, sessionId).catch(() => {});
    const mustResume = waitDebugger && (waitingForDebugger !== false);
    if (mustResume) {
      await send("Runtime.runIfWaitingForDebugger", {}, sessionId);
      sessions.get(sessionId).resumedDebugger = true;
    }
  };

  const setupChain = new Map();
  const enqueueSetup = (sessionId, targetInfo, waitingForDebugger) => {
    const prev = setupChain.get(sessionId) ?? Promise.resolve();
    const job = prev
      .then(() => setupChild(sessionId, targetInfo, waitingForDebugger))
      .catch((err) => {
        logEvent({ session: sessionId, method: "__error", params: { phase: "setup", message: String(err) } });
      });
    setupChain.set(sessionId, job);
    return job;
  };

  const drainSetups = async () => {
    for (let i = 0; i < 200 && pendingSetups > 0; i += 1) {
      await sleep(50);
    }
  };

  const onAttached = (params, parentSession) => {
    pendingSetups += 1;
    enqueueSetup(params.sessionId, params.targetInfo, params.waitingForDebugger)
      .then(() => {
        const { sessionId, waitingForDebugger, targetInfo } = params;
        logEvent({
          session: sessionId,
          method: "__session_attached",
          params: {
            parentSession,
            waitingForDebugger,
            targetId: targetInfo.targetId,
            type: targetInfo.type,
            url: targetInfo.url,
            resumed: sessions.get(sessionId)?.resumedDebugger ?? false,
          },
        });
      })
      .finally(() => {
        pendingSetups -= 1;
      });
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
        onAttached(msg.params, msg.sessionId ?? null);
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

  await send("Target.setDiscoverTargets", { discover: true });
  await send("Target.setAutoAttach", autoAttachParams);

  const pageUrl = plan.pageUrl;
  const { targetId: mainTargetId } = await send("Target.createTarget", { url: pageUrl });
  await drainSetups();
  await sleep(300);

  let rootSession = sessionsByTarget.get(mainTargetId);
  if (!rootSession) {
    for (let i = 0; i < 50 && !rootSession; i += 1) {
      await sleep(100);
      await setupChain;
      rootSession = sessionsByTarget.get(mainTargetId);
    }
  }
  if (!rootSession) {
    throw new Error(`sessão principal não anexada para target ${mainTargetId}`);
  }

  const S = (method, params) => send(method, params, rootSession);

  await send("Target.setAutoAttach", autoAttachParams, rootSession);
  await S("Network.setCacheDisabled", { cacheDisabled: true });
  if (plan.bypassServiceWorker) {
    await S("Network.setBypassServiceWorker", { bypass: true });
  }
  await S("Network.clearBrowserCache");
  await S("Network.clearBrowserCookies");

  const expectedMarkers = plan.expectedMarkers ?? 16;
  const multiLogPath = plan.multiLogPath ? path.resolve(plan.multiLogPath) : null;

  const serverMarkerCount = () => {
    if (!multiLogPath || !fs.existsSync(multiLogPath)) return 0;
    const seen = new Set();
    for (const line of fs.readFileSync(multiLogPath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const mk = JSON.parse(line).marker;
        if (mk) seen.add(mk);
      } catch {
        /* ignore */
      }
    }
    return seen.size;
  };

  await sleep(2500);
  try {
    await S("Runtime.evaluate", {
      expression: "window.__scrapelensMulti?.clickBlank?.()",
      returnByValue: true,
    });
  } catch {
    /* ignore */
  }
  try {
    const base = pageUrl.replace(/\/multi\/?$/, "");
    await send("Target.createTarget", { url: `${base}/multi/blank.html?m=blank-1` });
    await sleep(4000);
    await drainSetups();
    await S("Runtime.evaluate", { expression: "window.__scrapelensMulti?.openIframe?.()" });
    await sleep(4000);
    await drainSetups();
  } catch {
    /* ignore */
  }

  const doneDeadline = Date.now() + (plan.waitForDoneMs ?? 75000);
  while (Date.now() < doneDeadline) {
    if (serverMarkerCount() >= expectedMarkers) break;
    await sleep(350);
  }
  await sleep(plan.settleMs ?? 5000);
  await drainSetups();
  await Promise.race([Promise.all(setupChain.values()), sleep(10000)]);

  const requests = [];
  for (const line of fs.readFileSync(eventsPath, "utf8").split("\n")) {
    if (!line) continue;
    const row = JSON.parse(line);
    if (row.method !== "Network.requestWillBeSent") continue;
    const p = row.params;
    const rid = p.requestId;
    const sid = row.session;
    requestKeys.set(rid, (requestKeys.get(rid) ?? 0) + 1);
    requests.push({
      sessionId: sid,
      requestId: rid,
      url: p.request?.url,
      method: p.request?.method,
    });
  }

  const bodyRows = [];
  const bodyTargets = requests.filter((r) => r.url?.includes("m="));
  const bodyLimit = plan.bodyFetchLimit ?? 24;
  const fetchBody = plan.fetchAllBodies === true;
  for (const req of bodyTargets.slice(0, bodyLimit)) {
    const sid = req.sessionId;
    let postData = null;
    let responseBody = null;
    let postErr = null;
    let respErr = null;
    if (!fetchBody) {
      bodyRows.push({
        sessionId: sid,
        requestId: req.requestId,
        url: req.url,
        postDataAvailable: null,
        skipped: true,
      });
      continue;
    }
    try {
      const r = await Promise.race([
        send("Network.getRequestPostData", { requestId: req.requestId }, sid),
        sleep(8000).then(() => {
          throw new Error("timeout");
        }),
      ]);
      postData = r.postData ?? null;
    } catch (err) {
      postErr = err.message;
    }
    try {
      const r = await Promise.race([
        send("Network.getResponseBody", { requestId: req.requestId }, sid),
        sleep(8000).then(() => {
          throw new Error("timeout");
        }),
      ]);
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

  const ridCollisions = [...requestKeys.entries()]
    .filter(([, n]) => n > 1)
    .map(([rid, n]) => ({ requestId: rid, sessions: n }));

  fs.writeFileSync(
    sessionsPath,
    JSON.stringify(
      {
        waitForDebuggerOnStart: waitDebugger,
        mainTargetId,
        rootSession,
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

  await Promise.race([send("Browser.close", {}), sleep(5000)]);
  await sleep(300);
  ws.close();
}

main().catch((err) => {
  console.error(err.stack || String(err));
  process.exitCode = 1;
});
