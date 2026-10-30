#!/usr/bin/env node
/**
 * Prova mínima: setAutoAttach na sessão da página + recursivo em iframe/worker,
 * com log de attaches e comandos CDP por sessão. Só /multi/ (sem blank/popup extra).
 */
import fs from "node:fs";
import path from "node:path";

function parseArgs(argv) {
  const out = { port: "9222", outdir: ".", pageUrl: "http://127.0.0.1:8781/multi/" };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--no-wait-debugger") {
      out.waitDebugger = false;
      continue;
    }
    const value = argv[i + 1];
    i += 1;
    if (key === "--port") out.port = value;
    else if (key === "--outdir") out.outdir = value;
    else if (key === "--page-url") out.pageUrl = value;
  }
  return out;
}

const args = parseArgs(process.argv);
const waitDebugger = args.waitDebugger !== false;
const outdir = path.resolve(args.outdir);
fs.mkdirSync(outdir, { recursive: true });

const eventsPath = path.join(outdir, "cdp-events.jsonl");
const commandsPath = path.join(outdir, "commands.jsonl");
const summaryPath = path.join(outdir, "probe-summary.json");
fs.writeFileSync(eventsPath, "");
fs.writeFileSync(commandsPath, "");

const SKIP_TYPES = new Set(["browser_ui", "other"]);
const AUTO_ATTACH_TYPES = new Set(["page", "iframe", "worker", "service_worker"]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function markerFromUrl(url) {
  const m = /[?&]m=([^&#]+)/.exec(url || "");
  return m ? decodeURIComponent(m[1]) : null;
}

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
  const attaches = [];

  const logEvent = (row) => fs.appendFileSync(eventsPath, `${JSON.stringify(row)}\n`);
  const logCommand = (sessionId, method, params) => {
    fs.appendFileSync(
      commandsPath,
      `${JSON.stringify({ ms: Date.now() - t0, sessionId: sessionId ?? null, method, params })}\n`
    );
  };

  function send(method, params = {}, sessionId) {
    const id = ++nextId;
    logCommand(sessionId ?? null, method, params);
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

  const setupSession = async (sessionId, targetInfo, waitingForDebugger, parentSession) => {
    const type = targetInfo.type ?? "unknown";
    if (sessions.has(sessionId)) {
      if (waitDebugger && waitingForDebugger) {
        await send("Runtime.runIfWaitingForDebugger", {}, sessionId);
      }
      return;
    }
    sessions.set(sessionId, { sessionId, type, url: targetInfo.url ?? "", targetId: targetInfo.targetId });

    attaches.push({
      ms: Date.now() - t0,
      sessionId,
      type,
      url: targetInfo.url ?? "",
      parentSession: parentSession ?? null,
      waitingForDebugger: !!waitingForDebugger,
    });
    logEvent({
      session: sessionId,
      method: "__attach_log",
      params: attaches[attaches.length - 1],
    });

    if (!SKIP_TYPES.has(type)) {
      if (AUTO_ATTACH_TYPES.has(type) || type === "page") {
        await send("Target.setAutoAttach", autoAttachParams, sessionId);
      }
      await send("Network.enable", { maxPostDataSize: 5_000_000 }, sessionId);
      if (type === "page" || type === "iframe") {
        await send("Page.enable", {}, sessionId).catch(() => {});
      }
      await send("Runtime.enable", {}, sessionId).catch(() => {});
      if (waitDebugger && waitingForDebugger !== false) {
        await send("Runtime.runIfWaitingForDebugger", {}, sessionId);
      }
    } else if (waitDebugger && waitingForDebugger) {
      await send("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => {});
    }
  };

  const setupChain = new Map();
  const enqueueSetup = (sessionId, targetInfo, waitingForDebugger, parentSession) => {
    const prev = setupChain.get(sessionId) ?? Promise.resolve();
    const job = prev
      .then(() => setupSession(sessionId, targetInfo, waitingForDebugger, parentSession))
      .catch((err) => {
        logEvent({ session: sessionId, method: "__error", params: { message: String(err) } });
      });
    setupChain.set(sessionId, job);
    return job;
  };

  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
      return;
    }
    if (!msg.method) return;
    logEvent({ session: msg.sessionId ?? null, method: msg.method, params: msg.params });
    if (msg.method === "Target.attachedToTarget") {
      const p = msg.params;
      enqueueSetup(p.sessionId, p.targetInfo, p.waitingForDebugger, msg.sessionId ?? null);
    }
  });

  await send("Target.setDiscoverTargets", { discover: true });
  await send("Target.setAutoAttach", autoAttachParams);

  const { targetId } = await send("Target.createTarget", { url: args.pageUrl });
  await sleep(500);

  let rootSession = [...sessions.entries()].find(([, s]) => s.targetId === targetId)?.[0];
  for (let i = 0; i < 80 && !rootSession; i += 1) {
    await sleep(100);
    rootSession = [...sessions.entries()].find(([, s]) => s.targetId === targetId)?.[0];
  }
  if (rootSession) {
    await send("Target.setAutoAttach", autoAttachParams, rootSession);
    await send("Network.setCacheDisabled", { cacheDisabled: true }, rootSession);
  }

  const deadline = Date.now() + 45000;
  const want = new Set([
    "oopif-get-1",
    "oopif-post-1",
    "worker-get-1",
    "worker-post-1",
    "oopif-1",
  ]);
  const seen = new Map();

  while (Date.now() < deadline) {
    for (const line of fs.readFileSync(eventsPath, "utf8").split("\n")) {
      if (!line) continue;
      const row = JSON.parse(line);
      if (row.method !== "Network.requestWillBeSent") continue;
      const url = row.params?.request?.url ?? "";
      const mk = markerFromUrl(url);
      if (mk && want.has(mk)) {
        seen.set(mk, { sessionId: row.session, url });
      }
    }
    if ([...want].filter((m) => m.endsWith("-1") && m.includes("get") || m.includes("post")).every((m) => seen.has(m))) {
      break;
    }
    if (seen.has("oopif-get-1") && seen.has("oopif-post-1") && seen.has("worker-get-1") && seen.has("worker-post-1")) {
      break;
    }
    await sleep(400);
  }
  await sleep(2000);
  await Promise.race([Promise.all(setupChain.values()), sleep(8000)]);

  const byType = {};
  for (const a of attaches) {
    byType[a.type] = (byType[a.type] ?? 0) + 1;
  }

  const summary = {
    browser: version.Browser,
    protocolVersion: version["Protocol-Version"],
    waitForDebuggerOnStart: waitDebugger,
    pageUrl: args.pageUrl,
    attachCount: attaches.length,
    attachByType: byType,
    attaches,
    networkMarkers: Object.fromEntries(seen),
    iframeAttached: attaches.some((a) => a.type === "iframe"),
    workerAttached: attaches.some((a) => a.type === "worker"),
    elapsedMs: Date.now() - t0,
  };
  fs.writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);

  ws.close();
  console.log(JSON.stringify(summary));
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
