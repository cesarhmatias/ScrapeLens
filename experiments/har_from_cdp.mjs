#!/usr/bin/env node
/**
 * HAR 1.2 rebuilt from CDP events — NOT the DevTools exporter. It exists for two reasons:
 *   1. Chrome 156 does not expose `Network.getHAR` (verified in this experiment);
 *   2. the Core/importers need a realistic HAR fixture, with headers
 *      as a list of pairs (not a dictionary).
 *
 * The field `log.creator.name` declares the origin. The recorded order is the
 * enumeration order of the CDP object: for request headers that means the
 * ASCII order of Chrome's internal map, not the wire order.
 */
import fs from "node:fs";
import path from "node:path";

const dir = path.resolve(process.argv[2] ?? ".");
const events = fs
  .readFileSync(path.join(dir, "cdp-events.jsonl"), "utf8")
  .split("\n")
  .filter(Boolean)
  .map(JSON.parse);

const entries = new Map();

function entryFor(requestId) {
  if (!entries.has(requestId)) {
    entries.set(requestId, {
      requestId,
      startedDateTime: null,
      request: { method: "", url: "", httpVersion: "", headers: [], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
      response: { status: 0, statusText: "", httpVersion: "", headers: [], cookies: [], content: { size: 0, mimeType: "" }, redirectURL: "", headersSize: -1, bodySize: -1 },
      cache: {},
      timings: { send: 0, wait: 0, receive: 0 },
    });
  }
  return entries.get(requestId);
}

function splitJoined(name, value) {
  return String(value)
    .split("\n")
    .map((v) => ({ name, value: v }));
}

for (const ev of events) {
  const p = ev.params || {};
  if (ev.method === "Network.requestWillBeSent") {
    const e = entryFor(p.requestId);
    e.startedDateTime = p.wallTime ? new Date(p.wallTime * 1000).toISOString() : null;
    e.request.method = p.request.method;
    e.request.url = p.request.url;
    e.request.httpVersion = p.request.url.startsWith("https") ? "h2" : "http/1.1";
    e.request.headers = Object.entries(p.request.headers).map(([name, value]) => ({ name, value }));
  } else if (ev.method === "Network.requestWillBeSentExtraInfo") {
    const e = entryFor(p.requestId);
    const extra = Object.entries(p.headers || {}).flatMap(([n, v]) => splitJoined(n, v));
    // Merges like the DevTools exporter: ExtraInfo entries replace the
    // requestWillBeSent ones and are appended at the end.
    const byName = new Map(e.request.headers.map((h) => [h.name.toLowerCase(), h]));
    for (const h of extra) byName.set(h.name.toLowerCase(), h);
    e.request.headers = [...e.request.headers.filter((h) => !extra.some((x) => x.name.toLowerCase() === h.name.toLowerCase())), ...extra];
  } else if (ev.method === "Network.responseReceived") {
    const e = entryFor(p.requestId);
    e.response.status = p.response.status;
    e.response.statusText = p.response.statusText;
    e.response.httpVersion = p.response.protocol;
    e.response.content.mimeType = p.response.mimeType;
    e.response.content.size = p.response.encodedDataLength ?? 0;
  } else if (ev.method === "Network.responseReceivedExtraInfo") {
    const e = entryFor(p.requestId);
    if (p.headersText) {
      const lines = p.headersText.split("\r\n").filter(Boolean).slice(1);
      e.response.headers = lines.map((ln) => {
        const i = ln.indexOf(":");
        return { name: ln.slice(0, i), value: ln.slice(i + 1).trim() };
      });
    } else {
      e.response.headers = Object.entries(p.headers || {}).flatMap(([n, v]) => splitJoined(n, v));
    }
  }
}

const har = {
  log: {
    version: "1.2",
    creator: { name: "scrapelens-experiments/har_from_cdp", version: "1", comment: "Rebuilt from CDP; not the DevTools HAR exporter." },
    entries: [...entries.values()].map(({ requestId, ...rest }) => ({ ...rest, _requestId: requestId })),
  },
};
const out = path.join(dir, "har-derived.json");
fs.writeFileSync(out, JSON.stringify(har, null, 2));
console.log(`${out}: ${har.log.entries.length} entries`);
