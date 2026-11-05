// Generates the v1 fixture (contract docs/03-contracts.md) from the original demo
// session in scripts/legacy-demo-session.ts. The output is synthetic and marked with
// "synthetic-fixture": no data is real.
//
//   node scripts/gen-demo-v1.mjs
//
// Output:
//   src/demo/session.v1.json     (read by the UI and the browser mode)
//   src/demo/attachments.json    (text previews of the demo bodies)
//   ../src-tauri/demo/session.json (embedded in the binary for the open/demo commands)

import { build } from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const legacyPath = path.join(appRoot, "scripts/legacy-demo-session.ts");

const built = await build({
  entryPoints: [legacyPath],
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
  logLevel: "silent",
});
const module = await import(
  "data:text/javascript;base64," + Buffer.from(built.outputFiles[0].text).toString("base64")
);
const legacy = module.demoSession;

const SOURCE = { cdp: "cdp", netlog: "netlog", har: "har", session: "derived", derived: "derived" };

function protocol(value) {
  if (value === "HTTP/1.1") return "h1";
  if (value === "HTTP/2") return "h2";
  if (value === "HTTP/3") return "h3";
  return "unknown";
}

function provenance(verification, fallbackSource = "cdp") {
  if (!verification || verification.status === "unverified") {
    return {
      source: fallbackSource,
      method: verification?.reason ?? "no evidence",
      verification: "unverified",
      notes: verification?.reason ? [verification.reason] : undefined,
    };
  }
  return {
    source: SOURCE[verification.evidence.source] ?? "derived",
    event: verification.evidence.event,
    sourceId: verification.evidence.eventRef,
    wallTime: verification.evidence.timestamp,
    browserVersion: "156.0.8079.0",
    method: verification.evidence.method,
    verification: verification.status,
    notes: verification.missing ? [verification.missing] : undefined,
  };
}

function headerView(pairs, verification) {
  const pseudoHeaders = [];
  const headers = [];
  const prov = provenance(verification);
  for (const pair of pairs) {
    const entry = { name: pair.name, value: pair.value, ...prov };
    if (pair.name.startsWith(":")) pseudoHeaders.push(entry);
    else headers.push(entry);
  }
  const h1 = protocolOfHeaders(pairs);
  return {
    ...(pseudoHeaders.length ? { pseudoHeaders } : {}),
    headers,
    orderState: "sourceOrder",
    ...(h1 ? { notes: ["HTTP/1.1 origin: no pseudoheaders"] } : {}),
  };
}

function protocolOfHeaders(pairs) {
  return pairs.some((p) => p.name === ":method") ? false : pairs.some((p) => p.name === "host");
}

function mapBody(body, verification, attachment, provenanceOverride) {
  const reason = body.reason ?? "";
  let state = "unavailable";
  if (body.availability === "available") state = "captured";
  else if (body.availability === "truncated") state = "truncated";
  else if (body.availability === "discarded" || body.availability === "omitted") state = "discarded";
  else if (body.availability === "unavailable") {
    const empty =
      reason.includes("request without body") ||
      reason.includes("content-length: 0") ||
      reason.includes("declared content-length: 0");
    state = empty ? "empty" : "unavailable";
  }
  const hasBytes = body.preview !== undefined || state === "captured" || state === "truncated";
  return {
    state,
    ...(hasBytes && attachment ? { attachment } : {}),
    ...(body.encodedSize !== undefined || body.decodedSize !== undefined
      ? { bytes: body.decodedSize ?? body.encodedSize }
      : {}),
    ...(state === "truncated" && body.truncatedAt ? { truncatedAt: body.truncatedAt } : {}),
    ...(body.contentType ? { contentType: body.contentType } : {}),
    ...(body.reason ? { note: body.reason } : {}),
    ...provenanceOverride,
    provenance: provenance(verification),
  };
}

function parseSetCookie(raw) {
  const tokens = raw.split(";").map((t) => t.trim()).filter(Boolean);
  const [pair, ...attrs] = tokens;
  const eq = pair.indexOf("=");
  if (eq <= 0) return { parsed: null, parseError: "Set-Cookie without a name=value pair" };
  const parsed = {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1),
    secure: false,
    httpOnly: false,
    partitioned: false,
  };
  for (const attr of attrs) {
    const idx = attr.indexOf("=");
    const key = (idx > 0 ? attr.slice(0, idx) : attr).trim();
    const value = idx > 0 ? attr.slice(idx + 1).trim() : undefined;
    switch (key.toLowerCase()) {
      case "path": parsed.path = value; break;
      case "domain": parsed.domain = value; break;
      case "expires": parsed.expires = value; break;
      case "max-age": parsed.maxAge = Number(value); break;
      case "secure": parsed.secure = true; break;
      case "httponly": parsed.httpOnly = true; break;
      case "samesite": parsed.sameSite = value; break;
      case "partitioned": parsed.partitioned = true; break;
      default: parsed.extensions = [...(parsed.extensions ?? []), [key, value ?? ""]];
    }
  }
  return { parsed };
}

function mapCookies(req, requestProv) {
  const rawValues = req.requestHeaders.filter((h) => h.name === "cookie").map((h) => h.value);
  const cookieProv = provenance(req.verification.cookies);
  const pairs = req.cookiesSent.map((c) => ({
    name: c.name,
    value: c.value,
    raw: `${c.name}=${c.value}`,
    ...cookieProv,
  }));
  // Demo of Cookie splitting on the wire (h2/h3): only where the example payload makes
  // clear the lines are synthetic. The raw field stays.
  const fragmented = req.id === "req-0008" && rawValues.length === 1;
  const wireLines = fragmented
    ? [rawValues[0].split("; ").slice(0, 2).join("; "), rawValues[0].split("; ").slice(2).join("; ")]
    : rawValues;
  return {
    raw: rawValues,
    pairs,
    wireLines,
    unparsed: [],
    ...(fragmented ? { notes: ["synthetic demo: two Cookie lines on the wire"] } : {}),
    provenance: cookieProv,
  };
}

function setCookies(req) {
  const prov = provenance(req.verification.cookies);
  return req.cookiesReceived.map((c) => ({
    raw: c.raw,
    ...parseSetCookie(c.raw),
    ...prov,
    notes: ["synthetic fixture"],
  }));
}

function timings(req) {
  const estimated = req.verification.timings.status === "unverified";
  return {
    wallTime: req.startedAt,
    totalMs: req.durationMs,
    estimated,
    ...(estimated ? {} : {}),
  };
}

const attachments = {};
const requests = [];
const warnings = [];
const connections = new Map();
const streamSessions = [];

for (const req of legacy.requests) {
  const requestProv = provenance(req.verification.requestHeaders);
  const responseProv = provenance(req.verification.responseHeaders);
  const requestProvBody = provenance(req.verification.payload);
  const responseProvBody = provenance(req.verification.responseBody);

  const payloadName = req.payload.preview ? `${req.id}.request.txt` : undefined;
  const responseName = req.responseBody.preview ? `${req.id}.response.txt` : undefined;
  if (payloadName) attachments[payloadName] = req.payload.preview;
  if (responseName) attachments[responseName] = req.responseBody.preview;

  const requestHeaders = headerView(req.requestHeaders, req.verification.requestHeaders);
  const responseHeaders = headerView(req.responseHeaders, req.verification.responseHeaders);
  const requestBody = mapBody(req.payload, req.verification.payload, payloadName);
  const responseBody = mapBody(req.responseBody, req.verification.responseBody, responseName);

  const proto = protocol(req.protocol);
  const matched = req.id === "req-0007" ? "unmatched" : req.id === "req-0011" ? "ambiguous" : "matched";
  const candidates =
    matched === "ambiguous"
      ? [
          { entityId: `${req.id}-candidate-a`, score: 62, reasons: ["same URL", "same method", "2 ms window"] },
          { entityId: `${req.id}-candidate-b`, score: 58, reasons: ["same URL", "same method", "different loaderId"] },
        ]
      : undefined;

  const attemptId = `${req.id}-a0`;
  const host = new URL(req.url).host;
  const connectionId = `conn-${host}-${protocol}`;
  if (!connections.has(connectionId)) {
    connections.set(connectionId, {
      id: connectionId,
      netlogId: 40 + connections.size,
      protocol,
      host,
      port: 443,
      alpn: protocol === "unknown" ? undefined : protocol,
      tlsVersion: "TLS 1.3",
      reused: connections.size > 0,
      provenance: provenance(req.verification.protocol),
    });
  }
  const streamSessionId = `stream-${req.id}`;
  streamSessions.push({
    id: streamSessionId,
    connectionId,
    protocol,
    streamId: 1 + streamSessions.length,
    attemptId,
    netlogSessionId: 40 + connections.size,
    provenance: provenance(req.verification.protocol),
  });
  const attempts = [
    {
      id: attemptId,
      logicalId: req.id,
      index: 0,
      url: req.url,
      method: req.method,
      protocol: proto,
      ...(req.status ? { status: req.status } : {}),
      connectionId,
      streamSessionId,
      outcome: "completed",
      requestHeaders,
      responseHeaders,
      cookie: mapCookies(req, requestProv),
      setCookies: setCookies(req),
      headerEvidence: [],
      requestBody,
      responseBody,
      ...(req.primarySource === "cdp"
        ? { cdp: { requestId: `cdp-${req.id}`, loaderId: `loader-${req.id}` } }
        : {}),
      netlog: { sourceIds: [3000 + requests.length], streamIds: proto === "h2" ? [7] : [] },
      match: matched,
      ...(candidates ? { matchCandidates: candidates } : {}),
      provenance: requestProv,
    },
  ];

  const redirects = [];
  if (req.redirects.length > 1) {
    for (let i = 1; i < req.redirects.length; i += 1) {
      const hop = req.redirects[i];
      const nextId = `${req.id}-a${i}`;
      attempts.push({
        id: nextId,
        logicalId: req.id,
        index: i,
        url: hop.url,
        method: req.method,
        protocol: protocol(hop.protocol),
        ...(hop.status ? { status: hop.status } : {}),
        outcome: "completed",
        requestHeaders: { headers: [], orderState: "unknown", notes: ["headers of this hop were not preserved in the fixture"] },
        responseHeaders: { headers: [], orderState: "unknown", notes: ["headers of this hop were not preserved in the fixture"] },
        cookie: { raw: [], pairs: [], wireLines: [], unparsed: [], provenance: provenance(undefined) },
        setCookies: [],
        headerEvidence: [],
        requestBody: { state: "unavailable", note: "hop without body in the fixture", provenance: provenance(undefined) },
        responseBody: { state: "unavailable", note: "hop without body in the fixture", provenance: provenance(undefined) },
        netlog: {},
        match: "unmatched",
        provenance: provenance(undefined),
      });
      redirects.push({
        id: `${req.id}-r${i}`,
        logicalId: req.id,
        fromAttemptId: `${req.id}-a${i - 1}`,
        toAttemptId: nextId,
        ...(hop.status ? { status: hop.status } : {}),
        ...(hop.location ? { location: hop.location } : {}),
        fromUrl: req.redirects[i - 1].url,
        toUrl: hop.url,
        provenance: provenance(req.verification.responseHeaders),
      });
    }
  }

  requests.push({
    id: req.id,
    url: req.url,
    method: req.method,
    protocol: proto,
    ...(req.status ? { status: req.status } : {}),
    resourceType: req.type,
    ...(req.primarySource === "cdp" ? { cdp: { requestId: `cdp-${req.id}`, loaderId: `loader-${req.id}` } } : {}),
    netlog: { sourceIds: [3000 + requests.length], streamIds: proto === "h2" ? [7] : [] },
    attempts,
    ...(redirects.length ? { redirects } : {}),
    requestHeaders,
    responseHeaders,
    cookie: mapCookies(req, requestProv),
    setCookies: setCookies(req),
    requestBody,
    responseBody,
    timings: timings(req),
    match: matched,
    ...(candidates ? { matchCandidates: candidates } : {}),
    provenance: requestProv,
  });

  if (matched === "ambiguous") {
    warnings.push({
      code: "correlation.ambiguous",
      message: "Two NetLog attempts match the same URL and time window; neither was chosen.",
      severity: "warning",
      entity: req.id,
      detail: { candidates: candidates?.map((c) => c.entityId) },
    });
  }
}

warnings.unshift({
  code: "fixture.synthetic",
  message: "Synthetic v1 contract fixture: no bytes were captured from a real site.",
  severity: "info",
  entity: "demo-synthetic-01",
});
warnings.push({
  code: "capture.body.discarded",
  message: "Body discarded by the sensitive-capture policy; not recoverable.",
  severity: "warning",
  entity: "req-0013",
});

const session = {
  schemaVersion: 1,
  session: {
    id: "demo-synthetic-01",
    browser: {
      name: "Chrome",
      version: "156.0.8079.0",
      platform: "macOS arm64 (test build)",
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
    },
    startedAt: "2026-10-26T18:02:11.418Z",
    endedAt: "2026-10-26T18:02:19.870Z",
    completeness: {
      state: "complete",
      reasons: [],
      counts: {
        requests: legacy.requests.length,
        attempts: legacy.requests.length + 1,
        redirects: 1,
        connections: 2,
        streamSessions: 2,
        sourceEvents: legacy.capture.cdpEvents,
        sourceEventsUsed: legacy.capture.cdpEvents - 4,
        sourceEventsUnknown: 4,
        warnings: warnings.length,
      },
    },
    capture: {
      mode: "cdp+netlog",
      browserBinary: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      headless: false,
      notes: "Synthetic demo fixture; no Chrome was started to generate this file.",
    },
    labels: ["synthetic-fixture", "demo"],
    notes: [...legacy.notes, "File generated by app/scripts/gen-demo-v1.mjs from the wave-1 demo fixture."],
  },
  requests,
  connections: [...connections.values()],
  streamSessions,
  warnings,
};

const outJson = path.join(appRoot, "src/demo/session.v1.json");
const outAttachments = path.join(appRoot, "src/demo/attachments.json");
const rustCopy = path.resolve(appRoot, "..", "src-tauri/demo/session.json");

fs.writeFileSync(outJson, JSON.stringify(session, null, 2) + "\n");
fs.writeFileSync(outAttachments, JSON.stringify(attachments, null, 2) + "\n");
fs.writeFileSync(rustCopy, JSON.stringify(session, null, 2) + "\n");

console.log(`session v1: ${requests.length} requests, ${warnings.length} warnings`);
console.log(`attachments: ${Object.keys(attachments).length} previews`);
console.log(`written: ${outJson}`);
console.log(`written: ${rustCopy}`);
