// Request mínima = fixture de exportação (campos opcionais omitidos, como o core aceita).
// Rodar: npm run test:adapter
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { adaptSession } from "../src/v1/adapter";
import type { SessionV1 } from "../src/v1/types";

const minimal = {
  schemaVersion: 1,
  session: { id: "s", startedAt: "2026-10-27T15:00:00Z", labels: [], completeness: { state: "complete", counts: {} } },
  requests: [{ id: "r", method: "POST", url: "https://x.invalid/echo", protocol: "h1", status: 200 }],
} as unknown as SessionV1;

const run = (raw: SessionV1) => adaptSession(raw).session.requests[0];

let r = run(minimal);
assert.equal(r.attempts.length, 0);
assert.equal(r.redirects.length, 0);
assert.equal(r.cookiesSent.length, 0);
assert.equal(r.cookiesReceived.length, 0);
assert.equal(r.requestHeaders.length, 0);
assert.equal(r.payload.availability, "unavailable");
assert.equal(r.verification.protocol.status, "partial");

const bare = { schemaVersion: 1, session: { id: "s", startedAt: "t" }, requests: [minimal.requests[0]] } as unknown as SessionV1;
const a = adaptSession(bare);
assert.equal(a.session.completeness.state, "partial");
assert.equal(a.session.requests.length, 1);

const withAttempt = structuredClone(minimal) as any;
withAttempt.requests[0].attempts = [{ id: "a", logicalId: "r", index: 0, url: "u", method: "GET", protocol: "h1" }];
r = run(withAttempt);
assert.equal(r.attempts[0].outcome, "unknown");
assert.equal(r.attempts[0].requestHeaderCount, 0);

try {
  const f = JSON.parse(readFileSync("../tests/.work/exportacao-manual/source/session.json", "utf8"));
  const fr = run(f);
  assert.equal(fr.method, "POST");
  assert.equal(fr.requestHeaders.length, 3);
  assert.equal(fr.attempts.length, 0);
  console.log("fixture exportacao-manual: ok");
} catch (e: any) {
  if (e.code !== "ENOENT") throw e;
}
// Rótulos de origem: nunca "real"/"ao vivo" sem rótulo explícito do core.
const origin = (labels: string[]) => {
  const raw = structuredClone(minimal) as any;
  raw.session.labels = labels;
  return adaptSession(raw).session;
};
assert.deepEqual(
  [origin([]).origin.kind, origin([]).origin.real, origin([]).origin.label],
  ["unknown", false, "origem não informada"],
);
assert.equal(origin(["live-capture"]).origin.label, "Captura ao vivo");
assert.equal(origin(["live-capture"]).origin.real, true);
assert.equal(origin(["capture-import"]).origin.label, "Captura importada (CDP/NetLog)");
assert.equal(origin(["capture-import"]).origin.real, true);
assert.equal(origin(["har-import"]).origin.label, "HAR importado");
assert.equal(origin(["netlog-import"]).origin.label, "NetLog importado");
assert.equal(origin(["synthetic-fixture", "capture-import"]).origin.kind, "synthetic");
assert.equal(origin(["synthetic-fixture"]).origin.real, false);
assert.equal(origin(["sanitized"]).origin.real, false);
assert.match(origin(["sanitized"]).origin.label, /origem não informada/);
assert.match(origin(["sanitized", "live-capture"]).label, /Captura ao vivo \(sanitizada\)/);
const tr = structuredClone(minimal) as any;
tr.requests[0].responseBody = { state: "captured", attachment: "a.body", bytes: 3, transformed: ["chrome-decoded"], provenance: { source: "cdp", method: "m", verification: "verified" } };
assert.deepEqual(adaptSession(tr).session.requests[0].responseBody.transformed, ["chrome-decoded"]);
// Realce: bytes UTF-8 → índices JS; sem byteLength nada é realçado.
import { matchRanges } from "../src/highlight";
const txt = "á=é&cmd=ação";
const enc = new TextEncoder();
const off = enc.encode("á=é&cmd=").length;
const got = matchRanges(txt, [{ byteOffset: off, byteLength: enc.encode("ação").length, decoded: true, exact: false }]);
assert.deepEqual(got.ranges, [{ start: 8, end: 12, decoded: true }]);
assert.equal(txt.slice(got.ranges[0].start, got.ranges[0].end), "ação");
assert.equal(matchRanges(txt, [{ byteOffset: 0, decoded: false }]).ranges.length, 0);
assert.equal(matchRanges(txt, [{ byteOffset: 0, byteLength: 9999, decoded: false }]).beyond, 1);
// Realce sólido (exact + trecho literal) × tracejado (exact=false ou trecho diferente).
const lit = "x=cmd_consultar_placa&y=a%20b";
const o1 = enc.encode("x=").length;
const solid = matchRanges(lit, [{ byteOffset: o1, byteLength: 19, decoded: true, exact: true }], "cmd_consultar_placa");
assert.equal(solid.ranges[0].decoded, false);
assert.equal(matchRanges(lit, [{ byteOffset: o1, byteLength: 19, decoded: true, exact: true }], "CMD_CONSULTAR_PLACA", true).ranges[0].decoded, true);
const pct = matchRanges(lit, [{ byteOffset: lit.indexOf("a%20b"), byteLength: 5, decoded: true, exact: true }], "a b");
assert.equal(pct.ranges[0].decoded, true);
assert.equal(matchRanges(lit, [{ byteOffset: o1, byteLength: 19, decoded: false, exact: false }], "cmd_consultar_placa").ranges[0].decoded, true);
console.log("adapter-minimal: ok");
