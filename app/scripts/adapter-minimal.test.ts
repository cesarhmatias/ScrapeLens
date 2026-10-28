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
console.log("adapter-minimal: ok");
