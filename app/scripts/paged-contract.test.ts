// P5 (docs/19-contrato-app.md): o detalhe sob demanda e o resumo da lista
// produzem o mesmo que o adaptador da sessão inteira. Rodar: npm run test:paged
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { adaptRequestDetail, adaptSession, summaryFromRaw, summaryOfRecord } from "../src/v1/adapter";
import type { RawRequestSummary, SessionV1 } from "../src/v1/types";

const demo = JSON.parse(readFileSync(new URL("../src/demo/session.v1.json", import.meta.url), "utf8")) as SessionV1;
const full = adaptSession(demo);
const header: SessionV1 = { ...demo, requests: [], warnings: (demo.warnings ?? []).filter((w) => !w.entity) };

assert.ok(full.session.requests.length >= 2, "fixture demo precisa de requisições");
assert.equal(full.session.paged, false);
assert.equal(adaptSession({ ...header, requestCount: 7 } as SessionV1).session.paged, true);
assert.equal(adaptSession({ ...header, requestCount: 7 } as SessionV1).session.requestCount, 7);

for (const [index, request] of demo.requests.entries()) {
  const attemptIds = new Set(request.attempts.map((a) => a.id));
  const detail = {
    request,
    warnings: (demo.warnings ?? []).filter((w) => w.entity === request.id),
    streamSessions: (demo.streamSessions ?? []).filter((s) => s.attemptId && attemptIds.has(s.attemptId)),
  };
  const expected = full.session.requests[index];
  assert.deepEqual(adaptRequestDetail(header, detail), expected, `detalhe ${request.id}`);

  // Resumo como o src-tauri/src/listing.rs monta (campos crus do v1).
  const initiator = request.attempts.at(-1)?.initiator ?? request.attempts[0]?.initiator;
  const raw: RawRequestSummary = {
    id: request.id,
    url: request.url,
    method: request.method,
    status: request.status,
    protocol: request.protocol,
    resourceType: request.resourceType,
    wallTime: request.timings?.wallTime,
    totalMs: request.timings?.totalMs,
    estimated: request.timings?.estimated,
    initiator: initiator ? { kind: initiator.kind, url: initiator.url } : undefined,
    target: request.target ? 0 : undefined,
    links: request.links,
    source: request.provenance.source,
    warningCount: detail.warnings.length,
  };
  assert.deepEqual(summaryFromRaw(raw, demo.session.startedAt, request.target ? [request.target] : []), summaryOfRecord(expected), `resumo ${request.id}`);
}

console.log(`paged-contract: ok (${demo.requests.length} requisições)`);
