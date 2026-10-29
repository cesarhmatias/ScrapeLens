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
import { classifyTransforms } from "../src/transforms";
assert.deepEqual(classifyTransforms(["chrome-decoded"]), { warn: [], chromeDecoded: true });
assert.deepEqual(classifyTransforms(["chrome-decoded", "charset:iso-8859-1->utf-8"]), { warn: ["charset:iso-8859-1->utf-8"], chromeDecoded: true });
assert.deepEqual(classifyTransforms(["lossy-postData"]).warn, ["lossy-postData"]);
assert.deepEqual(classifyTransforms(undefined), { warn: [], chromeDecoded: false });
import { dynamicOnly, fieldClassLabel, groupOrigins, oldestEvidence, originStatusLabel } from "../src/flow";
const vo = (over: any) => ({ scope: "body", field: "f", occurrence: 0, value: "v", length: 1, status: "none", label: "", offset: null, oldest: null, evidences: [], repeatedFrom: [], parent: null, note: null, ...over });
const grouped = groupOrigins([vo({ field: "XML", status: "composite" }), vo({ field: "XML", parent: "XML", offset: 0 }), vo({ field: "XML", parent: "XML", offset: 20 }), vo({ field: "OTHER" })]);
assert.equal(grouped.length, 2);
assert.equal(grouped[0].parts.length, 2);
assert.equal(originStatusLabel(vo({ status: "none" })), "sem origem observada");
assert.equal(originStatusLabel(vo({ status: "ambiguous" })), "ambíguo");
const ev = (id: string) => ({ kind: "value-match", strength: "medium", role: "produced", producerRequestId: id, producerAttemptId: id, scope: "responseBody", field: null, producerOffset: null, consumedOffset: null, consumedLength: null });
assert.equal(oldestEvidence(vo({ evidences: [ev("a"), ev("b")], oldest: 1 }))?.producerRequestId, "b");
assert.equal(oldestEvidence(vo({ evidences: [ev("a")], oldest: null })), undefined);
const fd = (over: any) => ({ scope: "body", field: "f", occurrence: 0, class: "static", label: "", dynamicKind: null, originLabel: null, a: "1", b: "1", origin: null, parts: [], ...over });
const counts = { static: 0, dynamic: 0, runtime: 0, noOrigin: 0, onlyA: 0, onlyB: 0, redacted: 0 };
const pairs = [
  { a: { requestId: "a1", method: "GET", url: "u" }, b: { requestId: "b1", method: "GET", url: "u" }, alignedBy: "model", outOfOrder: false, counts, fields: [fd({ field: "z" }), fd({ field: "a", class: "dynamic", dynamicKind: "runtime", originLabel: "obter em runtime (origem: cdp-r0001)" })] },
  { a: { requestId: "a2", method: "GET", url: "u" }, b: { requestId: "b2", method: "GET", url: "u" }, alignedBy: "model", outOfOrder: false, counts, fields: [fd({})] },
] as any;
const dyn = dynamicOnly(pairs);
assert.equal(dyn.length, 1);
assert.equal(dyn[0].fields[0].field, "a");
assert.deepEqual(pairs[0].fields.map((f: any) => f.field), ["z", "a"]); // ordem da fonte, sem ordenar
assert.equal(fieldClassLabel(pairs[0].fields[1]), "obter em runtime (origem: cdp-r0001)");
assert.equal(fieldClassLabel(fd({ class: "dynamic", dynamicKind: "noOrigin" })), "dinâmico sem origem");
assert.equal(fieldClassLabel(fd({})), "estático");
import { DYNAMIC_ONLY_THRESHOLD, dynamicSummary, originConfidence, stepConfidence, visibleFields } from "../src/flow";
const strongEv = { ...ev("p"), kind: "cookie-jar", strength: "strong" };
// esquema antigo: status "origin" decide pela força da evidência
assert.equal(originConfidence(vo({ status: "origin", evidences: [ev("a")] })), "possible");
assert.equal(originStatusLabel(vo({ status: "origin", evidences: [ev("a")], oldest: 0 })), "possível origem (value-match)");
assert.equal(originConfidence(vo({ status: "origin", evidences: [strongEv] })), "strong");
assert.equal(originStatusLabel(vo({ status: "origin", evidences: [strongEv], oldest: 0 })), "origem observada");
assert.equal(originConfidence(vo({ status: "origin", evidences: [ev("a"), strongEv] })), "strong");
// esquema novo: campo `confidence` do core decide (mesmo contra a força das evidências)
assert.equal(originConfidence(vo({ status: "origin", confidence: "possible", evidences: [strongEv] })), "possible");
assert.equal(originConfidence(vo({ status: "origin", confidence: "strong", evidences: [ev("a")] })), "strong");
assert.equal(originConfidence(vo({ status: "origin", confidence: null, evidences: [ev("a")] })), "possible");
// status "possible-origin" hipotético
assert.equal(originConfidence(vo({ status: "possible-origin", evidences: [ev("a")] })), "possible");
assert.match(originStatusLabel(vo({ status: "possible-origin", evidences: [ev("a")], oldest: 0 })), /^possível origem/);
assert.equal(originStatusLabel(vo({ status: "ambiguous", evidences: [ev("a"), ev("b")] })), "ambíguo (possível origem)");
assert.equal(originConfidence(vo({ status: "none" })), "none");
const reason = (strength: string) => ({ provides: "x", field: "f", kind: "k", strength, consumedBy: "r" });
const step = (over: any) => ({ requestId: "r", attemptId: "a", method: "GET", url: "u", startedAt: 0, class: "application", reason: "", reasons: [], ...over });
assert.equal(stepConfidence(step({ confidence: "possible", reasons: [reason("strong")] })), "possible");
assert.equal(stepConfidence(step({ reasons: [reason("medium")] })), "possible");
assert.equal(stepConfidence(step({ reasons: [reason("medium"), reason("strong")] })), "strong");
assert.equal(stepConfidence(step({ confidence: "strong" })), "strong");
const pc = { static: 5, dynamic: 12, runtime: 12, noOrigin: 0 };
assert.equal(dynamicSummary({ ...counts, dynamic: 44 }, pc), "44 dinâmico(s), sendo 12 em trechos de campos compostos");
assert.equal(dynamicSummary({ ...counts, dynamic: 44 }), "44 dinâmico(s)");
assert.equal(visibleFields([fd({ field: "s" }), fd({ field: "d", class: "dynamic" })], true).length, 1);
assert.equal(visibleFields([fd({ field: "s" }), fd({ field: "d", class: "dynamic" })], false).length, 2);
assert.equal(DYNAMIC_ONLY_THRESHOLD, 500);
assert.equal(originStatusLabel(vo({ status: "origin", confidence: "possible", label: "possível origem (value-match)", evidences: [ev("a")] })), "possível origem (value-match)");
assert.equal(originStatusLabel(vo({ status: "origin", confidence: "strong", label: "origem observada", evidences: [strongEv] })), "origem observada");
import { CONTEXT_LABEL, highlightedWarnings, isCookiesAbsent, partialCompositionText, producerKindLabel, roundHeader } from "../src/flow";
assert.equal(producerKindLabel({ ...ev("p"), htmlControl: true, field: "STAMP" } as any), "controle de formulário HTML (STAMP)");
assert.equal(producerKindLabel(ev("p") as any), null);
assert.equal(CONTEXT_LABEL, "também presente em recurso estático: provável constante do protocolo");
assert.equal(partialCompositionText(vo({})), null);
assert.equal(partialCompositionText(vo({ partialComposition: [] })), null);
assert.equal(
  partialCompositionText(vo({ label: "sem origem observada; contém o valor de SESSIONID de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente", partialComposition: [{ producerRequestId: "har-0001", field: "SESSIONID", start: 0, length: 9 }] })),
  "sem origem observada; contém o valor de SESSIONID de har-0001 (prefixo) e parte sem fonte observada — provável composição no cliente",
);
assert.match(partialCompositionText(vo({ label: "x", partialComposition: [{ producerRequestId: "har-0001", field: "SESSIONID", start: 0, length: 9 }] }))!, /^sem origem observada; contém SESSIONID de har-0001 \+ parte sem fonte — provável composição no cliente$/);
assert.equal(partialCompositionText(vo({ partialComposition: "texto do core" })), "texto do core");
const warns = highlightedWarnings(["a", "o HAR não contém cookies (exportação...)"], ["a", "b"]);
assert.deepEqual(warns, ["o HAR não contém cookies (exportação...)", "a", "b"]);
assert.equal(isCookiesAbsent("har.cookies_absent"), true);
const rounds = [{ aRound: 0, bRound: 1, score: 9, aRequests: 12, bRequests: 11 }];
assert.equal(roundHeader(0, undefined, rounds), "Rodada 1: A#1 ↔ B#2 · 12 × 11 requisições · 9 modelo(s) em comum");
assert.equal(roundHeader(0, 0, rounds), null);
assert.equal(roundHeader(undefined, undefined, rounds), null);
// origem com unobservable.suggestion: o campo é preservado pelo adapter de tipos
const sug = vo({ unobservable: [{ requestId: "har-0003", state: "unavailable", suggestion: "har-0030" }] }) as any;
assert.equal(sug.unobservable[0].suggestion, "har-0030");
import { initiatorLabel } from "../src/v1/adapter";
assert.equal(initiatorLabel(undefined), undefined);
assert.equal(initiatorLabel({ kind: "parser", url: "https://x.invalid/a.html" }), "parser · https://x.invalid/a.html");
assert.equal(initiatorLabel({ kind: "script" }), "script");
const withInit = structuredClone(minimal) as any;
withInit.requests[0].attempts = [{ id: "a", logicalId: "r", index: 0, url: "u", method: "GET", protocol: "h1", initiator: { kind: "parser", url: "https://x.invalid/p" } }];
assert.equal(adaptSession(withInit).session.requests[0].initiator, "parser · https://x.invalid/p");
assert.equal(adaptSession(minimal).session.requests[0].initiator, undefined);
import { isAppFailure, type ResponseOutcome } from "../src/assess";
const oc = (verdictKind: ResponseOutcome["verdictKind"], httpOk = true) => ({ requestId: "r", method: "POST", url: "u", status: 200, httpOk, appSignals: [], verdict: verdictKind, verdictKind, missingFields: [] }) as ResponseOutcome;
assert.equal(isAppFailure(oc("app-error")), true);
assert.equal(isAppFailure(oc("blocked")), true); // 200 bloqueado fica visível no filtro
assert.equal(isAppFailure(oc("indeterminado")), false);
assert.equal(isAppFailure(oc("app-ok")), false);
assert.equal(isAppFailure(undefined), false);
console.log("adapter-minimal: ok");
