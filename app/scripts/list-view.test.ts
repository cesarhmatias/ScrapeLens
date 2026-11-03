// Lista da demo e selo de gravação (rodada 13). Rodar: npm run test:list-view
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { adaptSession, summaryOfRecord } from "../src/v1/adapter";
import type { SessionV1 } from "../src/v1/types";
import { activeFilterLabels, outcomeChipDisabled, sessionIsRecording } from "../src/listView";

const demo = JSON.parse(readFileSync(new URL("../src/demo/session.v1.json", import.meta.url), "utf8")) as SessionV1;
const { session } = adaptSession(demo);
// A demo é em memória (não paginada): a lista sai dos resumos locais, todos visíveis sem filtro.
assert.equal(session.paged, false);
assert.equal(session.requests.map(summaryOfRecord).length, session.requestCount);
assert.equal(session.requestCount, 13);

// Chips de avaliação com 0 não podem ser ligados (era o "0 de 13" do print); ativos continuam desligáveis.
assert.equal(outcomeChipDisabled(0, false), true);
assert.equal(outcomeChipDisabled(0, true), false);
assert.equal(outcomeChipDisabled(3, false), false);

const none = { query: "", typeFilter: "all", targetFilter: "all", protocol: "all", failFilter: false, blockFilter: false };
assert.deepEqual(activeFilterLabels(none), []);
assert.deepEqual(activeFilterLabels({ ...none, failFilter: true, blockFilter: true }), ["Falhas da aplicação", "Possíveis bloqueios?"]);

// Selo "gravando": separado da sessão exibida.
const rec = { sessionDir: "/x/sessions/capture-1" };
assert.equal(sessionIsRecording({ synthetic: true }, rec), false, "demo nunca recebe o selo");
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/other" }, rec), false);
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/capture-1/" }, rec), true);
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/capture-1" }, null), false);
console.log("list-view ok");
