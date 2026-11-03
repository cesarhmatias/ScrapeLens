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

// Ressalva (b): abrir uma sessão de 20.002 requisições faz no máximo 2 list_requests até a 1ª tela.
import { PagedList, pagesFor } from "../src/listView";
assert.deepEqual(pagesFor(0, 30, undefined, 2000), [0]);
assert.deepEqual(pagesFor(0, 30, 20002, 2000), [0, 1]);
assert.deepEqual(pagesFor(0, 30, 13, 2000), [0]);
assert.deepEqual(pagesFor(0, 0, 0, 2000), []);
assert.deepEqual(pagesFor(19990, 20002, 20002, 2000), [9, 10]);

await (async () => {
  const total = 20002;
  const seen: number[] = [];
  let renders = 0;
  const list = new PagedList<number, { matched: number }>(
    async (offset, limit) => {
      seen.push(offset);
      const rows = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, i) => offset + i);
      return { meta: { matched: total }, rows };
    },
    2000,
    () => {
      renders++;
      list.ensure(0, 30); // cada re-render pede de novo a janela visível
    },
  );
  // Montagem: três renders seguidos (StrictMode/efeitos) não podem multiplicar as chamadas.
  list.ensure(0, 30);
  list.ensure(0, 30);
  list.ensure(0, 30);
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  assert.ok(list.calls <= 2, `list_requests até a 1ª tela: ${list.calls}`);
  assert.deepEqual(seen, [0, 2000]);
  assert.equal(list.length, total);
  assert.equal(list.row(0), 0);
  assert.equal(list.row(2001), 2001);
  assert.ok(renders >= 1);
  // Rolar até o fim busca só as páginas da janela (+ folga), não as intermediárias.
  list.ensure(19990, 20002);
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(seen, [0, 2000, 18000, 20000]);
})();
console.log("paged-window ok");
