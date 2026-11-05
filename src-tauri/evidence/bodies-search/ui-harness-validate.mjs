// Harness da rodada 9: linha do tempo e "Validar execução…" sobre fixtures/detran-pb-real-shape
// (import-har --label synthetic-fixture) e traces gerados pelo script de priming contra o detran-sim
// local (127.0.0.1, modos ok e 403: trace-sim-ok.json / trace-sim-403.json). Timeline e validação vêm do
// Rust real (teste ignorado `dump_round9_evidence`); só o seletor nativo de pasta/arquivo é SIMULADO.
// uso: node ui-harness-validate.mjs <sessao> <dumpDir> <saida>
import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const [sessionDir, dump, outDir] = process.argv.slice(2);
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;
const J = (f) => JSON.parse(fs.readFileSync(path.join(dump, f), "utf8"));
let nextValidate = 0;
let dialogs = 0;
async function rpc(cmd, args) {
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "assess_session": return { schema: "scrapelens.assess/1", rules: "default", counts: {}, warnings: [], outcomes: [] };
    case "session_timeline": return J("timeline.json");
    case "validate_execution": return J(`validate-${nextValidate}.json`);
    case "adapter_view": return { side: args.side, fields: [], note: null };
    case "search_session": return { matches: [], scopesSearched: [], partial: false, partialAttempts: [], warnings: [] };
    default: return null;
  }
}
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await page.exposeFunction("__rpc", rpc);
await page.exposeFunction("__dialog", () => (dialogs++ === 0 ? sessionDir : `${dump}/trace-selecionado.json`));
await page.addInitScript(() => {
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1, unregisterCallback: () => {}, convertFileSrc: (p) => p,
    invoke: async (cmd, args = {}) => {
      switch (cmd) {
        case "app_info": return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
        case "detect_chrome": return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
        case "plugin:event|listen": return 1;
        case "plugin:event|unlisten": return null;
        case "plugin:dialog|open": return window.__dialog();
        default: return window.__rpc(cmd, args);
      }
    },
  };
});
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const shot = (name) => page.screenshot({ path: path.join(outDir, name) });
const results = {};
await page.goto(url, { waitUntil: "networkidle" });
await page.getByRole("button", { name: "Abrir captura…" }).click();
await page.waitForSelector("tbody tr:not(.spacer)");
// Linha do tempo
await page.getByRole("button", { name: "Linha do tempo" }).click();
await page.waitForSelector(".timeline-table tbody tr");
results.timelineRows = (await page.locator(".timeline-table tbody tr").evaluateAll((rows) => rows.map((r) => r.innerText.replace(/\s+/g, " ").slice(0, 150)))).slice(0, 16);
await shot("38-timeline.png");
await page.locator(".timeline-group summary").first().click();
results.groupExpanded = await page.locator(".timeline-group .chips").first().innerText();
// clicar abre a requisição
await page.locator(".timeline-table tr.clickable").nth(8).click();
await page.waitForSelector(".tabs");
results.openedFromTimeline = await page.locator("h1, .req-title, .detail-head").first().innerText().catch(() => null);
await page.getByRole("button", { name: /Sessão/ }).first().click();
// Validar execução: trace ok, depois 403
for (const [n, name] of [[0, "39-validate-execution-equivalent.png"], [1, "40-validate-execution-diverges-403.png"], [2, "41-validate-execution-incomplete.png"]]) {
  nextValidate = n;
  await page.getByRole("button", { name: "Validar execução…" }).click();
  await page.waitForSelector(".validation-table tbody tr");
  results[`summary${n}`] = await page.locator(".validation-view .notice").first().innerText();
  results[`warning${n}`] = await page.locator(".validation-view .notice-info").first().innerText();
  results[`steps${n}`] = await page.locator(".validation-table tbody tr").evaluateAll((rows) => rows.map((r) => r.innerText.replace(/\s+/g, " ").slice(0, 170)));
  await shot(name);
  await page.getByRole("button", { name: /← Sessão/ }).click();
}
results.pageErrors = errors;
fs.writeFileSync(path.join(outDir, "ui-harness-validate-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
