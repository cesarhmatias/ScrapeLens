// Harness da rodada 8 (adaptador Natural for Ajax) sobre fixtures/detran-pb-real-shape
// (import-har --label synthetic-fixture). Os dados de origens, cadeia, visão do adaptador e
// prévia do script de priming vêm do Rust real (teste ignorado `dump_adapter_evidence`, que
// registra o adaptador como o app); só o seletor nativo de pasta é SIMULADO.
// uso: node ui-harness-adapter.mjs <sessao> <dumpDir> <saida>
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
const dumped = (id, kind) => {
  const f = path.join(dump, `${id}.${kind}.json`);
  if (!fs.existsSync(f)) throw new Error(`sem dump ${id}.${kind}`);
  return JSON.parse(fs.readFileSync(f, "utf8"));
};
async function rpc(cmd, args) {
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "assess_session": return { schema: "scrapelens.assess/1", rules: "default", counts: {}, warnings: [], outcomes: [] };
    case "request_origins": return dumped(args.requestId, "origins");
    case "request_chain": return dumped(args.requestId, "chain");
    case "adapter_view": {
      try { return dumped(args.requestId, args.side); } catch { return { side: args.side, fields: [], note: null }; }
    }
    case "export_request": return dumped(args.requestId, "priming");
    case "search_session": return { matches: [], scopesSearched: [], partial: false, partialAttempts: [], warnings: [] };
    case "read_body": {
      const buf = fs.readFileSync(path.join(args.sessionDir, "attachments", args.name));
      return { kind: "text", text: buf.toString("utf8"), bytes: buf.length, shownBytes: buf.length, cut: false };
    }
    default: return null;
  }
}
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await page.exposeFunction("__rpc", rpc);
await page.addInitScript((dir) => {
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1, unregisterCallback: () => {}, convertFileSrc: (p) => p,
    invoke: async (cmd, args = {}) => {
      switch (cmd) {
        case "app_info": return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
        case "detect_chrome": return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
        case "plugin:event|listen": return 1;
        case "plugin:event|unlisten": return null;
        case "plugin:dialog|open": return dir;
        default: return window.__rpc(cmd, args);
      }
    },
  };
}, sessionDir);
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const shot = (name) => page.screenshot({ path: path.join(outDir, name) });
const results = {};
await page.goto(url, { waitUntil: "networkidle" });
await page.getByRole("button", { name: "Abrir captura…" }).click();
await page.waitForSelector("tbody tr:not(.spacer)");
await page.locator("tbody tr:not(.spacer)", { hasText: "har-0026" }).first().click().catch(async () => {
  await page.locator("tbody tr:not(.spacer)").nth(25).click();
});
await page.waitForTimeout(300);
// Origem: nomes internos do adaptador
await page.getByRole("tab", { name: /Origem/ }).click();
await page.waitForSelector(".origin-table");
results.originFields = await page.locator(".origin-table tbody tr").evaluateAll((rows) => rows.map((r) => r.innerText.replace(/\s+/g, " ").slice(0, 140)).filter((t) => /XML/.test(t)));
await page.locator(".origin-table").first().scrollIntoViewIfNeeded();
await shot("34-origem-nomes-adaptador.png");
// Visão estruturada no painel de payload (bruto primário acima, visão derivada abaixo)
await page.getByRole("tab", { name: /Payload/ }).click();
await page.waitForSelector("text=Visão do adaptador Natural (derivada)");
results.viewHeading = await page.locator("h3", { hasText: "Visão do adaptador" }).first().innerText();
results.viewRows = await page.locator("section:has(h3:has-text('Visão do adaptador')) tbody tr").evaluateAll((rows) => rows.map((r) => r.innerText.replace(/\s+/g, " ")));
await page.locator("h3", { hasText: "Visão do adaptador" }).first().scrollIntoViewIfNeeded();
await shot("35-visao-adaptador-natural.png");
if (process.env.HARNESS_ERR) {
  // Painel de erro de decode (campo grande demais) com a visão real do Rust sobre um corpo de 512 KiB + 10.
  await page.getByRole("tab", { name: /Payload/ }).click();
  await page.waitForSelector("text=Não foi possível decodificar o campo");
  results.errorPanel = await page.locator("section:has(h3:has-text('Visão do adaptador')) .body-flag").first().innerText();
  await shot("37-visao-adaptador-campo-grande.png");
  results.pageErrors = errors;
  fs.writeFileSync(path.join(outDir, "ui-harness-adapter-error-result.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
  await browser.close(); server.close(); process.exit(0);
}
// Exportar: script de priming com o codificador do adaptador
await page.getByRole("button", { name: /Exportar/ }).first().click();
await page.getByRole("tab", { name: /Script de priming/ }).click();
await page.waitForSelector("text=codificador do adaptador");
results.primingNote = await page.locator(".notice-info").last().innerText();
results.primingHasEncoder = (await page.locator("body").innerText()).includes("natural_ajax_encode");
await shot("36-exportar-priming-adaptador.png");
results.pageErrors = errors;
fs.writeFileSync(path.join(outDir, "ui-harness-adapter-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
