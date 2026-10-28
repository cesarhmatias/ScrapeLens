// Harness da onda 5b: aba Origem, cadeia de priming, comparação A × B e
// exportação com origens anotadas. Serve o `app/dist` real com Tauri stubado.
// Os comandos de origem/cadeia/comparação/exportação rodam o `scrapelens-core`
// REAL (mesmas funções do core que os commands Rust chamam); o seletor nativo de
// pasta é SIMULADO (devolve a pasta B). Não substitui o teste no .app.
//
// uso: node ui-harness-flow.mjs <sessaoA> <sessaoB> <scrapelens-core> <saida> <export-previews.json>
import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const [dirA, dirB, coreBin, outDir] = process.argv.slice(2);
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;

let pick = dirA;
let cmp = null;
const core = (...a) => JSON.parse(execFileSync(coreBin, a, { maxBuffer: 1 << 28 }).toString());
async function rpc(cmd, args) {
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "request_origins": return core("origins", args.sessionDir, args.requestId);
    case "request_chain": return core("chain", args.sessionDir, args.requestId);
    case "compare_open": {
      // Mesma lógica de resumo/página/campos do Rust (commands.rs), sobre o JSON real do core.
      cmp = core("compare", args.dirA, args.dirB);
      const dyn = (p) => p.counts.dynamic + p.counts.onlyA + p.counts.onlyB + p.counts.redacted > 0;
      return { handle: 1, pairs: cmp.pairs.length, dynamicPairs: cmp.pairs.filter(dyn).length, counts: cmp.counts, partsCounts: cmp.partsCounts, redactedFields: cmp.redactedFields, ambiguities: cmp.ambiguities, warnings: cmp.warnings, onlyInA: cmp.onlyInA.slice(0, 200), onlyInATotal: cmp.onlyInA.length, onlyInB: cmp.onlyInB.slice(0, 200), onlyInBTotal: cmp.onlyInB.length };
    }
    case "compare_page": {
      const dyn = (p) => p.counts.dynamic + p.counts.onlyA + p.counts.onlyB + p.counts.redacted > 0;
      const idx = cmp.pairs.map((p, index) => ({ p, index })).filter(({ p }) => !args.onlyDynamic || dyn(p));
      return { total: idx.length, items: idx.slice(args.offset, args.offset + args.limit).map(({ p, index }) => ({ index, a: p.a, b: p.b, alignedBy: p.alignedBy, outOfOrder: p.outOfOrder, counts: p.counts, partsCounts: p.partsCounts, fieldCount: p.fields.length })) };
    }
    case "compare_fields": return cmp.pairs[args.index].fields;
    case "read_body": {
      const buf = fs.readFileSync(path.join(args.sessionDir, "attachments", args.name));
      return { kind: "text", text: buf.toString("utf8"), bytes: buf.length, shownBytes: buf.length, cut: false };
    }
    case "export_request": {
      // Prévias REAIS geradas pelo Rust (export::preview_with), via teste ignorado dump_export_previews.
      const all = JSON.parse(fs.readFileSync(process.argv[6], "utf8"));
      return all[`${args.format}-${Boolean(args.annotateOrigins)}`];
    }
    default: return null;
  }
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await page.exposeFunction("__rpc", rpc);
await page.exposeFunction("__pick", () => pick);
await page.addInitScript(() => {
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1, unregisterCallback: () => {}, convertFileSrc: (p) => p,
    invoke: async (cmd, args = {}) => {
      switch (cmd) {
        case "app_info": return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
        case "detect_chrome": return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
        case "plugin:event|listen": return 1;
        case "plugin:event|unlisten": return null;
        case "plugin:dialog|open": return window.__pick();
        default: return window.__rpc(cmd, args);
      }
    },
  };
});
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const shot = (name) => page.screenshot({ path: path.join(outDir, name), fullPage: false });
const results = {};

await page.goto(url, { waitUntil: "networkidle" });
await page.getByRole("button", { name: "Abrir captura…" }).click();
await page.waitForSelector("tbody tr:not(.spacer)");
// 1º cmd_consultar_placa = cdp-r0011 (11ª linha da lista)
await page.locator("tbody tr:not(.spacer)").nth(10).click();
await page.getByRole("tab", { name: /Origem/ }).click();
await page.waitForSelector(".origin-table");
await page.waitForSelector(".chain-list");
results.originRows = await page.locator(".origin-table tbody tr").count();
results.originText = await page.locator(".origin-table").innerText();
results.chainText = await page.locator(".chain-list").first().innerText();
results.protectionSection = await page.getByText("Proteção (não é lógica da aplicação)").count();
await shot("12-origem-valores.png");
await page.locator(".chain-list").first().scrollIntoViewIfNeeded();
await page.evaluate(() => document.querySelector(".chain-list")?.scrollIntoView({ block: "start" }));
await shot("13-cadeia-priming.png");
// navegação pela requisição produtora
const firstLink = page.locator(".origin-table .link-req").first();
results.firstLink = await firstLink.innerText();
await firstLink.click();
await page.waitForTimeout(500);
results.afterNavigate = await page.locator(".crumbs .mono").last().innerText();

// Exportação com anotação: volta ao cdp-r0011
await page.getByRole("button", { name: /Sessão/ }).first().click();
await page.locator("tbody tr:not(.spacer)").nth(10).click();
await page.getByRole("button", { name: /Exportar/ }).first().click();
await page.waitForTimeout(500);
results.annotateCheckbox = await page.getByLabel("anotar origens").count();
results.plainHasOriginComment = (await page.locator(".export-code, pre").first().innerText()).includes("obter em runtime");
await page.getByLabel("anotar origens").check();
await page.waitForTimeout(700);
results.annotatedHasOriginComment = (await page.locator(".export-code, pre").first().innerText()).includes("obter em runtime");
await shot("14-export-anotado.png");
await page.keyboard.press("Escape");

// Comparação A × B
await page.getByRole("button", { name: /Sessão/ }).first().click().catch(() => {});
pick = dirB;
await page.getByLabel("Buscar requisições").fill("");
await page.getByRole("button", { name: "Comparar capturas…" }).click();
await page.waitForSelector(".cmp-pair");
results.pairs = await page.locator(".cmp-pair").count();
await page.locator(".cmp-pair").nth(3).getByRole("button", { name: /campos/ }).click();
await page.waitForSelector(".cmp-field");
results.compareHeader = await page.locator(".body-panel .block-meta").first().innerText();
await shot("15-comparacao-ab.png");
await page.getByLabel(/só dinâmicos/).check();
await page.locator(".cmp-pair").nth(2).getByRole("button", { name: /campos/ }).click();
await page.waitForSelector(".cmp-field");
await page.waitForTimeout(300);
results.dynamicOnlyFields = await page.locator(".cmp-field").count();
results.staticLeft = await page.locator(".cmp-field:not(.cmp-dynamic)").count();
await shot("16-comparacao-so-dinamicos.png");

results.pageErrors = errors.filter((e) => !e.includes("unregisterListener"));
fs.writeFileSync(path.join(outDir, "ui-harness-flow-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
