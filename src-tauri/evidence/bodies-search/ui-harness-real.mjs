// Harness da onda 6b (docs/10): origem com controle HTML, cadeia com páginas e
// proteção, aviso de HAR sem cookies, compare por rodadas (1×2) e prévia da
// sanitização, sobre fixtures/detran-pb-real-shape importadas com
// `import-har --label synthetic-fixture`. Origens/cadeia/busca/compare rodam o
// `scrapelens-core` REAL; a prévia da sanitização é a do Rust real (teste
// ignorado dump_sanitize_preview). Seletor nativo de pasta SIMULADO.
//
// uso: node ui-harness-real.mjs <rs-1round> <rs-2rounds> <rs-composite> <scrapelens-core> <saida> <sanitize-1round.json>
import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const [d1, d2, dc, coreBin, outDir, sanitizeFile] = process.argv.slice(2);
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;

let pick = d1;
let cmp = null;
let injectedAux = false;
const core = (...a) => JSON.parse(execFileSync(coreBin, a, { maxBuffer: 1 << 28 }).toString());
const dyn = (p) => p.counts.dynamic + p.counts.onlyA + p.counts.onlyB + p.counts.redacted > 0;
async function rpc(cmd, args) {
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "request_origins": return core("origins", args.sessionDir, args.requestId);
    case "request_chain": {
      const chain = core("chain", args.sessionDir, args.requestId);
      // Nenhuma fixture emite auxiliaryPages ainda: INJETADO À MÃO (2 frames sintéticos copiados de `pages`) só para o print 19.
      if (!(chain.auxiliaryPages ?? []).length && chain.pages?.length) {
        chain.auxiliaryPages = chain.pages.slice(0, 2).map((p, i) => ({ ...p, class: "auxiliary", url: p.url.replace(/[^/]*$/, i === 0 ? "SIM1000X_JLIBS.html" : "cscform.html"), reason: "frame auxiliar carregado por parser" }));
        injectedAux = true;
      }
      return chain;
    }
    case "search_session": {
      const a = ["search", args.sessionDir, args.text];
      for (const s of args.scopes) a.push("--scope", s);
      return core(...a);
    }
    case "compare_open": {
      const a = ["compare", args.dirA, args.dirB];
      if (args.includeAll) a.push("--all");
      if (args.aRange) a.push("--a-range", args.aRange);
      if (args.bRange) a.push("--b-range", args.bRange);
      cmp = core(...a);
      return { handle: 1, pairs: cmp.pairs.length, dynamicPairs: cmp.pairs.filter(dyn).length, counts: cmp.counts, partsCounts: cmp.partsCounts, redactedFields: cmp.redactedFields, ambiguities: cmp.ambiguities, warnings: cmp.warnings, onlyInA: cmp.onlyInA.slice(0, 200), onlyInATotal: cmp.onlyInA.length, onlyInB: cmp.onlyInB.slice(0, 200), onlyInBTotal: cmp.onlyInB.length, reordered: (cmp.reordered ?? []).slice(0, 200), reorderedTotal: (cmp.reordered ?? []).length, rounds: cmp.rounds, unpairedRounds: cmp.unpairedRounds, entryRequest: cmp.entryRequest, groups: (cmp.groups ?? []).map((g) => ({ kind: g.kind, a: g.a.slice(0, 200), aTotal: g.a.length, b: g.b.slice(0, 200), bTotal: g.b.length })), includeAll: Boolean(args.includeAll) };
    }
    case "compare_page": {
      const idx = cmp.pairs.map((p, index) => ({ p, index })).filter(({ p }) => !args.onlyDynamic || dyn(p));
      return { total: idx.length, items: idx.slice(args.offset, args.offset + args.limit).map(({ p, index }) => ({ index, round: p.round, a: p.a, b: p.b, alignedBy: p.alignedBy, outOfOrder: p.outOfOrder, counts: p.counts, partsCounts: p.partsCounts, fieldCount: p.fields.length })) };
    }
    case "compare_fields": return cmp.pairs[args.index].fields;
    case "preview_sanitized": return JSON.parse(fs.readFileSync(sanitizeFile, "utf8"));
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
const shot = (name, full = false) => page.screenshot({ path: path.join(outDir, name), fullPage: full });
const results = {};
const openSession = async (dir) => {
  pick = dir;
  await page.getByRole("button", { name: "Abrir captura…" }).click();
  await page.waitForSelector("tbody tr:not(.spacer)");
  await page.waitForTimeout(300);
};
const backToSession = async () => { await page.getByRole("button", { name: /Sessão/ }).first().click().catch(() => {}); };

await page.goto(url, { waitUntil: "networkidle" });
await openSession(d1);
results.cookieWarning = await page.locator(".warn-strip").allInnerTexts();
await shot("20-warning-har-no-cookies.png");

// 1º cmd_consultar_placa (har-0019): STAMP por controle HTML, delta (trechos do XML), SESSIONID
const first = core("search", d1, "cmd_consultar_placa").matches[0].requestId;
results.firstPlaca = first;
results.htmlControlMatches = core("search", d1, "DLTC0005").matches.filter((m) => m.htmlControl).length;
await page.getByLabel("Buscar requisições").fill("DLTC0005");
await page.waitForTimeout(900);
results.searchStatus = await page.locator(".search-status").innerText();
await page.locator("tbody tr:not(.spacer)").first().click();
await page.waitForSelector(".match-box");
results.matchBox = await page.locator(".match-box").innerText();
results.htmlControlChip = await page.locator(".match-box .chip", { hasText: "controle HTML" }).count();
await shot("24-search-control-html.png");
await backToSession();
await page.getByLabel("Buscar requisições").fill("");
await page.waitForTimeout(400);
const rowIndex = Number(first.split("-")[1]) - 1;
await page.locator("tbody tr:not(.spacer)").nth(rowIndex).click();
await page.getByRole("tab", { name: /Origem/ }).click();
await page.waitForSelector(".origin-table");
await page.waitForSelector(".chain-list");
results.warnings = await page.locator("[role=alert]").allInnerTexts();
results.originSummary = (await page.locator(".origin-table").innerText()).split("\n").filter((l) => /STAMP|controle|possível|origem observada/.test(l)).slice(0, 8);
await shot("18-origin-control-html.png");
const stampRow = page.locator(".origin-table tbody tr", { hasText: "STAMP" }).last();
await stampRow.scrollIntoViewIfNeeded();
results.stampRow = await stampRow.innerText();
await page.screenshot({ path: path.join(outDir, "18b-origin-stamp-control-html.png") });
await page.evaluate(() => document.querySelector(".chain-list")?.scrollIntoView({ block: "start" }));
results.pagesGroup = await page.getByText(/Páginas de contexto/).count();
results.protectionGroup = await page.getByText(/Proteção \(não é lógica/).count();
results.auxiliaryGroup = await page.getByText(/Frames auxiliares/).count();
results.auxiliaryInjectedByHand = injectedAux;
await page.locator("summary", { hasText: "Frames auxiliares" }).click();
await shot("19-chain-pages-protection.png");

// Composite (campo curto com componentes)
await backToSession();
await openSession(dc);
await page.locator("tbody tr:not(.spacer)").nth(2).click();
await page.getByRole("tab", { name: /Origem/ }).click();
await page.waitForSelector(".origin-table");
results.compositeRows = (await page.locator(".origin-table").innerText()).split("\n").filter((l) => /composto|token|↳/.test(l)).slice(0, 6);
await shot("21-origin-composite.png");

// Compare 1 × 2 rodadas
await backToSession();
await openSession(d1);
pick = d2;
await page.getByRole("button", { name: "Comparar capturas…" }).click();
await page.waitForSelector(".cmp-pair");
results.compareHeader = await page.locator(".body-panel .block-meta").first().innerText();
results.roundHeaders = await page.locator(".cmp-round").allInnerTexts();
results.unpaired = await page.getByText(/Rodadas sem par/).count();
results.groups = await page.locator(".cmp-group > summary").allInnerTexts();
results.ambiguities = (await page.getByText(/Ambiguidades no alinhamento/).allInnerTexts());
await shot("22-compare-rounds.png");
// incluir tudo + faixa
await page.getByLabel(/incluir tudo/).check();
await page.getByLabel("Faixa A").fill("1:12");
await page.getByRole("button", { name: "Recomparar" }).click();
await page.waitForTimeout(1500);
results.afterOptions = await page.locator(".body-panel .block-meta").first().innerText();
results.groupsAfter = await page.locator(".cmp-group > summary").count();
await shot("22b-compare-include-all-range.png");

// Sanitização
await backToSession();
await page.getByRole("button", { name: /Sanitizar/ }).click();
await page.waitForSelector(".redaction-list");
results.redactions = await page.locator(".redaction-list").innerText();
results.businessWarning = await page.getByText(/Campo de negócio sem valor/).count();
await shot("23-sanitize-preview.png");

results.pageErrors = errors.filter((e) => !e.includes("unregisterListener"));
fs.writeFileSync(path.join(outDir, "ui-harness-real-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
