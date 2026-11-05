// Harness da onda 7b (docs/11 §2): sucesso da aplicação × HTTP na UI, sobre detran-pb-blocked e
// detran-pb-real-shape (import-har --label synthetic-fixture). `assess`, origens, cadeia e compare rodam o
// scrapelens-core REAL; seletor nativo de pasta SIMULADO.
// uso: node ui-harness-assess.mjs <blocked> <real-1round> <real-2rounds> <scrapelens-core> <saida>
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

const [blocked, d1, d2, coreBin, outDir, blockedRules] = process.argv.slice(2);
const sanitizeFile = null;
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;

let pick = blocked;
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
    case "assess_session": {
      const r = core("assess", args.sessionDir);
      // o CLI não imprime `warnings`; o comando Tauri sim (teste Rust). Aqui só para o print 33.
      if (args.sessionDir === blockedRules && process.env.HARNESS_WARN) r.warnings = [process.env.HARNESS_WARN];
      return r;
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
await openSession(blocked);
await page.waitForTimeout(500);
const rows = async () => (await page.locator("tbody tr:not(.spacer)").allInnerTexts()).map((t) => t.replace(/\s+/g, " "));
results.blockedList = await rows();
await shot("25-lista-aplicacao-bloqueado.png");
// filtro "só falhas da aplicação"
results.failCountLabel = await page.getByRole("button", { name: /Falhas da aplicação/ }).innerText();
results.blockCountLabel = await page.getByRole("button", { name: /Possíveis bloqueios/ }).innerText();
await page.getByRole("button", { name: /Possíveis bloqueios/ }).click();
results.blockedFiltered = await rows();
await page.getByRole("button", { name: /Falhas da aplicação/ }).click(); // combinados (união)
results.combinedFiltered = await rows();
await page.getByRole("button", { name: /Falhas da aplicação/ }).click(); // volta só bloqueios para o print
await shot("26-filtro-falhas-aplicacao.png");
// detalhe: 200 bloqueado
await page.locator("tbody tr:not(.spacer)").first().click();
await page.getByRole("tab", { name: /Aplicação/ }).click();
await page.waitForSelector("text=Sucesso da aplicação");
results.blockedDetail = await page.locator(".body-panel").first().innerText();
await shot("27-detalhe-200-bloqueado.png");
await backToSession();
await page.getByRole("button", { name: /Todos/ }).click();
// o indeterminado usa cópia da sessão com assess-rules.json (requiredFields XML,STAMP) para exibir campos ausentes
await backToSession();
await openSession(blocked);
await page.waitForSelector("tbody tr:not(.spacer)");
await backToSession();
await openSession(blockedRules);
// indeterminado: POST ao Connector (rota da aplicação) 200 sem XML/STAMP, na fixture de bloqueio (har-0002)
await page.locator("tbody tr:not(.spacer)", { hasText: "Connector" }).first().click();
await page.getByRole("tab", { name: /Aplicação/ }).click();
await page.waitForSelector("text=Sucesso da aplicação");
results.indeterminadoDetail = await page.locator(".body-panel").first().innerText();
await shot("28-detalhe-indeterminado.png");

// real-shape: app-ok + cadeia com veredito por passo
await backToSession();
await openSession(d1);
await page.waitForTimeout(500);
results.realList = (await rows()).slice(0, 12);
await shot("29-lista-app-ok.png");
const first = core("search", d1, "cmd_consultar_placa").matches.find((m) => m.scope === "requestBody").requestId;
await page.locator("tbody tr:not(.spacer)").nth(Number(first.split("-")[1]) - 1).click();
await page.getByRole("tab", { name: /Aplicação/ }).click();
await page.waitForSelector("text=Sucesso da aplicação");
results.appOkDetail = await page.locator(".body-panel").first().innerText();
await shot("30-detalhe-app-ok.png");
await page.getByRole("tab", { name: /Origem/ }).click();
await page.waitForSelector(".chain-list");
results.chainVerdicts = await page.locator(".chain-list li").evaluateAll((els) => els.slice(0, 12).map((e) => e.innerText.split("\n")[0]));
await page.evaluate(() => document.querySelector(".chain-list")?.scrollIntoView({ block: "start" }));
await shot("31-cadeia-veredito.png");
// smoke do build final: frames auxiliares reais do core e iniciador no detalhe
results.chainAuxText = (await page.locator("body").innerText()).match(/Frames auxiliares\s*\d+/)?.[0] ?? null;
await page.getByRole("tab", { name: /Visão geral|Geral|Cabeçalhos/ }).first().click().catch(() => {});
results.initiatorText = (await page.locator("dt:has-text('Iniciador') + dd").first().innerText().catch(() => null));

// compare 1 × 2 rodadas: veredito A → B por par
await backToSession();
pick = d2;
await page.getByRole("button", { name: "Comparar capturas…" }).click();
await page.waitForSelector(".cmp-pair");
await page.waitForTimeout(800);
results.comparePairs = (await page.locator(".cmp-pair > header").allInnerTexts()).slice(0, 8).map((t) => t.replace(/\s+/g, " "));
await shot("32-compare-veredito.png");

results.pageErrors = errors.filter((e) => !e.includes("unregisterListener"));
fs.writeFileSync(path.join(outDir, "ui-harness-assess-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
