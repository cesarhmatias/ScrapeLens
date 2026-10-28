// Harness de UI da onda 4b (busca no payload + painel de corpos).
//
// Serve o `app/dist` real e injeta um stub de `__TAURI_INTERNALS__`. O stub
// encaminha para Node: `search_session` roda o `scrapelens-core search` REAL
// (mesmo `core::search` que o command Rust chama) sobre a sessão importada da
// fixture detran-pb; `open_session` lê o session.json real. `read_body` é
// reimplementado em Node (o command Rust tem testes próprios em commands.rs).
// Diálogo nativo e clipboard são simulados: não substitui o teste manual no .app.
//
// uso: node ui-harness.mjs <sessao-detran> <sessao-edge> <scrapelens-core> <saida>
import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const [detranDir, edgeDir, coreBin, outDir] = process.argv.slice(2);
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
fs.mkdirSync(outDir, { recursive: true });

const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;

const rpcLog = [];
async function rpc(cmd, args) {
  rpcLog.push(cmd);
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "search_session": {
      const a = ["search", args.sessionDir, args.text];
      for (const s of args.scopes) a.push("--scope", s);
      if (args.caseSensitive) a.push("--case-sensitive");
      return JSON.parse(execFileSync(coreBin, a, { maxBuffer: 1 << 28 }).toString());
    }
    case "read_body": {
      const buf = fs.readFileSync(path.join(args.sessionDir, "attachments", args.name));
      const part = buf.subarray(0, args.limit ?? 262144);
      const cut = part.length < buf.length;
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(part);
        return { kind: "text", text, bytes: buf.length, shownBytes: part.length, cut };
      } catch {
        return { kind: "binary", hex: [...buf.subarray(0, 256)].map((b) => b.toString(16).padStart(2, "0")).join(" "), bytes: buf.length, shownBytes: Math.min(256, buf.length), cut: buf.length > 256 };
      }
    }
    case "export_request": {
      // Texto REAL do exportador do core; o envelope é montado aqui (harness).
      const text = execFileSync(coreBin, [`export-${args.format}`, args.sessionDir, args.requestId]).toString();
      return { sessionId: "harness", requestId: args.requestId, requestMethod: "POST", requestUrl: "", protocol: "h1", headerVerification: "verified", format: args.format, text, warnings: [], skippedHeaders: [], bodyIncluded: true, bodyState: "captured" };
    }
    default:
      return null;
  }
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
await page.exposeFunction("__rpc", rpc);
let pick = detranDir;
await page.exposeFunction("__rpcPick", () => pick);
await page.addInitScript(() => {
  window.__copied = [];
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1, unregisterCallback: () => {}, convertFileSrc: (p) => p,
    invoke: async (cmd, args = {}) => {
      switch (cmd) {
        case "app_info": return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
        case "detect_chrome": return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
        case "plugin:event|listen": return 1;
        case "plugin:event|unlisten": return null;
        case "plugin:clipboard-manager|write_text": window.__copied.push(args.text); return null;
        case "plugin:dialog|open": return window.__rpcPick();
        case "export_request": return window.__rpc(cmd, args) ?? null;
        default: return window.__rpc(cmd, args);
      }
    },
  };
});
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
const results = {};
var shot = (name) => page.screenshot({ path: path.join(outDir, name) });
const rows = () => page.locator("tbody tr:not(.spacer):not(:has(.empty))").count();

async function openSession(dir) {
  pick = dir;
  await page.getByRole("button", { name: "Abrir captura…" }).click();
  await page.waitForFunction(() => document.querySelector("tbody tr:not(.spacer)") !== null);
  await page.waitForTimeout(300);
}

await page.goto(url, { waitUntil: "networkidle" });
await openSession(detranDir);
results.originBanner = await page.locator(".real-banner, .demo-banner").first().innerText();
results.originTags = await page.locator(".tag").allInnerTexts();
results.detranRows = await rows();
await shot("01-detran-lista.png");

// Busca no payload: só os 2 POSTs com o comando, nenhum pela URL.
const search = page.getByLabel("Buscar requisições");
await search.fill("cmd_consultar_placa");
await page.waitForSelector(".search-status .chip", { timeout: 8000 }).catch(async () => { await shot("debug.png"); throw new Error("sem chips: " + (await page.locator(".search-status").allInnerTexts())); });
await page.waitForTimeout(400);
results.searchRows = await rows();
results.searchStatus = await page.locator(".search-status").innerText();
await shot("02-busca-payload.png");

// Escopo só URL: nenhuma requisição.
for (const label of ["header (env.)", "header (rec.)", "cookies", "corpo req.", "corpo resp."]) {
  await page.locator(".search-opts label", { hasText: label }).click();
}
await page.waitForTimeout(600);
results.urlOnlyRows = await rows();
results.urlOnlyStatus = await page.locator(".search-status").innerText();
await shot("03-busca-escopo-url.png");
await page.locator(".search-opts label", { hasText: "corpo req." }).click();
await page.waitForTimeout(600);
results.afterRestoreRows = await rows();

// Detalhe com destaque.
await page.locator("tbody tr:not(.spacer)").first().click();
await page.waitForSelector(".match-box");
results.matchBox = await page.locator(".match-box").innerText();
await page.getByRole("tab", { name: /Payload/ }).click();
await page.waitForSelector(".body-panel pre.code");
results.highlightMarks = await page.locator(".body-panel pre.code mark").count();
results.markText = await page.locator(".body-panel pre.code mark").allInnerTexts();
await shot("04-detalhe-match.png");
results.copyBody = null;
await page.getByRole("button", { name: "Copiar corpo" }).first().click();
await page.waitForTimeout(300);
results.copiedPayloadHasCmd = (await page.evaluate(() => window.__copied)).some((t) => t.includes("cmd_consultar_placa"));

// HTML capturado: resposta é text/html, nunca renderizada.
await page.getByRole("tab", { name: /Resposta/ }).click();
await page.waitForSelector(".body-panel pre.code");
results.iframes = await page.locator("iframe").count();
results.htmlRenderedInPanel = await page.locator(".body-panel .code > *:not(mark)").count();
results.responseFoot = await page.locator(".body-panel .body-foot").first().innerText();
await shot("05-resposta-html-como-texto.png");

// Sessão edge: truncado, vazio, binário, indisponível, redirect 307.
await page.getByRole("button", { name: /Sessão/ }).first().click().catch(() => {});
await openSession(edgeDir).catch(() => {});
await page.waitForTimeout(300);
const body = async (index, tab, name) => {
  await page.locator("tbody tr:not(.spacer)").nth(index).click();
  await page.getByRole("tab", { name: new RegExp(tab) }).click();
  await page.waitForTimeout(400);
  results[name] = await page.locator(".body-panel").first().innerText();
  await shot(name + ".png");
  await page.getByRole("button", { name: /Sessão/ }).first().click();
};
await page.getByLabel("Buscar requisições").fill("");
await page.waitForTimeout(300);
results.edgeRows = await rows();
await body(5, "Resposta", "06-corpo-truncado");
await body(6, "Resposta", "07-corpo-vazio");
await body(3, "Payload", "08b-corpo-binario");
await body(2, "Payload", "08-corpo-json");
await body(0, "Payload", "09-corpo-indisponivel");
// 307 com exportação
await page.locator("tbody tr:not(.spacer)").nth(1).click();
await page.getByRole("button", { name: /Exportar/ }).first().click().catch(() => {});
await page.waitForTimeout(600);
results.redirectWarning = await page.locator("[role=alert]").allInnerTexts();
await shot("10-export-aviso-307.png");

results.pageErrors = errors.filter((e) => !e.includes("unregisterListener"));
results.ignoredStubErrors = errors.length - results.pageErrors.length;
results.rpcCalls = rpcLog.length;
fs.writeFileSync(path.join(outDir, "ui-harness-result.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
await browser.close();
server.close();
