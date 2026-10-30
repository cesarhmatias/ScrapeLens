// Prints da onda 3 (docs/14): lista com filtro de alvo, detalhe de popup,
// detalhe do SW ligado e "Limites desta captura", sobre captura REAL /multi/.
//
// uso: node ui-harness-multi.mjs <sessao-multi> <saida>
import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const [sessionDir, outDir] = process.argv.slice(2);
if (!sessionDir || !outDir) {
  console.error("uso: node ui-harness-multi.mjs <sessao-multi> <saida>");
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });
const dist = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../../app/dist");
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const server = http.createServer((req, res) => {
  const file = path.join(dist, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!file.startsWith(dist) || !fs.existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }).end(fs.readFileSync(file));
});
await new Promise((r) => server.listen(0, r));
const url = `http://127.0.0.1:${server.address().port}/`;

let pick = sessionDir;
async function rpc(cmd, args) {
  switch (cmd) {
    case "open_session": {
      const session = JSON.parse(fs.readFileSync(path.join(args.path, "session.json"), "utf8"));
      return { session, sessionDir: args.path, synthetic: false, pending: false };
    }
    case "assess_session":
      return { outcomes: [], warnings: [], byVerdict: {} };
    case "session_timeline":
      return {
        entryRequest: null,
        rounds: 0,
        items: [],
        counts: { events: 0, protection: 0, static: 0 },
        warnings: [],
      };
    case "search_session":
      return { matches: [], limitReached: false, partial: false, partialAttempts: [], skippedBinary: 0 };
    default:
      return null;
  }
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await page.exposeFunction("__rpc", rpc);
await page.exposeFunction("__pick", () => pick);
await page.addInitScript(() => {
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  window.__TAURI_INTERNALS__ = {
    transformCallback: () => 1,
    unregisterCallback: () => {},
    convertFileSrc: (p) => p,
    invoke: async (cmd, args = {}) => {
      switch (cmd) {
        case "app_info":
          return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
        case "detect_chrome":
          return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
        case "plugin:event|listen":
          return 1;
        case "plugin:event|unlisten":
          return null;
        case "plugin:dialog|open":
          return window.__pick();
        default:
          return window.__rpc(cmd, args);
      }
    },
  };
});
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const shot = (name, full = false) => page.screenshot({ path: path.join(outDir, name), fullPage: full });
const results = { sessionDir };

await page.goto(url, { waitUntil: "networkidle" });
pick = sessionDir;
await page.getByRole("button", { name: "Abrir captura…" }).click();
await page.waitForSelector("tbody tr:not(.spacer)");
await page.waitForTimeout(400);

results.targetFilters = await page.locator(".target-filters .chip-filter").allInnerTexts();
results.targetColumn = await page.locator("th.col-target").count();
await shot("42-multi-lista-filtro.png");

const popupFilter = page.locator(".target-filters .chip-filter", { hasText: /^popup/ });
if ((await popupFilter.count()) > 0) {
  await popupFilter.click();
  await page.waitForTimeout(300);
  await shot("42b-multi-filtro-popup.png");
}
{
  // Prefere popup.html (window.open) a blank (_blank).
  const rows = page.locator("tbody tr:not(.spacer)");
  const n = await rows.count();
  let opened = false;
  for (const needle of ["popup.html", "popup-get", "popup ·"]) {
    for (let i = 0; i < n; i++) {
      const text = await rows.nth(i).innerText();
      if (text.includes(needle) && !text.includes("blank")) {
        await rows.nth(i).click();
        opened = true;
        break;
      }
    }
    if (opened) break;
  }
  if (!opened && n > 0) await rows.first().click();
}
await page.waitForSelector(".target-panel");
results.popupTarget = await page.locator(".target-panel").innerText();
await shot("43-multi-detalhe-popup.png", true);

await page.getByRole("button", { name: /Sessão/ }).first().click();
await page.waitForSelector("tbody tr:not(.spacer)");
const allFilter = page.locator(".target-filters .chip-filter", { hasText: /^todos os alvos/ });
if ((await allFilter.count()) > 0) await allFilter.click();
const swFilter = page.locator(".target-filters .chip-filter", { hasText: /service worker/ });
if ((await swFilter.count()) > 0) {
  await swFilter.click();
  await page.waitForTimeout(250);
}
const swRows = page.locator("tbody tr:not(.spacer)");
const swN = await swRows.count();
let swOpened = false;
for (let i = 0; i < swN; i++) {
  const text = await swRows.nth(i).innerText();
  if (text.includes("sw-fetch") || text.includes("service worker")) {
    await swRows.nth(i).click();
    swOpened = true;
    break;
  }
}
if (!swOpened && swN > 0) await swRows.first().click();
await page.waitForSelector(".target-panel");
results.swPanel = await page.locator(".target-panel").innerText();
results.swLinks = await page.locator(".target-links li").count();
await shot("44-multi-detalhe-sw.png", true);

// Limites: rolar até a faixa no detalhe
await page.locator(".limits-strip").scrollIntoViewIfNeeded();
results.limits = await page.locator(".limits-strip").innerText();
await shot("45-multi-limites.png", true);

results.pageErrors = errors.filter((e) => !e.includes("unregisterListener"));
results.ignoredStubErrors = errors.length - results.pageErrors.length;
fs.writeFileSync(path.join(outDir, "ui-harness-multi-result.json"), JSON.stringify(results, null, 2));
await browser.close();
server.close();
if (results.pageErrors.length) {
  console.error("page errors", results.pageErrors);
  process.exit(1);
}
console.log("ok", results.targetColumn, "col; links", results.swLinks);
