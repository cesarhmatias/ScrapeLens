// Measures the virtualized list with the synthetic stress session (12,000
// requests). Reports only measured numbers; it is not a capture benchmark.
//
//   node scripts/perf.mjs

import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const distDir = path.join(appRoot, "dist");
const outFile = path.resolve(appRoot, "..", "docs", "perf", "virtualization.json");

const mime = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };
const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url ?? "/").split("?")[0]);
  const filePath = path.join(distDir, urlPath === "/" ? "index.html" : urlPath);
  if (!filePath.startsWith(distDir) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404).end("not found");
    return;
  }
  res.writeHead(200, { "content-type": mime[path.extname(filePath)] ?? "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
});
await new Promise((resolve) => server.listen(4174, "127.0.0.1", resolve));

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
const started = Date.now();
await page.goto("http://127.0.0.1:4174/index.html?demo=large&theme=light", { waitUntil: "load" });
await page.waitForFunction(() => document.body.innerText.includes("12,000 requests"), null, { timeout: 120000 });
const loadMs = Date.now() - started;
await page.waitForTimeout(300);

const initial = await page.evaluate(() => {
  const rows = [...document.querySelectorAll(".req-table tbody tr")].filter((row) => !row.classList.contains("spacer"));
  return {
    totalRequests: 12000,
    renderedRows: rows.length,
    firstVisibleId: rows[0]?.querySelector("td:nth-child(3)")?.textContent ?? null,
    domNodes: document.querySelectorAll("*").length,
    statusBar: document.querySelector(".statusbar")?.textContent ?? "",
  };
});

const scroll = await page.evaluate(() => {
  const wrap = document.querySelector(".table-wrap");
  if (!wrap) return null;
  wrap.scrollTop = wrap.scrollHeight;
  return { scrollHeight: wrap.scrollHeight, clientHeight: wrap.clientHeight };
});
await page.waitForTimeout(350);
const bottom = await page.evaluate(() => {
  const rows = [...document.querySelectorAll(".req-table tbody tr")].filter((row) => !row.classList.contains("spacer"));
  return {
    renderedRows: rows.length,
    lastRowIndex: rows.at(-1)?.querySelector("td:first-child")?.textContent ?? null,
    lastPath: rows.at(-1)?.querySelector("td:nth-child(4)")?.textContent ?? null,
  };
});

await page.screenshot({ path: path.join(appRoot, "..", "docs", "screenshots", "14-list-12k-virtualized.png") });

const report = {
  generatedAt: new Date().toISOString(),
  synthetic: true,
  requests: 12000,
  loadMs,
  ...initial,
  scroll,
  bottom,
  verdict: {
    virtualized: initial.renderedRows < 200 && initial.totalRequests === 12000,
    rowsAtBottom: bottom.renderedRows,
  },
};

fs.mkdirSync(path.dirname(outFile), { recursive: true });
fs.writeFileSync(outFile, JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));

await browser.close();
server.close();
