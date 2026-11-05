import { chromium } from "playwright";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import http from "node:http";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const distDir = path.join(appRoot, "dist");
const distIndex = path.join(distDir, "index.html");
const outDir = path.resolve(appRoot, "..", "docs", "screenshots");

if (!fs.existsSync(distIndex)) {
  console.error("dist/index.html does not exist — run `npm run build` first.");
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".woff2": "font/woff2",
};

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

await new Promise((resolve) => server.listen(4173, "127.0.0.1", resolve));
const base = "http://127.0.0.1:4173/index.html";

const shots = [
  { name: "01-main-light", query: "view=session&theme=light", w: 1440, h: 900, fullPage: false },
  { name: "02-main-dark", query: "view=session&theme=dark", w: 1440, h: 900, fullPage: false },
  { name: "03-detail-headers-light", query: "view=detail&id=req-0004&tab=headers&theme=light", w: 1440, h: 1000, fullPage: true },
  { name: "04-detail-headers-dark", query: "view=detail&id=req-0004&tab=headers&theme=dark", w: 1440, h: 1000, fullPage: true },
  { name: "05-detail-normalized-light", query: "view=detail&id=req-0004&tab=normalized&theme=light", w: 1440, h: 1000, fullPage: true },
  { name: "06-detail-cookies-light", query: "view=detail&id=req-0001&tab=cookies&theme=light", w: 1440, h: 1000, fullPage: true },
  { name: "07-detail-payload-light", query: "view=detail&id=req-0008&tab=payload&theme=light", w: 1440, h: 1000, fullPage: true },
  { name: "08-detail-redirects-dark", query: "view=detail&id=req-0011&tab=redirects&theme=dark", w: 1440, h: 1000, fullPage: true },
  { name: "09-comparison-light", query: "view=compare&a=req-0009&b=req-0010&theme=light", w: 1440, h: 1000, fullPage: true },
  { name: "10-comparison-dark", query: "view=compare&a=req-0009&b=req-0010&theme=dark", w: 1440, h: 1000, fullPage: true },
  { name: "11-detail-verification-dark", query: "view=detail&id=req-0007&tab=headers&theme=dark", w: 1440, h: 1000, fullPage: true },
  { name: "12-main-search-light", query: "view=session&q=products&theme=light", w: 1440, h: 620, fullPage: false },
  { name: "13-main-filter-errors-dark", query: "view=session&filter=error&theme=dark", w: 1440, h: 620, fullPage: false },
  { name: "15-detail-attempts-ambiguous", query: "view=detail&id=req-0011&tab=attempts&theme=light", w: 1440, h: 1000, fullPage: true },
];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2,
  reducedMotion: "reduce",
  locale: "en-US",
  timezoneId: "UTC",
});
const page = await context.newPage();

for (const shot of shots) {
  await page.setViewportSize({ width: shot.w, height: shot.h });
  await page.goto(`${base}?${shot.query}`, { waitUntil: "load" });
  await page.evaluate(() => document.fonts?.ready);
  await page.addStyleTag({ content: "*,*::before,*::after{transition:none!important;animation:none!important}" });
  await page.waitForTimeout(180);
  const file = path.join(outDir, `${shot.name}.png`);
  await page.screenshot({ path: file, fullPage: shot.fullPage });
  const { width, height } = await page.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    height: document.documentElement.scrollHeight,
  }));
  console.log(`${shot.name}.png  css ${width}x${height}`);
}

await browser.close();
server.close();
console.log(`\nPNGs in ${outDir}`);
