// Harness de UI para evidência da rodada de exportação.
//
// Serve o `dist/` real do frontend e injeta um stub de `__TAURI_INTERNALS__`
// antes do carregamento. As respostas dos commands de exportação/sanitização
// são as respostas REAIS gravadas pelo Rust (`command-output.txt`); apenas os
// diálogos nativos, o clipboard e o file picker são simulados. O objetivo é
// exercitar os componentes React e registrar prints — não substitui o fluxo
// manual no bundle com os diálogos reais do macOS.

import { chromium } from "../../../app/node_modules/playwright/index.mjs";
import fs from "node:fs";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname);
const read = (name) => JSON.parse(fs.readFileSync(path.join(here, name), "utf8"));
const previews = { curl: read("preview-curl.json"), python: read("preview-python.json") };
const sanitizePreview = read("sanitize-preview.json");
const sanitizeSaved = read("sanitize-saved.json");
const origPayload = read("orig-payload.json");
const sanitizedPayload = read("sanitized-payload.json");
const savedExport = path.join(here, "saved-har-0002.sh");

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 920 }, deviceScaleFactor: 1 });

await page.addInitScript(
  ({ previews, sanitizePreview, sanitizeSaved, origPayload, sanitizedPayload, savedExport }) => {
    const calls = [];
    const state = { cancelNextSave: false, cancelNextSanitize: false };
    window.__harness = { calls, state };
    window.__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      unregisterCallback: () => {},
      convertFileSrc: (p) => p,
      invoke: async (cmd, args = {}) => {
        calls.push({ cmd, args });
        switch (cmd) {
          case "app_info":
            return { version: "0.1.0", tauri: "2", arch: "arm64", demo: false };
          case "detect_chrome":
            return { found: true, path: "/Applications/Google Chrome.app", source: "detected", candidates: [] };
          case "plugin:event|listen":
            return 1;
          case "plugin:event|unlisten":
            return null;
          case "plugin:clipboard-manager|write_text":
            window.__harness.copied = args.text;
            return null;
          case "plugin:dialog|open":
            return origPayload.sessionDir;
          case "plugin:dialog|save":
            return args.options?.defaultPath?.includes("-sanitized")
              ? sanitizeSaved.path
              : savedExport;
          case "open_session":
            return args.path === sanitizeSaved.path ? sanitizedPayload : origPayload;
          case "export_request":
            return previews[args.format];
          case "save_export_file":
            window.__harness.savedExport = { path: args.path, text: args.text };
            return { path: args.path, bytes: args.text.length };
          case "preview_sanitized":
            return sanitizePreview;
          case "save_sanitized":
            window.__harness.savedSanitized = args;
            return sanitizeSaved;
          case "reveal_path":
            return null;
          case "read_attachment":
            return { kind: "binary", bytes: 0 };
          default:
            return null;
        }
      },
    };
  },
  { previews, sanitizePreview, sanitizeSaved, origPayload, sanitizedPayload, savedExport },
);

const errors = [];
page.on("pageerror", (error) => errors.push(String(error)));
page.on("console", (message) => {
  if (message.type() === "error") errors.push(message.text());
});

await page.goto("http://localhost:4173/", { waitUntil: "networkidle" });
await page.screenshot({ path: path.join(here, "05-app-demo.png") });

// Abre a sessão persistida (o file picker nativo é simulado pelo stub).
await page.getByRole("button", { name: "Abrir captura…" }).click();
await page.waitForSelector("text=har-3dbc391c02a985c5");
await page.screenshot({ path: path.join(here, "06-session-open.png") });

// Seleciona a requisição com Cookie sintético e abre o detalhe.
await page.locator("tr", { hasText: "/setcookie" }).first().click();
await page.waitForSelector("text=Exportar…");
await page.screenshot({ path: path.join(here, "07-detail.png") });

await page.getByRole("button", { name: "Exportar…" }).click();
await page.waitForSelector("pre.export-code");
await page.screenshot({ path: path.join(here, "08-dialog-curl.png") });
const curlText = await page.locator("pre.export-code").innerText();

await page.getByRole("tab", { name: "Python" }).click();
await page.waitForFunction(
  () => document.querySelector("pre.export-code")?.textContent?.includes("http.client"),
);
await page.screenshot({ path: path.join(here, "09-dialog-python.png") });
const pythonText = await page.locator("pre.export-code").innerText();

await page.locator(".modal").getByRole("button", { name: "Copiar", exact: true }).click();
await page.waitForSelector("text=Texto python copiado para a área de transferência.");
const copied = await page.evaluate(() => window.__harness.copied);

// Cancelar o diálogo nativo não grava nada.
await page.evaluate(() => {
  window.__harness.state.cancelNextSave = true;
});
await page.evaluate(() => {
  const original = window.__TAURI_INTERNALS__.invoke;
  window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
    if (cmd === "plugin:dialog|save" && window.__harness.state.cancelNextSave) {
      window.__harness.state.cancelNextSave = false;
      window.__harness.calls.push({ cmd, args, cancelled: true });
      return null;
    }
    return original(cmd, args);
  };
});
await page.locator(".modal").getByRole("button", { name: "Salvar…", exact: true }).click();
await page.waitForSelector("text=Salvamento cancelado; nada foi gravado.");
await page.screenshot({ path: path.join(here, "10-dialog-cancel.png") });

await page.locator(".modal").getByRole("button", { name: "Salvar…", exact: true }).click();
await page.waitForSelector("text=Arquivo salvo");
await page.screenshot({ path: path.join(here, "11-dialog-saved.png") });
const savedText = await page.evaluate(() => window.__harness.savedExport?.text);

await page.locator(".modal").getByRole("button", { name: "Fechar", exact: true }).click();

// Sanitização da sessão inteira.
await page.getByRole("button", { name: "← Sessão" }).click();
await page.getByRole("button", { name: "Sanitizar…" }).click();
await page.waitForSelector("text=Redações por origem");
await page.screenshot({ path: path.join(here, "12-dialog-sanitize.png") });

await page.getByRole("button", { name: "Escolher destino e salvar…" }).click();
await page.waitForSelector("text=Sessão sanitizada gravada em pasta nova e privada");
await page.screenshot({ path: path.join(here, "13-dialog-sanitize-saved.png") });

await page.getByRole("button", { name: "Abrir sessão sanitizada" }).click();
await page.waitForSelector("text=Sessão sanitizada aberta");
await page.screenshot({ path: path.join(here, "14-sanitized-session.png") });

const summary = {
  curl_len: curlText.length,
  python_len: pythonText.length,
  copied_matches_python: copied === pythonText,
  saved_matches_python: savedText === pythonText,
  saved_path: await page.evaluate(() => window.__harness.savedExport?.path),
  sanitized_arg: await page.evaluate(() => window.__harness.savedSanitized),
  errors,
};
fs.writeFileSync(path.join(here, "ui-harness-result.json"), JSON.stringify(summary, null, 2));
fs.writeFileSync(savedExport, savedText ?? "");

await browser.close();
console.log(JSON.stringify(summary, null, 2));
