// Ponte única entre a UI e o shell Tauri 2.
// Fora do Tauri (navegador, para prints/testes) usa a fixture v1 local; dentro
// do Tauri chama os commands preparados para o core/.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import type { SessionV1 } from "./v1/types";

export interface SessionPayload {
  session: SessionV1;
  sessionDir?: string;
  synthetic: boolean;
  notice?: string;
  pending?: boolean;
}

export interface ChromeInfo {
  found: boolean;
  path?: string;
  source?: "detected" | "manual" | "none";
  candidates: string[];
}

export type MenuAction = "open" | "import-har" | "import-netlog" | "find" | "copy" | "demo";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function copyFallback(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export const bridge = {
  isTauri,

  async appInfo(): Promise<{ version: string; tauri: string; arch: string; demo: boolean } | null> {
    if (!isTauri()) return null;
    return invoke("app_info");
  },

  async demoSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("demo_session");
  },

  /** Abre um diretório de sessão v1 (ou um session.json) via diálogo nativo. */
  async pickAndOpenSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Abrir sessão do ScrapeLens",
      message: "Escolha a pasta da sessão (com session.json) ou o próprio arquivo.",
      directory: true,
      multiple: false,
    });
    if (!picked) return null;
    return invoke("open_session", { path: picked });
  },

  async importHar(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Importar HAR",
      multiple: false,
      filters: [{ name: "HAR", extensions: ["har", "json"] }],
    });
    if (!picked) return null;
    return invoke("import_har", { path: picked });
  },

  async importNetlog(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Importar NetLog",
      multiple: false,
      filters: [{ name: "NetLog", extensions: ["json"] }],
    });
    if (!picked) return null;
    return invoke("import_netlog", { path: picked });
  },

  async startSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("start_session");
  },

  async stopSession(): Promise<void> {
    if (!isTauri()) return;
    await invoke("stop_session");
  },

  async detectChrome(): Promise<ChromeInfo | null> {
    if (!isTauri()) return null;
    return invoke("detect_chrome");
  },

  /** Seleção manual do Chrome quando o detect não encontra. */
  async chooseChrome(): Promise<ChromeInfo | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Selecionar Google Chrome",
      message: "Escolha Google Chrome.app (ou o binário dentro de Contents/MacOS).",
      directory: true,
      multiple: false,
    });
    if (!picked) return null;
    return invoke("set_chrome_path", { path: picked });
  },

  async revealPath(path: string): Promise<void> {
    if (!isTauri()) return;
    await invoke("reveal_path", { path });
  },

  async readAttachment(sessionDir: string, name: string): Promise<{ kind: "text" | "binary"; text?: string; bytes: number }> {
    return invoke("read_attachment", { sessionDir, name });
  },

  async copyText(text: string): Promise<boolean> {
    if (isTauri()) {
      try {
        const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
        await writeText(text);
        return true;
      } catch {
        /* cai para o fallback */
      }
    }
    return copyFallback(text);
  },

  /** Eventos do menu nativo (⌘O, ⌘F, ⌘C, importar, demo). */
  async onMenu(handler: (action: MenuAction) => void): Promise<() => void> {
    if (!isTauri()) return () => {};
    const unlisten = await listen<string>("menu://action", (event) => {
      handler(event.payload as MenuAction);
    });
    return unlisten;
  },
};

/** Sessão grande para exercitar a virtualização no modo navegador. */
export async function loadLargeDemo(): Promise<SessionPayload> {
  const { buildLargeSession } = await import("./demo/large");
  return { session: buildLargeSession(12000), synthetic: true, notice: "Sessão sintética de estresse (12.000 requisições)." };
}
