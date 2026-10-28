// Ponte única entre a UI e o shell Tauri 2.
// Fora do Tauri (navegador, para prints/testes) usa a fixture v1 local; dentro
// do Tauri chama os commands preparados para o core/.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import type { SessionV1 } from "./v1/types";
import type { PrimingChain, SessionComparison, ValueOrigins } from "./flow";

export interface SessionPayload {
  session: SessionV1;
  sessionDir?: string;
  synthetic: boolean;
  notice?: string;
  pending?: boolean;
}

export interface CaptureStatus {
  recording: boolean;
  events: number;
  chromePid?: number;
  sessionId: string;
  sessionDir: string;
  startedAt: string;
  pageUrl: string;
  lastError?: string;
}

export interface ChromeInfo {
  found: boolean;
  path?: string;
  source?: "detected" | "manual" | "none";
  candidates: string[];
}

export interface WarningDto {
  code: string;
  message: string;
  severity?: "info" | "warning" | "error";
  entity?: string;
}

/** Prévia gerada no Rust; `text` é a fonte da cópia e do arquivo salvo. */
export interface ExportPreview {
  sessionId: string;
  requestId: string;
  requestMethod: string;
  requestUrl: string;
  protocol: string;
  headerVerification: "verified" | "partial" | "unverified";
  format: "curl" | "python";
  text: string;
  warnings: WarningDto[];
  skippedHeaders: string[];
  bodyIncluded: boolean;
  bodyNote?: string;
  bodyState: string;
}

export interface SavedFile {
  path: string;
  bytes: number;
}

export interface RedactionCount {
  key: string;
  count: number;
}

export interface SanitizePreview {
  sessionId: string;
  originalDir: string;
  suggestedDestination: string;
  requests: number;
  redactions: RedactionCount[];
  totalRedactions: number;
  warnings: WarningDto[];
  omittedAttachments: string[];
  attachmentsKept: number;
  rawArtifactsDropped: string[];
}

export interface SanitizeSaved {
  path: string;
  sessionId: string;
  requests: number;
  totalRedactions: number;
  omittedAttachments: string[];
  attachmentsKept: number;
  rawArtifactsDropped: string[];
  sessionBytes: number;
}

export type SearchScope = "url" | "requestHeaders" | "responseHeaders" | "cookies" | "requestBody" | "responseBody";

export interface SearchMatch {
  requestId: string;
  attemptId: string;
  scope: SearchScope;
  field: string | null;
  byteOffset: number | null;
  /** Comprimento em bytes UTF-8 do trecho original (core ≥ rodada 4b-fix). */
  byteLength?: number;
  /** true: o intervalo é literal no original; false: achado só na visão decodificada. */
  exact?: boolean;
  snippet: string;
  decoded: boolean;
}

/** Resultado de `scrapelens_core::search`; a UI não refaz a busca. */
export interface SearchResultDto {
  matches: SearchMatch[];
  skippedBinary: number;
  partial: boolean;
  partialAttempts: string[];
  limitReached: boolean;
}

export interface BodyData {
  kind: "text" | "binary";
  text?: string;
  hex?: string;
  bytes: number;
  shownBytes: number;
  cut: boolean;
}

export type MenuAction =
  | "open"
  | "import-har"
  | "import-netlog"
  | "choose-chrome"
  | "find"
  | "copy"
  | "demo"
  | "theme";

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

  async stopSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("stop_session");
  },

  async captureStatus(): Promise<CaptureStatus | null> {
    if (!isTauri()) return null;
    return invoke("capture_status");
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

  async searchSession(
    sessionDir: string,
    text: string,
    scopes: SearchScope[],
    caseSensitive: boolean,
    maxMatches = 2000,
  ): Promise<SearchResultDto> {
    return invoke("search_session", { sessionDir, text, scopes, caseSensitive, maxMatches });
  },

  /** Lê um corpo anexado (texto, ou tamanho + prévia hex se binário). */
  async readBody(sessionDir: string, name: string, limit?: number): Promise<BodyData> {
    return invoke("read_body", { sessionDir, name, limit });
  },

  /** Abre uma pasta de sessão já conhecida, sem diálogo. */
  async openSessionAt(path: string): Promise<SessionPayload> {
    return invoke("open_session", { path });
  },

  /**
   * Gera a exportação no Rust a partir da sessão persistida. O texto devolvido
   * é exatamente o que a UI mostra, copia e salva — nada é executado.
   */
  async exportRequest(
    sessionDir: string,
    requestId: string,
    format: "curl" | "python",
    annotateOrigins = false,
  ): Promise<ExportPreview> {
    return invoke("export_request", { sessionDir, requestId, format, annotateOrigins });
  },

  async requestOrigins(sessionDir: string, requestId: string): Promise<ValueOrigins> {
    return invoke("request_origins", { sessionDir, requestId });
  },

  async requestChain(sessionDir: string, requestId: string): Promise<PrimingChain> {
    return invoke("request_chain", { sessionDir, requestId });
  },

  /** Seletor nativo de pasta para a 2ª captura; `null` se o usuário cancelar. */
  async pickCompareSession(): Promise<string | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Escolher a 2ª captura (pasta da sessão B)",
      message: "Escolha a pasta de uma sessão do ScrapeLens para comparar com a aberta.",
      directory: true,
      multiple: false,
    });
    return typeof picked === "string" ? picked : null;
  },

  async compareSessions(dirA: string, dirB: string): Promise<SessionComparison> {
    return invoke("compare_session_dirs", { dirA, dirB });
  },

  /** Diálogo nativo de salvamento + gravação 0600 sem sobrescrever. */
  async saveExport(defaultName: string, text: string): Promise<SavedFile | null> {
    if (!isTauri()) return null;
    const picked = await saveDialog({
      title: "Salvar exportação",
      defaultPath: defaultName,
      filters: [{ name: defaultName.endsWith(".py") ? "Python" : "Shell", extensions: [defaultName.endsWith(".py") ? "py" : "sh"] }],
    });
    if (!picked) return null;
    return invoke("save_export_file", { path: picked, text });
  },

  /** Contagens/avisos da sanitização; não grava nada. */
  async previewSanitized(sessionDir: string): Promise<SanitizePreview> {
    return invoke("preview_sanitized", { sessionDir });
  },

  /**
   * Diálogo nativo escolhendo uma pasta nova e gravação da sessão sanitizada.
   * Cancelar o diálogo devolve `null` sem tocar na origem.
   */
  async saveSanitized(sessionDir: string, suggestedDestination: string): Promise<SanitizeSaved | null> {
    if (!isTauri()) return null;
    const picked = await saveDialog({
      title: "Escolher pasta nova para a sessão sanitizada",
      defaultPath: suggestedDestination,
      canCreateDirectories: true,
    });
    if (!picked) return null;
    return invoke("save_sanitized", { sessionDir, destination: picked });
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
