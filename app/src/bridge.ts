export interface CookieSourceDto {
  id: string;
  browser: string;
  profile: string;
  label: string;
  kind: "chromium" | "firefox" | "safari";
}
export interface CookieSourcesPayload { sources: CookieSourceDto[]; selected: string | null }

// Single bridge between the UI and the Tauri 2 shell.
// Outside Tauri (browser, for screenshots/tests) it uses the local v1 fixture; inside
// Tauri it calls the commands prepared for the core.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import type { RawRequestDetail, RawRequestSummary, SessionV1, TargetProvenance } from "./v1/types";
import type { AssessResult, VerdictKind } from "./assess";
import type { ComparePage, CompareSummary, FieldDiff, PrimingChain, ValueOrigins } from "./flow";
import type { CookieImportReport } from "./cookieImport";
import { chromePickerOptions } from "./listView";
import type { ProxyInfo, ProxyState } from "./proxyRules";

export interface SessionPayload {
  session: SessionV1;
  sessionDir?: string;
  /** Token for `sessionDir`: pass it back for bodies and reveal (the backend issues it). */
  sessionToken?: string;
  synthetic: boolean;
  notice?: string;
  /** Cookie import of a live capture; absent when there was none or the capture is older. */
  cookieImport?: CookieImportReport;
  pending?: boolean;
}

/** Filter for `list_requests` (src-tauri/src/listing.rs `ListFilter`). */
export interface ListFilter {
  typeFilter?: "all" | "fetch" | "document" | "media" | "error";
  protocol?: string;
  target?: string;
  query?: string;
  payloadSearch?: boolean;
  matchIds?: string[];
  restrictIds?: string[] | null;
}

export interface RequestPageDto {
  total: number;
  matched: number;
  offset: number;
  items: RawRequestSummary[];
  /** Distinct targets of the page; `items[i].target` is the index. */
  targets: TargetProvenance[];
  counts: { all: number; fetch: number; document: number; media: number; error: number };
  targetCounts: Record<string, number>;
  hasTargets: boolean;
  /** Warnings tied to requests across the whole session (unfiltered). */
  warningTotal: number;
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
  /** Why a saved browser preference was not used at startup (only from detectChrome). */
  notice?: string | null;
}

export interface WarningDto {
  code: string;
  message: string;
  severity?: "info" | "warning" | "error";
  entity?: string;
}

/** Preview generated in Rust; `text` is the source of the copy and of the saved file. */
export interface ExportPreview {
  sessionId: string;
  requestId: string;
  requestMethod: string;
  requestUrl: string;
  protocol: string;
  headerVerification: "verified" | "partial" | "unverified";
  format: "curl" | "python" | "priming";
  text: string;
  warnings: WarningDto[];
  skippedHeaders: string[];
  bodyIncluded: boolean;
  bodyNote?: string;
  bodyState: string;
  /** Protocol adapter whose encoder was included in the priming script. */
  adapter?: string;
}

export interface TimelineEventDto {
  type: "event";
  requestId: string;
  round: number;
  kind: string;
  label: string;
  method: string;
  url: string;
  status: number | null;
  tMs: number | null;
  verdict: string;
  verdictKind: VerdictKind;
  consumed: string[];
  produced: string[];
}
export interface TimelineGroupDto {
  type: "group";
  kind: "protection" | "static";
  count: number;
  requestIds: string[];
}
export interface TimelineDto {
  entryRequest: string | null;
  rounds: number;
  items: (TimelineEventDto | TimelineGroupDto)[];
  counts: { events: number; protection: number; static: number };
  warnings: string[];
}

export interface FieldNoteDto { scope: string; field: string; reason: string }
export interface StepValidationDto {
  step: number;
  traceRequestId: string;
  captureRequestId: string | null;
  method: string;
  url: string;
  statusCapture: number | null;
  statusTrace: number | null;
  verdictCapture: VerdictKind | null;
  verdictTrace: VerdictKind;
  expected: FieldNoteDto[];
  unexpected: FieldNoteDto[];
  problem: string | null;
}
export interface ValidationResultDto {
  traceDir: string;
  traceRequests: number;
  validation: {
    schema: string;
    /** Verdict from the core; other values (the core may add some) show up as a divergence. */
    verdict: string;
    step: number | null;
    reason: string | null;
    summary: string;
    steps: StepValidationDto[];
    missingInTrace: string[];
    mappedOrigin: { from: string; to: string } | null;
    warnings: string[];
  };
}

export interface AdapterViewDto {
  side: "request" | "response";
  fields: {
    field: string;
    adapterId: string;
    raw: string;
    error?: string | null;
    parts: { name: string; role: string; value: string; offset: number; len: number }[];
    omittedParts?: number;
  }[];
  note?: string | null;
}

export interface SavedFile {
  path: string;
  bytes: number;
  /** Token for `revealPath` (the backend issues it). */
  token: string;
}

export interface RedactionCount {
  key: string;
  count: number;
}

export interface SanitizePreview {
  includeSensitive?: boolean;
  rawArtifactsKept?: string[];
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
  includeSensitive?: boolean;
  rawArtifactsKept?: string[];
  path: string;
  /** Token for `openSessionAt` and `revealPath` (the backend issues it). */
  token: string;
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
  /** Length in UTF-8 bytes of the original excerpt (core ≥ round 4b-fix). */
  byteLength?: number;
  /** The finding is in an HTML form control (input/textarea/select). */
  htmlControl?: boolean;
  /** true: the range is literal in the original; false: finding only in the decoded view. */
  exact?: boolean;
  snippet: string;
  decoded: boolean;
}

/** Result of `scrapelens_core::search`; the UI does not redo the search. */
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
  | "start-session"
  | "stop-session"
  | "choose-chrome"
  | "find"
  | "copy"
  | "demo"
  | "theme";

export interface CliActionPayload {
  kind: "import-har" | "import-netlog" | "open-capture" | "error" | "warning" | string;
  path: string;
  /** For `open-capture`: a session token (the path stays in the backend). */
  token?: string;
  /** Error or warning from the test CLI (kind `error`/`warning`). */
  message?: string;
}

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

  /** Opens a v1 session folder chosen in the native dialog (the backend opens the dialog). */
  async pickAndOpenSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("open_session");
  },

  async importHar(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Import HAR",
      multiple: false,
      filters: [{ name: "HAR", extensions: ["har", "json"] }],
    });
    if (!picked) return null;
    return invoke("import_har", { path: picked });
  },

  async importNetlog(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Import NetLog",
      multiple: false,
      filters: [{ name: "NetLog", extensions: ["json"] }],
    });
    if (!picked) return null;
    return invoke("import_netlog", { path: picked });
  },

  async startSession(startUrl?: string, cookieSource?: string): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("start_session", { startUrl: startUrl ?? null, cookieSource: cookieSource || null });
  },

  async listCookieSources(): Promise<CookieSourcesPayload> {
    if (!isTauri()) return { sources: [], selected: null };
    return invoke("list_cookie_sources");
  },

  async setCaptureCookieSource(source: string | null): Promise<string | null> {
    if (!isTauri()) return null;
    return invoke("set_capture_cookie_source", { source });
  },

  /** Proxy field state: the saved server, the link kept in memory, no credentials. */
  async getProxyState(): Promise<ProxyState | null> {
    if (!isTauri()) return null;
    const raw = await invoke<{ saved: string | null; active: ProxyInfo | null; needsLink: boolean }>("get_proxy_state");
    return { saved: raw.saved, active: raw.active, needsLink: raw.needsLink };
  },

  /** Sends the typed link once; the backend keeps it in memory and returns the address only. */
  async setProxyLink(link: string): Promise<ProxyInfo> {
    return invoke("set_proxy_link", { link });
  },

  async clearProxyLink(): Promise<void> {
    await invoke("clear_proxy_link");
  },

  async stopSession(): Promise<SessionPayload | null> {
    if (!isTauri()) return null;
    return invoke("stop_session");
  },

  /** Preference / env for the start URL field. */
  async captureStartUrl(): Promise<string> {
    if (!isTauri()) return "";
    return invoke("capture_start_url");
  },

  async setCaptureStartUrl(url: string): Promise<string> {
    if (!isTauri()) return url.trim();
    return invoke("set_capture_start_url", { url });
  },

  /** Page of summaries (P5); filters run in the backend. */
  async listRequests(sessionDir: string, offset: number, limit: number, filter: ListFilter): Promise<RequestPageDto> {
    return invoke("list_requests", { sessionDir, offset, limit, filter });
  },

  /** Detail of one request, on demand (P5). */
  async getRequest(sessionDir: string, id: string): Promise<RawRequestDetail> {
    return invoke("get_request", { sessionDir, id });
  },

  /** Consumes `--import-har` / `--import-netlog` / `--open-capture` (once). */
  async takeCliAction(): Promise<CliActionPayload | null> {
    if (!isTauri()) return null;
    return invoke("take_cli_action");
  },

  async importHarAt(path: string): Promise<SessionPayload> {
    return invoke("import_har", { path });
  },

  async importNetlogAt(path: string): Promise<SessionPayload> {
    return invoke("import_netlog", { path });
  },

  async captureStatus(): Promise<CaptureStatus | null> {
    if (!isTauri()) return null;
    return invoke("capture_status");
  },

  async detectChrome(): Promise<ChromeInfo | null> {
    if (!isTauri()) return null;
    return invoke("detect_chrome");
  },

  /** Manual selection of Chrome when detection does not find it. */
  async chooseChrome(): Promise<ChromeInfo | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Select Google Chrome",
      ...chromePickerOptions(),
      multiple: false,
    });
    if (!picked) return null;
    return invoke("set_chrome_path", { path: picked });
  },

  /** Shows a folder or file the backend issued a token for (see `grants`). */
  async revealPath(token: string): Promise<void> {
    if (!isTauri()) return;
    await invoke("reveal_path", { token });
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

  /** Reads an attached body (text, or size + hex preview if binary). */
  async readBody(sessionToken: string, name: string, limit?: number): Promise<BodyData> {
    return invoke("read_body", { sessionToken, name, limit });
  },

  /** Opens a session folder by the token the backend issued for it, without a dialog. */
  async openSessionAt(token: string): Promise<SessionPayload> {
    return invoke("open_session", { token });
  },

  /**
   * Generates the export in Rust from the persisted session. The returned text
   * is exactly what the UI shows, copies and saves — nothing is executed.
   */
  async exportRequest(
    sessionDir: string,
    requestId: string,
    format: "curl" | "python" | "priming",
    annotateOrigins = false,
    lenientParts = false,
  ): Promise<ExportPreview> {
    return invoke("export_request", { sessionDir, requestId, format, annotateOrigins, lenientParts });
  },

  async requestOrigins(sessionDir: string, requestId: string): Promise<ValueOrigins> {
    return invoke("request_origins", { sessionDir, requestId });
  },

  async adapterView(sessionDir: string, requestId: string, side: "request" | "response"): Promise<AdapterViewDto> {
    return invoke("adapter_view", { sessionDir, requestId, side });
  },

  async sessionTimeline(sessionDir: string): Promise<TimelineDto> {
    return invoke("session_timeline", { sessionDir });
  },

  /** Native picker for the trace file (`--trace` of the priming script); `null` if cancelled. */
  async pickTraceFile(): Promise<string | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Choose the trace of the script run",
      message: "JSON file generated by the priming script with --trace (scrapelens.trace/1).",
      multiple: false,
      filters: [{ name: "Trace", extensions: ["json"] }],
    });
    return typeof picked === "string" ? picked : null;
  },

  async validateExecution(sessionDir: string, tracePath: string, mapOrigin?: string): Promise<ValidationResultDto> {
    return invoke("validate_execution", { sessionDir, tracePath, mapOrigin: mapOrigin || null });
  },

  /** Deletes the trace's temporary session (when closing the validation screen). */
  async discardValidation(traceDir: string): Promise<void> {
    if (!isTauri()) return;
    return invoke("discard_validation", { traceDir });
  },

  /** "Keep this run": picks a new folder and moves the trace session there; `null` if cancelled. */
  async keepValidation(traceDir: string): Promise<string | null> {
    if (!isTauri()) return null;
    const picked = await saveDialog({
      title: "Choose a new folder to keep the run",
      defaultPath: "script-run",
      canCreateDirectories: true,
    });
    if (!picked) return null;
    return invoke("keep_validation", { traceDir, destination: picked });
  },

  async assessSession(sessionDir: string): Promise<AssessResult> {
    return invoke("assess_session", { sessionDir });
  },

  async requestChain(sessionDir: string, requestId: string): Promise<PrimingChain> {
    return invoke("request_chain", { sessionDir, requestId });
  },

  /** Native folder picker for the 2nd capture; `null` if the user cancels. */
  async pickCompareSession(): Promise<string | null> {
    if (!isTauri()) return null;
    const picked = await openDialog({
      title: "Choose the 2nd capture (session B folder)",
      message: "Choose the folder of a ScrapeLens session to compare with the open one.",
      directory: true,
      multiple: false,
    });
    return typeof picked === "string" ? picked : null;
  },

  /** Compares A × B in Rust and returns only the summary; pairs and fields come per page. */
  async compareOpen(
    dirA: string,
    dirB: string,
    options: { includeAll?: boolean; aRange?: string; bRange?: string } = {},
  ): Promise<CompareSummary> {
    return invoke("compare_open", {
      dirA,
      dirB,
      includeAll: options.includeAll ?? false,
      aRange: options.aRange || null,
      bRange: options.bRange || null,
    });
  },

  async comparePage(handle: number, offset: number, limit: number, onlyDynamic: boolean): Promise<ComparePage> {
    return invoke("compare_page", { handle, offset, limit, onlyDynamic });
  },

  async compareFields(handle: number, index: number): Promise<FieldDiff[]> {
    return invoke("compare_fields", { handle, index });
  },


  /** The backend opens the native save dialog and writes 0600 without overwriting; `null` if cancelled. */
  async saveExport(defaultName: string, text: string): Promise<SavedFile | null> {
    if (!isTauri()) return null;
    return invoke("save_export_file", { defaultName, text });
  },

  /** Sanitization counts/warnings; writes nothing. */
  async previewSanitized(sessionDir: string, includeSensitive = false): Promise<SanitizePreview> {
    return invoke("preview_sanitized", { sessionDir, includeSensitive });
  },

  /**
   * Native dialog to choose a new folder and write the sanitized session.
   * Cancelling the dialog returns `null` without touching the source.
   */
  async saveSanitized(sessionDir: string, suggestedDestination: string, includeSensitive = false): Promise<SanitizeSaved | null> {
    if (!isTauri()) return null;
    const picked = await saveDialog({
      title: includeSensitive ? "Export full capture with sensitive data" : "Choose a new folder for the sanitized session",
      defaultPath: suggestedDestination,
      canCreateDirectories: true,
    });
    if (!picked) return null;
    return invoke("save_sanitized", { sessionDir, destination: picked, includeSensitive });
  },

  async copyText(text: string): Promise<boolean> {
    if (isTauri()) {
      try {
        const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
        await writeText(text);
        return true;
      } catch {
        /* fall through to the fallback */
      }
    }
    return copyFallback(text);
  },

  /** Native menu events (⌘O, ⌘F, ⌘C, import, demo). */
  async onMenu(handler: (action: MenuAction) => void): Promise<() => void> {
    if (!isTauri()) return () => {};
    const unlisten = await listen<string>("menu://action", (event) => {
      handler(event.payload as MenuAction);
    });
    return unlisten;
  },
};

/** Large session to exercise virtualization in browser mode. */
export async function loadLargeDemo(): Promise<SessionPayload> {
  const { buildLargeSession } = await import("./demo/large");
  return { session: buildLargeSession(12000), synthetic: true, notice: "Synthetic stress session (12,000 requests)." };
}
