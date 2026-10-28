// Modelo de exibição da UI. Derivado do contrato v1 (src/v1/types.ts) pelo
// adaptador em src/v1/adapter.ts. Nenhuma tela importa JSON bruto.

export type SourceId = "cdp" | "netlog" | "har" | "ownFormat" | "capture" | "derived" | "manual";
export type Protocol = "HTTP/1.1" | "HTTP/2" | "HTTP/3" | "desconhecido";
export type ResourceType =
  | "document"
  | "stylesheet"
  | "script"
  | "xhr"
  | "fetch"
  | "image"
  | "font"
  | "other";

export interface HeaderPair {
  index: number;
  name: string;
  value: string;
  kind: "pseudo" | "regular";
  note?: string;
  /** Proveniência copiada da entrada v1 (fonte, evento, método). */
  source?: SourceId;
  event?: string;
  method?: string;
  wallTime?: string;
  verification?: "verified" | "partial" | "unverified";
}

export interface CookiePair {
  name: string;
  value: string;
  index: number;
  raw?: string;
}

export interface ReceivedCookie extends CookiePair {
  attributes: { name: string; value?: string }[];
  raw: string;
  parseError?: string;
}

export interface BodyInfo {
  availability: "available" | "empty" | "truncated" | "discarded" | "omitted" | "unavailable";
  contentType?: string;
  encodedSize?: number;
  decodedSize?: number;
  preview?: string;
  truncatedAt?: number;
  reason?: string;
  captureRef?: string;
  attachment?: string;
  transformed?: string[];
}

export interface RedirectHop {
  index: number;
  url: string;
  status: number;
  location?: string;
  protocol: Protocol;
}

export interface EvidenceRef {
  source: SourceId;
  event: string;
  /** Instante absoluto ISO, quando a fonte fornece. */
  timestamp: string;
  /** Tempo monotônico da fonte (segundos), quando não há relógio de parede. */
  sourceTime?: number;
  method: string;
  eventRef?: string;
  notes?: string[];
}

export type Verification =
  | { status: "verified"; evidence: EvidenceRef }
  | { status: "partial"; evidence: EvidenceRef; missing: string }
  | { status: "unverified"; reason: string };

export type VerificationKey =
  | "requestHeaders"
  | "responseHeaders"
  | "normalizedHeaders"
  | "cookies"
  | "payload"
  | "responseBody"
  | "protocol"
  | "timings";

export interface AttemptView {
  id: string;
  index: number;
  url: string;
  method: string;
  protocol: Protocol;
  status?: number;
  outcome: string;
  failure?: string;
  requestHeaderCount: number;
  responseHeaderCount: number;
  headerEvidence: number;
  match: "matched" | "ambiguous" | "unmatched";
  connectionId?: string;
  streamSessionId?: string;
  cdpRequestId?: string;
  netlogSourceIds: number[];
}

export interface MatchView {
  state: "matched" | "ambiguous" | "unmatched";
  candidates: { entityId: string; score: number; reasons: string[] }[];
}

export interface WarningView {
  code: string;
  message: string;
  severity: "info" | "warning" | "error";
  entity?: string;
}

export interface RequestRecord {
  id: string;
  url: string;
  method: string;
  domain: string;
  path: string;
  status: number;
  statusText?: string;
  protocol: Protocol;
  type: ResourceType;
  startedAt: string;
  durationMs: number;
  initiator?: string;
  requestHeaders: HeaderPair[];
  responseHeaders: HeaderPair[];
  cookiesSent: CookiePair[];
  cookiesReceived: ReceivedCookie[];
  cookieRaw: string[];
  cookieWireLines: string[];
  cookieNotes?: string[];
  payload: BodyInfo;
  responseBody: BodyInfo;
  redirects: RedirectHop[];
  attempts: AttemptView[];
  match: MatchView;
  warnings: WarningView[];
  primarySource: SourceId;
  verification: Record<VerificationKey, Verification>;
}

export interface SessionOrigin {
  kind: "synthetic" | "live" | "capture-import" | "har-import" | "netlog-import" | "unknown";
  /** Rótulo humano da origem; nunca "ao vivo"/"real" sem rótulo explícito do core. */
  label: string;
  /** Selo "real": só captura ao vivo ou arquivo do usuário importado. */
  real: boolean;
  /** Texto curto para tags. */
  tag: string;
}

export interface SessionRecord {
  origin: SessionOrigin;
  id: string;
  label: string;
  synthetic: boolean;
  createdAt: string;
  endedAt?: string;
  chromeVersion?: string;
  completeness: { state: "complete" | "partial"; reasons: string[] };
  capture: { cdpEvents: number; netlogBytes?: number; status: "closed" | "partial" | "open"; mode?: string };
  requests: RequestRecord[];
  sources: SourceId[];
  warnings: WarningView[];
  notes?: string[];
  labels: string[];
  sourcePath?: string;
  attachments?: Record<string, string>;
}
