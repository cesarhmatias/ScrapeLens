// Tipos do contrato PROVISÓRIO — ver ../CONTRACT-DRAFT.md.
// Este arquivo é o espelho executável do rascunho e será trocado pelo
// contrato oficial do líder (docs/03-contratos.md).

export type SourceId = "cdp" | "netlog" | "har" | "session";
export type Protocol = "HTTP/1.1" | "HTTP/2" | "HTTP/3";
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
}

export interface CookiePair {
  name: string;
  value: string;
  index: number;
}

export interface ReceivedCookie extends CookiePair {
  attributes: { name: string; value?: string }[];
  raw: string;
}

export interface BodyInfo {
  availability: "available" | "truncated" | "discarded" | "omitted" | "unavailable";
  contentType?: string;
  encodedSize?: number;
  decodedSize?: number;
  preview?: string;
  truncatedAt?: number;
  reason?: string;
  captureRef?: string;
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
  timestamp: string;
  method: string;
  eventRef?: string;
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
  payload: BodyInfo;
  responseBody: BodyInfo;
  redirects: RedirectHop[];
  primarySource: SourceId;
  verification: Record<VerificationKey, Verification>;
}

export interface SessionRecord {
  id: string;
  label: string;
  synthetic: boolean;
  createdAt: string;
  chromeVersion?: string;
  capture: { cdpEvents: number; netlogBytes?: number; status: "closed" | "partial" | "open" };
  requests: RequestRecord[];
  sources: SourceId[];
  notes?: string[];
}
