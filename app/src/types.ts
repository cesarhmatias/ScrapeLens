// UI display model. Derived from the v1 contract (src/v1/types.ts) by the
// adapter in src/v1/adapter.ts. No screen imports raw JSON.

export type SourceId = "cdp" | "netlog" | "har" | "ownFormat" | "capture" | "derived" | "manual";
export type Protocol = "HTTP/1.1" | "HTTP/2" | "HTTP/3" | "unknown";
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
  /** Provenance copied from the v1 entry (source, event, method). */
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
  /** Absolute ISO instant, when the source provides it. */
  timestamp: string;
  /** Monotonic time from the source (seconds), when there is no wall clock. */
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

/** CDP target type (`Target.targetInfo.type`), mirror of the core. */
export type TargetKind =
  | "page"
  | "iframe"
  | "worker"
  | "service_worker"
  | "shared_worker"
  | "other";

/** CDP target provenance; absent in old sessions and in NetLog-only ones. */
export interface TargetView {
  targetId?: string;
  kind: TargetKind;
  url?: string;
  openerId?: string;
  parentSessionId?: string;
  attached?: boolean;
  /** Informational notes from the core (e.g. "target closed during setup"). */
  notes: string[];
}

/** Sibling observation (service worker): `linked` or `ambiguous`. */
export interface RequestLinkView {
  kind: string;
  request: string;
  evidence: string[];
  resolution: string;
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
  /** CDP target; absent = old session or NetLog only. */
  target?: TargetView;
  /** Linked observations (SW); never a duplicate without this field. */
  links: RequestLinkView[];
  /**
   * No target provenance and a NetLog source: mark "unknown target (NetLog only)".
   * In old sessions (without a Target column) this badge does not appear.
   */
  netlogOnlyUnknownTarget: boolean;
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

/** List row (P5): only what the table, filters and targets need; the detail comes from `get_request`. */
export type RequestSummary = Pick<
  RequestRecord,
  | "id"
  | "url"
  | "method"
  | "domain"
  | "path"
  | "status"
  | "statusText"
  | "protocol"
  | "type"
  | "startedAt"
  | "durationMs"
  | "initiator"
  | "target"
  | "links"
  | "netlogOnlyUnknownTarget"
  | "primarySource"
> & {
  warningCount: number;
  /** Duration estimated or missing in the source (same rule as the timings check). */
  durationApprox: boolean;
};

export interface SessionOrigin {
  kind: "synthetic" | "live" | "capture-import" | "har-import" | "netlog-import" | "unknown";
  /** Human-readable label of the origin; never "live"/"real" without an explicit label from the core. */
  label: string;
  /** "Real" badge: only for a live capture or a user-imported file. */
  real: boolean;
  /** Short text for tags. */
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
  /** Total number of requests (in a paged session, `requests` stays empty). */
  requestCount: number;
  /** Session paged by the backend (P5): list via `list_requests`, detail via `get_request`. */
  paged: boolean;
}
