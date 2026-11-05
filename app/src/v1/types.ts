// Official v1 contract types — mirror core/src/model/*.rs (serde camelCase).
// They are not a parallel contract: they are the TypeScript projection of docs/03-contracts.md.

export type Source = "cdp" | "netlog" | "har" | "ownFormat" | "capture" | "derived" | "manual";
export type Verification = "verified" | "partial" | "unverified";
export type Protocol = "h1" | "h2" | "h3" | "unknown";
export type MatchState = "matched" | "ambiguous" | "unmatched";
export type BodyState = "captured" | "empty" | "truncated" | "unavailable" | "discarded";
export type OrderState = "sourceOrder" | "reconstructed" | "normalized" | "unknown";

export interface Provenance {
  source: Source;
  event?: string;
  sourceId?: string;
  /** Seconds, source clock. */
  timestamp?: number;
  /** Absolute ISO 8601 instant, when the source provides it. */
  wallTime?: string;
  browserVersion?: string;
  method: string;
  verification: Verification;
  notes?: string[];
}

export interface HeaderEntry extends Provenance {
  name: string;
  value: string;
}

export interface HeaderView {
  pseudoHeaders?: HeaderEntry[];
  headers: HeaderEntry[];
  startLine?: string;
  rawBlock?: string;
  orderState: OrderState;
  notes?: string[];
}

export interface Body {
  state: BodyState;
  attachment?: string;
  bytes?: number;
  truncatedAt?: number;
  contentType?: string;
  contentEncoding?: string;
  note?: string;
  /** Transformations applied to the body (e.g. chrome-decoded); empty = wire bytes. */
  transformed?: string[];
  provenance: Provenance;
}

export interface CookiePairEntry extends Provenance {
  name: string;
  value: string;
  raw: string;
}

export interface CookieField {
  raw: string[];
  pairs: CookiePairEntry[];
  wireLines: string[];
  unparsed: string[];
  notes?: string[];
  provenance: Provenance;
}

export interface ParsedSetCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  partitioned: boolean;
  extensions?: [string, string][];
  notes?: string[];
}

export interface SetCookieRecord extends Provenance {
  raw: string;
  parsed?: ParsedSetCookie;
  parseError?: string;
}

export interface Redirect {
  id: string;
  logicalId: string;
  fromAttemptId: string;
  toAttemptId?: string;
  status?: number;
  location?: string;
  fromUrl: string;
  toUrl?: string;
  provenance: Provenance;
}

export interface CdpRef {
  sessionId?: string;
  requestId?: string;
  loaderId?: string;
  frameId?: string;
}

export interface NetlogRefs {
  sourceIds?: number[];
  streamIds?: number[];
  dependencyIds?: number[];
}

export interface MatchCandidate {
  entityId: string;
  score: number;
  reasons?: string[];
}

export interface Span {
  start: number;
  end: number;
}

export interface Timings {
  requestTime?: number;
  wallTime?: string;
  dns?: Span;
  connect?: Span;
  tls?: Span;
  send?: Span;
  wait?: Span;
  receive?: Span;
  totalMs?: number;
  estimated?: boolean;
}

export interface HeaderEvidence {
  id: string;
  role: "request" | "response";
  protocol: Protocol;
  event: string;
  sourceId?: number;
  streamId?: number;
  view: HeaderView;
}

export interface Initiator {
  kind: string;
  url?: string;
}

export interface Attempt {
  /** Who started the attempt (CDP initiator, HAR _initiator), when known. */
  initiator?: Initiator;
  id: string;
  logicalId: string;
  index: number;
  url: string;
  method: string;
  protocol: Protocol;
  /** Optional, additive: `not-sent` when the NetLog proves no bytes reached the network. */
  networkState?: "not-sent";
  status?: number;
  connectionId?: string;
  streamSessionId?: string;
  outcome: "completed" | "failed" | "aborted" | "pending" | "unknown";
  failure?: string;
  startedAt?: number;
  endedAt?: number;
  requestHeaders: HeaderView;
  responseHeaders: HeaderView;
  cookie: CookieField;
  setCookies?: SetCookieRecord[];
  headerEvidence?: HeaderEvidence[];
  requestBody: Body;
  responseBody: Body;
  cdp?: CdpRef;
  netlog?: NetlogRefs;
  match: MatchState;
  matchCandidates?: MatchCandidate[];
  provenance: Provenance;
}

export type TargetKind =
  | "page"
  | "iframe"
  | "worker"
  | "service_worker"
  | "shared_worker"
  | "other";

export interface TargetProvenance {
  targetId?: string;
  kind?: TargetKind;
  url?: string;
  openerId?: string;
  parentSessionId?: string;
  attached?: boolean;
  /** Informational notes (e.g. target closed during setup). */
  notes?: string[];
}

export interface RequestLink {
  kind: string;
  request: string;
  evidence?: string[];
  resolution: string;
}

export interface LogicalRequest {
  id: string;
  url: string;
  method: string;
  protocol: Protocol;
  /** Optional, additive: `not-sent` when the NetLog proves no bytes reached the network. */
  networkState?: "not-sent";
  status?: number;
  resourceType?: string;
  cdp?: CdpRef;
  /** CDP target (page/iframe/worker/…); absent in old files and NetLog-only. */
  target?: TargetProvenance;
  /** Sibling observations (service worker); `linked` or `ambiguous`. */
  links?: RequestLink[];
  netlog?: NetlogRefs;
  attempts: Attempt[];
  redirects?: Redirect[];
  requestHeaders: HeaderView;
  responseHeaders: HeaderView;
  cookie: CookieField;
  setCookies?: SetCookieRecord[];
  requestBody: Body;
  responseBody: Body;
  timings: Timings;
  match: MatchState;
  matchCandidates?: MatchCandidate[];
  provenance: Provenance;
  /** The UI adds this field when opening the session (not part of the JSON). */
  sessionId?: string;
}

export interface Warning {
  code: string;
  message: string;
  severity: "info" | "warning" | "error";
  entity?: string;
  detail?: unknown;
}

export interface SessionMeta {
  id: string;
  browser: {
    name: string;
    version?: string;
    platform?: string;
    userAgent?: string;
  };
  startedAt: string;
  endedAt?: string;
  completeness: {
    state: "complete" | "partial";
    reasons: string[];
    counts?: Record<string, number>;
  };
  capture?: {
    mode?: string;
    browserBinary?: string;
    headless?: boolean;
    chromeArgs?: string[];
    notes?: string;
  };
  labels: string[];
  notes?: string[];
}

export interface Connection {
  id: string;
  netlogId?: number;
  protocol: Protocol;
  host?: string;
  port?: number;
  ip?: string;
  alpn?: string;
  tlsVersion?: string;
  reused?: boolean;
  provenance: Provenance;
}

export interface StreamSession {
  id: string;
  connectionId?: string;
  protocol: Protocol;
  streamId?: number;
  attemptId?: string;
  netlogSessionId?: number;
  provenance: Provenance;
}

export interface SessionV1 {
  schemaVersion: number;
  session: SessionMeta;
  requests: LogicalRequest[];
  connections?: Connection[];
  streamSessions?: StreamSession[];
  warnings?: Warning[];
}

/** Raw `list_requests` summary (src-tauri/src/listing.rs). */
export interface RawRequestSummary {
  id: string;
  url: string;
  method: string;
  status?: number;
  protocol: Protocol;
  networkState?: "not-sent";
  resourceType?: string;
  wallTime?: string;
  totalMs?: number;
  estimated?: boolean;
  initiator?: { kind: string; url?: string };
  /** Index into `RequestPageDto.targets`. */
  target?: number;
  links?: RequestLink[];
  source: Provenance["source"];
  warningCount: number;
}

/** `get_request` detail. */
export interface RawRequestDetail {
  request: LogicalRequest;
  warnings: Warning[];
  streamSessions: StreamSession[];
}

/** Header of `open_session` (P5): no requests. */
export interface SessionHeaderV1 extends SessionV1 {
  requestCount?: number;
  sources?: Provenance["source"][];
}

export const SYNTHETIC_LABEL = "synthetic-fixture";

export function isSynthetic(session: SessionV1): boolean {
  return session.session.labels?.includes(SYNTHETIC_LABEL) ?? false;
}
