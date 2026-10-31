// Tipos do contrato oficial v1 — espelham core/src/model/*.rs (serde camelCase).
// Não são um contrato paralelo: são a projeção TypeScript de docs/03-contratos.md.

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
  /** Segundos, relógio da fonte. */
  timestamp?: number;
  /** Instante absoluto ISO 8601, quando a fonte fornece. */
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
  /** Transformações aplicadas ao corpo (ex.: chrome-decoded); vazio = bytes do fio. */
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
  /** Quem iniciou a tentativa (CDP initiator, HAR _initiator), quando conhecido. */
  initiator?: Initiator;
  id: string;
  logicalId: string;
  index: number;
  url: string;
  method: string;
  protocol: Protocol;
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
  /** Notas informativas (ex.: alvo encerrado durante a configuração). */
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
  status?: number;
  resourceType?: string;
  cdp?: CdpRef;
  /** Alvo CDP (page/iframe/worker/…); ausente em arquivo antigo e NetLog-only. */
  target?: TargetProvenance;
  /** Observações irmãs (service worker); `linked` ou `ambiguous`. */
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
  /** A UI acrescenta este campo ao abrir a sessão (não faz parte do JSON). */
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

export const SYNTHETIC_LABEL = "synthetic-fixture";

export function isSynthetic(session: SessionV1): boolean {
  return session.session.labels?.includes(SYNTHETIC_LABEL) ?? false;
}
