// v1 contract adapter (docs/03-contracts.md) → display model.
// Rule: nothing is sorted or merged here. Headers follow pseudo + regular order in
// the source's order; the normalized view is derived in the UI and labeled.

import type {
  AttemptView,
  BodyInfo,
  HeaderPair,
  Protocol,
  ReceivedCookie,
  RedirectHop,
  RequestLinkView,
  RequestRecord,
  RequestSummary,
  ResourceType,
  SessionRecord,
  SessionOrigin,
  SourceId,
  TargetKind,
  TargetView,
  Verification,
  VerificationKey,
  WarningView,
} from "../types";
import type {
  Body,
  HeaderEntry,
  HeaderView,
  LogicalRequest,
  Provenance,
  RawRequestDetail,
  RawRequestSummary,
  RequestLink,
  SessionHeaderV1,
  SessionV1,
  TargetProvenance,
  Timings,
} from "./types";

const TARGET_KINDS = new Set<TargetKind>([
  "page",
  "iframe",
  "worker",
  "service_worker",
  "shared_worker",
  "other",
]);

function mapTarget(raw: TargetProvenance | undefined): TargetView | undefined {
  if (!raw) return undefined;
  const kind = TARGET_KINDS.has((raw.kind ?? "other") as TargetKind)
    ? ((raw.kind ?? "other") as TargetKind)
    : "other";
  const notes = raw.notes ?? [];
  // Empty provenance (serde default) does not become a confusing column.
  if (
    !raw.targetId &&
    kind === "other" &&
    !raw.url &&
    !raw.openerId &&
    !raw.parentSessionId &&
    raw.attached === undefined &&
    notes.length === 0
  ) {
    return undefined;
  }
  return {
    targetId: raw.targetId,
    kind,
    url: raw.url,
    openerId: raw.openerId,
    parentSessionId: raw.parentSessionId,
    attached: raw.attached,
    notes,
  };
}

function mapLinks(raw: RequestLink[] | undefined): RequestLinkView[] {
  return (raw ?? []).map((link) => ({
    kind: link.kind,
    request: link.request,
    evidence: link.evidence ?? [],
    resolution: link.resolution,
  }));
}

const protocolLabel = (p: string): Protocol =>
  p === "h1" ? "HTTP/1.1" : p === "h2" ? "HTTP/2" : p === "h3" ? "HTTP/3" : "unknown";

/**
 * `networkState: "not-sent"` (core contract): the NetLog proves the request was cancelled
 * before any bytes were written. The protocol stays `unknown` and is never inferred.
 * Absent in sessions saved before the field: those keep the previous behaviour.
 */
export function networkStateOf(request: { networkState?: string; attempts?: { networkState?: string }[] }) {
  if (request.networkState === "not-sent") return "not-sent" as const;
  // The core marks the request only when every attempt was not sent; one such attempt is not enough.
  const attempts = request.attempts ?? [];
  if (attempts.length > 0 && attempts.every((attempt) => attempt.networkState === "not-sent")) {
    return "not-sent" as const;
  }
  return undefined;
}

/** Text shown for the protocol: a request that was not sent has no protocol to show. */
export function protocolText(protocol: Protocol, networkState?: string): string {
  return networkState === "not-sent" ? "not sent" : protocol;
}

const sourceLabel = (s: Provenance["source"]): SourceId => s;

const RESOURCE_TYPES = new Set<ResourceType>([
  "document",
  "stylesheet",
  "script",
  "xhr",
  "fetch",
  "image",
  "font",
  "other",
]);

const rank: Record<Provenance["verification"], number> = { verified: 2, partial: 1, unverified: 0 };

function evidenceOf(p: Provenance) {
  return {
    source: sourceLabel(p.source),
    event: p.event ?? p.sourceId ?? "no event name",
    timestamp: p.wallTime ?? "",
    sourceTime: p.wallTime ? undefined : p.timestamp,
    method: p.method,
    eventRef: p.sourceId,
    notes: p.notes,
  };
}

export function verificationOf(p?: Provenance): Verification {
  if (!p) return { status: "unverified", reason: "no provenance recorded by the source" };
  if (p.verification === "verified") return { status: "verified", evidence: evidenceOf(p) };
  if (p.verification === "partial") {
    return {
      status: "partial",
      evidence: evidenceOf(p),
      missing: p.notes?.filter(Boolean).join(" · ") || "the source preserves part of the information",
    };
  }
  return {
    status: "unverified",
    reason: p.notes?.filter(Boolean).join(" · ") || p.method || "no evidence in the capture",
  };
}

function weakestVerification(entries: HeaderEntry[], view?: HeaderView): Verification {
  if (entries.length === 0) {
    return {
      status: "unverified",
      reason:
        view?.notes?.filter(Boolean).join(" · ") ||
        "no header line was observed in this capture",
    };
  }
  let weakest = entries[0];
  for (const entry of entries) {
    if (rank[entry.verification] < rank[weakest.verification]) weakest = entry;
  }
  return verificationOf(weakest);
}

function flattenHeaders(view: HeaderView | undefined): HeaderPair[] {
  if (!view) return [];
  const all = [...(view.pseudoHeaders ?? []), ...(view.headers ?? [])];
  return all.map((entry, index) => ({
    index,
    name: entry.name,
    value: entry.value,
    kind: entry.name.startsWith(":") ? "pseudo" : "regular",
    note: entry.notes?.join(" · "),
    source: sourceLabel(entry.source),
    event: entry.event,
    method: entry.method,
    wallTime: entry.wallTime,
    verification: entry.verification,
  }));
}

const AVAILABILITY: Record<Body["state"], BodyInfo["availability"]> = {
  captured: "available",
  empty: "empty",
  truncated: "truncated",
  discarded: "discarded",
  unavailable: "unavailable",
};

function mapBody(body: Body | undefined, attachments?: Record<string, string>): BodyInfo {
  if (!body) {
    return { availability: "unavailable", reason: "body not provided by the contract" };
  }
  const preview = body.attachment ? attachments?.[body.attachment] : undefined;
  return {
    availability: AVAILABILITY[body.state] ?? "unavailable",
    contentType: body.contentType,
    encodedSize: body.bytes,
    decodedSize: body.bytes,
    preview,
    truncatedAt: body.truncatedAt,
    reason: body.note,
    captureRef: body.attachment,
    transformed: body.transformed,
    attachment: body.attachment,
  };
}

function mapSetCookies(request: LogicalRequest): ReceivedCookie[] {
  return (request.setCookies ?? []).map((record, index) => {
    const parsed = record.parsed;
    const attributes: { name: string; value?: string }[] = [];
    if (parsed) {
      if (parsed.domain !== undefined) attributes.push({ name: "Domain", value: parsed.domain });
      if (parsed.path !== undefined) attributes.push({ name: "Path", value: parsed.path });
      if (parsed.expires !== undefined) attributes.push({ name: "Expires", value: parsed.expires });
      if (parsed.maxAge !== undefined) attributes.push({ name: "Max-Age", value: String(parsed.maxAge) });
      if (parsed.secure) attributes.push({ name: "Secure" });
      if (parsed.httpOnly) attributes.push({ name: "HttpOnly" });
      if (parsed.sameSite !== undefined) attributes.push({ name: "SameSite", value: parsed.sameSite });
      if (parsed.partitioned) attributes.push({ name: "Partitioned" });
      for (const [name, value] of parsed.extensions ?? []) attributes.push({ name, value });
    }
    return {
      index,
      name: parsed?.name ?? record.raw.split("=")[0]?.trim() ?? "(no name)",
      value: parsed?.value ?? "",
      raw: record.raw,
      attributes,
      parseError: record.parseError,
    };
  });
}

function cookieVerification(request: LogicalRequest): Verification {
  if (request.cookie.pairs.length === 0 && request.cookie.raw.length === 0) {
    return { status: "unverified", reason: "no cookie sent in this request" };
  }
  return verificationOf(request.cookie.provenance);
}

function timingsVerification(t: Timings, request: LogicalRequest): Verification {
  if (t.estimated) {
    return {
      status: "unverified",
      reason: "estimated duration: the source did not provide a completion event",
    };
  }
  if (t.totalMs === undefined) return { status: "unverified", reason: "no total time from the source" };
  return {
    status: "partial",
    evidence: evidenceOf(request.provenance),
    missing: "timings do not carry their own provenance in the v1 contract",
  };
}

/** Headers of a request that never reached the network: they came from CDP and were not sent. */
function notSentHeaders(base: Verification): Verification {
  const reason =
    "headers come from CDP before the cancel and were never transmitted: the request did not reach the network";
  return {
    status: "unverified",
    reason: base.status === "unverified" && base.reason ? `${base.reason} · ${reason}` : reason,
  };
}

function notSentProtocolVerification(request: LogicalRequest, attempt: LogicalRequest["attempts"][number] | undefined): Verification {
  // The proof is the NetLog cancel (the attempt's NetLog source), not the CDP structure.
  const provenance = attempt?.provenance ?? request.provenance;
  const notes = (provenance.notes ?? []).filter(Boolean).join(" · ");
  const netlogSource = attempt?.netlog?.sourceIds?.[0];
  return {
    status: "verified",
    evidence: {
      source: "netlog",
      event: "URL_REQUEST cancelled; no send event",
      timestamp: provenance.wallTime ?? "",
      sourceTime: provenance.wallTime ? undefined : provenance.timestamp,
      method: ["no protocol: the request never reached the network", notes].filter(Boolean).join(" · "),
      eventRef: netlogSource !== undefined ? String(netlogSource) : provenance.sourceId,
      notes: provenance.notes,
    },
  };
}

/** Not sent: the time is the cancel moment, not a network duration. */
function notSentTimings(): Verification {
  return {
    status: "unverified",
    reason: "not sent: there is no network time; the recorded value is when the request was cancelled",
  };
}

function protocolVerification(
  request: LogicalRequest,
  streams: Map<string, NonNullable<SessionV1["streamSessions"]>[number]>,
): Verification {
  const attempt = request.attempts[0];
  if (networkStateOf(request) === "not-sent") return notSentProtocolVerification(request, attempt);
  const stream = attempt ? streams.get(attempt.id) : undefined;
  if (!stream) {
    return {
      status: "partial",
      evidence: evidenceOf(request.provenance),
      missing: "no NetLog StreamSession associated with this attempt",
    };
  }
  return verificationOf(stream.provenance);
}

function statusOf(request: LogicalRequest): number {
  return request.status ?? 0;
}

function durationOf(request: LogicalRequest): number {
  return Math.round(request.timings.totalMs ?? 0);
}

function startedAtOf(request: LogicalRequest, session: SessionV1): string {
  return request.timings.wallTime ?? session.session.startedAt;
}

function attemptsOf(request: LogicalRequest): AttemptView[] {
  return request.attempts.map((attempt) => ({
    id: attempt.id,
    index: attempt.index,
    url: attempt.url,
    method: attempt.method,
    protocol: protocolLabel(attempt.protocol),
    networkState: attempt.networkState === "not-sent" ? "not-sent" : undefined,
    status: attempt.status,
    outcome: attempt.outcome,
    failure: attempt.failure,
    requestHeaderCount:
      (attempt.requestHeaders.pseudoHeaders?.length ?? 0) + attempt.requestHeaders.headers.length,
    responseHeaderCount:
      (attempt.responseHeaders.pseudoHeaders?.length ?? 0) + attempt.responseHeaders.headers.length,
    headerEvidence: attempt.headerEvidence?.length ?? 0,
    match: attempt.match,
    connectionId: attempt.connectionId,
    streamSessionId: attempt.streamSessionId,
    cdpRequestId: attempt.cdp?.requestId,
    netlogSourceIds: attempt.netlog?.sourceIds ?? [],
  }));
}

function redirectsOf(request: LogicalRequest): RedirectHop[] {
  if (!request.redirects?.length) return [];
  const protocolByAttempt = new Map(request.attempts.map((a) => [a.id, protocolLabel(a.protocol)]));
  return request.redirects.map((redirect, index) => ({
    index,
    url: redirect.fromUrl,
    status: redirect.status ?? 0,
    location: redirect.location ?? redirect.toUrl,
    protocol: protocolByAttempt.get(redirect.fromAttemptId) ?? protocolLabel(request.protocol),
  }));
}

function warningView(w: NonNullable<SessionV1["warnings"]>[number]): WarningView {
  return { code: w.code, message: w.message, severity: w.severity, entity: w.entity };
}

function matchOf(request: LogicalRequest) {
  return {
    state: request.match,
    candidates: (request.matchCandidates ?? []).map((c) => ({
      entityId: c.entityId,
      score: c.score,
      reasons: c.reasons ?? [],
    })),
  };
}


// Mirrors the core's #[serde(default)] values (core/src/model): the v1 contract allows
// omitting these fields. Fills only the empty value equivalent to the core default —
// "no attempts", "no cookies", "body not provided" — never invented data.
const defaultProvenance = (): Provenance => ({
  source: "ownFormat",
  method: "unspecified",
  verification: "unverified",
});

const defaultHeaderView = (): HeaderView => ({ headers: [] }) as unknown as HeaderView;

const defaultBody = (): Body =>
  ({
    state: "unavailable",
    note: "body not provided by the source",
    provenance: defaultProvenance(),
  }) as unknown as Body;

const defaultCookie = (): LogicalRequest["cookie"] => ({
  raw: [],
  pairs: [],
  wireLines: [],
  unparsed: [],
  provenance: defaultProvenance(),
});

function normalizeHeaderView(view: HeaderView | undefined): HeaderView {
  const base = view ?? defaultHeaderView();
  return { ...base, headers: base.headers ?? [], pseudoHeaders: base.pseudoHeaders ?? [] };
}

function normalizeCookie(cookie: LogicalRequest["cookie"] | undefined): LogicalRequest["cookie"] {
  const base = cookie ?? defaultCookie();
  return {
    ...base,
    raw: base.raw ?? [],
    pairs: base.pairs ?? [],
    wireLines: base.wireLines ?? [],
    unparsed: base.unparsed ?? [],
    provenance: base.provenance ?? defaultProvenance(),
  };
}

function normalizeBody(body: Body | undefined): Body {
  if (!body) return defaultBody();
  return { ...body, provenance: body.provenance ?? defaultProvenance() };
}

function normalizeAttempt(attempt: LogicalRequest["attempts"][number]): LogicalRequest["attempts"][number] {
  return {
    ...attempt,
    outcome: attempt.outcome ?? "unknown",
    requestHeaders: normalizeHeaderView(attempt.requestHeaders),
    responseHeaders: normalizeHeaderView(attempt.responseHeaders),
    cookie: normalizeCookie(attempt.cookie),
    requestBody: normalizeBody(attempt.requestBody),
    responseBody: normalizeBody(attempt.responseBody),
    match: attempt.match ?? "unmatched",
    provenance: attempt.provenance ?? defaultProvenance(),
  };
}

function normalizeRequest(request: LogicalRequest): LogicalRequest {
  return {
    ...request,
    attempts: (request.attempts ?? []).map(normalizeAttempt),
    redirects: request.redirects ?? [],
    requestHeaders: normalizeHeaderView(request.requestHeaders),
    responseHeaders: normalizeHeaderView(request.responseHeaders),
    cookie: normalizeCookie(request.cookie),
    setCookies: request.setCookies ?? [],
    requestBody: normalizeBody(request.requestBody),
    responseBody: normalizeBody(request.responseBody),
    timings: request.timings ?? {},
    match: request.match ?? "unmatched",
    matchCandidates: request.matchCandidates ?? [],
    provenance: request.provenance ?? defaultProvenance(),
  } as LogicalRequest;
}

export function normalizeSession(raw: SessionV1): SessionV1 {
  const meta = raw.session;
  return {
    ...raw,
    session: {
      ...meta,
      browser: meta.browser ?? { name: "unknown" },
      labels: meta.labels ?? [],
      completeness: meta.completeness ?? {
        state: "partial",
        reasons: ["completeness not stated by the source"],
      },
    },
    requests: (raw.requests ?? []).map(normalizeRequest),
  };
}

export interface AdaptedSession {
  session: SessionRecord;
  /** v1 version for exports and for the lossless diff. */
  raw: SessionV1;
  sourcePath?: string;
}

/** Origin from the core's labels; without a known label it is never "real" or "live". */
export function sessionOrigin(labels: string[]): SessionOrigin {
  if (labels.includes("synthetic-fixture"))
    return { kind: "synthetic", label: "Demo — synthetic showcase", real: false, tag: "DEMO" };
  if (labels.includes("live-capture"))
    return { kind: "live", label: "Live capture", real: true, tag: "live capture" };
  if (labels.includes("capture-import"))
    return { kind: "capture-import", label: "Imported capture (CDP/NetLog)", real: true, tag: "imported" };
  if (labels.includes("har-import"))
    return { kind: "har-import", label: "HAR imported", real: true, tag: "imported" };
  if (labels.includes("netlog-import"))
    return { kind: "netlog-import", label: "NetLog imported", real: true, tag: "imported" };
  return {
    kind: "unknown",
    label: labels.includes("sanitized") ? "Sanitized session (origin not stated)" : "origin not stated",
    real: false,
    tag: "origin not stated",
  };
}

export function adaptSession(
  input: SessionV1,
  options: { attachments?: Record<string, string>; sourcePath?: string } = {},
): AdaptedSession {
  const raw = normalizeSession(input);
  const synthetic = raw.session.labels?.includes("synthetic-fixture") ?? false;
  const warnings = (raw.warnings ?? []).map(warningView);
  const sessionWarnings = warnings.filter((w) => !w.entity);
  const counts = raw.session.completeness.counts ?? {};

  const streams = new Map(
    (raw.streamSessions ?? []).filter((stream) => stream.attemptId).map((stream) => [stream.attemptId!, stream]),
  );

  const requests: RequestRecord[] = raw.requests.map((request) => {
    const requestHeaders = flattenHeaders(request.requestHeaders);
    const responseHeaders = flattenHeaders(request.responseHeaders);
    const attempts = attemptsOf(request);
    const ownWarnings = warnings.filter((w) => w.entity === request.id);
    const isSynthetic = synthetic;

    const notSent = networkStateOf(request) === "not-sent";
    const verification: Record<VerificationKey, Verification> = {
      requestHeaders: (() => {
        const base = weakestVerification(
          [...(request.requestHeaders.pseudoHeaders ?? []), ...request.requestHeaders.headers],
          request.requestHeaders,
        );
        return notSent ? notSentHeaders(base) : base;
      })(),
      responseHeaders: weakestVerification(
        [...(request.responseHeaders.pseudoHeaders ?? []), ...request.responseHeaders.headers],
        request.responseHeaders,
      ),
      normalizedHeaders: {
        status: "partial",
        evidence: {
          source: "derived",
          event: "derive:normalizedHeaders",
          timestamp: "",
          method: "local UI derivation from the original",
        },
        missing: "derived view, not transmitted",
      },
      cookies: cookieVerification(request),
      payload: verificationOf(request.requestBody?.provenance),
      responseBody: verificationOf(request.responseBody?.provenance),
      protocol: protocolVerification(request, streams),
      timings: notSent ? notSentTimings() : timingsVerification(request.timings, request),
    };

    const rawStatus = statusOf(request);
    const bodyPreview = mapBody(request.responseBody, options.attachments);
    if (isSynthetic && bodyPreview.attachment && !bodyPreview.preview) {
      bodyPreview.reason = bodyPreview.reason ?? "synthetic preview not included";
    }

    const target = mapTarget(request.target);
    const primarySource = sourceLabel(request.provenance.source);
    return {
      id: request.id,
      url: request.url,
      method: request.method,
      domain: safeHost(request.url),
      path: safePath(request.url),
      status: rawStatus,
      statusText: statusText(rawStatus),
      initiator: initiatorLabel(request.attempts?.length ? request.attempts[request.attempts.length - 1].initiator ?? request.attempts[0].initiator : undefined),
      protocol: protocolLabel(request.protocol),
      networkState: networkStateOf(request),
      type: RESOURCE_TYPES.has((request.resourceType ?? "").toLowerCase() as ResourceType)
        ? ((request.resourceType ?? "other").toLowerCase() as ResourceType)
        : "other",
      startedAt: startedAtOf(request, raw),
      durationMs: durationOf(request),
      target,
      links: mapLinks(request.links),
      netlogOnlyUnknownTarget: !target && primarySource === "netlog",
      requestHeaders,
      responseHeaders,
      cookiesSent: request.cookie.pairs.map((pair, index) => ({
        index,
        name: pair.name,
        value: pair.value,
        raw: pair.raw,
      })),
      cookiesReceived: mapSetCookies(request),
      cookieRaw: request.cookie.raw,
      cookieWireLines: request.cookie.wireLines,
      cookieNotes: request.cookie.notes,
      payload: mapBody(request.requestBody, options.attachments),
      responseBody: bodyPreview,
      redirects: redirectsOf(request),
      attempts,
      match: matchOf(request),
      warnings: ownWarnings,
      primarySource,
      verification,
    };
  });

  const sources = new Set<SourceId>();
  for (const request of raw.requests) {
    sources.add(sourceLabel(request.provenance.source));
    for (const attempt of request.attempts) {
      sources.add(sourceLabel(attempt.provenance.source));
      for (const cookie of attempt.cookie.pairs) sources.add(sourceLabel(cookie.source));
    }
  }

  const browser = raw.session.browser;
  const labels = raw.session.labels ?? [];
  const origin = sessionOrigin(labels);
  const kind = labels.includes("sanitized") && origin.kind !== "unknown" ? `${origin.label} (sanitized)` : origin.label;
  const browserLabel = [browser.name, browser.version].filter(Boolean).join(" ");
  const label = synthetic
    ? "Demo — synthetic showcase"
    : `${kind}${browserLabel ? ` — ${browserLabel}` : ""}`;

  return {
    raw,
    sourcePath: options.sourcePath,
    session: {
      origin,
      id: raw.session.id,
      label,
      synthetic,
      createdAt: raw.session.startedAt,
      endedAt: raw.session.endedAt,
      chromeVersion: [browser.name, browser.version].filter(Boolean).join(" ") || undefined,
      completeness: {
        state: raw.session.completeness.state,
        reasons: raw.session.completeness.reasons ?? [],
      },
      capture: {
        cdpEvents: counts.sourceEvents ?? 0,
        status: raw.session.completeness.state === "complete" ? "closed" : "partial",
        mode: raw.session.capture?.mode,
        proxy: raw.session.capture?.proxy,
      },
      requests,
      sources: [...sources],
      warnings: sessionWarnings,
      notes: raw.session.notes,
      labels: raw.session.labels ?? [],
      sourcePath: options.sourcePath,
      attachments: options.attachments,
      requestCount: (raw as SessionHeaderV1).requestCount ?? requests.length,
      paged: (raw as SessionHeaderV1).requestCount !== undefined,
    },
  };
}

function typeOf(resourceType: string | undefined): ResourceType {
  const lower = (resourceType ?? "other").toLowerCase() as ResourceType;
  return RESOURCE_TYPES.has(lower) ? lower : "other";
}

/** `list_requests` summary → table row (same rules as `adaptSession`). */
export function summaryFromRaw(
  raw: RawRequestSummary,
  sessionStartedAt: string,
  targets: TargetProvenance[] = [],
): RequestSummary {
  const target = mapTarget(raw.target === undefined ? undefined : targets[raw.target]);
  const primarySource = sourceLabel(raw.source);
  const status = raw.status ?? 0;
  return {
    id: raw.id,
    url: raw.url,
    method: raw.method,
    domain: safeHost(raw.url),
    path: safePath(raw.url),
    status,
    statusText: statusText(status),
    protocol: protocolLabel(raw.protocol),
    networkState: raw.networkState === "not-sent" ? "not-sent" : undefined,
    type: typeOf(raw.resourceType),
    startedAt: raw.wallTime ?? sessionStartedAt,
    durationMs: Math.round(raw.totalMs ?? 0),
    durationApprox: Boolean(raw.estimated) || raw.totalMs === undefined || raw.networkState === "not-sent",
    initiator: initiatorLabel(raw.initiator),
    target,
    links: mapLinks(raw.links),
    netlogOnlyUnknownTarget: !target && primarySource === "netlog",
    primarySource,
    warningCount: raw.warningCount,
  };
}

/** Table row from a full record (in-memory sessions: demo, browser). */
export function summaryOfRecord(r: RequestRecord): RequestSummary {
  return {
    id: r.id,
    url: r.url,
    method: r.method,
    domain: r.domain,
    path: r.path,
    status: r.status,
    statusText: r.statusText,
    protocol: r.protocol,
    networkState: r.networkState,
    type: r.type,
    startedAt: r.startedAt,
    durationMs: r.durationMs,
    durationApprox: r.verification.timings.status === "unverified",
    initiator: r.initiator,
    target: r.target,
    links: r.links,
    netlogOnlyUnknownTarget: r.netlogOnlyUnknownTarget,
    primarySource: r.primarySource,
    warningCount: r.warnings.length,
  };
}

/** `get_request` detail → `RequestRecord`, via the same `adaptSession` (one request). */
export function adaptRequestDetail(
  header: SessionV1,
  detail: RawRequestDetail,
  options: { attachments?: Record<string, string>; sourcePath?: string } = {},
): RequestRecord {
  const mini: SessionV1 = {
    schemaVersion: header.schemaVersion,
    session: header.session,
    requests: [detail.request],
    streamSessions: detail.streamSessions,
    warnings: detail.warnings,
  };
  return adaptSession(mini, options).session.requests[0];
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function safePath(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return url;
  }
}

/** `kind` + initiator url; without it, `undefined` (the UI shows "not stated"). */
export function initiatorLabel(initiator: { kind: string; url?: string } | undefined): string | undefined {
  if (!initiator?.kind) return undefined;
  return initiator.url ? `${initiator.kind} · ${initiator.url}` : initiator.kind;
}

function statusText(status: number): string {
  if (status === 0) return "no status";
  if (status >= 500) return "server error";
  if (status >= 400) return "client error";
  if (status >= 300) return "redirect";
  if (status >= 200) return "success";
  return "informational";
}
