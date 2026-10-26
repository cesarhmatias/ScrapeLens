// Adaptador contrato v1 (docs/03-contratos.md) → modelo de exibição.
// Regra: nada é ordenado nem fundido aqui. Headers seguem pseudo+regulares na
// ordem da fonte; a visão normalizada é derivada na tela e rotulada.

import type {
  AttemptView,
  BodyInfo,
  HeaderPair,
  Protocol,
  ReceivedCookie,
  RedirectHop,
  RequestRecord,
  ResourceType,
  SessionRecord,
  SourceId,
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
  SessionV1,
  Timings,
} from "./types";

const protocolLabel = (p: string): Protocol =>
  p === "h1" ? "HTTP/1.1" : p === "h2" ? "HTTP/2" : p === "h3" ? "HTTP/3" : "desconhecido";

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
    event: p.event ?? p.sourceId ?? "sem nome de evento",
    timestamp: p.wallTime ?? "",
    method: p.method,
    eventRef: p.sourceId,
    notes: p.notes,
  };
}

export function verificationOf(p?: Provenance): Verification {
  if (!p) return { status: "unverified", reason: "sem proveniência registrada pela fonte" };
  if (p.verification === "verified") return { status: "verified", evidence: evidenceOf(p) };
  if (p.verification === "partial") {
    return {
      status: "partial",
      evidence: evidenceOf(p),
      missing: p.notes?.filter(Boolean).join(" · ") || "a fonte preserva parte da informação",
    };
  }
  return {
    status: "unverified",
    reason: p.notes?.filter(Boolean).join(" · ") || p.method || "sem evidência na captura",
  };
}

function weakestVerification(entries: HeaderEntry[], view?: HeaderView): Verification {
  if (entries.length === 0) {
    return {
      status: "unverified",
      reason:
        view?.notes?.filter(Boolean).join(" · ") ||
        "nenhuma linha de header foi observada nesta captura",
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
    return { availability: "unavailable", reason: "corpo não informado pelo contrato" };
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
      name: parsed?.name ?? record.raw.split("=")[0]?.trim() ?? "(sem nome)",
      value: parsed?.value ?? "",
      raw: record.raw,
      attributes,
      parseError: record.parseError,
    };
  });
}

function cookieVerification(request: LogicalRequest): Verification {
  if (request.cookie.pairs.length === 0 && request.cookie.raw.length === 0) {
    return { status: "unverified", reason: "nenhum cookie enviado nesta requisição" };
  }
  return verificationOf(request.cookie.provenance);
}

function timingsVerification(t: Timings, request: LogicalRequest): Verification {
  if (t.estimated) {
    return {
      status: "unverified",
      reason: "duração estimada: a fonte não forneceu evento de conclusão",
    };
  }
  if (t.totalMs === undefined) return { status: "unverified", reason: "sem tempo total na fonte" };
  return {
    status: "partial",
    evidence: evidenceOf(request.provenance),
    missing: "timings não carregam proveniência própria no contrato v1",
  };
}

function protocolVerification(
  request: LogicalRequest,
  streams: Map<string, NonNullable<SessionV1["streamSessions"]>[number]>,
): Verification {
  const attempt = request.attempts[0];
  const stream = attempt ? streams.get(attempt.id) : undefined;
  if (!stream) {
    return {
      status: "partial",
      evidence: evidenceOf(request.provenance),
      missing: "nenhuma StreamSession NetLog associada a esta tentativa",
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

export interface AdaptedSession {
  session: SessionRecord;
  /** Versão v1 para exportações e para o diff sem perda. */
  raw: SessionV1;
  sourcePath?: string;
}

export function adaptSession(
  raw: SessionV1,
  options: { attachments?: Record<string, string>; sourcePath?: string } = {},
): AdaptedSession {
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

    const verification: Record<VerificationKey, Verification> = {
      requestHeaders: weakestVerification(
        [...(request.requestHeaders.pseudoHeaders ?? []), ...request.requestHeaders.headers],
        request.requestHeaders,
      ),
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
          method: "derivação local da UI a partir do original",
        },
        missing: "visão derivada, não transmitida",
      },
      cookies: cookieVerification(request),
      payload: verificationOf(request.requestBody?.provenance),
      responseBody: verificationOf(request.responseBody?.provenance),
      protocol: protocolVerification(request, streams),
      timings: timingsVerification(request.timings, request),
    };

    const rawStatus = statusOf(request);
    const bodyPreview = mapBody(request.responseBody, options.attachments);
    if (isSynthetic && bodyPreview.attachment && !bodyPreview.preview) {
      bodyPreview.reason = bodyPreview.reason ?? "prévia sintética não incluída";
    }

    return {
      id: request.id,
      url: request.url,
      method: request.method,
      domain: safeHost(request.url),
      path: safePath(request.url),
      status: rawStatus,
      statusText: statusText(rawStatus),
      protocol: protocolLabel(request.protocol),
      type: RESOURCE_TYPES.has((request.resourceType ?? "") as ResourceType)
        ? ((request.resourceType ?? "other") as ResourceType)
        : "other",
      startedAt: startedAtOf(request, raw),
      durationMs: durationOf(request),
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
      primarySource: sourceLabel(request.provenance.source),
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
  const label = synthetic
    ? "Demonstração — vitrine sintética"
    : raw.session.capture?.notes?.split("\n")[0] || `Sessão ${raw.session.id}`;

  return {
    raw,
    sourcePath: options.sourcePath,
    session: {
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
      },
      requests,
      sources: [...sources],
      warnings: sessionWarnings,
      notes: raw.session.notes,
      labels: raw.session.labels ?? [],
      sourcePath: options.sourcePath,
      attachments: options.attachments,
    },
  };
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

function statusText(status: number): string {
  if (status === 0) return "sem status";
  if (status >= 500) return "erro do servidor";
  if (status >= 400) return "erro do cliente";
  if (status >= 300) return "redirecionamento";
  if (status >= 200) return "sucesso";
  return "informativo";
}
