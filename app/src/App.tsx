import type { ReactElement } from "react";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import demoRaw from "./demo/session.v1.json";
import demoAttachments from "./demo/attachments.json";
import { resolveCaptureStartUrl, trimUrl, validateHttpUrl } from "./captureUrl";
import {
  bridge,
  isTauri,
  loadLargeDemo,
  type BodyData,
  type ChromeInfo,
  type ListFilter,
  type RequestPageDto,
  type SearchMatch,
  type SearchResultDto,
  type SearchScope,
  type SessionPayload,
  type ValidationResultDto,
} from "./bridge";
import { ExportDialog, SanitizeDialog } from "./Export";
import { matchRanges } from "./highlight";
import { classifyTransforms } from "./transforms";
import { OriginsTab } from "./Origins";
import { CaptureCompareView } from "./CaptureCompare";
import { AdapterViewPanel } from "./AdapterView";
import { TimelineView, ValidationView } from "./Timeline";
import { AppSuccessSection, AssessWarnings, VerdictChip, isAppFailure, isPossibleBlock, useAssess, type OutcomeMap } from "./assess";
import type { CompareSummary } from "./flow";
import { diffCookies, diffHeaders, kindLabel, normalizeHeaders } from "./diff";
import { activeFilterLabels, outcomeChipDisabled, PagedList, sessionIsRecording } from "./listView";
import { adaptRequestDetail, adaptSession, summaryFromRaw, summaryOfRecord, type AdaptedSession } from "./v1/adapter";
import type { SessionV1 } from "./v1/types";
import type {
  BodyInfo,
  HeaderPair,
  Protocol,
  RequestRecord,
  RequestSummary,
  SessionRecord,
  Verification,
  VerificationKey,
} from "./types";
import {
  TARGET_FILTERS,
  attachFailureWarnings,
  captureTargets,
  linkResolutionLabel,
  matchesTargetFilter,
  sessionShowsTargets,
  shortTargetUrl,
  targetBadge,
  targetFilterCount,
  targetKindLabel,
  targetSetupWarnings,
  type TargetFilter,
} from "./target";

/** Página de `list_requests` (máximo do backend). */
const PAGE = 2000;

type View = "session" | "detail" | "compare" | "capture-compare" | "timeline" | "validate";
type Theme = "light" | "dark";
type DetailTab =
  | "headers"
  | "normalized"
  | "cookies"
  | "payload"
  | "response"
  | "origins"
  | "app"
  | "redirects"
  | "attempts"
  | "event";
type TypeFilter = "all" | "fetch" | "document" | "media" | "error";

const params = new URLSearchParams(window.location.search);
const storedTheme = typeof localStorage !== "undefined" ? localStorage.getItem("scrapelens.theme") : null;
const initialTheme: Theme =
  params.get("theme") === "dark" || params.get("theme") === "light"
    ? (params.get("theme") as Theme)
    : storedTheme === "dark" || storedTheme === "light"
      ? (storedTheme as Theme)
      : typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
const initialView: View =
  params.get("view") === "detail" ? "detail" : params.get("view") === "compare" ? "compare" : "session";
const initialTab = (params.get("tab") as DetailTab | null) ?? "headers";
const initialA = params.get("a") ?? "req-0009";
const initialB = params.get("b") ?? "req-0010";

const verificationLabels: Record<VerificationKey, string> = {
  requestHeaders: "Headers da requisição",
  responseHeaders: "Headers da resposta",
  normalizedHeaders: "Visão normalizada",
  cookies: "Cookies",
  payload: "Payload",
  responseBody: "Corpo da resposta",
  protocol: "Protocolo",
  timings: "Tempos",
};

const sourceLabels: Record<string, string> = {
  cdp: "CDP",
  netlog: "NetLog",
  har: "HAR",
  ownFormat: "Formato próprio",
  capture: "Captura",
  derived: "Derivada",
  manual: "Manual",
  session: "Sessão",
};

const typeLabels: Record<string, string> = {
  document: "documento",
  stylesheet: "estilo",
  script: "script",
  xhr: "xhr",
  fetch: "fetch",
  image: "imagem",
  font: "fonte",
  other: "outro",
};

const methodClass: Record<string, string> = {
  GET: "m-get",
  POST: "m-post",
  PUT: "m-put",
  DELETE: "m-del",
};

function fmtTime(iso: string) {
  const t = iso.slice(11, 23);
  return t || iso;
}

function fmtDuration(req: RequestRecord | RequestSummary) {
  const approx = "durationApprox" in req ? req.durationApprox : req.verification.timings.status === "unverified";
  return `${approx ? "≈" : ""}${req.durationMs} ms`;
}

function fmtBytes(n?: number) {
  if (n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1).replace(".", ",")} KiB`;
  return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} MiB`;
}

const fmtStatus = (status: number) => (status === 0 ? "—" : String(status));
const fmtProtocol = (value: Protocol) => (value === "desconhecido" ? "—" : value);

function statusClass(status: number) {
  if (status >= 500) return "s-err";
  if (status >= 400) return "s-warn";
  if (status >= 300) return "s-redir";
  if (status >= 200) return "s-ok";
  return "s-info";
}

function verifyClass(status: Verification["status"]) {
  return status === "verified" ? "v-ok" : status === "partial" ? "v-partial" : "v-none";
}

function verificationTitle(verification: Verification) {
  if (verification.status === "unverified") return verification.reason;
  const evidence = verification.evidence;
  const missing = verification.status === "partial" ? ` · falta: ${verification.missing}` : "";
  return `${sourceLabels[evidence.source] ?? evidence.source} · ${evidence.event} · ${evidence.method}${missing}`;
}

const matchLabels = {
  matched: "correspondida",
  ambiguous: "ambígua",
  unmatched: "sem par",
} as const;

const matchClass = {
  matched: "v-ok",
  ambiguous: "v-partial",
  unmatched: "v-none",
} as const;

const verifyText: Record<Verification["status"], string> = {
  verified: "verificada",
  partial: "parcial",
  unverified: "não verificada",
};

function dupeNames(pairs: HeaderPair[]) {
  const counts = new Map<string, number>();
  for (const p of pairs) counts.set(p.name, (counts.get(p.name) ?? 0) + 1);
  return counts;
}

function HeaderBlock({
  title,
  pairs,
  side,
  verification,
  onCopy,
}: {
  title: string;
  pairs: HeaderPair[];
  side: string;
  verification: Verification;
  onCopy: (value: string, label: string) => void;
}) {
  const dupes = dupeNames(pairs);
  const regular = pairs.filter((p) => p.kind === "regular").length;
  return (
    <section className="header-block">
      <header className="block-head">
        <h3>{title}</h3>
        <span className="block-meta">
          {pairs.length} pares · {regular} regulares · {pairs.length - regular}{" "}
          {pairs.length - regular === 1 ? "pseudoheader" : "pseudoheaders"}
        </span>
        <span className={`chip ${verifyClass(verification.status)}`} title={verificationTitle(verification)}>
          {verifyText[verification.status]}
        </span>
      </header>
      {pairs.length === 0 ? (
        <div className="empty">
          Nenhuma linha observada pela fonte desta captura.
          <br />
          Header ausente não é reconstruído — estado: não verificado.
        </div>
      ) : (
        <ol className="header-list">
          {pairs.map((p) => (
            <li key={`${side}-${p.index}`} className={p.kind === "pseudo" ? "hrow h-pseudo" : "hrow"}>
              <span className="h-idx">{p.index}</span>
              <span className="h-name">{p.name}</span>
              <span className="h-value">{p.value}</span>
              {dupes.get(p.name)! > 1 && (
                <span className="tag tag-dup" title="O mesmo nome aparece mais de uma vez na sequência da fonte">
                  duplicata ×{dupes.get(p.name)}
                </span>
              )}
              <button
                className="icon-btn copy"
                title={`Copiar ${p.name}${p.source ? ` · fonte ${p.source}${p.wallTime ? ` · ${p.wallTime}` : ""}` : ""}`}
                aria-label={`Copiar ${p.name}`}
                onClick={() => onCopy(p.value, p.name)}
              >
                ⧉
              </button>
            </li>
          ))}
        </ol>
      )}
      <footer className="block-foot">
        {pairs.length === 0
          ? "Sem linhas: a fonte não entregou esta lista nesta captura."
          : "Ordem preservada da fonte — nada foi ordenado nem agrupado nesta visão."}
      </footer>
    </section>
  );
}

const scopeLabels: Record<SearchScope, string> = {
  url: "URL",
  requestHeaders: "header (env.)",
  responseHeaders: "header (rec.)",
  cookies: "cookies",
  requestBody: "corpo req.",
  responseBody: "corpo resp.",
};
const ALL_SCOPES = Object.keys(scopeLabels) as SearchScope[];

const PREVIEW_LIMIT = 262_144;
const COPY_LIMIT = 16 * 1024 * 1024;
const MAX_HIGHLIGHTS = 300;

/** Nós React com os trechos dos achados do core realçados (texto escapado). */
function highlightMatches(text: string, matches: SearchMatch[], needle?: string, caseSensitive = false): { nodes: (string | ReactElement)[] | string; shown: number; beyond: number; dashed: number } {
  const { ranges, beyond } = matchRanges(text, matches, needle, caseSensitive);
  const nodes: (string | ReactElement)[] = [];
  let from = 0;
  for (const range of ranges.slice(0, MAX_HIGHLIGHTS)) {
    if (range.start < from || range.end <= range.start) continue; // sobreposto: o anterior já cobre
    if (range.start > from) nodes.push(text.slice(from, range.start));
    nodes.push(
      <mark key={range.start} className={range.decoded ? "decoded" : undefined} title={range.decoded ? "achado na visão decodificada" : "achado da busca"}>
        {text.slice(range.start, range.end)}
      </mark>,
    );
    from = range.end;
  }
  nodes.push(text.slice(from));
  const used = ranges.slice(0, MAX_HIGHLIGHTS);
  return { nodes: nodes.length === 1 ? text : nodes, shown: ranges.length, beyond, dashed: used.filter((range) => range.decoded).length };
}

function OriginTag({ session, long }: { session: SessionRecord; long?: boolean }) {
  const { origin } = session;
  if (origin.kind === "synthetic") return <span className="tag tag-demo">DEMO</span>;
  if (!origin.real) return <span className="tag tag-synthetic" title={origin.label}>{origin.tag}</span>;
  return (
    <span className="tag tag-real" title={origin.label}>
      {long ? `SESSÃO REAL · ${origin.label}` : origin.tag}
    </span>
  );
}

function BodyPanel({
  title,
  body,
  kind,
  onCopy,
  sessionDir,
  matches,
  highlightNeedle,
}: {
  title: string;
  body: BodyInfo;
  kind: "payload" | "response";
  onCopy?: (value: string, label: string) => void;
  sessionDir?: string;
  /** Achados do core para este corpo (mesmo escopo e tentativa). */
  matches?: SearchMatch[];
  highlightNeedle?: { text: string; caseSensitive: boolean };
}) {
  const [data, setData] = useState<BodyData | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  useEffect(() => {
    setData(null);
    setLoadError(null);
    if (!sessionDir || !body.attachment || body.preview) return;
    let alive = true;
    bridge
      .readBody(sessionDir, body.attachment, PREVIEW_LIMIT)
      .then((result) => alive && setData(result))
      .catch((error) => alive && setLoadError(String(error)));
    return () => {
      alive = false;
    };
  }, [sessionDir, body.attachment, body.preview]);

  const transforms = classifyTransforms(body.transformed);
  const text = body.preview ?? (data?.kind === "text" ? data.text : undefined);
  const lit = useMemo(
    () => (text !== undefined && matches?.length ? highlightMatches(text, matches, highlightNeedle?.text, highlightNeedle?.caseSensitive) : { nodes: text ?? "", shown: 0, beyond: 0, dashed: 0 }),
    [text, matches, highlightNeedle?.text, highlightNeedle?.caseSensitive],
  );
  const copyBody = async () => {
    if (body.preview !== undefined) return onCopy?.(body.preview, title);
    if (!sessionDir || !body.attachment) return;
    try {
      const full = await bridge.readBody(sessionDir, body.attachment, COPY_LIMIT);
      if (full.kind !== "text" || full.text === undefined) return;
      onCopy?.(full.text, full.cut ? `${title} (primeiros ${fmtBytes(full.shownBytes)})` : title);
    } catch (error) {
      onCopy?.("", `${title}: ${String(error)}`);
    }
  };
  const flagged =
    body.availability === "truncated" ||
    body.availability === "discarded" ||
    body.availability === "omitted" ||
    body.availability === "unavailable";
  const stateClass =
    body.availability === "available"
      ? "v-ok"
      : body.availability === "truncated"
        ? "v-partial"
        : body.availability === "empty"
          ? "tag"
          : "v-none";
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>{title}</h3>
        <span className="block-meta">
          {body.contentType ?? "tipo desconhecido"} · {fmtBytes(body.decodedSize ?? body.encodedSize)}
          {body.attachment ? <span className="mono"> · {body.attachment}</span> : null}
        </span>
        <span className={`chip ${stateClass}`}>{availabilityLabels[body.availability]}</span>
        {text !== undefined && onCopy && (
          <button className="ghost-btn small" onClick={() => void copyBody()} title="Copiar corpo como texto">
            Copiar corpo
          </button>
        )}
      </header>
      {transforms.warn.length > 0 && (
        <div className="body-flag flag-truncated">
          <strong>Não idêntico aos bytes trafegados</strong>
          <span>Transformações: {[...(transforms.chromeDecoded ? ["chrome-decoded"] : []), ...transforms.warn].join(", ")}</span>
        </div>
      )}
      {flagged && (
        <div className={`body-flag flag-${body.availability}`}>
          <strong>
            {body.availability === "truncated"
              ? `Corpo truncado na captura: ${fmtBytes(body.truncatedAt)} capturados de ${fmtBytes(body.encodedSize)} (originalSize)`
              : body.availability === "discarded"
                ? "Corpo descartado — não recuperável"
                : body.availability === "omitted"
                  ? "Corpo não exibido"
                  : "Corpo indisponível"}
          </strong>
          <span>{body.reason ?? "sem motivo registrado pela fonte"}</span>
        </div>
      )}
      {text !== undefined ? (
        <>
          <pre className="code">{lit.nodes}</pre>
          <div className="body-foot">
            {lit.shown > 0 && lit.nodes !== text ? `${lit.shown} achado(s) da busca realçado(s)${lit.dashed > 0 ? "; realce tracejado = trecho derivado/decodificado, diferente do texto buscado" : ""}. ` : ""}
            {transforms.chromeDecoded && transforms.warn.length === 0 ? "Texto decodificado pelo Chrome. " : ""}
            {lit.beyond > 0 ? `${lit.beyond} achado(s) além da parte exibida. ` : ""}
            {data?.cut ? `Exibindo os primeiros ${fmtBytes(data.shownBytes)} de ${fmtBytes(data.bytes)}; “Copiar corpo” entrega até ${fmtBytes(COPY_LIMIT)}. ` : ""}
            {body.contentType?.includes("html")
              ? "HTML exibido como texto — nunca renderizado como interface."
              : "Texto UTF-8 exibido sem interpretação."}
            {body.captureRef ? <span className="mono dim"> · {body.captureRef}</span> : null}
          </div>
        </>
      ) : data?.kind === "binary" ? (
        <>
          <div className="empty">
            <strong>Conteúdo binário ({fmtBytes(data.bytes)}) — não renderizado.</strong>
            <br />
            Primeiros {data.shownBytes} bytes em hexadecimal:
          </div>
          <pre className="code small hex">{data.hex}</pre>
        </>
      ) : loadError ? (
        <div className="empty">
          <strong>Não foi possível ler o anexo.</strong>
          <br />
          {loadError}
        </div>
      ) : body.attachment && sessionDir && !data ? (
        <div className="empty">Carregando corpo…</div>
      ) : body.availability === "empty" ? (
        <div className="empty">
          <strong>Corpo vazio (0 B).</strong>
          <br />
          {body.reason ?? "A fonte informou que não há corpo nesta mensagem."}
        </div>
      ) : body.availability === "available" ? (
        <div className="empty">
          <strong>Corpo capturado em anexo.</strong>
          <br />
          {body.attachment
            ? `Arquivo: ${body.attachment}. A prévia textual é carregada sob demanda nesta sessão.`
            : "A fonte marcou o corpo como capturado, mas não há anexo associado."}
        </div>
      ) : (
        <div className="empty">Nenhum conteúdo textual disponível para exibir.</div>
      )}
      {kind === "response" &&
        body.encodedSize !== undefined &&
        body.decodedSize !== undefined &&
        body.encodedSize !== body.decodedSize && (
          <div className="body-foot">
            Tamanho na rede {fmtBytes(body.encodedSize)} · decodificado {fmtBytes(body.decodedSize)}
          </div>
        )}
    </section>
  );
}

function BodyContext({ req }: { req: RequestRecord }) {
  const requestContentEncoding = req.requestHeaders.find((h) => h.name.toLowerCase() === "content-encoding")?.value;
  const responseContentEncoding = req.responseHeaders.find((h) => h.name.toLowerCase() === "content-encoding")?.value;
  const verification = (key: VerificationKey) => req.verification[key];
  return (
    <div className="meta-grid">
      <section className="meta-card">
        <h3>Metadados de conteúdo</h3>
        <dl className="kv tight">
          <dt>Tipo</dt>
          <dd>{typeLabels[req.type]} · {req.method} {fmtStatus(req.status)}</dd>
          <dt>Payload</dt>
          <dd className="mono">
            {req.payload.contentType ?? "sem corpo"}
            {requestContentEncoding ? ` · ${requestContentEncoding}` : ""}
          </dd>
          <dt>Resposta</dt>
          <dd className="mono">
            {req.responseBody.contentType ?? "tipo não informado"}
            {responseContentEncoding ? ` · ${responseContentEncoding}` : ""}
          </dd>
          <dt>Tamanho na rede</dt>
          <dd>{fmtBytes(req.payload.encodedSize)} / {fmtBytes(req.responseBody.encodedSize)}</dd>
          <dt>Decodificado</dt>
          <dd>{fmtBytes(req.payload.decodedSize)} / {fmtBytes(req.responseBody.decodedSize)}</dd>
          <dt>Prévia</dt>
          <dd>
            {req.payload.availability === "truncated" || req.responseBody.availability === "truncated"
              ? "parcial (truncada na gravação)"
              : "como registrada pela fonte"}
          </dd>
          <dt>Verificação</dt>
          <dd>
            <span className={`chip ${verifyClass(verification("payload").status)}`}>payload {verifyText[verification("payload").status]}</span>{" "}
            <span className={`chip ${verifyClass(verification("responseBody").status)}`}>resposta {verifyText[verification("responseBody").status]}</span>
          </dd>
        </dl>
      </section>
      <section className="meta-card">
        <h3>Regras de exibição</h3>
        <ul className="rules">
          <li>HTML e JSON capturados aparecem como texto — nunca executados como interface.</li>
          <li>Corpo ausente, truncado ou descartado mostra o motivo; nada é reconstruído.</li>
          <li>Binários não são convertidos em texto: o arquivo fica na pasta da sessão.</li>
          <li>Copiar usa o valor bruto do evento, não o texto abreviado da tabela.</li>
        </ul>
      </section>
    </div>
  );
}

const availabilityLabels: Record<BodyInfo["availability"], string> = {
  available: "disponível",
  empty: "vazio",
  truncated: "truncado",
  discarded: "descartado",
  omitted: "não exibido",
  unavailable: "indisponível",
};

function bodyState(body: BodyInfo) {
  if (body.availability === "unavailable" && body.encodedSize === undefined) return "sem corpo";
  return availabilityLabels[body.availability];
}

function CaptureLimits({
  session,
  requests,
}: {
  session: SessionRecord;
  requests: RequestSummary[];
}) {
  const showTargets = sessionShowsTargets(requests, session.warnings);
  const targets = showTargets ? captureTargets(requests) : [];
  const attachFails = attachFailureWarnings(session.warnings);
  const uniqueFails = [...new Map(attachFails.map((w) => [w.message, w])).values()];
  const setupWarns = targetSetupWarnings(session.warnings);
  const uniqueSetup = [...new Map(setupWarns.map((w) => [w.message, w])).values()];
  return (
    <ul>
      <li>Headers sem evento correspondente aparecem como “não verificada”, nunca como fato.</li>
      <li>Corpo omitido, truncado ou descartado mostra o motivo — nada é reconstruído.</li>
      <li>HTML capturado nunca é executado como interface; o contrato é o v1 do core.</li>
      <li>
        Documento de aba <span className="mono">target=_blank</span> pode vir só do NetLog (sem{" "}
        <span className="mono">requestWillBeSent</span> na sessão filha); a UI marca “alvo desconhecido
        (só NetLog)” e não inventa headers CDP.
      </li>
      {showTargets && targets.length > 0 && (
        <li>
          Alvos acompanhados nesta captura:
          <ul className="limits-targets">
            {targets.map((t) => (
              <li key={`${t.kind}-${t.url}`}>
                <span className="chip tag">{t.kind}</span>{" "}
                <span className="mono">{t.url}</span>
                {t.attached === false ? (
                  <span className="chip v-partial">não anexado</span>
                ) : null}{" "}
                <span className="dim">({t.count} req.)</span>
              </li>
            ))}
          </ul>
        </li>
      )}
      {uniqueFails.length > 0 && (
        <li>
          Falhas ao anexar alvo ({uniqueFails.length}):
          <ul className="limits-targets">
            {uniqueFails.map((w) => (
              <li key={w.message}>
                <span className="chip v-partial">{w.code}</span> {w.message}
              </li>
            ))}
          </ul>
        </li>
      )}
      {uniqueSetup.length > 0 && (
        <li>
          Avisos de configuração de alvo ({uniqueSetup.length}):
          <ul className="limits-targets">
            {uniqueSetup.map((w) => (
              <li key={w.message}>
                <span className="chip v-partial">{w.code}</span> {w.message}
              </li>
            ))}
          </ul>
        </li>
      )}
      <li>
        {session.synthetic
          ? "Sessão sintética: nenhum byte saiu do computador — sem telemetria, sem rede."
          : "Captura local: sem telemetria; os anexos ficam na pasta da sessão."}
      </li>
    </ul>
  );
}

function VerificationPanel({
  req,
  onOpenEvent,
  session,
}: {
  req: RequestRecord;
  onOpenEvent: () => void;
  session: SessionRecord;
}) {
  const keys = Object.keys(verificationLabels) as VerificationKey[];
  return (
    <aside className="side-panel">
      <div className="side-card">
        <h3>Fonte</h3>
        <div className="source-row">
          <span className={`src-chip ${req.primarySource === "cdp" ? "src-cdp" : "src-netlog"}`}>
            {sourceLabels[req.primarySource]} · primária
          </span>
          {session.sources.includes("cdp") && session.sources.includes("netlog") ? (
            <span className="src-chip src-muted">
              {req.primarySource === "cdp" ? "NetLog" : "CDP"} · cruzamento
            </span>
          ) : (
            <span className="src-chip src-muted">fonte única nesta sessão</span>
          )}
        </div>
        <dl className="kv">
          <dt>Requisição</dt>
          <dd className="mono">{req.id}</dd>
          <dt>Início</dt>
          <dd className="mono">{fmtTime(req.startedAt)}</dd>
          <dt>Iniciador</dt>
          <dd>{req.initiator ?? "não informado"}</dd>
          <dt>Sessão</dt>
          <dd>
            <span className="mono">{session.id}</span>{" "}
            <OriginTag session={session} />
          </dd>
        </dl>
      </div>

      <div className="side-card">
        <div className="side-head">
          <h3>Correspondência CDP × NetLog</h3>
          <span className={`chip ${matchClass[req.match.state]}`}>{matchLabels[req.match.state]}</span>
        </div>
        {req.match.state === "ambiguous" ? (
          <>
            <p className="verif-reason">
              Mais de um candidato compatível: nenhuma associação silenciosa. Veja a aba Tentativas.
            </p>
            <ul className="candidate-list">
              {req.match.candidates.map((candidate) => (
                <li key={candidate.entityId} className="mono">
                  {candidate.entityId} · score {candidate.score}
                </li>
              ))}
            </ul>
          </>
        ) : req.match.state === "unmatched" ? (
          <p className="verif-reason">A fonte oposta não registrou esta requisição; nada foi inferido.</p>
        ) : (
          <p className="verif-reason">Chaves explícitas da fonte; a tentativa corresponde à contraparte.</p>
        )}
      </div>

      {req.warnings.length > 0 && (
        <div className="side-card">
          <h3>Avisos desta requisição</h3>
          <ul className="warning-list">
            {req.warnings.map((warning) => (
              <li key={warning.code} className={`warning warning-${warning.severity}`}>
                <span className="mono">{warning.code}</span>
                <span>{warning.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="side-card">
        <div className="side-head">
          <h3>Estado de verificação</h3>
          <span className="hint">por informação</span>
        </div>
        <ul className="verif-list">
          {keys.map((key) => {
            const v = req.verification[key];
            return (
              <li key={key} className="verif-item">
                <div className="verif-top">
                  <span className="verif-name">{verificationLabels[key]}</span>
                  <span className={`chip ${verifyClass(v.status)}`}>{verifyText[v.status]}</span>
                </div>
                {v.status === "unverified" ? (
                  <p className="verif-reason">Sem evidência: {v.reason}</p>
                ) : (
                  <>
                    <p className="verif-evidence mono">
                      {sourceLabels[v.evidence.source]} · {v.evidence.event}
                    </p>
                    <p className="verif-line">
                      {fmtTime(v.evidence.timestamp) ||
                        (v.evidence.sourceTime !== undefined
                          ? `t=${v.evidence.sourceTime.toFixed(3)} s (relógio da fonte)`
                          : "sem horário")}{" "}
                      · {v.evidence.method}
                    </p>
                    {v.status === "partial" && <p className="verif-reason">Falta: {v.missing}</p>}
                  </>
                )}
              </li>
            );
          })}
        </ul>
        <button
          className="ghost-btn wide"
          title="Ver a tabela de eventos brutos que sustentam estes dados"
          onClick={onOpenEvent}
        >
          Ver eventos originais ↗
        </button>
      </div>
    </aside>
  );
}
function DetailView({
  req,
  tab,
  setTab,
  onBack,
  session,
  onCopy,
  onExport,
  onOpenRequest,
  matches,
  needle,
  outcomes,
  limitsRequests,
  assessError,
  assessLoading,
  assessWarnings,
}: {
  outcomes: OutcomeMap;
  limitsRequests: RequestSummary[];
  assessError?: string;
  assessLoading?: boolean;
  assessWarnings?: string[];
  onOpenRequest: (id: string) => void;
  matches: SearchMatch[];
  needle?: { text: string; caseSensitive: boolean };
  req: RequestRecord;
  tab: DetailTab;
  setTab: (t: DetailTab) => void;
  onBack: () => void;
  session: SessionRecord;
  onCopy: (value: string, label: string) => void;
  onExport: () => void;
}) {
  const reqNorm = useMemo(() => normalizeHeaders(req.requestHeaders), [req]);
  const resNorm = useMemo(() => normalizeHeaders(req.responseHeaders), [req]);
  const effectivePayload = req.payload;
  const effectiveResponse = req.responseBody;
  const bodyMatches = (scope: SearchScope, body: BodyInfo) =>
    matches.filter((m) => m.scope === scope && body.attachment?.startsWith(`${m.attemptId}.`));
  const tabs: { id: DetailTab; label: string; count?: number }[] = [
    { id: "headers", label: "Headers brutos", count: req.requestHeaders.length + req.responseHeaders.length },
    { id: "normalized", label: "Normalizado" },
    { id: "cookies", label: "Cookies", count: req.cookiesSent.length + req.cookiesReceived.length },
    { id: "payload", label: "Payload" },
    { id: "response", label: "Resposta" },
    { id: "redirects", label: "Redirects", count: req.redirects.length },
    { id: "attempts", label: "Tentativas", count: req.attempts.length },
    { id: "app", label: "Aplicação" },
    { id: "origins", label: "Origem" },
    { id: "event", label: "Evento" },
  ];

  return (
    <div className="detail">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Sessão
        </button>
        <div className="crumbs">
          <span className="mono">{session.id}</span>
          <span className="sep">/</span>
          <span className="mono">{req.id}</span>
          <OriginTag session={session} />
        </div>
      </div>

      <header className="detail-head">
        <div className="dh-line">
          <span className={`method ${methodClass[req.method] ?? "m-other"}`}>{req.method}</span>
          <span className="dh-path mono">{req.path}</span>
          <span className={`status ${statusClass(req.status)}`}>{req.status}</span>
          <span className="proto">{req.protocol}</span>
          <span className="type">{typeLabels[req.type]}</span>
        </div>
        <div className="dh-sub">
          <span className="mono url">{req.url}</span>
          <button className="ghost-btn small" title="Copiar URL completa" onClick={() => onCopy(req.url, "URL")}>
            Copiar URL
          </button>
          <button
            className="ghost-btn small"
            onClick={onExport}
            disabled={!session.sourcePath}
            title={
              session.sourcePath
                ? "Prévia cURL/Python gerada no Rust; copie ou salve sem executar nada"
                : "Exportação indisponível: esta sessão não tem pasta persistida (demo ou modo navegador)"
            }
          >
            Exportar…
          </button>
          <span className="dot">·</span>
          <span className="mono" title={req.verification.timings.status === "unverified" ? "Tempos não verificados: duração estimada pela UI" : "Duração medida pela fonte"}>
            {fmtDuration(req)}
          </span>
          <span className="dot">·</span>
          <span>{req.domain}</span>
          {(() => {
            const badge = targetBadge(req);
            return badge ? (
              <>
                <span className="dot">·</span>
                <span className="chip tag target-chip" title="Alvo CDP desta requisição">
                  {badge}
                </span>
              </>
            ) : null;
          })()}
        </div>
      </header>

      {(req.target || req.netlogOnlyUnknownTarget || req.links.length > 0) && (
        <section className="target-panel" aria-label="Alvo da requisição">
          <h3>Alvo</h3>
          {req.netlogOnlyUnknownTarget && !req.target ? (
            <p className="notice notice-info">
              <span className="notice-icon">i</span>
              <span>
                Alvo desconhecido (só NetLog): esta requisição não tem proveniência CDP. Documento de aba{" "}
                <span className="mono">target=_blank</span> pode aparecer só no NetLog.
              </span>
            </p>
          ) : null}
          {req.target && (
            <dl className="kv target-kv">
              <dt>Tipo</dt>
              <dd>{targetKindLabel(req.target)}</dd>
              <dt>URL do alvo</dt>
              <dd className="mono">
                {req.target.url ?? (
                  <span className="dim" title={req.url}>
                    não informada no Target.* · requisição {shortTargetUrl(req.url) || req.path}
                  </span>
                )}
              </dd>
              <dt>Aberto por</dt>
              <dd className="mono">{req.target.openerId ?? "— (página principal ou sem opener)"}</dd>
              <dt>Sessão pai</dt>
              <dd className="mono">{req.target.parentSessionId ?? "—"}</dd>
              <dt>targetId</dt>
              <dd className="mono">{req.target.targetId ?? "—"}</dd>
              <dt>Anexado</dt>
              <dd>
                {req.target.attached === true
                  ? "sim"
                  : req.target.attached === false
                    ? "não (fica só com o NetLog)"
                    : "não informado"}
              </dd>
              {req.target.notes.length > 0 && (
                <>
                  <dt>Notas</dt>
                  <dd>
                    <ul className="target-notes">
                      {req.target.notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  </dd>
                </>
              )}
            </dl>
          )}
          {req.links.length > 0 && (
            <div className="target-links">
              <h4>Observações ligadas (service worker)</h4>
              <p className="dim">
                A mesma requisição lógica pode aparecer na página e no service worker. Navegue entre as
                observações; ambiguidade nunca vira duplicata silenciosa.
              </p>
              <ul className="link-list">
                {req.links.map((link) => (
                  <li key={`${link.request}-${link.resolution}`}>
                    <span className={`chip ${link.resolution === "linked" ? "v-ok" : "v-partial"}`}>
                      {linkResolutionLabel(link)}
                    </span>
                    <button
                      type="button"
                      className="link mono"
                      onClick={() => onOpenRequest(link.request)}
                      title="Abrir a outra observação"
                    >
                      {link.request}
                    </button>
                    {link.evidence.length > 0 && (
                      <span className="dim"> · {link.evidence.join(" · ")}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {matches.length > 0 && (
        <section className="match-box" aria-label="Achados da busca">
          <h3>
            Achados da busca <span className="count">{matches.length}</span>
          </h3>
          <ul>
            {matches.slice(0, 50).map((m, index) => {
              const attemptIndex = req.attempts.findIndex((attempt) => attempt.id === m.attemptId);
              return (
                <li key={index}>
                  <span className="chip mono">{scopeLabels[m.scope]}</span>
                  {m.field ? <span className="mono"> {m.field}</span> : null}
                  <span className="dim"> · tentativa {attemptIndex >= 0 ? attemptIndex + 1 : m.attemptId}</span>
                  {m.byteOffset !== null ? <span className="dim"> · byte {m.byteOffset}</span> : null}
                  {m.htmlControl && <span className="chip tag" title="O achado está num controle de formulário HTML (input/textarea/select) da resposta">controle HTML</span>}
                  {m.decoded && <span className="chip v-partial" title="Achado após decodificar form-urlencoded/JSON; o byte bruto pode diferir">visão decodificada</span>}
                  <div className="mono snippet">{m.snippet}</div>
                  {m.decoded && (
                    <div className="dim">
                      Trecho acima é a visão decodificada do campo (derivada); o corpo bruto, exibido na aba Payload/Resposta, é o dado primário.
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          {matches.length > 50 && <p className="dim">+{matches.length - 50} achados não listados aqui.</p>}
        </section>
      )}

      <nav className="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? "tab active" : "tab"}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count !== undefined && <span className="tab-count">{t.count}</span>}
          </button>
        ))}
      </nav>

      <div className="detail-body">
        <div className="detail-main">
          {tab === "headers" && (
            <>
              <div className="seq-banner">
                <span className="tag tag-seq">sequência da fonte</span>
                Índices 0–{Math.max(req.requestHeaders.length - 1, 0)} (requisição) e 0–{Math.max(req.responseHeaders.length - 1, 0)} (resposta).
                Pseudoheaders HTTP/2 aparecem antes dos regulares, como chegaram.
                {req.protocol === "HTTP/1.1" && (
                  <span className="seq-extra">Origem HTTP/1.1: sem pseudoheaders, apenas linhas nominais.</span>
                )}
              </div>
              <HeaderBlock
                title="Headers da requisição"
                pairs={req.requestHeaders}
                side="req"
                verification={req.verification.requestHeaders}
                onCopy={onCopy}
              />
              <HeaderBlock
                title="Headers da resposta"
                pairs={req.responseHeaders}
                side="res"
                verification={req.verification.responseHeaders}
                onCopy={onCopy}
              />
            </>
          )}

          {tab === "normalized" && (
            <>
              <div className="norm-banner">
                <strong>Visão normalizada — não é a sequência transmitida.</strong>
                <span>
                  Derivada localmente: agrupada por nome, em ordem alfabética, duplicatas preservadas e contadas.
                  Use a aba “Headers brutos” para a ordem da fonte.
                </span>
              </div>
              {[
                { title: "Requisição (normalizada)", rows: reqNorm },
                { title: "Resposta (normalizada)", rows: resNorm },
              ].map(({ title, rows }) => (
                <section className="norm-block" key={title}>
                  <header className="block-head">
                    <h3>{title}</h3>
                    <span className="block-meta">{rows.length} nomes únicos</span>
                  </header>
                  <table className="norm-table">
                    <thead>
                      <tr>
                        <th>Nome</th>
                        <th>Valores (na ordem da fonte)</th>
                        <th className="num">Ocorrências</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row) => (
                        <tr key={row.name}>
                          <td className="mono">{row.name}</td>
                          <td className="mono values">
                            {row.values.map((v, i) => (
                              <div key={i} className="val-line">
                                <span className="val-idx">{i + 1}</span>
                                {v}
                              </div>
                            ))}
                          </td>
                          <td className="num">
                            {row.count > 1 ? <span className="tag tag-dup">×{row.count}</span> : row.count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <footer className="block-foot">Visão derivada — estado de verificação: parcial.</footer>
                </section>
              ))}
            </>
          )}

          {tab === "cookies" && (
            <div className="cookies">
              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies enviados</h3>
                  <span className="block-meta">header Cookie parseado · {req.cookiesSent.length} pares</span>
                </header>
                <div className="cookie-grid">
                  {req.cookiesSent.length === 0 && <div className="empty">Nenhum cookie enviado nesta requisição.</div>}
                  {req.cookiesSent.map((c) => (
                    <div className="cookie-card" key={`${c.name}-${c.index}`}>
                      <div className="cookie-name mono">{c.name}</div>
                      <div className="cookie-value mono">{c.value}</div>
                      <div className="cookie-meta">par #{c.index} · ordem do header</div>
                    </div>
                  ))}
                </div>
                <footer className="block-foot">
                  Pares internos preservados; valores longos encurtados aqui para leitura.
                </footer>
              </section>

              {(req.cookieRaw.length > 0 || req.cookieWireLines.length > 0) && (
                <section className="header-block">
                  <header className="block-head">
                    <h3>Cookie enviado — campo bruto e linhas do fio</h3>
                    <span className="block-meta">
                      {req.cookieRaw.length} campo(s) bruto(s) · {req.cookieWireLines.length} linha(s) no fio
                    </span>
                  </header>
                  <div className="cookie-raw">
                    {req.cookieRaw.map((line, index) => (
                      <div key={`raw-${index}`} className="raw-line">
                        <span className="tag">campo bruto</span>
                        <span className="mono">{line}</span>
                      </div>
                    ))}
                    {req.cookieWireLines.map((line, index) => (
                      <div key={`wire-${index}`} className="raw-line">
                        <span className="tag tag-seq">linha do fio</span>
                        <span className="mono">{line}</span>
                      </div>
                    ))}
                  </div>
                  <footer className="block-foot">
                    {req.cookieWireLines.length > req.cookieRaw.length
                      ? "O fio mostra mais linhas Cookie que o campo original — divisão preservada, nada fundido."
                      : "Divisão no fio não observada nesta requisição."}
                    {req.cookieNotes?.length ? ` ${req.cookieNotes.join(" · ")}` : ""}
                  </footer>
                </section>
              )}

              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies recebidos</h3>
                  <span className="block-meta">linhas Set-Cookie separadas · {req.cookiesReceived.length}</span>
                </header>
                {req.cookiesReceived.length === 0 ? (
                  <div className="empty">Nenhum Set-Cookie nesta resposta.</div>
                ) : (
                  <table className="norm-table cookies-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Nome</th>
                        <th>Valor</th>
                        <th>Atributos</th>
                      </tr>
                    </thead>
                    <tbody>
                      {req.cookiesReceived.map((c) => (
                        <tr key={`${c.name}-${c.index}`}>
                          <td className="mono dim">{c.index}</td>
                          <td className="mono">{c.name}</td>
                          <td className="mono">{c.value}</td>
                          <td className="attrs">
                            {c.attributes.map((a, i) => (
                              <span className="attr" key={i}>
                                {a.name}
                                {a.value !== undefined ? `=${a.value}` : ""}
                              </span>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <footer className="block-foot">
                  Linha bruta preservada no evento de origem; a tabela não junta Set-Cookie com “;”.
                </footer>
              </section>

              {req.cookiesReceived.length > 0 && (
                <section className="header-block">
                  <header className="block-head">
                    <h3>Linhas Set-Cookie brutas</h3>
                    <span className="block-meta">como o evento entregou · ordem da fonte</span>
                  </header>
                  <pre className="code small">{req.cookiesReceived.map((c) => c.raw).join("\n")}</pre>
                  <footer className="block-foot">
                    A tabela acima é derivada destas linhas; nenhum atributo é inventado ou reordenado.
                  </footer>
                </section>
              )}
            </div>
          )}

          {tab === "payload" && (
            <>
              <BodyPanel title="Payload da requisição" body={effectivePayload} kind="payload" onCopy={onCopy} sessionDir={session.sourcePath} matches={bodyMatches("requestBody", effectivePayload)} highlightNeedle={needle} />
              <AdapterViewPanel sessionDir={session.sourcePath} requestId={req.id} side="request" />
              <BodyContext req={req} />
              <BodyPanel title="Corpo da resposta (referência)" body={effectiveResponse} kind="response" onCopy={onCopy} sessionDir={session.sourcePath} matches={bodyMatches("responseBody", effectiveResponse)} highlightNeedle={needle} />
            </>
          )}
          {tab === "response" && (
            <>
              <BodyPanel title="Corpo da resposta" body={effectiveResponse} kind="response" onCopy={onCopy} sessionDir={session.sourcePath} matches={bodyMatches("responseBody", effectiveResponse)} highlightNeedle={needle} />
              <AdapterViewPanel sessionDir={session.sourcePath} requestId={req.id} side="response" />
              <BodyContext req={req} />
            </>
          )}

          {tab === "redirects" &&
            (req.redirects.length === 0 ? (
              <div className="empty big">
                <strong>Sem redirects nem tentativas registradas.</strong>
                <span>Nenhum hop nesta requisição; nada a comparar.</span>
              </div>
            ) : (
              <section className="header-block">
                <header className="block-head">
                  <h3>Cadeia de redirects e tentativas</h3>
                  <span className="block-meta">{req.redirects.length} hops</span>
                </header>
                <ol className="hop-list">
                  {req.redirects.map((hop) => (
                    <li className="hop" key={hop.index}>
                      <span className="hop-idx">{hop.index}</span>
                      <span className={`status ${statusClass(hop.status)}`}>{hop.status}</span>
                      <span className="proto">{hop.protocol}</span>
                      <div className="hop-body">
                        <div className="mono">{hop.url}</div>
                        {hop.location && <div className="hop-loc">→ location: <span className="mono">{hop.location}</span></div>}
                      </div>
                    </li>
                  ))}
                </ol>
                <footer className="block-foot">
                  Salto HTTP/1.1 → HTTP/2 registrado como dois hops; cada hop tem evidência própria.
                </footer>
              </section>
            ))}

          {tab === "attempts" &&
            (req.attempts.length === 0 ? (
              <div className="empty big">
                <strong>Nenhuma tentativa registrada.</strong>
                <span>O contrato v1 não trouxe Attempts para esta requisição lógica.</span>
              </div>
            ) : (
              <section className="header-block">
                <header className="block-head">
                  <h3>Tentativas da requisição lógica</h3>
                  <span className="block-meta">
                    {req.attempts.length} tentativa(s) · correlação {matchLabels[req.match.state]}
                  </span>
                </header>
                <table className="norm-table event-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>ID</th>
                      <th>Status</th>
                      <th>Protocolo</th>
                      <th>Resultado</th>
                      <th>Headers (req/res)</th>
                      <th>Correspondência</th>
                    </tr>
                  </thead>
                  <tbody>
                    {req.attempts.map((attempt) => (
                      <tr key={attempt.id}>
                        <td className="mono dim">{attempt.index}</td>
                        <td className="mono">{attempt.id}</td>
                        <td><span className={`status ${statusClass(attempt.status ?? 0)}`}>{fmtStatus(attempt.status ?? 0)}</span></td>
                        <td><span className="proto">{fmtProtocol(attempt.protocol)}</span></td>
                        <td>{attempt.outcome}{attempt.failure ? ` · ${attempt.failure}` : ""}</td>
                        <td className="mono">{attempt.requestHeaderCount} / {attempt.responseHeaderCount}</td>
                        <td>
                          <span className={`chip ${matchClass[attempt.match]}`}>{matchLabels[attempt.match]}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {req.match.state === "ambiguous" && (
                  <div className="body-flag flag-truncated">
                    <strong>Correspondência ambígua — nenhuma fonte foi escolhida</strong>
                    <span>
                      {req.match.candidates.length} candidato(s):{" "}
                      {req.match.candidates
                        .map((candidate) => `${candidate.entityId} (${candidate.score})`)
                        .join(", ")}
                      . O ScrapeLens não associa silenciosamente.
                    </span>
                  </div>
                )}
                <footer className="block-foot">
                  Cada tentativa mantém seus próprios headers, Cookie, corpos e proveniência.
                </footer>
              </section>
            ))}

          {tab === "app" && (
            <AppSuccessSection outcome={outcomes.get(req.id)} error={assessError} loading={assessLoading} warnings={assessWarnings} />
          )}

          {tab === "origins" && (
            <OriginsTab sessionDir={session.sourcePath} requestId={req.id} onOpen={onOpenRequest} verdicts={outcomes} />
          )}

          {tab === "event" && (
            <section className="header-block">
              <header className="block-head">
                <h3>Eventos originais</h3>
                <span className="block-meta">somente leitura · dados sintéticos</span>
              </header>
              <table className="norm-table event-table">
                <thead>
                  <tr>
                    <th>Fonte</th>
                    <th>Evento</th>
                    <th>Timestamp</th>
                    <th>Como foi obtido</th>
                    <th>Ref.</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(req.verification).map(([key, v]) => {
                    if (v.status === "unverified") {
                      return (
                        <tr key={key} className="row-missing">
                          <td>—</td>
                          <td>{verificationLabels[key as VerificationKey]}</td>
                          <td className="dim">sem evento</td>
                          <td className="dim">{v.reason}</td>
                          <td className="dim">—</td>
                        </tr>
                      );
                    }
                    return (
                      <tr key={key}>
                        <td>
                          <span className="src-chip small">{sourceLabels[v.evidence.source]}</span>
                        </td>
                        <td className="mono">{v.evidence.event}</td>
                        <td className="mono">{fmtTime(v.evidence.timestamp)}</td>
                        <td>{v.evidence.method}</td>
                        <td className="mono dim">{v.evidence.eventRef}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <footer className="block-foot">
                O evento bruto é a autoridade; a tabela acima só o referencia.
              </footer>
            </section>
          )}

          <section className="limits-strip">
            <div className="limits-head">
              <OriginTag session={session} long />
              <h3>Limites desta captura</h3>
              <span className="hint">visível em todas as abas</span>
            </div>
            <CaptureLimits session={session} requests={limitsRequests} />
          </section>
        </div>

        <VerificationPanel req={req} onOpenEvent={() => setTab("event")} session={session} />
      </div>
    </div>
  );
}

/** Comparação: o seletor usa os resumos; as duas requisições vêm sob demanda (P5). */
function CompareView(props: {
  aId: string;
  bId: string;
  setA: (id: string) => void;
  setB: (id: string) => void;
  onBack: () => void;
  requests: RequestSummary[];
  session: SessionRecord;
  resolve: (id: string) => Promise<RequestRecord>;
}) {
  const { requests, resolve } = props;
  const aId = requests.some((r) => r.id === props.aId) ? props.aId : requests[0]?.id ?? "";
  const bId = requests.some((r) => r.id === props.bId) ? props.bId : requests[1]?.id ?? "";
  const [pair, setPair] = useState<{ key: string; a?: RequestRecord; b?: RequestRecord; error?: string } | null>(null);
  const key = `${aId}\u0000${bId}`;
  useEffect(() => {
    let alive = true;
    setPair({ key });
    Promise.all([resolve(aId), resolve(bId)])
      .then(([a, b]) => alive && setPair({ key, a, b }))
      .catch((error) => alive && setPair({ key, error: String(error) }));
    return () => {
      alive = false;
    };
  }, [aId, bId, key, resolve]);
  if (pair?.key === key && pair.a && pair.b) {
    return <CompareBody {...props} a={pair.a} b={pair.b} />;
  }
  return (
    <div className="empty big">
      <strong>{pair?.error ? "Não foi possível carregar as requisições." : "Carregando as duas requisições…"}</strong>
      {pair?.error ? <span>{pair.error}</span> : null}
      <button className="link" onClick={props.onBack}>
        Voltar
      </button>
    </div>
  );
}

function CompareBody({
  a,
  b,
  setA,
  setB,
  onBack,
  requests,
  session,
}: {
  a: RequestRecord;
  b: RequestRecord;
  setA: (id: string) => void;
  setB: (id: string) => void;
  onBack: () => void;
  requests: RequestSummary[];
  session: SessionRecord;
}) {
  const headerDiff = useMemo(() => diffHeaders(a.requestHeaders, b.requestHeaders), [a, b]);
  const resDiff = useMemo(() => diffHeaders(a.responseHeaders, b.responseHeaders), [a, b]);
  const cookieDiff = useMemo(() => diffCookies(a.cookiesSent, b.cookiesSent), [a, b]);
  const counts = headerDiff.counts;
  const total = counts.added + counts.removed + counts.changed + counts.reordered;

  const headerRow = (row: (typeof headerDiff.rows)[number]) => (
    <div className={`diff-row k-${row.kind}`} key={row.key}>
      <div className="diff-cell side-a">
        {row.a ? (
          <>
            <span className="pos">{row.a.index}</span>
            <span className="mono dname">{row.a.name}</span>
            <span className="mono dvalue">{row.a.value}</span>
          </>
        ) : (
          <span className="absent">— ausente em A</span>
        )}
      </div>
      <div className="diff-flag">
        <span className={`chip k-${row.kind}`}>{kindLabel[row.kind]}</span>
      </div>
      <div className="diff-cell side-b">
        {row.b ? (
          <>
            <span className="pos">{row.b.index}</span>
            <span className="mono dname">{row.b.name}</span>
            <span className="mono dvalue">{row.b.value}</span>
          </>
        ) : (
          <span className="absent">ausente em B —</span>
        )}
      </div>
    </div>
  );

  const pickerRow = (label: string, value: string, set: (id: string) => void) => (
    <label className="picker">
      <span className="picker-label">{label}</span>
      <select value={value} onChange={(e) => set(e.target.value)}>
        {requests.map((r) => (
          <option key={r.id} value={r.id}>
            {r.id} · {r.method} {r.path} · {r.status}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <div className="compare">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Sessão
        </button>
        <div className="crumbs">
          <span className="mono">{session.id}</span>
          <span className="sep">/</span>
          <span>comparação</span>
          <OriginTag session={session} />
        </div>
      </div>

      <header className="compare-head">
        <div>
          <h2>Comparar duas requisições</h2>
          <p className="sub">
            Lado a lado, na sequência das fontes. Pares repetidos são casados por valor, nunca por posição.
          </p>
        </div>
        <div className="compare-pickers">
          {pickerRow("A", a.id, setA)}
          <span className="vs">vs</span>
          {pickerRow("B", b.id, setB)}
        </div>
      </header>

      <div className="compare-summary">
        <span className="summary-total">{total} diferenças</span>
        <span className="chip k-added">+{counts.added} {counts.added === 1 ? "adicionado" : "adicionados"}</span>
        <span className="chip k-removed">−{counts.removed} {counts.removed === 1 ? "removido" : "removidos"}</span>
        <span className="chip k-changed">~{counts.changed} {counts.changed === 1 ? "alterado" : "alterados"}</span>
        <span className="chip k-reordered">↕{counts.reordered} {counts.reordered === 1 ? "reordenado" : "reordenados"}</span>
        <span className="summary-note">
          {a.protocol === b.protocol ? (
            <>Protocolo igual: <span className="mono">{a.protocol}</span></>
          ) : (
            <>Protocolo difere: <span className="mono">{a.protocol}</span> → <span className="mono">{b.protocol}</span></>
          )}
        </span>
      </div>

      <div className="compare-cols">
        <div className="col-head">
          <div>
            <span className={`method ${methodClass[a.method] ?? "m-other"}`}>{a.method}</span>
            <span className="mono col-url">{a.path}</span>
            <span className={`status ${statusClass(a.status)}`}>{a.status}</span>
          </div>
          <span className="col-meta">{a.id} · {fmtTime(a.startedAt)} · {fmtDuration(a)}</span>
        </div>
        <div className="col-head spacer">
          <span className="hint">diff</span>
        </div>
        <div className="col-head">
          <div>
            <span className={`method ${methodClass[b.method] ?? "m-other"}`}>{b.method}</span>
            <span className="mono col-url">{b.path}</span>
            <span className={`status ${statusClass(b.status)}`}>{b.status}</span>
          </div>
          <span className="col-meta">{b.id} · {fmtTime(b.startedAt)} · {fmtDuration(b)}</span>
        </div>
      </div>

      <section className="diff-section">
        <header className="diff-head">
          <h3>Headers da requisição</h3>
          <span className="block-meta">{a.requestHeaders.length} vs {b.requestHeaders.length} pares · posição original à esquerda</span>
        </header>
        <div className="diff-rows">{headerDiff.rows.map(headerRow)}</div>
      </section>

      {counts.reordered > 0 && (
        <p className="reorder-note">
          <span className="chip k-reordered">reordenado</span> mesmo par nos dois lados, ordem relativa invertida —
          os índices mostram a posição original em cada sequência.
        </p>
      )}

      <section className="diff-section">
        <header className="diff-head">
          <h3>Headers da resposta</h3>
          <span className="block-meta">{resDiff.rows.length} nomes · {resDiff.counts.changed} alterados, {resDiff.counts.added} adicionados, {resDiff.counts.removed} removidos</span>
        </header>
        <div className="diff-rows">{resDiff.rows.map(headerRow)}</div>
      </section>

      <section className="diff-section">
        <header className="diff-head">
          <h3>Cookies enviados</h3>
          <span className="block-meta">casamento por nome e valor</span>
        </header>
        <div className="diff-rows">
          {cookieDiff.map((row) => (
            <div className={`diff-row k-${row.kind}`} key={row.key}>
              <div className="diff-cell side-a">
                {row.a ? (
                  <>
                    <span className="pos">{row.a.index}</span>
                    <span className="mono dname">{row.a.name}</span>
                    <span className="mono dvalue">{row.a.value}</span>
                  </>
                ) : (
                  <span className="absent">— cookie ausente em A</span>
                )}
              </div>
              <div className="diff-flag">
                <span className={`chip k-${row.kind}`}>{kindLabel[row.kind]}</span>
              </div>
              <div className="diff-cell side-b">
                {row.b ? (
                  <>
                    <span className="pos">{row.b.index}</span>
                    <span className="mono dname">{row.b.name}</span>
                    <span className="mono dvalue">{row.b.value}</span>
                  </>
                ) : (
                  <span className="absent">cookie ausente em B —</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="diff-section bodies">
        <header className="diff-head">
          <h3>Corpo e protocolo</h3>
          <span className="block-meta">sem normalização de conteúdo</span>
        </header>
        <div className="body-compare">
          {[
            { r: a, label: "A" },
            { r: b, label: "B" },
          ].map(({ r, label }) => (
            <div className="body-col" key={label}>
              <div className="body-col-head">
                <span className="tag">{label}</span>
                <span className="mono">{r.protocol}</span>
                <span className={`status ${statusClass(r.status)}`}>{r.status}</span>
              </div>
              <dl className="kv tight">
                <dt>Payload</dt>
                <dd>{r.payload.preview ? `${r.payload.preview.length} caracteres` : bodyState(r.payload)}</dd>
                <dt>Resposta</dt>
                <dd>{bodyState(r.responseBody)} · {fmtBytes(r.responseBody.decodedSize ?? r.responseBody.encodedSize)}</dd>
                <dt>Set-Cookie</dt>
                <dd>{r.cookiesReceived.length} linha(s)</dd>
              </dl>
              {r.responseBody.preview ? (
                <pre className="code small">{r.responseBody.preview}</pre>
              ) : (
                <div className="body-flag flag-unavailable">
                  <strong>Sem corpo para comparar</strong>
                  <span>{r.responseBody.reason ?? "a fonte não forneceu prévia"}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [view, setView] = useState<View>(initialView);
  const [query, setQuery] = useState(params.get("q") ?? "");
  const initialFilter = (params.get("filter") as TypeFilter | null) ?? "all";
  const [typeFilter, setTypeFilter] = useState<TypeFilter>(initialFilter);
  const [targetFilter, setTargetFilter] = useState<TargetFilter>("all");
  const [failFilter, setFailFilter] = useState(false);
  const [blockFilter, setBlockFilter] = useState(false);
  const [protocol, setProtocol] = useState<"all" | Protocol>("all");
  const [selectedId, setSelectedId] = useState(params.get("id") ?? "req-0004");
  const [tab, setTab] = useState<DetailTab>(initialTab);
  const [aId, setAId] = useState(initialA);
  const [bId, setBId] = useState(initialB);
  const [loaded, setLoaded] = useState<AdaptedSession>(() =>
    adaptSession(demoRaw as unknown as SessionV1, { attachments: demoAttachments as Record<string, string> }),
  );
  const [notice, setNotice] = useState<{
    kind: "info" | "error" | "success";
    text: string;
    detail?: string;
    action?: "open" | "chrome" | "start";
  } | null>(null);
  const [recording, setRecording] = useState<{
    sessionId: string;
    sessionDir: string;
    startedAt: string;
    events: number;
    pageUrl: string;
    chromePid?: number;
  } | null>(null);
  const [startUrl, setStartUrl] = useState("");
  const [startUrlError, setStartUrlError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [exportTarget, setExportTarget] = useState<RequestRecord | null>(null);
  const [sanitizeOpen, setSanitizeOpen] = useState(false);
  const [sanitizeTraceDir, setSanitizeTraceDir] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ result: ValidationResultDto; tracePath: string; kept?: boolean } | null>(null);
  const [chrome, setChrome] = useState<ChromeInfo | null>(null);
  const [isLargeDemo, setIsLargeDemo] = useState(false);
  const [captureCmp, setCaptureCmp] = useState<{ summary: CompareSummary; dirA: string; dirB: string; labelA: string; labelB: string } | null>(null);
  const [scopes, setScopes] = useState<SearchScope[]>(ALL_SCOPES);
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [searchState, setSearchState] = useState<{
    key: string;
    loading: boolean;
    result?: SearchResultDto;
    error?: string;
  } | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const tableRef = useRef<HTMLDivElement | null>(null);

  const session = loaded.session;
  const desktop = isTauri();
  // P5: sessão paginada → resumos via list_requests e detalhe via get_request;
  // sessão em memória (demonstração, modo navegador) → mesmos resumos derivados localmente.
  const pagedDir = session.paged && session.sourcePath ? session.sourcePath : undefined;
  const memorySummaries = useMemo(() => session.requests.map(summaryOfRecord), [session.requests]);
  const [remoteAll, setRemoteAll] = useState<{ dir: string; items: RequestSummary[]; first?: RequestPageDto } | null>(null);
  // A lista inteira só é varrida quando uma tela precisa dela (detalhe, linha do tempo, comparação);
  // a tela principal usa `PagedList` (páginas visíveis + 1) e as contagens do backend.
  const needFull = Boolean(pagedDir) && (view === "detail" || view === "timeline" || view === "compare");
  useEffect(() => {
    if (!pagedDir) {
      setRemoteAll(null);
      return;
    }
    if (!needFull || remoteAll?.dir === pagedDir) return;
    let alive = true;
    void (async () => {
      const items: RequestSummary[] = [];
      let first: RequestPageDto | undefined;
      try {
        for (let offset = 0; ; offset += PAGE) {
          const page = await bridge.listRequests(pagedDir, offset, PAGE, {});
          if (!alive) return;
          first = first ?? page;
          for (const raw of page.items) items.push(summaryFromRaw(raw, session.createdAt, page.targets));
          if (page.items.length === 0 || offset + PAGE >= page.matched) break;
        }
        if (alive) setRemoteAll({ dir: pagedDir, items, first });
      } catch (error) {
        if (alive) setNotice({ kind: "error", text: "Não foi possível listar as requisições.", detail: String(error) });
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pagedDir, session.createdAt, needFull]);
  const requests: RequestSummary[] = pagedDir
    ? remoteAll?.dir === pagedDir
      ? remoteAll.items
      : []
    : memorySummaries;
  const requestCount = session.requestCount;
  const effectiveId =
    pagedDir && selectedId && !remoteAll
      ? selectedId
      : requests.some((r) => r.id === selectedId)
        ? selectedId
        : requests[0]?.id ?? "";
  const resolveRecord = useCallback(
    async (id: string): Promise<RequestRecord> => {
      if (!pagedDir) {
        const found = session.requests.find((r) => r.id === id);
        if (!found) throw new Error(`requisição ${id} não encontrada`);
        return found;
      }
      const detail = await bridge.getRequest(pagedDir, id);
      return adaptRequestDetail(loaded.raw, detail, { sourcePath: pagedDir, attachments: session.attachments });
    },
    [pagedDir, session.requests, session.attachments, loaded.raw],
  );
  const [remoteDetail, setRemoteDetail] = useState<{ dir: string; id: string; record?: RequestRecord; error?: string } | null>(null);
  useEffect(() => {
    if (!pagedDir || !effectiveId) return;
    let alive = true;
    resolveRecord(effectiveId)
      .then((record) => alive && setRemoteDetail({ dir: pagedDir, id: effectiveId, record }))
      .catch((error) => alive && setRemoteDetail({ dir: pagedDir, id: effectiveId, error: String(error) }));
    return () => {
      alive = false;
    };
  }, [pagedDir, effectiveId, resolveRecord]);
  const selected: RequestRecord | undefined = pagedDir
    ? remoteDetail?.dir === pagedDir && remoteDetail.id === effectiveId
      ? remoteDetail.record
      : undefined
    : session.requests.find((r) => r.id === selectedId) ?? session.requests[0];
  const detailPending = Boolean(pagedDir && effectiveId && !selected);
  const limitsRequests = requests;
  const [listMeta, setListMeta] = useState<RequestPageDto | undefined>(undefined);
  const warningTotal =
    session.warnings.length +
    (pagedDir
      ? listMeta?.warningTotal ?? 0
      : requests.reduce((total, request) => total + request.warningCount, 0));
  const compareCaptures = async () => {
    if (!session.sourcePath) return;
    try {
      const dirB = await bridge.pickCompareSession();
      if (!dirB) return;
      setBusy("Comparando capturas…");
      const summary = await bridge.compareOpen(session.sourcePath, dirB);
      setCaptureCmp({ summary, dirA: session.sourcePath, dirB, labelA: session.label, labelB: dirB.split("/").filter(Boolean).pop() ?? dirB });
      setView("capture-compare");
    } catch (error) {
      setNotice({ kind: "error", text: "Não foi possível comparar as capturas.", detail: String(error) });
    } finally {
      setBusy(null);
    }
  };

  const applyPayload = useCallback((payload: SessionPayload | null) => {
    if (!payload) return;
    setLoaded(
      adaptSession(payload.session, {
        attachments: payload.synthetic ? (demoAttachments as Record<string, string>) : undefined,
        sourcePath: payload.sessionDir,
      }),
    );
    setView("session");
    setQuery("");
    setTypeFilter("all");
    setFailFilter(false);
    setBlockFilter(false);
    setProtocol("all");
    setSelectedId(payload.session.requests?.[0]?.id ?? "");
    setIsLargeDemo(false);
    if (payload.notice) setNotice({ kind: "info", text: payload.notice });
  }, []);

  // Uma abertura/importação por vez (o backend também recusa a segunda).
  const loadingRef = useRef(false);
  const beginLoading = useCallback(() => {
    if (loadingRef.current) {
      setNotice({ kind: "info", text: "Já há uma sessão sendo aberta ou importada. Aguarde terminar." });
      return false;
    }
    loadingRef.current = true;
    return true;
  }, []);
  const endLoading = useCallback(() => {
    loadingRef.current = false;
  }, []);

  const openSession = useCallback(async () => {
    if (!desktop) {
      setNotice({
        kind: "info",
        text: "Abrir captura usa o diálogo nativo do macOS e só existe no app desktop.",
        detail: "Rode `npm run tauri dev` para abrir o shell Tauri.",
      });
      return;
    }
    if (!beginLoading()) return;
    setBusy("Abrindo sessão… (sessões grandes levam alguns segundos)");
    try {
      applyPayload(await bridge.pickAndOpenSession());
    } catch (error) {
      setNotice({ kind: "error", text: "Não foi possível abrir a sessão.", detail: String(error), action: "open" });
    } finally {
      endLoading();
      setBusy(null);
    }
  }, [applyPayload, desktop, beginLoading, endLoading]);

  const validationRef = useRef(validation);
  validationRef.current = validation;
  // Fechar a tela de validação apaga a sessão temporária do trace (a menos que tenha sido guardada).
  const closeValidation = useCallback(() => {
    const current = validationRef.current;
    setView("session");
    setSanitizeTraceDir(null);
    if (current) {
      if (!current.kept) void bridge.discardValidation(current.result.traceDir).catch(() => {});
      setValidation(null);
    }
  }, []);

  const validateExecution = useCallback(async (again?: { tracePath: string; mapOrigin: string }) => {
    if (!desktop || !loaded.session.sourcePath) return;
    const dir = loaded.session.sourcePath;
    try {
      const tracePath = again?.tracePath ?? (await bridge.pickTraceFile());
      if (!tracePath) return;
      setBusy("Importando o trace e validando…");
      const result = await bridge.validateExecution(dir, tracePath, again?.mapOrigin);
      if (validationRef.current && !validationRef.current.kept) void bridge.discardValidation(validationRef.current.result.traceDir).catch(() => {});
      setValidation({ result, tracePath });
      setView("validate");
    } catch (error) {
      setNotice({ kind: "error", text: "Não foi possível validar a execução.", detail: String(error) });
    } finally {
      setBusy(null);
    }
  }, [desktop, loaded.session.sourcePath]);

  const importCapture = useCallback(
    async (kind: "har" | "netlog") => {
      if (!desktop) {
        setNotice({ kind: "info", text: `Importar ${kind.toUpperCase()} só está disponível no app desktop.` });
        return;
      }
      if (recording) {
        setNotice({ kind: "info", text: "Há uma captura em andamento. Encerre a gravação antes de importar." });
        return;
      }
      if (!beginLoading()) return;
      setBusy(kind === "har" ? "Importando HAR…" : "Importando NetLog…");
      try {
        applyPayload(kind === "har" ? await bridge.importHar() : await bridge.importNetlog());
      } catch (error) {
        setNotice({ kind: "error", text: `A importação de ${kind.toUpperCase()} falhou.`, detail: String(error) });
      } finally {
        endLoading();
        setBusy(null);
      }
    },
    [applyPayload, desktop, recording, beginLoading, endLoading],
  );

  const chooseChrome = useCallback(async () => {
    try {
      const info = await bridge.chooseChrome();
      if (info) {
        setChrome(info);
        setNotice({ kind: "success", text: `Chrome configurado: ${info.path ?? "caminho salvo"}` });
      }
    } catch (error) {
      setNotice({ kind: "error", text: "O caminho escolhido não é um Chrome utilizável.", detail: String(error) });
    }
  }, []);

  const startCapture = useCallback(async () => {
    if (!desktop) {
      setNotice({ kind: "info", text: "A captura ao vivo usa o Chrome externo e só existe no app desktop." });
      return;
    }
    const resolved = resolveCaptureStartUrl(startUrl);
    if (!resolved.ok) {
      setStartUrlError(resolved.error);
      setNotice({ kind: "error", text: "URL inicial inválida.", detail: resolved.error, action: "start" });
      return;
    }
    setStartUrlError(null);
    setBusy("Abrindo Chrome com perfil dedicado e conectando ao CDP…");
    try {
      const payload = await bridge.startSession(trimUrl(startUrl) ? trimUrl(startUrl) : undefined);
      if (!payload) return;
      setRecording({
        sessionId: payload.session.session.id,
        sessionDir: payload.sessionDir ?? "",
        startedAt: payload.session.session.startedAt,
        events: 0,
        pageUrl: resolved.url,
      });
      setNotice({ kind: "info", text: payload.notice ?? "Captura iniciada. Navegue no Chrome e clique em Encerrar." });
    } catch (error) {
      const info = await bridge.detectChrome().catch(() => null);
      if (info) setChrome(info);
      setNotice({
        kind: "error",
        text: "Não foi possível iniciar a captura.",
        detail: String(error),
        action: info && !info.found ? "chrome" : "start",
      });
    } finally {
      setBusy(null);
    }
  }, [desktop, startUrl]);

  const stopCapture = useCallback(async () => {
    setBusy("Encerrando o Chrome, aguardando o NetLog e importando a sessão…");
    try {
      const payload = await bridge.stopSession();
      setRecording(null);
      if (payload) applyPayload(payload);
      else setNotice({ kind: "error", text: "A captura terminou sem sessão.", action: "start" });
    } catch (error) {
      setRecording(null);
      setNotice({
        kind: "error",
        text: "Não foi possível encerrar/importar a captura.",
        detail: String(error),
        action: "start",
      });
    } finally {
      setBusy(null);
    }
  }, [applyPayload]);

  const copy = useCallback(async (text: string, label = "Valor copiado") => {
    const ok = await bridge.copyText(text);
    setNotice({
      kind: ok ? "success" : "error",
      text: ok ? `${label} para a área de transferência.` : "Não foi possível copiar.",
    });
    window.setTimeout(() => setNotice((current) => (current?.kind === "success" ? null : current)), 2400);
  }, []);

  useEffect(() => {
    localStorage.setItem("scrapelens.theme", theme);
  }, [theme]);

  useEffect(() => {
    if (!desktop) return;
    void bridge.detectChrome().then(setChrome).catch(() => setChrome({ found: false, candidates: [] }));
    void bridge.appInfo().catch(() => null);
    void bridge.captureStartUrl().then((url) => {
      setStartUrl(url);
      if (url.trim()) {
        const check = validateHttpUrl(url);
        setStartUrlError(check.ok ? null : check.error);
      }
    });
  }, [desktop]);

  useEffect(() => {
    if (!desktop) return;
    let cancelled = false;
    void (async () => {
      try {
        const action = await bridge.takeCliAction();
        if (cancelled || !action) return;
        if (action.kind === "error" || action.kind === "warning") {
          setNotice({
            kind: action.kind === "error" ? "error" : "info",
            text: action.kind === "error" ? "Argumento de linha de comando inválido." : "Argumentos de linha de comando ignorados.",
            detail: action.message,
          });
          return;
        }
        setBusy(
          action.kind === "import-har"
            ? "Importando HAR (CLI)…"
            : action.kind === "import-netlog"
              ? "Importando NetLog (CLI)…"
              : "Abrindo captura (CLI)…",
        );
        const payload =
          action.kind === "import-har"
            ? await bridge.importHarAt(action.path)
            : action.kind === "import-netlog"
              ? await bridge.importNetlogAt(action.path)
              : await bridge.openSessionAt(action.path);
        if (!cancelled) applyPayload(payload);
      } catch (error) {
        if (!cancelled) {
          setNotice({ kind: "error", text: "Falha no argumento CLI de abertura.", detail: String(error) });
        }
      } finally {
        if (!cancelled) setBusy(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [applyPayload, desktop]);

  useEffect(() => {
    if (params.get("demo") !== "large") return;
    void loadLargeDemo()
      .then((payload) => {
        setLoaded(adaptSession(payload.session, {}));
        setIsLargeDemo(true);
        setNotice({ kind: "info", text: payload.notice ?? "Sessão sintética de estresse." });
      })
      .catch((error) => setNotice({ kind: "error", text: "Falha ao gerar a sessão de estresse.", detail: String(error) }));
  }, []);

  useEffect(() => {
    let dispose = () => {};
    void bridge
      .onMenu((action) => {
        if (action === "open") void openSession();
        else if (action === "import-har") void importCapture("har");
        else if (action === "import-netlog") void importCapture("netlog");
        else if (action === "start-session") void startCapture();
        else if (action === "stop-session") void stopCapture();
        else if (action === "choose-chrome") void chooseChrome();
        else if (action === "find") {
          setView("session");
          window.setTimeout(() => searchRef.current?.focus(), 60);
        } else if (action === "copy" && selected) void copy(selected.url, "URL");
        else if (action === "demo") void bridge.demoSession().then(applyPayload);
        else if (action === "theme") setTheme((current) => (current === "light" ? "dark" : "light"));
      })
      .then((fn) => {
        dispose = fn;
      });
    return () => dispose();
  }, [applyPayload, chooseChrome, copy, importCapture, openSession, selected, startCapture, stopCapture]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const meta = event.metaKey || event.ctrlKey;
      if (!meta) return;
      const key = event.key.toLowerCase();
      if (key === "f") {
        event.preventDefault();
        setView("session");
        window.setTimeout(() => {
          searchRef.current?.focus();
          searchRef.current?.select();
        }, 60);
      } else if (key === "o") {
        event.preventDefault();
        void openSession();
      } else if (key === "c") {
        const target = event.target as HTMLElement | null;
        const typing =
          target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable === true;
        const hasSelection = (window.getSelection()?.toString() ?? "").length > 0;
        if (!typing && !hasSelection && selected) {
          event.preventDefault();
          void copy(selected.url, "URL da requisição");
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [copy, openSession, selected]);

  useEffect(() => {
    if (!recording || !desktop) return;
    const interval = window.setInterval(() => {
      void bridge
        .captureStatus()
        .then((status) => {
          if (!status) {
            setRecording(null);
            return;
          }
          setRecording((current) =>
            current
              ? {
                  ...current,
                  events: status.events,
                  chromePid: status.chromePid,
                  pageUrl: status.pageUrl,
                }
              : current,
          );
        })
        .catch(() => {});
    }, 900);
    return () => window.clearInterval(interval);
  }, [recording?.sessionId, desktop]);

  const searchDir = desktop ? session.sourcePath : undefined;
  const assess = useAssess(searchDir);
  const outcomes = assess.map;
  const searchText = query.trim();
  const searchKey = searchDir && searchText ? JSON.stringify([searchDir, searchText, scopes, caseSensitive]) : "";
  useEffect(() => {
    if (!searchKey || !searchDir) {
      setSearchState(null);
      return;
    }
    setSearchState({ key: searchKey, loading: true });
    let alive = true;
    const timer = window.setTimeout(() => {
      bridge
        .searchSession(searchDir, searchText, scopes, caseSensitive)
        .then((result) => alive && setSearchState({ key: searchKey, loading: false, result }))
        .catch((error) => alive && setSearchState({ key: searchKey, loading: false, error: String(error) }));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [searchKey, searchDir, searchText, scopes, caseSensitive]);
  const searchResult = searchState?.key === searchKey ? searchState.result : undefined;
  const matchesById = useMemo(() => {
    const map = new Map<string, SearchMatch[]>();
    for (const match of searchResult?.matches ?? []) {
      const list = map.get(match.requestId);
      if (list) list.push(match);
      else map.set(match.requestId, [match]);
    }
    return map;
  }, [searchResult]);
  const payloadSearch = Boolean(searchKey);

  const showTargetColumn = useMemo(
    () =>
      pagedDir
        ? Boolean(listMeta?.hasTargets) || sessionShowsTargets([], session.warnings)
        : sessionShowsTargets(requests, session.warnings),
    [pagedDir, listMeta, requests, session.warnings],
  );

  const localFiltered = useMemo(() => {
    if (pagedDir) return [];
    const q = query.trim().toLowerCase();
    return requests.filter((r) => {
      if (typeFilter === "fetch" && !(r.type === "fetch" || r.type === "xhr")) return false;
      if (typeFilter === "document" && r.type !== "document") return false;
      if (typeFilter === "media" && !(r.type === "image" || r.type === "font")) return false;
      if (typeFilter === "error" && r.status < 400) return false;
      if (showTargetColumn && !matchesTargetFilter(r, targetFilter)) return false;
      if (failFilter || blockFilter) {
        const o = outcomes.get(r.id);
        if (!((failFilter && isAppFailure(o)) || (blockFilter && isPossibleBlock(o)))) return false;
      }
      if (protocol !== "all" && r.protocol !== protocol) return false;
      if (!q) return true;
      if (payloadSearch) {
        // Busca do core: só as requisições com achado (id/método/status continuam valendo).
        return (
          matchesById.has(r.id) ||
          r.id.includes(q) ||
          r.method.toLowerCase() === q ||
          String(r.status).includes(q)
        );
      }
      return (
        r.url.toLowerCase().includes(q) ||
        r.id.includes(q) ||
        r.method.toLowerCase() === q ||
        String(r.status).includes(q)
      );
    });
  }, [
    pagedDir,
    requests,
    query,
    typeFilter,
    targetFilter,
    showTargetColumn,
    failFilter,
    blockFilter,
    protocol,
    payloadSearch,
    matchesById,
    outcomes,
  ]);

  // Filtro no backend (P5): mesma semântica de `localFiltered`, em src-tauri/src/listing.rs.
  const remoteFilter = useMemo<ListFilter>(() => {
    const restrict =
      failFilter || blockFilter
        ? [...outcomes.entries()]
            .filter(([, o]) => (failFilter && isAppFailure(o)) || (blockFilter && isPossibleBlock(o)))
            .map(([id]) => id)
        : null;
    return {
      typeFilter,
      protocol,
      target: targetFilter,
      query,
      payloadSearch,
      matchIds: payloadSearch ? [...matchesById.keys()] : [],
      restrictIds: restrict,
    };
  }, [typeFilter, protocol, targetFilter, query, payloadSearch, matchesById, failFilter, blockFilter, outcomes]);
  const remoteKey = pagedDir ? `${pagedDir}\u0000${JSON.stringify(remoteFilter)}` : "";
  const remoteFilterRef = useRef(remoteFilter);
  remoteFilterRef.current = remoteFilter;
  const [, bumpList] = useReducer((n: number) => n + 1, 0);
  // Uma `PagedList` por (sessão, filtro): troca só quando a chave muda, não a cada render.
  const pagedList = useMemo(() => {
    if (!pagedDir) return null;
    const filter = remoteFilterRef.current;
    const createdAt = session.createdAt;
    return new PagedList<RequestSummary, RequestPageDto>(
      async (offset, limit) => {
        const page = await bridge.listRequests(pagedDir, offset, limit, filter);
        return { meta: page, rows: page.items.map((raw) => summaryFromRaw(raw, createdAt, page.targets)) };
      },
      PAGE,
      bumpList,
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remoteKey]);
  useEffect(() => () => pagedList?.dispose(), [pagedList]);
  useEffect(() => {
    if (pagedList?.meta) setListMeta(pagedList.meta);
  });
  useEffect(() => {
    if (pagedList?.error) setNotice({ kind: "error", text: "Falha ao listar as requisições.", detail: pagedList.error });
  }, [pagedList, pagedList?.error]);
  useEffect(() => {
    if (!pagedDir) setListMeta(undefined);
  }, [pagedDir]);
  const filteredLength = pagedList ? pagedList.length : localFiltered.length;
  const rowAt = (index: number): RequestSummary | undefined =>
    pagedList ? pagedList.row(index) : localFiltered[index];

  const remoteCounts = pagedDir ? listMeta?.counts : undefined;
  const counts = remoteCounts ?? {
    all: requests.length,
    fetch: requests.filter((r) => r.type === "fetch" || r.type === "xhr").length,
    document: requests.filter((r) => r.type === "document").length,
    media: requests.filter((r) => r.type === "image" || r.type === "font").length,
    error: requests.filter((r) => r.status >= 400).length,
  };
  const targetCount = (id: TargetFilter) =>
    pagedDir ? listMeta?.targetCounts?.[id] ?? 0 : targetFilterCount(requests, id);
  const failCount = pagedDir
    ? [...outcomes.values()].filter((o) => isAppFailure(o)).length
    : requests.filter((r) => isAppFailure(outcomes.get(r.id))).length;
  const blockCount = pagedDir
    ? [...outcomes.values()].filter((o) => isPossibleBlock(o)).length
    : requests.filter((r) => isPossibleBlock(outcomes.get(r.id))).length;

  const ROW_HEIGHT = 34;
  const OVERSCAN = 6;
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(720);

  useEffect(() => {
    const element = tableRef.current;
    if (!element) return;
    const update = () => setViewportH(element.clientHeight || 720);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, [view]);

  useEffect(() => {
    setScrollTop(0);
    if (tableRef.current) tableRef.current.scrollTop = 0;
  }, [query, typeFilter, targetFilter, failFilter, blockFilter, protocol]);

  const colCount = showTargetColumn ? 10 : 9;

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(filteredLength, Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN);
  // Na sessão paginada, pede só a janela visível (+1 página); linhas ainda não chegadas ficam de fora.
  pagedList?.ensure(startIndex, Math.max(endIndex, Math.ceil(viewportH / ROW_HEIGHT) + OVERSCAN));
  const visibleRows: RequestSummary[] = [];
  for (let i = startIndex; i < endIndex; i++) {
    const row = rowAt(i);
    if (row) visibleRows.push(row);
  }

  const openDetail = (id: string) => {
    setSelectedId(id);
    setTab("headers");
    setView("detail");
  };

  return (
    <div className="app" data-theme={theme}>
      <div className="window">
        <div className="titlebar">
          <div className="traffic">
            <span className="tl close" />
            <span className="tl min" />
            <span className="tl max" />
          </div>
          <div className="title">
            ScrapeLens
            <span className="title-sep">—</span>
            <span className="title-sub">
              {session.synthetic ? "sessão de demonstração" : session.label}
            </span>
          </div>
          <div className="title-actions">
            <OriginTag session={session} />
            <span className="tag tag-synthetic">{desktop ? "Tauri 2" : "modo navegador"}</span>
            <button
              className="icon-btn theme"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              title={`Tema ${theme === "light" ? "claro" : "escuro"} — alternar`}
            >
              {theme === "light" ? "◐" : "◑"}
            </button>
          </div>
        </div>

        {session.synthetic ? (
          <div className="demo-banner">
            <span className="demo-badge">DEMO</span>
            <p>
              {session.sourcePath ? (
                <>
                  <strong>Fixture sintética:</strong> valores inventados com a forma de um caso real; nada foi
                  capturado. Para capturar de verdade, use Iniciar sessão (Chrome externo) ou Abrir captura.
                </>
              ) : (
                <>
                  <strong>Sessão sintética (contrato v1).</strong> Nenhum byte foi capturado: domínios{" "}
                  <span className="mono">.invalid</span>, corpos inventados e eventos simulados servem para revisar a
                  interface. Para capturar de verdade, use Iniciar sessão (Chrome externo) ou Abrir captura.
                </>
              )}
            </p>
            <span className="demo-right mono">sem telemetria</span>
          </div>
        ) : (
          <div className="real-banner">
            <OriginTag session={session} long />
            <p>
              <strong>{session.label}</strong> · {session.completeness.state === "complete" ? "completa" : "parcial"}
              {session.sourcePath ? <> · <span className="mono">{session.sourcePath}</span></> : null}
            </p>
            <span className="demo-right mono">{warningTotal} aviso(s)</span>
          </div>
        )}

        {view === "session" && (
          <>
            {session.warnings
              .filter((warning) => warning.code === "har.cookies_absent")
              .map((warning) => (
                <div className="body-flag flag-truncated warn-strip" role="alert" key={warning.code}>
                  <strong>HAR sem cookies — origem de cookies não avaliável</strong>
                  <span>
                    {warning.message} Para avaliar cookies, use <strong>Iniciar sessão</strong> (captura ao vivo CDP/NetLog).
                  </span>
                </div>
              ))}
            <div className="session-bar">
              <div className="session-id">
                <div className="sid-top">
                  <span className="dot-live" />
                  <span className="sid-label">{session.label}</span>
                  <OriginTag session={session} />
                  {sessionIsRecording(session, recording) ? (
                    <span className="tag tag-recording">
                      <span className="rec-dot" /> gravando
                    </span>
                  ) : (
                    <span className="tag tag-state">
                      {session.completeness.state === "complete" ? "sessão completa" : "sessão parcial"}
                    </span>
                  )}
                  {isLargeDemo && <span className="tag">estresse 12k</span>}
                </div>
                <div className="sid-meta mono">
                  {session.id} · {session.chromeVersion ?? "navegador não informado"} · criada{" "}
                  {fmtTime(session.createdAt)} · {requestCount} requisições ·{" "}
                  {session.capture.mode ?? "modo não informado"}
                </div>
              </div>
              <div className="session-actions">
                <label className="start-url-field" htmlFor="scrapelens-start-url">
                  <span className="start-url-label">URL inicial</span>
                  <input
                    id="scrapelens-start-url"
                    className="start-url-input mono"
                    type="url"
                    inputMode="url"
                    placeholder="http://127.0.0.1:8781/page"
                    value={startUrl}
                    disabled={!desktop || !!recording || !!busy}
                    aria-label="URL inicial da captura"
                    aria-invalid={!!startUrlError}
                    onChange={(event) => {
                      const value = event.target.value;
                      setStartUrl(value);
                      if (!trimUrl(value)) {
                        setStartUrlError(null);
                        return;
                      }
                      const check = validateHttpUrl(value);
                      setStartUrlError(check.ok ? null : check.error);
                    }}
                    onBlur={() => {
                      if (!desktop) return;
                      const normalized = trimUrl(startUrl);
                      if (normalized !== startUrl) setStartUrl(normalized);
                      void bridge.setCaptureStartUrl(normalized).catch((error) => {
                        setStartUrlError(String(error));
                      });
                    }}
                  />
                  {startUrlError ? <span className="start-url-error">{startUrlError}</span> : null}
                </label>
                <button
                  id="scrapelens-start-session"
                  className="btn primary"
                  onClick={() => void startCapture()}
                  disabled={!desktop || !!recording || !!busy || !!startUrlError}
                  aria-label="Iniciar sessão"
                  title={
                    desktop
                      ? "Abrir Chrome com perfil dedicado e gravar CDP+NetLog — ⌘⇧R"
                      : "Captura ao vivo só no app desktop (Tauri)"
                  }
                >
                  Iniciar sessão
                </button>
                <button
                  id="scrapelens-stop-session"
                  className="btn"
                  onClick={() => void stopCapture()}
                  disabled={!recording || !!busy}
                  aria-label="Encerrar sessão"
                  title="Sair do Chrome, aguardar o flush do NetLog, importar com o core e abrir a sessão — ⌘."
                >
                  Encerrar
                </button>
                <button
                  id="scrapelens-open-capture"
                  className="btn"
                  onClick={() => void openSession()}
                  disabled={!desktop || !!recording}
                  aria-label="Abrir captura"
                  title={
                    desktop
                      ? "Abrir uma pasta de sessão v1 (session.json) com diálogo nativo — ⌘O"
                      : "Abrir captura usa o diálogo nativo do macOS; disponível no app Tauri."
                  }
                >
                  Abrir captura…
                </button>
                <button
                  className="btn"
                  onClick={() => setSanitizeOpen(true)}
                  disabled={!desktop || !session.sourcePath || !!recording || !!busy}
                  title={
                    !desktop
                      ? "Sanitização usa o diálogo nativo do macOS e só existe no app desktop."
                      : !session.sourcePath
                        ? "Sanitização indisponível: esta sessão não tem pasta persistida (demo ou modo navegador)."
                        : "Redigir credenciais da sessão inteira e gravar em uma pasta nova; a origem não é alterada"
                  }
                >
                  Sanitizar…
                </button>
                <button
                  className="btn"
                  onClick={() => setView("timeline")}
                  disabled={!session.sourcePath || !!recording || !!busy}
                  title={session.sourcePath ? "Eventos da aplicação na ordem, sem o ruído da proteção" : "Linha do tempo indisponível: esta sessão não tem pasta persistida."}
                >
                  Linha do tempo
                </button>
                <button
                  className="btn"
                  onClick={() => void validateExecution()}
                  disabled={!desktop || !session.sourcePath || !!recording || !!busy}
                  title={
                    !desktop
                      ? "Validar execução usa o seletor nativo do macOS e só existe no app desktop."
                      : "Importa o trace do script (--trace) e compara a execução com esta captura; nada é executado pelo ScrapeLens"
                  }
                >
                  Validar execução…
                </button>
              </div>
            </div>

            {recording && (
              <div className="recording-banner" id="scrapelens-recording-banner">
                <span className="rec-dot" />
                <strong>Gravando com Chrome externo</strong>
                <span>
                  sessão <span className="mono">{recording.sessionId}</span> · {recording.events} evento(s) CDP
                  {recording.pageUrl ? (
                    <span className="mono dim"> · {recording.pageUrl}</span>
                  ) : null}
                </span>
                {(!recording.pageUrl || recording.pageUrl === "about:blank") && (
                  <span className="recording-blank-warn" role="status">
                    a captura começou em branco; navegue no Chrome ou informe a URL
                  </span>
                )}
                <span className="grow" />
                <button
                  id="scrapelens-stop-recording"
                  className="ghost-btn small"
                  onClick={() => void stopCapture()}
                  disabled={!!busy}
                  aria-label="Encerrar e abrir"
                >
                  Encerrar e abrir
                </button>
              </div>
            )}

            {notice && (
              <div className={`notice notice-${notice.kind}`}>
                <span className="notice-icon">{notice.kind === "error" ? "!" : notice.kind === "success" ? "✓" : "i"}</span>
                <span>
                  <strong>{notice.text}</strong>
                  {notice.detail && <span className="notice-detail mono"> {notice.detail}</span>}
                </span>
                {notice.action === "chrome" && desktop && (
                  <button className="ghost-btn small" onClick={() => void chooseChrome()}>
                    Selecionar Chrome…
                  </button>
                )}
                {notice.action === "open" && desktop && (
                  <button className="ghost-btn small" onClick={() => void openSession()}>
                    Escolher outro…
                  </button>
                )}
                {notice.action === "start" && desktop && (
                  <button className="ghost-btn small" onClick={() => void startCapture()}>
                    Tentar de novo
                  </button>
                )}
                <button className="icon-btn" onClick={() => setNotice(null)} title="Fechar aviso">
                  ×
                </button>
              </div>
            )}

            {busy && (
              <div className="notice notice-info" role="status" aria-live="polite">
                <span className="notice-icon">…</span>
                <span>{busy}</span>
              </div>
            )}

            {!busy && pagedList && !pagedList.meta && requestCount > 0 && (
              <div className="notice notice-info" role="status" aria-live="polite">
                <span className="notice-icon">…</span>
                <span>Carregando a lista de {requestCount} requisições…</span>
              </div>
            )}

            {desktop && chrome && !chrome.found && (
              <div className="notice notice-warn">
                <span className="notice-icon">!</span>
                <span>
                  <strong>Chrome não encontrado</strong> em /Applications. A captura precisa de um Chrome externo —
                  selecione manualmente o <span className="mono">Google Chrome.app</span>.
                </span>
                <button className="ghost-btn small" onClick={() => void chooseChrome()}>
                  Selecionar Chrome…
                </button>
              </div>
            )}

            <div className="toolbar">
              <div className="search">
                <span className="search-icon">⌕</span>
                <input
                  ref={searchRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Buscar domínio, caminho, id, status…"
                  aria-label="Buscar requisições"
                />
                <kbd>⌘F</kbd>
              </div>
              {searchDir && (
                <div className="search-opts" role="group" aria-label="Escopos da busca">
                  {ALL_SCOPES.map((scope) => (
                    <label key={scope} className={scopes.includes(scope) ? "chip-filter active" : "chip-filter"}>
                      <input
                        type="checkbox"
                        checked={scopes.includes(scope)}
                        onChange={(e) =>
                          setScopes((current) =>
                            e.target.checked
                              ? [...current, scope]
                              : current.length > 1
                                ? current.filter((item) => item !== scope)
                                : current,
                          )
                        }
                      />
                      {scopeLabels[scope]}
                    </label>
                  ))}
                  <label className={caseSensitive ? "chip-filter active" : "chip-filter"}>
                    <input type="checkbox" checked={caseSensitive} onChange={(e) => setCaseSensitive(e.target.checked)} />
                    Aa
                  </label>
                </div>
              )}
              <AssessWarnings warnings={assess.result?.warnings} />
              <div className="filters">
                {(
                  [
                    ["all", "Todos"],
                    ["fetch", "Fetch/XHR"],
                    ["document", "Documento"],
                    ["media", "Mídia"],
                    ["error", "Erros 4xx/5xx"],
                  ] as [TypeFilter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    className={typeFilter === id ? "chip-filter active" : "chip-filter"}
                    onClick={() => setTypeFilter(id)}
                  >
                    {label}
                    <span className="count">{counts[id]}</span>
                  </button>
                ))}
                <button
                  className={failFilter ? "chip-filter active" : "chip-filter"}
                  disabled={outcomeChipDisabled(failCount, failFilter)}
                  onClick={() => setFailFilter((v) => !v)}
                  title="Respostas com falha da aplicação afirmada (app-error), mesmo com HTTP 200"
                >
                  Falhas da aplicação
                  <span className="count">{failCount}</span>
                </button>
                <button
                  className={blockFilter ? "chip-filter active" : "chip-filter"}
                  disabled={outcomeChipDisabled(blockCount, blockFilter)}
                  onClick={() => setBlockFilter((v) => !v)}
                  title="Possíveis bloqueios (blocked?): evidência, não confirmação"
                >
                  Possíveis bloqueios?
                  <span className="count">{blockCount}</span>
                </button>
              </div>
              {showTargetColumn && (
                <div className="filters target-filters" aria-label="Filtro por tipo de alvo">
                  {TARGET_FILTERS.filter(
                    (f) => f.id === "all" || targetCount(f.id) > 0,
                  ).map((f) => (
                    <button
                      key={f.id}
                      className={targetFilter === f.id ? "chip-filter active" : "chip-filter"}
                      onClick={() => setTargetFilter(f.id)}
                      title="Filtrar pela proveniência do alvo CDP"
                    >
                      {f.label}
                      <span className="count">{targetCount(f.id)}</span>
                    </button>
                  ))}
                </div>
              )}
              <label className="proto-select">
                <span>Protocolo</span>
                <select value={protocol} onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
                  <option value="all">todos</option>
                  <option value="HTTP/1.1">HTTP/1.1</option>
                  <option value="HTTP/2">HTTP/2</option>
                  <option value="HTTP/3">HTTP/3</option>
                  <option value="desconhecido">desconhecido</option>
                </select>
              </label>
              <div className="toolbar-actions">
                <button
                  id="scrapelens-import-har"
                  className="btn small"
                  onClick={() => void importCapture("har")}
                  disabled={!desktop || !!recording}
                  aria-label="Importar HAR"
                  title={desktop ? "Importar HAR — ⌘⇧H" : "Importação só no app desktop"}
                >
                  HAR
                </button>
                <button
                  id="scrapelens-import-netlog"
                  className="btn small"
                  onClick={() => void importCapture("netlog")}
                  disabled={!desktop || !!recording}
                  aria-label="Importar NetLog"
                  title={desktop ? "Importar NetLog — ⌘⇧N" : "Importação só no app desktop"}
                >
                  NetLog
                </button>
                <button
                  className="btn"
                  onClick={() => setView("compare")}
                  disabled={requestCount < 2}
                  title={requestCount < 2 ? "São necessárias duas requisições" : "Comparar duas requisições"}
                >
                  Comparar…
                </button>
                <button
                  className="btn"
                  onClick={() => void compareCaptures()}
                  disabled={!desktop || !session.sourcePath || !!recording}
                  title={session.sourcePath ? "Comparar esta captura com outra sessão (pasta)" : "Exige uma sessão com pasta persistida"}
                >
                  Comparar capturas…
                </button>
              </div>
            </div>

            {searchText && (
              <div className="search-status" role="status">
                {!searchDir ? (
                  <span>Busca só em metadados (URL, id, status): a busca no payload exige uma sessão real aberta no app.</span>
                ) : !searchResult && !searchState?.error ? (
                  <span>Buscando no payload…</span>
                ) : searchState?.error ? (
                  <span className="err">Busca falhou: {searchState.error}</span>
                ) : searchResult ? (
                  <>
                    <span>
                      {searchResult.matches.length} achado(s) em {matchesById.size} requisição(ões)
                    </span>
                    {searchResult.limitReached && (
                      <span className="chip v-partial">limite atingido: há mais achados não listados</span>
                    )}
                    {searchResult.partial && (
                      <span className="chip v-partial" title={searchResult.partialAttempts.join(", ")}>
                        busca parcial: {searchResult.partialAttempts.length} corpo(s) truncado(s)
                      </span>
                    )}
                    {searchResult.skippedBinary > 0 && (
                      <span className="chip tag">{searchResult.skippedBinary} corpo(s) binário(s) não pesquisado(s)</span>
                    )}
                  </>
                ) : null}
              </div>
            )}

            <div className="table-wrap" ref={tableRef} onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}>
              <table className="req-table">
                <thead>
                  <tr>
                    <th className="col-idx">#</th>
                    <th className="col-method">Método</th>
                    <th className="col-domain">Domínio</th>
                    <th className="col-path">Caminho</th>
                    {showTargetColumn && <th className="col-target">Alvo</th>}
                    <th className="col-status">Status</th>
                    <th className="col-app" title="Sucesso da aplicação (≠ status HTTP)">Aplicação</th>
                    <th className="col-proto">Protocolo</th>
                    <th className="col-type">Tipo</th>
                    <th className="col-time num">Duração</th>
                  </tr>
                </thead>
                <tbody>
                  {startIndex > 0 && (
                    <tr className="spacer" aria-hidden="true">
                      <td colSpan={colCount} style={{ height: startIndex * ROW_HEIGHT }} />
                    </tr>
                  )}
                  {visibleRows.map((r, i) => {
                    const badge = showTargetColumn ? targetBadge(r) : null;
                    return (
                    <tr
                      key={r.id}
                      className={selected?.id === r.id ? "selected" : undefined}
                      onClick={() => openDetail(r.id)}
                      title="Abrir painel de detalhe"
                    >
                      <td className="mono dim">{String(startIndex + i + 1).padStart(2, "0")}</td>
                      <td>
                        <span className={`method ${methodClass[r.method] ?? "m-other"}`}>{r.method}</span>
                      </td>
                      <td className="domain">{r.domain}</td>
                      <td className="mono path">{r.path}</td>
                      {showTargetColumn && (
                        <td className="target-cell">
                          <span
                            className={`chip tag target-chip${
                              !badge || r.netlogOnlyUnknownTarget ? " v-partial" : ""
                            }`}
                            title={badge ?? "alvo desconhecido (só NetLog)"}
                          >
                            {badge ?? "alvo desconhecido (só NetLog)"}
                          </span>
                        </td>
                      )}
                      <td>
                        <span className={`status ${statusClass(r.status)}`}>{fmtStatus(r.status)}</span>
                      </td>
                      <td>
                        <VerdictChip outcome={outcomes.get(r.id)} />
                      </td>
                      <td>
                        <span className="proto">{fmtProtocol(r.protocol)}</span>
                      </td>
                      <td className="type">{typeLabels[r.type]}</td>
                      <td className="num mono time">
                        <span className="time-bar" style={{ width: `${Math.min(100, (r.durationMs / 460) * 100)}%` }} />
                        <span className="time-val">{fmtDuration(r)}</span>
                      </td>
                    </tr>
                    );
                  })}
                  {endIndex < filteredLength && (
                    <tr className="spacer" aria-hidden="true">
                      <td colSpan={colCount} style={{ height: (filteredLength - endIndex) * ROW_HEIGHT }} />
                    </tr>
                  )}
                  {filteredLength === 0 && (
                    <tr>
                      <td colSpan={colCount}>
                        <div className="empty">
                          {requestCount === 0
                            ? "Esta sessão não tem requisições."
                            : `Nenhuma requisição corresponde aos filtros ativos: ${activeFilterLabels({ query, typeFilter, targetFilter, protocol, failFilter, blockFilter }).join(", ") || "nenhum"}.`}
                          <button
                            className="link"
                            onClick={() => {
                              setQuery("");
                              setTypeFilter("all");
                              setTargetFilter("all");
                              setFailFilter(false);
                              setBlockFilter(false);
                              setProtocol("all");
                            }}
                          >
                            Limpar busca e filtros
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="statusbar">
              <span>
                {filteredLength} de {requestCount} requisições
              </span>
              <span className="sep">·</span>
              <span>{visibleRows.length} linhas renderizadas (virtualização)</span>
              <span className="sep">·</span>
              <span>{session.capture.mode ?? "fonte não informada"}</span>
              <span className="sep">·</span>
              <span>
                {session.completeness.state === "complete"
                  ? "sessão completa"
                  : `parcial: ${session.completeness.reasons[0] ?? "motivo não informado"}`}
              </span>
              <span className="grow" />
              <span className="mono dim">⌘O abrir · ⌘F buscar · ⌘C copiar · ⌘⇧C URL</span>
            </div>
          </>
        )}

        {view === "detail" && selected && (
          <DetailView
            req={selected}
            tab={tab}
            setTab={setTab}
            onBack={() => setView("session")}
            session={session}
            onCopy={copy}
            onExport={() => setExportTarget(selected)}
            onOpenRequest={(id) => {
              if (requests.some((r) => r.id === id)) setSelectedId(id);
            }}
            matches={matchesById.get(selected.id) ?? []}
            needle={payloadSearch ? { text: searchText, caseSensitive } : undefined}
            outcomes={outcomes}
            limitsRequests={limitsRequests}
            assessError={assess.error}
            assessLoading={assess.loading}
            assessWarnings={assess.result?.warnings}
          />
        )}

        {view === "detail" && detailPending && (
          <div className="empty big">
            <strong>{remoteDetail?.error ? "Não foi possível carregar a requisição." : "Carregando a requisição…"}</strong>
            {remoteDetail?.error ? <span>{remoteDetail.error}</span> : null}
            <button className="link" onClick={() => setView("session")}>
              Voltar
            </button>
          </div>
        )}

        {view === "detail" && !selected && !detailPending && (
          <div className="empty big">
            <strong>Sessão sem requisições.</strong>
            <span>O session.json foi lido, mas não há nenhuma LogicalRequest nele.</span>
            <button className="link" onClick={() => setView("session")}>
              Voltar
            </button>
          </div>
        )}

        {view === "timeline" && (
          <TimelineView
            sessionDir={session.sourcePath}
            requests={requests}
            onBack={() => setView("session")}
            onOpenRequest={(id) => {
              if (requests.some((r) => r.id === id)) {
                setSelectedId(id);
                setTab("headers");
                setView("detail");
              }
            }}
          />
        )}

        {view === "validate" && validation && (
          <ValidationView
            result={validation.result}
            tracePath={validation.tracePath}
            onBack={closeValidation}
            onSanitizeTrace={() => setSanitizeTraceDir(validation.result.traceDir)}
            onKept={() => setValidation((v) => (v ? { ...v, kept: true } : v))}
            onRevalidate={(mapOrigin) => void validateExecution({ tracePath: validation.tracePath, mapOrigin })}
          />
        )}

        {view === "capture-compare" && captureCmp && (
          <CaptureCompareView
            summary={captureCmp.summary}
            dirA={captureCmp.dirA}
            dirB={captureCmp.dirB}
            labelA={captureCmp.labelA}
            labelB={captureCmp.labelB}
            onBack={() => setView("session")}
          />
        )}

        {view === "compare" && requests.length >= 2 && (
          <CompareView
            aId={aId}
            bId={bId}
            setA={setAId}
            setB={setBId}
            onBack={() => setView("session")}
            requests={requests}
            session={session}
            resolve={resolveRecord}
          />
        )}

        {view === "compare" && requests.length < 2 && (
          <div className="empty big">
            <strong>Comparação precisa de duas requisições.</strong>
            <span>Esta sessão tem {requestCount}.</span>
            <button className="link" onClick={() => setView("session")}>
              Voltar
            </button>
          </div>
        )}

        {exportTarget && (
          <ExportDialog
            session={session}
            request={exportTarget}
            onClose={() => setExportTarget(null)}
          />
        )}

        {sanitizeTraceDir && (
          <SanitizeDialog
            session={{ ...session, id: "script-trace", sourcePath: sanitizeTraceDir }}
            onClose={() => setSanitizeTraceDir(null)}
            onOpened={(payload) => {
              closeValidation(); // a sessão sanitizada passa a ser a aberta; a temporária do trace é apagada
              applyPayload(payload);
            }}
          />
        )}

        {sanitizeOpen && (
          <SanitizeDialog
            session={session}
            onClose={() => setSanitizeOpen(false)}
            onOpened={(payload) => {
              applyPayload(payload);
              setSanitizeOpen(false);
            }}
          />
        )}
      </div>
    </div>
  );
}
