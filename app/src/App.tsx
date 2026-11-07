import { CookieSourceSelect } from "./CookieSourceSelect";
import { ProxyField } from "./ProxyField";
import { proxyHeaderView, proxyStartBlock, type ProxyState } from "./proxyRules";
import type { CookieSourceDto } from "./bridge";
import { desktopShortcut } from "./shortcuts";
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
import { cookieImportNotice, type CookieImportReport } from "./cookieImport";
import {
  IS_MAC,
  NATIVE_DIALOG,
  activeFilterLabels,
  chromeNotFoundCopy,
  outcomeChipDisabled,
  PagedList,
  sessionIsRecording,
  shortcutLabel,
} from "./listView";
import { adaptRequestDetail, adaptSession, protocolText, summaryFromRaw, summaryOfRecord, type AdaptedSession } from "./v1/adapter";
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

/** Page size for `list_requests` (the backend maximum). */
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
  requestHeaders: "Request headers",
  responseHeaders: "Response headers",
  normalizedHeaders: "Normalized view",
  cookies: "Cookies",
  payload: "Payload",
  responseBody: "Response body",
  protocol: "Protocol",
  timings: "Timings",
};

const sourceLabels: Record<string, string> = {
  cdp: "CDP",
  netlog: "NetLog",
  har: "HAR",
  ownFormat: "Own format",
  capture: "Capture",
  derived: "Derived",
  manual: "Manual",
  session: "Session",
};

const typeLabels: Record<string, string> = {
  document: "document",
  stylesheet: "stylesheet",
  script: "script",
  xhr: "xhr",
  fetch: "fetch",
  image: "image",
  font: "font",
  other: "other",
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
const NOT_SENT_TITLE = "Cancelled before any bytes were sent: the request never reached the network, so it has no protocol";

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
  const missing = verification.status === "partial" ? ` · missing: ${verification.missing}` : "";
  return `${sourceLabels[evidence.source] ?? evidence.source} · ${evidence.event} · ${evidence.method}${missing}`;
}

const matchLabels = {
  matched: "matched",
  ambiguous: "ambiguous",
  unmatched: "unpaired",
} as const;

const matchClass = {
  matched: "v-ok",
  ambiguous: "v-partial",
  unmatched: "v-none",
} as const;

const verifyText: Record<Verification["status"], string> = {
  verified: "verified",
  partial: "partial",
  unverified: "not verified",
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
          {pairs.length} pairs · {regular} regular · {pairs.length - regular}{" "}
          {pairs.length - regular === 1 ? "pseudoheader" : "pseudoheaders"}
        </span>
        <span className={`chip ${verifyClass(verification.status)}`} title={verificationTitle(verification)}>
          {verifyText[verification.status]}
        </span>
      </header>
      {pairs.length === 0 ? (
        <div className="empty">
          No lines were observed by this capture's source.
          <br />
          A missing header is not reconstructed — state: not verified.
        </div>
      ) : (
        <ol className="header-list">
          {pairs.map((p) => (
            <li key={`${side}-${p.index}`} className={p.kind === "pseudo" ? "hrow h-pseudo" : "hrow"}>
              <span className="h-idx">{p.index}</span>
              <span className="h-name">{p.name}</span>
              <span className="h-value">{p.value}</span>
              {dupes.get(p.name)! > 1 && (
                <span className="tag tag-dup" title="The same name appears more than once in the source sequence">
                  duplicate ×{dupes.get(p.name)}
                </span>
              )}
              <button
                className="icon-btn copy"
                title={`Copy ${p.name}${p.source ? ` · source ${p.source}${p.wallTime ? ` · ${p.wallTime}` : ""}` : ""}`}
                aria-label={`Copy ${p.name}`}
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
          ? "No lines: the source did not deliver this list in this capture."
          : "Source order preserved — nothing was sorted or grouped in this view."}
      </footer>
    </section>
  );
}

const scopeLabels: Record<SearchScope, string> = {
  url: "URL",
  requestHeaders: "header (req.)",
  responseHeaders: "header (resp.)",
  cookies: "cookies",
  requestBody: "req. body",
  responseBody: "resp. body",
};
const ALL_SCOPES = Object.keys(scopeLabels) as SearchScope[];

const PREVIEW_LIMIT = 262_144;
const COPY_LIMIT = 16 * 1024 * 1024;
const MAX_HIGHLIGHTS = 300;

/** React nodes with the core's match snippets highlighted (escaped text). */
function highlightMatches(text: string, matches: SearchMatch[], needle?: string, caseSensitive = false): { nodes: (string | ReactElement)[] | string; shown: number; beyond: number; dashed: number } {
  const { ranges, beyond } = matchRanges(text, matches, needle, caseSensitive);
  const nodes: (string | ReactElement)[] = [];
  let from = 0;
  for (const range of ranges.slice(0, MAX_HIGHLIGHTS)) {
    if (range.start < from || range.end <= range.start) continue; // overlapping: the previous one already covers it
    if (range.start > from) nodes.push(text.slice(from, range.start));
    nodes.push(
      <mark key={range.start} className={range.decoded ? "decoded" : undefined} title={range.decoded ? "match in the decoded view" : "search match"}>
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
      {long ? `REAL SESSION · ${origin.label}` : origin.tag}
    </span>
  );
}

function BodyPanel({
  title,
  body,
  kind,
  onCopy,
  sessionToken,
  matches,
  highlightNeedle,
}: {
  title: string;
  body: BodyInfo;
  kind: "payload" | "response";
  onCopy?: (value: string, label: string) => void;
  /** Token of the session folder; the bodies are read by token, never by path. */
  sessionToken?: string;
  /** Core matches for this body (same scope and attempt). */
  matches?: SearchMatch[];
  highlightNeedle?: { text: string; caseSensitive: boolean };
}) {
  const [data, setData] = useState<BodyData | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  useEffect(() => {
    setData(null);
    setLoadError(null);
    if (!sessionToken || !body.attachment || body.preview) return;
    let alive = true;
    bridge
      .readBody(sessionToken, body.attachment, PREVIEW_LIMIT)
      .then((result) => alive && setData(result))
      .catch((error) => alive && setLoadError(String(error)));
    return () => {
      alive = false;
    };
  }, [sessionToken, body.attachment, body.preview]);

  const transforms = classifyTransforms(body.transformed);
  const text = body.preview ?? (data?.kind === "text" ? data.text : undefined);
  const lit = useMemo(
    () => (text !== undefined && matches?.length ? highlightMatches(text, matches, highlightNeedle?.text, highlightNeedle?.caseSensitive) : { nodes: text ?? "", shown: 0, beyond: 0, dashed: 0 }),
    [text, matches, highlightNeedle?.text, highlightNeedle?.caseSensitive],
  );
  const copyBody = async () => {
    if (body.preview !== undefined) return onCopy?.(body.preview, title);
    if (!sessionToken || !body.attachment) return;
    try {
      const full = await bridge.readBody(sessionToken, body.attachment, COPY_LIMIT);
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
          {body.contentType ?? "unknown type"} · {fmtBytes(body.decodedSize ?? body.encodedSize)}
          {body.attachment ? <span className="mono"> · {body.attachment}</span> : null}
        </span>
        <span className={`chip ${stateClass}`}>{availabilityLabels[body.availability]}</span>
        {text !== undefined && onCopy && (
          <button className="ghost-btn small" onClick={() => void copyBody()} title="Copy body as text">
            Copy body
          </button>
        )}
      </header>
      {transforms.warn.length > 0 && (
        <div className="body-flag flag-truncated">
          <strong>Not identical to the bytes transferred</strong>
          <span>Transforms: {[...(transforms.chromeDecoded ? ["chrome-decoded"] : []), ...transforms.warn].join(", ")}</span>
        </div>
      )}
      {flagged && (
        <div className={`body-flag flag-${body.availability}`}>
          <strong>
            {body.availability === "truncated"
              ? `Body truncated in capture: ${fmtBytes(body.truncatedAt)} captured of ${fmtBytes(body.encodedSize)} (originalSize)`
              : body.availability === "discarded"
                ? "Body discarded — not recoverable"
                : body.availability === "omitted"
                  ? "Body not shown"
                  : "Body unavailable"}
          </strong>
          <span>{body.reason ?? "no reason recorded by the source"}</span>
        </div>
      )}
      {text !== undefined ? (
        <>
          <pre className="code">{lit.nodes}</pre>
          <div className="body-foot">
            {lit.shown > 0 && lit.nodes !== text ? `${lit.shown} search match(es) highlighted${lit.dashed > 0 ? "; dashed highlight = derived/decoded snippet, differs from the searched text" : ""}. ` : ""}
            {transforms.chromeDecoded && transforms.warn.length === 0 ? "Text decoded by Chrome. " : ""}
            {lit.beyond > 0 ? `${lit.beyond} match(es) beyond the shown portion. ` : ""}
            {data?.cut ? `Showing the first ${fmtBytes(data.shownBytes)} of ${fmtBytes(data.bytes)}; “Copy body” delivers up to ${fmtBytes(COPY_LIMIT)}. ` : ""}
            {body.contentType?.includes("html")
              ? "HTML shown as text — never rendered as UI."
              : "UTF-8 text shown without interpretation."}
            {body.captureRef ? <span className="mono dim"> · {body.captureRef}</span> : null}
          </div>
        </>
      ) : data?.kind === "binary" ? (
        <>
          <div className="empty">
            <strong>Binary content ({fmtBytes(data.bytes)}) — not rendered.</strong>
            <br />
            First {data.shownBytes} bytes in hexadecimal:
          </div>
          <pre className="code small hex">{data.hex}</pre>
        </>
      ) : loadError ? (
        <div className="empty">
          <strong>Could not read the attachment.</strong>
          <br />
          {loadError}
        </div>
      ) : body.attachment && sessionToken && !data ? (
        <div className="empty">Loading body…</div>
      ) : body.availability === "empty" ? (
        <div className="empty">
          <strong>Empty body (0 B).</strong>
          <br />
          {body.reason ?? "The source reported that this message has no body."}
        </div>
      ) : body.availability === "available" ? (
        <div className="empty">
          <strong>Body captured as attachment.</strong>
          <br />
          {body.attachment
            ? `File: ${body.attachment}. The text preview is loaded on demand in this session.`
            : "The source marked the body as captured, but no attachment is associated."}
        </div>
      ) : (
        <div className="empty">No text content available to display.</div>
      )}
      {kind === "response" &&
        body.encodedSize !== undefined &&
        body.decodedSize !== undefined &&
        body.encodedSize !== body.decodedSize && (
          <div className="body-foot">
            Size on the wire {fmtBytes(body.encodedSize)} · decoded {fmtBytes(body.decodedSize)}
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
        <h3>Content metadata</h3>
        <dl className="kv tight">
          <dt>Type</dt>
          <dd>{typeLabels[req.type]} · {req.method} {fmtStatus(req.status)}</dd>
          <dt>Payload</dt>
          <dd className="mono">
            {req.payload.contentType ?? "no body"}
            {requestContentEncoding ? ` · ${requestContentEncoding}` : ""}
          </dd>
          <dt>Response</dt>
          <dd className="mono">
            {req.responseBody.contentType ?? "type not reported"}
            {responseContentEncoding ? ` · ${responseContentEncoding}` : ""}
          </dd>
          <dt>Size on the wire</dt>
          <dd>{fmtBytes(req.payload.encodedSize)} / {fmtBytes(req.responseBody.encodedSize)}</dd>
          <dt>Decoded</dt>
          <dd>{fmtBytes(req.payload.decodedSize)} / {fmtBytes(req.responseBody.decodedSize)}</dd>
          <dt>Preview</dt>
          <dd>
            {req.payload.availability === "truncated" || req.responseBody.availability === "truncated"
              ? "partial (truncated during recording)"
              : "as recorded by the source"}
          </dd>
          <dt>Verification</dt>
          <dd>
            <span className={`chip ${verifyClass(verification("payload").status)}`}>payload {verifyText[verification("payload").status]}</span>{" "}
            <span className={`chip ${verifyClass(verification("responseBody").status)}`}>response {verifyText[verification("responseBody").status]}</span>
          </dd>
        </dl>
      </section>
      <section className="meta-card">
        <h3>Display rules</h3>
        <ul className="rules">
          <li>Captured HTML and JSON appear as text — never executed as UI.</li>
          <li>A missing, truncated, or discarded body shows the reason; nothing is reconstructed.</li>
          <li>Binaries are not converted to text: the file stays in the session folder.</li>
          <li>Copy uses the event's raw value, not the table's abbreviated text.</li>
        </ul>
      </section>
    </div>
  );
}

const availabilityLabels: Record<BodyInfo["availability"], string> = {
  available: "available",
  empty: "empty",
  truncated: "truncated",
  discarded: "discarded",
  omitted: "not shown",
  unavailable: "unavailable",
};

function bodyState(body: BodyInfo) {
  if (body.availability === "unavailable" && body.encodedSize === undefined) return "no body";
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
      <li>Headers with no matching event appear as “not verified”, never as fact.</li>
      <li>An omitted, truncated, or discarded body shows the reason — nothing is reconstructed.</li>
      <li>Captured HTML is never executed as UI; the contract is the core's v1.</li>
      <li>
        A tab document with <span className="mono">target=_blank</span> may come only from NetLog (without{" "}
        <span className="mono">requestWillBeSent</span> in the child session); the UI marks it “unknown target
        (NetLog only)” and does not invent CDP headers.
      </li>
      {showTargets && targets.length > 0 && (
        <li>
          Targets tracked in this capture:
          <ul className="limits-targets">
            {targets.map((t) => (
              <li key={`${t.kind}-${t.url}`}>
                <span className="chip tag">{t.kind}</span>{" "}
                <span className="mono">{t.url}</span>
                {t.attached === false ? (
                  <span className="chip v-partial">not attached</span>
                ) : null}{" "}
                <span className="dim">({t.count} req.)</span>
              </li>
            ))}
          </ul>
        </li>
      )}
      {uniqueFails.length > 0 && (
        <li>
          Target attach failures ({uniqueFails.length}):
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
          Target configuration warnings ({uniqueSetup.length}):
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
          ? "Synthetic session: no bytes left this computer — no telemetry, no network."
          : "Local capture: no telemetry; attachments stay in the session folder."}
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
        <h3>Source</h3>
        <div className="source-row">
          <span className={`src-chip ${req.primarySource === "cdp" ? "src-cdp" : "src-netlog"}`}>
            {sourceLabels[req.primarySource]} · primary
          </span>
          {session.sources.includes("cdp") && session.sources.includes("netlog") ? (
            <span className="src-chip src-muted">
              {req.primarySource === "cdp" ? "NetLog" : "CDP"} · cross-check
            </span>
          ) : (
            <span className="src-chip src-muted">single source in this session</span>
          )}
        </div>
        <dl className="kv">
          <dt>Request</dt>
          <dd className="mono">{req.id}</dd>
          <dt>Start</dt>
          <dd className="mono">{fmtTime(req.startedAt)}</dd>
          <dt>Initiator</dt>
          <dd>{req.initiator ?? "not reported"}</dd>
          <dt>Session</dt>
          <dd>
            <span className="mono">{session.id}</span>{" "}
            <OriginTag session={session} />
          </dd>
        </dl>
      </div>

      <div className="side-card">
        <div className="side-head">
          <h3>CDP × NetLog matching</h3>
          <span className={`chip ${matchClass[req.match.state]}`}>{matchLabels[req.match.state]}</span>
        </div>
        {req.match.state === "ambiguous" ? (
          <>
            <p className="verif-reason">
              More than one compatible candidate: no silent association. See the Attempts tab.
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
          <p className="verif-reason">The opposite source did not record this request; nothing was inferred.</p>
        ) : (
          <p className="verif-reason">Explicit keys from the source; the attempt matches its counterpart.</p>
        )}
      </div>

      {req.warnings.length > 0 && (
        <div className="side-card">
          <h3>Warnings for this request</h3>
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
          <h3>Verification status</h3>
          <span className="hint">per item</span>
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
                  <p className="verif-reason">No evidence: {v.reason}</p>
                ) : (
                  <>
                    <p className="verif-evidence mono">
                      {sourceLabels[v.evidence.source]} · {v.evidence.event}
                    </p>
                    <p className="verif-line">
                      {fmtTime(v.evidence.timestamp) ||
                        (v.evidence.sourceTime !== undefined
                          ? `t=${v.evidence.sourceTime.toFixed(3)} s (source clock)`
                          : "no time")}{" "}
                      · {v.evidence.method}
                    </p>
                    {v.status === "partial" && <p className="verif-reason">Missing: {v.missing}</p>}
                  </>
                )}
              </li>
            );
          })}
        </ul>
        <button
          className="ghost-btn wide"
          title="See the raw event table behind this data"
          onClick={onOpenEvent}
        >
          View original events ↗
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
    { id: "headers", label: "Raw headers", count: req.requestHeaders.length + req.responseHeaders.length },
    { id: "normalized", label: "Normalized" },
    { id: "cookies", label: "Cookies", count: req.cookiesSent.length + req.cookiesReceived.length },
    { id: "payload", label: "Payload" },
    { id: "response", label: "Response" },
    { id: "redirects", label: "Redirects", count: req.redirects.length },
    { id: "attempts", label: "Attempts", count: req.attempts.length },
    { id: "app", label: "App" },
    { id: "origins", label: "Origin" },
    { id: "event", label: "Event" },
  ];

  return (
    <div className="detail">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Session
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
          <span className="proto" title={req.networkState ? NOT_SENT_TITLE : undefined}>
            {protocolText(req.protocol, req.networkState)}
          </span>
          <span className="type">{typeLabels[req.type]}</span>
        </div>
        <div className="dh-sub">
          <span className="mono url">{req.url}</span>
          <button className="ghost-btn small" title="Copy full URL" onClick={() => onCopy(req.url, "URL")}>
            Copy URL
          </button>
          <button
            className="ghost-btn small"
            onClick={onExport}
            disabled={!session.sourcePath}
            title={
              session.sourcePath
                ? "cURL/Python preview generated in Rust; copy or save without running anything"
                : "Export unavailable: this session has no persisted folder (demo or browser mode)"
            }
          >
            Export…
          </button>
          <span className="dot">·</span>
          <span className="mono" title={req.verification.timings.status === "unverified" ? "Timings not verified: duration estimated by the UI" : "Duration measured by the source"}>
            {fmtDuration(req)}
          </span>
          <span className="dot">·</span>
          <span>{req.domain}</span>
          {(() => {
            const badge = targetBadge(req);
            return badge ? (
              <>
                <span className="dot">·</span>
                <span className="chip tag target-chip" title="CDP target of this request">
                  {badge}
                </span>
              </>
            ) : null;
          })()}
        </div>
      </header>

      {(req.target || req.netlogOnlyUnknownTarget || req.links.length > 0) && (
        <section className="target-panel" aria-label="Request target">
          <h3>Target</h3>
          {req.netlogOnlyUnknownTarget && !req.target ? (
            <p className="notice notice-info">
              <span className="notice-icon">i</span>
              <span>
                Unknown target (NetLog only): this request has no CDP provenance. A tab document with{" "}
                <span className="mono">target=_blank</span> may appear only in NetLog.
              </span>
            </p>
          ) : null}
          {req.target && (
            <dl className="kv target-kv">
              <dt>Type</dt>
              <dd>{targetKindLabel(req.target)}</dd>
              <dt>Target URL</dt>
              <dd className="mono">
                {req.target.url ?? (
                  <span className="dim" title={req.url}>
                    not reported in Target.* · request {shortTargetUrl(req.url) || req.path}
                  </span>
                )}
              </dd>
              <dt>Opened by</dt>
              <dd className="mono">{req.target.openerId ?? "— (main page or no opener)"}</dd>
              <dt>Parent session</dt>
              <dd className="mono">{req.target.parentSessionId ?? "—"}</dd>
              <dt>targetId</dt>
              <dd className="mono">{req.target.targetId ?? "—"}</dd>
              <dt>Attached</dt>
              <dd>
                {req.target.attached === true
                  ? "yes"
                  : req.target.attached === false
                    ? "no (stays with NetLog only)"
                    : "not reported"}
              </dd>
              {req.target.notes.length > 0 && (
                <>
                  <dt>Notes</dt>
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
              <h4>Linked observations (service worker)</h4>
              <p className="dim">
                The same logical request may appear in the page and in the service worker. Navigate between the
                observations; ambiguity never becomes a silent duplicate.
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
                      title="Open the other observation"
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
        <section className="match-box" aria-label="Search matches">
          <h3>
            Search matches <span className="count">{matches.length}</span>
          </h3>
          <ul>
            {matches.slice(0, 50).map((m, index) => {
              const attemptIndex = req.attempts.findIndex((attempt) => attempt.id === m.attemptId);
              return (
                <li key={index}>
                  <span className="chip mono">{scopeLabels[m.scope]}</span>
                  {m.field ? <span className="mono"> {m.field}</span> : null}
                  <span className="dim"> · attempt {attemptIndex >= 0 ? attemptIndex + 1 : m.attemptId}</span>
                  {m.byteOffset !== null ? <span className="dim"> · byte {m.byteOffset}</span> : null}
                  {m.htmlControl && <span className="chip tag" title="The match is in an HTML form control (input/textarea/select) of the response">HTML control</span>}
                  {m.decoded && <span className="chip v-partial" title="Match after decoding form-urlencoded/JSON; the raw byte may differ">decoded view</span>}
                  <div className="mono snippet">{m.snippet}</div>
                  {m.decoded && (
                    <div className="dim">
                      The snippet above is the decoded view of the field (derived); the raw body, shown in the Payload/Response tab, is the primary data.
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          {matches.length > 50 && <p className="dim">+{matches.length - 50} matches not listed here.</p>}
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
                <span className="tag tag-seq">source sequence</span>
                Indices 0–{Math.max(req.requestHeaders.length - 1, 0)} (request) and 0–{Math.max(req.responseHeaders.length - 1, 0)} (response).
                HTTP/2 pseudoheaders appear before the regular ones, as they arrived.
                {req.protocol === "HTTP/1.1" && (
                  <span className="seq-extra">HTTP/1.1 origin: no pseudoheaders, only named lines.</span>
                )}
              </div>
              <HeaderBlock
                title="Request headers"
                pairs={req.requestHeaders}
                side="req"
                verification={req.verification.requestHeaders}
                onCopy={onCopy}
              />
              <HeaderBlock
                title="Response headers"
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
                <strong>Normalized view — not the transmitted sequence.</strong>
                <span>
                  Derived locally: grouped by name, in alphabetical order, duplicates kept and counted.
                  Use the “Raw headers” tab for the source order.
                </span>
              </div>
              {[
                { title: "Request (normalized)", rows: reqNorm },
                { title: "Response (normalized)", rows: resNorm },
              ].map(({ title, rows }) => (
                <section className="norm-block" key={title}>
                  <header className="block-head">
                    <h3>{title}</h3>
                    <span className="block-meta">{rows.length} unique names</span>
                  </header>
                  <table className="norm-table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Values (in source order)</th>
                        <th className="num">Occurrences</th>
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
                  <footer className="block-foot">Derived view — verification status: partial.</footer>
                </section>
              ))}
            </>
          )}

          {tab === "cookies" && (
            <div className="cookies">
              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies sent</h3>
                  <span className="block-meta">parsed Cookie header · {req.cookiesSent.length} pairs</span>
                </header>
                <div className="cookie-grid">
                  {req.cookiesSent.length === 0 && <div className="empty">No cookies sent in this request.</div>}
                  {req.cookiesSent.map((c) => (
                    <div className="cookie-card" key={`${c.name}-${c.index}`}>
                      <div className="cookie-name mono">{c.name}</div>
                      <div className="cookie-value mono">{c.value}</div>
                      <div className="cookie-meta">pair #{c.index} · header order</div>
                    </div>
                  ))}
                </div>
                <footer className="block-foot">
                  Inner pairs preserved; long values shortened here for readability.
                </footer>
              </section>

              {(req.cookieRaw.length > 0 || req.cookieWireLines.length > 0) && (
                <section className="header-block">
                  <header className="block-head">
                    <h3>Cookie sent — raw field and wire lines</h3>
                    <span className="block-meta">
                      {req.cookieRaw.length} raw field(s) · {req.cookieWireLines.length} wire line(s)
                    </span>
                  </header>
                  <div className="cookie-raw">
                    {req.cookieRaw.map((line, index) => (
                      <div key={`raw-${index}`} className="raw-line">
                        <span className="tag">raw field</span>
                        <span className="mono">{line}</span>
                      </div>
                    ))}
                    {req.cookieWireLines.map((line, index) => (
                      <div key={`wire-${index}`} className="raw-line">
                        <span className="tag tag-seq">wire line</span>
                        <span className="mono">{line}</span>
                      </div>
                    ))}
                  </div>
                  <footer className="block-foot">
                    {req.cookieWireLines.length > req.cookieRaw.length
                      ? "The wire shows more Cookie lines than the original field — split preserved, nothing merged."
                      : "No split on the wire observed in this request."}
                    {req.cookieNotes?.length ? ` ${req.cookieNotes.join(" · ")}` : ""}
                  </footer>
                </section>
              )}

              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies received</h3>
                  <span className="block-meta">separate Set-Cookie lines · {req.cookiesReceived.length}</span>
                </header>
                {req.cookiesReceived.length === 0 ? (
                  <div className="empty">No Set-Cookie in this response.</div>
                ) : (
                  <table className="norm-table cookies-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Name</th>
                        <th>Value</th>
                        <th>Attributes</th>
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
                  The raw line is preserved in the source event; the table does not join Set-Cookie with “;”.
                </footer>
              </section>

              {req.cookiesReceived.length > 0 && (
                <section className="header-block">
                  <header className="block-head">
                    <h3>Raw Set-Cookie lines</h3>
                    <span className="block-meta">as the event delivered them · source order</span>
                  </header>
                  <pre className="code small">{req.cookiesReceived.map((c) => c.raw).join("\n")}</pre>
                  <footer className="block-foot">
                    The table above is derived from these lines; no attribute is invented or reordered.
                  </footer>
                </section>
              )}
            </div>
          )}

          {tab === "payload" && (
            <>
              <BodyPanel title="Request payload" body={effectivePayload} kind="payload" onCopy={onCopy} sessionToken={session.sourceToken} matches={bodyMatches("requestBody", effectivePayload)} highlightNeedle={needle} />
              <AdapterViewPanel sessionToken={session.sourceToken} requestId={req.id} side="request" />
              <BodyContext req={req} />
              <BodyPanel title="Response body (reference)" body={effectiveResponse} kind="response" onCopy={onCopy} sessionToken={session.sourceToken} matches={bodyMatches("responseBody", effectiveResponse)} highlightNeedle={needle} />
            </>
          )}
          {tab === "response" && (
            <>
              <BodyPanel title="Response body" body={effectiveResponse} kind="response" onCopy={onCopy} sessionToken={session.sourceToken} matches={bodyMatches("responseBody", effectiveResponse)} highlightNeedle={needle} />
              <AdapterViewPanel sessionToken={session.sourceToken} requestId={req.id} side="response" />
              <BodyContext req={req} />
            </>
          )}

          {tab === "redirects" &&
            (req.redirects.length === 0 ? (
              <div className="empty big">
                <strong>No redirects or attempts recorded.</strong>
                <span>No hops in this request; nothing to compare.</span>
              </div>
            ) : (
              <section className="header-block">
                <header className="block-head">
                  <h3>Redirect chain and attempts</h3>
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
                  An HTTP/1.1 → HTTP/2 jump is recorded as two hops; each hop has its own evidence.
                </footer>
              </section>
            ))}

          {tab === "attempts" &&
            (req.attempts.length === 0 ? (
              <div className="empty big">
                <strong>No attempts recorded.</strong>
                <span>The v1 contract did not include Attempts for this logical request.</span>
              </div>
            ) : (
              <section className="header-block">
                <header className="block-head">
                  <h3>Attempts of the logical request</h3>
                  <span className="block-meta">
                    {req.attempts.length} attempt(s) · correlation {matchLabels[req.match.state]}
                  </span>
                </header>
                <table className="norm-table event-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>ID</th>
                      <th>Status</th>
                      <th>Protocol</th>
                      <th>Outcome</th>
                      <th>Headers (req/res)</th>
                      <th>Matching</th>
                    </tr>
                  </thead>
                  <tbody>
                    {req.attempts.map((attempt) => (
                      <tr key={attempt.id}>
                        <td className="mono dim">{attempt.index}</td>
                        <td className="mono">{attempt.id}</td>
                        <td><span className={`status ${statusClass(attempt.status ?? 0)}`}>{fmtStatus(attempt.status ?? 0)}</span></td>
                        <td><span className="proto" title={attempt.networkState ? NOT_SENT_TITLE : undefined}>{protocolText(attempt.protocol, attempt.networkState)}</span></td>
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
                    <strong>Ambiguous match — no source was chosen</strong>
                    <span>
                      {req.match.candidates.length} candidate(s):{" "}
                      {req.match.candidates
                        .map((candidate) => `${candidate.entityId} (${candidate.score})`)
                        .join(", ")}
                      . ScrapeLens does not associate silently.
                    </span>
                  </div>
                )}
                <footer className="block-foot">
                  Each attempt keeps its own headers, Cookie, bodies, and provenance.
                </footer>
              </section>
            ))}

          {tab === "app" && (
            <AppSuccessSection outcome={outcomes.get(req.id)} error={assessError} loading={assessLoading} warnings={assessWarnings} />
          )}

          {tab === "origins" && (
            <OriginsTab sessionToken={session.sourceToken} requestId={req.id} onOpen={onOpenRequest} verdicts={outcomes} />
          )}

          {tab === "event" && (
            <section className="header-block">
              <header className="block-head">
                <h3>Original events</h3>
                <span className="block-meta">read-only · synthetic data</span>
              </header>
              <table className="norm-table event-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Event</th>
                    <th>Timestamp</th>
                    <th>How it was obtained</th>
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
                          <td className="dim">no event</td>
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
                The raw event is the authority; the table above only references it.
              </footer>
            </section>
          )}

          <section className="limits-strip">
            <div className="limits-head">
              <OriginTag session={session} long />
              <h3>Limits of this capture</h3>
              <span className="hint">visible on all tabs</span>
            </div>
            <CaptureLimits session={session} requests={limitsRequests} />
          </section>
        </div>

        <VerificationPanel req={req} onOpenEvent={() => setTab("event")} session={session} />
      </div>
    </div>
  );
}

/** Comparison: the selector uses the summaries; the two requests are fetched on demand (P5). */
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
      <strong>{pair?.error ? "Could not load the requests." : "Loading both requests…"}</strong>
      {pair?.error ? <span>{pair.error}</span> : null}
      <button className="link" onClick={props.onBack}>
        Back
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
          <span className="absent">— missing in A</span>
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
          <span className="absent">missing in B —</span>
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
          ← Session
        </button>
        <div className="crumbs">
          <span className="mono">{session.id}</span>
          <span className="sep">/</span>
          <span>comparison</span>
          <OriginTag session={session} />
        </div>
      </div>

      <header className="compare-head">
        <div>
          <h2>Compare two requests</h2>
          <p className="sub">
            Side by side, in source order. Repeated pairs are matched by value, never by position.
          </p>
        </div>
        <div className="compare-pickers">
          {pickerRow("A", a.id, setA)}
          <span className="vs">vs</span>
          {pickerRow("B", b.id, setB)}
        </div>
      </header>

      <div className="compare-summary">
        <span className="summary-total">{total} differences</span>
        <span className="chip k-added">+{counts.added} {counts.added === 1 ? "added" : "added"}</span>
        <span className="chip k-removed">−{counts.removed} {counts.removed === 1 ? "removed" : "removed"}</span>
        <span className="chip k-changed">~{counts.changed} {counts.changed === 1 ? "changed" : "changed"}</span>
        <span className="chip k-reordered">↕{counts.reordered} {counts.reordered === 1 ? "reordered" : "reordered"}</span>
        <span className="summary-note">
          {a.protocol === b.protocol ? (
            <>Same protocol: <span className="mono">{a.protocol}</span></>
          ) : (
            <>Protocol differs: <span className="mono">{a.protocol}</span> → <span className="mono">{b.protocol}</span></>
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
          <h3>Request headers</h3>
          <span className="block-meta">{a.requestHeaders.length} vs {b.requestHeaders.length} pairs · original position on the left</span>
        </header>
        <div className="diff-rows">{headerDiff.rows.map(headerRow)}</div>
      </section>

      {counts.reordered > 0 && (
        <p className="reorder-note">
          <span className="chip k-reordered">reordered</span> same pair on both sides, relative order inverted —
          the indices show the original position in each sequence.
        </p>
      )}

      <section className="diff-section">
        <header className="diff-head">
          <h3>Response headers</h3>
          <span className="block-meta">{resDiff.rows.length} names · {resDiff.counts.changed} changed, {resDiff.counts.added} added, {resDiff.counts.removed} removed</span>
        </header>
        <div className="diff-rows">{resDiff.rows.map(headerRow)}</div>
      </section>

      <section className="diff-section">
        <header className="diff-head">
          <h3>Cookies sent</h3>
          <span className="block-meta">matched by name and value</span>
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
                  <span className="absent">— cookie missing in A</span>
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
                  <span className="absent">cookie missing in B —</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="diff-section bodies">
        <header className="diff-head">
          <h3>Body and protocol</h3>
          <span className="block-meta">no content normalization</span>
        </header>
        <div className="body-compare">
          {[
            { r: a, label: "A" },
            { r: b, label: "B" },
          ].map(({ r, label }) => (
            <div className="body-col" key={label}>
              <div className="body-col-head">
                <span className="tag">{label}</span>
                <span className="mono" title={r.networkState ? NOT_SENT_TITLE : undefined}>{protocolText(r.protocol, r.networkState)}</span>
                <span className={`status ${statusClass(r.status)}`}>{r.status}</span>
              </div>
              <dl className="kv tight">
                <dt>Payload</dt>
                <dd>{r.payload.preview ? `${r.payload.preview.length} characters` : bodyState(r.payload)}</dd>
                <dt>Response</dt>
                <dd>{bodyState(r.responseBody)} · {fmtBytes(r.responseBody.decodedSize ?? r.responseBody.encodedSize)}</dd>
                <dt>Set-Cookie</dt>
                <dd>{r.cookiesReceived.length} line(s)</dd>
              </dl>
              {r.responseBody.preview ? (
                <pre className="code small">{r.responseBody.preview}</pre>
              ) : (
                <div className="body-flag flag-unavailable">
                  <strong>No body to compare</strong>
                  <span>{r.responseBody.reason ?? "the source did not provide a preview"}</span>
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
  const [cookieImport, setCookieImport] = useState<CookieImportReport | null>(null);
  const cookieImportView = useMemo(() => cookieImportNotice(cookieImport), [cookieImport]);
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
  const [cookieSources, setCookieSources] = useState<CookieSourceDto[]>([]);
  const [cookieSource, setCookieSource] = useState("");
  const [cookieSourcesReady, setCookieSourcesReady] = useState(false);
  const [proxyState, setProxyState] = useState<ProxyState | null>(null);
  const [proxyDraft, setProxyDraft] = useState("");
  const [proxyError, setProxyError] = useState<string | null>(null);
  const [startUrlError, setStartUrlError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [exportTarget, setExportTarget] = useState<RequestRecord | null>(null);
  const [sanitizeOpen, setSanitizeOpen] = useState(false);
  const [sanitizeTrace, setSanitizeTrace] = useState<{ path: string; token: string } | null>(null);
  const [validation, setValidation] = useState<{ result: ValidationResultDto; tracePath: string; traceToken: string; kept?: boolean } | null>(null);
  const [chrome, setChrome] = useState<ChromeInfo | null>(null);
  const [isLargeDemo, setIsLargeDemo] = useState(false);
  const [captureCmp, setCaptureCmp] = useState<{ summary: CompareSummary; tokenA: string; tokenB: string; labelA: string; labelB: string } | null>(null);
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
  // P5: paged session → summaries via list_requests and detail via get_request;
  // in-memory session (demo, browser mode) → the same summaries, derived locally.
  const pagedToken = session.paged && session.sourceToken ? session.sourceToken : undefined;
  const memorySummaries = useMemo(() => session.requests.map(summaryOfRecord), [session.requests]);
  const [remoteAll, setRemoteAll] = useState<{ dir: string; items: RequestSummary[]; first?: RequestPageDto } | null>(null);
  // The whole list is only scanned when a view needs it (detail, timeline, comparison);
  // the main view uses `PagedList` (visible pages + 1) and the backend counts.
  const needFull = Boolean(pagedToken) && (view === "detail" || view === "timeline" || view === "compare");
  useEffect(() => {
    if (!pagedToken) {
      setRemoteAll(null);
      return;
    }
    if (!needFull || remoteAll?.dir === pagedToken) return;
    let alive = true;
    void (async () => {
      const items: RequestSummary[] = [];
      let first: RequestPageDto | undefined;
      try {
        for (let offset = 0; ; offset += PAGE) {
          const page = await bridge.listRequests(pagedToken, offset, PAGE, {});
          if (!alive) return;
          first = first ?? page;
          for (const raw of page.items) items.push(summaryFromRaw(raw, session.createdAt, page.targets));
          if (page.items.length === 0 || offset + PAGE >= page.matched) break;
        }
        if (alive) setRemoteAll({ dir: pagedToken, items, first });
      } catch (error) {
        if (alive) setNotice({ kind: "error", text: "Could not list the requests.", detail: String(error) });
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pagedToken, session.createdAt, needFull]);
  const requests: RequestSummary[] = pagedToken
    ? remoteAll?.dir === pagedToken
      ? remoteAll.items
      : []
    : memorySummaries;
  const requestCount = session.requestCount;
  const effectiveId =
    pagedToken && selectedId && !remoteAll
      ? selectedId
      : requests.some((r) => r.id === selectedId)
        ? selectedId
        : requests[0]?.id ?? "";
  const resolveRecord = useCallback(
    async (id: string): Promise<RequestRecord> => {
      if (!pagedToken) {
        const found = session.requests.find((r) => r.id === id);
        if (!found) throw new Error(`request ${id} not found`);
        return found;
      }
      const detail = await bridge.getRequest(pagedToken, id);
      return adaptRequestDetail(loaded.raw, detail, { sourceToken: pagedToken, attachments: session.attachments });
    },
    [pagedToken, session.requests, session.attachments, loaded.raw],
  );
  const [remoteDetail, setRemoteDetail] = useState<{ dir: string; id: string; record?: RequestRecord; error?: string } | null>(null);
  useEffect(() => {
    if (!pagedToken || !effectiveId) return;
    let alive = true;
    resolveRecord(effectiveId)
      .then((record) => alive && setRemoteDetail({ dir: pagedToken, id: effectiveId, record }))
      .catch((error) => alive && setRemoteDetail({ dir: pagedToken, id: effectiveId, error: String(error) }));
    return () => {
      alive = false;
    };
  }, [pagedToken, effectiveId, resolveRecord]);
  const selected: RequestRecord | undefined = pagedToken
    ? remoteDetail?.dir === pagedToken && remoteDetail.id === effectiveId
      ? remoteDetail.record
      : undefined
    : session.requests.find((r) => r.id === selectedId) ?? session.requests[0];
  const detailPending = Boolean(pagedToken && effectiveId && !selected);
  const limitsRequests = requests;
  const [listMeta, setListMeta] = useState<RequestPageDto | undefined>(undefined);
  const warningTotal =
    session.warnings.length +
    (pagedToken
      ? listMeta?.warningTotal ?? 0
      : requests.reduce((total, request) => total + request.warningCount, 0));
  const compareCaptures = async () => {
    if (!session.sourceToken) return;
    try {
      const picked = await bridge.pickCompareSession();
      if (!picked) return;
      setBusy("Comparing captures…");
      const summary = await bridge.compareOpen(session.sourceToken, picked.token);
      setCaptureCmp({
        summary,
        tokenA: session.sourceToken,
        tokenB: picked.token,
        labelA: session.label,
        labelB: picked.path.split("/").filter(Boolean).pop() ?? picked.path,
      });
      setView("capture-compare");
    } catch (error) {
      setNotice({ kind: "error", text: "Could not compare the captures.", detail: String(error) });
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
        sourceToken: payload.sessionToken,
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
    setCookieImport(payload.cookieImport ?? null);
    if (payload.notice) setNotice({ kind: "info", text: payload.notice });
  }, []);

  // One open/import at a time (the backend also rejects a second one).
  const loadingRef = useRef(false);
  const beginLoading = useCallback(() => {
    if (loadingRef.current) {
      setNotice({ kind: "info", text: "A session is already being opened or imported. Please wait for it to finish." });
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
        text: `Open capture uses the ${NATIVE_DIALOG} and is only available in the desktop app.`,
        detail: "Run `npm run tauri dev` to open the Tauri shell.",
      });
      return;
    }
    if (!beginLoading()) return;
    setBusy("Opening session… (large sessions take a few seconds)");
    try {
      applyPayload(await bridge.pickAndOpenSession());
    } catch (error) {
      setNotice({ kind: "error", text: "Could not open the session.", detail: String(error), action: "open" });
    } finally {
      endLoading();
      setBusy(null);
    }
  }, [applyPayload, desktop, beginLoading, endLoading]);

  const validationRef = useRef(validation);
  validationRef.current = validation;
  // Closing the validation view deletes the trace's temporary session (unless it was kept).
  const closeValidation = useCallback(() => {
    const current = validationRef.current;
    setView("session");
    setSanitizeTrace(null);
    if (current) {
      if (!current.kept) void bridge.discardValidation(current.result.traceToken).catch(() => {});
      setValidation(null);
    }
  }, []);

  const validateExecution = useCallback(
    async (again?: { traceToken: string; tracePath: string; mapOrigin: string }) => {
      const sessionToken = loaded.session.sourceToken;
      if (!desktop || !sessionToken) return;
      try {
        const picked = again ? { token: again.traceToken, path: again.tracePath } : await bridge.pickTraceFile();
        if (!picked) return;
        setBusy("Importing the trace and validating…");
        const result = await bridge.validateExecution(sessionToken, picked.token, again?.mapOrigin);
        if (validationRef.current && !validationRef.current.kept) {
          void bridge.discardValidation(validationRef.current.result.traceToken).catch(() => {});
        }
        setValidation({ result, tracePath: picked.path, traceToken: picked.token });
        setView("validate");
      } catch (error) {
        setNotice({ kind: "error", text: "Could not validate the execution.", detail: String(error) });
      } finally {
        setBusy(null);
      }
    },
    [desktop, loaded.session.sourceToken],
  );

  const importCapture = useCallback(
    async (kind: "har" | "netlog") => {
      if (!desktop) {
        setNotice({ kind: "info", text: `Importing ${kind.toUpperCase()} is only available in the desktop app.` });
        return;
      }
      if (recording) {
        setNotice({ kind: "info", text: "A capture is in progress. Stop the recording before importing." });
        return;
      }
      if (!beginLoading()) return;
      setBusy(kind === "har" ? "Importing HAR…" : "Importing NetLog…");
      try {
        applyPayload(kind === "har" ? await bridge.importHar() : await bridge.importNetlog());
      } catch (error) {
        setNotice({ kind: "error", text: `The ${kind.toUpperCase()} import failed.`, detail: String(error) });
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
        setNotice({ kind: "success", text: `Chrome configured: ${info.path ?? "saved path"}` });
      }
    } catch (error) {
      setNotice({ kind: "error", text: "The chosen path is not a usable Chrome.", detail: String(error) });
    }
  }, []);

  const startCapture = useCallback(async () => {
    if (!desktop) {
      setNotice({ kind: "info", text: "Live capture uses an external Chrome and is only available in the desktop app." });
      return;
    }
    if (!cookieSourcesReady || busy || recording) return;
    const proxyBlock = proxyStartBlock(proxyState, !!recording);
    if (proxyBlock) {
      setNotice({ kind: "error", text: "Could not start the capture.", detail: proxyBlock, action: "start" });
      return;
    }
    const resolved = resolveCaptureStartUrl(startUrl);
    if (!resolved.ok) {
      setStartUrlError(resolved.error);
      setNotice({ kind: "error", text: "Invalid start URL.", detail: resolved.error, action: "start" });
      return;
    }
    setStartUrlError(null);
    setBusy("Opening Chrome with a dedicated profile and connecting to CDP…");
    try {
      const payload = await bridge.startSession(trimUrl(startUrl) ? trimUrl(startUrl) : undefined, cookieSource || undefined);
      if (!payload) return;
      setRecording({
        sessionId: payload.session.session.id,
        sessionDir: payload.sessionDir ?? "",
        startedAt: payload.session.session.startedAt,
        events: 0,
        pageUrl: resolved.url,
      });
      setCookieImport(null);
      setNotice({ kind: "info", text: payload.notice ?? "Capture started. Browse in Chrome and click Stop." });
    } catch (error) {
      const info = await bridge.detectChrome().catch(() => null);
      if (info) setChrome(info);
      setNotice({
        kind: "error",
        text: "Could not start the capture.",
        detail: String(error),
        action: info && !info.found ? "chrome" : "start",
      });
    } finally {
      setBusy(null);
    }
  }, [desktop, startUrl, cookieSource, cookieSourcesReady, busy, recording, proxyState]);

  const applyProxy = useCallback(() => {
    setBusy("Checking the proxy link…");
    void bridge.setProxyLink(proxyDraft).then(async () => {
      // The typed text leaves the field as soon as the backend has it.
      setProxyDraft("");
      setProxyError(null);
      setProxyState(await bridge.getProxyState());
      setNotice({ kind: "info", text: "Proxy set for the next capture. Credentials, if any, are kept in memory only." });
    }).catch((error) => {
      setProxyError(String(error));
    }).finally(() => setBusy(null));
  }, [proxyDraft]);

  const clearProxy = useCallback(() => {
    setBusy("Clearing the proxy…");
    void bridge.clearProxyLink().then(async () => {
      setProxyDraft("");
      setProxyError(null);
      setProxyState(await bridge.getProxyState());
    }).catch((error) => {
      setProxyError(String(error));
    }).finally(() => setBusy(null));
  }, []);

  const stopCapture = useCallback(async () => {
    setBusy("Stopping Chrome, waiting for NetLog and importing the session…");
    try {
      const payload = await bridge.stopSession();
      setRecording(null);
      if (payload) applyPayload(payload);
      else setNotice({ kind: "error", text: "The capture ended without a session.", action: "start" });
    } catch (error) {
      setRecording(null);
      setNotice({
        kind: "error",
        text: "Could not stop/import the capture.",
        detail: String(error),
        action: "start",
      });
    } finally {
      setBusy(null);
    }
  }, [applyPayload]);

  const copy = useCallback(async (text: string, label = "Value") => {
    const ok = await bridge.copyText(text);
    setNotice({
      kind: ok ? "success" : "error",
      text: ok ? `${label} copied to the clipboard.` : "Could not copy.",
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
    void bridge.listCookieSources().then((payload) => {
      setCookieSources(payload.sources);
      setCookieSource(payload.selected ?? "");
    }).catch((error) => {
      setNotice({ kind: "error", text: "Could not list the cookie sources. The capture will use a clean session.", detail: String(error) });
    }).finally(() => setCookieSourcesReady(true));
    void bridge.getProxyState().then(setProxyState).catch(() => null);
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
            text: action.kind === "error" ? "Invalid command-line argument." : "Command-line arguments ignored.",
            detail: action.message,
          });
          return;
        }
        setBusy(
          action.kind === "import-har"
            ? "Importing HAR (CLI)…"
            : action.kind === "import-netlog"
              ? "Importing NetLog (CLI)…"
              : "Opening capture (CLI)…",
        );
        const payload =
          action.kind === "import-har"
            ? await bridge.importHarAt(action.token ?? "")
            : action.kind === "import-netlog"
              ? await bridge.importNetlogAt(action.token ?? "")
              : await bridge.openSessionAt(action.token ?? "");
        if (!cancelled) applyPayload(payload);
      } catch (error) {
        if (!cancelled) {
          setNotice({ kind: "error", text: "Failed to handle the CLI open argument.", detail: String(error) });
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
        setNotice({ kind: "info", text: payload.notice ?? "Synthetic stress session." });
      })
      .catch((error) => setNotice({ kind: "error", text: "Failed to generate the stress session.", detail: String(error) }));
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
      const shortcut = desktopShortcut(event, IS_MAC, {
        desktop, recording: !!recording, busy: !!busy, startUrlError: !!startUrlError,
      });
      if (shortcut) {
        event.preventDefault();
        if (shortcut === "start") void startCapture();
        else if (shortcut === "stop") void stopCapture();
        else if (shortcut === "har") void importCapture("har");
        else if (shortcut === "netlog") void importCapture("netlog");
        else if (shortcut === "demo") void bridge.demoSession().then(applyPayload);
        else if (shortcut === "copy" && selected) void copy(selected.url, "Request URL");
        return;
      }
      if (event.shiftKey) return;
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
          void copy(selected.url, "Request URL");
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [applyPayload, busy, copy, desktop, importCapture, openSession, recording, selected, startCapture, startUrlError, stopCapture]);

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

  const searchToken = desktop ? session.sourceToken : undefined;
  const assess = useAssess(searchToken);
  const outcomes = assess.map;
  const searchText = query.trim();
  const searchKey = searchToken && searchText ? JSON.stringify([searchToken, searchText, scopes, caseSensitive]) : "";
  useEffect(() => {
    if (!searchKey || !searchToken) {
      setSearchState(null);
      return;
    }
    setSearchState({ key: searchKey, loading: true });
    let alive = true;
    const timer = window.setTimeout(() => {
      bridge
        .searchSession(searchToken, searchText, scopes, caseSensitive)
        .then((result) => alive && setSearchState({ key: searchKey, loading: false, result }))
        .catch((error) => alive && setSearchState({ key: searchKey, loading: false, error: String(error) }));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [searchKey, searchToken, searchText, scopes, caseSensitive]);
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
      pagedToken
        ? Boolean(listMeta?.hasTargets) || sessionShowsTargets([], session.warnings)
        : sessionShowsTargets(requests, session.warnings),
    [pagedToken, listMeta, requests, session.warnings],
  );

  const localFiltered = useMemo(() => {
    if (pagedToken) return [];
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
        // Core search: only requests with a match (id/method/status still apply).
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
    pagedToken,
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

  // Backend filter (P5): same semantics as `localFiltered`, in src-tauri/src/listing.rs.
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
  const remoteKey = pagedToken ? `${pagedToken}\u0000${JSON.stringify(remoteFilter)}` : "";
  const remoteFilterRef = useRef(remoteFilter);
  remoteFilterRef.current = remoteFilter;
  const [, bumpList] = useReducer((n: number) => n + 1, 0);
  // One `PagedList` per (session, filter): replaced only when the key changes, not on every render.
  const pagedList = useMemo(() => {
    if (!pagedToken) return null;
    const filter = remoteFilterRef.current;
    const createdAt = session.createdAt;
    return new PagedList<RequestSummary, RequestPageDto>(
      async (offset, limit) => {
        const page = await bridge.listRequests(pagedToken, offset, limit, filter);
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
    if (pagedList?.error) setNotice({ kind: "error", text: "Failed to list the requests.", detail: pagedList.error });
  }, [pagedList, pagedList?.error]);
  useEffect(() => {
    if (!pagedToken) setListMeta(undefined);
  }, [pagedToken]);
  const filteredLength = pagedList ? pagedList.length : localFiltered.length;
  const rowAt = (index: number): RequestSummary | undefined =>
    pagedList ? pagedList.row(index) : localFiltered[index];

  const remoteCounts = pagedToken ? listMeta?.counts : undefined;
  const counts = remoteCounts ?? {
    all: requests.length,
    fetch: requests.filter((r) => r.type === "fetch" || r.type === "xhr").length,
    document: requests.filter((r) => r.type === "document").length,
    media: requests.filter((r) => r.type === "image" || r.type === "font").length,
    error: requests.filter((r) => r.status >= 400).length,
  };
  const targetCount = (id: TargetFilter) =>
    pagedToken ? listMeta?.targetCounts?.[id] ?? 0 : targetFilterCount(requests, id);
  const failCount = pagedToken
    ? [...outcomes.values()].filter((o) => isAppFailure(o)).length
    : requests.filter((r) => isAppFailure(outcomes.get(r.id))).length;
  const blockCount = pagedToken
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
  // In the paged session, only the visible window (+1 page) is requested; rows not yet arrived are left out.
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
        <div className="toolbar-top" id="scrapelens-toolbar">
          <div className="title-actions">
            <OriginTag session={session} />
            <span className="tag tag-synthetic">{desktop ? "Tauri 2" : "browser mode"}</span>
            <button
              className="icon-btn theme"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              title={`${theme === "light" ? "Light" : "Dark"} theme — toggle`}
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
                  <strong>Synthetic fixture:</strong> made-up values shaped like a real case; nothing was
                  captured. To capture for real, use Start session (external Chrome) or Open capture….
                </>
              ) : (
                <>
                  <strong>Synthetic session (v1 contract).</strong> No bytes were captured: the{" "}
                  <span className="mono">.invalid</span> domains, invented bodies, and simulated events are there to
                  review the interface. To capture for real, use Start session (external Chrome) or Open capture….
                </>
              )}
            </p>
            <span className="demo-right mono">no telemetry</span>
          </div>
        ) : (
          <div className="real-banner">
            <OriginTag session={session} long />
            <p>
              <strong>{session.label}</strong> · {session.completeness.state === "complete" ? "complete" : "partial"}
              {session.sourcePath ? <> · <span className="mono">{session.sourcePath}</span></> : null}
            </p>
            <span className="demo-right mono">{warningTotal} warning(s)</span>
          </div>
        )}

        {view === "session" && (
          <>
            {session.warnings
              .filter((warning) => warning.code === "har.cookies_absent")
              .map((warning) => (
                <div className="body-flag flag-truncated warn-strip" role="alert" key={warning.code}>
                  <strong>HAR without cookies — cookie origin cannot be assessed</strong>
                  <span>
                    {warning.message} To assess cookies, use <strong>Start session</strong> (live CDP/NetLog capture).
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
                      <span className="rec-dot" /> recording
                    </span>
                  ) : (
                    <span className="tag tag-state">
                      {session.completeness.state === "complete" ? "complete session" : "partial session"}
                    </span>
                  )}
                  {isLargeDemo && <span className="tag">stress 12k</span>}
                </div>
                <div className="sid-meta mono">
                  {session.id} · {session.chromeVersion ?? "browser not reported"} · created{" "}
                  {fmtTime(session.createdAt)} · {requestCount} requests ·{" "}
                  {session.capture.mode ?? "mode not reported"}
                </div>
                {(() => {
                  const proxy = proxyHeaderView(session.capture.proxy);
                  if (!proxy) return null;
                  return (
                    <div className="sid-meta proxy-header" data-testid="session-proxy">
                      <span className="tag">proxy</span>{" "}
                      <span className="mono">{proxy.address}</span>
                      {proxy.authenticated ? " · authenticated (password not recorded)" : " · no credentials"}
                      {" · "}{proxy.routeText}
                      <span className="proxy-header-note" data-testid="session-proxy-note">{proxy.http3Note}</span>
                    </div>
                  );
                })()}
              </div>
              <div className="session-actions">
                <label className="start-url-field" htmlFor="scrapelens-start-url">
                  <span className="start-url-label">Start URL</span>
                  <input
                    id="scrapelens-start-url"
                    className="start-url-input mono"
                    type="url"
                    inputMode="url"
                    placeholder="http://127.0.0.1:8781/page"
                    value={startUrl}
                    disabled={!desktop || !!recording || !!busy}
                    aria-label="Capture start URL"
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
                <CookieSourceSelect
                  sources={cookieSources}
                  value={cookieSource}
                  startUrl={startUrl}
                  disabled={!desktop || !!recording || !!busy || !cookieSourcesReady}
                  onChange={(value) => {
                    setBusy("Saving cookie source…");
                    void bridge.setCaptureCookieSource(value || null).then((saved) => {
                      setCookieSource(saved ?? "");
                    }).catch((error) => {
                      setNotice({ kind: "error", text: "Could not save the cookie source.", detail: String(error) });
                    }).finally(() => setBusy(null));
                  }}
                />
                <ProxyField
                  state={proxyState}
                  draft={proxyDraft}
                  error={proxyError}
                  disabled={!desktop || !!recording || !!busy}
                  onDraftChange={(value) => {
                    setProxyDraft(value);
                    setProxyError(null);
                  }}
                  onApply={applyProxy}
                  onClear={clearProxy}
                />
                <button
                  id="scrapelens-start-session"
                  className="btn primary"
                  onClick={() => void startCapture()}
                  disabled={!desktop || !!recording || !!busy || !!startUrlError || !cookieSourcesReady || !!proxyStartBlock(proxyState, !!recording)}
                  aria-label="Start session"
                  title={
                    desktop
                      ? "Open Chrome with a dedicated profile and record CDP+NetLog — " + shortcutLabel("⌘⇧R")
                      : "Live capture is only available in the desktop app (Tauri)"
                  }
                >
                  Start session
                </button>
                <button
                  id="scrapelens-stop-session"
                  className="btn"
                  onClick={() => void stopCapture()}
                  disabled={!recording || !!busy}
                  aria-label="Stop session"
                  title={"Quit Chrome, wait for the NetLog flush, import with the core and open the session — " + shortcutLabel("⌘.")}
                >
                  Stop
                </button>
                <button
                  id="scrapelens-open-capture"
                  className="btn"
                  onClick={() => void openSession()}
                  disabled={!desktop || !!recording}
                  aria-label="Open capture"
                  title={
                    desktop
                      ? "Open a v1 session folder (session.json) with a native dialog — " + shortcutLabel("⌘O")
                      : `Open capture uses the ${NATIVE_DIALOG}; available in the Tauri app.`
                  }
                >
                  Open capture…
                </button>
                <button
                  className="btn"
                  onClick={() => setSanitizeOpen(true)}
                  disabled={!desktop || !session.sourcePath || !!recording || !!busy}
                  title={
                    !desktop
                      ? `Sanitizing uses the ${NATIVE_DIALOG} and is only available in the desktop app.`
                      : !session.sourcePath
                        ? "Sanitizing unavailable: this session has no persisted folder (demo or browser mode)."
                        : "Redact credentials across the whole session and write to a new folder; the source is not changed"
                  }
                >
                  Export / Sanitize…
                </button>
                <button
                  className="btn"
                  onClick={() => setView("timeline")}
                  disabled={!session.sourcePath || !!recording || !!busy}
                  title={session.sourcePath ? "Application events in order, without the protection noise" : "Timeline unavailable: this session has no persisted folder."}
                >
                  Timeline
                </button>
                <button
                  className="btn"
                  onClick={() => void validateExecution()}
                  disabled={!desktop || !session.sourcePath || !!recording || !!busy}
                  title={
                    !desktop
                      ? `Validate execution uses the ${NATIVE_DIALOG.replace("dialog", "picker")} and is only available in the desktop app.`
                      : "Imports the script's trace (--trace) and compares the execution with this capture; ScrapeLens runs nothing"
                  }
                >
                  Validate execution…
                </button>
              </div>
            </div>

            {recording && (
              <div className="recording-banner" id="scrapelens-recording-banner">
                <span className="rec-dot" />
                <strong>Recording with external Chrome</strong>
                <span>
                  session <span className="mono">{recording.sessionId}</span> · {recording.events} CDP event(s)
                  {proxyState?.active ? (
                    <span className="mono dim"> · proxy {proxyState.active.serverUrl}</span>
                  ) : null}
                  {recording.pageUrl ? (
                    <span className="mono dim"> · {recording.pageUrl}</span>
                  ) : null}
                </span>
                {(!recording.pageUrl || recording.pageUrl === "about:blank") && (
                  <span className="recording-blank-warn" role="status">
                    the capture started blank; browse in Chrome or enter a URL
                  </span>
                )}
                <span className="grow" />
                <button
                  id="scrapelens-stop-recording"
                  className="ghost-btn small"
                  onClick={() => void stopCapture()}
                  disabled={!!busy}
                  aria-label="Stop and open"
                >
                  Stop and open
                </button>
              </div>
            )}

            {cookieImportView && (
              <div
                className={`notice ${cookieImportView.tone === "warning" ? "notice-warn" : "notice-info"} cookie-import`}
                role="status"
              >
                <span className="notice-icon">{cookieImportView.tone === "warning" ? "!" : "i"}</span>
                <div>
                  <strong>{cookieImportView.title}</strong>
                  <span className="notice-detail"> {cookieImportView.detail}</span>
                  {cookieImportView.action && <span className="notice-detail"> {cookieImportView.action}</span>}
                </div>
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
                    Select Chrome…
                  </button>
                )}
                {notice.action === "open" && desktop && (
                  <button className="ghost-btn small" onClick={() => void openSession()}>
                    Choose another…
                  </button>
                )}
                {notice.action === "start" && desktop && (
                  <button className="ghost-btn small" onClick={() => void startCapture()}>
                    Try again
                  </button>
                )}
                <button className="icon-btn" onClick={() => setNotice(null)} title="Close notice">
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
                <span>Loading the list of {requestCount} requests…</span>
              </div>
            )}

            {desktop && chrome && !chrome.found && (
              <div className="notice notice-warn">
                <span className="notice-icon">!</span>
                <span>
                  {(() => {
                    const copy = chromeNotFoundCopy(chrome.candidates ?? []);
                    return (
                      <>
                        <strong>{copy.title}</strong> {copy.text}
                        {copy.detail && <span className="notice-detail mono"> {copy.detail}</span>}
                      </>
                    );
                  })()}
                </span>
                <button className="ghost-btn small" onClick={() => void chooseChrome()}>
                  Select Chrome…
                </button>
              </div>
            )}

            {desktop && chrome?.notice && (
              <div className="notice notice-warn" data-testid="chrome-notice">
                <span className="notice-icon">!</span>
                <span>{chrome.notice}</span>
                <button className="ghost-btn small" onClick={() => void chooseChrome()}>
                  Select Chrome…
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
                  placeholder="Search domain, path, id, status…"
                  aria-label="Search requests"
                />
                <kbd>{shortcutLabel("⌘F")}</kbd>
              </div>
              {searchToken && (
                <div className="search-opts" role="group" aria-label="Search scopes">
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
                    ["all", "All"],
                    ["fetch", "Fetch/XHR"],
                    ["document", "Document"],
                    ["media", "Media"],
                    ["error", "Errors 4xx/5xx"],
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
                  title="Responses with a declared application failure (app-error), even with HTTP 200"
                >
                  App failures
                  <span className="count">{failCount}</span>
                </button>
                <button
                  className={blockFilter ? "chip-filter active" : "chip-filter"}
                  disabled={outcomeChipDisabled(blockCount, blockFilter)}
                  onClick={() => setBlockFilter((v) => !v)}
                  title="Possible blocks (blocked?): evidence, not confirmation"
                >
                  Possible blocks?
                  <span className="count">{blockCount}</span>
                </button>
              </div>
              {showTargetColumn && (
                <div className="filters target-filters" aria-label="Filter by target type">
                  {TARGET_FILTERS.filter(
                    (f) => f.id === "all" || targetCount(f.id) > 0,
                  ).map((f) => (
                    <button
                      key={f.id}
                      className={targetFilter === f.id ? "chip-filter active" : "chip-filter"}
                      onClick={() => setTargetFilter(f.id)}
                      title="Filter by CDP target provenance"
                    >
                      {f.label}
                      <span className="count">{targetCount(f.id)}</span>
                    </button>
                  ))}
                </div>
              )}
              <label className="proto-select">
                <span>Protocol</span>
                <select value={protocol} onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
                  <option value="all">all</option>
                  <option value="HTTP/1.1">HTTP/1.1</option>
                  <option value="HTTP/2">HTTP/2</option>
                  <option value="HTTP/3">HTTP/3</option>
                  <option value="unknown">unknown</option>
                </select>
              </label>
              <div className="toolbar-actions">
                <button
                  id="scrapelens-import-har"
                  className="btn small"
                  onClick={() => void importCapture("har")}
                  disabled={!desktop || !!recording}
                  aria-label="Import HAR"
                  title={desktop ? "Import HAR — " + shortcutLabel("⌘⇧H") : "Import is only available in the desktop app"}
                >
                  HAR
                </button>
                <button
                  id="scrapelens-import-netlog"
                  className="btn small"
                  onClick={() => void importCapture("netlog")}
                  disabled={!desktop || !!recording}
                  aria-label="Import NetLog"
                  title={desktop ? "Import NetLog — " + shortcutLabel("⌘⇧N") : "Import is only available in the desktop app"}
                >
                  NetLog
                </button>
                <button
                  className="btn"
                  onClick={() => setView("compare")}
                  disabled={requestCount < 2}
                  title={requestCount < 2 ? "Two requests are required" : "Compare two requests"}
                >
                  Compare…
                </button>
                <button
                  className="btn"
                  onClick={() => void compareCaptures()}
                  disabled={!desktop || !session.sourcePath || !!recording}
                  title={session.sourcePath ? "Compare this capture with another session (folder)" : "Requires a session with a persisted folder"}
                >
                  Compare captures…
                </button>
              </div>
            </div>

            {searchText && (
              <div className="search-status" role="status">
                {!searchToken ? (
                  <span>Search covers metadata only (URL, id, status): payload search requires a real session open in the app.</span>
                ) : !searchResult && !searchState?.error ? (
                  <span>Searching payloads…</span>
                ) : searchState?.error ? (
                  <span className="err">Search failed: {searchState.error}</span>
                ) : searchResult ? (
                  <>
                    <span>
                      {searchResult.matches.length} match(es) in {matchesById.size} request(s)
                    </span>
                    {searchResult.limitReached && (
                      <span className="chip v-partial">limit reached: more matches are not listed</span>
                    )}
                    {searchResult.partial && (
                      <span className="chip v-partial" title={searchResult.partialAttempts.join(", ")}>
                        partial search: {searchResult.partialAttempts.length} truncated body(ies)
                      </span>
                    )}
                    {searchResult.skippedBinary > 0 && (
                      <span className="chip tag">{searchResult.skippedBinary} binary body(ies) not searched</span>
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
                    <th className="col-method">Method</th>
                    <th className="col-domain">Domain</th>
                    <th className="col-path">Path</th>
                    {showTargetColumn && <th className="col-target">Target</th>}
                    <th className="col-status">Status</th>
                    <th className="col-app" title="Application success (≠ HTTP status)">App</th>
                    <th className="col-proto">Protocol</th>
                    <th className="col-type">Type</th>
                    <th className="col-time num">Duration</th>
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
                      title="Open detail panel"
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
                            title={badge ?? "unknown target (NetLog only)"}
                          >
                            {badge ?? "unknown target (NetLog only)"}
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
                        <span className="proto" title={r.networkState ? NOT_SENT_TITLE : undefined}>{protocolText(r.protocol, r.networkState)}</span>
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
                            ? "This session has no requests."
                            : `No requests match the active filters: ${activeFilterLabels({ query, typeFilter, targetFilter, protocol, failFilter, blockFilter }).join(", ") || "none"}.`}
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
                            Clear search and filters
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
                {filteredLength} of {requestCount} requests
              </span>
              <span className="sep">·</span>
              <span>{visibleRows.length} rows rendered (virtualized)</span>
              <span className="sep">·</span>
              <span>{session.capture.mode ?? "source not reported"}</span>
              <span className="sep">·</span>
              <span>
                {session.completeness.state === "complete"
                  ? "complete session"
                  : `partial: ${session.completeness.reasons[0] ?? "reason not reported"}`}
              </span>
              <span className="grow" />
              <span className="mono dim">{`${shortcutLabel("⌘O")} open · ${shortcutLabel("⌘F")} search · ${shortcutLabel("⌘C")} copy · ${shortcutLabel("⌘⇧C")} URL`}</span>
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
            <strong>{remoteDetail?.error ? "Could not load the request." : "Loading the request…"}</strong>
            {remoteDetail?.error ? <span>{remoteDetail.error}</span> : null}
            <button className="link" onClick={() => setView("session")}>
              Back
            </button>
          </div>
        )}

        {view === "detail" && !selected && !detailPending && (
          <div className="empty big">
            <strong>Session has no requests.</strong>
            <span>session.json was read, but it contains no LogicalRequest.</span>
            <button className="link" onClick={() => setView("session")}>
              Back
            </button>
          </div>
        )}

        {view === "timeline" && (
          <TimelineView
            sessionToken={session.sourceToken}
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
            onSanitizeTrace={() => setSanitizeTrace({ path: validation.result.traceDir, token: validation.result.traceToken })}
            onKept={() => setValidation((v) => (v ? { ...v, kept: true } : v))}
            onRevalidate={(mapOrigin) => void validateExecution({ traceToken: validation.traceToken, tracePath: validation.tracePath, mapOrigin })}
          />
        )}

        {view === "capture-compare" && captureCmp && (
          <CaptureCompareView
            summary={captureCmp.summary}
            tokenA={captureCmp.tokenA}
            tokenB={captureCmp.tokenB}
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
            <strong>Comparison needs two requests.</strong>
            <span>This session has {requestCount}.</span>
            <button className="link" onClick={() => setView("session")}>
              Back
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

        {sanitizeTrace && (
          <SanitizeDialog
            session={{ ...session, id: "script-trace", sourcePath: sanitizeTrace.path, sourceToken: sanitizeTrace.token }}
            onClose={() => setSanitizeTrace(null)}
            onOpened={(payload) => {
              closeValidation(); // the sanitized session becomes the open one; the trace's temporary session is deleted
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
