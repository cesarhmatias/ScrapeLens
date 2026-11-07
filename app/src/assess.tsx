// Application success × HTTP (core: assess::assess_session, schema scrapelens.assess/1).
// The UI only shows the core's verdict; nothing is inferred here.
import { useEffect, useMemo, useState } from "react";
import { bridge } from "./bridge";

/** Core verdict (`VerdictKind`, kebab-case). `not-assessed` since core 306e8f5. */
export type VerdictKind = "app-ok" | "app-error" | "blocked" | "undetermined" | "not-assessed";

/**
 * Canonical verdict key for a value read from core output. Legacy `indeterminado`
 * (sessions and cores before the rename) maps to `undetermined`.
 */
export function normalizeVerdictKind(kind: string): VerdictKind {
  return (kind === "indeterminado" ? "undetermined" : kind) as VerdictKind;
}

export interface AppSignal {
  signal: string;
  kind: "ok" | "error" | "protection" | "missing" | "info" | string;
  detail: string;
}

export interface ResponseOutcome {
  requestId: string;
  method: string;
  url: string;
  status: number | null;
  httpOk: boolean;
  appSignals: AppSignal[];
  verdict: string;
  verdictKind: VerdictKind;
  missingFields: string[];
  reason?: string;
}

export interface AssessResult {
  schema: string;
  rules: string;
  /** Keys equal to the core's `verdictKind` (`VerdictKind::count_key()`). */
  counts: Record<string, number>;
  /** Rule warnings (`AssessRules::warnings()`); absent in older cores. */
  warnings?: string[];
  outcomes: ResponseOutcome[];
}

/** Keys of `counts` in the `scrapelens.assess/1` schema (no `Debug`). */
export const VERDICT_KINDS: readonly VerdictKind[] = [
  "app-ok",
  "app-error",
  "blocked",
  "undetermined",
  "not-assessed",
];

/** Counts per verdict; keys outside the schema are ignored. Legacy keys are folded into their canonical verdict. */
export function verdictCounts(counts: Record<string, number> | undefined): Record<VerdictKind, number> {
  const out = Object.fromEntries(VERDICT_KINDS.map((kind) => [kind, 0])) as Record<VerdictKind, number>;
  for (const [key, n] of Object.entries(counts ?? {})) {
    const kind = normalizeVerdictKind(key);
    if (VERDICT_KINDS.includes(kind)) out[kind] += n;
  }
  return out;
}

export type OutcomeMap = Map<string, ResponseOutcome>;

/** Applies `normalizeVerdictKind` to the outcomes of a core assessment (counts are folded by `verdictCounts`). */
function normalizeAssessResult(result: AssessResult): AssessResult {
  return {
    ...result,
    outcomes: result.outcomes?.map((o) => ({ ...o, verdictKind: normalizeVerdictKind(o.verdictKind) })),
  };
}

const SHORT: Record<VerdictKind, string> = {
  "app-ok": "app-ok",
  "app-error": "app-error",
  blocked: "blocked?",
  undetermined: "undetermined",
  "not-assessed": "not assessed",
};
const CLASS: Record<VerdictKind, string> = {
  "app-ok": "v-ok",
  "app-error": "v-none",
  blocked: "v-none dashed",
  undetermined: "v-partial",
  "not-assessed": "tag dim",
};

/** Application failure = app-error (asserted; HTTP may have been 200). */
export const isAppFailure = (o: ResponseOutcome | undefined) => o?.verdictKind === "app-error";

/** Possible block = blocked? (not asserted). */
export const isPossibleBlock = (o: ResponseOutcome | undefined) => o?.verdictKind === "blocked";

export function VerdictChip({ outcome }: { outcome: ResponseOutcome | undefined }) {
  if (!outcome) return <span className="dim">—</span>;
  const kind = outcome.verdictKind;
  if (kind === "not-assessed") {
    return (
      <span className="dim" title={outcome.verdict}>
        {SHORT[kind]}
      </span>
    );
  }
  return (
    <span className={`chip ${CLASS[kind] ?? "tag"}`} title={outcome.verdict}>
      {SHORT[kind] ?? outcome.verdict}
    </span>
  );
}

/** Chip for a loose `verdictKind` (timeline and validation). */
export function VerdictKindChip({ kind: rawKind, title }: { kind: VerdictKind; title?: string }) {
  const kind = normalizeVerdictKind(rawKind);
  if (kind === "not-assessed") return <span className="dim" title={title}>{SHORT[kind]}</span>;
  return <span className={`chip ${CLASS[kind] ?? "tag"}`} title={title}>{SHORT[kind] ?? kind}</span>;
}

/** Loads the session's assessment (cached in Rust); `undefined` without a persisted folder. */
export function useAssess(token: string | undefined, enabled = true) {
  const [state, setState] = useState<{ token: string; result?: AssessResult; error?: string } | null>(null);
  useEffect(() => {
    if (!token || !enabled) {
      setState(null);
      return;
    }
    let alive = true;
    bridge
      .assessSession(token)
      .then((result) => alive && setState({ token, result: normalizeAssessResult(result) }))
      .catch((error) => alive && setState({ token, error: String(error) }));
    return () => {
      alive = false;
    };
  }, [token, enabled]);
  const current = state && state.token === token ? state : null;
  const map = useMemo<OutcomeMap>(
    () => new Map((current?.result?.outcomes ?? []).map((o) => [o.requestId, o])),
    [current?.result],
  );
  return { map, result: current?.result, error: current?.error, loading: Boolean(token && enabled && !current) };
}

const signalLabel: Record<string, string> = {
  ok: "success signal",
  error: "application error",
  protection: "protection",
  missing: "missing field",
  info: "note",
};

/** Warnings from `assess-rules.json` highlighted (rules that zero out detections, `/` as protection, empty marker). */
export function AssessWarnings({ warnings }: { warnings?: string[] }) {
  if (!warnings || warnings.length === 0) return null;
  return (
    <div className="body-flag flag-truncated" role="alert">
      <strong>Assessment rules (assess-rules.json) with a problem</strong>
      <ul className="chain-list">
        {warnings.map((w, i) => <li key={i}>{w}</li>)}
      </ul>
    </div>
  );
}

export function AppSuccessSection({ outcome, error, loading, warnings }: { outcome?: ResponseOutcome; error?: string; loading?: boolean; warnings?: string[] }) {
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>Application success</h3>
        <span className="block-meta">HTTP is not application success · core verdict</span>
      </header>
      <AssessWarnings warnings={warnings} />
      {error && <div className="body-flag flag-truncated"><strong>Assessment unavailable</strong><span>{error}</span></div>}
      {!error && !outcome && <div className="empty">{loading ? "Assessing…" : "No assessment: requires an open session from the persisted folder."}</div>}
      {outcome && (
        <div style={{ padding: "8px 13px" }}>
          <p>
            <span className={`chip ${outcome.httpOk ? "v-ok" : "v-none"}`}>HTTP {outcome.status ?? "?"}</span>{" "}
            <VerdictChip outcome={outcome} /> <strong className="mono">{outcome.verdict}</strong>
          </p>
          {outcome.httpOk && (outcome.verdictKind === "app-error" || outcome.verdictKind === "blocked") && (
            <div className="body-flag flag-truncated">
              <strong>HTTP succeeded, but the application did not succeed</strong>
              <span>
                {outcome.verdictKind === "blocked"
                  ? `possible block (not asserted) — evidence: ${evidenceText(outcome)}`
                  : `the response carries an application error — evidence: ${evidenceText(outcome)}`}
              </span>
            </div>
          )}
          {outcome.verdictKind === "blocked" && !(outcome.httpOk) && (
            <p className="dim">blocked? — evidence: {evidenceText(outcome)}</p>
          )}
          {outcome.reason && <p><strong>Reason:</strong> {outcome.reason}</p>}
          <h4>Signals ({outcome.appSignals.length})</h4>
          {outcome.appSignals.length === 0 ? (
            <p className="dim">No application signal in this response.</p>
          ) : (
            <ul className="chain-list">
              {outcome.appSignals.map((s, i) => (
                <li key={i}>
                  <span className="chip tag">{signalLabel[s.kind] ?? s.kind}</span> <span className="mono">{s.signal}</span>
                  {s.detail && <div className="why">{s.detail}</div>}
                </li>
              ))}
            </ul>
          )}
          {outcome.missingFields.length > 0 && (
            <>
              <h4>Missing fields ({outcome.missingFields.length})</h4>
              <p className="mono">{outcome.missingFields.join(", ")}</p>
              <p className="dim">Expected because the same route brought them in other responses of this session (or by the rules).</p>
            </>
          )}
        </div>
      )}
    </section>
  );
}

function evidenceText(o: ResponseOutcome): string {
  const protection = o.appSignals.filter((s) => s.kind === "protection" || s.kind === "error");
  const used = protection.length ? protection : o.appSignals;
  return used.length ? used.map((s) => (s.detail ? `${s.signal} (${s.detail})` : s.signal)).join("; ") : o.verdict;
}
