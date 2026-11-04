// Application timeline (core: timeline::timeline) and script run validation
// (core: validate::validate, schema scrapelens.validate/1). The UI only shows what the core
// returns; labels (`event @ page`) and verdicts are core text, rendered escaped.
import { useEffect, useMemo, useState } from "react";
import { bridge, type TimelineDto, type ValidationResultDto } from "./bridge";
import { VerdictKindChip } from "./assess";
import type { RequestSummary } from "./types";
import { timelineTargetBadge } from "./target";

export function TimelineView({
  sessionDir,
  requests,
  onOpenRequest,
  onBack,
}: {
  sessionDir?: string;
  /** For the target badge (outside the main page); the timeline core does not send target. */
  requests?: RequestSummary[];
  onOpenRequest: (id: string) => void;
  onBack: () => void;
}) {
  const byId = useMemo(() => {
    const map = new Map<string, RequestSummary>();
    for (const r of requests ?? []) map.set(r.id, r);
    return map;
  }, [requests]);
  const [data, setData] = useState<TimelineDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setData(null);
    setError(null);
    if (!sessionDir) {
      setError("This session has no persisted folder; the timeline needs the session's files.");
      return;
    }
    let alive = true;
    bridge
      .sessionTimeline(sessionDir)
      .then((t) => alive && setData(t))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, [sessionDir]);

  let round = 0;
  return (
    <div className="timeline-view">
      <div className="breadcrumb">
        <button className="link" onClick={onBack}>← Session</button> <span className="dim">/ Timeline</span>
      </div>
      <h2>Application timeline</h2>
      {error && <div className="notice notice-error"><span className="notice-icon">!</span><span>{error}</span></div>}
      {!data && !error && <div className="empty">Calculating in Rust…</div>}
      {data && (
        <>
          <p className="dim">
            {data.counts.events} application event(s) · {data.rounds} round(s) · protection {data.counts.protection} · static {data.counts.static}.
            Click a row to open the request.
          </p>
          {data.warnings.map((w, i) => (
            <div className="notice notice-info" key={i}><span className="notice-icon">i</span><span>{w}</span></div>
          ))}
          <table className="norm-table timeline-table">
            <thead>
              <tr><th>Round</th><th>Event</th><th>Type</th><th>Status</th><th>Application</th><th>Consumed</th><th>Produced</th></tr>
            </thead>
            <tbody>
              {data.items.map((item, i) => {
                if (item.type === "group") {
                  return (
                    <tr key={i} className="timeline-group">
                      <td colSpan={7}>
                        <details>
                          <summary>
                            {item.kind === "protection" ? "Protection" : "Static resources"} <span className="count">{item.count}</span>
                          </summary>
                          <div className="chips">
                            {item.requestIds.map((id) => (
                              <button key={id} className="link mono" onClick={() => onOpenRequest(id)}>{id}</button>
                            ))}
                          </div>
                        </details>
                      </td>
                    </tr>
                  );
                }
                const header = item.round !== round;
                round = item.round;
                const targetLabel = timelineTargetBadge(byId.get(item.requestId));
                return (
                  <tr key={i} className="clickable" onClick={() => onOpenRequest(item.requestId)} title={`${item.method} ${item.url}`}>
                    <td>{header ? `round ${item.round}` : ""}</td>
                    <td>
                      <strong className="mono">{item.label}</strong>{" "}
                      <span className="dim mono">{item.requestId}</span>
                      {targetLabel ? (
                        <span className="chip tag target-chip" title="CDP target (≠ main page)">
                          {targetLabel}
                        </span>
                      ) : null}
                    </td>
                    <td><span className="chip tag">{item.kind}</span></td>
                    <td className="mono">{item.status ?? "—"}</td>
                    <td><VerdictKindChip kind={item.verdictKind} title={item.verdict} /></td>
                    <td>{item.consumed.map((n) => <span className="chip tag mono" key={n}>{n}</span>)}</td>
                    <td>{item.produced.map((n) => <span className="chip tag mono" key={n}>{n}</span>)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

/** Difference class, from the prefix of the reason returned by the core. */
const NOTE_CLASSES: [string, string, "ok" | "bad" | "info"][] = [
  ["parâmetro do usuário", "user parameter", "info"],
  ["esperado (parâmetro do usuário)", "user parameter", "info"],
  ["valor congelado", "frozen value", "bad"],
  ["origem diferente", "different origin", "bad"],
  ["valor sem origem no trace", "no origin in trace", "bad"],
];
function noteClass(reason: string): { label: string; tone: "ok" | "bad" | "info" } | null {
  const hit = NOTE_CLASSES.find(([prefix]) => reason.includes(prefix));
  return hit ? { label: hit[1], tone: hit[2] } : null;
}
function NoteItem({ n }: { n: { scope: string; field: string; reason: string } }) {
  const cls = noteClass(n.reason);
  return (
    <li>
      <span className="mono">{n.scope}:{n.field}</span>{" "}
      {cls && <span className={`chip ${cls.tone === "bad" ? "v-none" : "v-partial"}`}>{cls.label}</span>}{" "}
      <span className="dim">{n.reason}</span>
    </li>
  );
}

const verdictClass: Record<string, string> = {
  equivalent: "notice-success",
  diverges: "notice-error",
  incomplete: "notice-info",
};
/** An unknown verdict (the core may add reasons) counts as a divergence, never as success. */
const noticeClass = (verdict: string) => verdictClass[verdict] ?? "notice-error";

export function ValidationView({
  result,
  tracePath,
  onBack,
  onSanitizeTrace,
  onKept,
  onRevalidate,
}: {
  result: ValidationResultDto;
  tracePath: string;
  onBack: () => void;
  onSanitizeTrace: () => void;
  onKept: (path: string) => void;
  onRevalidate: (mapOrigin: string) => void;
}) {
  const v = result.validation;
  const [mapText, setMapText] = useState("");
  const needsMap = v.verdict !== "equivalent" && (v.reason ?? "").includes("--map-origin");
  const [kept, setKept] = useState<string | null>(null);
  const [keepError, setKeepError] = useState<string | null>(null);
  const keep = async () => {
    setKeepError(null);
    try {
      const path = await bridge.keepValidation(result.traceDir);
      if (path) {
        setKept(path);
        onKept(path);
      }
    } catch (error) {
      setKeepError(String(error));
    }
  };
  const problemSteps = v.steps.filter((s) => s.problem || s.unexpected.length > 0).length;
  return (
    <div className="validation-view">
      <div className="breadcrumb">
        <button className="link" onClick={onBack}>← Session</button> <span className="dim">/ Validate run</span>
      </div>
      <h2>Validate script run</h2>
      <div className={`notice ${noticeClass(v.verdict)}`} role="status">
        <span className="notice-icon">{v.verdict === "equivalent" ? "✓" : v.verdict === "incomplete" ? "…" : "!"}</span>
        <span><strong>{v.summary}</strong></span>
      </div>
      <div className="notice notice-info">
        <span className="notice-icon">i</span>
        <span>
          The trace contains the run's session data (cookies, values, bodies); do not share it without sanitizing. The imported session is kept in a
          private temporary folder, <strong>deleted when this screen is closed</strong> or the app quits{kept ? <>; it was saved to <span className="mono">{kept}</span></> : null}.{" "}
          {!kept && <button className="link" onClick={() => void keep()}>Keep this run…</button>}{" "}
          {!kept && <button className="link" onClick={onSanitizeTrace}>Sanitize the trace session…</button>}
        </span>
      </div>
      <p className="dim">Trace read from <span className="mono">{tracePath}</span>.</p>
      {keepError && <div className="notice notice-error"><span className="notice-icon">!</span><span>{keepError}</span></div>}
      {v.mappedOrigin && (
        <p className="dim">Mapped origin: <span className="mono">{v.mappedOrigin.from}</span> → <span className="mono">{v.mappedOrigin.to}</span> (the host swap in the run does not count as a difference).</p>
      )}
      {v.warnings.map((w, i) => {
        const invalid = w.startsWith("parâmetro inválido");
        return (
          <div className={`notice ${invalid ? "notice-error" : "notice-info"}`} key={i}>
            <span className="notice-icon">{invalid ? "!" : "i"}</span>
            <span>{invalid ? <><strong>Parameter ignored.</strong> {w}</> : w}</span>
          </div>
        );
      })}
      {needsMap && (
        <div className="notice notice-info">
          <span className="notice-icon">i</span>
          <span>
            The run's host is not loopback and was not mapped automatically. Enter <span className="mono">capture-origin=trace-origin</span>:{" "}
            <input
              className="mono"
              style={{ minWidth: 320 }}
              value={mapText}
              placeholder="https://sistema.gov.br=https://staging.exemplo.com"
              onChange={(e) => setMapText(e.target.value)}
            />{" "}
            <button className="btn" disabled={!mapText.trim()} onClick={() => onRevalidate(mapText.trim())}>Revalidate with this mapping</button>
          </span>
        </div>
      )}
      {v.missingInTrace.length > 0 && (
        <div className="notice notice-error"><span className="notice-icon">!</span><span>Capture steps with no match in the trace: <span className="mono">{v.missingInTrace.join(", ")}</span></span></div>
      )}
      <p className="dim">{v.steps.length} step(s) in the trace · {problemSteps} with a problem or unexpected difference.</p>
      <table className="norm-table validation-table">
        <thead>
          <tr><th>Step</th><th>Capture → trace</th><th>Status</th><th>Application (capture × trace)</th><th>Differences</th></tr>
        </thead>
        <tbody>
          {v.steps.map((s) => (
            <tr key={s.step} className={s.problem || (v.verdict === "incomplete" && v.step === s.step) ? "row-problem" : undefined}>
              <td>{s.step}</td>
              <td>
                <span className="mono">{s.captureRequestId ?? "— (extra step)"} → {s.traceRequestId}</span>
                <div className="dim mono" title={s.url}>{s.method} {s.url.replace(/^https?:\/\/[^/]+/, "")}</div>
              </td>
              <td className="mono">{s.statusCapture ?? "—"} × {s.statusTrace ?? "—"}</td>
              <td>
                {s.verdictCapture ? <VerdictKindChip kind={s.verdictCapture} /> : <span className="dim">—</span>}
                {" × "}
                <VerdictKindChip kind={s.verdictTrace} />
              </td>
              <td>
                {s.problem && <div className="body-flag flag-truncated"><strong>Diverge</strong><span>{s.problem}</span></div>}
                {s.unexpected.length > 0 && (
                  <details open>
                    <summary>unexpected ({s.unexpected.length})</summary>
                    <ul className="chain-list">
                      {s.unexpected.map((n, i) => <NoteItem key={i} n={n} />)}
                    </ul>
                  </details>
                )}
                {s.expected.length > 0 && (
                  <details open={s.expected.some((n) => n.reason.includes("parâmetro do usuário"))}>
                    <summary>expected ({s.expected.length})</summary>
                    <ul className="chain-list">
                      {s.expected.map((n, i) => <NoteItem key={i} n={n} />)}
                    </ul>
                  </details>
                )}
                {!s.problem && v.verdict === "incomplete" && v.step === s.step && (
                  <div className="body-flag flag-truncated"><strong>Incomplete: stopped here</strong><span>{v.reason}</span></div>
                )}
                {!s.problem && !(v.verdict === "incomplete" && v.step === s.step) && s.unexpected.length === 0 && s.expected.length === 0 && <span className="dim">no differences</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
