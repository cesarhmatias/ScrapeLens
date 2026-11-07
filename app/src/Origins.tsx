// "Origin" tab: where each value of the request came from and the priming chain.
// Everything comes from the core (flow::value_origins / priming_chain); the UI infers nothing.
import { useEffect, useMemo, useState } from "react";
import { bridge } from "./bridge";
import { VerdictChip, type OutcomeMap } from "./assess";
import {
  CONTEXT_LABEL,
  evidenceLabels,
  highlightedWarnings,
  isCookiesAbsent,
  partialCompositionText,
  producerKindLabel,
  groupOrigins,
  originConfidence,
  stepConfidence,
  oldestEvidence,
  originStatusLabel,
  strengthLabels,
  type ChainStep,
  type Evidence,
  type PrimingChain,
  type ValueOrigin,
  type ValueOrigins,
} from "./flow";

const scopeLabel: Record<string, string> = {
  header: "header",
  cookie: "cookie",
  query: "query",
  body: "body",
};

function ReqLink({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  return (
    <button className="link-req mono" onClick={() => onOpen(id)} title="Open the producing request">
      {id}
    </button>
  );
}

function EvidenceItem({ ev, onOpen, oldest }: { ev: Evidence; onOpen: (id: string) => void; oldest: boolean }) {
  return (
    <div className="cand">
      <ReqLink id={ev.producerRequestId} onOpen={onOpen} />{" "}
      <span className={`chip ${ev.strength === "strong" ? "v-ok" : "v-partial"}`} title={evidenceLabels[ev.kind] ?? ev.kind}>
        {ev.kind} · {strengthLabels[ev.strength] ?? ev.strength}
      </span>{" "}
      {producerKindLabel(ev) && <span className="chip tag">{producerKindLabel(ev)}</span>}{" "}
      <span className="dim">
        {ev.role === "produced" ? "produced" : ev.role === "reissued" ? "reappeared" : ev.role}
        {ev.field ? ` in ${ev.scope}:${ev.field}` : ` in ${ev.scope}`}
        {ev.producerOffset !== null ? ` · byte ${ev.producerOffset}` : ""}
      </span>
      {oldest && <span className="chip tag"> oldest</span>}
    </div>
  );
}

function OriginRow({ value, part, onOpen }: { value: ValueOrigin; part?: boolean; onOpen: (id: string) => void }) {
  const oldest = oldestEvidence(value);
  const confidence = originConfidence(value);
  const ambiguous = value.status === "ambiguous";
  return (
    <tr className={part ? "part" : undefined}>
      <td>
        {part ? "↳ " : ""}
        <span className="chip mono">{scopeLabel[value.scope] ?? value.scope}</span> <span className="mono">{value.field}</span>
        {value.occurrence > 0 ? <span className="dim"> #{value.occurrence + 1}</span> : null}
        {value.offset !== null ? <div className="dim">offset {value.offset}</div> : null}
      </td>
      <td className="val">{value.value === "" ? <span className="dim">(empty)</span> : value.value}</td>
      <td>
        {confidence === "possible" ? (
          <span className="chip possible" title="Only medium evidence (value-match or generic same-field): value coincidence, not proof of origin">
            {originStatusLabel(value)}
          </span>
        ) : confidence === "strong" ? (
          <span className="chip strong">{originStatusLabel(value)}</span>
        ) : (
          originStatusLabel(value)
        )}
        {ambiguous && <div className="chip v-partial">ambiguous: {value.evidences.length} candidates</div>}
        {value.status === "none" || value.status === "repeated" ? (
          <div className="dim">neutral: may be a constant, user input or a value generated on the client</div>
        ) : null}
        {value.repeatedFrom.length > 0 && (
          <div className="dim">
            already circulated in{" "}
            {value.repeatedFrom.map((id) => (
              <span key={id}>
                <ReqLink id={id} onOpen={onOpen} />{" "}
              </span>
            ))}
          </div>
        )}
        {partialCompositionText(value) && <div className="dim">{partialCompositionText(value)}</div>}
        {value.context && value.context.length > 0 && (
          <div className="dim" title="Neutral: neither a producer nor a chain step">
            {CONTEXT_LABEL} ({value.context.map((c) => `${c.requestId}${c.field ? `:${c.field}` : ""}`).join(", ")})
          </div>
        )}
        {value.unobservable && value.unobservable.length > 0 && (
          <div className="dim">
            not observable (earlier response without body):{" "}
            {value.unobservable.map((item, index) => (
              <span key={index}>
                {index > 0 ? "; " : ""}
                {item.requestId} ({item.state}
                {item.reason ? `: ${item.reason}` : ""})
                {item.suggestion ? (
                  <>
                    {" · "}
                    <button className="link-req mono" onClick={() => onOpen(item.suggestion!)} title="Open the equivalent occurrence with an observable body">
                      equivalent occurrence with body ({item.suggestion})
                    </button>
                  </>
                ) : null}
              </span>
            ))}
          </div>
        )}
      </td>
      <td>
        {value.evidences.map((ev, index) => (
          <EvidenceItem key={index} ev={ev} onOpen={onOpen} oldest={value.evidences.length > 1 && oldest === ev} />
        ))}
      </td>
    </tr>
  );
}

function StepItem({ step, index, onOpen, verdicts }: { step: ChainStep; index?: number; onOpen: (id: string) => void; verdicts?: OutcomeMap }) {
  return (
    <li className={step.class === "protection" ? "chain-protection" : undefined}>
      {index !== undefined && <strong>{index + 1}. </strong>}
      <span className="mono">{step.method}</span> <ReqLink id={step.requestId} onOpen={onOpen} />{" "}
      {step.class === "application" && (
        <span className={`chip ${stepConfidence(step) === "strong" ? "strong" : "possible"}`}>
          {stepConfidence(step) === "strong" ? "strong confidence" : "possible"}
        </span>
      )}{" "}
      {verdicts && <span title="Application success at this step"><VerdictChip outcome={verdicts.get(step.requestId)} /> </span>}
      <span className="mono dim">{step.url}</span>
      <div className="why">
        {step.reasons.length === 0
          ? step.reason
          : [...new Set(step.reasons.map((r) => `${r.field} → ${r.consumedBy} (${r.kind}, ${strengthLabels[r.strength] ?? r.strength})`))]
              .slice(0, 12)
              .join(" · ")}
      </div>
    </li>
  );
}

export function ChainPanel({ chain, onOpen, verdicts }: { chain: PrimingChain; onOpen: (id: string) => void; verdicts?: OutcomeMap }) {
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>Priming chain</h3>
        <span className="block-meta">
          minimum requests, in flow order, that precede {chain.requestId}
        </span>
      </header>
      <div className="body-foot">
        Derived from core evidence (does not prove causality); it is not an executable script. <strong>strong confidence</strong> = there is strong evidence
        (cookie-jar / non-generic same-field); <strong>possible</strong> = value coincidence only (value-match).
      </div>
      <ol className="chain-list" style={{ padding: "0 13px" }}>
        {chain.steps.map((step, index) => (
          <StepItem key={step.requestId} step={step} index={index} onOpen={onOpen} verdicts={verdicts} />
        ))}
        {chain.steps.length === 0 && <li>No earlier request provides values to this one.</li>}
      </ol>
      {chain.pages && chain.pages.length > 0 && (
        <div style={{ padding: "0 13px" }}>
          <h4>Context pages (loaded the page from which the steps were issued; they produce no values)</h4>
          <ol className="chain-list">
            {chain.pages.map((step) => (
              <StepItem key={step.requestId} step={step} onOpen={onOpen} verdicts={verdicts} />
            ))}
          </ol>
        </div>
      )}
      {chain.auxiliaryPages && chain.auxiliaryPages.length > 0 && (
        <details style={{ padding: "0 13px" }}>
          <summary>
            Auxiliary frames <span className="count">{chain.auxiliaryPages.length}</span>{" "}
            <span className="dim">(loaded by parser: *_JLIBS, cscform, about:blank; they produce no values)</span>
          </summary>
          <ol className="chain-list">
            {chain.auxiliaryPages.map((step) => (
              <StepItem key={step.requestId} step={step} onOpen={onOpen} verdicts={verdicts} />
            ))}
          </ol>
        </details>
      )}
      {chain.protection.length > 0 && (
        <div style={{ padding: "0 13px" }}>
          <h4>Protection (not application logic)</h4>
          <ol className="chain-list">
            {chain.protection.map((step) => (
              <StepItem key={step.requestId} step={step} onOpen={onOpen} verdicts={verdicts} />
            ))}
          </ol>
        </div>
      )}
      {chain.unresolved.length > 0 && (
        <div style={{ padding: "0 13px 10px" }}>
          <h4>
            No observed origin <span className="count">{chain.unresolved.length}</span>
          </h4>
          <ul className="chain-list">
            {chain.unresolved.map((item, index) => (
              <li key={index}>
                <span className="chip mono">{scopeLabel[item.scope] ?? item.scope}</span> <span className="mono">{item.field}</span>
                <div className="why">{item.label}</div>
              </li>
            ))}
          </ul>
        </div>
      )}
      {chain.redactedValues > 0 && (
        <div className="body-foot">{chain.redactedValues} redacted value(s) cannot be traced.</div>
      )}
    </section>
  );
}

function WarningStrip({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="body-flag flag-truncated" role="alert">
      <strong>Analysis warnings ({warnings.length})</strong>
      {warnings.map((warning, index) => (
        <span key={index}>
          {isCookiesAbsent(warning) ? "⚠ " : ""}
          {warning}
        </span>
      ))}
    </div>
  );
}

export function OriginsTab({
  sessionToken,
  requestId,
  onOpen,
  verdicts,
}: {
  sessionToken?: string;
  requestId: string;
  onOpen: (id: string) => void;
  verdicts?: OutcomeMap;
}) {
  const [origins, setOrigins] = useState<ValueOrigins | null>(null);
  const [chain, setChain] = useState<PrimingChain | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setOrigins(null);
    setChain(null);
    setError(null);
    if (!sessionToken) return;
    let alive = true;
    bridge
      .requestOrigins(sessionToken, requestId)
      .then((result) => alive && setOrigins(result))
      .catch((reason) => alive && setError(String(reason)));
    bridge
      .requestChain(sessionToken, requestId)
      .then((result) => alive && setChain(result))
      .catch((reason) => alive && setError((current) => current ?? String(reason)));
    return () => {
      alive = false;
    };
  }, [sessionToken, requestId]);

  const groups = useMemo(() => (origins ? groupOrigins(origins.values) : []), [origins]);

  if (!sessionToken) {
    return <div className="empty">Value origins require a session with a persisted folder (open a capture or import a file).</div>;
  }
  if (error) {
    return (
      <div className="empty">
        <strong>Could not compute the origin.</strong>
        <br />
        {error}
      </div>
    );
  }
  if (!origins) return <div className="empty">Computing origins…</div>;

  return (
    <>
      <WarningStrip warnings={highlightedWarnings(origins.warnings, chain?.warnings)} />
      <section className="body-panel">
        <header className="block-head">
          <h3>Value origins</h3>
          <span className="block-meta">{origins.values.length} value(s) consumed by {origins.requestId}</span>
        </header>
        <div className="body-foot">
          The evidence type shows its strength: <strong>cookie-jar</strong> and <strong>same-field</strong> are strong; <strong>value-match</strong>{" "}
          is only value coincidence (medium) — not proof of cause. “No observed origin” does not mean an error.
        </div>
        <table className="origin-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Value</th>
              <th>Status</th>
              <th>Evidence / producer</th>
            </tr>
          </thead>
          <tbody>
            {groups.flatMap((group, gi) => [
              <OriginRow key={`g${gi}`} value={group.top} onOpen={onOpen} />,
              ...group.parts.map((part, pi) => <OriginRow key={`g${gi}p${pi}`} value={part} part onOpen={onOpen} />),
            ])}
          </tbody>
        </table>
        {origins.redactedValues > 0 && (
          <div className="body-foot">{origins.redactedValues} redacted value(s) (sanitization) cannot be traced.</div>
        )}
        {origins.ties.length > 0 && (
          <div className="body-foot">Attempts with the same start time, excluded as producers: {origins.ties.join(", ")}.</div>
        )}
      </section>
      {chain ? <ChainPanel chain={chain} onOpen={onOpen} verdicts={verdicts} /> : <div className="empty">Computing chain…</div>}
    </>
  );
}
