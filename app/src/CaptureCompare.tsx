// Comparison A × B between two captures (compare::compare_sessions of the core).
import { useEffect, useState } from "react";
import { bridge } from "./bridge";
import { VerdictChip, useAssess, type OutcomeMap } from "./assess";
import {
  DYNAMIC_ONLY_THRESHOLD,
  dynamicSummary,
  fieldClassLabel,
  roundHeader,
  visibleFields,
  type CompareSummary,
  type FieldDiff,
  type PairSummary,
  type RequestRef,
} from "./flow";

function FieldRow({ field }: { field: FieldDiff }) {
  const dynamic = field.class !== "static";
  return (
    <>
      <div className={dynamic ? "cmp-field cmp-dynamic" : "cmp-field"}>
        <div>
          <span className="chip mono">{field.scope}</span> <span className="mono">{field.field}</span>
          {field.occurrence > 0 ? <span className="dim"> #{field.occurrence + 1}</span> : null}
        </div>
        <div className="mono">{field.a ?? <span className="dim">—</span>}</div>
        <div className="mono">{field.b ?? <span className="dim">—</span>}</div>
        <div>
          <span title={fieldClassLabel(field)} className={`chip ${field.originLabel?.includes("possível") ? "possible" : dynamic ? "v-partial" : "tag"}`}>{fieldClassLabel(field)}</span>
          {field.origin && (
            <div className="dim">
              {field.origin.kind}
              {field.origin.ambiguous ? " · ambiguous" : ""}
            </div>
          )}
        </div>
      </div>
      {field.parts.map((part, index) => (
        <div key={index} className={part.class === "static" ? "cmp-field" : "cmp-field cmp-dynamic"} style={{ paddingLeft: 24 }}>
          <div className="dim">fragment @ {part.aOffset ?? "?"}/{part.bOffset ?? "?"}</div>
          <div className="mono">{part.a ?? "—"}</div>
          <div className="mono">{part.b ?? "—"}</div>
          <div>
            <span className="chip tag">{part.class === "static" ? "static" : part.originLabel || "dynamic without origin"}</span>
          </div>
        </div>
      ))}
    </>
  );
}

const PAGE_SIZE = 50;

function OnlyList({
  side,
  title,
  items,
  total,
  counterpart,
}: {
  title: string;
  items: RequestRef[];
  total: number;
  /** requestId on this side → request on the other side of the same model (reordering). */
  counterpart: Map<string, string>;
  side: "A" | "B";
}) {
  if (total === 0) return null;
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>
          {title} <span className="count">{total}</span>
        </h3>
      </header>
      <ul className="chain-list" style={{ padding: "0 13px" }}>
        {items.map((r) => (
          <li key={r.requestId} id={`only-${side}-${r.requestId}`}>
            <span className="mono">{r.method}</span> <span className="mono">{r.requestId}</span> <span className="mono dim">{r.url}</span>
            {(counterpart.has(r.requestId) || r.reordered || r.outOfOrder) && (
              <span className="chip possible" title="Leftover of the same model on both sides (core mark)">
                possibly the same request, in another order
                {counterpart.has(r.requestId) && (
                  <>
                    {" "}
                    (
                    <button
                      className="link-req mono"
                      title="Go to the matching request on the other side"
                      onClick={() =>
                        document
                          .getElementById(`only-${side === "A" ? "B" : "A"}-${counterpart.get(r.requestId)}`)
                          ?.scrollIntoView({ block: "center", behavior: "smooth" })
                      }
                    >
                      {side === "A" ? "B" : "A"} {counterpart.get(r.requestId)}
                    </button>
                    )
                  </>
                )}
              </span>
            )}
          </li>
        ))}
      </ul>
      {total > items.length && <div className="body-foot">Showing {items.length} of {total}.</div>}
    </section>
  );
}

function PairBlock({ handle, pair, onlyDynamic, outA, outB }: { handle: number; pair: PairSummary; onlyDynamic: boolean; outA?: OutcomeMap; outB?: OutcomeMap }) {
  const [open, setOpen] = useState(false);
  const [fields, setFields] = useState<FieldDiff[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!open || fields) return;
    let alive = true;
    bridge
      .compareFields(handle, pair.index)
      .then((result) => alive && setFields(result))
      .catch((reason) => alive && setError(String(reason)));
    return () => {
      alive = false;
    };
  }, [open, fields, handle, pair.index]);
  const shown = fields ? visibleFields(fields, onlyDynamic) : [];
  return (
    <section className="cmp-pair">
      <header>
        <button className="ghost-btn small" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? "▾" : "▸"} fields
        </button>
        <span className="mono">{pair.a.method}</span>
        <span className="mono">A {pair.a.requestId}</span>
        <span className="sep">↔</span>
        <span className="mono">B {pair.b.requestId}</span>
        <span className="mono dim">{pair.a.url}</span>
        {outA && outB && (
          <span title="Application success: A → B">
            app: <VerdictChip outcome={outA.get(pair.a.requestId)} /> → <VerdictChip outcome={outB.get(pair.b.requestId)} />
          </span>
        )}
        <span className="chip tag">aligned by {pair.alignedBy}</span>
        {pair.outOfOrder && <span className="chip v-partial">out of order</span>}
        <span className="dim">
          {pair.counts.static} static · {pair.counts.dynamic} dyn. · {pair.fieldCount} field(s)
        </span>
      </header>
      {open && error && <div className="empty">{error}</div>}
      {open && !fields && !error && <div className="empty">Loading fields…</div>}
      {open && fields && shown.length === 0 && <div className="empty">No dynamic fields in this pair.</div>}
      {open && shown.map((field, index) => <FieldRow key={index} field={field} />)}
    </section>
  );
}

export function CaptureCompareView({
  summary: initial,
  dirA,
  dirB,
  labelA,
  labelB,
  onBack,
}: {
  summary: CompareSummary;
  dirA: string;
  dirB: string;
  labelA: string;
  labelB: string;
  onBack: () => void;
}) {
  const assessA = useAssess(dirA);
  const assessB = useAssess(dirB);
  const [summary, setSummary] = useState(initial);
  const [includeAll, setIncludeAll] = useState(initial.includeAll ?? false);
  const [aRange, setARange] = useState("");
  const [bRange, setBRange] = useState("");
  const [recomputing, setRecomputing] = useState(false);
  const [optionError, setOptionError] = useState<string | null>(null);
  const [onlyDynamic, setOnlyDynamic] = useState(initial.pairs > DYNAMIC_ONLY_THRESHOLD);
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<{ total: number; items: PairSummary[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const recompare = async () => {
    setRecomputing(true);
    setOptionError(null);
    try {
      const next = await bridge.compareOpen(dirA, dirB, { includeAll, aRange, bRange });
      setSummary(next);
      setOffset(0);
      setOnlyDynamic(next.pairs > DYNAMIC_ONLY_THRESHOLD);
    } catch (reason) {
      setOptionError(String(reason));
    } finally {
      setRecomputing(false);
    }
  };

  useEffect(() => {
    setPage(null);
    setError(null);
    let alive = true;
    bridge
      .comparePage(summary.handle, offset, PAGE_SIZE, onlyDynamic)
      .then((result) => alive && setPage(result))
      .catch((reason) => alive && setError(String(reason)));
    return () => {
      alive = false;
    };
  }, [summary.handle, offset, onlyDynamic]);

  const c = summary.counts;
  const total = page?.total ?? 0;
  const rounds = summary.rounds ?? [];
  return (
    <div className="detail">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Session
        </button>
        <div className="crumbs">
          <span className="mono">A: {labelA}</span>
          <span className="sep">×</span>
          <span className="mono">B: {labelB}</span>
        </div>
      </div>
      <section className="body-panel">
        <header className="block-head">
          <h3>Comparison between captures</h3>
          <span className="block-meta">
            {summary.pairs} pair(s) · {c.static} static · {dynamicSummary(c, summary.partsCounts)} ({c.runtime} obtained at runtime, {c.noOrigin} without origin) · only in A {summary.onlyInATotal} · only in B {summary.onlyInBTotal}
          </span>
          <label className="annotate-opt">
            <input
              type="checkbox"
              checked={onlyDynamic}
              onChange={(e) => {
                setOffset(0);
                setOnlyDynamic(e.target.checked);
              }}
            />{" "}
            dynamic only ({summary.dynamicPairs} of {summary.pairs} pairs)
          </label>
        </header>
        <div className="cmp-options" role="group" aria-label="Comparison options">
          <label className="annotate-opt">
            <input type="checkbox" checked={includeAll} onChange={(e) => setIncludeAll(e.target.checked)} /> include everything (protection and static resources in the alignment)
          </label>
          <label className="annotate-opt">
            range A <input className="range-input mono" value={aRange} onChange={(e) => setARange(e.target.value)} placeholder="from:to (e.g.: 10:50)" aria-label="Range A" />
          </label>
          <label className="annotate-opt">
            range B <input className="range-input mono" value={bRange} onChange={(e) => setBRange(e.target.value)} placeholder="from:to" aria-label="Range B" />
          </label>
          <button className="btn small" disabled={recomputing} onClick={() => void recompare()}>
            {recomputing ? "Comparing…" : "Compare again"}
          </button>
          {optionError && <span className="err">{optionError}</span>}
        </div>
        <div className="body-foot">
          “Obtained at runtime” = the origin in B is an earlier response from B (evidence indicated; value-match is only coincidence). Repeated fields follow the source order. The fields of each pair load when expanded.
          {summary.pairs > DYNAMIC_ONLY_THRESHOLD && " Large comparison: “dynamic only” started on."}
          {summary.includeAll ? " Alignment with everything included." : " By default only the application is aligned; protection and static resources stay in the groups below."}
        </div>
        {summary.entryRequest && (
          <div className="body-foot">
            Rounds segmented by the entry request: <span className="mono">{summary.entryRequest}</span>. {rounds.length} paired round(s)
            {(summary.unpairedRounds?.length ?? 0) > 0 ? `, ${summary.unpairedRounds!.length} unpaired` : ""}.
          </div>
        )}
        {summary.ambiguities.length > 0 && (
          <div className="body-flag flag-truncated">
            <strong>Ambiguities in the alignment ({summary.ambiguities.length})</strong>
            <span>{summary.ambiguities.join(" · ")}</span>
          </div>
        )}
        {summary.redactedFields > 0 && (
          <div className="body-flag flag-truncated">
            <strong>{summary.redactedFields} redacted field(s)</strong>
            <span>Redacted values cannot be compared or traced.</span>
          </div>
        )}
        {summary.warnings.map((warning, index) => (
          <div className="body-foot" key={index}>
            {warning}
          </div>
        ))}
      </section>
      {(summary.unpairedRounds?.length ?? 0) > 0 && (
        <section className="body-panel">
          <header className="block-head">
            <h3>
              Unpaired rounds <span className="count">{summary.unpairedRounds!.length}</span>
            </h3>
          </header>
          <ul className="chain-list" style={{ padding: "0 13px" }}>
            {summary.unpairedRounds!.map((round, index) => (
              <li key={index}>
                <strong>
                  Round {round.round + 1} of {round.side}
                </strong>{" "}
                · {round.requests} request(s): <span className="mono">{round.first.requestId}</span> → <span className="mono">{round.last.requestId}</span>
                <div className="why">No similar round on the other side; not counted in “only in A/B”.</div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {(summary.groups ?? []).map((group) => (
        <details className="body-panel cmp-group" key={group.kind}>
          <summary>
            {group.kind === "protection" ? "Protection (/TSPD/ etc.)" : group.kind === "static" ? "Static resources" : group.kind} — outside the alignment · A {group.aTotal} · B {group.bTotal}
          </summary>
          <div className="cmp-group-cols">
            {([["A", group.a, group.aTotal], ["B", group.b, group.bTotal]] as const).map(([side, items, count]) => (
              <ul className="chain-list" key={side}>
                {items.map((r) => (
                  <li key={r.requestId}>
                    <span className="chip tag">{side}</span> <span className="mono">{r.method}</span> <span className="mono">{r.requestId}</span> <span className="mono dim">{r.url}</span>
                  </li>
                ))}
                {count > items.length && <li className="dim">+{count - items.length} not listed</li>}
              </ul>
            ))}
          </div>
        </details>
      ))}
      <OnlyList side="A" title="Only in A" items={summary.onlyInA} total={summary.onlyInATotal} counterpart={new Map((summary.reordered ?? []).map((pair) => [pair.a.requestId, pair.b.requestId]))} />
      <OnlyList side="B" title="Only in B" items={summary.onlyInB} total={summary.onlyInBTotal} counterpart={new Map((summary.reordered ?? []).map((pair) => [pair.b.requestId, pair.a.requestId]))} />
      {(summary.reorderedTotal ?? 0) > 0 && (
        <div className="body-foot" style={{ margin: "0 14px" }}>
          {summary.reorderedTotal} leftover(s) of the same model on both sides: possibly the same requests in another order (pairing stays monotonic).
        </div>
      )}
      <div className="cmp-pager">
        <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          ← Previous
        </button>
        <span className="dim">
          {total === 0 ? "0 pairs" : `pairs ${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}`}
        </span>
        <button className="btn small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Next →
        </button>
      </div>
      {error && <div className="empty">{error}</div>}
      {!page && !error && <div className="empty">Loading pairs…</div>}
      {page?.items.map((pair, index) => {
        const header = roundHeader(pair.round, index === 0 && offset === 0 ? undefined : page.items[index - 1]?.round ?? undefined, rounds);
        return (
          <div key={`${summary.handle}-${pair.index}-${onlyDynamic}`}>
            {header && <h4 className="cmp-round">{header}</h4>}
            <PairBlock handle={summary.handle} pair={pair} onlyDynamic={onlyDynamic} outA={assessA.map} outB={assessB.map} />
          </div>
        );
      })}
      {page && page.items.length === 0 && <div className="empty">No pair to show with this filter.</div>}
    </div>
  );
}
