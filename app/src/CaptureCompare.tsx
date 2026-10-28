// Comparação A × B entre duas capturas (compare::compare_sessions do core).
import { useEffect, useState } from "react";
import { bridge } from "./bridge";
import {
  DYNAMIC_ONLY_THRESHOLD,
  dynamicSummary,
  fieldClassLabel,
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
          <span className={`chip ${dynamic ? "v-partial" : "tag"}`}>{fieldClassLabel(field)}</span>
          {field.origin && (
            <div className="dim">
              {field.origin.kind}
              {field.origin.ambiguous ? " · ambíguo" : ""}
            </div>
          )}
        </div>
      </div>
      {field.parts.map((part, index) => (
        <div key={index} className={part.class === "static" ? "cmp-field" : "cmp-field cmp-dynamic"} style={{ paddingLeft: 24 }}>
          <div className="dim">trecho @ {part.aOffset ?? "?"}/{part.bOffset ?? "?"}</div>
          <div className="mono">{part.a ?? "—"}</div>
          <div className="mono">{part.b ?? "—"}</div>
          <div>
            <span className="chip tag">{part.class === "static" ? "estático" : part.originLabel || "dinâmico sem origem"}</span>
          </div>
        </div>
      ))}
    </>
  );
}

const PAGE_SIZE = 50;

function OnlyList({ title, items, total }: { title: string; items: RequestRef[]; total: number }) {
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
          <li key={r.requestId}>
            <span className="mono">{r.method}</span> <span className="mono">{r.requestId}</span> <span className="mono dim">{r.url}</span>
          </li>
        ))}
      </ul>
      {total > items.length && <div className="body-foot">Mostrando {items.length} de {total}.</div>}
    </section>
  );
}

function PairBlock({ handle, pair, onlyDynamic }: { handle: number; pair: PairSummary; onlyDynamic: boolean }) {
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
          {open ? "▾" : "▸"} campos
        </button>
        <span className="mono">{pair.a.method}</span>
        <span className="mono">A {pair.a.requestId}</span>
        <span className="sep">↔</span>
        <span className="mono">B {pair.b.requestId}</span>
        <span className="mono dim">{pair.a.url}</span>
        <span className="chip tag">alinhado por {pair.alignedBy}</span>
        {pair.outOfOrder && <span className="chip v-partial">fora de ordem</span>}
        <span className="dim">
          {pair.counts.static} est. · {pair.counts.dynamic} din. · {pair.fieldCount} campo(s)
        </span>
      </header>
      {open && error && <div className="empty">{error}</div>}
      {open && !fields && !error && <div className="empty">Carregando campos…</div>}
      {open && fields && shown.length === 0 && <div className="empty">Sem campos dinâmicos neste par.</div>}
      {open && shown.map((field, index) => <FieldRow key={index} field={field} />)}
    </section>
  );
}

export function CaptureCompareView({
  summary,
  labelA,
  labelB,
  onBack,
}: {
  summary: CompareSummary;
  labelA: string;
  labelB: string;
  onBack: () => void;
}) {
  const [onlyDynamic, setOnlyDynamic] = useState(summary.pairs > DYNAMIC_ONLY_THRESHOLD);
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<{ total: number; items: PairSummary[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

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
  return (
    <div className="detail">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Sessão
        </button>
        <div className="crumbs">
          <span className="mono">A: {labelA}</span>
          <span className="sep">×</span>
          <span className="mono">B: {labelB}</span>
        </div>
      </div>
      <section className="body-panel">
        <header className="block-head">
          <h3>Comparação entre capturas</h3>
          <span className="block-meta">
            {summary.pairs} par(es) · {c.static} estático(s) · {dynamicSummary(c, summary.partsCounts)} ({c.runtime} obter em runtime, {c.noOrigin} sem origem) · só em A {summary.onlyInATotal} · só em B {summary.onlyInBTotal}
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
            só dinâmicos ({summary.dynamicPairs} de {summary.pairs} pares)
          </label>
        </header>
        <div className="body-foot">
          “Obter em runtime” = a origem em B é uma resposta anterior de B (evidência indicada; value-match é só coincidência). Campos repetidos seguem a ordem da fonte. Os campos de cada par carregam ao expandir.
          {summary.pairs > DYNAMIC_ONLY_THRESHOLD && " Comparação grande: “só dinâmicos” começou ligado."}
        </div>
        {summary.ambiguities.length > 0 && (
          <div className="body-flag flag-truncated">
            <strong>Ambiguidades no alinhamento ({summary.ambiguities.length})</strong>
            <span>{summary.ambiguities.join(" · ")}</span>
          </div>
        )}
        {summary.redactedFields > 0 && (
          <div className="body-flag flag-truncated">
            <strong>{summary.redactedFields} campo(s) redigido(s)</strong>
            <span>Valores redigidos não podem ser comparados nem rastreados.</span>
          </div>
        )}
        {summary.warnings.map((warning, index) => (
          <div className="body-foot" key={index}>
            {warning}
          </div>
        ))}
      </section>
      <OnlyList title="Só em A" items={summary.onlyInA} total={summary.onlyInATotal} />
      <OnlyList title="Só em B" items={summary.onlyInB} total={summary.onlyInBTotal} />
      <div className="cmp-pager">
        <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          ← Anteriores
        </button>
        <span className="dim">
          {total === 0 ? "0 pares" : `pares ${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} de ${total}`}
        </span>
        <button className="btn small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Próximos →
        </button>
      </div>
      {error && <div className="empty">{error}</div>}
      {!page && !error && <div className="empty">Carregando pares…</div>}
      {page?.items.map((pair) => (
        <PairBlock key={`${summary.handle}-${pair.index}-${onlyDynamic}`} handle={summary.handle} pair={pair} onlyDynamic={onlyDynamic} />
      ))}
      {page && page.items.length === 0 && <div className="empty">Nenhum par para exibir com este filtro.</div>}
    </div>
  );
}
