// Comparação A × B entre duas capturas (compare::compare_sessions do core).
import { useMemo, useState } from "react";
import { dynamicOnly, fieldClassLabel, type FieldDiff, type PairComparison, type SessionComparison } from "./flow";

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

export function CaptureCompareView({
  result,
  labelA,
  labelB,
  onBack,
}: {
  result: SessionComparison;
  labelA: string;
  labelB: string;
  onBack: () => void;
}) {
  const [onlyDynamic, setOnlyDynamic] = useState(false);
  const pairs: PairComparison[] = useMemo(() => (onlyDynamic ? dynamicOnly(result.pairs) : result.pairs), [onlyDynamic, result]);
  const c = result.counts;
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
            {result.pairs.length} par(es) · {c.static} estático(s) · {c.dynamic} dinâmico(s) ({c.runtime} obter em runtime, {c.noOrigin} sem origem) · só em A {result.onlyInA.length} · só em B {result.onlyInB.length}
          </span>
          <label className="annotate-opt">
            <input type="checkbox" checked={onlyDynamic} onChange={(e) => setOnlyDynamic(e.target.checked)} /> só dinâmicos
          </label>
        </header>
        <div className="body-foot">
          “Obter em runtime” = a origem em B é uma resposta anterior de B (evidência indicada). Campos repetidos seguem a ordem da fonte.
        </div>
        {result.ambiguities.length > 0 && (
          <div className="body-flag flag-truncated">
            <strong>Ambiguidades no alinhamento ({result.ambiguities.length})</strong>
            <span>{result.ambiguities.join(" · ")}</span>
          </div>
        )}
        {result.redactedFields > 0 && (
          <div className="body-flag flag-truncated">
            <strong>{result.redactedFields} campo(s) redigido(s)</strong>
            <span>Valores redigidos não podem ser comparados nem rastreados.</span>
          </div>
        )}
        {result.warnings.map((warning, index) => (
          <div className="body-foot" key={index}>
            {warning}
          </div>
        ))}
      </section>
      {result.onlyInA.length > 0 && (
        <section className="body-panel">
          <header className="block-head">
            <h3>Só em A</h3>
          </header>
          <ul className="chain-list" style={{ padding: "0 13px" }}>
            {result.onlyInA.map((r) => (
              <li key={r.requestId}>
                <span className="mono">{r.method}</span> <span className="mono">{r.requestId}</span> <span className="mono dim">{r.url}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.onlyInB.length > 0 && (
        <section className="body-panel">
          <header className="block-head">
            <h3>Só em B</h3>
          </header>
          <ul className="chain-list" style={{ padding: "0 13px" }}>
            {result.onlyInB.map((r) => (
              <li key={r.requestId}>
                <span className="mono">{r.method}</span> <span className="mono">{r.requestId}</span> <span className="mono dim">{r.url}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {pairs.map((pair, index) => (
        <section className="cmp-pair" key={index}>
          <header>
            <span className="mono">{pair.a.method}</span>
            <span className="mono">A {pair.a.requestId}</span>
            <span className="sep">↔</span>
            <span className="mono">B {pair.b.requestId}</span>
            <span className="mono dim">{pair.a.url}</span>
            <span className="chip tag">alinhado por {pair.alignedBy}</span>
            {pair.outOfOrder && <span className="chip v-partial">fora de ordem</span>}
            <span className="dim">
              {pair.counts.static} est. · {pair.counts.dynamic} din.
            </span>
          </header>
          {pair.fields.map((field, fi) => (
            <FieldRow key={fi} field={field} />
          ))}
        </section>
      ))}
      {pairs.length === 0 && <div className="empty">Nenhum campo dinâmico encontrado nos pares alinhados.</div>}
    </div>
  );
}
