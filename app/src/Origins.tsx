// Aba "Origem": de onde veio cada valor da requisição e a cadeia de priming.
// Tudo vem do core (flow::value_origins / priming_chain); a UI não infere nada.
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
  body: "corpo",
};

function ReqLink({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  return (
    <button className="link-req mono" onClick={() => onOpen(id)} title="Abrir a requisição produtora">
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
        {ev.role === "produced" ? "produziu" : ev.role === "reissued" ? "reapareceu" : ev.role}
        {ev.field ? ` em ${ev.scope}:${ev.field}` : ` em ${ev.scope}`}
        {ev.producerOffset !== null ? ` · byte ${ev.producerOffset}` : ""}
      </span>
      {oldest && <span className="chip tag"> mais antigo</span>}
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
      <td className="val">{value.value === "" ? <span className="dim">(vazio)</span> : value.value}</td>
      <td>
        {confidence === "possible" ? (
          <span className="chip possible" title="Só evidência média (value-match ou same-field genérico): coincidência de valor, não prova de origem">
            {originStatusLabel(value)}
          </span>
        ) : confidence === "strong" ? (
          <span className="chip strong">{originStatusLabel(value)}</span>
        ) : (
          originStatusLabel(value)
        )}
        {ambiguous && <div className="chip v-partial">ambíguo: {value.evidences.length} candidatos</div>}
        {value.status === "none" || value.status === "repeated" ? (
          <div className="dim">neutro: pode ser constante, entrada do usuário ou valor gerado no cliente</div>
        ) : null}
        {value.repeatedFrom.length > 0 && (
          <div className="dim">
            já circulava em{" "}
            {value.repeatedFrom.map((id) => (
              <span key={id}>
                <ReqLink id={id} onOpen={onOpen} />{" "}
              </span>
            ))}
          </div>
        )}
        {partialCompositionText(value) && <div className="dim">{partialCompositionText(value)}</div>}
        {value.context && value.context.length > 0 && (
          <div className="dim" title="Neutro: não é produtor nem passo da cadeia">
            {CONTEXT_LABEL} ({value.context.map((c) => `${c.requestId}${c.field ? `:${c.field}` : ""}`).join(", ")})
          </div>
        )}
        {value.unobservable && value.unobservable.length > 0 && (
          <div className="dim">
            não observável (resposta anterior sem corpo):{" "}
            {value.unobservable.map((item, index) => (
              <span key={index}>
                {index > 0 ? "; " : ""}
                {item.requestId} ({item.state}
                {item.reason ? `: ${item.reason}` : ""})
                {item.suggestion ? (
                  <>
                    {" · "}
                    <button className="link-req mono" onClick={() => onOpen(item.suggestion!)} title="Abrir a ocorrência equivalente com corpo observável">
                      ocorrência equivalente com corpo ({item.suggestion})
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
          {stepConfidence(step) === "strong" ? "confiança forte" : "possível"}
        </span>
      )}{" "}
      {verdicts && <span title="Sucesso da aplicação neste passo"><VerdictChip outcome={verdicts.get(step.requestId)} /> </span>}
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
        <h3>Cadeia de priming</h3>
        <span className="block-meta">
          requisições mínimas, na ordem do fluxo, que antecedem {chain.requestId}
        </span>
      </header>
      <div className="body-foot">
        Derivada de evidências do core (não prova causalidade); não é um script executável. <strong>confiança forte</strong> = há evidência forte
        (cookie-jar / same-field não genérico); <strong>possível</strong> = só coincidência de valor (value-match).
      </div>
      <ol className="chain-list" style={{ padding: "0 13px" }}>
        {chain.steps.map((step, index) => (
          <StepItem key={step.requestId} step={step} index={index} onOpen={onOpen} verdicts={verdicts} />
        ))}
        {chain.steps.length === 0 && <li>Nenhuma requisição anterior fornece valores a esta.</li>}
      </ol>
      {chain.pages && chain.pages.length > 0 && (
        <div style={{ padding: "0 13px" }}>
          <h4>Páginas de contexto (carregaram a página de onde os passos foram emitidos; não produzem valores)</h4>
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
            Frames auxiliares <span className="count">{chain.auxiliaryPages.length}</span>{" "}
            <span className="dim">(carregados por parser: *_JLIBS, cscform, about:blank; não produzem valores)</span>
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
          <h4>Proteção (não é lógica da aplicação)</h4>
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
            Sem origem observada <span className="count">{chain.unresolved.length}</span>
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
        <div className="body-foot">{chain.redactedValues} valor(es) redigido(s) não podem ser rastreados.</div>
      )}
    </section>
  );
}

function WarningStrip({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="body-flag flag-truncated" role="alert">
      <strong>Avisos da análise ({warnings.length})</strong>
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
  sessionDir,
  requestId,
  onOpen,
  verdicts,
}: {
  sessionDir?: string;
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
    if (!sessionDir) return;
    let alive = true;
    bridge
      .requestOrigins(sessionDir, requestId)
      .then((result) => alive && setOrigins(result))
      .catch((reason) => alive && setError(String(reason)));
    bridge
      .requestChain(sessionDir, requestId)
      .then((result) => alive && setChain(result))
      .catch((reason) => alive && setError((current) => current ?? String(reason)));
    return () => {
      alive = false;
    };
  }, [sessionDir, requestId]);

  const groups = useMemo(() => (origins ? groupOrigins(origins.values) : []), [origins]);

  if (!sessionDir) {
    return <div className="empty">Origem dos valores exige uma sessão com pasta persistida (abra uma captura ou importe um arquivo).</div>;
  }
  if (error) {
    return (
      <div className="empty">
        <strong>Não foi possível calcular a origem.</strong>
        <br />
        {error}
      </div>
    );
  }
  if (!origins) return <div className="empty">Calculando origens…</div>;

  return (
    <>
      <WarningStrip warnings={highlightedWarnings(origins.warnings, chain?.warnings)} />
      <section className="body-panel">
        <header className="block-head">
          <h3>Origem dos valores</h3>
          <span className="block-meta">{origins.values.length} valor(es) consumido(s) por {origins.requestId}</span>
        </header>
        <div className="body-foot">
          O tipo da evidência mostra a força: <strong>cookie-jar</strong> e <strong>same-field</strong> são fortes; <strong>value-match</strong>{" "}
          é só coincidência de valor (média) — não é prova de causa. “Sem origem observada” não significa erro.
        </div>
        <table className="origin-table">
          <thead>
            <tr>
              <th>Campo</th>
              <th>Valor</th>
              <th>Status</th>
              <th>Evidência / produtor</th>
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
          <div className="body-foot">{origins.redactedValues} valor(es) redigido(s) (sanitização) não podem ser rastreados.</div>
        )}
        {origins.ties.length > 0 && (
          <div className="body-foot">Tentativas com o mesmo instante de início, excluídas como produtoras: {origins.ties.join(", ")}.</div>
        )}
      </section>
      {chain ? <ChainPanel chain={chain} onOpen={onOpen} verdicts={verdicts} /> : <div className="empty">Calculando cadeia…</div>}
    </>
  );
}
