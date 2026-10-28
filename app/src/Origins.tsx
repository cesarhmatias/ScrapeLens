// Aba "Origem": de onde veio cada valor da requisição e a cadeia de priming.
// Tudo vem do core (flow::value_origins / priming_chain); a UI não infere nada.
import { useEffect, useMemo, useState } from "react";
import { bridge } from "./bridge";
import {
  evidenceLabels,
  groupOrigins,
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
        {originStatusLabel(value)}
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
        {value.unobservable && value.unobservable.length > 0 && (
          <div className="dim">
            não observável (resposta anterior sem corpo):{" "}
            {value.unobservable.map((item) => `${item.requestId} (${item.state}${item.reason ? `: ${item.reason}` : ""})`).join("; ")}
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

function StepItem({ step, index, onOpen }: { step: ChainStep; index?: number; onOpen: (id: string) => void }) {
  return (
    <li className={step.class === "protection" ? "chain-protection" : undefined}>
      {index !== undefined && <strong>{index + 1}. </strong>}
      <span className="mono">{step.method}</span> <ReqLink id={step.requestId} onOpen={onOpen} />{" "}
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

export function ChainPanel({ chain, onOpen }: { chain: PrimingChain; onOpen: (id: string) => void }) {
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>Cadeia de priming</h3>
        <span className="block-meta">
          requisições mínimas, na ordem do fluxo, que antecedem {chain.requestId}
        </span>
      </header>
      <div className="body-foot">Derivada de evidências do core (não prova causalidade); não é um script executável.</div>
      <ol className="chain-list" style={{ padding: "0 13px" }}>
        {chain.steps.map((step, index) => (
          <StepItem key={step.requestId} step={step} index={index} onOpen={onOpen} />
        ))}
        {chain.steps.length === 0 && <li>Nenhuma requisição anterior fornece valores a esta.</li>}
      </ol>
      {chain.protection.length > 0 && (
        <div style={{ padding: "0 13px" }}>
          <h4>Proteção (não é lógica da aplicação)</h4>
          <ol className="chain-list">
            {chain.protection.map((step) => (
              <StepItem key={step.requestId} step={step} onOpen={onOpen} />
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
      {chain.warnings.map((warning, index) => (
        <div className="body-foot" key={index}>
          {warning}
        </div>
      ))}
    </section>
  );
}

export function OriginsTab({
  sessionDir,
  requestId,
  onOpen,
}: {
  sessionDir?: string;
  requestId: string;
  onOpen: (id: string) => void;
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
        {origins.warnings.map((warning, index) => (
          <div className="body-foot" key={index}>
            {warning}
          </div>
        ))}
      </section>
      {chain ? <ChainPanel chain={chain} onOpen={onOpen} /> : <div className="empty">Calculando cadeia…</div>}
    </>
  );
}
