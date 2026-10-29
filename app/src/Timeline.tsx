// Linha do tempo da aplicação (core: timeline::timeline) e validação da execução do script
// (core: validate::validate, esquema scrapelens.validate/1). A UI só apresenta o que o core
// devolve; rótulos (`event @ page`) e vereditos são texto do core, renderizados escapados.
import { useEffect, useState } from "react";
import { bridge, type TimelineDto, type ValidationResultDto } from "./bridge";
import { VerdictKindChip } from "./assess";

export function TimelineView({
  sessionDir,
  onOpenRequest,
  onBack,
}: {
  sessionDir?: string;
  onOpenRequest: (id: string) => void;
  onBack: () => void;
}) {
  const [data, setData] = useState<TimelineDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setData(null);
    setError(null);
    if (!sessionDir) {
      setError("Esta sessão não tem pasta persistida; a linha do tempo precisa dos arquivos da sessão.");
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
        <button className="link" onClick={onBack}>← Sessão</button> <span className="dim">/ Linha do tempo</span>
      </div>
      <h2>Linha do tempo da aplicação</h2>
      {error && <div className="notice notice-error"><span className="notice-icon">!</span><span>{error}</span></div>}
      {!data && !error && <div className="empty">Calculando no Rust…</div>}
      {data && (
        <>
          <p className="dim">
            {data.counts.events} evento(s) da aplicação · {data.rounds} rodada(s) · proteção {data.counts.protection} · estáticos {data.counts.static}.
            Clique numa linha para abrir a requisição.
          </p>
          {data.warnings.map((w, i) => (
            <div className="notice notice-info" key={i}><span className="notice-icon">i</span><span>{w}</span></div>
          ))}
          <table className="norm-table timeline-table">
            <thead>
              <tr><th>Rodada</th><th>Evento</th><th>Tipo</th><th>Status</th><th>Aplicação</th><th>Consumiu</th><th>Produziu</th></tr>
            </thead>
            <tbody>
              {data.items.map((item, i) => {
                if (item.type === "group") {
                  return (
                    <tr key={i} className="timeline-group">
                      <td colSpan={7}>
                        <details>
                          <summary>
                            {item.kind === "protection" ? "Proteção" : "Recursos estáticos"} <span className="count">{item.count}</span>
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
                return (
                  <tr key={i} className="clickable" onClick={() => onOpenRequest(item.requestId)} title={`${item.method} ${item.url}`}>
                    <td>{header ? `rodada ${item.round}` : ""}</td>
                    <td><strong className="mono">{item.label}</strong> <span className="dim mono">{item.requestId}</span></td>
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

const verdictClass: Record<string, string> = {
  equivalent: "notice-success",
  diverges: "notice-error",
  incomplete: "notice-info",
};

export function ValidationView({
  result,
  tracePath,
  onBack,
  onSanitizeTrace,
}: {
  result: ValidationResultDto;
  tracePath: string;
  onBack: () => void;
  onSanitizeTrace: () => void;
}) {
  const v = result.validation;
  const problemSteps = v.steps.filter((s) => s.problem || s.unexpected.length > 0).length;
  return (
    <div className="validation-view">
      <div className="breadcrumb">
        <button className="link" onClick={onBack}>← Sessão</button> <span className="dim">/ Validar execução</span>
      </div>
      <h2>Validar execução do script</h2>
      <div className={`notice ${verdictClass[v.verdict] ?? "notice-info"}`} role="status">
        <span className="notice-icon">{v.verdict === "equivalent" ? "✓" : v.verdict === "diverges" ? "!" : "…"}</span>
        <span><strong>{v.summary}</strong></span>
      </div>
      <div className="notice notice-info">
        <span className="notice-icon">i</span>
        <span>
          O trace contém dados da sessão da execução (cookies, valores, corpos); não o compartilhe sem sanitizar. Ele foi importado para
          <span className="mono"> {result.traceDir}</span> (pasta privada) a partir de <span className="mono">{tracePath}</span>.{" "}
          <button className="link" onClick={onSanitizeTrace}>Sanitizar a sessão do trace…</button>
        </span>
      </div>
      {v.mappedOrigin && (
        <p className="dim">Origem mapeada: <span className="mono">{v.mappedOrigin.from}</span> → <span className="mono">{v.mappedOrigin.to}</span> (a troca de host da execução não conta como diferença).</p>
      )}
      {v.warnings.map((w, i) => (
        <div className="notice notice-info" key={i}><span className="notice-icon">i</span><span>{w}</span></div>
      ))}
      {v.missingInTrace.length > 0 && (
        <div className="notice notice-error"><span className="notice-icon">!</span><span>Passos da captura sem par no trace: <span className="mono">{v.missingInTrace.join(", ")}</span></span></div>
      )}
      <p className="dim">{v.steps.length} passo(s) no trace · {problemSteps} com problema ou diferença inesperada.</p>
      <table className="norm-table validation-table">
        <thead>
          <tr><th>Passo</th><th>Captura → trace</th><th>Status</th><th>Aplicação (captura × trace)</th><th>Diferenças</th></tr>
        </thead>
        <tbody>
          {v.steps.map((s) => (
            <tr key={s.step} className={s.problem ? "row-problem" : undefined}>
              <td>{s.step}</td>
              <td>
                <span className="mono">{s.captureRequestId ?? "— (passo extra)"} → {s.traceRequestId}</span>
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
                    <summary>inesperadas ({s.unexpected.length})</summary>
                    <ul className="chain-list">
                      {s.unexpected.map((n, i) => <li key={i}><span className="mono">{n.scope}:{n.field}</span> <span className="dim">{n.reason}</span></li>)}
                    </ul>
                  </details>
                )}
                {s.expected.length > 0 && (
                  <details open={s.expected.some((n) => n.reason.includes("parâmetro do usuário"))}>
                    <summary>esperadas ({s.expected.length})</summary>
                    <ul className="chain-list">
                      {s.expected.map((n, i) => (
                        <li key={i}>
                          <span className="mono">{n.scope}:{n.field}</span>{" "}
                          {n.reason.includes("parâmetro do usuário") && <span className="chip v-partial">parâmetro do usuário</span>}{" "}
                          <span className="dim">{n.reason}</span>
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                {!s.problem && s.unexpected.length === 0 && s.expected.length === 0 && <span className="dim">sem diferenças</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
