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

/** Classe da diferença, a partir do prefixo do motivo devolvido pelo core. */
const NOTE_CLASSES: [string, string, "ok" | "bad" | "info"][] = [
  ["parâmetro do usuário", "parâmetro do usuário", "info"],
  ["esperado (parâmetro do usuário)", "parâmetro do usuário", "info"],
  ["valor congelado", "valor congelado", "bad"],
  ["origem diferente", "origem diferente", "bad"],
  ["valor sem origem no trace", "sem origem no trace", "bad"],
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
/** Veredito desconhecido (o core pode acrescentar motivos) conta como divergência, nunca como sucesso. */
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
        <button className="link" onClick={onBack}>← Sessão</button> <span className="dim">/ Validar execução</span>
      </div>
      <h2>Validar execução do script</h2>
      <div className={`notice ${noticeClass(v.verdict)}`} role="status">
        <span className="notice-icon">{v.verdict === "equivalent" ? "✓" : v.verdict === "incomplete" ? "…" : "!"}</span>
        <span><strong>{v.summary}</strong></span>
      </div>
      <div className="notice notice-info">
        <span className="notice-icon">i</span>
        <span>
          O trace contém dados da sessão da execução (cookies, valores, corpos); não o compartilhe sem sanitizar. A sessão importada fica numa
          pasta temporária privada, <strong>apagada ao fechar esta tela</strong> ou o app{kept ? <>; ela foi guardada em <span className="mono">{kept}</span></> : null}.{" "}
          {!kept && <button className="link" onClick={() => void keep()}>Guardar esta execução…</button>}{" "}
          {!kept && <button className="link" onClick={onSanitizeTrace}>Sanitizar a sessão do trace…</button>}
        </span>
      </div>
      <p className="dim">Trace lido de <span className="mono">{tracePath}</span>.</p>
      {keepError && <div className="notice notice-error"><span className="notice-icon">!</span><span>{keepError}</span></div>}
      {v.mappedOrigin && (
        <p className="dim">Origem mapeada: <span className="mono">{v.mappedOrigin.from}</span> → <span className="mono">{v.mappedOrigin.to}</span> (a troca de host da execução não conta como diferença).</p>
      )}
      {v.warnings.map((w, i) => {
        const invalid = w.startsWith("parâmetro inválido");
        return (
          <div className={`notice ${invalid ? "notice-error" : "notice-info"}`} key={i}>
            <span className="notice-icon">{invalid ? "!" : "i"}</span>
            <span>{invalid ? <><strong>Parâmetro ignorado.</strong> {w}</> : w}</span>
          </div>
        );
      })}
      {needsMap && (
        <div className="notice notice-info">
          <span className="notice-icon">i</span>
          <span>
            O host da execução não é loopback e não foi mapeado automaticamente. Informe <span className="mono">origem-da-captura=origem-do-trace</span>:{" "}
            <input
              className="mono"
              style={{ minWidth: 320 }}
              value={mapText}
              placeholder="https://sistema.gov.br=https://staging.exemplo.com"
              onChange={(e) => setMapText(e.target.value)}
            />{" "}
            <button className="btn" disabled={!mapText.trim()} onClick={() => onRevalidate(mapText.trim())}>Revalidar com este mapeamento</button>
          </span>
        </div>
      )}
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
            <tr key={s.step} className={s.problem || (v.verdict === "incomplete" && v.step === s.step) ? "row-problem" : undefined}>
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
                      {s.unexpected.map((n, i) => <NoteItem key={i} n={n} />)}
                    </ul>
                  </details>
                )}
                {s.expected.length > 0 && (
                  <details open={s.expected.some((n) => n.reason.includes("parâmetro do usuário"))}>
                    <summary>esperadas ({s.expected.length})</summary>
                    <ul className="chain-list">
                      {s.expected.map((n, i) => <NoteItem key={i} n={n} />)}
                    </ul>
                  </details>
                )}
                {!s.problem && v.verdict === "incomplete" && v.step === s.step && (
                  <div className="body-flag flag-truncated"><strong>Incompleta: parou aqui</strong><span>{v.reason}</span></div>
                )}
                {!s.problem && !(v.verdict === "incomplete" && v.step === s.step) && s.unexpected.length === 0 && s.expected.length === 0 && <span className="dim">sem diferenças</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
