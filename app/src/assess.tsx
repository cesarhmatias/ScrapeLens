// Sucesso da aplicação × HTTP (core: assess::assess_session, esquema scrapelens.assess/1).
// A UI só mostra o veredito do core; nada é inferido aqui.
import { useEffect, useMemo, useState } from "react";
import { bridge } from "./bridge";

/** Veredito do core (`VerdictKind`, kebab-case). `not-assessed` desde o core 306e8f5. */
export type VerdictKind = "app-ok" | "app-error" | "blocked" | "indeterminado" | "not-assessed";

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
  /** Chaves iguais ao `verdictKind` do core (`VerdictKind::count_key()`). */
  counts: Record<string, number>;
  outcomes: ResponseOutcome[];
}

/** Chaves de `counts` no esquema `scrapelens.assess/1` (nada de `Debug`). */
export const VERDICT_KINDS: readonly VerdictKind[] = [
  "app-ok",
  "app-error",
  "blocked",
  "indeterminado",
  "not-assessed",
];

/** Contagens por veredito; chaves fora do esquema são ignoradas. */
export function verdictCounts(counts: Record<string, number> | undefined): Record<VerdictKind, number> {
  return Object.fromEntries(VERDICT_KINDS.map((kind) => [kind, counts?.[kind] ?? 0])) as Record<VerdictKind, number>;
}

export type OutcomeMap = Map<string, ResponseOutcome>;

const SHORT: Record<VerdictKind, string> = {
  "app-ok": "app-ok",
  "app-error": "app-error",
  blocked: "blocked?",
  indeterminado: "indeterminado",
  "not-assessed": "não-avaliado",
};
const CLASS: Record<VerdictKind, string> = {
  "app-ok": "v-ok",
  "app-error": "v-none",
  blocked: "v-none dashed",
  indeterminado: "v-partial",
  "not-assessed": "tag dim",
};

/** Falha da aplicação = app-error ou blocked? (HTTP pode ter sido 200). */
export const isAppFailure = (o: ResponseOutcome | undefined) =>
  o?.verdictKind === "app-error" || o?.verdictKind === "blocked";

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

/** Carrega a avaliação da sessão (cache no Rust); `undefined` sem pasta persistida. */
export function useAssess(dir: string | undefined, enabled = true) {
  const [state, setState] = useState<{ dir: string; result?: AssessResult; error?: string } | null>(null);
  useEffect(() => {
    if (!dir || !enabled) {
      setState(null);
      return;
    }
    let alive = true;
    bridge
      .assessSession(dir)
      .then((result) => alive && setState({ dir, result }))
      .catch((error) => alive && setState({ dir, error: String(error) }));
    return () => {
      alive = false;
    };
  }, [dir, enabled]);
  const current = state && state.dir === dir ? state : null;
  const map = useMemo<OutcomeMap>(
    () => new Map((current?.result?.outcomes ?? []).map((o) => [o.requestId, o])),
    [current?.result],
  );
  return { map, result: current?.result, error: current?.error, loading: Boolean(dir && enabled && !current) };
}

const signalLabel: Record<string, string> = {
  ok: "sinal de sucesso",
  error: "erro da aplicação",
  protection: "proteção",
  missing: "campo ausente",
  info: "observação",
};

export function AppSuccessSection({ outcome, error, loading }: { outcome?: ResponseOutcome; error?: string; loading?: boolean }) {
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>Sucesso da aplicação</h3>
        <span className="block-meta">HTTP não é sucesso da aplicação · veredito do core</span>
      </header>
      {error && <div className="body-flag flag-truncated"><strong>Avaliação indisponível</strong><span>{error}</span></div>}
      {!error && !outcome && <div className="empty">{loading ? "Avaliando…" : "Sem avaliação: exige uma sessão aberta da pasta persistida."}</div>}
      {outcome && (
        <div style={{ padding: "8px 13px" }}>
          <p>
            <span className={`chip ${outcome.httpOk ? "v-ok" : "v-none"}`}>HTTP {outcome.status ?? "?"}</span>{" "}
            <VerdictChip outcome={outcome} /> <strong className="mono">{outcome.verdict}</strong>
          </p>
          {outcome.httpOk && (outcome.verdictKind === "app-error" || outcome.verdictKind === "blocked") && (
            <div className="body-flag flag-truncated">
              <strong>HTTP bem-sucedido, mas a aplicação não teve sucesso</strong>
              <span>
                {outcome.verdictKind === "blocked"
                  ? `possível bloqueio (não afirmado) — evidência: ${evidenceText(outcome)}`
                  : `a resposta traz erro da aplicação — evidência: ${evidenceText(outcome)}`}
              </span>
            </div>
          )}
          {outcome.verdictKind === "blocked" && !(outcome.httpOk) && (
            <p className="dim">blocked? — evidência: {evidenceText(outcome)}</p>
          )}
          {outcome.reason && <p><strong>Motivo:</strong> {outcome.reason}</p>}
          <h4>Sinais ({outcome.appSignals.length})</h4>
          {outcome.appSignals.length === 0 ? (
            <p className="dim">Nenhum sinal da aplicação nesta resposta.</p>
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
              <h4>Campos ausentes ({outcome.missingFields.length})</h4>
              <p className="mono">{outcome.missingFields.join(", ")}</p>
              <p className="dim">Esperados porque a mesma rota os trouxe em outras respostas desta sessão (ou pelas regras).</p>
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
