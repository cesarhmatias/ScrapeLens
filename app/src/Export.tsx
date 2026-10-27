// Diálogos de exportação (cURL/Python) e de sessão sanitizada.
//
// O texto exibido é gerado pelo Rust e é exatamente o que a cópia e o arquivo
// salvo recebem. A UI não monta, não edita e não executa o código exportado.

import { useCallback, useEffect, useMemo, useState } from "react";

import { bridge, type ExportPreview, type SanitizePreview, type SanitizeSaved, type SavedFile } from "./bridge";
import type { RequestRecord, SessionRecord } from "./types";

const bodyStateLabel: Record<string, string> = {
  captured: "capturado",
  truncated: "truncado na captura",
  unavailable: "indisponível",
  empty: "vazio",
  discarded: "descartado",
};

const verificationLabel: Record<string, string> = {
  verified: "headers verificados",
  partial: "headers parcialmente verificados",
  unverified: "headers não verificados",
};

function safeFileName(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned || "export";
}

function Modal({
  title,
  subtitle,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div
        className={wide ? "modal modal-wide" : "modal"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header className="modal-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p className="modal-sub">{subtitle}</p>}
          </div>
          <button className="icon-btn" onClick={onClose} title="Fechar (Esc)" aria-label="Fechar">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

function WarningList({ warnings }: { warnings: { code: string; message: string }[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="export-block">
      <h3>
        Avisos do core <span className="count">{warnings.length}</span>
      </h3>
      <ul className="export-list">
        {warnings.map((warning, index) => (
          <li key={`${warning.code}-${index}`}>
            <span className="mono chip-code">{warning.code}</span>
            <span>{warning.message}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ExportDialog({
  session,
  request,
  onClose,
}: {
  session: SessionRecord;
  request: RequestRecord;
  onClose: () => void;
}) {
  const sessionDir = session.sourcePath;
  const [format, setFormat] = useState<"curl" | "python">("curl");
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<SavedFile | null>(null);

  useEffect(() => {
    if (!sessionDir) {
      setError("Esta sessão não tem pasta persistida; abra uma captura ou importe um arquivo para exportar.");
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    setStatus(null);
    setSaved(null);
    setPreview(null);
    bridge
      .exportRequest(sessionDir, request.id, format)
      .then((result) => {
        if (!alive) return;
        if (result.requestId !== request.id) {
          setError(`A geração devolveu a requisição ${result.requestId}; esperada ${request.id}. Gere de novo.`);
          return;
        }
        setPreview(result);
      })
      .catch((reason) => {
        if (alive) setError(String(reason));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [format, request.id, sessionDir]);

  const copy = useCallback(async () => {
    if (!preview) return;
    const ok = await bridge.copyText(preview.text);
    setStatus(ok ? `Texto ${preview.format} copiado para a área de transferência.` : "Não foi possível copiar.");
  }, [preview]);

  const save = useCallback(async () => {
    if (!preview) return;
    if (preview.requestId !== request.id) {
      setError("A seleção mudou enquanto a prévia era gerada. Feche e abra a exportação de novo.");
      return;
    }
    setSaving(true);
    setError(null);
    setStatus(null);
    const name = `${safeFileName(request.id)}.${preview.format === "python" ? "py" : "sh"}`;
    try {
      // O texto salvo é o mesmo objeto mostrado na prévia; nada é regenerado.
      const result = await bridge.saveExport(name, preview.text);
      if (!result) {
        setStatus("Salvamento cancelado; nada foi gravado.");
        return;
      }
      setSaved(result);
      setStatus(`Arquivo salvo (${result.bytes} bytes).`);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSaving(false);
    }
  }, [preview, request.id]);

  // O estado vem da sessão; a nota abaixo é a explicação literal do core
  // (ex.: "corpo não incluído: estado Unavailable"). Não reescrevemos o texto
  // do core nem duplicamos a conclusão dele.
  const bodyState = useMemo(() => {
    if (!preview) return null;
    return {
      label: bodyStateLabel[preview.bodyState] ?? preview.bodyState,
      note: preview.bodyNote?.trim() ?? null,
    };
  }, [preview]);

  return (
    <Modal
      title="Exportar requisição"
      subtitle={`${request.method} ${request.url}`}
      onClose={onClose}
      wide
      footer={
        <>
          <span className="modal-note">
            O ScrapeLens não executa nem reenvia a requisição. Pode conter cookies/credenciais da sessão.
          </span>
          <span className="grow" />
          <button className="btn" onClick={() => void copy()} disabled={!preview || loading}>
            Copiar
          </button>
          <button className="btn primary" onClick={() => void save()} disabled={!preview || loading || saving}>
            {saving ? "Salvando…" : "Salvar…"}
          </button>
        </>
      }
    >
      <div className="export-tabs" role="tablist" aria-label="Formato da exportação">
        {(["curl", "python"] as const).map((id) => (
          <button
            key={id}
            role="tab"
            aria-selected={format === id}
            className={format === id ? "tab active" : "tab"}
            onClick={() => setFormat(id)}
          >
            {id === "curl" ? "cURL" : "Python"}
          </button>
        ))}
        <span className="grow" />
        {preview && (
          <span className={`tag ${preview.headerVerification === "verified" ? "tag-real" : "tag-demo"}`}>
            {verificationLabel[preview.headerVerification] ?? preview.headerVerification}
          </span>
        )}
        {preview && <span className="tag">{preview.protocol.toUpperCase()}</span>}
      </div>

      <p className="export-disclaimer">
        A exportação reproduz a requisição no nível HTTP. Ela <strong>não</strong> replica TLS, JA3/JA4, ordem de
        frames ou HPACK do navegador.
      </p>

      {loading && <div className="notice notice-info"><span className="notice-icon">…</span><span>Gerando exportação no Rust…</span></div>}
      {error && <div className="notice notice-error"><span className="notice-icon">!</span><span>{error}</span></div>}
      {status && <div className="notice notice-success"><span className="notice-icon">✓</span><span>{status}</span></div>}

      {preview && (
        <>
          {bodyState && (
            <div className="export-body-state">
              <span className="export-body-label">Corpo: {bodyState.label}</span>
              {bodyState.note && <span className="export-body-note">{bodyState.note}</span>}
            </div>
          )}
          <pre className="export-code" aria-label="Prévia da exportação">
            {preview.text}
          </pre>
          {preview.skippedHeaders.length > 0 && (
            <div className="export-block">
              <h3>
                Headers não exportados <span className="count">{preview.skippedHeaders.length}</span>
              </h3>
              <p className="export-hint">
                O core omitiu estes headers por não poderem ser representados com segurança (por exemplo, valores com
                CR/LF).
              </p>
              <div className="chip-row">
                {preview.skippedHeaders.map((name) => (
                  <span className="chip mono" key={name}>
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
          <WarningList warnings={preview.warnings} />
          {saved && (
            <p className="export-saved mono" title={saved.path}>
              {saved.path}
            </p>
          )}
        </>
      )}

      {!sessionDir && !error && <p className="export-hint">Sessão sem pasta persistida.</p>}
    </Modal>
  );
}

export function SanitizeDialog({
  session,
  onClose,
  onOpened,
}: {
  session: SessionRecord;
  onClose: () => void;
  onOpened: (payload: Awaited<ReturnType<typeof bridge.openSessionAt>>) => void;
}) {
  const sessionDir = session.sourcePath;
  const [preview, setPreview] = useState<SanitizePreview | null>(null);
  const [saved, setSaved] = useState<SanitizeSaved | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!sessionDir) {
      setError("Esta sessão não tem pasta persistida; a sanitização precisa dos arquivos da sessão.");
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    bridge
      .previewSanitized(sessionDir)
      .then((result) => {
        if (alive) setPreview(result);
      })
      .catch((reason) => {
        if (alive) setError(String(reason));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [sessionDir]);

  const save = useCallback(async () => {
    if (!sessionDir || !preview) return;
    setSaving(true);
    setError(null);
    setStatus(null);
    try {
      const result = await bridge.saveSanitized(sessionDir, preview.suggestedDestination);
      if (!result) {
        setStatus("Salvamento cancelado; a sessão original não foi alterada.");
        return;
      }
      setSaved(result);
      setStatus("Sessão sanitizada gravada em pasta nova e privada (0700/0600).");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSaving(false);
    }
  }, [preview, sessionDir]);

  const open = useCallback(async () => {
    if (!saved) return;
    try {
      const payload = await bridge.openSessionAt(saved.path);
      onOpened(payload);
      onClose();
    } catch (reason) {
      setError(String(reason));
    }
  }, [onClose, onOpened, saved]);

  return (
    <Modal
      title="Sanitizar sessão inteira"
      subtitle={session.id}
      onClose={onClose}
      wide
      footer={
        <>
          <span className="modal-note">
            {saved ? "A origem permanece intacta." : "Nada é gravado até você confirmar o destino no diálogo nativo."}
          </span>
          <span className="grow" />
          <button className="btn" onClick={onClose}>
            Fechar
          </button>
          {saved ? (
            <>
              <button className="btn" onClick={() => void bridge.revealPath(saved.path)}>
                Mostrar no Finder
              </button>
              <button className="btn primary" onClick={() => void open()}>
                Abrir sessão sanitizada
              </button>
            </>
          ) : (
            <button className="btn primary" onClick={() => void save()} disabled={!preview || loading || saving}>
              {saving ? "Gravando…" : "Escolher destino e salvar…"}
            </button>
          )}
        </>
      }
    >
      <p className="export-disclaimer">
        Usa a política conservadora do core (<span className="mono">keep_raw_events=false</span>): redige headers,
        cookies, tokens em URL e corpos sensíveis, e omite anexos que não podem ser sanitizados com segurança. A
        origem nunca é alterada.
      </p>

      {loading && <div className="notice notice-info"><span className="notice-icon">…</span><span>Calculando a prévia no Rust…</span></div>}
      {error && <div className="notice notice-error"><span className="notice-icon">!</span><span>{error}</span></div>}
      {status && <div className="notice notice-success"><span className="notice-icon">✓</span><span>{status}</span></div>}

      {preview && (
        <>
          <div className="stat-row">
            <div className="stat">
              <span className="stat-num">{preview.requests}</span>
              <span className="stat-label">requisições</span>
            </div>
            <div className="stat">
              <span className="stat-num">{preview.totalRedactions}</span>
              <span className="stat-label">redações</span>
            </div>
            <div className="stat">
              <span className="stat-num">{preview.attachmentsKept}</span>
              <span className="stat-label">anexos mantidos</span>
            </div>
            <div className="stat">
              <span className="stat-num">{preview.omittedAttachments.length}</span>
              <span className="stat-label">anexos omitidos</span>
            </div>
          </div>

          <div className="export-block">
            <h3>Redações por origem</h3>
            {preview.redactions.length === 0 ? (
              <p className="export-hint">
                Nenhuma redação contabilizada. Isso não prova que a sessão está livre de credenciais: a sanitização é
                heurística.
              </p>
            ) : (
              <ul className="redaction-list">
                {preview.redactions.map((item) => (
                  <li key={item.key}>
                    <span className="mono">{item.key}</span>
                    <span className="count">{item.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {preview.omittedAttachments.length > 0 && (
            <div className="export-block">
              <h3>
                Anexos omitidos <span className="count">{preview.omittedAttachments.length}</span>
              </h3>
              <p className="export-hint">
                Binários, texto não estruturado ou JSON inválido são omitidos com aviso em vez de copiados.
              </p>
              <div className="chip-row">
                {preview.omittedAttachments.map((name) => (
                  <span className="chip mono" key={name}>
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {preview.rawArtifactsDropped.length > 0 && (
            <div className="export-block">
              <h3>Artefatos brutos não copiados</h3>
              <div className="chip-row">
                {preview.rawArtifactsDropped.map((name) => (
                  <span className="chip mono" key={name}>
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}

          <WarningList warnings={preview.warnings} />

          <p className="export-hint mono">destino sugerido: {preview.suggestedDestination}</p>

          {saved && (
            <div className="export-block">
              <h3>Resultado gravado</h3>
              <ul className="redaction-list">
                <li>
                  <span className="mono">{saved.path}</span>
                </li>
                <li>
                  <span>requisições</span>
                  <span className="count">{saved.requests}</span>
                </li>
                <li>
                  <span>redações</span>
                  <span className="count">{saved.totalRedactions}</span>
                </li>
                <li>
                  <span>anexos mantidos</span>
                  <span className="count">{saved.attachmentsKept}</span>
                </li>
                <li>
                  <span>anexos omitidos</span>
                  <span className="count">{saved.omittedAttachments.length}</span>
                </li>
                <li>
                  <span>session.json</span>
                  <span className="count">{saved.sessionBytes} B</span>
                </li>
              </ul>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
