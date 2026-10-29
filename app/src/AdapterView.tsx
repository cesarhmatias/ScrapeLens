// Visão estruturada (derivada) dos campos que um adaptador de protocolo reivindica
// (hoje Natural for Ajax). O corpo bruto, exibido acima, continua sendo o dado primário.
// Todo texto é renderizado como texto React (escapado); nada é interpretado como HTML.
import { useEffect, useState } from "react";
import { bridge, type AdapterViewDto } from "./bridge";

const adapterLabel: Record<string, string> = { "natural-ajax": "Natural" };

export function AdapterViewPanel({
  sessionDir,
  requestId,
  side,
}: {
  sessionDir?: string;
  requestId: string;
  side: "request" | "response";
}) {
  const [view, setView] = useState<AdapterViewDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setView(null);
    setError(null);
    if (!sessionDir) return;
    let alive = true;
    bridge
      .adapterView(sessionDir, requestId, side)
      .then((v) => alive && setView(v))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, [sessionDir, requestId, side]);

  if (error) {
    return (
      <section className="body-panel">
        <div className="body-flag flag-truncated"><strong>Visão do adaptador indisponível</strong><span>{error}</span></div>
      </section>
    );
  }
  if (!view || view.fields.length === 0) return null;
  return (
    <>
      {view.fields.map((f, i) => (
        <section className="body-panel" key={`${f.field}-${i}`}>
          <header className="block-head">
            <h3>Visão do adaptador {adapterLabel[f.adapterId] ?? f.adapterId} (derivada)</h3>
            <span className="block-meta">
              campo <span className="mono">{f.field}</span> · o bruto acima é o dado primário
            </span>
          </header>
          {f.error ? (
            <div style={{ padding: "8px 13px" }}>
              <div className="body-flag flag-truncated">
                <strong>Não foi possível decodificar o campo</strong>
                <span>{f.error}</span>
              </div>
              <h4>Bruto</h4>
              <pre className="mono">{f.raw}</pre>
            </div>
          ) : (
            <div style={{ padding: "8px 13px" }}>
              <table className="norm-table">
                <thead>
                  <tr><th>parte</th><th>papel</th><th>valor</th></tr>
                </thead>
                <tbody>
                  {f.parts.map((p, j) => (
                    <tr key={j}>
                      <td className="mono">{f.field}.{p.name}</td>
                      <td>{p.role}</td>
                      <td className="mono" title={`bytes ${p.offset}–${p.offset + p.len} do campo bruto`}>{p.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ))}
      {view.note && <p className="dim">{view.note}</p>}
    </>
  );
}
