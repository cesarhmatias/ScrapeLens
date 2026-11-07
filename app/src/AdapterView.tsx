// Structured (derived) view of the fields that a protocol adapter claims
// (today Natural for Ajax). The raw body, shown above, remains the primary data.
// All text is rendered as React text (escaped); nothing is interpreted as HTML.
import { useEffect, useState } from "react";
import { bridge, type AdapterViewDto } from "./bridge";

const adapterLabel: Record<string, string> = { "natural-ajax": "Natural" };

export function AdapterViewPanel({
  sessionToken,
  requestId,
  side,
}: {
  sessionToken?: string;
  requestId: string;
  side: "request" | "response";
}) {
  const [view, setView] = useState<AdapterViewDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setView(null);
    setError(null);
    if (!sessionToken) return;
    let alive = true;
    bridge
      .adapterView(sessionToken, requestId, side)
      .then((v) => alive && setView(v))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, [sessionToken, requestId, side]);

  if (error) {
    return (
      <section className="body-panel">
        <div className="body-flag flag-truncated"><strong>Adapter view unavailable</strong><span>{error}</span></div>
      </section>
    );
  }
  if (!view || view.fields.length === 0) return null;
  return (
    <>
      {view.fields.map((f, i) => (
        <section className="body-panel" key={`${f.field}-${i}`}>
          <header className="block-head">
            <h3>Adapter view {adapterLabel[f.adapterId] ?? f.adapterId} (derived)</h3>
            <span className="block-meta">
              field <span className="mono">{f.field}</span> · the raw data above is the primary data
            </span>
          </header>
          {f.error ? (
            <div style={{ padding: "8px 13px" }}>
              <div className="body-flag flag-truncated">
                <strong>Could not decode the field</strong>
                <span>{f.error}</span>
              </div>
              <h4>Raw</h4>
              <pre className="mono">{f.raw}</pre>
            </div>
          ) : (
            <div style={{ padding: "8px 13px" }}>
              <table className="norm-table">
                <thead>
                  <tr><th>part</th><th>role</th><th>value</th></tr>
                </thead>
                <tbody>
                  {f.parts.map((p, j) => (
                    <tr key={j}>
                      <td className="mono">{f.field}.{p.name}</td>
                      <td>{p.role}</td>
                      <td className="mono" title={`bytes ${p.offset}–${p.offset + p.len} of the raw field`}>{p.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(f.omittedParts ?? 0) > 0 && (
                <p className="dim">{f.omittedParts} parts omitted — see the raw data.</p>
              )}
            </div>
          )}
        </section>
      ))}
      {view.note && <p className="dim">{view.note}</p>}
    </>
  );
}
