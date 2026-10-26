import { useMemo, useState } from "react";
import { demoSession } from "./demo/session";
import { diffCookies, diffHeaders, kindLabel, normalizeHeaders } from "./diff";
import type {
  BodyInfo,
  HeaderPair,
  Protocol,
  RequestRecord,
  Verification,
  VerificationKey,
} from "./types";

type View = "session" | "detail" | "compare";
type Theme = "light" | "dark";
type DetailTab = "headers" | "normalized" | "cookies" | "payload" | "response" | "redirects" | "event";
type TypeFilter = "all" | "fetch" | "document" | "media" | "error";

const params = new URLSearchParams(window.location.search);
const initialTheme: Theme = params.get("theme") === "dark" ? "dark" : "light";
const initialView: View =
  params.get("view") === "detail" ? "detail" : params.get("view") === "compare" ? "compare" : "session";
const initialTab = (params.get("tab") as DetailTab | null) ?? "headers";
const initialA = params.get("a") ?? "req-0009";
const initialB = params.get("b") ?? "req-0010";

const verificationLabels: Record<VerificationKey, string> = {
  requestHeaders: "Headers da requisição",
  responseHeaders: "Headers da resposta",
  normalizedHeaders: "Visão normalizada",
  cookies: "Cookies",
  payload: "Payload",
  responseBody: "Corpo da resposta",
  protocol: "Protocolo",
  timings: "Tempos",
};

const sourceLabels: Record<string, string> = {
  cdp: "CDP",
  netlog: "NetLog",
  har: "HAR",
  session: "Sessão",
};

const typeLabels: Record<string, string> = {
  document: "documento",
  stylesheet: "estilo",
  script: "script",
  xhr: "xhr",
  fetch: "fetch",
  image: "imagem",
  font: "fonte",
  other: "outro",
};

const methodClass: Record<string, string> = {
  GET: "m-get",
  POST: "m-post",
  PUT: "m-put",
  DELETE: "m-del",
};

function fmtTime(iso: string) {
  const t = iso.slice(11, 23);
  return t || iso;
}

function fmtDuration(req: RequestRecord) {
  return `${req.verification.timings.status === "unverified" ? "≈" : ""}${req.durationMs} ms`;
}

function fmtBytes(n?: number) {
  if (n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1).replace(".", ",")} KiB`;
  return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} MiB`;
}

function statusClass(status: number) {
  if (status >= 500) return "s-err";
  if (status >= 400) return "s-warn";
  if (status >= 300) return "s-redir";
  if (status >= 200) return "s-ok";
  return "s-info";
}

function verifyClass(status: Verification["status"]) {
  return status === "verified" ? "v-ok" : status === "partial" ? "v-partial" : "v-none";
}

const verifyText: Record<Verification["status"], string> = {
  verified: "verificada",
  partial: "parcial",
  unverified: "não verificada",
};

function dupeNames(pairs: HeaderPair[]) {
  const counts = new Map<string, number>();
  for (const p of pairs) counts.set(p.name, (counts.get(p.name) ?? 0) + 1);
  return counts;
}

function HeaderBlock({ title, pairs, side }: { title: string; pairs: HeaderPair[]; side: string }) {
  const dupes = dupeNames(pairs);
  const regular = pairs.filter((p) => p.kind === "regular").length;
  return (
    <section className="header-block">
      <header className="block-head">
        <h3>{title}</h3>
        <span className="block-meta">
          {pairs.length} pares · {regular} regulares · {pairs.length - regular}{" "}
          {pairs.length - regular === 1 ? "pseudoheader" : "pseudoheaders"}
        </span>
      </header>
      {pairs.length === 0 ? (
        <div className="empty">
          Nenhuma linha observada pela fonte desta captura.
          <br />
          Header ausente não é reconstruído — estado: não verificado.
        </div>
      ) : (
        <ol className="header-list">
          {pairs.map((p) => (
            <li key={`${side}-${p.index}`} className={p.kind === "pseudo" ? "hrow h-pseudo" : "hrow"}>
              <span className="h-idx">{p.index}</span>
              <span className="h-name">{p.name}</span>
              <span className="h-value">{p.value}</span>
              {dupes.get(p.name)! > 1 && (
                <span className="tag tag-dup" title="O mesmo nome aparece mais de uma vez na sequência da fonte">
                  duplicata ×{dupes.get(p.name)}
                </span>
              )}
              <button className="icon-btn copy" title="Copiar valor" aria-label={`Copiar ${p.name}`}>
                ⧉
              </button>
            </li>
          ))}
        </ol>
      )}
      <footer className="block-foot">
        {pairs.length === 0
          ? "Sem linhas: a fonte não entregou esta lista nesta captura."
          : "Ordem preservada da fonte — nada foi ordenado nem agrupado nesta visão."}
      </footer>
    </section>
  );
}

function BodyPanel({ title, body, kind }: { title: string; body: BodyInfo; kind: "payload" | "response" }) {
  const unavailable = body.availability !== "available";
  return (
    <section className="body-panel">
      <header className="block-head">
        <h3>{title}</h3>
        <span className="block-meta">
          {body.contentType ?? "tipo desconhecido"} · {fmtBytes(body.decodedSize ?? body.encodedSize)}
        </span>
      </header>
      {unavailable && (
        <div className={`body-flag flag-${body.availability}`}>
          <strong>
            {body.availability === "truncated"
              ? `Prévia truncada em ${fmtBytes(body.truncatedAt)}`
              : body.availability === "discarded"
                ? "Corpo descartado — não recuperável"
                : body.availability === "omitted"
                  ? "Corpo não exibido"
                  : "Corpo indisponível"}
          </strong>
          <span>{body.reason ?? "sem motivo registrado pela fonte"}</span>
        </div>
      )}
      {body.preview ? (
        <>
          <pre className="code">{body.preview}</pre>
          <div className="body-foot">
            {body.contentType?.includes("html")
              ? "HTML exibido como texto — nunca renderizado como interface."
              : "Prévia em texto, sem interpretação."}
            {body.captureRef ? <span className="mono dim"> · {body.captureRef}</span> : null}
          </div>
        </>
      ) : (
        <div className="empty">
          {body.availability === "available" ? "Corpo vazio (0 B)." : "Nenhum conteúdo textual disponível para exibir."}
        </div>
      )}
      {kind === "response" && body.encodedSize !== undefined && body.decodedSize !== undefined && body.encodedSize !== body.decodedSize && (
        <div className="body-foot">
          Tamanho na rede {fmtBytes(body.encodedSize)} · decodificado {fmtBytes(body.decodedSize)}
        </div>
      )}
    </section>
  );
}

function BodyContext({ req }: { req: RequestRecord }) {
  const reqEncoding = req.requestHeaders.find((h) => h.name === "content-encoding")?.value;
  const resEncoding = req.responseHeaders.find((h) => h.name === "content-encoding")?.value;
  return (
    <div className="meta-grid">
      <section className="meta-card">
        <h3>Metadados de conteúdo</h3>
        <dl className="kv tight">
          <dt>Tipo</dt>
          <dd>{typeLabels[req.type]} · {req.method} {req.status}</dd>
          <dt>Payload</dt>
          <dd className="mono">{req.payload.contentType ?? "sem corpo"}{reqEncoding ? ` · ${reqEncoding}` : ""}</dd>
          <dt>Resposta</dt>
          <dd className="mono">{req.responseBody.contentType ?? "tipo não informado"}{resEncoding ? ` · ${resEncoding}` : ""}</dd>
          <dt>Tamanho na rede</dt>
          <dd>{fmtBytes(req.payload.encodedSize)} / {fmtBytes(req.responseBody.encodedSize)}</dd>
          <dt>Decodificado</dt>
          <dd>{fmtBytes(req.payload.decodedSize)} / {fmtBytes(req.responseBody.decodedSize)}</dd>
          <dt>Prévia</dt>
          <dd>
            {req.payload.availability === "truncated" || req.responseBody.availability === "truncated"
              ? "parcial (truncada na gravação)"
              : "como registrada pela fonte"}
          </dd>
        </dl>
      </section>
      <section className="meta-card">
        <h3>Regras de exibição</h3>
        <ul className="rules">
          <li>HTML e JSON capturados aparecem como texto — nunca executados como interface.</li>
          <li>Corpo ausente, truncado ou descartado mostra o motivo; nada é reconstruído.</li>
          <li>Binários não são convertidos em texto: o arquivo fica na pasta da sessão.</li>
          <li>Copiar usa o valor bruto do evento, não o texto abreviado da tabela.</li>
        </ul>
      </section>
    </div>
  );
}

const availabilityLabels: Record<BodyInfo["availability"], string> = {
  available: "disponível",
  truncated: "truncado",
  discarded: "descartado",
  omitted: "omitido",
  unavailable: "indisponível",
};

function bodyState(body: BodyInfo) {
  if (body.availability === "unavailable" && body.encodedSize === undefined) return "sem corpo";
  return availabilityLabels[body.availability];
}

function VerificationPanel({ req }: { req: RequestRecord }) {
  const keys = Object.keys(verificationLabels) as VerificationKey[];
  return (
    <aside className="side-panel">
      <div className="side-card">
        <h3>Fonte</h3>
        <div className="source-row">
          <span className={`src-chip ${req.primarySource === "cdp" ? "src-cdp" : "src-netlog"}`}>
            {sourceLabels[req.primarySource]} · primária
          </span>
          <span className="src-chip src-muted">{req.primarySource === "cdp" ? "NetLog" : "CDP"} · cruzamento</span>
        </div>
        <dl className="kv">
          <dt>Requisição</dt>
          <dd className="mono">{req.id}</dd>
          <dt>Início</dt>
          <dd className="mono">{fmtTime(req.startedAt)}</dd>
          <dt>Iniciador</dt>
          <dd>{req.initiator ?? "não informado"}</dd>
          <dt>Sessão</dt>
          <dd>demo-sintetica-01 <span className="tag tag-demo">DEMO</span></dd>
        </dl>
      </div>

      <div className="side-card">
        <div className="side-head">
          <h3>Estado de verificação</h3>
          <span className="hint">por informação</span>
        </div>
        <ul className="verif-list">
          {keys.map((key) => {
            const v = req.verification[key];
            return (
              <li key={key} className="verif-item">
                <div className="verif-top">
                  <span className="verif-name">{verificationLabels[key]}</span>
                  <span className={`chip ${verifyClass(v.status)}`}>{verifyText[v.status]}</span>
                </div>
                {v.status === "unverified" ? (
                  <p className="verif-reason">Sem evidência: {v.reason}</p>
                ) : (
                  <>
                    <p className="verif-evidence mono">
                      {sourceLabels[v.evidence.source]} · {v.evidence.event}
                    </p>
                    <p className="verif-line">
                      {fmtTime(v.evidence.timestamp)} · {v.evidence.method}
                    </p>
                    {v.status === "partial" && <p className="verif-reason">Falta: {v.missing}</p>}
                  </>
                )}
              </li>
            );
          })}
        </ul>
        <button className="ghost-btn wide" title="Abre o evento bruto que sustenta o primeiro dado verificado">
          Abrir evento original ↗
        </button>
      </div>
    </aside>
  );
}
function DetailView({
  req,
  tab,
  setTab,
  onBack,
}: {
  req: RequestRecord;
  tab: DetailTab;
  setTab: (t: DetailTab) => void;
  onBack: () => void;
}) {
  const reqNorm = useMemo(() => normalizeHeaders(req.requestHeaders), [req]);
  const resNorm = useMemo(() => normalizeHeaders(req.responseHeaders), [req]);
  const tabs: { id: DetailTab; label: string; count?: number }[] = [
    { id: "headers", label: "Headers brutos", count: req.requestHeaders.length + req.responseHeaders.length },
    { id: "normalized", label: "Normalizado" },
    { id: "cookies", label: "Cookies", count: req.cookiesSent.length + req.cookiesReceived.length },
    { id: "payload", label: "Payload" },
    { id: "response", label: "Resposta" },
    { id: "redirects", label: "Redirects", count: req.redirects.length },
    { id: "event", label: "Evento" },
  ];

  return (
    <div className="detail">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Sessão
        </button>
        <div className="crumbs">
          <span>demo-sintetica-01</span>
          <span className="sep">/</span>
          <span className="mono">{req.id}</span>
          <span className="tag tag-demo">DEMO</span>
        </div>
      </div>

      <header className="detail-head">
        <div className="dh-line">
          <span className={`method ${methodClass[req.method] ?? "m-other"}`}>{req.method}</span>
          <span className="dh-path mono">{req.path}</span>
          <span className={`status ${statusClass(req.status)}`}>{req.status}</span>
          <span className="proto">{req.protocol}</span>
          <span className="type">{typeLabels[req.type]}</span>
        </div>
        <div className="dh-sub">
          <span className="mono url">{req.url}</span>
          <button className="ghost-btn small" title="Copiar URL completa">Copiar URL</button>
          <span className="dot">·</span>
          <span className="mono" title={req.verification.timings.status === "unverified" ? "Tempos não verificados: duração estimada pela UI" : "Duração medida pela fonte"}>
            {fmtDuration(req)}
          </span>
          <span className="dot">·</span>
          <span>{req.domain}</span>
        </div>
      </header>

      <nav className="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? "tab active" : "tab"}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count !== undefined && <span className="tab-count">{t.count}</span>}
          </button>
        ))}
      </nav>

      <div className="detail-body">
        <div className="detail-main">
          {tab === "headers" && (
            <>
              <div className="seq-banner">
                <span className="tag tag-seq">sequência da fonte</span>
                Índices 0–{Math.max(req.requestHeaders.length - 1, 0)} (requisição) e 0–{Math.max(req.responseHeaders.length - 1, 0)} (resposta).
                Pseudoheaders HTTP/2 aparecem antes dos regulares, como chegaram.
                {req.protocol === "HTTP/1.1" && (
                  <span className="seq-extra">Origem HTTP/1.1: sem pseudoheaders, apenas linhas nominais.</span>
                )}
              </div>
              <HeaderBlock title="Headers da requisição" pairs={req.requestHeaders} side="req" />
              <HeaderBlock title="Headers da resposta" pairs={req.responseHeaders} side="res" />
            </>
          )}

          {tab === "normalized" && (
            <>
              <div className="norm-banner">
                <strong>Visão normalizada — não é a sequência transmitida.</strong>
                <span>
                  Derivada localmente: agrupada por nome, em ordem alfabética, duplicatas preservadas e contadas.
                  Use a aba “Headers brutos” para a ordem da fonte.
                </span>
              </div>
              {[
                { title: "Requisição (normalizada)", rows: reqNorm },
                { title: "Resposta (normalizada)", rows: resNorm },
              ].map(({ title, rows }) => (
                <section className="norm-block" key={title}>
                  <header className="block-head">
                    <h3>{title}</h3>
                    <span className="block-meta">{rows.length} nomes únicos</span>
                  </header>
                  <table className="norm-table">
                    <thead>
                      <tr>
                        <th>Nome</th>
                        <th>Valores (na ordem da fonte)</th>
                        <th className="num">Ocorrências</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row) => (
                        <tr key={row.name}>
                          <td className="mono">{row.name}</td>
                          <td className="mono values">
                            {row.values.map((v, i) => (
                              <div key={i} className="val-line">
                                <span className="val-idx">{i + 1}</span>
                                {v}
                              </div>
                            ))}
                          </td>
                          <td className="num">
                            {row.count > 1 ? <span className="tag tag-dup">×{row.count}</span> : row.count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <footer className="block-foot">Visão derivada — estado de verificação: parcial.</footer>
                </section>
              ))}
            </>
          )}

          {tab === "cookies" && (
            <div className="cookies">
              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies enviados</h3>
                  <span className="block-meta">header Cookie parseado · {req.cookiesSent.length} pares</span>
                </header>
                <div className="cookie-grid">
                  {req.cookiesSent.length === 0 && <div className="empty">Nenhum cookie enviado nesta requisição.</div>}
                  {req.cookiesSent.map((c) => (
                    <div className="cookie-card" key={`${c.name}-${c.index}`}>
                      <div className="cookie-name mono">{c.name}</div>
                      <div className="cookie-value mono">{c.value}</div>
                      <div className="cookie-meta">par #{c.index} · ordem do header</div>
                    </div>
                  ))}
                </div>
                <footer className="block-foot">
                  Pares internos preservados; valores longos encurtados aqui para leitura.
                </footer>
              </section>

              <section className="header-block">
                <header className="block-head">
                  <h3>Cookies recebidos</h3>
                  <span className="block-meta">linhas Set-Cookie separadas · {req.cookiesReceived.length}</span>
                </header>
                {req.cookiesReceived.length === 0 ? (
                  <div className="empty">Nenhum Set-Cookie nesta resposta.</div>
                ) : (
                  <table className="norm-table cookies-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Nome</th>
                        <th>Valor</th>
                        <th>Atributos</th>
                      </tr>
                    </thead>
                    <tbody>
                      {req.cookiesReceived.map((c) => (
                        <tr key={`${c.name}-${c.index}`}>
                          <td className="mono dim">{c.index}</td>
                          <td className="mono">{c.name}</td>
                          <td className="mono">{c.value}</td>
                          <td className="attrs">
                            {c.attributes.map((a, i) => (
                              <span className="attr" key={i}>
                                {a.name}
                                {a.value !== undefined ? `=${a.value}` : ""}
                              </span>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <footer className="block-foot">
                  Linha bruta preservada no evento de origem; a tabela não junta Set-Cookie com “;”.
                </footer>
              </section>

              {req.cookiesReceived.length > 0 && (
                <section className="header-block">
                  <header className="block-head">
                    <h3>Linhas Set-Cookie brutas</h3>
                    <span className="block-meta">como o evento entregou · ordem da fonte</span>
                  </header>
                  <pre className="code small">{req.cookiesReceived.map((c) => c.raw).join("\n")}</pre>
                  <footer className="block-foot">
                    A tabela acima é derivada destas linhas; nenhum atributo é inventado ou reordenado.
                  </footer>
                </section>
              )}
            </div>
          )}

          {tab === "payload" && (
            <>
              <BodyPanel title="Payload da requisição" body={req.payload} kind="payload" />
              <BodyContext req={req} />
              <BodyPanel title="Corpo da resposta (referência)" body={req.responseBody} kind="response" />
            </>
          )}
          {tab === "response" && (
            <>
              <BodyPanel title="Corpo da resposta" body={req.responseBody} kind="response" />
              <BodyContext req={req} />
            </>
          )}

          {tab === "redirects" &&
            (req.redirects.length === 0 ? (
              <div className="empty big">
                <strong>Sem redirects nem tentativas registradas.</strong>
                <span>Nenhum hop nesta requisição; nada a comparar.</span>
              </div>
            ) : (
              <section className="header-block">
                <header className="block-head">
                  <h3>Cadeia de redirects e tentativas</h3>
                  <span className="block-meta">{req.redirects.length} hops</span>
                </header>
                <ol className="hop-list">
                  {req.redirects.map((hop) => (
                    <li className="hop" key={hop.index}>
                      <span className="hop-idx">{hop.index}</span>
                      <span className={`status ${statusClass(hop.status)}`}>{hop.status}</span>
                      <span className="proto">{hop.protocol}</span>
                      <div className="hop-body">
                        <div className="mono">{hop.url}</div>
                        {hop.location && <div className="hop-loc">→ location: <span className="mono">{hop.location}</span></div>}
                      </div>
                    </li>
                  ))}
                </ol>
                <footer className="block-foot">
                  Salto HTTP/1.1 → HTTP/2 registrado como dois hops; cada hop tem evidência própria.
                </footer>
              </section>
            ))}

          {tab === "event" && (
            <section className="header-block">
              <header className="block-head">
                <h3>Eventos originais</h3>
                <span className="block-meta">somente leitura · dados sintéticos</span>
              </header>
              <table className="norm-table event-table">
                <thead>
                  <tr>
                    <th>Fonte</th>
                    <th>Evento</th>
                    <th>Timestamp</th>
                    <th>Como foi obtido</th>
                    <th>Ref.</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(req.verification).map(([key, v]) => {
                    if (v.status === "unverified") {
                      return (
                        <tr key={key} className="row-missing">
                          <td>—</td>
                          <td>{verificationLabels[key as VerificationKey]}</td>
                          <td className="dim">sem evento</td>
                          <td className="dim">{v.reason}</td>
                          <td className="dim">—</td>
                        </tr>
                      );
                    }
                    return (
                      <tr key={key}>
                        <td>
                          <span className="src-chip small">{sourceLabels[v.evidence.source]}</span>
                        </td>
                        <td className="mono">{v.evidence.event}</td>
                        <td className="mono">{fmtTime(v.evidence.timestamp)}</td>
                        <td>{v.evidence.method}</td>
                        <td className="mono dim">{v.evidence.eventRef}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <footer className="block-foot">
                O evento bruto é a autoridade; a tabela acima só o referencia.
              </footer>
            </section>
          )}

          <section className="limits-strip">
            <div className="limits-head">
              <span className="tag tag-demo">DEMO</span>
              <h3>Limites desta captura</h3>
              <span className="hint">visível em todas as abas</span>
            </div>
            <ul>
              <li>Headers sem evento correspondente aparecem como “não verificada”, nunca como fato.</li>
              <li>Corpo omitido, truncado ou descartado mostra o motivo — nada é reconstruído.</li>
              <li>HTML capturado nunca é executado como interface; esta fatia usa contrato provisório.</li>
              <li>Sessão sintética: nenhum byte saiu do computador — sem telemetria, sem rede.</li>
            </ul>
          </section>
        </div>

        <VerificationPanel req={req} />
      </div>
    </div>
  );
}

function CompareView({
  aId,
  bId,
  setA,
  setB,
  onBack,
}: {
  aId: string;
  bId: string;
  setA: (id: string) => void;
  setB: (id: string) => void;
  onBack: () => void;
}) {
  const a = demoSession.requests.find((r) => r.id === aId) ?? demoSession.requests[0];
  const b = demoSession.requests.find((r) => r.id === bId) ?? demoSession.requests[1];
  const headerDiff = useMemo(() => diffHeaders(a.requestHeaders, b.requestHeaders), [a, b]);
  const resDiff = useMemo(() => diffHeaders(a.responseHeaders, b.responseHeaders), [a, b]);
  const cookieDiff = useMemo(() => diffCookies(a.cookiesSent, b.cookiesSent), [a, b]);
  const counts = headerDiff.counts;
  const total = counts.added + counts.removed + counts.changed + counts.reordered;

  const headerRow = (row: (typeof headerDiff.rows)[number]) => (
    <div className={`diff-row k-${row.kind}`} key={row.key}>
      <div className="diff-cell side-a">
        {row.a ? (
          <>
            <span className="pos">{row.a.index}</span>
            <span className="mono dname">{row.a.name}</span>
            <span className="mono dvalue">{row.a.value}</span>
          </>
        ) : (
          <span className="absent">— ausente em A</span>
        )}
      </div>
      <div className="diff-flag">
        <span className={`chip k-${row.kind}`}>{kindLabel[row.kind]}</span>
      </div>
      <div className="diff-cell side-b">
        {row.b ? (
          <>
            <span className="pos">{row.b.index}</span>
            <span className="mono dname">{row.b.name}</span>
            <span className="mono dvalue">{row.b.value}</span>
          </>
        ) : (
          <span className="absent">ausente em B —</span>
        )}
      </div>
    </div>
  );

  const pickerRow = (label: string, value: string, set: (id: string) => void) => (
    <label className="picker">
      <span className="picker-label">{label}</span>
      <select value={value} onChange={(e) => set(e.target.value)}>
        {demoSession.requests.map((r) => (
          <option key={r.id} value={r.id}>
            {r.id} · {r.method} {r.path} · {r.status}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <div className="compare">
      <div className="detail-top">
        <button className="back" onClick={onBack}>
          ← Sessão
        </button>
        <div className="crumbs">
          <span>demo-sintetica-01</span>
          <span className="sep">/</span>
          <span>comparação</span>
          <span className="tag tag-demo">DEMO</span>
        </div>
      </div>

      <header className="compare-head">
        <div>
          <h2>Comparar duas requisições</h2>
          <p className="sub">
            Lado a lado, na sequência das fontes. Pares repetidos são casados por valor, nunca por posição.
          </p>
        </div>
        <div className="compare-pickers">
          {pickerRow("A", a.id, setA)}
          <span className="vs">vs</span>
          {pickerRow("B", b.id, setB)}
        </div>
      </header>

      <div className="compare-summary">
        <span className="summary-total">{total} diferenças</span>
        <span className="chip k-added">+{counts.added} {counts.added === 1 ? "adicionado" : "adicionados"}</span>
        <span className="chip k-removed">−{counts.removed} {counts.removed === 1 ? "removido" : "removidos"}</span>
        <span className="chip k-changed">~{counts.changed} {counts.changed === 1 ? "alterado" : "alterados"}</span>
        <span className="chip k-reordered">↕{counts.reordered} {counts.reordered === 1 ? "reordenado" : "reordenados"}</span>
        <span className="summary-note">
          {a.protocol === b.protocol ? (
            <>Protocolo igual: <span className="mono">{a.protocol}</span></>
          ) : (
            <>Protocolo difere: <span className="mono">{a.protocol}</span> → <span className="mono">{b.protocol}</span></>
          )}
        </span>
      </div>

      <div className="compare-cols">
        <div className="col-head">
          <div>
            <span className={`method ${methodClass[a.method] ?? "m-other"}`}>{a.method}</span>
            <span className="mono col-url">{a.path}</span>
            <span className={`status ${statusClass(a.status)}`}>{a.status}</span>
          </div>
          <span className="col-meta">{a.id} · {fmtTime(a.startedAt)} · {fmtDuration(a)}</span>
        </div>
        <div className="col-head spacer">
          <span className="hint">diff</span>
        </div>
        <div className="col-head">
          <div>
            <span className={`method ${methodClass[b.method] ?? "m-other"}`}>{b.method}</span>
            <span className="mono col-url">{b.path}</span>
            <span className={`status ${statusClass(b.status)}`}>{b.status}</span>
          </div>
          <span className="col-meta">{b.id} · {fmtTime(b.startedAt)} · {fmtDuration(b)}</span>
        </div>
      </div>

      <section className="diff-section">
        <header className="diff-head">
          <h3>Headers da requisição</h3>
          <span className="block-meta">{a.requestHeaders.length} vs {b.requestHeaders.length} pares · posição original à esquerda</span>
        </header>
        <div className="diff-rows">{headerDiff.rows.map(headerRow)}</div>
      </section>

      {counts.reordered > 0 && (
        <p className="reorder-note">
          <span className="chip k-reordered">reordenado</span> mesmo par nos dois lados, ordem relativa invertida —
          os índices mostram a posição original em cada sequência.
        </p>
      )}

      <section className="diff-section">
        <header className="diff-head">
          <h3>Headers da resposta</h3>
          <span className="block-meta">{resDiff.rows.length} nomes · {resDiff.counts.changed} alterados, {resDiff.counts.added} adicionados, {resDiff.counts.removed} removidos</span>
        </header>
        <div className="diff-rows">{resDiff.rows.map(headerRow)}</div>
      </section>

      <section className="diff-section">
        <header className="diff-head">
          <h3>Cookies enviados</h3>
          <span className="block-meta">casamento por nome e valor</span>
        </header>
        <div className="diff-rows">
          {cookieDiff.map((row) => (
            <div className={`diff-row k-${row.kind}`} key={row.key}>
              <div className="diff-cell side-a">
                {row.a ? (
                  <>
                    <span className="pos">{row.a.index}</span>
                    <span className="mono dname">{row.a.name}</span>
                    <span className="mono dvalue">{row.a.value}</span>
                  </>
                ) : (
                  <span className="absent">— cookie ausente em A</span>
                )}
              </div>
              <div className="diff-flag">
                <span className={`chip k-${row.kind}`}>{kindLabel[row.kind]}</span>
              </div>
              <div className="diff-cell side-b">
                {row.b ? (
                  <>
                    <span className="pos">{row.b.index}</span>
                    <span className="mono dname">{row.b.name}</span>
                    <span className="mono dvalue">{row.b.value}</span>
                  </>
                ) : (
                  <span className="absent">cookie ausente em B —</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="diff-section bodies">
        <header className="diff-head">
          <h3>Corpo e protocolo</h3>
          <span className="block-meta">sem normalização de conteúdo</span>
        </header>
        <div className="body-compare">
          {[
            { r: a, label: "A" },
            { r: b, label: "B" },
          ].map(({ r, label }) => (
            <div className="body-col" key={label}>
              <div className="body-col-head">
                <span className="tag">{label}</span>
                <span className="mono">{r.protocol}</span>
                <span className={`status ${statusClass(r.status)}`}>{r.status}</span>
              </div>
              <dl className="kv tight">
                <dt>Payload</dt>
                <dd>{r.payload.preview ? `${r.payload.preview.length} caracteres` : bodyState(r.payload)}</dd>
                <dt>Resposta</dt>
                <dd>{bodyState(r.responseBody)} · {fmtBytes(r.responseBody.decodedSize ?? r.responseBody.encodedSize)}</dd>
                <dt>Set-Cookie</dt>
                <dd>{r.cookiesReceived.length} linha(s)</dd>
              </dl>
              {r.responseBody.preview ? (
                <pre className="code small">{r.responseBody.preview}</pre>
              ) : (
                <div className="body-flag flag-unavailable">
                  <strong>Sem corpo para comparar</strong>
                  <span>{r.responseBody.reason ?? "a fonte não forneceu prévia"}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [view, setView] = useState<View>(initialView);
  const [query, setQuery] = useState(params.get("q") ?? "");
  const initialFilter = (params.get("filter") as TypeFilter | null) ?? "all";
  const [typeFilter, setTypeFilter] = useState<TypeFilter>(initialFilter);
  const [protocol, setProtocol] = useState<"all" | Protocol>("all");
  const [selectedId, setSelectedId] = useState(params.get("id") ?? "req-0004");
  const [tab, setTab] = useState<DetailTab>(initialTab);
  const [aId, setAId] = useState(initialA);
  const [bId, setBId] = useState(initialB);

  const requests = demoSession.requests;
  const selected = requests.find((r) => r.id === selectedId) ?? requests[0];

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return requests.filter((r) => {
      if (typeFilter === "fetch" && !(r.type === "fetch" || r.type === "xhr")) return false;
      if (typeFilter === "document" && r.type !== "document") return false;
      if (typeFilter === "media" && !(r.type === "image" || r.type === "font")) return false;
      if (typeFilter === "error" && r.status < 400) return false;
      if (protocol !== "all" && r.protocol !== protocol) return false;
      if (!q) return true;
      return (
        r.url.toLowerCase().includes(q) ||
        r.id.includes(q) ||
        r.method.toLowerCase() === q ||
        String(r.status).includes(q)
      );
    });
  }, [requests, query, typeFilter, protocol]);

  const errors = requests.filter((r) => r.status >= 400).length;
  const counts = {
    all: requests.length,
    fetch: requests.filter((r) => r.type === "fetch" || r.type === "xhr").length,
    document: requests.filter((r) => r.type === "document").length,
    media: requests.filter((r) => r.type === "image" || r.type === "font").length,
    error: errors,
  };

  const openDetail = (id: string) => {
    setSelectedId(id);
    setTab("headers");
    setView("detail");
  };

  return (
    <div className="app" data-theme={theme}>
      <div className="window">
        <div className="titlebar">
          <div className="traffic">
            <span className="tl close" />
            <span className="tl min" />
            <span className="tl max" />
          </div>
          <div className="title">
            ScrapeLens
            <span className="title-sep">—</span>
            <span className="title-sub">
              {demoSession.synthetic ? "sessão de demonstração" : demoSession.label}
            </span>
          </div>
          <div className="title-actions">
            {demoSession.synthetic && <span className="tag tag-demo">DEMO</span>}
            <span className="tag tag-synthetic">dados sintéticos</span>
            <button
              className="icon-btn theme"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              title="Alternar tema claro/escuro"
            >
              {theme === "light" ? "◐" : "◑"}
            </button>
          </div>
        </div>

        <div className="demo-banner">
          <span className="demo-badge">DEMO</span>
          <p>
            <strong>Sessão sintética.</strong> Nenhum byte foi capturado: domínios <span className="mono">.invalid</span>,
            corpos inventados e eventos simulados servem só para revisar a interface. Controles de captura seguem
            desativados até o gate de fidelidade.
          </p>
          <span className="demo-right mono">sem telemetria</span>
        </div>

        {view === "session" && (
          <>
            <div className="session-bar">
              <div className="session-id">
                <div className="sid-top">
                  <span className="dot-live" />
                  <span className="sid-label">{demoSession.label}</span>
                  <span className="tag tag-demo">DEMO</span>
                  <span className="tag tag-state">sessão fechada</span>
                </div>
                <div className="sid-meta mono">
                  {demoSession.id} · {demoSession.chromeVersion} · criada {fmtTime(demoSession.createdAt)} ·{" "}
                  {demoSession.capture.cdpEvents} eventos CDP · NetLog {fmtBytes(demoSession.capture.netlogBytes)}
                </div>
              </div>
              <div className="session-actions">
                <button className="btn primary" disabled title="Captura ao vivo depende do gate de fidelidade">
                  Iniciar sessão
                </button>
                <button className="btn" disabled title="Nada para encerrar nesta fatia">
                  Encerrar
                </button>
                <button className="btn" disabled title="Importação HAR/NetLog chega depois dos contratos">
                  Abrir captura…
                </button>
              </div>
            </div>

            <div className="notice">
              <span className="notice-icon">i</span>
              <span>
                Controles de sessão desativados nesta fatia de UI. O botão “Abrir captura…” e a captura ao vivo
                entram depois do contrato oficial e da prova de fidelidade.
              </span>
            </div>

            <div className="toolbar">
              <div className="search">
                <span className="search-icon">⌕</span>
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Buscar domínio, caminho, id, status…"
                  aria-label="Buscar requisições"
                />
                <kbd>⌘F</kbd>
              </div>
              <div className="filters">
                {(
                  [
                    ["all", "Todos"],
                    ["fetch", "Fetch/XHR"],
                    ["document", "Documento"],
                    ["media", "Mídia"],
                    ["error", "Erros 4xx/5xx"],
                  ] as [TypeFilter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    className={typeFilter === id ? "chip-filter active" : "chip-filter"}
                    onClick={() => setTypeFilter(id)}
                  >
                    {label}
                    <span className="count">{counts[id]}</span>
                  </button>
                ))}
              </div>
              <label className="proto-select">
                <span>Protocolo</span>
                <select value={protocol} onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
                  <option value="all">todos</option>
                  <option value="HTTP/1.1">HTTP/1.1</option>
                  <option value="HTTP/2">HTTP/2</option>
                  <option value="HTTP/3">HTTP/3</option>
                </select>
              </label>
              <button className="btn" onClick={() => setView("compare")}>
                Comparar requisições…
              </button>
            </div>

            <div className="table-wrap">
              <table className="req-table">
                <thead>
                  <tr>
                    <th className="col-idx">#</th>
                    <th className="col-method">Método</th>
                    <th className="col-domain">Domínio</th>
                    <th className="col-path">Caminho</th>
                    <th className="col-status">Status</th>
                    <th className="col-proto">Protocolo</th>
                    <th className="col-type">Tipo</th>
                    <th className="col-time num">Duração</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <tr
                      key={r.id}
                      className={undefined}
                      onClick={() => openDetail(r.id)}
                      title="Abrir painel de detalhe"
                    >
                      <td className="mono dim">{String(i + 1).padStart(2, "0")}</td>
                      <td>
                        <span className={`method ${methodClass[r.method] ?? "m-other"}`}>{r.method}</span>
                      </td>
                      <td className="domain">{r.domain}</td>
                      <td className="mono path">{r.path}</td>
                      <td>
                        <span className={`status ${statusClass(r.status)}`}>{r.status}</span>
                      </td>
                      <td>
                        <span className="proto">{r.protocol}</span>
                      </td>
                      <td className="type">{typeLabels[r.type]}</td>
                      <td className="num mono time">
                        <span className="time-bar" style={{ width: `${Math.min(100, (r.durationMs / 460) * 100)}%` }} />
                        <span className="time-val">{fmtDuration(r)}</span>
                      </td>
                    </tr>
                  ))}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={8}>
                        <div className="empty">
                          Nenhuma requisição corresponde a “{query}” com os filtros atuais.
                          <button className="link" onClick={() => { setQuery(""); setTypeFilter("all"); setProtocol("all"); }}>
                            Limpar busca e filtros
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="statusbar">
              <span>
                {filtered.length} de {requests.length} requisições
              </span>
              <span className="sep">·</span>
              <span>2 fontes: CDP + NetLog</span>
              <span className="sep">·</span>
              <span>{demoSession.capture.cdpEvents} eventos CDP</span>
              <span className="sep">·</span>
              <span>Sessão sintética — nada foi capturado</span>
              <span className="grow" />
              <span className="mono dim">⌘O abrir · ⌘F buscar · ⌘C copiar</span>
            </div>
          </>
        )}

        {view === "detail" && (
          <DetailView req={selected} tab={tab} setTab={setTab} onBack={() => setView("session")} />
        )}

        {view === "compare" && (
          <CompareView aId={aId} bId={bId} setA={setAId} setB={setBId} onBack={() => setView("session")} />
        )}
      </div>
    </div>
  );
}
