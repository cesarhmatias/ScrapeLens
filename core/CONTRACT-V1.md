# ScrapeLens — formato de sessão v1 (implementação do core)

Este documento descreve o JSON produzido/consumido por `core/`. Ele segue
`docs/03-contratos.md` e a matriz `docs/02-matriz-fidelidade.md`; em caso de
divergência, os docs oficiais vencem.

## Diretório

```
<sessao>/
  session.json        # documento completo (metadados + requests + entidades + warnings)
  cdp-events.jsonl    # eventos CDP brutos, um JSON por linha (opcional)
  netlog.json         # NetLog original do Chrome (opcional)
  attachments/        # corpos, nomes relativos citados em body.attachment
```

`session.json` é autossuficiente para a UI. Os artefatos brutos são preservados
ao lado para auditoria e nunca reescritos pelo importador. Escrita do core:
diretório `0700`, arquivos `0600`, rename atômico.

## Documento

```json
{
  "schemaVersion": 1,
  "session": {
    "id": "cdp-6f...",
    "browser": { "name": "Chrome", "version": "156.0.8078.48", "platform": "macOS arm64" },
    "startedAt": "2026-10-26T20:50:05.949Z",
    "endedAt": null,
    "completeness": {
      "state": "complete",
      "reasons": [],
      "counts": {
        "requests": 12, "attempts": 12, "redirects": 0,
        "connections": 1, "streamSessions": 2,
        "sourceEvents": 1845, "sourceEventsUsed": 122,
        "sourceEventsUnknown": 0, "warnings": 1
      }
    },
    "capture": { "mode": "cdp+netlog", "headless": true },
    "labels": [],
    "notes": []
  },
  "requests": [ /* LogicalRequest */ ],
  "connections": [ /* Connection */ ],
  "streamSessions": [ /* StreamSession */ ],
  "warnings": [ /* Warning */ ]
}
```

- `completeness.state`: `complete | partial`. `partial` significa captura
  interrompida, artefato ausente/inválido ou erro de parse. Ambiguidade de
  correlação é um estado de `match`, não rebaixa `completeness`.
  `reasons` explica cada caso; inferência de completude nunca é silenciosa.
- `labels`: `synthetic-fixture` em fixtures; `sanitized` em exportação
  sanitizada; `har-import`/`netlog-import` nos importadores correspondentes.
- `completeness.counts.sourceEvents*` é persistido por HAR/NetLog/CDP e
  sobrevive ao fechar e reabrir a sessão; não é apenas um aviso de importação.
- `warnings`: lista persistida de tudo que foi desconhecido, omitido ou
  truncado. `severity` é `info | warning | error`.

## HeaderView

Headers são **arrays ordenados de pares**, nunca dicionário. Duplicatas e caixa
original são preservadas. Pseudoheaders ficam em lista separada.

```json
{
  "pseudoHeaders": [
    { "name": ":method", "value": "GET", "source": "netlog", "method": "netlog.headers", "verification": "partial", "event": "HTTP2_SESSION_SEND_HEADERS" }
  ],
  "headers": [
    { "name": "x-rep", "value": "a", "source": "netlog", "method": "netlog.headers", "verification": "partial" },
    { "name": "X-Rep", "value": "b", "source": "netlog", "method": "netlog.headers", "verification": "partial" }
  ],
  "startLine": "GET /x HTTP/1.1",
  "rawBlock": "GET /x HTTP/1.1\r\nx-rep: a\r\n...",
  "orderState": "sourceOrder",
  "notes": []
}
```

- `orderState`: `sourceOrder | reconstructed | normalized | unknown`.
- `rawBlock` é o texto original quando a fonte o fornece (h1 `headersText` do
  CDP ou linha de request h1 do NetLog); nos demais eventos os pares ordenados
  já são o original e não são duplicados. Visões normalizadas **não**
  substituem este bloco.
- Cada header carrega `provenance` (campos achatados no próprio objeto):
  `source`, `event?`, `sourceId?`, `timestamp?` (segundos), `wallTime?`,
  `browserVersion?`, `method`, `verification`, `notes?`.
- `verification` é **por informação**: `verified | partial | unverified`.
  Nunca existe selo de sessão. A política está em
  `core/src/model/provenance.rs::policy` e reproduz D2.

## Cookie e Set-Cookie

```json
"cookie": {
  "raw": ["sl_a=1; sl_b=2; sl_c=3"],
  "pairs": [
    { "name": "sl_a", "value": "1", "raw": "sl_a=1", "source": "netlog", "method": "netlog.headers", "verification": "partial" }
  ],
  "wireLines": ["sl_a=1"],
  "unparsed": [],
  "notes": ["linhas do fio ..."],
  "provenance": { "source": "netlog", "method": "netlog.headers", "verification": "partial" }
}
```

- `raw` preserva o campo da fonte (0..N campos).
- `pairs` são os pares internos parseados, com o texto original de cada par.
- `wireLines` são as linhas `Cookie` observadas na fonte. O NetLog pode mostrar
  1 campo enquanto o fio h3 recebe N (cookie crumble); o core **não inventa**
  os campos que a fonte não mostra — registra a limitação em `notes`.
- `Set-Cookie`: `{ "raw": "...", "parsed": { name, value, domain?, path?,
  expires?, maxAge?, secure, httpOnly, sameSite?, partitioned, extensions?,
  notes? }, "parseError?", ...provenance }`. Linhas brutas repetidas são
  registros separados, na ordem.

## Entidades

### LogicalRequest

```json
{
  "id": "cdp-r0001",
  "url": "https://demo.invalid/x",
  "method": "GET",
  "protocol": "h2",
  "status": 200,
  "resourceType": "document",
  "cdp": { "requestId": "95631.6", "loaderId": "...", "frameId": "..." },
  "netlog": { "sourceIds": [77], "streamIds": [1], "dependencyIds": [84] },
  "attempts": [ /* Attempt */ ],
  "redirects": [ /* Redirect */ ],
  "requestHeaders": { /* HeaderView da tentativa final */ },
  "responseHeaders": { /* HeaderView */ },
  "cookie": { /* CookieField */ },
  "setCookies": [ /* SetCookieRecord */ ],
  "requestBody": { /* Body */ },
  "responseBody": { /* Body */ },
  "timings": { "requestTime": 5640473.315, "totalMs": 120.0, "estimated": false },
  "match": "matched",
  "matchCandidates": [],
  "provenance": { /* Provenance */ }
}
```

`match`: `matched | ambiguous | unmatched`. `ambiguous` sempre traz
`matchCandidates` com `entityId`, `score` e `reasons`; nenhum candidato é
escolhido silenciosamente. `requestHeaders`/`responseHeaders` no nível lógico
são a **visão primária selecionada**; todo original fica em
`attempts[].headerEvidence`.

### Attempt

Campos de `LogicalRequest` que variam por tentativa (`url`, `method`,
`protocol`, `status`, `requestHeaders`, `responseHeaders`, `cookie`,
`setCookies`, `requestBody`, `responseBody`, corpos, `timings`,
`headerEvidence`, `connectionId`, `streamSessionId`, `failure`, `outcome`,
`match`). `outcome`: `completed | failed | aborted | pending | unknown`.

### Redirect / Connection / StreamSession

- `Redirect`: `{ id, logicalId, fromAttemptId, toAttemptId?, status?, location?,
  fromUrl, toUrl?, provenance }`.
- `Connection`: `{ id, netlogId?, protocol, host?, port?, ip?, alpn?,
  tlsVersion?, reused?, provenance }`.
- `StreamSession`: `{ id, connectionId?, protocol, streamId?, attemptId?,
  netlogSessionId?, provenance }`.

`headerEvidence[]`: `{ id, role: "request"|"response", protocol, event,
sourceId?, streamId?, view }`. Guarda o bloco de cada fonte (CDP Blink,
CDP ExtraInfo, NetLog transacional, NetLog de sessão) mesmo depois de a visão
primária passar de uma fonte para outra.

## Body

```json
{ "state": "captured", "attachment": "req-1.request.bin", "bytes": 42,
  "truncatedAt": null, "contentType": "application/json",
  "contentEncoding": null, "note": null, "provenance": { ... } }
```

`state`: `captured | empty | truncated | unavailable | discarded`. Ausência de
corpo **não** significa vazio: use `empty` só quando a fonte afirma 0 bytes;
`unavailable` e `discarded` têm `note`. `attachment` é relativo a
`attachments/` e validado contra path traversal na leitura.

## Regras de verificação (D2 resumido)

| Informação | Fonte | Estado |
|---|---|---|
| request h1 ordem+duplicatas | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | verified |
| response h1/h2/h3 ordem+duplicatas | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | verified |
| request h2/h3 ordem | NetLog sessão/transação | partial (Cookie pode estar fundido no log) |
| response h2/h3 repetições | NetLog sessão, NUL expandido | partial |
| response h1 `headersText` | CDP ExtraInfo | verified |
| objetos CDP `headers` | CDP | unverified (ASCII, duplicatas colapsadas) |
| HAR | HAR 1.2 | unverified (ordem não comprovada) |

O core expande repetições `\x00` dos eventos de sessão h2/h3 e re-dividindo
`Set-Cookie` fundido por `\n` no objeto CDP apenas para o parse, preservando o
valor bruto original no `HeaderView`.

## API Rust

```rust
use scrapelens_core::{import_har, import_netlog, import_session_dir};
use scrapelens_core::parse::import_capture;
use scrapelens_core::correlate::CorrelationOptions;
use scrapelens_core::store::write_session_dir;
use scrapelens_core::normalize::normalize_request;
use scrapelens_core::diff::{diff_requests, DiffOptions};
use scrapelens_core::export::curl::to_curl;
use scrapelens_core::export::python::to_python;
use scrapelens_core::export::sanitize::{sanitize_bundle, SanitizeOptions};
```

Cada importador devolve `ImportedSession { bundle, report }`; `bundle.session` é
`SessionV1`, `bundle.attachments` são os bytes carregados, e `report` traz
contagens/avisos da importação. Nenhuma função abre conexão de rede.

## CLI

```
scrapelens-core inspect <sessao>
scrapelens-core import-har <har> --out <sessao>
scrapelens-core import-netlog <netlog> --out <sessao>
scrapelens-core import-capture <cdp.jsonl> <netlog.json> --out <sessao>
scrapelens-core export-curl <sessao> <requestId> [--out arquivo]
scrapelens-core export-python <sessao> <requestId> [--out arquivo]
scrapelens-core sanitize <sessao> <saida>
scrapelens-core diff <sessao> <requestIdA> <requestIdB>
```

## Limites explícitos

- Exportadores cURL/Python reproduzem a requisição HTTP, **não** TLS, JA3/JA4,
  ordem de frames, HPACK/QPACK ou fingerprint do navegador.
- cURL usa quoting bash/POSIX (`$'...'` para bytes de controle). Headers com
  CR/LF/NUL são descartados com aviso; `Content-Length` é removido quando o
  corpo não acompanha a exportação.
- Sanitização é **heurística**: cobre nomes de parâmetros/headers conhecidos
  (`token`, `sid`, `jsessionid`, `phpsessid`, ...), prefixos de autenticação
  (`Bearer`, `Basic`, `Digest`, `Token`) e corpos estruturados. Não detecta
  tokens embutidos em segmentos de path, HTML/JS livre ou texto não
  estruturado; esses corpos são omitidos com aviso. Nomes e contagem de
  headers/cookies são preservados para auditoria. Notas da sessão e metadados
  de conexão são preservados; revise-os antes de compartilhar.
- HAR não comprova ordem/duplicatas; NetLog h3 mostra Cookie fundido, embora o
  fio possa receber N campos.
- O NetLog isolado não prova cobertura de sessão CDP; a sessão resultante fica
  `partial` até ser correlacionada com uma captura CDP.
