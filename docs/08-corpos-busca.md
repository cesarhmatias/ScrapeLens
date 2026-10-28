# Rodada 4 — corpos CDP e busca no payload

## Motivo

A captura ao vivo não grava corpos. `core/src/parse/cdp.rs` marca toda
requisição e resposta como `unavailable` ("corpo CDP não carregado"). A busca
da UI filtra só metadados. O caso de referência DETRAN-PB
(`docs/05-caso-referencia-detran.md`) precisa achar `cmd_consultar_placa` no
corpo form-urlencoded e distinguir dois POSTs com a mesma URL e o mesmo método.
Especificação: "Payload e corpos quando disponíveis", "Busca e filtros" e
"Mostre corpos indisponíveis, truncados ou descartados explicitamente".

Fora do escopo: decodificador Natural for Ajax, comparação dinâmico × estático
entre capturas, replay, rede externa e publicação.

## Ondas (máx. 3 executores)

- 4a, em paralelo: Captura (gravar corpos), Core (importar corpos + busca) e
  Testes (fixtures com corpos), todos sobre o formato do §1.
- 4b, depois de 4a verde: App (busca e corpos na UI) e revisão independente.

## Propriedade nesta rodada

| Dono | Caminhos |
|---|---|
| Captura | `src-tauri/src/capture.rs`, `experiments/` (evidência dos corpos) |
| Core | `core/` |
| Testes | `fixtures/`, `testserver/`, `tests/` |
| App (4b) | `app/`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs` |
| Líder | `docs/` |

Se alguém precisar de um arquivo de outro dono, deve reportar antes de editar.
Preservar `tests/results/app-latest/testserver/app-20261027/h1.jsonl`
(modificação pré-existente, fora dos commits).

## 1. Formato `cdp-bodies.jsonl` (contrato entre Captura, Core e Testes)

Arquivo irmão de `cdp-events.jsonl` no diretório da captura, com permissão
0600 e um objeto JSON por linha:

```json
{"v":1,"requestId":"1234.5","attemptIndex":0,"kind":"request|response",
 "state":"captured|truncated|empty|unavailable|discarded",
 "encoding":"utf8|base64|null","data":"…|null",
 "originalSize":123,"capturedSize":123,
 "source":"requestWillBeSent.postData|requestWillBeSent.postDataEntries|Network.getRequestPostData|Network.getResponseBody",
 "reason":"texto|null","timestamp":12345.678}
```

Regras:
- `requestId` e `attemptIndex` seguem a numeração de tentativas que o core
  já usa (`attemptIndex` 0 = primeiro `requestWillBeSent`; cada redirect
  soma 1).
- Corpo de requisição: por tentativa, vindo do `postData`/`postDataEntries` do
  respectivo `requestWillBeSent`; se `hasPostData` sem dados, usar
  `Network.getRequestPostData`.
- Corpo de resposta: apenas da tentativa final, via `Network.getResponseBody`
  depois de `loadingFinished`. Respostas de redirect recebem `unavailable` com
  motivo "resposta de redirect: CDP não fornece corpo". `loadingFailed`,
  recurso despejado ou erro do CDP também viram `unavailable`, com a mensagem
  real do erro.
- Limite por corpo: padrão 5 MiB de bytes decodificados. Acima disso, gravar o
  prefixo com `truncated` e `originalSize` quando conhecido. Orçamento total
  da sessão: padrão 256 MiB. Excedido, os corpos seguintes ficam `discarded`
  com o motivo "orçamento de corpos da sessão excedido".
- `base64` se o CDP disser `base64Encoded` ou se os bytes não forem UTF-8
  válido. Nunca decodificar, reinterpretar ou normalizar `data`: os bytes são
  os entregues pelo CDP.
- Streaming, WebSocket e SSE ficam `unavailable` com motivo, nunca vazios.
- A coleta não pode atrasar a navegação nem perder eventos. Falhas de coleta
  viram linhas `unavailable`, nunca silêncio.

## 2. Core

- `import-capture` lê `cdp-bodies.jsonl` ao lado do `.jsonl` de eventos,
  ou recebe `--bodies <arquivo>`. Sem o arquivo, mantém o comportamento atual,
  com um aviso por sessão (não por requisição).
- Cada corpo `captured`/`truncated` vira anexo em `attachments/` com o estado
  e a proveniência (`Source::Cdp`, evento = `source`, `requestId`). As linhas
  `unavailable`/`discarded` levam o motivo. Linha órfã (requisição
  inexistente) gera aviso, nunca associação por URL ou horário.
- A busca vive no core: `search(session, query) -> Vec<Match>`.
  - Escopos: `url`, `requestHeaders`, `responseHeaders`, `cookies`,
    `requestBody`, `responseBody`. O padrão é todos.
  - Match: `requestId`, `attemptId`, `scope`, `field` (nome do header, chave
    do form, caminho JSON ou null), `byteOffset` no original, `snippet`
    e `decoded: bool`.
  - Visão decodificada opcional e marcada: percent-decoding de
    form-urlencoded e strings JSON sem escape. Um match nela traz
    `decoded=true` e o `field`.
  - Corpos binários ou em base64 que não sejam texto são contados como
    `skippedBinary`, não pesquisados. Corpos `truncated` são pesquisados e o
    resultado diz "busca parcial".
  - CLI: `scrapelens-core search <sessao> <texto> [--scope …] [--case-sensitive]`
    com saída JSON.
- A exportação (cURL/Python) passa a incluir o corpo `captured` da tentativa
  correta, sem mudar as garantias atuais.

## 3. Aceite da rodada

1. DETRAN-PB (fixtures com corpos sintéticos de Testes): `search
   cmd_consultar_placa` acha exatamente os 2 POSTs pelo `requestBody`
   (`decoded=true`, `field` correto) e nenhum pela URL. A placa sintética da
   1ª consulta acha só a 1ª. `cmd_nova` acha o POST certo.
2. Captura ao vivo contra `testserver` local: POST form-urlencoded, JSON e
   binário. Os bytes gravados são idênticos aos recebidos pelo servidor. A
   resposta é idêntica aos bytes servidos (texto e gzip decodificado pelo
   Chrome).
3. Corpo > limite vira `truncated` com `originalSize`; um redirect 302 tem
   resposta `unavailable` com motivo; um 307 com corpo tem o corpo da
   requisição em cada tentativa.
4. Nenhum corpo ausente aparece como vazio. `empty` só com evidência (ex.:
   204, `Content-Length: 0`).
5. Sanitização: corpos continuam sendo redigidos pela política atual. A busca
   numa sessão sanitizada não acha os marcadores sensíveis.
6. Bateria verde: `cargo test` (core, src-tauri), `tests/exportacao`, aceite
   `tests/aceite/run_acceptance.py` sem regressão.

Commits Conventional Commits por dono, sem push nem publicação, sem executar
código exportado e sem rede externa.
