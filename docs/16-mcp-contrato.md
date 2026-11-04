# Contrato do MCP do ScrapeLens (rodada 11, onda 1)

Dono: Core e importadores. Código: `mcp/` (crate `scrapelens-mcp`, binário
`scrapelens-mcp`). Base: `docs/15a-mercado-mcp.md` (seção de ferramentas). Este
documento vem antes do código; mudanças de contrato passam pelo líder.

## 1. O que é

Servidor MCP **local** sobre sessões já capturadas (leitura) e, desde a onda 2,
com captura controlada de navegador (§6b). Um agente
de IA o usa para entender a configuração de um site (cadeia de requisições,
headers na ordem original, cookies, tokens, corpos) a partir de sessões do
ScrapeLens. Fica fora do escopo: agir no navegador (`act`), executar scripts,
CloakBrowser (adiado por decisão do usuário), HTTP/streamable (só stdio nesta
onda).

Princípios:

- Reaproveita o core (`scrapelens-core`): nenhum parser, correlação, diff ou
  busca é reimplementado. O crate só traduz parâmetros, aplica a política de
  segurança e formata saídas.
- Não abre conexões de rede por conta própria (o core também não; o crate não
  depende de cliente HTTP). O único tráfego é o do Chrome da captura controlada,
  restrito à allowlist confirmada (§6b), e a porta CDP em loopback. Sem telemetria.
- Fidelidade acima de conveniência: headers voltam como **arrays ordenados de
  pares** com duplicatas, pseudoheaders separados e `orderState`; nunca viram
  mapa nem são ordenados. Cada visão carrega a fonte e o estado de verificação.
- Heurística nunca é apresentada como fato: ligações ambíguas, `possible`,
  `unobservable` e avisos do core passam adiante com os mesmos rótulos.

## 2. Execução e diretórios

```
scrapelens-mcp --sessions-dir <dir> [--out-dir <dir>] [--extra-sessions-dir <dir>]...
               [--allow-reveal] [--max-import-bytes <n>]
```

| Opção | Significado |
|---|---|
| `--sessions-dir` | Obrigatória. Onde `import_session` grava e de onde `list_sessions` lê. Criado 0700 se não existir. |
| `--out-dir` | Onde vão os arquivos de corpos grandes. Padrão: `<sessions-dir>/.mcp-out` (0700). |
| `--extra-sessions-dir` | Zero ou mais. Diretórios com sessões **só para leitura** (ex.: fixtures). Nunca recebem escrita. |
| `--allow-reveal` | Sem esta opção `reveal=true` é recusado (`reveal_disabled`). |
| `--max-import-bytes` | Limite por arquivo de entrada do `import_session` (padrão 512 MiB). |

Stdout é o canal JSON-RPC; todo log vai para stderr. Transporte: stdio.

### Limites de leitura e escrita

- **Escrita** só em: `<sessions-dir>/<session_id>/` (import) e `<out-dir>/`
  (corpos grandes e `export_session`) ou no `destination` absoluto validado da
  exportação (novo/vazio, 0700, fora da sessão de origem). Todo caminho de
  escrita é montado pelo servidor a partir de nomes validados
  (`[A-Za-z0-9._-]`, sem `..`, sem `/`) e conferido depois de canonicalizado: se
  sair do diretório, a chamada falha com `outside_allowed_dir`. Diretórios 0700,
  arquivos 0600, escrita atômica.
- **Leitura de sessões**: só `--sessions-dir` e `--extra-sessions-dir`.
  Parâmetros `session_id` são handles, nunca caminhos.
- **Leitura de entrada do import**: o `path` pode ser qualquer arquivo/diretório
  que o usuário aponte (o servidor roda com as permissões dele), mas só
  arquivo regular ou diretório; symlink na raiz é resolvido, limite de tamanho
  se aplica, nada é executado e o conteúdo é tratado como dado não confiável.
- Strings vindas de sessões (URLs, headers, corpos) são **dados não confiáveis**:
  o servidor nunca as interpreta como instrução nem as usa como caminho.

## 3. Segredos: mascarados por padrão

`reveal` (booleano, padrão `false`) existe em toda ferramenta que devolve
valores. `reveal=true` exige `--allow-reveal` no servidor.
**Decisão do líder (rodada 11):** a trava é dupla — parâmetro por chamada
*e* `--allow-reveal` ao iniciar o servidor; o agente não revela sozinho.
**Exceção explícita (rodada 17):** `export_session` com `include_sensitive:true`
grava os valores no diretório local 0700/0600 a pedido do usuário, mas o JSON de
resposta não devolve valor algum (ver §5.10).

Com `reveal=false`:

- A sessão é passada pelo mesmo sanitizador de `export::sanitize` (o da
  exportação sanitizada), uma vez por sessão, em memória, e as ferramentas
  `list_requests`, `get_request`, `get_body`, `search_bodies`, `diff_requests` e
  `diff_sessions` operam sobre essa cópia. Isso cobre `Authorization`,
  `Cookie`/`Set-Cookie`, tokens em URL (query e fragmento), headers de
  credencial, campos de negócio sensíveis e valores sensíveis propagados para
  outros lugares. Placeholder: `[REDACTED]`.
- **Corpos**: só JSON e formulários passam, com os campos sensíveis
  redigidos. HTML, JS, texto livre e binário **não são sanitizáveis com
  segurança** (política do core): `get_body` devolve o descritor com
  `masked: "unsupported"` e sem conteúdo; `search_bodies` não os varre e conta
  em `skippedMasked`. Para lê-los é preciso `reveal=true`.
- **Metadados de corpo** (`state`, `bytes`, `contentType`, `hasRequestBody`/
  `hasResponseBody`) saem da sessão original mesmo na visão mascarada, para a
  máscara não esconder que existe um corpo; só o conteúdo é retido.
- **`target` e `initiator`**: o sanitizador do core mascara `target.url`,
  `initiator.url` e a URL do topo do stack (query e fragmento) em toda
  exportação sanitizada. O servidor aplica `sanitize_url` de novo nesses
  campos e nas URLs de `trace_value` (defesa em profundidade, coberta por
  teste próprio).
- **Formas de URL e nomes** (revisão, docs/17): o sanitizador cobre também
  fragmento (`#access_token=`), parâmetros de matriz (`;jsessionid=`), userinfo
  (`user:senha@`), `nome=valor` sem `?` (Refresh, Location, texto livre), `%3D`,
  esquemas de autenticação sem caixa exata (`bearer`, `ApiKey`, `OAuth`…), os
  nomes `jwt`, `senha`, `pwd`, `otp`, `passcode`, `pin`, `ticket`,
  `SAMLResponse`, `*-api-key`, `*-appkey`, `*-secret`, `*-token`,
  `*-subscription-key`, `*csrf*`/`*xsrf*`, e o `parseError` de Set-Cookie não
  repete o valor cru.
- **Valor sensível em caminho (limitação aceita, A7-B5/A8-M1):** o valor de um nome
  sensível num CAMINHO (`/a;jsessionid=X/b`, `/s/token=X/y`) vai até o próximo `?`
  (ou `#`, ou o fim do caminho) e é redigido inteiro, `/` incluída, porque um
  credencial (base64) pode conter `/`. Custa o resto do caminho depois dele:
  `/a;v=2/session=keep/b` sai `/a;v=2/session=[REDACTED]`. Vale igual para o texto
  (linha de requisição, headers, JSON) e para a URL. Nomes não sensíveis não
  mudam nada. A segurança prevalece sobre a fidelidade. Exceção (A9-B1): `,` ou `|`
  seguido de `/` encerra o valor (lista sem espaço `/a/token=x/b,/c/keep` preserva o
  item seguinte); um credencial que contenha `,/` ou `|/` vaza o que vem depois.
- **Texto cru com query** (rodada 11, correção de vazamento): o sanitizador do
  core redige o valor de parâmetro de query com nome sensível também em
  `startLine` de requisição (`GET /p?token=… HTTP/1.1`), em qualquer valor de
  header que não seja URL conhecida (`Refresh`, `X-Original-Url`,
  `Content-Security-Policy` `report-uri`…), em `view.notes`, notas de
  proveniência, `failure`, evidências de ligação, razões de correlação e
  mensagens de aviso; a propagação por valor também varre `startLine`, notas,
  `target.url` e `initiator.url`. Além disso, **toda saída sem `revealed: true`
  de qualquer ferramenta** passa por uma última varredura do JSON inteiro
  (`scrub_output`), não só dos campos conhecidos. Limite herdado do core:
  parâmetros cujo **nome** não é sensível (ex.: `k=…`) não são redigidos nas
  URLs; nas saídas de captura a query inteira some (`?…`).
- **Custo**: a primeira chamada mascarada de uma sessão a carrega inteira em
  memória para sanitizá-la (cópia guardada em cache). Sessões muito grandes
  podem levar segundos e responder `too_large` se o core recusar o carregamento.
- **Valores de segredo nunca aparecem em `trace_value`** sem `reveal`: a
  ferramenta calcula sobre a sessão original (precisa dos valores reais para
  casar produtor e consumidor) e devolve apenas nomes, comprimentos,
  booleanos de igualdade e posições.
- `diff_requests` e `diff_sessions` comparam a cópia mascarada: dois valores
  mascarados diferentes aparecem iguais (`[REDACTED]`). A saída traz
  `masked: true` e a nota correspondente; o `diff_sessions` do core classifica
  esses campos como `redacted`, não como `static`.
- `search_bodies` mascarado não serve de oráculo: consultar um valor secreto
  não encontra nada, porque ele já está redigido na cópia pesquisada.

Com `reveal=true` as mesmas ferramentas leem a sessão original. Cada resposta
traz `revealed: true`.

## 4. Convenções

- Saída: `structuredContent` (objeto JSON, camelCase, mesmo vocabulário do
  `session.json` do core) e o mesmo JSON em texto. Todas as ferramentas têm
  `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`
  (`import_session` é a exceção: escreve em `--sessions-dir`; fica
  `readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`).
- IDs: `session_id` = nome do diretório da sessão; `request_id` = `id` lógico
  do `session.json` (ex.: `har-0003`, `cdp-r0007`).
- Paginação: `limit` (padrão 50, máximo 200), `cursor` opaco devolvido em
  `nextCursor` (ausente quando acabou). Saídas paginadas trazem `total` e
  `hasMore`.
- Erros: resultado com `isError: true` e `structuredContent`
  `{"error":{"code","message"}}`. Parâmetros que não casam com o esquema
  (campo obrigatório ausente, tipo errado) são recusados pelo SDK com
  `isError: true` e texto livre dizendo o campo, sem `structuredContent`. Códigos: `invalid_argument`, `not_found`
  (sessão ou requisição), `outside_allowed_dir`, `reveal_disabled`,
  `import_failed`, `too_large`, `exists`, `io`.
- Corpos: nunca texto gigante na resposta. Limite inline `maxInlineBytes`
  (padrão 32 KiB, máximo 256 KiB). Acima disso, ou se não for UTF-8, o conteúdo
  vai para um arquivo em `--out-dir` e a resposta traz `path`.

## 5. Ferramentas

Notação: `?` = opcional. Todos os `session_id`/`request_id` são strings.

### 5.1 `list_sessions`

Entrada: `{ cursor?, limit? }`.
Saída: `{ total, hasMore, nextCursor?, sessions: [ { sessionId, readOnly,
startedAt, browser: {name, version?}, captureMode?, requests, attempts,
completeness: {state, reasons[]}, warnings, labels[] } ] }` — ordenadas por
`startedAt` decrescente, depois por `sessionId`.

### 5.2 `import_session`

Entrada: `{ path, format?, name? }`.
`format`: `auto` (padrão) | `har` | `netlog` | `session` | `capture`.
`capture` = diretório com `cdp-events.jsonl` e um NetLog (`netlog.json` ou
`chrome-netlog.json`), opcionalmente `cdp-bodies.jsonl`: correlação CDP×NetLog
pelo core. `session` = diretório com `session.json` (sessão nativa) copiado
para `--sessions-dir`. `name`: nome do handle (validado); sem ele, é derivado do
nome do arquivo e do id da sessão. Se o handle já existir: se vier do mesmo
conteúdo (mesmo `meta.id`) devolve `alreadyImported: true` sem regravar; com
`name` explícito e conteúdo diferente, `exists`.
Saída: `{ sessionId, alreadyImported, format, requests, warnings: [{code,
message, severity}] (até 50), report: {sourceEvents, unknown, ...} }`.
Escreve só em `<sessions-dir>/<sessionId>/` via `store::write_session_dir`.

### 5.3 `list_requests`

Entrada: `{ session_id, host?, method?, status?, resource_type?, text?,
cursor?, limit?, reveal? }`.

- `host`: igual (sem diferenciar caixa) ao `host[:porta]` da URL.
- `method`: igual, sem diferenciar caixa.
- `status`: `"200"`, `"2xx"`, `"4xx"`, `"none"` (sem resposta) ou número.
- `resource_type`: igual (sem diferenciar caixa) ao tipo da requisição (CDP/HAR).
- `text`: substring (sem diferenciar caixa) na URL **apresentada** (mascarada
  se `reveal=false`). Para corpos use `search_bodies`.

Saída: `{ sessionId, total, hasMore, nextCursor?, items: [ { requestId, method,
url, host, status?, resourceType?, protocol, totalMs?, attempts, redirects,
sources[] ("cdp"|"netlog"|"har"|...), match, targetType? , hasRequestBody,
hasResponseBody, startedAt?, warnings? } ] }` na **ordem da sessão, que não é
cronológica** em capturas reais (medido: a lista vem por id; `cdp-r0004` pode ser a
primeira requisição no tempo). `startedAt` (segundos da fonte, menor tempo entre
as tentativas) permite ordenar. Resumo apenas: sem headers nem corpos.

### 5.4 `get_request`

Entrada: `{ session_id, request_id, attempt?, verbose?, reveal? }`.
`attempt`: id ou índice da tentativa (padrão: visão primária da requisição
lógica, que é a última tentativa). `verbose`: devolve também a proveniência por
entrada (padrão: só por visão).

Saída:

```
{ sessionId, requestId, method, url, status?, protocol, resourceType?,
  target?, links[], attempts: [{id,index,url,status?,outcome,connectionId?,streamSessionId?,match}],
  redirects[], 
  request:  { startLine?, orderState, source, verification, pseudoHeaders: [[n,v]],
              headers: [[n,v]], rawBlock?, notes[] },
  response: { ...idem... },
  cookies:   { raw[], pairs: [{name,value}], wireLines[], unparsed[] },
  setCookies:[{ raw, name?, attributes{domain,path,expires,maxAge,secure,httpOnly,sameSite,partitioned}, parseError? }],
  headerEvidence: [{ id, role, protocol, event, sourceId?, order, count }],
  requestBody:  { state, bytes?, contentType?, contentEncoding?, transformed[], note?, hasContent },
  responseBody: { ... },
  timings: { totalMs?, tls?, send?, wait?, receive?, estimated },
  initiator?: { kind, url?, line?, stackTop? ... },
  origin: { logical: "cdp"|"netlog"|"har"|..., cdp?: {sessionId,requestId,loaderId,frameId}, netlog?: {sourceIds[],streamIds[]}, match, matchCandidates[] },
  warnings[], revealed }
```

Headers vêm **na ordem original** (`headers` e `pseudoHeaders` separados),
duplicatas preservadas. `source`/`verification` vêm da proveniência da visão
(`cdp`, `netlog`, `har`; `verified` | `unverified` | ...), `orderState` diz se
a ordem é comprovada. Quando há várias evidências (ex.: transação + sessão h2)
elas aparecem em `headerEvidence` sem fundir; o conteúdo de uma evidência
específica sai com `attempt` e `verbose`.

### 5.5 `get_body`

Entrada: `{ session_id, request_id, part?, offset?, length?, max_inline_bytes?,
reveal? }`. `part`: `response` (padrão) | `request`. `offset`/`length` em bytes
do corpo armazenado (limite de leitura 5 MiB do core; acima disso
`readTruncated: true`).

Saída: `{ sessionId, requestId, part, state, bytes?, contentType?,
contentEncoding?, transformed[], note?, masked?: "unsupported"|"redacted",
revealed, range: {offset,length,total}, inline: bool, text?, path?,
encoding: "utf8"|"binary" }`.

- Capturado, UTF-8 e dentro do limite inline: `inline: true`, `text`.
- Maior que o limite ou binário: grava `<out-dir>/bodies/<sessionId>/<requestId>-<part>-<offset>-<length>[.masked].bin|txt`
  e devolve `path` (`inline: false`). O arquivo é a fatia exata devolvida.
- Corpo `empty`/`unavailable`/`discarded`/`truncated`: o estado e a nota do core
  são devolvidos sem inventar conteúdo. `truncated` indica `truncatedAt`.
- Os bytes são os armazenados na sessão; o servidor não decodifica
  `Content-Encoding` (o core já registra `transformed` quando decodificou).

### 5.6 `search_bodies`

Entrada: `{ session_id, query, scopes?, case_sensitive?, cursor?, limit?,
reveal? }`. `scopes` ⊂ {`url`, `requestHeaders`, `responseHeaders`, `cookies`,
`requestBody`, `responseBody`}; vazio = todos. Busca de **texto literal**
(regex fica fora desta onda).
Saída: `{ sessionId, total, hasMore, nextCursor?, matches: [ { requestId,
attemptId, scope, field?, byteOffset?, byteLength?, exact, snippet, decoded,
htmlControl } ], partial, partialAttempts[], skippedBinary, skippedMasked,
limitReached, revealed }`. `snippet` é curto (limite do core); nunca o corpo
inteiro. `partial: true` = algum corpo truncado foi pesquisado (busca parcial).

### 5.7 `diff_requests`

Entrada: `{ session_id, request_a, request_b, other_session_id?, ignore?,
reveal? }`. `other_session_id`: sessão de `request_b` (padrão: a mesma).
`ignore`: nomes de header/cookie (sem diferenciar caixa) removidos das listas
`added/removed/changed/reordered` e dos cookies antes de devolver; o total
removido vem em `ignored`.
Saída: o `RequestDiff` do core (`diff::diff_requests`) + `{ sessionId,
otherSessionId, masked, ignored, notes[] }`. Duplicatas e a ordem original são
preservadas (`reordered` separa mudança de posição de mudança de valor). Nunca
há ordenação alfabética silenciosa.

### 5.8 `diff_sessions`

Entrada: `{ session_id_a, session_id_b, map_origin?: {from,to}, a_range?,
b_range?, include_all?, only_changed?, cursor?, limit?, reveal? }`.
`a_range`/`b_range`: `"de:ate"` (ids ou números 1-based).
`only_changed` (padrão `true`): em cada par, só os campos que não são
`static`. `cursor`/`limit` paginam `pairs` (padrão 10, máximo 50).
Saída: o `SessionComparison` do core (`compare::compare_sessions`) com
`pairs` paginado + `{ masked, totalPairs, hasMore, nextCursor? }`. Avisos,
ambiguidades, rodadas sem par e mapeamento de origem passam como vieram.

### 5.9 `trace_value`

De onde vem um cookie ou token e onde é usado. Três modos (exatamente um):

- `{ session_id, cookie }` — **cookie por nome**: respostas que o definem
  (`Set-Cookie`, em ordem de tempo), requisições que o enviam.
- `{ session_id, value, reveal:true }` — **valor** (token, id): onde aparece, com
  produtor mais antigo e consumidores posteriores. **O modo `value` EXIGE
  `reveal`** (dupla trava: `reveal:true` e servidor com `--allow-reveal`). Sem
  isso responde `reveal_required`, qualquer que seja o valor: achar ou não achar
  um valor fornecido pelo agente seria um oráculo sobre conteúdo mascarado
  (substring, força bruta, reimportação da sessão para zerar contadores,
  estrutura conhecida como `Basic base64("admin:PIN")`). A busca é por
  substring literal (evidência `literal-match`). Os modos `cookie` e
  `request_id` continuam sem `reveal`, sem `valueLength` nem outro dado derivado
  do valor (com `reveal`, `valueLength` volta).
- `{ session_id, request_id, field? }` — **origem dos valores consumidos por
  uma requisição** (`flow::value_origins` do core, com as mesmas
  `evidences`, `strength`, `confidence`, `unobservable`, `context`).

Comuns: `limit?` (padrão 50, máximo 200 por lista), `reveal?`.
Os modos `cookie` e `value` ordenam as requisições por `startedAt` (menor tempo
entre as tentativas) quando todas têm tempo; senão usam a ordem da sessão e
isso vai em `notes`. "Primeiro" e "depois" sempre se referem a essa ordem.

Saída (cookie): `{ mode:"cookie", cookie, firstSetter?: {requestId, attemptId,
url, startedAt?, source, attributes{...}}, setters[], users: [ {requestId,
attemptId, url, startedAt?, sentValueEqualsFirstSetter: true|false|null} ],
truncated, notes[], evidence }`. Sem resposta observada que defina o cookie,
`firstSetter` é nulo e `notes` diz que ele pode vir de `document.cookie`, do
perfil do navegador ou de captura incompleta — nunca se afirma a origem.
`sentValueEqualsFirstSetter` compara na sessão original e devolve só o booleano
(`null` = sem setter para comparar).

Saída (valor, só com reveal): `{ mode:"value", length, firstProducer?, producers[],
consumers[], truncated, warnings[] }` onde cada ocorrência é `{requestId,
attemptId, scope, field?, byteOffset?, position}`. Produtor = ocorrência em
resposta (headers, `Set-Cookie`, corpo); consumidor = URL, headers da requisição,
cookies enviados, corpo da requisição, depois do produtor. Valores com menos de
8 caracteres geram aviso (coincidência pode ser acaso). A relação é igualdade de
substring (`"literal-match"`); não prova causalidade.

Saída (requisição): o `ValueOrigins` do core; a prévia `value` de cada entrada
é `"[REDACTED]"` salvo `reveal=true` (comprimento, campo, escopo e evidências
ficam).

`value` fornecido pelo agente nunca é ecoado sem `reveal`.

### 5.10 `export_session`

Grava uma cópia da sessão num diretório privado. **Não** revela valores no JSON
de resposta: devolve só caminho e contagens.

```json
{ "session_id": "...", "destination": "minha-exportacao", "include_sensitive": false }
```

- **Sanitizada (padrão, `include_sensitive: false`):** aplica
  `export::sanitize::sanitize_bundle` com as opções padrão, grava com
  `store::write_session_dir` e **não** leva `cdp-events.jsonl` nem `netlog.json`
  brutos. Saída: `{sessionId, path, includeSensitive:false, requests,
  attachmentsWritten, rawArtifactsWritten:[], totalRedactions, report
  {redactions, warnings, omittedAttachments}}`.
- **Completa (`include_sensitive: true`):** grava o bundle original **sem
  redação** e copia os artefatos brutos existentes na origem
  (`cdp-events.jsonl`, `netlog.json`, `cdp-bodies.jsonl`), recusando symlink e
  aplicando 0600. Saída sem `report` e com `totalRedactions: 0`. Não exige
  `--allow-reveal`: é uma ação local, explícita, pedida pelo usuário ao LLM;
  os segredos ficam no diretório 0700/0600, nunca no stdout.
- **Destino:** `destination` omitido → `<out-dir>/<session_id>-sanitized` (com
  `-2`, `-3`… se existir) ou `<out-dir>/<session_id>-full` (recusa se já
  existir). Nome simples sem `/` resolve dentro de `--out-dir`; caminho absoluto
  é aceito se não for a sessão de origem nem ficar dentro dela (ou de outra
  sessão/raiz reservada), se nenhum ancestral existente for symlink (exceto os
  aliases de sistema do macOS `/var`, `/tmp`, `/etc` → `/private/...`) e se o
  diretório não existir ou estiver vazio (o diretório pai precisa existir). O
  destino é criado 0700; os arquivos, 0600.

## 6. Testes exigidos

- Unitários por ferramenta, contra as fixtures existentes
  (`fixtures/aceite/*`, HARs de `fixtures/`, capturas de `experiments/results/`),
  sem editá-las.
- Mascaramento: segredos de `fixtures/aceite/sanitize` não aparecem em nenhuma
  saída sem `reveal`; `reveal` recusado sem `--allow-reveal`.
- Limites de caminho: `name` com `..`/`/`, `session_id` com caminho, escrita fora
  do diretório.
- Ponta a ponta: o binário real por stdio (`initialize`, `tools/list`,
  `tools/call` para cada ferramenta), com asserção de que stdout só traz
  JSON-RPC.
- `export_session`: sanitizada redige os segredos e não leva artefatos brutos;
  `include_sensitive:true` preserva headers/cookies/corpos e os arquivos
  `cdp-events.jsonl`/`netlog.json`/`cdp-bodies.jsonl` com 0700/0600, e o JSON
  devolvido não contém os valores; destinos perigosos (dentro da origem, outra
  sessão, raiz reservada, symlink, diretório não vazio) são recusados.

## 6b. Navegador e perfil do site (rodada 11, onda 2)

Cinco ferramentas ligam `scrapelens-capture` (`capture/`) e `scrapelens-recon`
(`recon/`) ao servidor, com os esquemas de `docs/16b-mcp-navegador.md` (§3, §4,
§5). Dependências por path; o servidor não reimplementa nada da captura.

- `start_capture {allowed_hosts[], third_party_hosts?[], start_url?,
  binary_path?, headless?, expose_cdp?}` → `StartInfo` (sem caminhos) +
  `captureId`, `sessionId` (nome do diretório que a sessão terá em
  `--sessions-dir`) e `confirmation` (`elicited` | `unconfirmed-flag`).
- `navigate {capture_id, url, wait?=load|none, timeout_ms?}` → `NavigateResult`.
  A allowlist recusa antes de enviar (`url_not_allowed`).
- `capture_status {capture_id}` → `recording`, `events`, `pageUrl`, `lastError`.
- `stop_capture {capture_id}` → `StopReport` (sem caminhos) + `sessionId`
  legível pelas ferramentas de leitura (`readable: true`), com
  `allowlist.blockedHosts` e `violations`.
- `site_profile {session_id, target_request_id?}` → `scrapelens.site-profile/1`
  (achados com evidência, recomendação). Os ids de evidência resolvem em
  `get_request`. Roda sobre a sessão original (precisa dos valores para
  rastrear tokens); o `recon` já redige valores (`[redigido, N bytes]`) e tira a
  query das URLs, e o servidor passa as URLs pelo filtro mesmo assim.

Regras do servidor:

- **Confirmação**: `start_capture` SEMPRE pede elicitação MCP (formulário com a
  caixa `confirmo`), mostrando `allowed_hosts`, `third_party_hosts`, URL inicial,
  `expose_cdp`, modo, binário do Chrome e `SENSITIVE_NOTICE`. Nenhum parâmetro
  `confirmed` existe no esquema. Só `accept` com a caixa marcada abre o Chrome;
  recusa, cancelamento, erro JSON-RPC, resposta malformada, `confirmo` que não
  seja o booleano `true`, prazo (5 min) ou conexão caída → `confirmation_denied`,
  e **nada é aberto**, mesmo com a flag. Só quando o cliente **não declara**
  suporte a elicitação → `confirmation_unavailable`, a menos que o servidor
  tenha sido iniciado com `--allow-unconfirmed-capture` (dupla trava, como o
  reveal). Cancelar o pedido, deixar o prazo vencer ou desconectar abandona a
  confirmação: um aceite tardio é ignorado, nada abre e a vaga é sempre
  liberada; se o Chrome já estava subindo, ele é parado quando fica pronto. O
  texto da confirmação segue a semântica oficial do 16b §2.2: o navegador
  impõe o HOST em todas as portas, a **porta só é imposta no `navigate`**, e
  aprovar `localhost:8080` aprova `localhost` em qualquer porta para a página.
  Pedidos inválidos (allowlist vazia/larga/inválida, `start_url` fora) são
  recusados **antes** da confirmação, sem incomodar o usuário.
- **Mapa de capturas**: `capture_id` → captura, em memória; ids opacos
  (`cap-<16 hex>`), nunca caminhos. **Uma captura ativa por vez**
  (`capture_already_running`, inclusive enquanto a confirmação está pendente).
  Depois de `stop_capture` o id deixa de existir (`capture_not_found`).
- **Encerramento**: stdin fechado, SIGTERM ou SIGINT param todas as capturas
  ativas de forma graciosa (a sessão é gravada) antes de sair. Um Chrome que
  ainda está subindo (`start_capture` em andamento) é esperado e parado assim
  que fica pronto (até 120 s); o servidor só sai depois. Ao iniciar, o servidor
  chama `cleanup_orphans` (órfãos de execuções que morreram).
- **Diretório da sessão**: `--sessions-dir/capture-<ms>`; o Chrome escreve só
  ali (perfil temporário próprio fica com o `capture/`).
- **Escrita de sessão** (`core::store::write_session_dir`/`write_atomic`):
  destino que seja symlink é recusado; temporário com nome único e `create_new`
  (um symlink plantado no nome previsível nunca é seguido); `attachments/` que
  seja symlink é recusado antes de qualquer `mkdir`/`chmod`; tudo é gravado sob
  o diretório canonicalizado.
- **Spill de corpos** (`get_body`): diretórios e arquivo temporário únicos
  criados sem seguir symlink (`create_new`); um componente que seja symlink é
  recusado (`outside_allowed_dir`) antes de qualquer `mkdir`/`chmod`; o arquivo
  sai 0600; handles que o `slug` fundiria (`x.y`, `x-y`) usam diretórios
  distintos (hash no nome); `session.json` que seja symlink não lista a sessão.
- **Sem caminhos nas saídas** (`sessionDir` removido). Nas saídas de captura
  (`pageUrl`, `exampleUrl`, `violations[].url`) e em qualquer texto delas
  (`warnings[]`) a **query, o fragmento e os parâmetros de matriz somem**
  (`…`): não há como saber qual parâmetro é segredo.
- Anotações: `start_capture` e `navigate` têm `readOnlyHint: false` e
  `openWorldHint: true` (tráfego para os hosts listados); `stop_capture`
  `readOnlyHint: false` (grava a sessão); `capture_status` e `site_profile` são
  só leitura.
- `expose_cdp=true` entrega o endereço CDP em loopback ao agente (depois do
  portão de `16b` §4.1). As ações do agente por esse CDP **não** passam por esta
  confirmação; o que as limita é a allowlist de rede aplicada pelo Chrome.

Testes: `mcp/tests/live.rs` (política e mapa, backend contado),
`mcp/tests/e2e_capture.rs` (servidor real com navegador falso do exemplo
`fake_server`: elicitação aceita/recusada/ausente, navigate fora da allowlist,
stop → `list_requests`/`site_profile`, encerramento por EOF e SIGTERM) e
`mcp/tests/e2e_live.rs` (`#[ignore]`, Chrome real + servidor em loopback). O
exemplo `fake_server` só é construído por `cargo test` (sem filtro) ou
`cargo build --examples`.

## 7. Fora desta onda

HTTP local, resources (`scrapelens://...`), regex em `search_bodies`,
ferramenta de ação do agente no navegador (`act`; o agente usa o CDP exposto),
`generate_priming_script`, `validate_run`. Entram em onda própria, com o líder.
