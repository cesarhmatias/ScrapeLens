# Contrato do MCP do ScrapeLens (rodada 11, onda 1)

Dono: Core e importadores. Código: `mcp/` (crate `scrapelens-mcp`, binário
`scrapelens-mcp`). Base: `docs/15a-mercado-mcp.md` (seção de ferramentas). Este
documento vem antes do código; mudanças de contrato passam pelo líder.

## 1. O que é

Servidor MCP **local e somente leitura** sobre sessões já capturadas. Um agente
de IA o usa para entender a configuração de um site (cadeia de requisições,
headers na ordem original, cookies, tokens, corpos) a partir de sessões do
ScrapeLens. Fica fora do escopo: lançar navegador, capturar, navegar, executar
scripts, CloakBrowser (adiado por decisão do usuário), HTTP/streamable (só
stdio nesta onda).

Princípios:

- Reaproveita o core (`scrapelens-core`): nenhum parser, correlação, diff ou
  busca é reimplementado. O crate só traduz parâmetros, aplica a política de
  segurança e formata saídas.
- Não abre conexões de rede (o core também não; o crate não depende de cliente
  HTTP). Sem telemetria.
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
  (corpos grandes). Todo caminho de escrita é montado pelo servidor a partir de
  nomes validados (`[A-Za-z0-9._-]`, sem `..`, sem `/`) e conferido depois de
  canonicalizado: se sair do diretório, a chamada falha com
  `outside_allowed_dir`. Diretórios 0700, arquivos 0600, escrita atômica.
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
hasResponseBody, warnings? } ] }` na ordem da sessão. Resumo apenas: sem headers
nem corpos.

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
- `{ session_id, value }` — **valor literal** (token, id): onde aparece, com
  produtor mais antigo e consumidores posteriores.
- `{ session_id, request_id, field? }` — **origem dos valores consumidos por
  uma requisição** (`flow::value_origins` do core, com as mesmas
  `evidences`, `strength`, `confidence`, `unobservable`, `context`).

Comuns: `limit?` (padrão 50, máximo 200 por lista), `reveal?`.

Saída (cookie): `{ mode:"cookie", cookie, firstSetter?: {requestId, attemptId,
url, startedAt?, source, attributes{...}}, setters[], users: [ {requestId,
attemptId, url, startedAt?, sentValueEqualsFirstSetter: true|false|null} ],
truncated, notes[], evidence }`. Sem resposta observada que defina o cookie,
`firstSetter` é nulo e `notes` diz que ele pode vir de `document.cookie`, do
perfil do navegador ou de captura incompleta — nunca se afirma a origem.
`sentValueEqualsFirstSetter` compara na sessão original e devolve só o booleano
(`null` = sem setter para comparar).

Saída (valor): `{ mode:"value", length, firstProducer?, producers[],
consumers[], truncated, warnings[] }` onde cada ocorrência é `{requestId,
attemptId, scope, field?, byteOffset?, position}`. Produtor = ocorrência em
resposta (headers, `Set-Cookie`, corpo); consumidor = URL, headers da requisição,
cookies enviados, corpo da requisição, depois do produtor. Valores com menos de
8 caracteres geram aviso (coincidência pode ser acaso). A relação é **igualdade
literal de texto**, sinalizada como `evidence: "literal-match"`; não prova
causalidade.

Saída (requisição): o `ValueOrigins` do core; a prévia `value` de cada entrada
é `"[REDACTED]"` salvo `reveal=true` (comprimento, campo, escopo e evidências
ficam).

`value` fornecido pelo agente nunca é ecoado sem `reveal`.

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

## 7. Fora desta onda

HTTP local, resources (`scrapelens://...`), regex em `search_bodies`,
ferramentas de ação (`browser_*`, `generate_priming_script`, `validate_run`),
elicitation. Entram em onda própria, com o líder.
