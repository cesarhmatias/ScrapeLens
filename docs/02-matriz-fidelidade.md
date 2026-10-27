# Matriz de fidelidade — ordem e repetição de headers

Pergunta central: **quais fontes e eventos preservam qual sequência de
headers em cada protocolo e versão do navegador?**

Preencher por experimento controlado. Cada linha exige evidência (arquivo de
experimento + captura). Sem evidência = "não verificada".

## Ambiente medido

| Item | Valor |
|---|---|
| Navegador | Chrome `156.0.8078.48` (headless=new, perfil temporário dedicado) |
| SO | macOS `26.5.2` (25F84), arm64 |
| Data | 2026-10-26 |
| Protocolos | HTTP/1.1 (`127.0.0.1:8781`), h2/TLS+ALPN (`:8782`), h3/QUIC (`:8783`) |
| Referência (camada c) | servidor local que grava os pares decodificados em JSONL, sem dicionário |
| Amostra | 15 experimentos, **60 requisições** analisadas (20 por protocolo) |
| Reprodução | `cd experiments && .venv/bin/python run_experiment.py --all && .venv/bin/python compare.py` |

h3 funcionou neste ambiente contra o servidor `aioquic` do mock (QUIC habilitado,
`--origin-to-force-quic-on=127.0.0.1:8783`, certificado autoassinado dispensado
por SPKI hash — nada instalado). Contra o servidor de contrato (`quiche`) o h3
está bloqueado: ver "Cross-check" abaixo.

## Veredito rápido

`✓` preserva · `~` preserva com perda parcial · `—` não preserva

| Fonte / evento | h1 ordem | h1 duplicatas | h2 ordem | h2 duplicatas | h3 ordem | h3 duplicatas |
|---|---|---|---|---|---|---|
| CDP `requestWillBeSent.request.headers` | — (subconjunto) | — | — (subconjunto) | — | — (subconjunto) | — |
| CDP `requestWillBeSentExtraInfo.headers` | — | — | — | — | — | — |
| CDP `responseReceivedExtraInfo.headersText` | ✓ | ✓ | n/d | n/d | n/d | n/d |
| CDP `responseReceivedExtraInfo.headers` | — | — | — | — | — | — |
| NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | ✓ | ✓ | n/d | n/d | n/d | n/d |
| NetLog `HTTP2_SESSION_SEND_HEADERS` | n/d | n/d | ~ (1 troca) | ~ (`cookie` pode ser dividido) | n/d | n/d |
| NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | n/d | n/d | n/d | n/d | ✓ | — (campo `cookie` dividido no fio) |
| NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| NetLog `HTTP2_SESSION_RECV_HEADERS` | n/d | n/d | ✓ | ~ (`\x00`) | n/d | n/d |
| NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | n/d | n/d | n/d | n/d | ✓ | ~ (`\x00`) |
| HAR (exportador do DevTools) | não verificada | não verificada | não verificada | não verificada | não verificada | não verificada |

`n/d` = não se aplica ao protocolo. Detalhe e evidência por linha abaixo.

Duas ressalvas que valem para a tabela acima:
`cookie` e `priority` trocam de posição no fio h2 (o log mostra `cookie` antes);
e a fragmentação de `Cookie` em vários campos no h2 é **condicional** — 1 campo
com 2–3 cookies no mock, N campos com 3–4 cookies no contrato.

## Matriz principal

Ordens separadas em três colunas, conforme exigido:
**(a)** ordem apresentada pela fonte · **(b)** ordem entregue ao codificador
(HPACK/QPACK/linha HTTP) · **(c)** ordem decodificada observada no servidor.

| Navegador | Protocolo | Fonte/evento | (a) ordem da fonte | (b) ao codificador | (c) decodificada | Preserva | Transformações observadas | Limites | Evidência |
|---|---|---|---|---|---|---|---|---|---|
| 156.0.8078.48 | h1 | CDP `Network.requestWillBeSent` → `request.headers` | objeto JSON com **5 a 9 headers** conforme o caso (5 em 16/20; 6 nos 2 POST; 9 nos 2 fetches com `Headers`): no GET simples `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | não é o ponto de entrada | `Host, Connection, Pragma, Cache-Control, sec-ch-ua*, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-*, Accept-Encoding, Accept-Language[, Cookie]` | apenas o conjunto desses headers | **omite** `Host`, `Accept`, `Cookie`, `Accept-Encoding`, `Accept-Language`; e a enumeração **não segue o fio** (no fio `sec-ch-ua*` vem antes de `Upgrade-Insecure-Requests`/`User-Agent`; aqui vem depois) | não serve para sequência; só para saber quais headers o Blink injetou | `results/h1-page/layers.json`, `results/h1-plain/cdp-events.jsonl` |
| 156.0.8078.48 | h1 | CDP `Network.requestWillBeSentExtraInfo` → `headers` | **ordem ASCII/case-sensitive** (20/20 `sorted_ascii=true`): `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Sec-Fetch-Dest, …, User-Agent, x-mixed-Case, x-rep, x-seq` | não é o ponto de entrada | ordem real do fio (acima) | conjunto completo de nomes | ordena por byte; **colapsa duplicatas** no `net::HttpRequestHeaders` antes de expor; valor sobrevivente = último | ordem inutilizável; duplicata já perdida na origem | `results/h1-ordered/layers.json` (ver `cdp_extra.verdict=reordenada`) |
| 156.0.8078.48 | h1 | CDP `Network.responseReceivedExtraInfo` → `headersText` | `HTTP/1.1 200 OK\r\ncontent-type: …\r\nset-cookie: sl_a=1\r\nset-cookie: sl_b=2\r\n…` | — | `content-type, cache-control, x-resp-order×2, set-cookie×2, content-length, connection` | **ordem e duplicatas exatas**, caixa original | nenhuma (bloco bruto) | só h1; só resposta; texto, não estrutura | `results/h1-page/layers.json` → `response.cdp_headersText.verdict=idêntica` |
| 156.0.8078.48 | h1 | CDP `Network.responseReceivedExtraInfo` → `headers` | objeto com chaves ordenadas: `cache-control, connection, content-length, content-type, set-cookie, x-resp-order` | — | 2× `set-cookie`, 2× `x-resp-order` | conjunto de nomes | ordena ASCII; funde duplicatas com `\n` (`"sl_a=1; Path=/\nsl_b=2; Path=/"`) | perde ordem **e** repetição; exige re-dividir por `\n` (perda se o valor contiver `\n`) | `results/h1-page/layers.json` → `response.cdp_object` |
| 156.0.8078.48 | h1 | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | lista `["Host: …", "Connection: …", …, "x-rep: c", …]` | **idêntica à do fio** (20/20, nome e caixa) | idêntica | ordem, caixa e duplicatas | nenhuma | evento por requisição; não traz o request id do CDP (correlação só por URL/método/tempo) | `results/h1-ordered/chrome-netlog.json`, `results/h1-page/layers.json` |
| 156.0.8078.48 | h1 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | lista com linha de status + pares | — | idêntica (20/20), inclusive 2× `set-cookie` e 2× `x-resp-order` | ordem e duplicatas | nenhuma | sem `requestId`; casar por URL/`content-length`/tempo | `results/h1-page/chrome-netlog.json` |
| 156.0.8078.48 | h2 | CDP `requestWillBeSent.request.headers` | 5–9 headers Blink (mesma distribuição do h1), ordem própria | não é o ponto de entrada | `:method, :authority, :scheme, :path` + 15–16 campos | apenas o conjunto | **não expõe pseudoheaders**; omite `Host`/`Cookie`/`Accept`; ordem ≠ fio | não serve para sequência | `results/h2-page/layers.json` |
| 156.0.8078.48 | h2 | CDP `requestWillBeSentExtraInfo` → `headers` | ASCII (20/20); nomes em minúsculas | não é o ponto de entrada | ordem do fio | conjunto de nomes | ordena ASCII; colapsa duplicatas; **não** representa pseudoheaders | ordem inutilizável | `results/h2-page/layers.json` |
| 156.0.8078.48 | h2 | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | lista com pseudoheaders `":method", ":authority", ":scheme", ":path"` + campos | igual ao evento de sessão | ordem do fio, exceto o par `cookie`/`priority` | ordem e duplicatas | pseudoheaders aparecem como texto `":path: /x"` | mesma troca de posição do evento de sessão | `results/h2-page/chrome-netlog.json` |
| 156.0.8078.48 | h2 | NetLog `HTTP2_SESSION_SEND_HEADERS` | lista de pares na ordem de envio ao HPACK | **referência da camada (b)** | **20/20: 7 idênticas, 13 com `cookie` antes de `priority`**; o fio traz `priority` antes de `cookie` | ordem (com 1 exceção), caixa, duplicatas | pseudoheaders incluídos; `cookie`/`priority` trocam de posição na codificação | 1 posição divergente quando há `Cookie` | `results/h2-page/layers.json` (`b_netlog.verdict=reordenada`) |
| 156.0.8078.48 | h2 | NetLog `HTTP2_SESSION_RECV_HEADERS` | lista **com duplicatas fundidas por `\x00`**: `"x-resp-order: 1\u00002"`, `"set-cookie: sl_a=1…\u0000sl_b=2…"` | — | 2× `set-cookie`, 2× `x-resp-order`, ordem correta | ordem | funde repetições num único par separado por NUL; após expandir, 20/20 idênticas | parser que só divide por `\n` perde a 2ª ocorrência | `results/h2-page/layers.json` → `response.netlog_session.nul_joined=true` |
| 156.0.8078.48 | h2 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `"HTTP/1.1 200"` sintético + pares **separados** | — | idêntica (20/20) | ordem e duplicatas | inventa linha de status HTTP/1.1 para resposta h2 | status vem de `HTTP2_SESSION_RECV_HEADERS` (`:status`) | `results/h2-page/layers.json` → `response.netlog_other` |
| 156.0.8078.48 | h3 | CDP `requestWillBeSent.request.headers` | 5–9 headers Blink (mesma distribuição do h1), ordem própria | não é o ponto de entrada | `:method, :authority, :scheme, :path` + 14–16 campos | apenas o conjunto | igual ao h2: sem pseudoheaders, ordem ≠ fio | não serve para sequência | `results/h3-page/layers.json` |
| 156.0.8078.48 | h3 | CDP `requestWillBeSentExtraInfo` → `headers` | ASCII (20/20) | não é o ponto de entrada | ordem do fio | conjunto de nomes | ordena; **funde os campos `cookie` em 1** (13/20 divergem só por isso) | ordem e repetição perdidas | `results/h3-page/layers.json` (`cdp_extra.verdict=duplicatas fundidas` em 13/20) |
| 156.0.8078.48 | h3 | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | lista com `":method" …` e **1** `cookie: sl_a=1; sl_b=2; sl_c=3` | mesma lista do evento de sessão | **3** campos `cookie` (1 por cookie) | ordem geral | **cookie "crumble"**: o QPACK divide o campo Cookie em N campos; o NetLog mostra a forma não dividida | contagem de `Cookie` no NetLog ≠ fio; posição relativa a `priority` preservada | `results/h3-page/layers.json` (`b_netlog.verdict=duplicatas fundidas` 13/20) |
| 156.0.8078.48 | h3 | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | lista de pares + `quic_stream_id`, urgência | **referência da camada (b)** | como acima | ordem, caixa; **não** a divisão de cookie | 1 `cookie` no log → N no fio; `priority` ao final | requer cruzar com o servidor para saber o nº real de campos Cookie | `results/h3-page/chrome-netlog.json` |
| 156.0.8078.48 | h3 | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | pares com `\x00` nas repetições (`:status` incluso) | — | 2× `set-cookie` na ordem escrita | ordem, duplicatas após expandir NUL | funde repetições com `\x00` | idem h2 | `results/h3-page/layers.json` |
| 156.0.8078.48 | h3 | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | status sintético + pares separados | — | idêntica (20/20) | ordem e duplicatas | status fabricado | idem h2 | `results/h3-page/layers.json` |
| 156.0.8078.48 | todos | **HAR (exportador do DevTools)** | **não verificada** | — | — | — | `Network.getHAR` não existe no CDP desta versão; o exportador HAR do DevTools é código de frontend e não foi instrumentado | ordem HAR não comprovada; qualquer ordem herdada seria a de `ExtraInfo` (ASCII), com duplicatas fundidas | ver "HAR" abaixo; `results/*/har-derived.json` é reconstrução rotulada |

### Cookie: um campo no log, N campos no fio

| Observação | h1 | h2 (mock) | h2 (contrato) | h3 |
|---|---|---|---|---|
| 2 cookies → campos `cookie` no fio | 1 | 1 | — | 2 |
| 3 cookies (JS) → campos no fio | 1 | 1 | — | 3 |
| 3 cookies (Set-Cookie + `SameSite=Lax`, mesmos nomes/valores do contrato) → campos no fio | 1 | 1 | 3 | 3 |
| 4 cookies no contrato → campos no fio | 1 | — | 4 | — |
| NetLog / CDP mostram | 1 | 1 | 1 | 1 |

- h1 **nunca** fragmenta (1 campo com pares separados por `; `).
- h3 **sempre** fragmenta (1 campo por cookie).
- h2 é **dependente do par (servidor/configuração)**, não do conjunto de cookies:
  os *mesmos* 3 cookies (`sc_a=alpha; sc_b=beta; sc_dup=two`, `Path=/;
  SameSite=Lax`) saíram como **1 campo** contra o mock e como **3 campos** contra
  o servidor de contrato, no mesmo Chrome. Experimentos `*-set3`.
  O fator do lado do servidor (SETTINGS/HPACK do par) **não foi isolado**.
- Prova de que a fragmentação acontece depois do ponto de log: o bloco HPACK
  bruto do contrato (`header_block_b64`) decodificado à parte contém 3–4 campos
  `cookie`, enquanto `requestWillBeSentExtraInfo.headers` traz **um** só.
- Consequência para o produto: `Cookie` deve ser lido como **lista de campos**
  (0..N) e reunido por nome ao comparar com o que o scraper enviou.

### Pseudoheaders: ordem estável e igual em h2 e h3

Medido em três decodificadores independentes (meu servidor `h2`/`aioquic`,
NetLog do Chrome e o bloco HPACK bruto do contrato decodificado à parte):
`:method, :authority, :scheme, :path` — **a mesma ordem em h2 e em h3**, em
todas as 60 requisições. Não há inversão `:scheme`/`:authority` entre protocolos;
o que muda é onde cada fonte os expõe (CDP não expõe pseudoheader algum; o NetLog
mostra `":path: /x"` como texto).

Nota: o README/mensagem do `testserver/` descreve h2 como
`:method, :scheme, :authority, :path`; o JSONL e o `header_block_b64` do próprio
`testserver/` mostram `:method, :authority, :scheme, :path`. Vale a evidência
gravada, não a descrição.

### Camada (b) ≠ camada (c): exemplos concretos

h1 — `GET /echo-order?case=ordered`, header list entregue por
`Fetch.continueRequest` (`results/h1-ordered/fetch-decisions.jsonl`):

| (b) lista fornecida (6 pares) | (c) decodificada no servidor (3 pares) |
|---|---|
| `x-rep: a`, `x-seq: 1`, `X-Rep: b`, `x-seq: 2`, `x-mixed-Case: V`, `x-rep: c` | `x-rep: c`, `x-seq: 2`, `x-mixed-Case: V` |

O Chrome deduplica por nome case-insensitive (último valor vence) e mantém a
ordem de primeira aparição. Ou seja: **header fornecido a uma API não é enviado
sem transformação** — nem em ordem, nem em repetição.

h1 — `GET /echo-order?from=jsheaders`, `Headers` da Fetch API com
`append('x-dup','a')` + `append('x-dup','b')`:
`(c)` mostra **um** header `x-dup: a, b`. Além disso a ordem de inserção
(`x-zeta, x-alpha, x-mid`) não sobrevive: os três aparecem intercalados com
headers do Chrome (`x-zeta, x-alpha, sec-ch-ua*, x-mid, …`).

h2 — `GET /page` com cookies: `(b)` `…, accept-language, cookie, priority`;
`(c)` `…, accept-language, priority, cookie`.

h3 — `GET /page` com 3 cookies: `(b)` `…, cookie: sl_a=1; sl_b=2; sl_c=3, priority`;
`(c)` `…, cookie: sl_a=1, cookie: sl_b=2, cookie: sl_c=3, priority`.

## Contagens (60 requisições)

| Protocolo | NetLog envio vs servidor | CDP `ExtraInfo` vs servidor |
|---|---|---|
| h1 | 20/20 idênticas (nome e caixa), duplicatas preservadas | 20/20 reordenadas (ASCII) |
| h2 | 7/20 idênticas; 13/20 reordenadas (`cookie`/`priority`) | 20/20 reordenadas (ASCII) |
| h3 | 7/20 idênticas; 13/20 com campo `cookie` fundido | 20/20 reordenadas; 13/20 também com `cookie` fundido |

Resposta (20 por protocolo): ordem idêntica em 60/60 no evento NetLog
transacional; repetições fundidas por `\x00` em 100% dos eventos de sessão
h2/h3 e preservadas em 100% dos eventos transacionais.

## Cross-check contra os servidores do contrato

O mesmo pipeline (launcher + CDP + NetLog) foi rodado contra `testserver/`
(Rust, `httlib-hpack` para h2 e `quiche` para h3), uma implementação
independente do meu mock Python. Evidência:
`experiments/results/contract-{h1,h2}/layers.json`; reprodutor:
`experiments/crosscheck_contract.py --proto all`.

| Protocolo | Requisições | NetLog vs servidor | Observação |
|---|---|---|---|
| h1 | 14 | **14/14 idênticas** (nome e caixa) | confirma a linha do mock, inclusive `Set-Cookie` duplicado e redirects |
| h2 | 14 | 13/14 com `cookie` fundido; 1/14 idêntica | confirma que o NetLog mostra **1** campo `cookie` e o fio recebe 3–4; confirma também a troca `cookie`/`priority` |
| h3 | 0 | **não verificada** | Chrome aborta com `ERR_QUIC_PROTOCOL_ERROR`; o NetLog mostra `TLS handshake failure … CERTIFICATE_VERIFY_FAILED` e um cliente `aioquic` independente também falha (`h3 poll error: StreamCreationError`) → defeito do servidor de contrato, não da captura |

Os 14 pedidos do contrato incluem casos que o mock não tem (redirects em cadeia,
duas requisições idênticas simultâneas, POST de 128 KiB) e o NetLog continuou
fiel no h1 e fiel-exceto-cookie no h2.

## HAR

`Network.getHAR` **não existe** no CDP do Chrome 156.0.8078.48
(`results/h1-plain/cdp-meta.json` → `harAvailable=false`). O exportador HAR do
DevTools roda no frontend, sobre os mesmos eventos CDP; não foi instrumentado
neste marco. Portanto: **ordem em HAR = não verificada**, e as linhas acima já
mostram que a matéria-prima que o exportador consome (`requestWillBeSentExtraInfo`)
vem ordenada em ASCII e com duplicatas já colapsadas.

`har_from_cdp.mjs` gera um HAR 1.2 **rotulado como reconstrução** para servir de
fixture ao importador (`results/h1-page/har-derived.json`). Não use esse arquivo
como prova de ordem.

## A ordem que o DevTools mostra é a transmitida?

**Não, e não dá para assumir que seja.** O painel de rede do DevTools e o
exportador HAR são construídos sobre os mesmos eventos CDP medidos aqui
(`requestWillBeSent` + `requestWillBeSentExtraInfo`). Nesses eventos a ordem é a
de um mapa ordenado por byte (ASCII) e as duplicatas já chegaram colapsadas no
`net::HttpRequestHeaders` — ou seja, a lista que aparece na tela **não é** a
lista entregue ao codificador nem a decodificada no servidor (linhas h1/h2/h3
acima, 60 requisições).

Para o caso de referência (ordem do WebInspector do Chromium 141, reproduzida
manualmente com `curl_cffi`):

- Replicar a ordem do DevTools e a chamada funcionar **não prova** que a ordem
  foi transmitida: a maioria dos servidores ignora a ordem dos campos, e o
  próprio caso documenta que o que quebrava era valor dinâmico (SESSIONID/
  STAMP/delta), não ordem de header.
- Em h1 a prova existe e é barata: `HTTP_TRANSACTION_SEND_REQUEST_HEADERS`
  (NetLog) traz a ordem, a caixa e as duplicatas exatas; em h2/h3 o evento de
  sessão traz a lista entregue ao HPACK/QPACK.
- Sem esses eventos, o estado correto na interface e na exportação é
  **"ordem transmitida: não verificada"** — nunca "ordem preservada".
- Medido nesta matriz em Chrome **156**; o caso usou **141**. O mecanismo
  (mapa ordenado no `HttpRequestHeaders`) é o mesmo tipo de estrutura, mas 141
  não foi medido aqui — se for preciso afirmar algo sobre 141, rode este mesmo
  harness com aquela build.

Checagem de 2 minutos para o caso real, quando houver atribuição: abrir a
captura com NetLog, pegar a requisição da aplicação (POST Connector) e comparar
`HTTP_TRANSACTION_SEND_REQUEST_HEADERS` com a ordem que o HAR/DevTools mostra.
Divergência de ordem no HAR é esperada; o que importa é o que o NetLog diz.

## Limites

- Tudo em `headless=new`. Comportamento de headers do Chrome é o mesmo em headed
  nos testes anteriores do projeto, mas **não foi medido aqui** com janela visível.
- h3 exigiu `--origin-to-force-quic-on`; Alt-Svc não foi usado (evita migração
  silenciosa h2→h3 no meio do experimento). Sem esse flag o Chrome usaria h2.
- Cada sessão usa um NetLog isolado (`--host-resolver-rules` bloqueia DNS externo),
  mas eventos de background do próprio navegador ainda aparecem no arquivo; o
  comparador filtra por URL/`content-length`.
- Correlação CDP↔NetLog é feita por URL+método+`content-length`(+presença de
  `set-cookie`); os IDs não são equivalentes. Nos 60 casos a resposta foi
  inequívoca, mas a ferramenta
  deve tratar ambiguidade como ambígua (ver `b_netlog.candidates`).
- `Fetch.continueRequest` foi usado apenas para *injetar* ordem/duplicatas, não é
  mecanismo de captura do produto.
- Não foi medido `QUIC` com 0-RTT nem retry. Requisições idênticas simultâneas
  foram exercitadas apenas no servidor de contrato (h1/h2), onde a correlação
  por URL+método+ordem de ocorrência se manteve inequívoca.
- h3 contra o servidor de contrato está bloqueado (ver acima); a linha h3 desta
  matriz vem do servidor `aioquic` do mock.
- O gatilho da fragmentação de `Cookie` no h2 não foi isolado.

## Regras

- Não assumir: HAR preserva ordem; enumeração CDP = sequência transmitida;
  evento NetLog = sequência final; headers de biblioteca são enviados sem
  transformação; 403 vem da ordem de headers.
- Referência de servidor deve observar a ordem bruta no ponto de decodificação
  (dicionário normalizado não serve).
- Diferenciar ordem de headers de requisição de ordem de pacotes/frames/
  requisições concorrentes.
- Se a sequência transmitida não puder ser comprovada: registrar "não
  verificada" e seguir com funcionalidades independentes.
