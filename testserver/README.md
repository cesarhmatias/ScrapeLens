# testserver — servidores de referência da ordem de headers

Servidores locais do projeto ScrapeLens que observam a **ordem decodificada**
dos headers no primeiro ponto disponível de cada protocolo, antes de qualquer
normalização em dicionário. Toda evidência é JSONL, sintética e local.

| Porta | Protocolo | Ponto de observação |
|---|---|---|
| `127.0.0.1:8781` | HTTP/1.1 (TCP) | bytes crus do socket: linha de requisição + linhas de header como chegaram (ordem, caixa, duplicatas) |
| `127.0.0.1:8782` | HTTP/2 (TLS, ALPN `h2`) | lista emitida pelo decodificador HPACK (`httlib-hpack 0.1.3`) na ordem de decodificação, pseudoheaders incluídos |
| `127.0.0.1:8783` | HTTP/3 (QUIC, ALPN `h3`) | lista `Vec<Header>` devolvida por `quiche 0.30` em `h3::Event::Headers` (ordem de decodificação QPACK) |

O h3 também escuta em UDP `127.0.0.1:8782` por padrão. QUIC usa UDP e o h2 usa
TCP, então as duas pilhas compartilham o número de porta: é isso que permite
`chrome --origin-to-force-quic-on=127.0.0.1:8782` medir h3 no mesmo origin do
h2. Desative com `--no-h3-on-h2-port`.

## Comandos

```sh
cd testserver
cargo build                      # Rust 1.98.1; Cargo.lock commitado
cargo test                       # 8 testes de integração (h1, h2, h3)
cargo run -- gen-cert            # só se fixtures/tls/ estiver ausente
cargo run -- serve               # três servidores, portas padrão
cargo run -- serve --only h1,h2  # subconjunto
./run-demo.sh                    # sobe, envia requisições ordenadas, resume a evidência
./scripts/chrome-probe.sh        # Chrome 156 headless: /page em h2 e em h3
```

Portas ocupadas? `./run-demo.sh 9781` (h1 9781, h2 9782, h3 9783) e
`./scripts/chrome-probe.sh 9781`.

Evidência: `fixtures/evidence/<run-id>/{h1,h2,h3}.jsonl` + `run.json` (metadados
da execução: portas, certificado, pin SPKI, `decode_points`, capacidade QPACK).
Cada requisição é um registro, com `flush` imediato — o arquivo é inspecionável
com os servidores ainda rodando.

## Endpoints (idênticos nos três protocolos)

| Endpoint | Comportamento |
|---|---|
| `GET /echo-order` | JSON com a lista de headers na ordem decodificada, duplicatas preservadas, `pseudoheaders` separados |
| `GET /setcookie` | dois `Set-Cookie` distintos (`sc_a`, `sc_b`) + par de mesmo nome (`sc_dup=one`, `sc_dup=two`), intercalados com marcadores `x-scrapelens-order: 0..4` |
| `POST /echo` | eco byte a byte do corpo (até 5 MiB; acima disso marca `body_truncated`) |
| `GET /page` | HTML sintético que dispara: cookies via JS + servidor, fetch com headers repetidos, duas requisições simultâneas idênticas, cadeia de redirect, POST pequeno e POST de 128 KiB, e um segundo fetch já com cookies |
| `GET /redirect?n=N` | `N` respostas 302 (`location: /redirect?n=N-1`) e depois 200 |
| `GET /multi/` | página multi-alvo (popup, `target=_blank`, OOPIF, worker, service worker); ver seção própria abaixo |
| `GET /healthz` | `ok` |

Respostas também trazem `server`, `content-length`, `cache-control: no-store`
e, no h2, `alt-svc: h3=":<porta-h3>"; ma=86400`. A ordem dos headers de
resposta é registrada na evidência exatamente como foi enviada.

## Evidência JSONL (`scrapelens.testserver.evidence/1`)

```json
{"schema":"scrapelens.testserver.evidence/1","seq":0,"ts_rfc3339":"2026-10-26T20:29:07.813Z",
 "ts_unix_ms":1793046547813,"proto":"h2","proto_wire":"HTTP/2 over TLS (ALPN h2)",
 "decode_point":"HPACK decoded field list (httlib-hpack 0.1.3), recorded in decode order before any map is built",
 "server":"127.0.0.1:8782","conn":"c1","stream":1,"method":"GET",
 "target":"/echo-order?probe=demo-h2","authority":"127.0.0.1:8782",
 "headers":[[":method","GET"],[":scheme","https"],[":authority","127.0.0.1:8782"],
            [":path","/echo-order?probe=demo-h2"],["user-agent","curl/8.7.1"],["accept","*/*"],
            ["x-order","first"],["x-order","second"],["x-dup","same"]],
 "pseudoheaders":[[":method","GET"],[":scheme","https"],[":authority","127.0.0.1:8782"],
                  [":path","/echo-order?probe=demo-h2"]],
 "header_count":9,"raw_head_b64":null,"header_block_b64":"godBigidXAuBcNx914UEkmCkn...",
 "body_b64":null,"body_len":0,"body_truncated":false,"body_framing":null,
 "response":{"status":200,"headers":[["content-type","application/json; charset=utf-8"],["..."],["content-length","1143"]],
             "header_count":8,"body_len":1143},
 "notes":[]}
```

Exemplos completos e reais de um registro por protocolo:
`fixtures/evidence-sample/{h1,h2,h3}.jsonl`.

Campos principais:

- `headers`: array ordenado de pares `[nome, valor]`, pseudoheaders na posição
  decodificada (h2/h3) e nomes em caixa original (h1). **Nunca** um objeto.
- `pseudoheaders`: subconjunto ordenado dos campos `:`.
- `raw_head_b64` (h1): bytes exatos da cabeçalho da requisição, com CRLF.
- `header_block_b64` (h2): bloco HPACK cru recebido (HEADERS + CONTINUATION),
  ao lado da lista decodificada.
- `body_b64`, `body_len`, `body_truncated`, `body_framing` (`content-length`,
  `chunked`, `none`).
- `response.headers`: headers de resposta na ordem enviada (inclui transporte).
- `conn`/`stream`: identificadores **do servidor** (`h3-3`, `c1`, stream h2/h3).
  Duas requisições idênticas e simultâneas aparecem como dois registros com
  `conn`/`stream` distintos; nada é associado por URL ou horário.
- `decode_point`: frase exata do ponto de observação daquele protocolo.
- `marker`: valor de `?m=` do target, quando existe (páginas `/multi/`); nos
  demais registros é `null`. O mesmo registro também vai para o `multi.jsonl`
  compacto — ver "Páginas multi-alvo".

## Certificado (fixtures/tls/)

PKI sintética de teste: CA (`scrapelens-test-ca.crt.pem`) + leaf para
`localhost`, `127.0.0.1` e `::1`. O pin do leaf está em
`fixtures/tls/spki-sha256-base64.txt`.

```sh
curl --cacert fixtures/tls/scrapelens-test-ca.crt.pem https://127.0.0.1:8782/echo-order
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PIN=$(grep -m1 -E '^[A-Za-z0-9+/=]+$' fixtures/tls/spki-sha256-base64.txt)
"$CHROME" --headless=new --user-data-dir=$(mktemp -d) \
  --ignore-certificate-errors-spki-list="$PIN" --enable-quic \
  --origin-to-force-quic-on=127.0.0.1:8782 \
  --dump-dom https://127.0.0.1:8782/page
```

Não instale a CA no chaveiro do sistema: o pin SPKI resolve o Chrome e os
clientes Rust usam a CA explicitamente. A chave da CA está no repositório
porque é material descartável de teste — nunca use fora daqui.

## O que o experimento com Chrome 156 já mostrou

Headless Chrome 156.0.8078.48, página `/page`, evidência do servidor (sintética):

- Headers repetidos passados a `fetch()` como lista de arrays chegam ao
  servidor **fundidos em um único campo com vírgula**: `x-order: first, second`
  e `x-dup: same, same` — em h2 e em h3. Ou seja, a lista entregue ao codificador
  já não contém as duplicatas; quem quiser provar duplicatas reais precisa de
  uma fonte que as tenha antes disso.
- Cookies são enviados como **quatro campos `cookie` separados** (um por
  cookie: `sc_page`, `sc_a`, `sc_b`, `sc_dup`), não como um campo com vírgulas,
  tanto em h2 quanto em h3. A ordem dos campos `cookie` seguiu a ordem de
  criação/armazenamento observada.
- `Set-Cookie: sc_dup=one` seguido de `sc_dup=two` (mesmo nome e Path) resultou
  em apenas `sc_dup=two` no pedido seguinte; `sc_a` e `sc_b` sobreviveram.
- Ordem dos pseudoheaders decodificados: h2 `:method,:scheme,:authority,:path`;
  h3 `:method,:authority,:scheme,:path`. Ordem preservada pelo servidor em ambos.
- Duas requisições idênticas simultâneas (`/echo-order?concurrent=1`) viram
  dois registros com streams distintos em uma única conexão, sem associação
  automática entre elas.
- Com a tabela dinâmica QPACK desabilitada no servidor, o Chrome manteve **uma
  conexão h3 para 13 requisições** sequenciais, incluindo POST de 128 KiB.

`/favicon.ico` também é registrado (404), como ruído real de navegador.

## Limites conhecidos

- **QPACK com tabela dinâmica**: o servidor anuncia `SETTINGS_QPACK_MAX_TABLE_CAPACITY=0`
  por padrão. Isso mantém cada field section autossuficiente (tabela estática +
  literais) e não afeta ordem nem duplicatas. Com capacidade > 0
  (`--h3-qpack-table 4096`), Chrome 156 abre a tabela dinâmica e quiche 0.30
  falha a **segunda** requisição da conexão com `QpackDecompressionFailed`
  (reproduzível; o Chrome então abre outra conexão). Registrado como limitação
  da ferramenta de referência, não conclusão sobre o navegador.
- quiche não expõe os bytes QPACK crus: a referência h3 é a lista já decodificada
  (é o ponto de decodificação, que é o que a matriz exige).
- O servidor h1 é HTTP em texto claro (porta 8781) de propósito: é a leitura
  bruta dos bytes. Para TLS/HTTP1.1 use h2 e force ALPN se necessário (não
  implementado aqui).
- `Alt-Svc` com origem em IP literal não foi honrado pelo Chrome headless nas
  execuções; use `--origin-to-force-quic-on`. O h2 continua anunciando o h3.
- Corpos acima de 5 MiB são truncados e marcados (`body_truncated: true`);
  o restante é drenado para manter o enquadramento.
- Dados 100% sintéticos, nada de telemetria, nada sai de `127.0.0.1`.

## Por que Rust (e não Go)

Mantido em Rust: os três servidores já estavam implementados, testados (8 testes
de integração) e validados com Chrome 156 em h1/h2/h3 — h2 no nível de frames com
o decoder HPACK exposto e h3 via quiche com `Vec<Header>` na ordem decodificada.
Go 1.27.3 (`net/http2` + `quic-go`) teria sido viável, mas a troca descartaria um
caminho já verificado, sem ganho de fidelidade (o ponto de observação seria o
mesmo); o contrato de portas, endpoints e JSONL não muda com a linguagem.

## Dependências (lockfile commitado)

Rust 1.98.1 · `httlib-hpack 0.1.3` (HPACK) · `quiche 0.30.0` (QUIC/h3/QPACK,
BoringSSL via cmake) · `rustls 0.23` + `rustls-pemfile` · `rcgen 0.14` ·
`serde`/`serde_json` · `base64` · `chrono` · `sha2`.
O build do quiche exige `cmake` (instalado via Homebrew) e rede apenas na
primeira compilação do BoringSSL embutido.

## Rotas para captura de corpos (rodada 4, docs/08-corpos-busca.md §3.2–3.3)

Iguais em h1/h2/h3. `serve` grava os corpos recebidos por `/sink` em `<evidence>/<run>/bodies/sink-NNNN-<sha256[..12]>.bin`
(além do `body_b64` completo já presente na evidência JSONL) para comparar byte a byte com `cdp-bodies.jsonl`.

| Rota | Resposta |
|---|---|
| `POST /sink` | grava o corpo; JSON `{len, truncated, sha256, file, content_type}` (limite de leitura 5 MiB, `truncated` se excedido) |
| `GET /json` | `application/json` fixo |
| `GET /binary` | 4099 bytes não-UTF-8 (`octet-stream`) |
| `GET /big[?mib=N]` | N MiB (padrão 6) de texto determinístico |
| `GET /gzip` | texto fixo com `Content-Encoding: gzip` (decodificado: `endpoints::GZIP_TEXT`) |
| `GET /redirect302` | 302 → `/json` |
| `POST /redirect307` | 307 → `/sink` (Chrome reenvia método e corpo) |
| `GET /empty` | 204 sem corpo (evidência para `empty`) |
| `GET /zero` | 200 com `Content-Length: 0` |

Teste: `cargo test h1_body_routes` (binário/6 MiB/gzip/302/307/204/sink).

## Páginas multi-alvo (rodada 10, docs/14-captura-multi-alvo.md)

Página de referência para o experimento de captura multi-alvo do CDP. Cada ação
dispara requisições com um marcador único `?m=`; o servidor grava o marcador no
JSONL normal e um log compacto `multi.jsonl` por run.

```sh
cargo run --release -- serve --only h1 --h1 127.0.0.1:8781
# abra http://127.0.0.1:8781/multi/ num Chrome (popup bloqueado? use
# --disable-popup-blocking, ou chame window.__scrapelensMulti.openPopup() via CDP)
./scripts/multi-probe.sh            # sobe o h1, abre /multi/ no Chrome headless
                                    # e confere os 16 marcadores; falha se faltar algum
```

URLs (todas em `testserver/`, só loopback):

| URL | Alvo que exercita |
|---|---|
| `GET /multi/` | página principal (top-level) |
| `GET /multi/popup.html?m=popup-1` | popup aberto com `window.open` |
| `GET /multi/blank.html?m=blank-1` | link `target=_blank` (auto-clicado aos 200 ms; também clicável por CDP) |
| `GET /multi/iframe.html?m=oopif-1` | iframe de **outra origem** (`http://localhost:<porta>` × `http://127.0.0.1:<porta>`), OOPIF |
| `GET /multi/worker.js` | worker dedicado (`Worker`) |
| `GET /multi/sw.js` | service worker com escopo `/multi/` |
| `GET /multi/beacon?m=...` | GET de sondagem; JSON determinístico com marcador, headers e corpo |
| `POST /multi/ping?m=...` | POST de sondagem (corpo conhecido); JSON com `body_text` e `body_sha256` |
| `GET /multi/sw-fetch?m=sw-intercept-1` | requisição interceptada pelo service worker (ele faz o `fetch` de rede) |

Marcadores que o `multi.jsonl` mostra ao abrir `/multi/` (`?auto=0` desliga o
disparo automático):

| Tipo de alvo | Marcadores | Corpo POST conhecido |
|---|---|---|
| página principal | `main-1`, `main-post-1` | `main-post-body-1` |
| popup (`window.open`) | `popup-1` (navegação), `popup-get-1`, `popup-post-1` | `popup-post-body-1` |
| `target=_blank` | `blank-1` (navegação), `blank-get-1`, `blank-post-1` | `blank-post-body-1` |
| iframe OOPIF (outra origem) | `oopif-1` (navegação), `oopif-get-1`, `oopif-post-1` | `oopif-post-body-1` |
| worker dedicado | `worker-get-1`, `worker-post-1` | `worker-post-body-1` |
| service worker | `sw-intercept-1` (encaminhada), `sw-own-1`, `sw-own-post-1` | `sw-own-post-body-1` |

O iframe usa `http://localhost:<porta>` por padrão (mesma porta do servidor,
origem e site diferentes, força OOPIF). Para apontar para outra origem, use
`/multi/?oopif=http://127.0.0.1:PORT`. A página só é prática no servidor h1
(HTTP em texto claro); em h2/h3 o iframe precisa de um `?oopif=` explícito.

O service worker intercepta `/multi/sw-fetch`, faz o `fetch` próprio
(`sw-own-1`, `sw-own-post-1`) e encaminha a requisição interceptada à rede como
`/multi/sw-fetch?m=sw-intercept-1&passthrough=1`. AMP opcional: a primeira carga
não é controlada até `clients.claim()`; a página espera o controller antes do
fetch, e um reload também resolve.

`multi.jsonl` (`scrapelens.testserver.multi/1`), uma linha por requisição em
`/multi/...`:

```json
{"schema":"scrapelens.testserver.multi/1","ts_rfc3339":"...","marker":"worker-post-1",
 "server":"127.0.0.1:8781","conn":"c7","method":"POST","target":"/multi/ping?m=worker-post-1",
 "headers":[["Host","127.0.0.1:8781"],["Content-Length","20"],["..."],["..."],
 "body_b64":"d29ya2VyLXBvc3QtYm9keS0x","body_text":"worker-post-body-1","body_len":20,
 "response":{"status":200,"body_len":1255,"body":"{...}"}}
```

`headers` é a lista ordenada recebida (duplicatas preservadas, nunca um mapa);
a linha também sai no `h1.jsonl`/`h2.jsonl`/`h3.jsonl` normal, com o campo
`marker`. Teste: `cargo test multi_target_page_marks_every_request_kind`.
