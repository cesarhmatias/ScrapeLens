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

## Dependências (lockfile commitado)

Rust 1.98.1 · `httlib-hpack 0.1.3` (HPACK) · `quiche 0.30.0` (QUIC/h3/QPACK,
BoringSSL via cmake) · `rustls 0.23` + `rustls-pemfile` · `rcgen 0.14` ·
`serde`/`serde_json` · `base64` · `chrono` · `sha2`.
O build do quiche exige `cmake` (instalado via Homebrew) e rede apenas na
primeira compilação do BoringSSL embutido.
