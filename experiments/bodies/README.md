# Corpos na captura ao vivo (`cdp-bodies.jsonl`)

Verifica `src-tauri/src/capture.rs` contra o `testserver` h1 local (Chrome 156,
127.0.0.1, dados sintéticos, sem rede externa).

```bash
cd experiments/bodies && python3 run_bodies.py        # porta 9781; ~15 s
```

`run_bodies.py` sobe o testserver, roda `cargo test live_bodies_cycle --ignored`
(captura real), dirige a página same-origin por um segundo cliente CDP
(`drive.mjs`) e compara três fontes independentes: o que a página enviou/recebeu
(sha256), o que o servidor registrou (`/sink`) ou serve (bytes regenerados no
verificador) e `cdp-bodies.jsonl`. Saída em `../results/bodies/`
(`verification.json`, `report.md`, `sample-lines.jsonl`; com `--keep` a sessão e o NetLog,
centenas de MB, ficam em `session/` e `server/`, ignorados pelo git; sem `--keep` são apagados ao fim).

## Resultado (Chrome 156.0.8078.73, h1)

| caso | estado gravado | bytes |
|---|---|---|
| POST form-urlencoded | req `captured` utf8 (postDataEntries) | = enviado = servidor |
| POST JSON | req `captured` utf8 | = enviado = servidor |
| POST binário (0xFF 0xC0 0x00…) | req `captured` base64 | = enviado = servidor |
| eco binário | resposta `captured` base64 | = servido |
| POST 6 MiB texto / binário | req `truncated`, `originalSize` 6291456, 5242880 gravados | prefixo = enviado |
| GET 6 MiB | resposta `truncated`, mesmos tamanhos | prefixo = servido |
| gzip | resposta `captured` utf8 | = servido, já decodificado pelo Chrome |
| 302 | tentativa 0 `unavailable` ("resposta de redirect…"); tentativa 1 `captured` | tentativa 1 = servido |
| 307 com corpo | corpo da requisição `captured` nas duas tentativas; resposta 0 `unavailable` | iguais entre si e ao enviado |
| 204 / Content-Length: 0 | `empty` com a evidência no `reason` | — |
| conexão recusada | `unavailable` "loadingFailed: net::ERR_CONNECTION_REFUSED" | — |

## O que o CDP não fornece (observado)

- **`request.postData` é lossy para binário**: o Chrome converte para string e
  bytes inválidos viram U+FFFD (4099 bytes enviados → 6149 em UTF-8). Por isso
  `postDataEntries` (bytes exatos) tem prioridade; `postData` só é usado sem entries.
- **Corpo de 6 MiB não vem no evento (limiar exato não medido)**: só `hasPostData`; os bytes vêm de
  `Network.getRequestPostData` (binário voltou com `base64Encoded:true`, exato).
- **Corpo de resposta de redirect**: não existe (`getResponseBody` não serve).
- **gzip**: só o corpo já decodificado; os bytes do fio não são acessíveis.
- **`empty`** exige 204/205/304, HEAD ou `Content-Length: 0` visto nos headers do CDP;
  0 bytes sem isso vira `unavailable`.
- Não exercitado ao vivo (o testserver não tem o endpoint): SSE, WebSocket,
  corpos `Blob`/stream de requisição, h2 e h3. SSE/WebSocket, orçamento de
  256 MiB e falhas de comando têm teste unitário (`cargo test capture::`).

## Campo `transformed` (revisão 4a)

- Corpo de resposta que não vem em base64 → `"transformed":["chrome-decoded"]`: o
  `getResponseBody` entrega texto já decodificado pelo Chrome. Com charset
  declarado diferente de UTF-8 soma `"charset:<x>->utf-8"`. Caso ao vivo
  `latin1`: fio `53 e3 6f` ("São", ISO-8859-1) → CDP `53 c3 a3 6f`, marcado.
  Os bytes do fio não são reconstruídos.
- `postDataEntries` incompleto → tenta `Network.getRequestPostData`; se só restar
  o `postData` do evento, grava marcado `"lossy-postData"` (teste unitário; o
  Chrome 156 não produziu entradas incompletas nos casos ao vivo).
- Os bytes idênticos ao fio valem só para linhas sem `transformed`.

## Observação de estabilidade

Em 1 de ~6 execuções o ciclo ao vivo falhou na importação: "JSON inválido em
NetLog … line 3661" (NetLog não finalizado ao encerrar o Chrome). Não
reproduzido nas 5 execuções seguintes; não corrigido aqui.

## NetLog truncado (diagnóstico e correção)

- **Falha original**: 1 ciclo ("JSON inválido em NetLog … line 3661"); o NetLog terminava em
  evento completo + vírgula, sem `]}`. Esse ciclo veio logo após uma execução em que o
  driver falhou e deixou a captura (teste + Chrome) viva, escrevendo no mesmo diretório.
  **Não reproduzido**: 12 ciclos com diagnóstico e 20 ciclos finais, todos com
  `Browser.close` ok e saída graciosa do Chrome (0,2–2,4 s). A causa provável é essa captura
  órfã (harness), mas não está provada.
- **Defesa**: `run_bodies.py` encerra a captura própria no `finally`, recusa rodar se já
  houver `live_bodies_cycle` e `capture.rs` registra como o Chrome saiu.
- **Em `capture.rs`**: `cdp-events.jsonl` é gravado antes de qualquer passo que possa falhar.
  NetLog truncado é reparado (corta no último evento completo, fecha `]}`; o original fica em
  `netlog.original.json`); irreparável/ausente → importa só CDP+corpos. Em ambos:
  `completeness` parcial + aviso `capture.netlog_incomplete` / `capture.netlog_unusable`;
  Chrome morto à força → `capture.chrome_killed`. Nunca descarta a sessão em silêncio.
  Provado por testes unitários com NetLog real do Chrome cortado em 6 pontos (o core importa o
  reparado); não há prova ao vivo do reparo porque a falha não reproduziu.
- `python3 loop_bodies.py 20` → `results/bodies/cycles.json` (20 ciclos, 0 falhas).
