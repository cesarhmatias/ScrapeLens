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
(`verification.json`, `report.md`, `sample-lines.jsonl`; sessão e NetLog,
~50 MB, são apagados após a verificação).

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
