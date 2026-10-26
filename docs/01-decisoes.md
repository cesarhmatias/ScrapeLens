# ScrapeLens — Decisões de arquitetura

Fonte dos fatos: `docs/02-matriz-fidelidade.md` (evidências em `experiments/results/`, Chrome 156.0.8078.48, macOS arm64, 60 requisições).

## D1 — Stack (pós-prova de fidelidade)

- UI: React 19 + TypeScript + Vite (já validada em `app/`, commit `c16b15a`).
- Shell desktop: Tauri 2 (decisão original mantida — nenhum resultado da onda 1 a contraindica).
- Captura: launcher de Chrome externo + CDP (WebSocket 127.0.0.1) + NetLog (`--log-net-log`). Sem proxy MITM, sem certificados, sem desabilitar QUIC.
- Testes/servidores de referência: Rust (commits `9827d6f`, `f0059e5`).
- Linguagem do core: a definir pelo agente de Core entre Rust (preferência: mesmo runtime do Tauri, zero sidecar) ou Go (permitido pelo usuário, mas exigiria sidecar no pacote). Default do líder: **Rust**, para o binário empacotado não depender de instalação alguma.

## D2 — Proveniência de headers por protocolo (veredito da matriz)

| Informação | Fonte recomendada | Estado |
|---|---|---|
| Ordem+duplicatas de request h1 | CDP `responseReceivedExtraInfo.headersText` (resposta) / NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | verificada (Chrome 156) |
| Ordem de request h2 | NetLog `HTTP2_SESSION_SEND_HEADERS` (~: 1 troca observada; `cookie` pode ser dividido) | parcial |
| Ordem de request h3 | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` (✓ ordem; duplicatas de `cookie` divididas no fio) | parcial |
| Ordem+duplicatas de response (h1/h2/h3) | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | verificada |
| Headers "fácil" (CDP `request.headers` / `ExtraInfo.headers`) | nunca tratar como sequência transmitida; subconjunto sem ordem | verificado: NÃO preserva |

Regra de produto: quando a sequência transmitida não puder ser comprovada para uma informação, a UI mostra **"não verificada"** — nunca adivinha.

## D3 — Correlação CDP×NetLog

IDs não são equivalentes. Modelo com entidades separadas: requisição lógica, tentativa, redirect, conexão, sessão/stream. Relações explícitas quando existem; URL+método+horário são pistas com **ambiguidade explícita** quando houver mais de uma correspondência.

## D4 — Divisão de `Cookie` em h2/h3

A divisão do campo `cookie` no fio é um fato observado; o modelo de dados preserva o campo original do CDP e as linhas transmitidas do NetLog, sem fundir silenciosamente.

## D5 — Commits

Conventional Commits contínuos, regra do usuário registrada no canal.
