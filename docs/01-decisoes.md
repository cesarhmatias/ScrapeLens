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

## D6 — Navegadores de terceiros (CloakBrowser) e agente de IA

Data: 2026-10-31. Decisão do líder, após a fase A de viabilidade
(`docs/15-mcp-cloakbrowser.md`, seção "Viabilidade CloakBrowser (fase A)").

1. **Proxy MITM continua vetado.** Vale para qualquer navegador, inclusive o
   CloakBrowser. A fidelidade de headers HTTPS vem do NetLog; nenhum certificado
   próprio é instalado e o QUIC não é desabilitado (D1).
2. **O ScrapeLens nunca embute nem redistribui o binário do CloakBrowser.** Só
   aponta para um binário que o próprio usuário instalou, como já faz com o
   Chrome. A licença do binário proíbe redistribuição e exige licença OEM/SaaS
   para oferecê-lo a terceiros (`BINARY-LICENSE.md`; resumo no doc 15, item 1).
3. **Navegador compartilhado entre o agente de IA e o ScrapeLens:** o ScrapeLens
   lança o navegador e expõe a porta de depuração **somente em loopback**
   (`127.0.0.1`). O agente se conecta a essa porta; o ScrapeLens não depende de
   o agente lançar o navegador.
4. **Vetados no lançamento e na instalação de qualquer navegador de terceiros:**
   - `--no-sandbox` (o wrapper do CloakBrowser o passa por padrão, inclusive no
     macOS);
   - `xattr -cr` ou qualquer outro contorno do Gatekeeper/quarentena;
   - o wrapper `pip`/`npm` do CloakBrowser (traria atualização em segundo plano,
     validação de licença e o contorno do Gatekeeper acima).
5. **Estado:** download e execução do CloakBrowser (fases B1 e B2 do doc 15)
   **não estão autorizados**. Dependem de autorização expressa do usuário,
   repassada pelo líder.
6. **B1 adiada; o CloakBrowser só entra se o reconhecimento mostrar que é
   necessário.** O fluxo é: um agente de IA usa o MCP do ScrapeLens com o Chrome
   normal para entender a configuração de um site (`site_profile`,
   `docs/16b-mcp-navegador.md`); a recomendação "candidato a CloakBrowser" é o
   gatilho para voltar ao assunto.
