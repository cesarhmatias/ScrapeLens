# Rodada 11 — pesquisa de mercado: MCP para captura e navegador (2026-10-31)

Pesquisa web feita por um agente de pesquisa a pedido do líder. Estrelas lidas em 31/10/2026; o que está marcado "não verificado" não teve fonte primária.

## Achados principais
- Nenhum MCP examinado documenta a preservação da ORDEM dos headers. Esse espaço é do ScrapeLens, pelo NetLog.
- Chrome DevTools MCP (Google, Apache-2.0): `list_network_requests` paginado e `get_network_request` com o corpo inline ou em arquivo. Conecta a um Chrome já aberto. Não é stealth.
- Playwright MCP (Microsoft, Apache-2.0): rede opt-in (`--caps=network`), `--cdp-endpoint`, `--executable-path`, stdio ou HTTP. Não é stealth.
- browser-use e Stagehand: agentes de alto nível, dependentes de LLM e nuvem, sem ferramenta de rede. Evitar o modelo.
- Proxyman MCP (comercial): o melhor desenho de segurança visto. Bind em 127.0.0.1, token por sessão em arquivo 0600, redação ligada por padrão e ferramentas de leitura separadas das de escrita.
- mitmproxy-MCP, har-mcp, Burp e Charles: pequenos ou de comunidade. Bons padrões: redação por padrão e ferramentas de escrita só com opt-in.
- Puppeteer MCP de referência: arquivado. Evitar.

## CloakBrowser (a confirmar pela Captura, fase A)
- É um wrapper Python/JS (MIT) em volta de um binário Chromium com patches em C++. O binário tem licença própria, sem redistribuição.
- O build gratuito para macOS é o Chromium 145. Da v148 em diante exige chave de licença; a gratuita permite 1 sessão. A licença é validada em cloakbrowser.dev, e há checagem de atualização.
- Expõe CDP (`--remote-debugging-port`, cloakserve na porta 9222). Se aceita `--log-net-log` e `Target.setAutoAttach`: não verificado.
- O README admite que comandos CDP vazam sinais detectáveis (reCAPTCHA). Isso conflita com interceptar via CDP. O NetLog é passivo: é o candidato a captura principal no modo stealth.
- Riscos: issues abertas de detecção (#614, #598, #611, #602), crash no macOS arm64 (#575), assinatura ad-hoc (o Gatekeeper bloqueia). Não pode ser embutido: o ScrapeLens deve localizar um binário instalado pelo usuário.

## Padrões de desenho a adotar
- Listar e detalhar por ID, com handles explícitos (`session_id`, `request_id`) em cada chamada.
- Paginação própria (`cursor`/`has_more`, 25 a 50 itens), `structuredContent` com `outputSchema`, e `resource_link` para corpos grandes.
- Resources para sessões e corpos (`scrapelens://session/{id}/request/{rid}/body`); tools para busca, comparação e ações.
- Segurança:
  - redação ligada por padrão, com opt-in para valores reais;
  - bind local com token;
  - `readOnlyHint` e `destructiveHint`, que a especificação trata como não confiáveis;
  - confirmação (elicitation) para ações com efeito;
  - allowlist de domínios.
- Transporte stdio por padrão; HTTP local opcional. SDK rmcp (Rust oficial), que encaixa no backend Tauri.

## Ferramentas iniciais propostas
1. list_sessions
2. import_capture(path, kind)
3. list_requests(session_id, filtros, cursor, limit)
4. get_request(session_id, request_id, redact=true): headers em ordem, com a fonte da ordem
5. get_body(request_id, part, range, decode)
6. search_bodies(session_id, query, regex, scope)
7. diff_requests(a, b, ignore[])
8. diff_sessions(a, b, match_by)
9. get_cookies_and_tokens(session_id, redact): origem de cada cookie e token
10. browser_launch(engine=chrome|cloak, binary_path, proxy, capture=cdp|netlog|both): pede confirmação
11. browser_navigate(browser_id, url): allowlist e confirmação
12. browser_act(browser_id, action, ref, value)
13. browser_stop(browser_id): finaliza a captura
14. generate_priming_script(session_id, target_request_id)
15. validate_run(session_id, script_ref): executa com confirmação

## Fontes
- https://github.com/ChromeDevTools/chrome-devtools-mcp
- https://github.com/microsoft/playwright-mcp
- https://github.com/browser-use/browser-use
- https://github.com/browserbase/stagehand
- https://github.com/lups2000/mitmproxy-MCP
- https://github.com/tjamet/har-mcp
- https://github.com/PortSwigger/mcp-server
- https://proxyman.com/docs/mcp
- https://github.com/CloakHQ/CloakBrowser
- https://modelcontextprotocol.io/specification/latest/server/tools
- https://github.com/modelcontextprotocol/rust-sdk
