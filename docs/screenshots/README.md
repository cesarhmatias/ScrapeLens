# Prints da fatia de interface — sessão sintética (DEMO)

Gerados a partir de `app/` (React + TypeScript + Vite), renderizados em Chromium
real via Playwright em 1440 px CSS, escala 2×. Todos os dados são **sintéticos** e
a própria interface marca `DEMO` / `dados sintéticos` no título, no banner, na
sessão e no rodapé — nada foi capturado de um site real.

| Arquivo | O que mostra |
|---|---|
| `01-principal-claro.png` | Tela principal, tema claro: controles de sessão desativados com motivo, busca, filtros, 13 requisições com método/domínio/caminho/status/protocolo/tipo/duração |
| `02-principal-escuro.png` | Mesma tela em tema escuro |
| `03-detalhe-headers-claro.png` | Detalhe: headers na sequência da fonte, pseudoheaders, duplicatas, sidebar de fonte e verificação por informação |
| `04-detalhe-headers-escuro.png` | Mesmo detalhe em tema escuro |
| `05-detalhe-normalizado-claro.png` | Visão normalizada claramente identificada (agrupada, ordenada, duplicatas contadas) |
| `06-detalhe-cookies-claro.png` | Cookies enviados/paras internos, `Set-Cookie` recebidos com atributos, linhas brutas |
| `07-detalhe-payload-claro.png` | Payload POST, metadados de conteúdo e corpo da resposta de referência |
| `08-detalhe-redirects-escuro.png` | Cadeia HTTP/1.1 → HTTP/2 com dois hops e evidência por hop (tema escuro) |
| `09-comparacao-claro.png` | Comparação A/B: adicionados, removidos, alterados e reordenados; cookies e corpo |
| `10-comparacao-escuro.png` | Mesma comparação em tema escuro |
| `11-detalhe-verificacao-escuro.png` | Caso NetLog-only: headers de requisição ausentes, “não verificada”, duração estimada `≈` |
| `12-principal-busca-claro.png` | Busca “produtos” com contagem “2 de 13” |
| `13-principal-filtro-erros-escuro.png` | Filtro “Erros 4xx/5xx” (403, 403, 401) em tema escuro |

Contrato provisório da sessão de demonstração: `app/CONTRACT-DRAFT.md`.
Instruções de execução e limites: `app/README.md`.
