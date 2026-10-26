# Prints da interface — contrato v1 (sessão sintética, DEMO)

Prints 01–16: UI sobre a fixture sintética (`synthetic-fixture`, rótulos `DEMO`,
domínios `.invalid`), renderizados via Playwright ou do app Tauri. Prints 17–21:
**ciclo real no macOS** — Chrome 156 externo com perfil dedicado contra o
testserver local em `127.0.0.1:8781`, sessão `capture-*` real, e importações
reais de HAR/NetLog; nenhum dado sintético é apresentado como captura.

| Arquivo | O que mostra |
|---|---|
| `01-principal-claro.png` | Tela principal: controles de captura (desligados com motivo), busca, filtros, 13 requisições com status/protocolo/tipo/duração |
| `02-principal-escuro.png` | Mesma tela no tema escuro |
| `03-detalhe-headers-claro.png` | Headers na sequência da fonte (pseudoheaders + duplicatas), verificação por informação, correspondência CDP×NetLog |
| `04-detalhe-headers-escuro.png` | Mesmo detalhe no tema escuro |
| `05-detalhe-normalizado-claro.png` | Visão normalizada derivada e identificada (agrupada, ordenada, duplicatas contadas) |
| `06-detalhe-cookies-claro.png` | Cookie bruto + pares + linhas do fio; Set-Cookie bruto com atributos |
| `07-detalhe-payload-claro.png` | Payload POST, metadados, prévia de resposta e regras de exibição |
| `08-detalhe-redirects-escuro.png` | Cadeia HTTP/1.1 → HTTP/2 com dois hops e evidência por hop |
| `09-comparacao-claro.png` | Comparação A/B: adicionados, removidos, alterados, reordenados; cookies e corpo |
| `10-comparacao-escuro.png` | Mesma comparação no tema escuro |
| `11-detalhe-verificacao-escuro.png` | Caso NetLog-only: headers ausentes, “não verificada”, duração estimada `≈` |
| `12-principal-busca-claro.png` | Busca “produtos” com contagem “2 de 13” |
| `13-principal-filtro-erros-escuro.png` | Filtro “Erros 4xx/5xx” (403, 403, 401) |
| `14-lista-12k-virtualizada.png` | Lista virtualizada com 12.000 requisições sintéticas (24 linhas no DOM) |
| `15-detalhe-tentativas-ambigua.png` | Tentativas + correspondência ambígua com candidatos explícitos |
| `16-tauri-shell-escuro.png` | Janela real do shell Tauri 2 (build local ad-hoc) com título nativo, janela única e sessão demo |
| `17-real-captura-principal.png` | Captura real: Chrome 156 externo na página do testserver local (11 requisições, `cdp+netlog`) |
| `18-real-detalhe-headers.png` | Requisição real `/setcookie`: headers h1 na sequência do NetLog, verificação `verified`, timestamps da fonte |
| `19-real-cookies.png` | Cookies reais e quatro linhas `Set-Cookie` (incluindo `sc_dup` duplicado) preservadas |
| `20-real-har-importada.png` | HAR real (10 requisições) importado pelo core e aberto na UI (`har-import`) |
| `21-real-netlog-importado.png` | NetLog real (24 requisições incluindo tráfego de background) importado pelo core; sessão parcial declarada |

Contrato oficial: `docs/03-contratos.md`. Decisões: `docs/01-decisoes.md`.
Contrato provisório da onda 1 (histórico): `app/CONTRACT-DRAFT.md`.
Instruções do app, commands e limites: `app/README.md`.
Medição de virtualização: `docs/perf/virtualization.json`.
