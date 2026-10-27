# Capturas do frontend atual

Capturadas durante esta avaliação, a partir da implementação executada. Todas as sessões fotografadas contêm somente dados sintéticos. **As imagens 08–11 exibem “SESSÃO REAL” porque esse é um problema observado no aplicativo ao importar um HAR fictício**, e não porque houve captura real.

| Arquivo | Estado e ambiente |
|---|---|
| `01-inicio-demo-1440.jpg` | Browser, 1440 × 900, demo original de 13 chamadas, tema claro |
| `02-detalhe-1440.jpg` | Headers da chamada req-0004; fonte/verificação em painel lateral |
| `03-cookies-1440.jpg` | Cookies enviados, campo bruto e recebidos na demo original |
| `04-comparacao-1440.jpg` | Comparação padrão req-0009/req-0010 |
| `05-sem-resultados-1440.jpg` | Busca sem resultados e ação de limpar |
| `06-sessao-1280.jpg` | Browser, viewport 1280 × 800 |
| `07-muitas-requisicoes-1440.jpg` | Fixture de estresse original de 12.000 registros; sem captura real |
| `08-desktop-har-sintetico.png` | Instância Tauri isolada, importação real do HAR fictício de 64 chamadas |
| `09-desktop-filtro-api-vazio.png` | Fetch/XHR retorna zero após a importação; `_resourceType` não transportado |
| `10-desktop-sessao-reaberta.png` | Reabertura nativa da pasta persistida, 64 chamadas |
| `11-desktop-erro-importacao.png` | HAR propositalmente inválido; sessão anterior preservada |

As imagens desktop incluem a janela nativa, com aproximadamente 1440 × 920 de superfície capturada. Não são equivalentes ao viewport CSS das capturas do navegador. As fotos não foram retocadas. A janela de captura pessoal/original foi deixada intacta; os testes de importação usaram `app.scrapelens.uxreview`.
