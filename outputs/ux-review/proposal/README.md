# Protótipo navegável — ScrapeLens

Protótipo isolado em HTML/CSS/JavaScript, com dados sintéticos. Não altera `app/src`, `core/src` nem `src-tauri/src`. O desenho pode ser integrado aos componentes React existentes; o JavaScript desta demonstração não é substituto do adaptador, diff ou exportadores de produção.

## Abrir

Na raiz do repositório:

```sh
python3 -m http.server 4174 --bind 127.0.0.1 --directory outputs/ux-review/proposal
```

Abra **http://127.0.0.1:4174/?view=entry**. Não abrir `index.html` por `file://`: a fixture é carregada com `fetch` local.

Links diretos:

- [Entrada](http://127.0.0.1:4174/?view=entry)
- [Sessão](http://127.0.0.1:4174/?view=session)
- [Detalhe](http://127.0.0.1:4174/?view=detail&id=18&tab=headers)
- [Cookies](http://127.0.0.1:4174/?view=detail&id=18&tab=cookies)
- [Comparação](http://127.0.0.1:4174/?view=compare)

Não usa CDN, fontes remotas, serviço externo nem API de IA. Os domínios `.invalid` são dados exibidos e não são acessados.

## Percurso recomendado

1. Na entrada, abra a demonstração. Há 64 requisições com assets e APIs misturados.
2. Filtre Fetch/XHR e busque `produtos`. Veja #18 (navegador, 200/h2) e #64 (scraper, 403/h1).
3. Selecione a chamada com clique ou ↑/↓; Enter ou “Inspecionar chamada” abre o detalhe.
4. Na aba Headers, busque `text/plain`. A ocorrência 2 de 2 continua com o índice 5. Copie o valor.
5. Expanda pseudoheaders ou mude para “Normalizada · alfabética”. “Entender” explica os limites da sequência.
6. Veja Cookies: pares enviados, campo Cookie e dois Set-Cookie independentes. Armazenamento e linhas do fio estão indisponíveis na fixture.
7. Compare A/B. Troque Headers, Cookies, Payload, Protocolo e Resposta; desmarque “Somente diferenças”; inverta A/B.
8. “Código…” abre exemplo cURL sintético. A cópia contém o valor completo e headers repetidos.
9. “Nova captura” abre um fluxo **simulado**, sem iniciar Chrome ou tráfego. Encerre a simulação para voltar à demo.

Teclado: Tab/Shift+Tab, ↑/↓ na lista, Enter, Escape, ←/→ nas abas, ⌘F/Ctrl+F e ⌘O/Ctrl+O. Diálogos usam `<dialog>` e foco visível. Não há comando de executar o código exportado.

## Salvar e importar nesta demonstração

“Salvar cópia…” baixa `scrapelens-demo-ux.json`, formato próprio de demonstração, **não** o bundle v1 do produto. “Abrir sessão…” reconhece esse JSON e a fixture HAR incluída; o escopo é deliberadamente limitado à mesma demonstração. Não é um importador genérico nem lê NetLog.

A cópia baixada foi conferida em disco e é idêntica à fixture (64 chamadas). O seletor de arquivos da automação do navegador deu timeout; a reabertura do JSON pelo protótipo não foi validada de ponta a ponta. A importação HAR, persistência e reabertura v1 foram validadas no **aplicativo nativo atual**, separadamente.

A classificação Fetch/XHR da proposta vem do JSON da fixture. O importador HAR de produção atualmente perde `_resourceType`; isso está documentado como P0, com dependência Rust, e não foi corrigido aqui.

## Dados e fontes

- `fixtures/session.json`: dados de apresentação da proposta, gerados localmente.
- `fixtures/catalogo-sintetico.har`: HAR 1.2 da mesma navegação fictícia, usado para testar o importador nativo.
- `fixtures/invalido.har`: fixture inválida para testar recuperação de erro.
- `fixtures/session-v1-imported/`: saída do importador CLI existente. Foi acrescentada a label `synthetic-fixture` ao metadado para identificá-la ao reabrir. O HAR importado diretamente no app não recebe essa label automaticamente; a captura “SESSÃO REAL” documenta esse problema.
- `generate-fixture.py`: regenera JSON/HAR/fixture inválida. A importação CLI para v1 é uma etapa separada, descrita abaixo.

O JSON da proposta atribui fonte NetLog + CDP a #18 para demonstrar a UX de evidência parcial e HAR a #64. **Isso não é uma correlação executada.** Ao importar o HAR gerado no core, a fonte passa a ser HAR para todas as chamadas. São representações controladas do mesmo cenário, com limites diferentes, deliberadamente explicitados.

Para regenerar o v1:

```sh
python3 outputs/ux-review/proposal/generate-fixture.py
./core/target/debug/scrapelens-core import-har \
  outputs/ux-review/proposal/fixtures/catalogo-sintetico.har \
  --out /tmp/scrapelens-ux-session-v1
```

Se quiser reabrir essa saída como demonstração no app, adicionar `synthetic-fixture` a `session.labels`. Isso identifica a fixture; não muda as evidências HTTP. Não reclassificar capturas reais dessa maneira.

## Reproduzir a instância desktop isolada

Na raiz do repositório, com dependências existentes:

```sh
./app/node_modules/.bin/tauri build --debug --bundles app \
  --config outputs/ux-review/proposal/desktop-review.conf.json
```

Abra `src-tauri/target/debug/bundle/macos/ScrapeLens UX Review.app`. Identificador de dados: `app.scrapelens.uxreview`. O override modifica somente nome, identificador e geometria da janela. Não iniciar gravação na instância original durante a avaliação. O build isolado não precisa ser distribuído nem versionado.

## Capturas e verificação visual

As capturas entregues em `../after/` foram feitas no navegador real e examinadas individualmente. As quatro vistas principais existem em 1440 × 900 e 1280 × 800. `viewport-checks-*.json` registra as dimensões observadas e a ausência de overflow de página. As regiões de dados têm rolagem interna; não se pretende exibir 64 linhas ou todo valor extenso simultaneamente.

Para repetir as quatro capturas principais com o Playwright já instalado no projeto, mantenha o servidor acima ativo e execute, da raiz:

```sh
node outputs/ux-review/proposal/capture.mjs
```

O script grava em `../after/recapture/`, preservando as imagens revisadas. Ele espera o componente renderizado antes de fotografar, evitando captura vazia antes do `fetch` da fixture. **Reabrir e revisar as imagens é obrigatório** após qualquer alteração; executar o script por si só não constitui revisão visual.

Limites: protótipo de 64 itens sem virtualização; um tema; não é uma nova implementação do capturador, parser genérico, diff de produção, Python exporter, armazenamento de cookies ou formato v1. Não substitui teste de acessibilidade com VoiceOver nem avaliação com usuários.
