# ScrapeLens — app macOS (Tauri 2) + interface React

Implementação do shell desktop e da interface sobre o **contrato v1**
(`docs/03-contratos.md`). A UI não tem contrato próprio: consome `session.json`
v1 via `core/` e via commands Tauri.

## Estado atual (onda 2)

- **Tauri 2** com janela única, menu nativo do macOS e diálogos nativos.
- **Atalhos**: ⌘O (abrir captura), ⌘F (buscar), ⌘C (copiar URL da requisição
  selecionada quando não há texto selecionado). O menu Editar mantém copiar/
  colar nativos.
- **Tema claro/escuro** com escolha persistida em `localStorage` e padrão do
  sistema.
- **Chrome**: detecção automática em `/Applications` e seleção manual por
  diálogo nativo (`Selecionar Chrome…` no menu Arquivo ou no aviso da tela).
- **Integração real com o core/** (`scrapelens-core` como dependência crate,
  binário único, sem sidecar):
  - `start_session` abre o Chrome externo com perfil temporário dedicado,
    depuração só em `127.0.0.1` (porta efêmera), grava CDP + NetLog e navega
    para a URL inicial (padrão `about:blank`);
  - `stop_session` encerra o Chrome, aguarda o flush do NetLog, correlaciona
    CDP×NetLog no core, grava a sessão v1 e devolve a sessão pronta;
  - `import_har` e `import_netlog` leem o arquivo real, importam pelo core e
    gravam a sessão v1 (labels `har-import`/`netlog-import`);
  - `open_session` lê pasta/arquivo v1, valida `schemaVersion` e preserva a
    pasta para anexos; `read_attachment` carrega prévia textual.
- **Captura validada de ponta a ponta** no macOS: Chrome 156 externo, página do
  testserver local, 11 requisições reais, headers h1 `verified` vindos do NetLog,
  cookies/`Set-Cookie` preservados, correlação `matched` e `ambiguous` exposta.
- **Pendências explícitas**: assinatura/notarização e build Intel; captura de
  corpos CDP ainda não é baixada para anexos (estado `unavailable`), então a
  prévia de corpo real aparece como indisponível.
- **Lista virtualizada** (linha de 34 px, overscan): 12.000 requisições
  renderizam 24 linhas e 437 nós de DOM; ver `docs/perf/virtualization.json`.

## Contrato v1 na UI

`src/v1/types.ts` projeta `core/src/model/*.rs`; `src/v1/adapter.ts` converte
para o modelo de tela:

- headers como arrays ordenados (`pseudoHeaders` + `headers`), duplicatas
  preservadas e ordem nunca refeita;
- visão normalizada é derivada e marcada como parcial;
- `verification` por informação (verified/partial/unverified) com fonte, evento,
  horário, método e nota; “não verificada” aparece literalmente;
- `Cookie` mostra campo bruto, pares e linhas do fio separadamente;
- `Set-Cookie` bruto + atributos parseados, com erro de parse visível;
- corpos usam `Body.state` (`captured`, `empty`, `truncated`, `unavailable`,
  `discarded`) com motivo explícito e anexo indicado;
- `attempts`, `redirects` e `match` (matched/ambiguous/unmatched) com candidatos
  à mostra quando ambíguo;
- HTML capturado é sempre texto, nunca interface.

O rascunho `CONTRACT-DRAFT.md` fica como histórico da onda 1 e está marcado
como substituído.

## Rodar

Pré-requisitos de desenvolvimento: Node + Rust + Xcode Command Line Tools.
O app empacotado não exige Node, Python ou Rust.

```sh
# na raiz do repositório
./app/node_modules/.bin/tauri dev
./app/node_modules/.bin/tauri build --bundles app
# saída: src-tauri/target/release/bundle/macos/ScrapeLens.app
```

Ou pelos scripts do `app/`:

```sh
cd app
npm install
npm run dev            # UI no navegador (modo demo, sem commands)
npm run build
npm run shots          # prints em ../docs/screenshots
npm run perf           # mede a virtualização (docs/perf)
npm run desktop:dev    # Tauri dev (a partir de app/)
npm run desktop:build  # .app local, sem certificado Apple
```

> O build local é **não assinado** (sem certificado Apple). Para distribuir,
> assinatura e notarização são necessárias — não foram feitas e nada foi
> publicado.

## Commands e payload

Todos os commands de sessão devolvem o mesmo envelope:

```json
{
  "session": { "schemaVersion": 1, "session": {...}, "requests": [...] },
  "sessionDir": "/caminho/da/sessao",
  "synthetic": false,
  "notice": "Sessão aberta: 13 requisição(ões).",
  "pending": false
}
```

`pending: true` significa “o core ainda não executou esta etapa”; a UI mostra o
aviso e mantém a sessão demo rotulada. Ao plugar o core, só o corpo de
`start_session`/`import_har`/`import_netlog` muda.

## Limites desta entrega

- Diálogo nativo existe para abrir sessão e escolher Chrome; não há ainda
  “Salvar como”/exportação na UI.
- O launcher de Chrome e o cliente CDP vivem em `src-tauri/src/capture.rs`
  (o core não trouxe launcher; os parsers/correlação são dele).
- `SCRAPELENS_CAPTURE_URL`, `SCRAPELENS_CAPTURE_HEADLESS=1` e
  `SCRAPELENS_CAPTURE_IGNORE_CERT=1` são ganchos de desenvolvimento/teste;
  não aparecem na interface.
- Tema acompanha o sistema na primeira execução; não há sincronização com o
  tema do WebView do macOS além da classe do app.
- Assinatura/notarização e builds Intel não foram feitos nem testados; a máquina
  é Apple Silicon (arm64). Arquiteturas compiladas ≠ testadas.
- A prévia de corpo de sessões reais é carregada por `read_attachment` (limite
  de 1 MiB); binários não são convertidos em texto.
- Nenhuma telemetria, nenhuma rede em runtime.
