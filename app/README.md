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
- **Commands prontos** para o core: `start_session`, `stop_session`,
  `open_session`, `import_har`, `import_netlog`, `demo_session`,
  `detect_chrome`, `set_chrome_path`, `read_attachment`, `reveal_path`,
  `app_info`.
- **Leitura real de sessão v1** (`open_session`): valida `schemaVersion`, lê
  `session.json`, preserva a pasta para anexos e marca sessão parcial quando a
  fonte declara `completeness.partial`. Sessões com `synthetic-fixture` nunca
  aparecem como reais.
- **Pendências explícitas**: captura ao vivo e importadores HAR/NetLog dependem
  do `core/`. Até lá os commands devolvem a fixture demo **rotulada**
  (`synthetic: true`, `pending: true`) e um aviso na tela. Nenhum Chrome é
  aberto por este app ainda.
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

- Captura ao vivo, importadores HAR/NetLog e o launcher de Chrome pertencem ao
  `core/` e ainda não estão conectados.
- Diálogo nativo existe para abrir sessão e escolher Chrome; não há ainda
  “Salvar como”/exportação na UI.
- Tema acompanha o sistema na primeira execução; não há sincronização com o
  tema do WebView do macOS além da classe do app.
- Assinatura/notarização e builds Intel não foram feitos nem testados; a máquina
  é Apple Silicon (arm64). Arquiteturas compiladas ≠ testadas.
- A prévia de corpo de sessões reais é carregada por `read_attachment` (limite
  de 1 MiB); binários não são convertidos em texto.
- Nenhuma telemetria, nenhuma rede em runtime.
