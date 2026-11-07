# Pacote final (onda de empacotamento)

Base: `main`, árvore limpa antes do build. Commit do core em `main`: `d8f2f6d`
(`test(core): run store race rounds until real swaps happen`). Os commits 857cb8c,
e08111b, bacaed1 e 98293e2 não são ancestrais de `main`; o conteúdo deles está em `main`
(fsync em lote em `core/src/store.rs`; redação de sid/jsessionid/phpsessid/Bearer em
`core/src/export/sanitize.rs`).

Build: `./app/node_modules/.bin/tauri build --bundles app` (a partir da raiz). Assinatura:
identidade local autoassinada `ScrapeLens Local Signing` (sem Developer ID, sem notarização;
o log registra "skipping app notarization").

| Item | Valor |
|---|---|
| Executável | `target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens` |
| SHA-256 | `ec53aef44d7dc5cf9ba1621f8e9d7a6ebdbbab4370756c7d5555136f31cd016d` |
| Tamanho do executável | 26 096 512 bytes |
| Tamanho do `.app` | 26 224 KiB |
| `codesign --verify --deep --strict` | valid on disk; satisfies its Designated Requirement |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| Arquitetura | arm64 |
| Strings de teste no binário | nenhuma das variáveis de teste listadas em PACKAGING.md |
| `remote-allow-origins` no binário | 0 ocorrências |

Testes do core antes do build: `cargo test -p scrapelens-core` → exit 0.

Launch (sem foco): `open -g` do bundle; o processo ficou vivo e a janela "ScrapeLens"
(1440×920) apareceu na lista de janelas. A captura de tela com `screencapture -l` saiu
**em branco** (fundo escuro), nos dois disparos com ~8 s e ~18 s. O App Nap não deixa a
WebView pintar sem a janela ativa, como já registrado na memória do canal. Não há print do
conteúdo; um print com conteúdo exige trazer o app para frente, o que aguarda aprovação do líder.
O processo de teste foi encerrado.
