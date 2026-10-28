# Empacotamento — bundle final validado

Estado do pacote entregue nesta rodada. Serve como evidência reprodutível: os
comandos abaixo geram exatamente o artefato descrito, na mesma máquina e nas
mesmas condições.

## Fontes do build

| Item | Valor |
|---|---|
| Repositório | `/Users/cesar/Projects/scrapelens` |
| Commit do app no momento do build | `3a3c676` (`fix(exportacao): evita repetir o estado do corpo na prévia`) |
| Commits de exportação incluídos | `eaf5471` (shell Tauri), `0a6e696` (UI), `0446f18`/`12457cd` (formatação), `3a3c676` (ajuste da prévia) |
| Contrato da rodada | `4c97bc9` (`docs/07-exportacao-ui.md`) |
| Core | inalterado nesta rodada; entra como dependência de crate (`scrapelens-core = { path = "../core" }`) |
| Data do build | 2026-10-27 ~17:20 (UTC−03) |
| Working tree | limpo, exceto `tests/results/app-latest/testserver/app-20261027/h1.jsonl` (artefato pré-existente de teste, preservado e não commitado) |

Não há sidecar, processo auxiliar nem runtime Node/Python no produto.

## Comandos executados

```sh
# na raiz do repositório
cd app && npm install                     # uma vez
cd ../app && npx tsc --noEmit             # typecheck do frontend — sem saída
cd ../app && npm run build                # bundle Vite — 516 kB (gzip 102 kB)
cd ../core && cargo test                  # 55 passam, 1 ignorado
cd ../src-tauri && cargo test             # 15 passam, 1 ignorado (captura ao vivo)
cd ../src-tauri && cargo clippy --all-targets
cd .. && ./app/node_modules/.bin/tauri build --bundles app

# assinatura ad-hoc do bundle (o linker já deixa o binário ad-hoc; este passo
# cria _CodeSignature/CodeResources para que `codesign --verify` valide)
cd src-tauri/target/release/bundle/macos
codesign --force --deep --sign - ScrapeLens.app
codesign --verify --deep --strict ScrapeLens.app
```

Ferramentas usadas: rustc 1.98.1, Node 26.8.1, macOS 26.5.2 (arm64).

## Artefato

| Item | Valor |
|---|---|
| Bundle | `src-tauri/target/release/bundle/macos/ScrapeLens.app` |
| Executável | `ScrapeLens.app/Contents/MacOS/scrapelens` |
| Arquitetura | `Mach-O 64-bit executable arm64`, thin (sem universal binary) |
| Tamanho do bundle | 14.380 KiB (~14,1 MiB, `du -sk`) |
| Tamanho do executável | 13.968.432 bytes |
| SHA-256 do executável | `9c04b98b30b3d6451ee53fa5eee589aaba0cd4e5d3185894e39facb0335bdbe5` |
| Identificador | `app.scrapelens.desktop` |
| Assinatura | ad-hoc (`flags=0x2(adhoc)`, `TeamIdentifier=not set`) |
| `codesign --verify --deep --strict` | exit 0 (valid on disk, satisfaz o Designated Requirement) |
| `spctl -a` | rejeitado — esperado: sem Developer ID e sem notarização |

Rebuild de 0d4dbab (`fix(app)`: adapter tolera campos omitidos que o core aceita via serde default; teste `npm run test:adapter` com a fixture mínima; 15+1 ignorado Tauri, 16/16 regressões tests/exportacao). Hash anterior `5934556c…` (16015a1) substituído. Antes: rebuild com validação de todos os ancestrais do destino (F1/F2): o hash acima é deste build. O SHA-256 é do executável **após** o re-sign ad-hoc. Um `tauri build` limpo
produz um binário byte-diferente (o linker assina antes do bundle), por isso o
hash identifica este artefato, não a saída de qualquer build. O build anterior
desta mesma rodada, sem o ajuste `3a3c676`, tinha
`ee127a56fa51a1403616dc4cb3796afd3bb5ec4d595c6da699c0cac1a16d9344`; ele foi
substituído por este.

## Validação de execução

- Bundle iniciado pelo drive de automação (`app.scrapelens.desktop`), janela
  única 1440×920, sem telemetria.
- `cargo test` no `src-tauri` cobre a ponte de exportação: prévia cURL/Python,
  escaping de aspas, corpo `captured` vs `unavailable`, recusa de sobrescrita,
  recusa de link simbólico e origem intacta após sanitizar.
- `cargo test` no `core` cobre os exportadores e a sanitização usados aqui; não
  houve alteração no core nesta rodada.

## Evidência da exportação/sanitização

Pasta: `src-tauri/evidence/exportacao/`.

| Arquivo | Conteúdo |
|---|---|
| `command-output.txt` | saída real (gerada por exemplo `export_dump`, já removido do repositório): prévias cURL/Python, prévia da sanitização e resultado gravado |
| `preview-curl.json`, `preview-python.json` | respostas literais de `export::preview` (1317 e 1745 bytes de texto) |
| `sanitize-preview.json`, `sanitize-saved.json` | 24 requisições, 152 redações (`cookie`, `header:cookie`, `header:set-cookie`, `setCookie`), destino sugerido e resultado |
| `05`–`14-*.png` | telas do app: demo, sessão aberta, detalhe, diálogo cURL, diálogo Python, cancelamento, arquivo salvo, sanitização, resultado e sessão sanitizada aberta |
| `ui-harness.mjs` | harness Playwright que exercita os componentes React |
| `ui-harness-result.json` | resumo: cópia e arquivo salvos idênticos à prévia Python (`copied_matches_python`, `saved_matches_python`) |
| `saved-har-0002.sh` | texto exato que o diálogo de salvamento entregou ao command |
| `prepare-payloads.py` | recria os payloads grandes usados pelo harness |

Sessão usada: `~/Library/Application Support/app.scrapelens.desktop/sessions/har-3dbc391c02a985c5-2`
(24 requisições, importada de HAR sintético de `127.0.0.1:8781`). A pasta
sanitizada de referência (0700/0600, `session.json` com 872.082 bytes) foi
gerada em `evidence/exportacao/sanitized-har-synthetic/` e conferida por busca
de marcadores: `fromjs`, `sc_a=alpha` e `sc_b=beta` não aparecem em nenhum
arquivo sanitizado. Ela é derivada e por isso não entra no git; o exemplo `export_dump` que a gerava foi removido — recrie-a pelo comando de sanitização do app.

**O que o harness prova e o que não prova.** O harness serve o `dist/` real do
frontend, injeta um stub de `__TAURI_INTERNALS__` e usa as respostas **reais**
gravadas pelo Rust; apenas os diálogos nativos, o clipboard e o file picker são
simulados. Ele prova o comportamento dos componentes React (alternância
cURL/Python, texto copiado/salvo igual à prévia, cancelamento sem gravação,
abertura da sessão sanitizada). Ele **não** prova o diálogo nativo do macOS nem
a gravação real do arquivo pelo usuário; esses caminhos são cobertos pelos
testes Rust (`write_text_file`, `sanitize_to`) e pelo bundle, mas a passagem
manual pelo `NSSavePanel` não foi automatizada nesta rodada.

## Prints

| Arquivo | Conteúdo |
|---|---|
| `src-tauri/evidence/exportacao/08-dialog-curl.png` | prévia cURL com estado do corpo, avisos e aviso de não execução |
| `src-tauri/evidence/exportacao/09-dialog-python.png` | mesma requisição em Python (`http.client`) |
| `src-tauri/evidence/exportacao/10-dialog-cancel.png` | cancelamento do diálogo nativo: nada gravado |
| `src-tauri/evidence/exportacao/11-dialog-saved.png` | arquivo salvo com caminho e bytes |
| `src-tauri/evidence/exportacao/12-dialog-sanitize.png` | prévia de sanitização com redações por origem |
| `src-tauri/evidence/exportacao/14-sanitized-session.png` | sessão sanitizada aberta no app |

## Limitações que este pacote mantém

- Sem assinatura Apple Developer ID e sem notarização; distribuição fora desta
  máquina exige `xattr -d com.apple.quarantine` ou assinatura/notarização reais.
- Apenas arm64 compilado e testado; Intel não validado.
- Captura cobre um target/página por sessão.
- Corpos vindos do CDP ficam `unavailable` (não são baixados); a UI mostra o
  motivo em vez de inventar conteúdo. Nenhuma sessão capturada nesta máquina
  tem corpo; só o teste unitário cobre o caso `captured`.
- `--remote-allow-origins=*` no endpoint CDP (ver `src-tauri/src/capture.rs`);
  risco limitado a loopback, porta efêmera e à janela da captura.
- O fluxo manual de salvar pelo `NSSavePanel` dentro do bundle não foi
  automatizado: o painel nativo do macOS não expõe AX para o driver
  (`off_space_or_ax_unresolved`) e a tentativa em foreground atingiu outro app.
  Roteiro para validar em 2 minutos: abrir `ScrapeLens.app`, `Abrir captura…` →
  `har-3dbc391c02a985c5-2`, abrir a requisição `/setcookie`, `Exportar…`,
  `Salvar…`, escolher pasta nova e conferir o arquivo 0600; depois `Sanitizar…`
  e `Abrir sessão sanitizada`.
