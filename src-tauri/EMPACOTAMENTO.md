# Empacotamento — bundle final validado

Estado do pacote entregue nesta rodada. Serve como evidência reprodutível: os
comandos abaixo geram exatamente o artefato descrito, na mesma máquina e nas
mesmas condições.

## Fontes do build

| Item | Valor |
|---|---|
| Repositório | `/Users/cesar/Projects/scrapelens` |
| Commit do app no momento do build | `1581376` (`docs(ux): review ScrapeLens and add isolated interactive proposal`) |
| Commit mais recente do core incorporado | `b5846be` (`test(detran): espera unidade milliseconds após fixtures eac41da`) |
| Correções do core incluídas | `98293e2` (sanitização sid/jsessionid/phpsessid + Bearer por valor) e `f6c6bdd` (calibração da unidade de `time` do NetLog) |
| Data do build | 2026-10-27 04:00 (UTC−03) |
| Working tree | limpo no início do build (apenas `CONTRIBUTING.md` alterado depois) |

O core entra como dependência de crate (`scrapelens-core = { path = "../core" }`);
não há sidecar, processo auxiliar nem runtime Node/Python no produto.

## Comandos executados

```sh
# na raiz do repositório
cd app && npm install                     # uma vez
cd ../app && npx tsc --noEmit             # typecheck do frontend
cd ../app && npm run build                # bundle Vite
cd ../core && cargo test --offline        # 88 passam, 1 ignorado (benchmark manual)
cd ../src-tauri && cargo test             # 6 passam, 1 ignorado (captura ao vivo)
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
| Tamanho do bundle | 13.548 KiB (~13,2 MiB, `du -sk`) |
| Tamanho do executável | 13.119.296 bytes |
| SHA-256 do executável | `a7004d4e95e86e2d53750a76b0579d345cabf6e53cb25c3b15c446d25ec522c0` |
| Identificador | `app.scrapelens.desktop` |
| Assinatura | ad-hoc (`flags=0x2(adhoc)`, `TeamIdentifier=not set`) |
| `codesign --verify --deep --strict` | exit 0 (valid on disk, satisfaz o Designated Requirement) |
| `spctl -a` | rejeitado — esperado: sem Developer ID e sem notarização |

O SHA-256 é do executável **após** o re-sign ad-hoc. Um `tauri build` limpo
produz um binário byte-diferente (o linker assina antes do bundle), por isso o
hash identifica este artefato, não a saída de qualquer build.

## Validação de execução

- `open ScrapeLens.app` (build cru, antes do re-sign) → processo sobe e janela
  renderiza.
- Após o re-sign: app iniciado pelo drive de automação (bundle
  `app.scrapelens.desktop`), janela única 1440×920, sessão real aberta pelo
  diálogo nativo (`⌘O`) — `capture-1793058850184`, 11 requisições, `completa`,
  fonte `cdp+netlog`, 2 requisições ambíguas, sem rótulo DEMO.
- Navegação lista → detalhe: headers em sequência da fonte, badges `verificada`
  por informação e correspondência CDP×NetLog `correspondida`.
- Zero telemetria: nenhuma requisição de saída além do WebSocket CDP em
  `127.0.0.1` durante a sessão de captura.

## Prints

| Arquivo | Conteúdo |
|---|---|
| `docs/screenshots/22-final-app.png` | lista da sessão real aberta no bundle final (11 requisições, `cdp+netlog`) |
| `docs/screenshots/23-final-detalhe-verificado.png` | detalhe de `/echo` com headers na ordem da fonte e estado de verificação por informação |

## Limitações que este pacote mantém

- Sem assinatura Apple Developer ID e sem notarização; distribuição fora desta
  máquina exige `xattr -d com.apple.quarantine` ou assinatura/notarização reais.
- Apenas arm64 compilado e testado; Intel não validado.
- Captura cobre um target/página por sessão.
- Corpos vindos do CDP ficam `unavailable` (não são baixados); a UI mostra o
  motivo em vez de inventar conteúdo.
- `--remote-allow-origins=*` no endpoint CDP (ver `src-tauri/src/capture.rs`);
  risco limitado a loopback, porta efêmera e à janela da captura.
