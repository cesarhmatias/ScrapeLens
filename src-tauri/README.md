# src-tauri — shell Tauri 2

A UI em `app/` é embutida no binário; nenhum Node/Rust/Python é exigido do
usuário final. O contrato de dados é o v1 de `docs/03-contratos.md`.

## Build e testes

```sh
# na raiz do repositório
./app/node_modules/.bin/tauri dev
./app/node_modules/.bin/tauri build --bundles app

cd src-tauri && cargo test
```

Saída do build local: `src-tauri/target/release/bundle/macos/ScrapeLens.app`
(arm64, assinatura ad-hoc `linker-signed`, **sem certificado Apple** e sem
notarização). Distribuição/assinatura não fazem parte desta entrega.

## Commands (ponte estável para o core/)

Todos os commands de sessão devolvem `SessionPayload`:

```
session      JSON v1 (schemaVersion=1)
sessionDir   pasta da sessão (para attachments), quando existe
synthetic    true se a fixture/label é sintética
notice       texto acionável para a UI
pending      true quando o core/ ainda não executou a etapa
```

| Command | Estado | Observação |
|---|---|---|
| `app_info` | pronto | versão, arch, schema v1 |
| `demo_session` | pronto | fixture v1 sintética embutida |
| `open_session(path)` | **real** | lê pasta/arquivo `session.json`, valida `schemaVersion`, marca parcial e synthetic; guarda a pasta para anexos |
| `import_har(path)` | pendente do core | devolve demo rotulada + `pending` e aviso |
| `import_netlog(path)` | pendente do core | idem |
| `start_session` | pendente do core | idem; não abre Chrome |
| `stop_session` | pronto | no-op até existir captura |
| `detect_chrome` | pronto | detecta `/Applications` + preferência salva |
| `set_chrome_path(path)` | pronto | aceita `.app`, `Contents/MacOS` ou binário; persiste em `app_config_dir/preferences.json` |
| `read_attachment(sessionDir, name)` | pronto | prévia textual ≤ 1 MiB, sem `..`/separadores |
| `reveal_path(path)` | pronto | Finder (macOS) |

## Pontos de integração com o core/

1. Trocar o corpo de `import_har`, `import_netlog` e `start_session` em
   `src/commands.rs` por chamadas ao core (`import_har`, `import_netlog`,
   launcher de captura). A assinatura e o envelope não mudam.
2. O core deve produzir `SessionV1` serializável (camelCase) e gravar
   `session.json` + `attachments/`; `open_session` já lê esse formato.
3. Para `read_attachment`, o core deve manter os anexos em
   `<sessao>/attachments/<nome>`; a UI pede a prévia sob demanda.
4. Nenhum sidecar: `core` entra como dependência Rust de `src-tauri`.

## Atalhos

Menu nativo: ⌘O abrir, ⌘F buscar, ⌘⇧C copiar URL da requisição selecionada,
⌘C copiar texto nativo, ⌘⇧D carregar demonstração. A UI também trata ⌘O/⌘F/⌘C
como fallback no WebView.
