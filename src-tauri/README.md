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
| `import_har(path)` | **real** | core `import_har` + `store::write_session_dir` |
| `import_netlog(path)` | **real** | core `import_netlog` + persistência |
| `start_session` | **real** | Chrome externo com perfil dedicado + CDP + NetLog |
| `stop_session` | **real** | flush do NetLog, correlação no core, sessão v1 |
| `capture_status` | pronto | eventos, PID do Chrome, URL e erro da captura |
| `detect_chrome` | pronto | detecta `/Applications` + preferência salva |
| `set_chrome_path(path)` | pronto | aceita `.app`, `Contents/MacOS` ou binário; persiste em `app_config_dir/preferences.json` |
| `read_attachment(sessionDir, name)` | pronto | prévia textual ≤ 1 MiB, sem `..`/separadores |
| `reveal_path(path)` | pronto | Finder (macOS) |

## Integração real com o core/

1. `scrapelens-core` é dependência Rust (`path = "../core"`); binário único.
2. `import_har`/`import_netlog` chamam `scrapelens_core::import_har/netlog` e
   gravam com `store::write_session_dir`.
3. `capture.rs` implementa o launcher de Chrome e o cliente CDP (o core não
   trouxe launcher), grava `cdp-events.jsonl` + `netlog.json` e entrega ao
   `import_capture` do core.
4. `open_session` lê o `session.json` v1; `read_attachment` lê
   `<sessao>/attachments/<nome>` com limite de 1 MiB e sem traversal.
5. Sessões ficam em `app_data_dir()/sessions/<id>` (0700/0600 via core).

## Limitações conhecidas

- `--remote-allow-origins=*` no launcher: o endpoint CDP em
  `127.0.0.1:<porta efêmera>` aceita qualquer Origin durante a captura. O risco
  é limitado ao loopback, à porta aleatória e à janela da sessão; ainda assim,
  não navegue em páginas não confiáveis no Chrome inspecionado enquanto grava.
- Corpos CDP não são baixados para anexos nesta versão; aparecem como
  `unavailable` com nota, nunca inventados.
- A captura acompanha um target/página; abas abertas manualmente depois do
  início não entram na mesma sessão.
- Sem assinatura Apple/notarização; arm64 compilado e testado, Intel não.
- Captura com zero eventos CDP falha com erro explícito em vez de gravar uma
  sessão vazia; sessões com eventos parciais são preservadas como `partial`.

## Atalhos

Menu nativo: ⌘O abrir, ⌘F buscar, ⌘⇧C copiar URL da requisição selecionada,
⌘C copiar texto nativo, ⌘⇧D carregar demonstração. A UI também trata ⌘O/⌘F/⌘C
como fallback no WebView.
