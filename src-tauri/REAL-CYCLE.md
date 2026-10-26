# Ciclo real validado — macOS arm64

Data: 2026-10-26 (horário local). Chrome 156.0.8078.48. App Tauri 2.12.5
(`ScrapeLens.app` release, assinatura ad-hoc, 13,26 MiB) com `scrapelens-core`
como dependência crate (sem sidecar). Testserver h1 local em
`127.0.0.1:8781` (fixtures sintéticas do testserver; a captura é real do Chrome).

## Captura ao vivo

Comandos: `start_session` → navegação no Chrome externo (perfil temporário
`/var/folders/.../scrapelens-chrome-*`, CDP só em 127.0.0.1, NetLog `Everything`)
→ `stop_session` → `import_capture` + `store::write_session_dir`.

Sessões (diretório de dados do app):

- `~/Library/Application Support/app.scrapelens.desktop/sessions/capture-1793057139842`
  — 11 requisições, `completeness=complete`, `capture.mode=cdp+netlog`,
  5.036 eventos CDP+NetLog usados, 4 avisos (2 `correlate.ambiguous` nas duas
  requisições idênticas concorrentes), headers h1 com
  `verification=verified` e `source=netlog` (`HTTP_TRANSACTION_SEND_REQUEST_HEADERS`).
  Usada nos prints 17–19.
- `~/Library/Application Support/app.scrapelens.desktop/sessions/capture-1793058270253`
  — repetição a partir do `.app` release: 11 requisições, `complete`,
  `cdp+netlog`, mesmo padrão de correlação.
- `.../sessions/capture-1793056304065` — primeira captura da sessão de validação
  (mesmo ciclo; usada para o NetLog real importado abaixo).

Fontes observadas: `netlog.json` (1,3–2,1 MiB), `cdp-events.jsonl`
(31–371 KiB), `session.json` (105–856 KiB), `attachments/` vazio (corpos CDP
não foram baixados nesta rodada — estado `unavailable` explícito).

## Importações reais

- HAR real gerado por Chromium (Playwright, `content: embed`) sobre
  `http://127.0.0.1:8781/page` → `/tmp/scrapelens-real.har` (12 entradas).
  Importado pelo botão HAR e pelo diálogo nativo; sessão:
  `.../sessions/har-ae8b55ad56e338af` — 10 requisições, `complete`, 0 avisos,
  labels `har-import`; headers com verificação própria do HAR
  (ordem/duplicatas não verificadas). Print 20.
- NetLog real da captura acima → `.../sessions/netlog-b3f04ac555a0d2fe` —
  24 requisições (inclui tráfego de background do Chrome), `partial` com motivo
  “NetLog não declara captura CDP; cobertura de requisições não confirmada”,
  labels `netlog-import`. Print 21.

## Verificação

- `cd src-tauri && cargo test` — 6 passam, 1 `#[ignore]` (teste manual do ciclo
  real; executado com `--ignored`: 11 requisições reais, sessão importada).
- `cd app && npx tsc --noEmit` e `npm run build` — sem erro.
- `./app/node_modules/.bin/tauri build --bundles app` — `ScrapeLens.app`
  13,26 MiB, Mach-O arm64, `adhoc,linker-signed` (sem certificado Apple).
- App release lançado, abriu a sessão real via diálogo nativo (`⌘O`), iniciou e
  encerrou nova captura com o core.

## Limites desta rodada

- Corpos de resposta CDP não foram baixados para anexos; a UI mostra
  `unavailable`/`não verificada` em vez de inventar conteúdo.
- Captura acomoda uma página/target; novas abas abertas manualmente não entram
  na mesma sessão nesta versão.
- Assinatura/notarização e build Intel não foram feitos; só arm64 foi compilado e
  testado.
- Print 16 é o shell com fixture demo; 17–21 são o ciclo real.
