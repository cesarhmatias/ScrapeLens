# Contribuindo com o ScrapeLens

Obrigado pelo interesse. O projeto é um app macOS (Tauri 2 + React/TypeScript +
core Rust) para inspecionar a sequência real de headers de sessões HTTP.

## Antes de começar

- Leia `docs/03-contratos.md` (contrato de sessão v1) e `docs/01-decisoes.md`.
- O contrato é a fonte da verdade: headers são arrays ordenados de pares, com
  duplicatas e pseudoheaders; proveniência e verificação são **por informação**.
- Nada de dados fictícios apresentados como reais: fixtures usam
  `synthetic-fixture` e a UI mostra `DEMO`.
- Privacidade: sem telemetria/rede em runtime; o único socket é o CDP em
  `127.0.0.1`. Nunca commite segredos, perfis pessoais do Chrome ou sessões com
  dados sensíveis. Use `scrapelens-core sanitize` antes de compartilhar uma
  sessão.
- HTML capturado é dado, nunca interface executável. Não introduza `innerHTML`,
  `eval`, `iframe` ou `srcdoc` com conteúdo capturado.

## Requisitos de desenvolvimento

- macOS (arm64 é a arquitetura compilada e testada; Intel não foi validado).
- Xcode Command Line Tools, Rust estável (1.80+), Node.js 20+.
- Google Chrome/Chromium instalado para captura real (o app usa perfil
  dedicado temporário; nunca o perfil pessoal).
- O usuário final **não** instala Node, Python ou Rust: o app é um binário único
  Tauri com o core como dependência crate, sem sidecar.

## Comandos

```sh
# na raiz do repositório
cd app && npm install
cd ../core && cargo test --offline
cd ../src-tauri && cargo test
cd .. && ./app/node_modules/.bin/tauri dev
cd .. && ./app/node_modules/.bin/tauri build --bundles app
```

- UI apenas no navegador (sem commands Tauri): `cd app && npm run dev`.
- Checagem de tipos: `cd app && npx tsc --noEmit`.
- Bateria de aceite: `python3 tests/aceite/run_acceptance.py` (os testes do
  produto não exigem Python; o harness de aceite é ferramenta de
  desenvolvimento).
- Captura real de teste (Chrome externo contra o testserver local):

```sh
cd testserver && cargo build
./target/debug/scrapelens-testserver serve --only h1 --h1 127.0.0.1:8781 &
SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page \
  ./app/node_modules/.bin/tauri dev
```

`SCRAPELENS_CAPTURE_HEADLESS=1` e `SCRAPELENS_CAPTURE_IGNORE_CERT=1` são ganchos
de desenvolvimento/teste; não fazem parte da interface.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `app/` | UI React 19 + TypeScript + Vite (consome o contrato v1) |
| `src-tauri/` | shell Tauri 2, menu/diálogos, commands, launcher Chrome + CDP |
| `core/` | crate Rust: modelo v1, parsers, correlação, diff, exportadores |
| `testserver/`, `fixtures/`, `tests/` | servidores de referência e aceite |
| `experiments/` | evidências da matriz de fidelidade (histórico) |
| `docs/` | decisões, contratos, matriz e aceite |

Respeite a propriedade descrita em `docs/04-propriedade.md`: mudanças em áreas de
outros donos devem ser combinadas no canal do projeto.

## Estilo de contribuição

- **Conventional Commits** em cada passo (`feat`, `fix`, `docs`, `test`, `chore`,
  `perf`, com escopo: `core`, `app`, `tauri`, `sanitize`, `aceite`…).
- Mudou comportamento? Atualize teste e documentação no mesmo PR/commit.
- Rode `cargo fmt`, `cargo clippy --offline --all-targets` e os testes do crate
  tocado antes de enviar.
- Não publique releases sem autorização do mantenedor. O build local é **não
  assinado e não notarizado**; distribuição exige Developer ID + notarização.
- Limitações conhecidas que não devem regredir: `--remote-allow-origins=*` no
  CDP (loopback/porta efêmera/janela de captura), corpos CDP `unavailable`,
  captura de um target por sessão, sem build Intel validado.

## Reportando problemas

Inclua: versão do macOS/Chrome, como iniciou o app, passos, o que esperava, o que
aconteceu e (quando não houver dado sensível) o `session.json` sanitizado. Não
anexe perfis pessoais, cookies reais ou chaves.
