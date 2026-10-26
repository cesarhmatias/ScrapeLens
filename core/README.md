# scrapelens-core

Core em Rust do ScrapeLens: modelo de sessão v1, importadores, correlação
CDP×NetLog, visões normalizadas, diff e exportadores. Sem rede, sem telemetria,
sem sidecar: compila como biblioteca para o Tauri e como binário de inspeção.

## Uso rápido

```bash
cd core
cargo test --offline

# captura dos experimentos -> sessão v1
cargo run --offline -- import-capture \
  ../experiments/results/h1-page/cdp-events.jsonl \
  ../experiments/results/h1-page/chrome-netlog.json \
  --out /tmp/sl-demo

cargo run --offline -- inspect /tmp/sl-demo | head
cargo run --offline -- export-curl /tmp/sl-demo cdp-r0001
cargo run --offline -- export-python /tmp/sl-demo cdp-r0001
cargo run --offline -- sanitize /tmp/sl-demo /tmp/sl-sanitized
cargo run --offline -- diff /tmp/sl-demo cdp-r0001 cdp-r0002
```

## Módulos

| Módulo | Conteúdo |
|---|---|
| `model` | `SessionV1`, headers/pseudoheaders, cookies, corpos, proveniência, entidades |
| `parse::own` | diretório v1 (`session.json` + artefatos), limites e anexos |
| `parse::har` | HAR 1.2 tolerante, redirects, corpos base64 |
| `parse::netlog` | NetLog: NUL, sessão/transação, eventos desconhecidos, cadeia `HTTP_STREAM_JOB_BOUND_TO_REQUEST` |
| `parse::cdp` | eventos CDP, `ExtraInfo`, `headersText`, redirects, evidências |
| `correlate` | casamento explícito/heurístico, `match: ambiguous` |
| `normalize` | visões derivadas para busca (nunca substituem o original) |
| `diff` | adicionado/removido/alterado/reordenado por ocorrência |
| `export` | cURL, Python `http.client`, sanitização |
| `store` | escrita atômica com `0700/0600`, validação de anexo |

Contrato JSON e regras de verificação: [`CONTRACT-V1.md`](CONTRACT-V1.md).
Decisões do projeto: `../docs/01-decisoes.md`; matriz: `../docs/02-matriz-fidelidade.md`.

## Garantias testadas

- ordem/duplicatas/pseudoheaders preservados; Cookie bruto + pares + linhas do fio;
- proveniência e verificação por informação (D2), não por sessão;
- eventos desconhecidos e linhas inválidas sempre geram `Warning`;
- correlação real h1/h2/h3 dos experimentos: 12/12 casadas, 0 ambíguas;
- chain de redirect do contrato h1: 3 tentativas e 2 redirects preservados;
- capturas reais h1/h2 conferem ordem e expansão de NUL;
- diff não perde duplicatas nem ordena alfabeticamente;
- cURL/Python escapam dados não confiáveis e recusam injeção de header;
- sanitização redige segredos e omite anexo não sanitizável com aviso;
- escrita/leitura round-trip com permissões privadas;
- anexos gravados em lote (um fsync de diretório, não um por arquivo) e
  contagens `sourceEvents*` persistidas em HAR/NetLog/CDP.

## Fixtures

`tests/fixtures/` contém apenas dados sintéticos, marcados `SYNTHETIC FIXTURE`,
em domínios `.invalid`. Os testes contra `experiments/results/` usam as capturas
reais já commitadas (somente leitura).

## Integração Tauri

Os commands do app podem chamar direto:

```rust
let imported = scrapelens_core::import_har(&bytes)?;
scrapelens_core::store::write_session_dir(&imported.bundle, &session_dir)?;
// retornar imported.bundle.session (SessionV1 serializa em camelCase)
```

`import_netlog` e `import_capture(cdp, netlog, CorrelationOptions::default())`
seguem a mesma forma. Erros são `CoreError` (implementa `Display`), adequados
para mensagens acionáveis na UI. Para abrir uma sessão, use
`import_session_dir` — ele valida `schemaVersion`, carrega anexos e devolve
avisos de incompletude.
