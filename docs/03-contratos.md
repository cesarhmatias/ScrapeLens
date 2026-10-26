# ScrapeLens — Contratos oficiais (onda 2)

Substituem `app/CONTRACT-DRAFT.md` (provisório). Proveniência e vereditos: `docs/02-matriz-fidelidade.md`; decisões: `docs/01-decisoes.md`.

## 1. Formato de sessão próprio (v1)

Diretório de sessão:
```
<sessao>/
  session.json        # metadados: schemaVersion=1, browser, startedAt/endedAt, completeness
  cdp-events.jsonl    # eventos CDP brutos (um por linha)
  netlog.json         # NetLog original gravado pelo Chrome
  attachments/        # corpos (request/response) por requestId
```

Regras:
- `session.json.completeness`: `complete | partial` (parcial = falha antes do flush).
- Headers são **arrays ordenados de pares** `[name, value][]`; nunca dicionário. Duplicatas preservadas.
- Pseudoheaders separados (`:method`, `:path`, etc.), nunca misturados aos headers comuns.
- Campo `Cookie`: preservar (a) o valor original da fonte, (b) os pares internos parseados, (c) as linhas divididas observadas no fio (h2/h3). `Set-Cookie`: linhas brutas + parseadas.
- Cada unidade de informação carrega `provenance`: `{source, event, timestamp, browserVersion, method, verification}`.
- `verification` por informação: `verified | partial | unverified` (matriz D2 em `docs/01-decisoes.md`). "unverified" = a UI exibe "não verificada".
- Visões normalizadas (para busca/diff) são derivadas, jamais substituem o original.

## 2. Correlação

Entidades: `LogicalRequest`, `Attempt`, `Redirect`, `Connection`, `StreamSession`. Chaves explícitas quando a fonte fornece (ex.: `loaderId`+`requestId` CDP, `source_dependency` NetLog). Heurística URL+método+horário gera `match: "ambiguous"` quando houver >1 candidato — nunca associação silenciosa.

## 3. Módulos e propriedade (onda 2)

| Dono | Caminhos | Entrega |
|---|---|---|
| Core/importadores | `core/` | modelo v1, parsers HAR/NetLog/próprio, correlação, persistência, diff, exportadores cURL/Python, sanitização |
| App/interface | `app/`, `src-tauri/` | Tauri 2, atalhos ⌘O/F/C, diálogos nativos, integração com captura real |
| Testes/integração | `testserver/`, `fixtures/`, `tests/` | fixtures sintéticas dos casos da spec, testes de aceitação |
| Captura/protocolos | `experiments/`, launcher Rust em `core/capture` se delegado | launcher Chrome/CDP/NetLog como biblioteca usável pelo Tauri |

## 4. Regras transversais

- Conventional Commits contínuos; nada concluído sem commit.
- Fixtures sintéticas identificadas; zero telemetria/rede; nada publicado.
- Corpos indisponíveis/truncados/descartados: estado explícito no contrato (`body: {state, bytes?, truncatedAt?}`).
- HTML capturado é dado, nunca interface executável.
