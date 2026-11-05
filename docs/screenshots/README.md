# Interface screenshots — contract v1 (synthetic session, DEMO)

Screenshots 01–16: UI over the synthetic fixture (`synthetic-fixture`, `DEMO` labels,
`.invalid` domains), rendered via Playwright or from the Tauri app. Screenshots 17–21:
**real cycle on macOS** — external Chrome 156 with a dedicated profile against the
local testserver at `127.0.0.1:8781`, a real `capture-*` session, and real
HAR/NetLog imports; no synthetic data is presented as a capture.

| File | What it shows |
|---|---|
| `01-principal-claro.png` | Main screen: capture controls (disabled with reason), search, filters, 13 requests with status/protocol/type/duration |
| `02-principal-escuro.png` | Same screen in the dark theme |
| `03-detalhe-headers-claro.png` | Headers in the source sequence (pseudo-headers + duplicates), per-piece verification, CDP×NetLog match |
| `04-detalhe-headers-escuro.png` | Same detail in the dark theme |
| `05-detalhe-normalizado-claro.png` | Derived and labeled normalized view (grouped, sorted, duplicates counted) |
| `06-detalhe-cookies-claro.png` | Raw cookie + pairs + wire lines; raw Set-Cookie with attributes |
| `07-detalhe-payload-claro.png` | POST payload, metadata, response preview and display rules |
| `08-detalhe-redirects-escuro.png` | HTTP/1.1 → HTTP/2 chain with two hops and evidence per hop |
| `09-comparacao-claro.png` | A/B comparison: added, removed, changed, reordered; cookies and body |
| `10-comparacao-escuro.png` | Same comparison in the dark theme |
| `11-detalhe-verificacao-escuro.png` | NetLog-only case: missing headers, “não verificada” (not verified), estimated duration `≈` |
| `12-principal-busca-claro.png` | Search “produtos” (products) with count “2 de 13” (2 of 13) |
| `13-principal-filtro-erros-escuro.png` | “Erros 4xx/5xx” (Errors 4xx/5xx) filter (403, 403, 401) |
| `14-lista-12k-virtualizada.png` | Virtualized list with 12.000 synthetic requests (24 rows in the DOM) |
| `15-detalhe-tentativas-ambigua.png` | Attempts + ambiguous match with explicit candidates |
| `16-tauri-shell-escuro.png` | Real Tauri 2 shell window (local ad-hoc build) with native title, single window and demo session |
| `17-real-captura-principal.png` | Real capture: external Chrome 156 on the local testserver page (11 requests, `cdp+netlog`) |
| `18-real-detalhe-headers.png` | Real `/setcookie` request: h1 headers in the NetLog sequence, `verified` verification, source timestamps |
| `19-real-cookies.png` | Real cookies and four `Set-Cookie` lines (including the duplicated `sc_dup`) preserved |
| `20-real-har-importada.png` | Real HAR (10 requests) imported by the core and opened in the UI (`har-import`) |
| `21-real-netlog-importado.png` | Real NetLog (24 requests including background traffic) imported by the core; partial session declared |

Official contract: `docs/03-contratos.md`. Decisions: `docs/01-decisoes.md`.
Provisional wave 1 contract (history): `app/CONTRACT-DRAFT.md`.
App instructions, commands and limits: `app/README.md`.
Virtualization measurement: `docs/perf/virtualization.json`.
