# Interface screenshots — contract v1 (synthetic session, DEMO)

All screenshots show the synthetic demo session: UI over the synthetic fixture
(`synthetic-fixture`, `DEMO` labels, `.invalid` domains), rendered headless with
Playwright (`app/scripts/shoot.mjs`, locale `en-US`, timezone UTC). No screenshot in
this folder is a capture of a real site.

Screenshots of the desktop shell and of real captures (16–24 in the previous set) were
removed: they showed the Portuguese interface and local paths. Replacements, if any,
must be new English captures against the local test server.

| File | What it shows |
|---|---|
| `01-main-light.png` | Main screen: capture controls (disabled with reason), search, filters, 13 requests with status/protocol/type/duration |
| `02-main-dark.png` | Same screen in the dark theme |
| `03-detail-headers-light.png` | Headers in the source sequence (pseudo-headers + duplicates), per-piece verification, CDP×NetLog match |
| `04-detail-headers-dark.png` | Same detail in the dark theme |
| `05-detail-normalized-light.png` | Derived and labeled normalized view (grouped, sorted, duplicates counted) |
| `06-detail-cookies-light.png` | Raw cookie + pairs + wire lines; raw Set-Cookie with attributes |
| `07-detail-payload-light.png` | POST payload, metadata, response preview and display rules |
| `08-detail-redirects-dark.png` | HTTP/1.1 → HTTP/2 chain with two hops and evidence per hop |
| `09-comparison-light.png` | A/B comparison: added, removed, changed, reordered; cookies and body |
| `10-comparison-dark.png` | Same comparison in the dark theme |
| `11-detail-verification-dark.png` | NetLog-only case: missing headers, “not verified” status, estimated duration `≈` |
| `12-main-search-light.png` | Search “products” (a term from the synthetic URL paths) with count “2 of 13” |
| `13-main-filter-errors-dark.png` | “Errors 4xx/5xx” filter (403, 403, 401) |
| `14-list-12k-virtualized.png` | Virtualized list with 12,000 synthetic requests (24 rows in the DOM) |
| `15-detail-attempts-ambiguous.png` | Attempts + ambiguous match with explicit candidates |

Official contract: `docs/03-contracts.md`. Decisions: `docs/01-decisions.md`.
Provisional wave 1 contract (history): `app/CONTRACT-DRAFT.md`.
App instructions, commands and limits: `app/README.md`.
Virtualization measurement: `docs/perf/virtualization.json`.
