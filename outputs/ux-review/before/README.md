# Screenshots of the current frontend

Captured during this evaluation, from the running implementation. All photographed sessions contain synthetic data only. **Images 08–11 show “SESSÃO REAL” (REAL SESSION) because that is a problem observed in the application when importing a fictitious HAR**, not because there was a real capture.

| File | State and environment |
|---|---|
| `01-inicio-demo-1440.jpg` | Browser, 1440 × 900, original demo of 13 calls, light theme |
| `02-detalhe-1440.jpg` | Headers of call req-0004; source/verification in a side panel |
| `03-cookies-1440.jpg` | Cookies sent, raw field and received in the original demo |
| `04-comparacao-1440.jpg` | Default comparison req-0009/req-0010 |
| `05-sem-resultados-1440.jpg` | Search with no results and clear action |
| `06-sessao-1280.jpg` | Browser, 1280 × 800 viewport |
| `07-muitas-requisicoes-1440.jpg` | Original stress fixture of 12.000 records; no real capture |
| `08-desktop-har-sintetico.png` | Isolated Tauri instance, real import of the fictitious 64-call HAR |
| `09-desktop-filtro-api-vazio.png` | Fetch/XHR returns zero after the import; `_resourceType` not carried over |
| `10-desktop-sessao-reaberta.png` | Native reopening of the persisted folder, 64 calls |
| `11-desktop-erro-importacao.png` | Deliberately invalid HAR; previous session preserved |

The desktop images include the native window, with roughly 1440 × 920 of captured surface. They are not equivalent to the CSS viewport of the browser screenshots. The photos were not retouched. The personal/original capture window was left untouched; the import tests used `app.scrapelens.uxreview`.
