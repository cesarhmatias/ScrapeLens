# Propriedade de arquivos (onda 1)

Conflito zero: cada agente só escreve no que é seu.

| Dono | Caminhos |
|---|---|
| Captura/protocolos | `experiments/`, `docs/02-matriz-fidelidade.md` (linhas de evidência), `capture/` (crate `scrapelens-capture`, sem Tauri: launcher, CDP, NetLog, allowlist, captura controlada, `chrome.rs`), `recon/` (crate `scrapelens-recon`: `site_profile`), `docs/16b-mcp-navegador.md`, `docs/18-memoria-sessoes-grandes.md`, `docs/20-captcha-google.md`, `docs/21-linux.md` (e `experiments/linux/`, `experiments/memoria-sessao/`) |
| Testes/servidores | `testserver/`, `fixtures/` |
| Core e importadores | `core/`, `mcp/` (servidor MCP de leitura), `docs/16-mcp-contrato.md` |
| Líder | `docs/00-plano.md`, `docs/01-decisoes.md`, `docs/03-contratos.md` |

Compartilhado (nunca editar sem combinar): `README.md`, lockfiles, raiz.

Nota (rodada 11): `src-tauri/src/capture.rs` e `src-tauri/src/chrome.rs` são só adaptadores finos do App sobre `capture/` (`SessionPayload`, `CaptureSession`, `run()`, reexports); a interface e os commands do App seguem do App. `capture/` e `recon/` não dependem de Tauri.
