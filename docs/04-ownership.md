# File ownership (wave 1)

Zero conflict: each agent only writes to what is theirs.

| Owner | Paths |
|---|---|
| Capture/protocols | `experiments/`, `docs/02-matrix-fidelity.md` (evidence lines), `capture/` (crate `scrapelens-capture`, no Tauri: launcher, CDP, NetLog, allowlist, controlled capture, `chrome.rs`), `recon/` (crate `scrapelens-recon`: `site_profile`), `docs/16b-mcp-browser.md`, `docs/18-memory-sessions-large.md`, `docs/20-captcha-google.md`, `docs/21-linux.md` (and `experiments/linux/`, `experiments/session-memory/`) |
| Tests/servers | `testserver/`, `fixtures/` |
| Core and importers | `core/`, `mcp/` (read-only MCP server), `docs/16-mcp-contract.md` |
| Leader | `docs/00-plan.md`, `docs/01-decisions.md`, `docs/03-contracts.md` |

Shared (never edit without coordination): `README.md`, lockfiles, root.

Note (round 11): `src-tauri/src/capture.rs` and `src-tauri/src/chrome.rs` are only thin App adapters over `capture/` (`SessionPayload`, `CaptureSession`, `run()`, re-exports); the interface and the App commands remain the App's. `capture/` and `recon/` do not depend on Tauri.
