# Contributing to ScrapeLens

Thank you for your interest. The project is a macOS app (Tauri 2 + React/TypeScript +
Rust core) for inspecting the real header sequence of HTTP sessions.

## Before you start

- Read `docs/03-contratos.md` (session contract v1) and `docs/01-decisoes.md`.
- The contract is the source of truth: headers are ordered arrays of pairs, with
  duplicates and pseudo-headers; provenance and verification are **per piece of information**.
- No fictitious data presented as real: fixtures use
  `synthetic-fixture` and the UI shows `DEMO`.
- Privacy: no telemetry/network at runtime; the only socket is the CDP on
  `127.0.0.1`. Never commit secrets, personal Chrome profiles or sessions with
  sensitive data. Use `scrapelens-core sanitize` before sharing a
  session.
- Captured HTML is data, never executable interface. Do not introduce `innerHTML`,
  `eval`, `iframe` or `srcdoc` with captured content.

## Development requirements

- macOS (arm64 is the built and tested architecture; Intel has not been validated).
- Xcode Command Line Tools, stable Rust (1.80+), Node.js 20+.
- Google Chrome/Chromium installed for real capture (the app uses a
  temporary dedicated profile; never the personal profile).
- The end user does **not** install Node, Python or Rust: the app is a single
  Tauri binary with the core as a crate dependency, no sidecar.

## Commands

All the commands below start from the repository root and are independent:
each line indicates the directory in which it must be run.

```sh
# UI dependencies (once)
cd app && npm install

# core tests
cd core && cargo test --offline

# Tauri shell tests
cd src-tauri && cargo test

# app in development mode (from the root)
./app/node_modules/.bin/tauri dev

# .app bundle (from the root; output goes to src-tauri/target/release/bundle/macos/)
./app/node_modules/.bin/tauri build --bundles app
```

- UI in the browser only (no Tauri commands): `cd app && npm run dev`.
- Type check: `cd app && npx tsc --noEmit`.
- Acceptance suite: `python3 tests/aceite/run_acceptance.py` (the product's
  tests do not require Python; the acceptance harness is a development
  tool).
- Real test capture (external Chrome against the local testserver):

```sh
# 1. build and start the local h1 server (stays in the background)
cd testserver && cargo build
./target/debug/scrapelens-testserver serve --only h1 --h1 127.0.0.1:8781 &

# 2. back at the root, start the app pointing at the test page
cd .. 
SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page \
  ./app/node_modules/.bin/tauri dev
```

Stop the testserver with `kill %1` (or `pkill -f scrapelens-testserver`) when
you are done.

`SCRAPELENS_CAPTURE_HEADLESS=1` and `SCRAPELENS_CAPTURE_IGNORE_CERT=1` are
development/test hooks; they are not part of the interface.

## Structure

| Path | Contents |
|---|---|
| `app/` | React 19 + TypeScript + Vite UI (consumes the v1 contract) |
| `src-tauri/` | Tauri 2 shell, menu/dialogs, commands, Chrome launcher + CDP |
| `core/` | Rust crate: v1 model, parsers, correlation, diff, exporters |
| `testserver/`, `fixtures/`, `tests/` | reference and acceptance servers |
| `experiments/` | fidelity matrix evidence (history) |
| `docs/` | decisions, contracts, matrix and acceptance |

Respect the ownership described in `docs/04-propriedade.md`: changes in areas
owned by others must be agreed on the project channel.

## Contribution style

- **Conventional Commits** at every step (`feat`, `fix`, `docs`, `test`, `chore`,
  `perf`, with scope: `core`, `app`, `tauri`, `sanitize`, `aceite`…).
- Changed behavior? Update the test and the documentation in the same PR/commit.
- Run `cargo fmt`, `cargo clippy --offline --all-targets` and the tests of the
  touched crate before submitting.
- Do not publish releases without the maintainer's authorization. The local build is **not
  signed and not notarized**; distribution requires Developer ID + notarization.
- Known limitations that must not regress: `--remote-allow-origins=*` on the
  CDP (loopback/ephemeral port/capture window), CDP bodies `unavailable`,
  capture of one target per session, no validated Intel build.

## Reporting issues

Include: macOS/Chrome version, how you started the app, steps, what you expected, what
happened and (when there is no sensitive data) the sanitized `session.json`. Do not
attach personal profiles, real cookies or keys.
