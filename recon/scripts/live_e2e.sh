#!/bin/sh
# Ponta a ponta do site_profile: captura real (Chrome headless, loopback,
# servidor que imita sinais documentados) + análise. Nenhuma rede externa.
set -e
cd "$(dirname "$0")/../.."
OUT="${SL_RECON_E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/sl-recon-e2e.XXXXXX")}"
export SL_RECON_E2E_DIR="$OUT"
cargo test --manifest-path src-tauri/Cargo.toml --lib live_recon_scenarios -- --ignored --nocapture
cargo test --manifest-path recon/Cargo.toml --test live_e2e -- --ignored --nocapture --test-threads=1
echo "sessões em $OUT"
