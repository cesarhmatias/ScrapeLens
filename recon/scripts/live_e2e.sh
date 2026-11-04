#!/bin/sh
# End to end for site_profile: real capture (headless Chrome, loopback,
# server that imitates documented signals) + analysis. No external network.
set -e
cd "$(dirname "$0")/../.."
OUT="${SL_RECON_E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/sl-recon-e2e.XXXXXX")}"
export SL_RECON_E2E_DIR="$OUT"
cargo test --manifest-path capture/Cargo.toml --lib live_recon_scenarios -- --ignored --nocapture
cargo test --manifest-path recon/Cargo.toml --test live_e2e -- --ignored --nocapture --test-threads=1
echo "sessions in $OUT"
