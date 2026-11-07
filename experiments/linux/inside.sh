#!/usr/bin/env bash
# Runs INSIDE the container (experiments/linux/run.sh). Stages by argument; default: all.
#   inside.sh [build|unit|clippy|live|recon|multi ...]
set -uo pipefail
# The registry cache lives on the volume (/cache); rustup stays in /home/tester.
export CARGO_HOME=/cache/cargo
export PATH=/home/tester/.cargo/bin:$PATH
cd /work
if [ ! -d /work/scrapelens ] || [ "${SL_FRESH:-1}" = "1" ]; then rm -rf /work/scrapelens; cp -a /src /work/scrapelens; fi
cd /work/scrapelens
# capture's relay tests read the test leaf key from fixtures/tls, which is generated, not tracked.
[ -f fixtures/tls/scrapelens-test-localhost.key.pem ] || (cd testserver && cargo run -q -- gen-cert) || echo "gen-cert failed: capture relay tests will fail" >&2
stages=("$@"); [ ${#stages[@]} -eq 0 ] && stages=(info clippy unit live recon)
cargo_in() { local crate="$1"; shift; (cd "$crate" && CARGO_TARGET_DIR="/cache/target-$crate" "$@"); }
for stage in "${stages[@]}"; do
  echo; echo "######## [$SL_LABEL] $stage"
  case "$stage" in
    info)
      uname -m; sed -n 1,2p /etc/os-release; rustc --version
      for b in /opt/google/chrome/chrome /usr/lib/chromium/chromium; do [ -x "$b" ] && "$b" --version; done
      id -un; echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-<empty>} TMPDIR=${TMPDIR:-<empty>}" ;;
    build)  cargo_in capture cargo build --tests 2>&1 | tail -40 ;;
    clippy) cargo_in capture cargo clippy --all-targets -- -D warnings 2>&1 | tail -30
            cargo_in recon cargo clippy --all-targets -- -D warnings 2>&1 | tail -10 ;;
    unit)   cargo_in capture cargo test --lib 2>&1 | grep -E "^test .*FAILED|panicked|test result|error(\[|:)" ;;
    live)   # live tests on loopback; virtual window (Xvfb) only for what is not headless
            cargo_in capture xvfb-run -a cargo test --lib -- --ignored --skip live_recon_scenarios --test-threads=1 2>&1 \
              | grep -E "^test |test result|panicked" ;;
    recon)  cargo_in recon cargo test 2>&1 | grep -E "test result|FAILED|error(\[|:)"
            (cd recon && CARGO_TARGET_DIR=/cache/target-recon xvfb-run -a bash scripts/live_e2e.sh 2>&1 | grep -E "test result|FAILED|erro|error" | head) ;;
    multi)  # check_multi_target.py with Tauri swapped for the stand-in crate (shim)
            CARGO_TARGET_DIR=/cache/target-testserver cargo build --release --manifest-path testserver/Cargo.toml 2>&1 | tail -3
            mkdir -p target/release && cp /cache/target-testserver/release/scrapelens-testserver target/release/
            CARGO_TARGET_DIR=/cache/target-core cargo build --release --manifest-path core/Cargo.toml 2>&1 | tail -2
            mkdir -p target/release && cp /cache/target-core/release/scrapelens-core target/release/
            SL_CAPTURE_TEST_DIR=/work/scrapelens/experiments/linux/shim \
              CARGO_TARGET_DIR=/cache/target-shim python3 tests/acceptance/check_multi_target.py 2>&1 | tail -25 ;;
    xdg)    # profile and state root under $XDG_RUNTIME_DIR (0700), without TMPDIR
            export XDG_RUNTIME_DIR="$(mktemp -d /tmp/xdg.XXXXXX)"; chmod 700 "$XDG_RUNTIME_DIR"; unset TMPDIR
            : > /tmp/xdg-raw.txt
            ( for _ in $(seq 1 90); do ls -1 "$XDG_RUNTIME_DIR" >> /tmp/xdg-raw.txt; find "$XDG_RUNTIME_DIR" -maxdepth 2 -mindepth 2 -printf '%m %p\n' >> /tmp/xdg-raw.txt 2>/dev/null; sleep 0.5; done ) &
            sampler=$!
            cargo_in capture cargo test --lib -- --ignored live_full_capture_hides --test-threads=1 2>&1 | grep -E "test result|panicked|navigator"
            kill "$sampler" 2>/dev/null; wait "$sampler" 2>/dev/null
            echo "seen under \$XDG_RUNTIME_DIR during the capture:"; sort -u /tmp/xdg-raw.txt | sed 's/^/  /' 
            echo "after:"; ls -la "$XDG_RUNTIME_DIR" | sed 's/^/  /'
            find "$XDG_RUNTIME_DIR" -maxdepth 1 -mindepth 1 -printf '  %m %u %p\n' ;;
    headed) # with a window (not headless) under Xvfb: the two captures that hide navigator.webdriver
            SL_LIVE_HEADED=1 cargo_in capture xvfb-run -a cargo test --lib -- --ignored \
              live_full_capture_hides live_controlled_capture_hides --test-threads=1 2>&1 | grep -E "^test |test result|panicked"
            # the container's real browser (product, version, owning package), as validation sees it
            cargo_in capture cargo test --lib the_installed_browser -- --nocapture 2>&1 | grep -E "^(GoogleChrome|Chromium)|test result" ;;
    mcp)    cargo_in mcp cargo test 2>&1 | grep -E "test result|FAILED|error(\[|:)|warning: unused" | head -12 ;;
    workspace) # root workspace without the Tauri App (this image has no WebKitGTK)
            CARGO_TARGET_DIR=/cache/target-workspace cargo test --locked --workspace --exclude scrapelens 2>&1 \
              | grep -E "test result|FAILED|error(\[|:)";
            CARGO_TARGET_DIR=/cache/target-workspace cargo clippy --locked --workspace --all-targets --exclude scrapelens --exclude scrapelens-testserver -- -D warnings 2>&1 | tail -10 ;;
    *) echo "unknown stage: $stage" ;;
  esac
done
