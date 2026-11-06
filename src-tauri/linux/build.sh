#!/usr/bin/env bash
# Inside the container: tests, bundle (.deb and AppImage) and a smoke test with Xvfb.
set -uo pipefail
ARCH=$(dpkg --print-architecture)
OUT=/out/$ARCH; mkdir -p "$OUT"; LOG=$OUT/build.log; : > "$LOG"
step() { echo "== $*" | tee -a "$LOG"; }
fail=0
cd /src/src-tauri
step "cargo test"
if cargo test --locked >>"$LOG" 2>&1; then echo "cargo test ok" | tee -a "$LOG"; else echo "cargo test FAIL" | tee -a "$LOG"; fail=1; fi
grep -E "^test result" "$LOG" | tee -a "$OUT/summary.txt"
step "clippy"; cargo clippy --locked --all-targets -- -D warnings >>"$LOG" 2>&1 && echo "clippy ok" | tee -a "$LOG" || { echo "clippy FAIL" | tee -a "$LOG"; fail=1; }
cd /src/app
for t in test:shortcuts test:list-view test:paged test:capture-url test:adapter; do
  step "$t"; npm run -s $t >>"$LOG" 2>&1 && echo "$t ok" | tee -a "$LOG" || { echo "$t FAIL" | tee -a "$LOG"; fail=1; }
done
step "tsc"; npx tsc --noEmit >>"$LOG" 2>&1 && echo "tsc ok" | tee -a "$LOG" || { echo "tsc FAIL" | tee -a "$LOG"; fail=1; }
step "tauri build"
cd /src && ./app/node_modules/.bin/tauri build --bundles deb,appimage >>"$LOG" 2>&1 || { echo "build FAIL" | tee -a "$LOG"; exit 1; }
B=/src/src-tauri/target/release/bundle
cp $B/deb/*.deb $B/appimage/*.AppImage "$OUT"/
cp /src/src-tauri/target/release/scrapelens "$OUT/scrapelens"
# The smoke needs the test-only command line (`--import-har`), which release builds do not
# have: build a test-hooks binary from the same source. The shipped binary is the release one.
step "smoke binary (test-hooks)"
(cd /src/src-tauri && cargo build --locked --release --features test-hooks >>"$LOG" 2>&1) \
  && cp /src/src-tauri/target/release/scrapelens "$OUT/scrapelens-smoke" \
  || { echo "smoke binary FAIL" | tee -a "$LOG"; fail=1; }
step "smoke (Xvfb, --import-har)"
export HOME=/tmp/smokehome; rm -rf "$HOME"; mkdir -p "$HOME"
export SCRAPELENS_TEST_MODE=1 XDG_DATA_HOME=$HOME/.local/share XDG_CONFIG_HOME=$HOME/.config
HAR=/src/fixtures/acceptance/headers-cookies/headers-cookies.har
xvfb-run -a -s "-screen 0 1440x920x24" dbus-run-session -- "$OUT/scrapelens-smoke" --import-har "$HAR" >"$OUT/smoke.log" 2>&1 &
pid=$!; ok=0
for i in $(seq 1 60); do
  f=$(find "$XDG_DATA_HOME" -name session.json -path "*sessions*" 2>/dev/null | head -1)
  [ -n "$f" ] && { ok=1; break; }; sleep 1
done
pkill -TERM -f "$OUT/scrapelens-smoke" ; sleep 2; kill $pid 2>/dev/null; wait $pid 2>/dev/null
if [ $ok = 1 ]; then
  n=$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['requests']))" "$f" 2>/dev/null || grep -o '"requests"' "$f" | wc -l)
  echo "smoke ok: $f requests=$n" | tee -a "$LOG"
else echo "smoke FAIL (no session.json within 60 s)" | tee -a "$LOG"; fail=1; fi
step "sha256"; (cd "$OUT" && sha256sum *.deb *.AppImage scrapelens | tee SHA256SUMS | tee -a "$LOG")
echo "fail=$fail" | tee -a "$LOG"
exit $fail
