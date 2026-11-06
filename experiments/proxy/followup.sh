#!/bin/sh
# Live follow-up: https:// proxy with credentials (relay + system/test CA), HTTP/2 through
# an HTTP proxy (direct and relay), multi-target pairing through the proxy, a direct-route
# failure, and the HTTP-proxy direct captures Core asked for.
# Test only. Synthetic credentials. Dedicated Chrome profile (the capture creates it).
# Usage: followup.sh <out-dir>
set -u
OUT=${1:?out dir}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PW=${PROXY_TEST_PASSWORD:-Pw-Exp-7f3a9Q}
USER=${PROXY_TEST_USER:-exp-user}
TS="$ROOT/testserver/target/debug/scrapelens-testserver"
CA="$ROOT/fixtures/tls/scrapelens-test-ca.crt.pem"
BIN="$ROOT/capture/target/debug/examples/proxy_import"
mkdir -p "$OUT"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

if [ ! -x "$TS" ]; then
  (cd "$ROOT/testserver" && cargo build -q --bin scrapelens-testserver) || exit 1
fi
(cd "$ROOT/capture" && cargo build -q --example proxy_import) || exit 1

"$TS" serve --only h1,h2 --no-h3-on-h2-port \
  --h1 127.0.0.1:18781 --h2 127.0.0.1:18782 \
  --evidence "$OUT/evidence" > "$OUT/testserver.stdout" 2>&1 &
PIDS="$PIDS $!"
"$TS" proxy --kind http --port 18791 --evidence "$OUT/proxy-http-open.jsonl" \
  > "$OUT/proxy-http-open.stdout" 2>&1 &
PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PW" "$TS" proxy --kind http --port 18792 \
  --evidence "$OUT/proxy-http-auth.jsonl" --auth-env SCRAPELENS_TESTPROXY_AUTH \
  > "$OUT/proxy-http-auth.stdout" 2>&1 &
PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PW" "$TS" proxy --kind https --port 18793 \
  --evidence "$OUT/proxy-https-auth.jsonl" --auth-env SCRAPELENS_TESTPROXY_AUTH \
  > "$OUT/proxy-https-auth.stdout" 2>&1 &
PIDS="$PIDS $!"
sleep 2

run_one() { # name proxy-url target seconds
  name=$1
  route=$2
  target=$3
  seconds=$4
  dir="$OUT/$name"
  rm -rf "$dir"
  mkdir -p "$dir"
  SCRAPELENS_PROXY_URL="$route" SCRAPELENS_TEST_PROXY_CA="$CA" \
    perl -e 'alarm 180; exec @ARGV' "$BIN" "$dir" "$target" "$seconds" \
    > "$dir/stdout.txt" 2> "$dir/stderr.txt"
  echo "$name exit=$?"
}

run_one direct-http-page "http://127.0.0.1:18791" "http://127.0.0.1:18781/page" 8
run_one direct-h2 "http://127.0.0.1:18791" "https://127.0.0.1:18782/page" 10
run_one relay-h2 "http://$USER:$PW@127.0.0.1:18792" "https://127.0.0.1:18782/page" 10
run_one direct-multi "http://127.0.0.1:18791" "http://127.0.0.1:18781/multi/" 12
run_one relay-multi "http://$USER:$PW@127.0.0.1:18792" "http://127.0.0.1:18781/multi/" 12
run_one https-relay "https://$USER:$PW@127.0.0.1:18793" "http://127.0.0.1:18781/healthz" 8
run_one direct-down "http://127.0.0.1:1" "http://127.0.0.1:18781/healthz" 6
echo FOLLOWUP_DONE
