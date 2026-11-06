#!/bin/sh
# Real captures through the common capture path, imported by the current core, for each
# proxy route: none, SOCKS5 and HTTP/HTTPS proxies without credentials (direct route), and
# with credentials (relay), plus https+credentials (refused on the relay path).
# Test only: loopback origins (HTTP and TLS, synthetic), testserver proxies (synthetic
# credentials), a dedicated temporary Chrome profile. Usage: real_matrix.sh <out-dir>
set -u
OUT=${1:?out dir}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PW=${PROXY_TEST_PASSWORD:-Pw-Exp-7f3a9Q}; USER=${PROXY_TEST_USER:-exp-user}
TS="$ROOT/testserver/target/debug/scrapelens-testserver"
TLS="$ROOT/fixtures/tls"
mkdir -p "$OUT"
PIDS=""
cleanup() { for p in $PIDS; do kill $p 2>/dev/null; done; }
trap cleanup EXIT INT TERM
python3 "$HERE/origin.py" --port 18701 --log "$OUT/origin-http.jsonl" --cross-origin http://127.0.0.1:18701 > "$OUT/origin-http.stdout" 2>&1 & PIDS="$PIDS $!"
python3 "$HERE/origin.py" --port 18711 --log "$OUT/origin-https.jsonl" --cross-origin https://127.0.0.1:18711 \
  --tls-cert "$TLS/scrapelens-test-localhost.crt.pem" --tls-key "$TLS/scrapelens-test-localhost.key.pem" > "$OUT/origin-https.stdout" 2>&1 & PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PW" "$TS" proxy --kind http --port 18721 --evidence "$OUT/ts-http-auth.jsonl" --auth-env SCRAPELENS_TESTPROXY_AUTH > "$OUT/ts-http-auth.stdout" 2>&1 & PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PW" "$TS" proxy --kind https --port 18722 --evidence "$OUT/ts-https-auth.jsonl" --auth-env SCRAPELENS_TESTPROXY_AUTH > "$OUT/ts-https-auth.stdout" 2>&1 & PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PW" "$TS" proxy --kind socks5 --port 18723 --evidence "$OUT/ts-socks-auth.jsonl" --auth-env SCRAPELENS_TESTPROXY_AUTH > "$OUT/ts-socks-auth.stdout" 2>&1 & PIDS="$PIDS $!"
"$TS" proxy --kind socks5 --port 18724 --evidence "$OUT/ts-socks-open.jsonl" > "$OUT/ts-socks-open.stdout" 2>&1 & PIDS="$PIDS $!"
"$TS" proxy --kind http --port 18725 --evidence "$OUT/ts-http-open.jsonl" > "$OUT/ts-http-open.stdout" 2>&1 & PIDS="$PIDS $!"
"$TS" proxy --kind https --port 18726 --evidence "$OUT/ts-https-open.jsonl" > "$OUT/ts-https-open.stdout" 2>&1 & PIDS="$PIDS $!"
sleep 4
cd "$ROOT/capture" && cargo build -q --example proxy_import || exit 1
BIN="$ROOT/capture/target/debug/examples/proxy_import"
run_one() { # name route-url target-url
  name=$1; route=$2; target=$3
  dir="$OUT/$name"; rm -rf "$dir"; mkdir -p "$dir"
  if [ -n "$route" ]; then R="$route"; else R=""; fi
  SCRAPELENS_PROXY_URL="$R" perl -e 'alarm 150; exec @ARGV' "$BIN" "$dir/session" "$target" 8 > "$dir/stdout.txt" 2> "$dir/stderr.txt"
  echo "$name exit=$?"
}
for scheme in http https; do
  if [ $scheme = http ]; then T=http://localhost:18701/page; else T=https://localhost:18711/page; fi
  run_one "none-$scheme" "" "$T"
  run_one "socks-open-$scheme" "socks5://127.0.0.1:18724" "$T"
  run_one "socks-relay-$scheme" "socks5://$USER:$PW@127.0.0.1:18723" "$T"
  run_one "http-open-$scheme" "http://127.0.0.1:18725" "$T"
  run_one "http-relay-$scheme" "http://$USER:$PW@127.0.0.1:18721" "$T"
  run_one "https-open-$scheme" "https://127.0.0.1:18726" "$T"
  run_one "https-relay-$scheme" "https://$USER:$PW@127.0.0.1:18722" "$T"
done
echo MATRIX_DONE
