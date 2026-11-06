#!/bin/sh
# Live check of the product path: the controlled capture (stable Chrome, CDP + NetLog,
# allowlist) through the Rust relay and a test SOCKS5 upstream with credentials, against
# the synthetic origin. Test only: loopback, synthetic names, a test password.
# Usage: experiments/proxy/live_check.sh <out-dir>     (needs Google Chrome and cargo)
# Ends with a secret scan of every output: the password and its Base64 must not appear.
set -u
OUT=${1:?out dir}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PASS=${PROXY_TEST_PASSWORD:-Pw-Exp-7f3a9Q}
USER=${PROXY_TEST_USER:-exp-user}
ORIGIN=18701; UPSTREAM=18702
mkdir -p "$OUT/session"
python3 "$HERE/origin.py" --port $ORIGIN --log "$OUT/origin.jsonl" > "$OUT/origin.stdout" 2>&1 &
O=$!
sleep 1
UP_USER="$USER" UP_PASS="$PASS" python3 "$HERE/proxies.py" upstream --kind socks-auth --port $UPSTREAM \
  --log "$OUT/upstream.jsonl" --map '{"site-a.test":"127.0.0.1","site-b.test":"127.0.0.1"}' > "$OUT/upstream.stdout" 2>&1 &
U=$!
sleep 1
(cd "$ROOT/capture" && SCRAPELENS_PROXY_URL="socks5://$USER:$PASS@127.0.0.1:$UPSTREAM" \
  cargo run -q --example proxy_live -- "$OUT/session" $ORIGIN > "$OUT/live.stdout" 2> "$OUT/live.stderr")
RC=$?
kill $O $U 2>/dev/null
echo "capture exit: $RC"
B64=$(printf '%s:%s' "$USER" "$PASS" | base64)
HITS=0
for needle in "$PASS" "$B64"; do
  n=$(grep -rl -- "$needle" "$OUT" 2>/dev/null | wc -l | tr -d ' ')
  echo "secret scan (${needle%"${needle#????}"}...): $n file(s) in $OUT"
  HITS=$((HITS + n))
done
echo "secret hits total: $HITS"
[ "$RC" -eq 0 ] && [ "$HITS" -eq 0 ]
