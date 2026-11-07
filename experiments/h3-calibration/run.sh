#!/usr/bin/env bash
# Optional h3 QPACK-order calibration. Not part of the product.
# Usage: run.sh <output-dir>   (outside the repository; contains a key log and a pcap)
set -euo pipefail
OUT=${1:?usage: run.sh <output-dir>}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
TS="$ROOT/target/debug/scrapelens-testserver"

for tool in tshark tcpdump; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "LIMIT: $tool is not installed; h3 QPACK calibration not run. Matrix unchanged." >&2
    exit 2
  fi
done
[ -x "$CHROME" ] || { echo "missing Chrome: $CHROME" >&2; exit 2; }
[ -x "$TS" ] || { echo "missing testserver: $TS (cargo build -p scrapelens-testserver)" >&2; exit 2; }

mkdir -p "$OUT"
rm -f "$OUT/h3.pcap" "$OUT/keys.log" "$OUT/tshark.json" "$OUT/h3.jsonl"
SERVER_PID=""
CAP_PID=""
cleanup() {
  for pid in "$CAP_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "$CAP_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

"$TS" serve --only h3 --no-h3-on-h2-port --evidence "$OUT/server" --run-id h3cal \
  >"$OUT/server.stdout" 2>&1 &
SERVER_PID=$!
sleep 3
grep -q "listening on" "$OUT/server.stdout" || { cat "$OUT/server.stdout" >&2; exit 2; }

IFACE=lo0
[ "$(uname -s)" = Linux ] && IFACE=lo
# Requires BPF permission (macOS) or CAP_NET_RAW (Linux); the failure is explicit.
tcpdump -i "$IFACE" -n -s 0 -w "$OUT/h3.pcap" 'udp port 8783' >"$OUT/tcpdump.log" 2>&1 &
CAP_PID=$!
sleep 1
if ! kill -0 "$CAP_PID" 2>/dev/null; then
  cat "$OUT/tcpdump.log" >&2
  echo "LIMIT: tcpdump could not start; grant BPF access (macOS) or CAP_NET_RAW (Linux)." >&2
  exit 3
fi

PROFILE=$(mktemp -d "${TMPDIR:-/tmp}/sl-h3cal.XXXXXX")
SPKI=$(sed -n 's/.*spki-list=//p' "$OUT/server.stdout" | head -1)
timeout 25 "$CHROME" \
  --headless=new \
  --no-sandbox \
  --enable-quic \
  --ignore-certificate-errors-spki-list="$SPKI" \
  --virtual-time-budget=5000 \
  --user-data-dir="$PROFILE" \
  --ssl-key-log-file="$OUT/keys.log" \
  --origin-to-force-quic-on=127.0.0.1:8783 \
  --no-first-run --no-default-browser-check \
  --disable-background-networking --disable-component-update --disable-sync \
  --disable-default-apps --disable-extensions \
  --host-resolver-rules='MAP * ~NOTFOUND, EXCLUDE 127.0.0.1' \
  --dump-dom 'https://127.0.0.1:8783/echo-order?case=calibration' \
  >"$OUT/chrome.stdout" 2>"$OUT/chrome.stderr" || true
sleep 1
kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
CAP_PID=""
rm -rf "$PROFILE"

[ -s "$OUT/keys.log" ] || { echo "LIMIT: Chrome wrote no key log" >&2; exit 3; }
[ -s "$OUT/h3.pcap" ] || { echo "LIMIT: tcpdump wrote no pcap" >&2; exit 3; }

# PDML preserves repeated header fields; the JSON writer collapses same-named keys.
tshark -r "$OUT/h3.pcap" -o "tls.keylog_file:$OUT/keys.log" \
  -Y http3 -T pdml >"$OUT/tshark.pdml" 2>"$OUT/tshark.stderr" || true
cp "$OUT/server/h3cal/h3.jsonl" "$OUT/h3.jsonl" 2>/dev/null || true
python3 "$HERE/compare_qpack.py" --server "$OUT/h3.jsonl" --pdml "$OUT/tshark.pdml"
echo "OK: output in $OUT (keep the key log and pcap out of the repository and exports)"
