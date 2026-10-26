#!/usr/bin/env bash
# Headless Chrome probe against the reference servers.
#
# 1. Navigates to /page over HTTPS + h2 (all fetches: duplicates, cookies,
#    concurrent identical requests, redirects, POSTs).
# 2. Repeats the same navigation with QUIC forced on the h2 port, so the same
#    page is served over h3 by the extra UDP listener.
#
# Then summarises which protocol Chrome actually used, in the JSONL evidence.
#
# Usage: ./scripts/chrome-probe.sh [BASE_PORT] [RUN_ID]
#   servers are started by this script if they are not already listening.
set -euo pipefail

cd "$(dirname "$0")/.."

BASE_PORT="${1:-${SCRAPELENS_BASE_PORT:-8781}}"
RUN_ID="${2:-$(date -u +%Y%m%dT%H%M%SZ)-chrome}"
H1="127.0.0.1:${BASE_PORT}"
H2="127.0.0.1:$((BASE_PORT + 1))"
H3="127.0.0.1:$((BASE_PORT + 2))"
EVIDENCE_DIR="../fixtures/evidence/${RUN_ID}"
BIN=target/debug/scrapelens-testserver
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PIN=$(grep -m1 -E '^[A-Za-z0-9+/=]+$' ../fixtures/tls/spki-sha256-base64.txt)

cargo build --quiet
rm -rf "${EVIDENCE_DIR}"
mkdir -p "${EVIDENCE_DIR}"

"${BIN}" serve --run-id "${RUN_ID}" --h1 "${H1}" --h2 "${H2}" --h3 "${H3}" \
  >"${EVIDENCE_DIR}/server.log" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  if curl -fsS -m 1 "http://${H1}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
curl -fsS -m 2 "http://${H1}/healthz" >/dev/null

chrome() {
  local profile="$1" force="$2" out="$3"
  local args=(
    --headless=new
    --user-data-dir="${profile}"
    --ignore-certificate-errors-spki-list="${PIN}"
    --no-first-run --no-default-browser-check --disable-gpu
    --enable-quic
    --virtual-time-budget=9000
    --dump-dom
  )
  if [ -n "${force}" ]; then
    args+=(--origin-to-force-quic-on="${force}")
  fi
  "${CHROME}" "${args[@]}" "https://${H2}/page" >"${out}" 2>/dev/null || true
}

echo "== Chrome $( "${CHROME}" --version 2>/dev/null || echo 'version unknown' )"
echo "   pin: ${PIN}"

echo "== navigation 1: h2 fallback"
P1=$(mktemp -d)
chrome "${P1}" "" "${EVIDENCE_DIR}/dom-h2.html"
echo "   fetches logged: $(grep -c 'bytes,' "${EVIDENCE_DIR}/dom-h2.html" || true)"

echo "== navigation 2: force QUIC on ${H2} (h3)"
P2=$(mktemp -d)
chrome "${P2}" "${H2}" "${EVIDENCE_DIR}/dom-h3.html"
echo "   fetches logged: $(grep -c 'bytes,' "${EVIDENCE_DIR}/dom-h3.html" || true)"
rm -rf "${P1}" "${P2}"

echo
python3 - "${EVIDENCE_DIR}" <<'PY'
import json, sys, pathlib, collections
root = pathlib.Path(sys.argv[1])
print("== evidence summary")
seen = collections.Counter()
interesting = []
for name in ("h1.jsonl", "h2.jsonl", "h3.jsonl"):
    p = root / name
    if not p.exists():
        continue
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        seen[r["proto"]] += 1
        if r["target"].startswith("/echo-order") and r["headers"]:
            cookies = [v for n, v in r["headers"] if n == "cookie"]
            orders = [v for n, v in r["headers"] if n == "x-order"]
            interesting.append((r["proto"], r["target"], len(r["headers"]), cookies, orders))
for proto, count in sorted(seen.items()):
    print(f"  {proto:8} {count:3d} requests")
print()
for proto, target, n, cookies, orders in interesting:
    print(f"  {proto:8} {target}")
    print(f"    header count: {n}")
    if orders:
        print(f"    x-order fields observed: {orders!r}")
    if cookies:
        print(f"    cookie fields: {len(cookies)} -> {cookies!r}")
PY

echo
echo "Browsers may transform headers before encoding; that is a finding, not a"
echo "server bug. The evidence above is the decoded-at-the-server reference."
echo "Evidence: ${EVIDENCE_DIR}"
