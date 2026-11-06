#!/usr/bin/env bash
# ScrapeLens reference servers — one-command demo.
#
# Starts the three reference servers, sends deliberately ordered requests with
# duplicates over HTTP/1.1, h2 and h3, then prints the JSONL evidence summary.
#
# Usage:
#   ./run-demo.sh [BASE_PORT] [RUN_ID]
#
# Defaults: BASE_PORT=8781 (h1 8781, h2 8782, h3 8783), RUN_ID=UTC timestamp.
# Ports must be free; use another base (e.g. 9781) when 8781-8783 are in use.
set -euo pipefail
# Test certificates are generated, not tracked: make them when this checkout has none.
[ -f ../fixtures/tls/scrapelens-test-localhost.key.pem ] || cargo run -q -- gen-cert

cd "$(dirname "$0")"

BASE_PORT="${1:-${SCRAPELENS_BASE_PORT:-8781}}"
RUN_ID="${2:-$(date -u +%Y%m%dT%H%M%SZ)}"
H1="127.0.0.1:${BASE_PORT}"
H2="127.0.0.1:$((BASE_PORT + 1))"
H3="127.0.0.1:$((BASE_PORT + 2))"
EVIDENCE_DIR="../fixtures/evidence/${RUN_ID}"
LOG="${EVIDENCE_DIR}/server.log"
CA="../fixtures/tls/scrapelens-test-ca.crt.pem"
BIN=target/debug/scrapelens-testserver

cargo build --quiet
rm -rf "${EVIDENCE_DIR}"
mkdir -p "${EVIDENCE_DIR}"

"${BIN}" serve \
  --run-id "${RUN_ID}" \
  --h1 "${H1}" --h2 "${H2}" --h3 "${H3}" \
  >"${LOG}" 2>&1 &
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
if ! curl -fsS -m 2 "http://${H1}/healthz" >/dev/null; then
  echo "servers failed to start; see ${LOG}" >&2
  exit 1
fi

pin() { grep -m1 -E '^[A-Za-z0-9+/=]+$' ../fixtures/tls/spki-sha256-base64.txt; }

echo "== h1: raw socket order (names, casing, duplicates preserved)"
curl -sS -D- -o /dev/null \
  "http://${H1}/echo-order?probe=demo-h1" \
  -H 'x-order: first' -H 'x-order: second' -H 'x-dup: same' \
  -H 'X-Zeta: 1' -H 'X-Zeta: 2' \
  -H 'Cookie: a=1' -H 'Cookie: b=2' \
  | sed -n '1p'

echo
echo "== h1: /setcookie response order (markers interleaved with Set-Cookie)"
curl -sS -D- -o /dev/null "http://${H1}/setcookie" | grep -iE '^(set-cookie|x-scrapelens-order)'

echo
echo "== h2: HPACK decoded order"
curl -sS --http2 --cacert "${CA}" -D- -o /tmp/scrapelens-h2-body.json \
  "https://${H2}/echo-order?probe=demo-h2" \
  -H 'x-order: first' -H 'x-order: second' -H 'x-dup: same' | sed -n '1p;/^alt-svc/Ip'
echo "decoded request headers (in order):"
python3 - <<'PY'
import json
d = json.load(open('/tmp/scrapelens-h2-body.json'))
for i, (n, v) in enumerate(d['headers']):
    print(f"  [{i}] {n}: {v}")
PY

echo
echo "== h3: QPACK decoded order (quiche client, duplicate headers)"
"${BIN}" client-h3 "https://${H3}/echo-order?probe=demo-h3" \
  --header 'x-order: first' --header 'x-order: second' --header 'x-dup: same' \
  | sed -n '1,3p'

echo
echo "== POST echo (binary body, 128 KiB) over h1 and h2"
head -c 131072 /dev/zero | tr '\0' 'x' >/tmp/scrapelens-big.txt
for url in "http://${H1}" "https://${H2}"; do
  proto=$(curl -sS --http2 --cacert "${CA}" -o /tmp/scrapelens-echo.bin \
    -w '%{http_version}' --data-binary @/tmp/scrapelens-big.txt \
    -H 'content-type: application/octet-stream' "${url}/echo")
  printf '  %s -> HTTP/%s, echoed %s bytes\n' "${url}" "${proto}" "$(wc -c </tmp/scrapelens-echo.bin | tr -d ' ')"
done

echo
echo "== evidence"
echo "run dir: ${EVIDENCE_DIR}"
for f in h1.jsonl h2.jsonl h3.jsonl; do
  [ -f "${EVIDENCE_DIR}/${f}" ] || continue
  printf '  %-9s %3s requests  %s\n' "${f}" "$(wc -l <"${EVIDENCE_DIR}/${f}" | tr -d ' ')" "${EVIDENCE_DIR}/${f}"
done

echo
echo "== proof from the evidence (ordered header arrays, duplicates kept)"
python3 - "${EVIDENCE_DIR}" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
for name in ("h1.jsonl", "h2.jsonl", "h3.jsonl"):
    p = root / name
    if not p.exists():
        continue
    rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    for r in rows:
        if "/echo-order" in r["target"] and any(n == "x-order" for n, _ in r["headers"]):
            pairs = [f"{n}: {v}" for n, v in r["headers"] if n.lower() in ("x-order", "x-dup", "cookie")]
            print(f"  {r['proto']:8} {r['target']}")
            print(f"    decode_point: {r['decode_point'][:88]}...")
            print(f"    headers[{len(r['headers'])}], relevant in order: {pairs}")
            break
PY

echo
echo "Chrome probe: ./scripts/chrome-probe.sh ${BASE_PORT} ${RUN_ID}-chrome"
echo "Chrome pin:   --ignore-certificate-errors-spki-list=$(pin)"
