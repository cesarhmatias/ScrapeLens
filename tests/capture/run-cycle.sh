#!/usr/bin/env bash
# Real ScrapeLens capture cycle on macOS.
#
# Starts the local test servers, captures real Chrome (CDP + NetLog) on h1,
# h2 and h3 (QUIC forced on the h2 origin), imports the captures with the core CLI,
# imports the native HAR and writes tests/capture/runs/<RUN_ID>/run.json.
#
# Requirements: macOS, installed Chrome, Rust/cargo, Node 22+, curl.
# Nothing is installed on the system; the test certificate is waived by SPKI.
# Network: Chrome blocked by --host-resolver-rules except 127.0.0.1.
#
# Usage: tests/capture/run-cycle.sh [RUN_ID] [BASE_PORT]
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
# Test certificates are generated, not tracked: make them when this checkout has none.
[ -f "$ROOT/fixtures/tls/scrapelens-test-localhost.key.pem" ] || (cd "$ROOT/testserver" && cargo run -q -- gen-cert) || exit 1
RUN_ID="${1:-$(date -u +%Y%m%dT%H%M%SZ)}"
BASE_PORT="${2:-${SCRAPELENS_BASE_PORT:-9781}}"
H1="127.0.0.1:${BASE_PORT}"
H2="127.0.0.1:$((BASE_PORT + 1))"
H3="127.0.0.1:$((BASE_PORT + 2))"
RUN="tests/capture/runs/${RUN_ID}"
CORE="${ROOT}/target/release/scrapelens-core"
SERVER="${ROOT}/target/release/scrapelens-testserver"
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
NODE="${NODE_BIN:-$(command -v node)}"

if [[ ! -x "${CHROME}" ]]; then echo "Chrome not found at ${CHROME}" >&2; exit 1; fi
if [[ -z "${NODE}" ]]; then echo "node not found" >&2; exit 1; fi

echo "== build (offline)"
(cd core && cargo build --release --offline --quiet)
(cd testserver && cargo build --release --offline --quiet)

rm -rf "${RUN}"
mkdir -p "${RUN}/server"

echo "== local servers: h1 ${H1} · h2 ${H2} · h3 ${H3}"
"${SERVER}" serve --run-id "${RUN_ID}" --evidence "${RUN}/server" \
  --h1 "${H1}" --h2 "${H2}" --h3 "${H3}" \
  >"${RUN}/server/server.log" 2>&1 &
SERVER_PID=$!
CHROME_PIDS=()
cleanup() {
  for pid in "${CHROME_PIDS[@]:-}"; do kill "${pid}" 2>/dev/null || true; done
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  curl -fsS -m 1 "http://${H1}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS -m 2 "http://${H1}/healthz" >/dev/null

capture() {
  local name="$1" protocol="$2" urls="$3" force="${4:-}" har="${5:-}"
  echo "== capture ${name} (${protocol})"
  local extra=() harflag=()
  [[ -n "${force}" ]] && extra=(--force-quic "${force}")
  [[ -n "${har}" ]] && harflag=(--har)
  "${NODE}" tests/capture/capture_cycle.mjs \
    --outdir "${RUN}" --name "${name}" \
    --spki-file fixtures/tls/spki-sha256-base64.txt \
    --port "$((BASE_PORT + 100))" --urls "${urls}" \
    ${harflag[@]+"${harflag[@]}"} ${extra[@]+"${extra[@]}"}
  "${CORE}" import-capture "${RUN}/${name}.cdp-events.jsonl" "${RUN}/${name}.chrome-netlog.json" \
    --out "${RUN}/session-${name}" >"${RUN}/${name}.import.json"
}

# h1 (document, cookies, redirects, POSTs and concurrent requests) + h2/TLS.
capture h1h2 h2 \
  "http://${H1}/setcookie,http://${H1}/page,http://${H1}/redirect?n=2,https://${H2}/echo-order?case=real-h2" "" har

# h3/QUIC: forces QUIC on the h2 origin, which also listens on UDP h3.
capture h3 h3 "https://${H2}/page,https://${H2}/echo-order?case=real-h3" "${H2}"

# Realistic HAR derived from CDP (Chrome 156 does not expose Network.getHAR;
# the script declares the origin in the creator, and the order is that of the CDP map, not of the wire).
if [[ -f "${RUN}/h1h2.cdp-events.jsonl" && -f experiments/har_from_cdp.mjs ]]; then
  mkdir -p "${RUN}/har-derive"
  cp "${RUN}/h1h2.cdp-events.jsonl" "${RUN}/har-derive/cdp-events.jsonl"
  "${NODE}" experiments/har_from_cdp.mjs "${RUN}/har-derive" >/dev/null
  "${CORE}" import-har "${RUN}/har-derive/har-derived.json" --out "${RUN}/session-har" >"${RUN}/har.import.json"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
trap - EXIT

echo "== summary"
python3 tests/capture/summarize.py "${RUN}" --chrome-version "$("${CHROME}" --version 2>/dev/null || echo unknown)" \
  --ports "${BASE_PORT}" | tee "${RUN}/summary.txt"

# Small, stable evidence for commit (raw sessions stay in runs/).
LATEST="tests/results/capture-latest"
rm -rf "${LATEST}"
mkdir -p "${LATEST}"
cp "${RUN}/run.json" "${RUN}/summary.txt" "${RUN}/h1h2.meta.json" "${RUN}/h3.meta.json" "${LATEST}/"
for file in h1h2.import.json h3.import.json har.import.json; do
  [[ -f "${RUN}/${file}" ]] && cp "${RUN}/${file}" "${LATEST}/"
done
echo "${RUN}" > tests/results/last-capture.txt
echo
echo "run: ${RUN}/run.json"
echo "evidence: ${LATEST}/run.json"
