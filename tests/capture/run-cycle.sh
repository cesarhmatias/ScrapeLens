#!/usr/bin/env bash
# Ciclo real de captura do ScrapeLens no macOS.
#
# Sobe os servidores locais de teste, captura Chrome real (CDP + NetLog) em h1,
# h2 e h3 (QUIC forçado no origin do h2), importa as capturas com o CLI do core,
# importa o HAR nativo e grava tests/capture/runs/<RUN_ID>/run.json.
#
# Requisitos: macOS, Chrome instalado, Rust/cargo, Node 22+, curl.
# Nada é instalado no sistema; o certificado de teste é dispensado por SPKI.
# Rede: Chrome bloqueado por --host-resolver-rules exceto 127.0.0.1.
#
# Uso: tests/capture/run-cycle.sh [RUN_ID] [BASE_PORT]
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
RUN_ID="${1:-$(date -u +%Y%m%dT%H%M%SZ)}"
BASE_PORT="${2:-${SCRAPELENS_BASE_PORT:-9781}}"
H1="127.0.0.1:${BASE_PORT}"
H2="127.0.0.1:$((BASE_PORT + 1))"
H3="127.0.0.1:$((BASE_PORT + 2))"
RUN="tests/capture/runs/${RUN_ID}"
CORE="${ROOT}/core/target/release/scrapelens-core"
SERVER="${ROOT}/testserver/target/release/scrapelens-testserver"
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
NODE="${NODE_BIN:-$(command -v node)}"

if [[ ! -x "${CHROME}" ]]; then echo "Chrome não encontrado em ${CHROME}" >&2; exit 1; fi
if [[ -z "${NODE}" ]]; then echo "node não encontrado" >&2; exit 1; fi

echo "== build (offline)"
(cd core && cargo build --release --offline --quiet)
(cd testserver && cargo build --release --offline --quiet)

rm -rf "${RUN}"
mkdir -p "${RUN}/server"

echo "== servidores locais: h1 ${H1} · h2 ${H2} · h3 ${H3}"
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
  echo "== captura ${name} (${protocol})"
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

# h1 (documento, cookies, redirects, POSTs e simultâneas) + h2/TLS.
capture h1h2 h2 \
  "http://${H1}/setcookie,http://${H1}/page,http://${H1}/redirect?n=2,https://${H2}/echo-order?case=real-h2" "" har

# h3/QUIC: força QUIC no origin do h2, que também escuta UDP h3.
capture h3 h3 "https://${H2}/page,https://${H2}/echo-order?case=real-h3" "${H2}"

if [[ -f "${RUN}/h1h2.native-har.json" ]]; then
  "${CORE}" import-har "${RUN}/h1h2.native-har.json" --out "${RUN}/session-har" >"${RUN}/har.import.json"
fi

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
trap - EXIT

echo "== resumo"
python3 tests/capture/summarize.py "${RUN}" --chrome-version "$("${CHROME}" --version 2>/dev/null || echo unknown)" \
  --ports "${BASE_PORT}" | tee "${RUN}/summary.txt"

# Evidência pequena e estável para commit (as sessões brutas ficam em runs/).
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
echo "evidência: ${LATEST}/run.json"
