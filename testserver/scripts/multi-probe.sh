#!/usr/bin/env bash
# Multi-target probe (round 10, docs/14-multi-target-capture.md).
#
# Starts the h1 reference server and opens /multi/ in headless Chrome. The page
# fires one request per CDP target kind: top-level page, popup (window.open),
# target=_blank tab, OOPIF iframe on another origin (localhost x 127.0.0.1),
# dedicated worker and service worker. Then it checks that every expected
# ?m= marker reached the server, reading the compact `multi.jsonl` log.
#
# Usage: ./scripts/multi-probe.sh [BASE_PORT] [RUN_ID]
#   BASE_PORT defaults to 8781 (the h1 server port).
set -euo pipefail

cd "$(dirname "$0")/.."

BASE_PORT="${1:-${SCRAPELENS_BASE_PORT:-8781}}"
RUN_ID="${2:-multi-$(date -u +%Y%m%dT%H%M%SZ)}"
H1="127.0.0.1:${BASE_PORT}"
RUN_DIR="$(pwd)/../fixtures/evidence/${RUN_ID}"
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PROFILE="$(mktemp -d "${TMPDIR:-/tmp}/sl-multi-profile.XXXXXX")"

EXPECTED=(
  main-1 main-post-1
  popup-1 popup-get-1 popup-post-1
  blank-1 blank-get-1 blank-post-1
  oopif-1 oopif-get-1 oopif-post-1
  worker-get-1 worker-post-1
  sw-intercept-1 sw-own-1 sw-own-post-1
)

if [[ ! -x "${CHROME}" ]]; then echo "Chrome not found at ${CHROME}" >&2; exit 1; fi

cargo build --release --offline --quiet
BIN=target/release/scrapelens-testserver

mkdir -p "${RUN_DIR}"
"${BIN}" serve --only h1 --h1 "${H1}" --evidence "$(dirname "${RUN_DIR}")" --run-id "${RUN_ID}" \
  >"${RUN_DIR}/server.log" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
  rm -rf "${PROFILE}"
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  curl -fsS -m 1 "http://${H1}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS -m 2 "http://${H1}/healthz" >/dev/null

echo "== /multi/ at http://${H1}/multi/ (Chrome headless)"
"${CHROME}" \
  --headless=new \
  --user-data-dir="${PROFILE}" \
  --no-first-run --no-default-browser-check --disable-gpu \
  --disable-popup-blocking \
  --host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost" \
  --remote-debugging-port=0 \
  "http://${H1}/multi/" >"${RUN_DIR}/chrome.out" 2>"${RUN_DIR}/chrome.log" &
CHROME_PID=$!
# Give the page, popup, OOPIF, worker and service worker real time to run.
sleep "${MULTI_WAIT_SECONDS:-12}"
kill "${CHROME_PID}" 2>/dev/null || true
wait "${CHROME_PID}" 2>/dev/null || true

python3 - "${RUN_DIR}/multi.jsonl" "${RUN_DIR}/summary.json" "${EXPECTED[@]}" <<'PY'
import json, sys
log_path, out_path, expected = sys.argv[1], sys.argv[2], sys.argv[3:]
rows = [json.loads(line) for line in open(log_path, encoding="utf-8") if line.strip()]
seen = {r.get("marker") for r in rows if r.get("marker")}
missing = [m for m in expected if m not in seen]
by_marker = {}
for r in rows:
    m = r.get("marker")
    if not m:
        continue
    by_marker.setdefault(m, []).append({"method": r["method"], "target": r["target"], "body": r.get("body_text")})
summary = {
    "schema": "scrapelens.testserver.multi-summary/1",
    "requests": len(rows),
    "markers_seen": sorted(m for m in seen if m),
    "expected": expected,
    "missing": missing,
    "by_marker": by_marker,
}
open(out_path, "w", encoding="utf-8").write(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
print(f"markers: {len(seen)}/{len(expected)}")
for m in expected:
    print(("  ok  " if m in seen else "  MISSING ") + m)
sys.exit(1 if missing else 0)
PY
