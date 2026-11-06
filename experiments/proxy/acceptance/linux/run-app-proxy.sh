#!/bin/sh
# Real capture through the packaged App (Linux, in a container, under Xvfb, no user window),
# through a local test proxy with credentials, then the Export / Sanitize dialog.
# Test only: loopback origin and test proxy on this machine, synthetic credentials.
# Usage: run-app-proxy.sh <arch: amd64|arm64> <package: path to .deb or .AppImage> <out-dir> [ok|wrong]
# Coordinates of the window (1440x920, Xvfb) come from the environment: PX PY SX SY TX TY EX EY.
# The defaults are for the 0.1.2 layout: Proxy field (1065,187), Start (1302,175), Stop (1396,175),
# Export / Sanitize (1090,248).
set -eu
ARCH=$1; PKG=$2; OUT=$3; MODE=${4:-ok}
HERE=$(cd "$(dirname "$0")" && pwd)
ACC=$(cd "$HERE/.." && pwd)
REPO=$(cd "$ACC/../../.." && pwd)
TS="$REPO/testserver/target/debug/scrapelens-testserver"
USER=tester-synthetic; PASS='p@ss-w0rd!'; PCT='p%40ss-w0rd%21'
PPORT=18731; OPORT=18781
mkdir -p "$OUT"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
"$TS" serve --only h1 --evidence "$OUT/origin" --run-id linux --h1 127.0.0.1:$OPORT --no-h3-on-h2-port > "$OUT/origin.log" 2>&1 & PIDS="$PIDS $!"
SCRAPELENS_TESTPROXY_AUTH="$USER:$PASS" "$TS" proxy --kind http --port $PPORT --evidence "$OUT/proxy.jsonl" \
  --auth-env SCRAPELENS_TESTPROXY_AUTH --resolve site-a.test=127.0.0.1 > "$OUT/proxy.log" 2>&1 & PIDS="$PIDS $!"
sleep 2
if [ "$MODE" = wrong ]; then LINK="http://$USER:not-the-password@host.docker.internal:$PPORT"; else LINK="http://$USER:$PCT@host.docker.internal:$PPORT"; fi
case "$PKG" in
  *.deb)
    CTX=$(mktemp -d); cp "$PKG" "$CTX/ScrapeLens.deb"
    printf 'FROM sl-cookie-import:%s-chrome\nUSER root\nCOPY ScrapeLens.deb /tmp/ScrapeLens.deb\nRUN apt-get update && apt-get install -y --no-install-recommends /tmp/ScrapeLens.deb && rm -rf /var/lib/apt/lists/*\nUSER tester\n' "$ARCH" > "$CTX/Dockerfile"
    IMG="sl-app-proxy:$ARCH-deb"; docker build -q --platform "linux/$ARCH" -t "$IMG" "$CTX" > /dev/null
    BIN=/usr/bin/scrapelens ;;
  *.AppImage)
    CTX=$(mktemp -d); cp "$PKG" "$CTX/ScrapeLens.AppImage"; chmod +x "$CTX/ScrapeLens.AppImage"
    IMG="sl-cookie-import:$ARCH-chrome"; BIN=/app/ScrapeLens.AppImage ;;
  *) echo "unknown package" >&2; exit 2 ;;
esac
APPDIR=$(mktemp -d)
[ "${CTX:-}" ] && [ -f "${CTX:-}/ScrapeLens.AppImage" ] && cp "$CTX/ScrapeLens.AppImage" "$APPDIR/"
docker run --rm --platform "linux/$ARCH" --security-opt seccomp=unconfined --add-host host.docker.internal:host-gateway \
  --shm-size 1g -e PROXY_LINK="$LINK" -e START_URL="http://site-a.test:$OPORT/echo-order?probe=app-$MODE" \
  -e PX="${PX:-1065}" -e PY="${PY:-187}" -e SX="${SX:-1302}" -e SY="${SY:-175}" -e TX="${TX:-1396}" -e TY="${TY:-175}" \
  -e EX="${EX:-1090}" -e EY="${EY:-248}" -e OUT=/out \
  -v "$HERE/in-container.sh:/scripts/in-container.sh:ro" -v "$OUT:/out" -v "$APPDIR:/app:ro" \
  "$IMG" sh /scripts/in-container.sh "$BIN" > "$OUT/container.log" 2>&1 || true
echo "run finished: $OUT"
