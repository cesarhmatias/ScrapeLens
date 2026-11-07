#!/bin/sh
# Real capture through the packaged App (Linux, in a container, under Xvfb, no user window),
# through a local test proxy with credentials, then the Export / Sanitize dialog.
# Test only: loopback origin and test proxy on this machine, synthetic credentials.
#
# Usage: run-app-proxy.sh <arch: amd64|arm64> <package: .deb or .AppImage> <out-dir> [ok|wrong]
# Environment:
#   PROXY_KIND=http|https   test proxy kind (https: TLS to the proxy with the test certificate in TLSDIR,
#                           which the container trusts as a system CA; the App refuses it otherwise)
#   TLSDIR=<folder>         certificate folder for https (CA, leaf for host.docker.internal)
#   EGRESS=1                egress observer: iptables lets the container send only to the proxy
#                           (and loopback); the DROP counters are written to <out>/egress-iptables.txt
#   PX PY SX SY TX TY EX EY window coordinates (defaults: 0.1.2 layout)
set -eu
ARCH=$1; PKG=$2; OUT=$3; MODE=${4:-ok}
PROXY_KIND=${PROXY_KIND:-http}; EGRESS=${EGRESS:-0}
HERE=$(cd "$(dirname "$0")" && pwd)
ACC=$(cd "$HERE/.." && pwd)
REPO=$(cd "$ACC/../../.." && pwd)
TS="$REPO/target/debug/scrapelens-testserver"
USER=tester-synthetic; PASS='p@ss-w0rd!'; PCT='p%40ss-w0rd%21'
PPORT=18731; OPORT=18781
mkdir -p "$OUT"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
"$TS" serve --only h1 --evidence "$OUT/origin" --run-id linux --h1 127.0.0.1:$OPORT --no-h3-on-h2-port > "$OUT/origin.log" 2>&1 & PIDS="$PIDS $!"
TLS_ARG=""
if [ "$PROXY_KIND" = https ]; then TLS_ARG="--tls ${TLSDIR:?TLSDIR needed for https}"; fi
SCRAPELENS_TESTPROXY_AUTH="$USER:$PASS" "$TS" proxy --kind "$PROXY_KIND" --port $PPORT --evidence "$OUT/proxy.jsonl" \
  --auth-env SCRAPELENS_TESTPROXY_AUTH --resolve site-a.test=127.0.0.1 $TLS_ARG > "$OUT/proxy.log" 2>&1 & PIDS="$PIDS $!"
sleep 2
if [ "$MODE" = wrong ]; then CRED="$USER:not-the-password"; else CRED="$USER:$PCT"; fi
LINK="$PROXY_KIND://$CRED@host.docker.internal:$PPORT"
EXTRA_DOCKER=""; SETUP=""
case "$PKG" in
  *.deb)
    CTX=$(mktemp -d); cp "$PKG" "$CTX/ScrapeLens.deb"
    APPBIN=/usr/bin/scrapelens; APPCOPY=""
    ;;
  *.AppImage)
    CTX=$(mktemp -d); cp "$PKG" "$CTX/ScrapeLens.AppImage"; chmod +x "$CTX/ScrapeLens.AppImage"
    APPBIN=/app/ScrapeLens.AppImage; APPCOPY=1
    ;;
  *) echo "unknown package" >&2; exit 2 ;;
esac
# the derived image: the package, and (when needed) iptables and the test CA
DOCK="FROM sl-cookie-import:$ARCH-chrome
USER root"
if [ "$EGRESS" = 1 ]; then DOCK="$DOCK
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*"; fi
if [ "$PROXY_KIND" = https ]; then
  cp "$TLSDIR/scrapelens-test-ca.crt.pem" "$CTX/scrapelens-test-ca.crt"
  DOCK="$DOCK
COPY scrapelens-test-ca.crt /usr/local/share/ca-certificates/scrapelens-test-ca.crt
RUN update-ca-certificates >/dev/null"
fi
if [ "$APPCOPY" = "" ]; then DOCK="$DOCK
COPY ScrapeLens.deb /tmp/ScrapeLens.deb
RUN apt-get update && apt-get install -y --no-install-recommends /tmp/ScrapeLens.deb && rm -rf /var/lib/apt/lists/*"; fi
DOCK="$DOCK
USER tester"
printf '%s\n' "$DOCK" > "$CTX/Dockerfile"
IMG="sl-app-proxy:$ARCH-$PROXY_KIND-egress$EGRESS-$(basename "$PKG" | tr -c 'A-Za-z0-9' '-' | cut -c1-40)"
docker build -q --platform "linux/$ARCH" -t "$IMG" "$CTX" > "$OUT/image-build.log" 2>&1
if [ "$EGRESS" = 1 ]; then EGRESS_ARGS="--cap-add NET_ADMIN -e EGRESS=1 -e PROXY_HOST=host.docker.internal -e PROXY_PORT=$PPORT"; else EGRESS_ARGS=""; fi
if [ "$APPCOPY" = 1 ]; then APP_MOUNT="-v $CTX/ScrapeLens.AppImage:/app/ScrapeLens.AppImage:ro"; else APP_MOUNT=""; fi
RUN_ARGS="--platform linux/$ARCH --security-opt seccomp=unconfined --add-host host.docker.internal:host-gateway \
  --shm-size 1g $EGRESS_ARGS -e PROXY_LINK=$LINK -e START_URL=http://site-a.test:$OPORT/echo-order?probe=app-$MODE \
  -e PX=${PX:-1065} -e PY=${PY:-187} -e SX=${SX:-1302} -e SY=${SY:-175} -e TX=${TX:-1396} -e TY=${TY:-175} \
  -e EX=${EX:-1090} -e EY=${EY:-248} -e OUT=/out \
  -v $HERE:/scripts:ro -v $OUT:/out $APP_MOUNT"
if [ "$EGRESS" = 1 ]; then
  # the container runs in the background; the host applies the egress rules as root (docker exec),
  # so no root process of the run stays alive while the App works (see in-container.sh)
  CID=$(eval docker run -d --rm $RUN_ARGS "$IMG" sh /scripts/in-container.sh "$APPBIN")
  echo "$CID" > "$OUT/container-id.txt"
  i=0; while [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" != true ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
  docker exec -u root -e PROXY_HOST=host.docker.internal -e PROXY_PORT=$PPORT "$CID" sh /scripts/egress-rules.sh > "$OUT/egress-rules.log" 2>&1
  touch "$OUT/egress-rules-applied"
  i=0; while [ ! -f "$OUT/app-finished" ] && [ $i -lt 900 ] && [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" = true ]; do sleep 2; i=$((i+1)); done
  docker exec -u root "$CID" iptables -L OUTPUT -v -n > "$OUT/egress-iptables.txt" 2>&1 || true
  touch "$OUT/counters-read"
  docker wait "$CID" > /dev/null 2>&1 || true
  docker logs "$CID" > "$OUT/container.log" 2>&1 || true
else
  eval docker run --rm $RUN_ARGS "$IMG" sh /scripts/in-container.sh "$APPBIN" > "$OUT/container.log" 2>&1 || true
fi
echo "run finished: $OUT"
