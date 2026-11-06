#!/bin/sh
# Egress check of the dedicated Chrome profile through a proxy, measured by the packet
# counters of a container whose only allowed route is the proxy (plus UDP to a STUN probe
# on the host, outside loopback, in the WebRTC cases). Test only.
# Needs: image sl-proxy-egress:1 (Dockerfile here); on the host: the synthetic origins
# (experiments/proxy/origin.py on 18701 HTTP and 18711 TLS) and the testserver HTTP proxy
# on 18725 (no auth). Usage: egress_check.sh <out-dir>
set -u
OUT=${1:?out dir}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
python3 "$HERE/stun_probe.py" 3478 "$OUT/stun-probe.jsonl" > "$OUT/stun-probe.stdout" 2>&1 &
PROBE=$!
sleep 1
run_case() { # name case url udp-to-stun
  name=$1; case=$2; url=$3; stun=$4
  : > "$OUT/stun-probe.jsonl.$name"
  docker run --rm --platform linux/amd64 --cap-add NET_ADMIN --add-host host.docker.internal:host-gateway -v "$HERE/egress.sh:/egress.sh:ro" \
    --shm-size 1g sl-proxy-egress:1 "$case" 18725 "$url" $stun > "$OUT/$name.txt" 2>&1
  echo "$name rc=$?"
}
STUN="stun=0.250.250.254:3478"
ONLY=${EGRESS_ONLY:-}
run() { # run_case with an optional filter: EGRESS_ONLY="name1 name2"
  case " $ONLY " in *" $1 "*|"  ") run_case "$@" ;; esac
}
run "socks-bare-https"   socks-bare "https://localhost:18711/page" ""
run "socks-prefs-https"  socks-prefs "https://localhost:18711/page" ""
run "rules-direct-http"  rules-direct "http://localhost:18701/page" ""
kill $PROBE 2>/dev/null
echo EGRESS_CHECK_DONE
