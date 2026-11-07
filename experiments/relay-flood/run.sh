#!/bin/bash
# Real Chrome through the Linux relay while a local stranger floods it.
# Usage: run.sh <relay_server binary> [runs]
#   Build the binary with: cargo build --example relay_server   (in capture/)
# Run it in a container that has Chrome and the two users 1000 and 2000 available, e.g.
#   docker run --security-opt seccomp=unconfined --shm-size=1g ... bash run.sh <binary> 10
# A page is complete when the page reports ok=241 err=0 (240 images and one slow resource).
# The relay runs as uid 1000 with Chrome; the flood runs as uid 2000.
set -u
here=$(cd "$(dirname "$0")" && pwd)
S=${1:?relay_server binary}
N=${2:-10}
CHROME=${CHROME:-/opt/google/chrome/chrome}
TMP=${SCEN_TMP:-/tmp}
FL=$TMP/relay-flooder
gcc -O2 -pthread "$here/flooder.c" -o "$FL" || exit 1
export RELAY_UID=1000 STRANGER_UID=2000 SCEN_TMP=$TMP IMGS=240 HOSTS=40
ok=0
for i in $(seq 1 "$N"); do
  out=$(python3 -I "$here/realchrome.py" "$S" "$CHROME" "$FL" 4 600 2>&1 | grep -E '^\[realchrome|too many|relay_failures' | cut -c1-260)
  page=$(echo "$out" | grep -oE 'page=[^ ]*( [^ ]*)?' | head -1)
  echo "run $i: $page"
  if echo "$out" | grep -q 'page=ok=241 err=0'; then ok=$((ok+1)); fi
done
echo "full pages: $ok / $N"
