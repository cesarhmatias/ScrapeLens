#!/usr/bin/env bash
# Usage: experiments/linux/run.sh <label> <platform> <base> <chrome|chromium> [command...]
#   e.g.: experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome
# Builds the image (Docker cache), mounts a SNAPSHOT of the repository (read-only)
# and runs the command (default: experiments/linux/inside.sh) as a regular user, under Xvfb.
set -euo pipefail
label="$1"; platform="$2"; base="$3"; browser="$4"; shift 4
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="scrapelens-linux:$label"
docker build --platform "$platform" --build-arg BASE="$base" --build-arg BROWSER="$browser" \
    -t "$image" -f "$root/experiments/linux/Dockerfile" "$root/experiments/linux"
snap="$(mktemp -d /tmp/sl-linux-snap.XXXXXX)"
trap 'rm -rf "$snap"' EXIT
(cd "$root" && git archive HEAD | tar -x -C "$snap")
# Uncommitted changes in capture/ and recon/, if any, go into the snapshot.
if [ "${SL_WORKTREE:-1}" = "1" ]; then
    for d in capture recon docs experiments; do rsync -a --exclude target --exclude .idea "$root/$d/" "$snap/$d/"; done
fi
docker run --rm --platform "$platform" --security-opt seccomp=unconfined \
    -v "$snap":/src:ro -v "scrapelens-cargo-$label":/cache \
    -e SL_LABEL="$label" "$image" \
    bash -lc "${*:-/src/experiments/linux/inside.sh}"
