#!/usr/bin/env bash
# Uso: experiments/linux/run.sh <rótulo> <plataforma> <base> <chrome|chromium> [comando...]
#   ex.: experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome
# Constrói a imagem (cache do Docker), monta um SNAPSHOT do repositório (somente leitura)
# e roda o comando (padrão: experiments/linux/inside.sh) como usuário comum, sob Xvfb.
set -euo pipefail
label="$1"; platform="$2"; base="$3"; browser="$4"; shift 4
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="scrapelens-linux:$label"
docker build --platform "$platform" --build-arg BASE="$base" --build-arg BROWSER="$browser" \
    -t "$image" -f "$root/experiments/linux/Dockerfile" "$root/experiments/linux"
snap="$(mktemp -d /tmp/sl-linux-snap.XXXXXX)"
trap 'rm -rf "$snap"' EXIT
(cd "$root" && git archive HEAD | tar -x -C "$snap")
# Se houver alterações ainda não commitadas em capture/ e recon/, entram no snapshot.
if [ "${SL_WORKTREE:-1}" = "1" ]; then
    for d in capture recon docs experiments; do rsync -a --exclude target --exclude .idea "$root/$d/" "$snap/$d/"; done
fi
docker run --rm --platform "$platform" --security-opt seccomp=unconfined \
    -v "$snap":/src:ro -v "scrapelens-cargo-$label":/cache \
    -e SL_LABEL="$label" "$image" \
    bash -lc "${*:-/src/experiments/linux/inside.sh}"
