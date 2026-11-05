#!/usr/bin/env bash
# End-to-end check of the cookie import on a desktop-like Linux user, with the packaged App.
# Usage: [BROWSER=chromium|chrome|edge|brave|firefox] [KEYRING=unlocked|locked|absent] \
#        experiments/linux/cookie-import/run.sh <platform> <package-file> <out-dir>
#   <platform>: linux/arm64 or linux/amd64
#   <package-file>: a .deb (installed) or an AppImage (run in place)
#   <out-dir>: receives e2e-raw.txt, after-start.png, end.png, srv.log, app.log
# The App runs in a private HOME. Its browser profile and preferences are created by the
# script; no real browser profile or real cookie is read. The page server is loopback only.
set -euo pipefail
platform="$1"; package="$2"; out="$3"
BROWSER="${BROWSER:-chromium}"; KEYRING="${KEYRING:-unlocked}"
here="$(cd "$(dirname "$0")" && pwd)"
arch="${platform#linux/}"
image="sl-cookie-import:$arch-$BROWSER"
mkdir -p "$out"
docker build --platform "$platform" --build-arg "BROWSER=$BROWSER" -t "$image" "$here"
envs=(-e "APP_READY_WAIT=40" -e "BROWSER=$BROWSER" -e "KEYRING=$KEYRING")
case "$package" in
  *.deb)
    ctx="$(mktemp -d)"; trap 'rm -rf "$ctx"' EXIT
    cp "$package" "$ctx/ScrapeLens.deb"
    printf 'FROM %s\nUSER root\nCOPY ScrapeLens.deb /tmp/ScrapeLens.deb\nRUN apt-get update && apt-get install -y --no-install-recommends /tmp/ScrapeLens.deb && rm -rf /var/lib/apt/lists/*\nUSER tester\n' "$image" > "$ctx/Dockerfile"
    docker build --platform "$platform" -t "$image-deb" "$ctx"
    docker run --rm --platform "$platform" --security-opt seccomp=unconfined "${envs[@]}" \
      -v "$here:/scripts:ro" -v "$(cd "$out" && pwd):/out" "$image-deb" sh /scripts/e2e-app.sh /usr/bin/scrapelens ;;
  *.AppImage)
    app_dir="$(mktemp -d)"; trap 'rm -rf "$app_dir"' EXIT
    cp "$package" "$app_dir/ScrapeLens.AppImage"; chmod +x "$app_dir/ScrapeLens.AppImage"
    docker run --rm --platform "$platform" --security-opt seccomp=unconfined "${envs[@]}" \
      -v "$here:/scripts:ro" -v "$app_dir:/app:ro" -v "$(cd "$out" && pwd):/out" "$image" \
      sh /scripts/e2e-app.sh /app/ScrapeLens.AppImage ;;
  *) echo "unknown package: $package" >&2; exit 2 ;;
esac
grep -E "cookie database|cookie |cookiesImported|sid=|app-running|window=|keyring" "$out/e2e-raw.txt" || true
