#!/bin/bash
# Setup for the OrbStack Linux validation machines (round 14).
# Runs INSIDE the machine (e.g.: orb -m sl-ubuntu-amd64 bash -s < tests/linux/setup-vm.sh).
# Nothing here runs on macOS. Official repositories only; no real sites.
set -euo pipefail
ARCH="$(dpkg --print-architecture)"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  xvfb openbox xdotool x11-utils scrot imagemagick \
  iproute2 procps curl ca-certificates gnupg python3 python3-pip \
  fonts-liberation xauth
if [ "$ARCH" = "amd64" ]; then
  # Google Chrome stable, from Google's official repository.
  curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | sudo gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
    | sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y google-chrome-stable
  google-chrome-stable --version
else
  # arm64: Google does not publish Chrome for Linux arm64; uses Chromium.
  sudo apt-get install -y chromium || sudo apt-get install -y chromium-browser || true
  command -v chromium || command -v chromium-browser || echo "CHROMIUM_NOT_INSTALLED"
  (chromium --version || chromium-browser --version) 2>/dev/null || true
fi
echo "SETUP_OK arch=$ARCH"
