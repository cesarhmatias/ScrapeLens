#!/bin/bash
# Preparo das máquinas OrbStack de validação Linux (rodada 14).
# Roda DENTRO da máquina (ex.: orb -m sl-ubuntu-amd64 bash -s < tests/linux/setup-vm.sh).
# Nada aqui roda no macOS. Só repositórios oficiais; sem sites reais.
set -euo pipefail
ARCH="$(dpkg --print-architecture)"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  xvfb openbox xdotool x11-utils scrot imagemagick \
  iproute2 procps curl ca-certificates gnupg python3 python3-pip \
  fonts-liberation xauth
if [ "$ARCH" = "amd64" ]; then
  # Google Chrome estável, repositório oficial do Google.
  curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | sudo gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
    | sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y google-chrome-stable
  google-chrome-stable --version
else
  # arm64: Google não publica Chrome para Linux arm64; usa Chromium.
  sudo apt-get install -y chromium || sudo apt-get install -y chromium-browser || true
  command -v chromium || command -v chromium-browser || echo "CHROMIUM_NOT_INSTALLED"
  (chromium --version || chromium-browser --version) 2>/dev/null || true
fi
echo "SETUP_OK arch=$ARCH"
