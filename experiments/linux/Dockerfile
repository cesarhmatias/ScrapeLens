# Ambiente de teste Linux do ScrapeLens (docs/21-linux.md). Só dentro do container:
# nada é instalado no macOS do usuário. Sem site real; tudo em loopback.
#
#   Chrome estável (amd64):  --platform linux/amd64 --build-arg BASE=ubuntu:24.04 --build-arg BROWSER=chrome
#   Chromium (arm64):        --platform linux/arm64 --build-arg BASE=debian:12      --build-arg BROWSER=chromium
#
# O Google Chrome estável NÃO tem build Linux arm64; no arm64 o navegador aceito é o
# Chromium (pacote `chromium` do Debian, binário real em /usr/lib/chromium/chromium).
ARG BASE=ubuntu:24.04
FROM ${BASE}
ARG BROWSER=chrome
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential pkg-config git xvfb xauth python3 procps lsof \
        sqlite3 fonts-liberation dbus-x11 \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    if [ "$BROWSER" = "chrome" ]; then \
        curl -fsSL -o /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb; \
        apt-get update; apt-get install -y --no-install-recommends /tmp/chrome.deb; \
        rm -f /tmp/chrome.deb; \
    else \
        apt-get update; apt-get install -y --no-install-recommends chromium; \
    fi; \
    rm -rf /var/lib/apt/lists/*
# cmake: o testserver (quiche → BoringSSL) só compila com ele.
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
# Usuário comum (a validação do navegador exige binário de root, fora do alcance do usuário).
RUN useradd -m -u 1001 tester && mkdir /cache /work && chown tester /cache /work
USER tester
ENV HOME=/home/tester PATH=/home/tester/.cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && /home/tester/.cargo/bin/rustup component add clippy
WORKDIR /work
