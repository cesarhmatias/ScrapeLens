# ScrapeLens Linux test environment (docs/21-linux.md). Only inside the container:
# nothing is installed on the user's macOS. No real site; everything on loopback.
#
#   Stable Chrome (amd64):   --platform linux/amd64 --build-arg BASE=ubuntu:24.04 --build-arg BROWSER=chrome
#   Chromium (arm64):        --platform linux/arm64 --build-arg BASE=debian:12      --build-arg BROWSER=chromium
#
# Stable Google Chrome has NO Linux arm64 build; on arm64 the accepted browser is
# Chromium (Debian's `chromium` package, real binary at /usr/lib/chromium/chromium).
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
# cmake: the testserver (quiche → BoringSSL) only compiles with it.
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
# Regular user (browser validation requires a root-owned binary, out of the user's reach).
RUN useradd -m -u 1001 tester && mkdir /cache /work && chown tester /cache /work
USER tester
ENV HOME=/home/tester PATH=/home/tester/.cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && /home/tester/.cargo/bin/rustup component add clippy
WORKDIR /work
