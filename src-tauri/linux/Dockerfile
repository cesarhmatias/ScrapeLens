# Reproducible ScrapeLens build for Linux (round 14).
# Base pinned by digest (multi-architecture index of ubuntu:22.04), fixed Rust and Node,
# dependencies pinned by the lockfiles (src-tauri/Cargo.lock, app/package-lock.json).
#   docker build --platform linux/amd64 -f src-tauri/linux/Dockerfile -t scrapelens-linux:amd64 .
#   docker run --rm --platform linux/amd64 -v "$PWD/src-tauri/linux/out:/out" scrapelens-linux:amd64
FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

ARG RUST_VERSION=1.98.1
ARG NODE_VERSION=26.8.1
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TZ=UTC \
    CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup \
    PATH=/opt/cargo/bin:/opt/node/bin:$PATH \
    APPIMAGE_EXTRACT_AND_RUN=1 NO_STRIP=true SOURCE_DATE_EPOCH=1767225600

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl wget file xz-utils pkg-config git \
      libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev \
      libayatana-appindicator3-dev librsvg2-dev libssl-dev libxdo-dev patchelf \
      python3 xvfb xauth dbus-x11 xdg-utils desktop-file-utils squashfs-tools \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION} -c clippy \
    && rustc --version

# Official Node, verified against the release's own SHASUMS256.
RUN set -eux; case "$(uname -m)" in x86_64) a=x64;; aarch64) a=arm64;; esac; \
    f=node-v${NODE_VERSION}-linux-$a.tar.xz; cd /tmp; \
    curl -sSfO https://nodejs.org/dist/v${NODE_VERSION}/$f; \
    curl -sSf https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt | grep " $f\$" | sha256sum -c -; \
    mkdir /opt/node && tar -xJf $f -C /opt/node --strip-components=1 && rm $f; node --version

WORKDIR /src
COPY app/package.json app/package-lock.json app/
RUN cd app && npm ci --no-audit --no-fund
COPY core core
COPY capture capture
COPY recon recon
COPY mcp mcp
COPY adapters adapters
COPY src-tauri src-tauri
COPY app app
COPY fixtures fixtures
CMD ["bash", "/src/src-tauri/linux/build.sh"]
