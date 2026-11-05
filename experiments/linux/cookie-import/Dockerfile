# Desktop-like Debian 12 user for the cookie-import end-to-end check (docs/16b §2.1c).
# A default desktop install: the Secret Service (gnome-keyring), D-Bus, X and screenshot
# tools, and ONE browser chosen with --build-arg BROWSER=chromium|chrome|edge|firefox.
# Every browser comes from its own vendor source (Google, Microsoft, Debian). Nothing here
# installs sqlite3 or libsecret-tools: the App must not need them.
FROM debian:12
ARG BROWSER=chromium
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg python3 xvfb xauth dbus-x11 xdotool procps \
      gnome-keyring libsecret-1-0 fonts-liberation libegl1 libgl1 libgles2 x11-apps imagemagick \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "$BROWSER" in \
      chromium) apt-get update; apt-get install -y --no-install-recommends chromium ;; \
      chrome) \
        arch="$(dpkg --print-architecture)"; \
        curl -fsSL -o /tmp/chrome.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_${arch}.deb"; \
        apt-get update; apt-get install -y --no-install-recommends /tmp/chrome.deb; rm -f /tmp/chrome.deb ;; \
      edge) \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /usr/share/keyrings/microsoft.gpg; \
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/edge stable main" > /etc/apt/sources.list.d/microsoft-edge.list; \
        apt-get update; apt-get install -y --no-install-recommends microsoft-edge-stable ;; \
      firefox) apt-get update; apt-get install -y --no-install-recommends firefox-esr ;; \
      *) echo "unknown BROWSER: $BROWSER" >&2; exit 2 ;; \
    esac; \
    rm -rf /var/lib/apt/lists/*
# The App captures with Google Chrome; cookies may come from another browser (Firefox, Edge).
# So a non-Chrome image also gets Google Chrome as the capture browser.
RUN set -eux; \
    if [ "$BROWSER" != chrome ]; then \
      arch="$(dpkg --print-architecture)"; \
      curl -fsSL -o /tmp/chrome.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_${arch}.deb"; \
      apt-get update; apt-get install -y --no-install-recommends /tmp/chrome.deb; rm -f /tmp/chrome.deb; \
      rm -rf /var/lib/apt/lists/*; \
    fi
RUN useradd -m -u 1001 tester
USER tester
ENV HOME=/home/tester
WORKDIR /home/tester
