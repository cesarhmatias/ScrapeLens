# Desktop-like Debian 12 user for the cookie-import end-to-end check (docs/16b §2.1c).
# A default desktop install: Chromium, the Secret Service (gnome-keyring), D-Bus, X and
# screenshot tools. It deliberately has NO sqlite3 command and NO libsecret-tools.
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates python3 xvfb xauth dbus-x11 xdotool procps \
      gnome-keyring libsecret-1-0 chromium fonts-liberation \
      libegl1 libgl1 libgles2 x11-apps imagemagick \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 tester
USER tester
ENV HOME=/home/tester
WORKDIR /home/tester
