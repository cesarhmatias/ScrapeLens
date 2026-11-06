# Chrome for the egress test: no direct route is needed by the browser under test, and
# iptables in this container counts every packet that tries to leave it.
FROM --platform=linux/amd64 debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl fonts-liberation iptables iproute2 python3 \
 && curl -fsSLo /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
 && apt-get install -y --no-install-recommends /tmp/chrome.deb \
 && rm -rf /tmp/chrome.deb /var/lib/apt/lists/*
COPY egress.sh /egress.sh
ENTRYPOINT ["/bin/sh", "/egress.sh"]
