#!/bin/sh
# Egress observer. Usage (inside the container; see egress_check.sh):
#   egress.sh <case> <proxy-port> <url> [allow-udp-to-stun]
# <case>: "prefs" (proxy, dedicated-profile preferences and WebRTC flag), "bare" (proxy only,
# control), or "noproxy" (no proxy: positive control, the observer must see direct packets).
# The OUTPUT chain drops everything except the loopback and the proxy; the packet counters
# of the final DROP rule say how many packets tried to leave by another route.
set -u
set -f   # no globbing: the host-resolver rule contains "*"
CASE=$1; PPORT=$2; URL=$3; STUN=${4:-}
# SOCKS cases use the SOCKS5 test proxy, on its own port.
case "$CASE" in socks-*) PPORT=18724 ;; esac
PROXY_IP=$(getent hosts host.docker.internal | awk 'NR==1{print $1}')
iptables -P OUTPUT ACCEPT
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$PROXY_IP" -p tcp --dport "$PPORT" -j ACCEPT
if [ -n "$STUN" ]; then iptables -A OUTPUT -d 0.250.250.254 -p udp --dport 3478 -j ACCEPT; fi
# Categories of what tries to leave, counted separately (each is dropped).
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP
iptables -A OUTPUT -p udp --dport 5353 -j DROP
iptables -A OUTPUT -p udp -j DROP
iptables -A OUTPUT -p tcp --dport 443 -j DROP
iptables -A OUTPUT -p tcp -j DROP
iptables -A OUTPUT -j DROP
iptables -P OUTPUT DROP
PROFILE=/tmp/profile
rm -rf "$PROFILE"; mkdir -p "$PROFILE/Default"
if [ "$CASE" = prefs ] || [ "$CASE" = rules-direct ]; then
  echo '{"dns_over_https":{"mode":"off"}}' > "$PROFILE/Local State"
  echo '{"webrtc":{"ip_handling_policy":"disable_non_proxied_udp","multiple_routes_enabled":false,"nonproxied_udp_enabled":false}}' > "$PROFILE/Default/Preferences"
fi
EXTRA=""
[ "$CASE" = prefs ] && EXTRA="--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
[ "$CASE" = socks-prefs ] && EXTRA="--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
[ "$CASE" = socks-prefs ] && echo '{"dns_over_https":{"mode":"off"}}' > "$PROFILE/Local State" && echo '{"webrtc":{"ip_handling_policy":"disable_non_proxied_udp","multiple_routes_enabled":false,"nonproxied_udp_enabled":false}}' > "$PROFILE/Default/Preferences"
# Positional arguments, so that values with spaces (the host-resolver rule) stay whole.
set -- --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --user-data-dir="$PROFILE" --no-first-run --no-default-browser-check \
  --disable-background-networking --disable-sync --disable-component-update
case "$CASE" in
  socks-*) set -- "$@" "--proxy-server=socks5://$PROXY_IP:$PPORT" "--proxy-bypass-list=<-loopback>" ;;
  noproxy) ;;
  rules-direct) set -- "$@" "--proxy-server=http://$PROXY_IP:$PPORT" "--proxy-bypass-list=<-loopback>" \
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE $PROXY_IP" ;;
  *) set -- "$@" "--proxy-server=http://$PROXY_IP:$PPORT" "--proxy-bypass-list=<-loopback>" ;;
esac
[ -n "$EXTRA" ] && set -- "$@" "$EXTRA"
timeout 90 google-chrome-stable "$@" --ignore-certificate-errors --virtual-time-budget=15000 --dump-dom "$URL" > /tmp/dom.html 2> /tmp/chrome.err
echo "chrome exit: $?"
echo "dom bytes: $(wc -c < /tmp/dom.html)"
echo "--- OUTPUT counters (packets that tried to leave by another route are in the DROP row)"
iptables -L OUTPUT -v -n
