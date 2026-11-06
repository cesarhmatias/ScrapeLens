#!/bin/sh
# Egress rules for the packaged-App run (run as root by the host, with docker exec -u root,
# before the App starts). The container may send only to the proxy and to loopback.
# The proxy host name is resolved from /etc/hosts (the run passes --add-host), so no DNS packet
# is needed. The App keeps running as tester: no root process of the run stays alive.
set -u
PIP=$(getent hosts "$PROXY_HOST" | awk 'NR==1{print $1}')
echo "egress: proxy $PROXY_HOST = $PIP:$PROXY_PORT" > /out/egress-setup.txt
iptables -P OUTPUT ACCEPT; iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$PIP" -p tcp --dport "$PROXY_PORT" -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP
iptables -A OUTPUT -p udp --dport 5353 -j DROP
iptables -A OUTPUT -p udp -j DROP
iptables -A OUTPUT -p tcp --dport 443 -j DROP
iptables -A OUTPUT -p tcp -j DROP
iptables -A OUTPUT -j DROP
iptables -P OUTPUT DROP
echo rules-applied
