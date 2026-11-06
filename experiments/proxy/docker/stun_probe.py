#!/usr/bin/env python3
"""UDP probe outside loopback: logs every datagram that reaches it (STUN binding requests
start with 0x00 0x01). Usage: stun_probe.py <port> <log>"""
import json, socket, sys, time

port, log = int(sys.argv[1]), sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
print("READY", flush=True)
while True:
    data, addr = sock.recvfrom(2048)
    with open(log, "a") as f:
        f.write(json.dumps({"t": time.time(), "src": addr[0], "len": len(data), "head": data[:4].hex()}) + "\n")
