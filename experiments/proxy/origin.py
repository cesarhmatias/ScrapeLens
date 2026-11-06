#!/usr/bin/env python3
"""Synthetic HTTP/1.1 origin for the proxy experiment (stdlib, raw sockets).

Records every request exactly as received: request line and headers in wire order,
duplicates included, and the body. Synthetic content only, loopback only.
Usage: origin.py --port 18701 --log origin.jsonl
"""
from __future__ import annotations

import argparse
import json
import socketserver
import ssl
import threading

CROSS = "http://site-b.test:18701"  # set by --cross-origin (real imports use 127.0.0.1)


def page() -> bytes:
    return (f"""<!doctype html><html><head><title>proxy-exp</title></head><body>
<iframe src="{CROSS}/frame"></iframe>
<script>
  fetch('/echo?from=page');
  new Worker('/worker.js');
  window.open('{CROSS}/popup');
</script></body></html>""").encode()
FRAME = b"<!doctype html><html><body><script>fetch('/echo?from=frame');</script></body></html>"
POPUP = b"<!doctype html><html><body>popup</body></html>"
WORKER = b"fetch('/echo?from=worker');"
WEBRTC = b"""<!doctype html><html><body><script>
const pc = new RTCPeerConnection({iceServers: []});
const cands = [];
pc.createDataChannel('x');
pc.onicecandidate = (e) => {
  if (e.candidate) cands.push(e.candidate.candidate);
  else fetch('/report', {method: 'POST', body: JSON.stringify({cands})});
};
pc.createOffer().then((o) => pc.setLocalDescription(o));
</script></body></html>"""

# Same page with a STUN server taken from ?stun=host:port (the egress test uses a UDP
# probe outside loopback).
WEBRTC_STUN = b"""<!doctype html><html><body><script>
const stun = new URLSearchParams(location.search).get('stun');
const pc = new RTCPeerConnection({iceServers: stun ? [{urls: 'stun:' + stun}] : []});
const cands = [];
pc.createDataChannel('x');
pc.onicecandidate = (e) => {
  if (e.candidate) cands.push(e.candidate.candidate);
  else fetch('/report', {method: 'POST', body: JSON.stringify({cands})});
};
pc.createOffer().then((o) => pc.setLocalDescription(o));
</script></body></html>"""

LOCK = threading.Lock()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.rfile.read(1)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        request_line = lines[0].decode("latin-1")
        headers = []
        for raw in lines[1:]:
            name, _, value = raw.decode("latin-1").partition(":")
            headers.append([name, value.lstrip(" ")])
        length = 0
        for name, value in headers:
            if name.lower() == "content-length":
                length = int(value.strip())
        body = rest[:length] if length else b""
        if length and len(body) < length:
            body += self.rfile.read(length - len(body))
        method, _, target = request_line.partition(" ")
        target = target.rsplit(" ", 1)[0]
        with LOCK, open(self.server.log_path, "a") as f:
            f.write(json.dumps({"request_line": request_line, "headers": headers,
                                "body": body.decode("latin-1")}) + "\n")
        path = target.split("?", 1)[0]
        if path in ("/", "/page"):
            status, ctype, out = "200 OK", "text/html", page()
        elif path == "/frame":
            status, ctype, out = "200 OK", "text/html", FRAME
        elif path == "/popup":
            status, ctype, out = "200 OK", "text/html", POPUP
        elif path == "/worker.js":
            status, ctype, out = "200 OK", "text/javascript", WORKER
        elif path == "/webrtc":
            status, ctype, out = "200 OK", "text/html", WEBRTC
        elif path == "/webrtc-stun":
            status, ctype, out = "200 OK", "text/html", WEBRTC_STUN
        elif path == "/setcookie":
            extra = b"Set-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\nSet-Cookie: a=3; Path=/\r\n"
            self._send("200 OK", "text/plain", b"ok", extra)
            return
        elif path == "/report":
            status, ctype, out = "204 No Content", "text/plain", b""
        else:
            status, ctype, out = "200 OK", "application/json", json.dumps(
                {"path": target, "headers": headers}).encode()
        self._send(status, ctype, out, b"")

    def _send(self, status, ctype, out, extra):
        head = (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(out)}\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\n").encode() + extra + b"\r\n"
        self.wfile.write(head + out)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    tls_context = None

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_context is not None:
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        return sock, addr


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18701)
    ap.add_argument("--log", required=True)
    ap.add_argument("--cross-origin", default="http://site-b.test:18701")
    ap.add_argument("--tls-cert", help="serve HTTPS with this certificate (and --tls-key)")
    ap.add_argument("--tls-key")
    args = ap.parse_args()
    global CROSS
    CROSS = args.cross_origin
    srv = Server((args.host, args.port), Handler)
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.tls_context = ctx
    srv.log_path = args.log
    print(f"READY {args.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
