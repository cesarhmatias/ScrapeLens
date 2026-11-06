#!/usr/bin/env python3
"""Test upstream proxies and the local relay for the proxy experiment (stdlib only).

Subcommands
  upstream  test proxy: --kind socks-open | socks-auth | http-auth (CONNECT + Basic)
  relay     local SOCKS5 listener on 127.0.0.1 (no auth), forwards through an upstream
            (--upstream-kind none | socks-auth | http-auth), optional --allow host:port

Credentials come from the environment only (UP_USER/UP_PASS for upstream,
RELAY_USER/RELAY_PASS for the relay's upstream), never from argv, and are never logged.
Logs are JSON lines: one line per CONNECT with the outcome.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import socketserver
import threading
import time

SOCKS_OK, SOCKS_REFUSED, SOCKS_UNREACH, SOCKS_NOT_ALLOWED, SOCKS_GENERAL = 0, 5, 4, 2, 1


class Log:
    def __init__(self, path: str | None):
        self.path = path
        self.lock = threading.Lock()

    def write(self, **event):
        event.setdefault("t", round(time.time(), 3))
        if not self.path:
            return
        with self.lock, open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def pipe(a: socket.socket, b: socket.socket) -> None:
    def copy(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    t = threading.Thread(target=copy, args=(b, a), daemon=True)
    t.start()
    copy(a, b)
    t.join()
    for s in (a, b):
        try:
            s.close()
        except OSError:
            pass


def dial_http_upstream(host_port: str, host: str, port: int, auth: str | None) -> socket.socket:
    """HTTP CONNECT through an upstream proxy. Raises PermissionError on 407, ConnectionError otherwise."""
    sock = socket.create_connection(_split(host_port), timeout=15)
    headers = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if auth:
        headers += f"Proxy-Authorization: Basic {auth}\r\n"
    sock.sendall((headers + "\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("upstream closed during CONNECT")
        head += chunk
    status = int(head.split(b" ", 2)[1])
    if status == 407:
        sock.close()
        raise PermissionError("upstream refused the credentials (407)")
    if status != 200:
        sock.close()
        raise ConnectionError(f"upstream refused the target ({status})")
    sock.settimeout(None)
    return sock


def dial_socks_upstream(host_port: str, host: str, port: int, user: str | None, password: str | None) -> socket.socket:
    sock = socket.create_connection(_split(host_port), timeout=15)
    if user is not None:
        sock.sendall(b"\x05\x01\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    ver, method = read_exact(sock, 2)
    if method == 0x02:
        u, p = user.encode(), password.encode()
        sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        _, status = read_exact(sock, 2)
        if status != 0:
            sock.close()
            raise PermissionError("upstream refused the credentials (SOCKS5 auth)")
    elif method != 0x00:
        sock.close()
        raise ConnectionError("upstream offered no usable SOCKS5 method")
    name = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    _, rep, _, atyp = read_exact(sock, 4)
    if atyp == 1:
        read_exact(sock, 4 + 2)
    elif atyp == 4:
        read_exact(sock, 16 + 2)
    else:
        n = read_exact(sock, 1)[0]
        read_exact(sock, n + 2)
    if rep != 0:
        sock.close()
        raise ConnectionError(f"upstream refused the target (SOCKS5 reply {rep})")
    sock.settimeout(None)
    return sock


def _split(host_port: str) -> tuple[str, int]:
    h, _, p = host_port.rpartition(":")
    return h, int(p)


class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SocksHandler(socketserver.BaseRequestHandler):
    """SOCKS5 CONNECT. `server.upstream` None means connect directly (test upstream)."""

    def handle(self):
        srv = self.server
        sock = self.request
        try:
            ver, nmethods = read_exact(sock, 2)
            methods = read_exact(sock, nmethods)
            if ver != 5:
                return
            need_auth = srv.user is not None
            if need_auth:
                if 0x02 not in methods:
                    sock.sendall(b"\x05\xff")
                    return
                sock.sendall(b"\x05\x02")
                _, ulen = read_exact(sock, 2)
                user = read_exact(sock, ulen)
                password = read_exact(sock, read_exact(sock, 1)[0])
                ok = user.decode(errors="replace") == srv.user and password.decode(errors="replace") == srv.password
                sock.sendall(bytes([1, 0 if ok else 1]))
                if not ok:
                    srv.log.write(side=srv.side, event="auth_refused")
                    return
            else:
                sock.sendall(b"\x05\x00")
            ver, cmd, _, atyp = read_exact(sock, 4)
            if atyp == 1:
                host = ".".join(str(b) for b in read_exact(sock, 4))
            elif atyp == 3:
                host = read_exact(sock, read_exact(sock, 1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
            else:
                return
            port = int.from_bytes(read_exact(sock, 2), "big")
            if cmd != 1:
                sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            if srv.allow is not None and not srv.allow(host, port):
                srv.log.write(side=srv.side, event="connect", host=host, port=port, result="not_allowed")
                sock.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
                return
            target = srv.dial(host, port)
            if target is None:
                return
            sock.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            srv.log.write(side=srv.side, event="connect", host=host, port=port, result="ok")
            pipe(sock, target)
        except Exception as exc:  # noqa: BLE001
            try:
                srv.log.write(side=srv.side, event="error", kind=type(exc).__name__)
            except Exception:  # noqa: BLE001
                pass


def serve_socks(port: int, log: Log, side: str, user, password, dial, allow=None) -> SocksServer:
    srv = SocksServer(("127.0.0.1", port), SocksHandler)
    srv.log, srv.side, srv.user, srv.password, srv.dial, srv.allow = log, side, user, password, dial, allow
    return srv


# ---------- upstream test server ----------

class HttpConnectHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        sock = self.request
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(1)
                if not chunk:
                    return
                head += chunk
            lines = head.split(b"\r\n")
            method, target, _ = lines[0].decode().split(" ", 2)
            if method != "CONNECT":
                sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            got = None
            for raw in lines[1:]:
                name, _, value = raw.decode(errors="replace").partition(":")
                if name.lower() == "proxy-authorization":
                    got = value.strip()
            if srv.auth is not None and got != f"Basic {srv.auth}":
                srv.log.write(side="upstream-http", event="auth_refused")
                sock.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                return
            host, _, port_s = target.rpartition(":")
            port = int(port_s)
            try:
                upstream = socket.create_connection((srv.resolve.get(host, host), port), timeout=10)
            except OSError:
                srv.log.write(side="upstream-http", event="connect", host=host, port=port, result="unreachable")
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            srv.log.write(side="upstream-http", event="connect", host=host, port=port, result="ok")
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            pipe(sock, upstream)
        except Exception as exc:  # noqa: BLE001
            srv.log.write(side="upstream-http", event="error", kind=type(exc).__name__)


class HttpConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def encode_basic(user: str, password: str) -> str:
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("upstream")
    up.add_argument("--kind", required=True, choices=["socks-open", "socks-auth", "http-auth"])
    up.add_argument("--port", type=int, default=0)
    up.add_argument("--log", required=True)
    up.add_argument("--map", default="{}", help='JSON host->ip, e.g. {"site-a.test":"127.0.0.1"}')
    rl = sub.add_parser("relay")
    rl.add_argument("--port", type=int, default=0)
    rl.add_argument("--log", required=True)
    rl.add_argument("--upstream-kind", required=True, choices=["none", "socks-auth", "http-auth", "socks-open"])
    rl.add_argument("--upstream", default="", help="host:port of the upstream proxy")
    rl.add_argument("--allow", default="", help="comma-separated host:port (controlled mode); empty = any")
    rl.add_argument("--map", default="{}", help="test only: host->ip used when there is no upstream")
    args = ap.parse_args()
    log = Log(args.log)

    if args.cmd == "upstream":
        resolve = json.loads(args.map)
        user = os.environ.get("UP_USER")
        password = os.environ.get("UP_PASS")
        if args.kind == "http-auth":
            srv = HttpConnectServer(("127.0.0.1", args.port), HttpConnectHandler)
            srv.log, srv.resolve = log, resolve
            srv.auth = encode_basic(user, password) if user is not None else None
        else:
            def dial(host, port, _r=resolve):
                return socket.create_connection((_r.get(host, host), port), timeout=10)
            srv = serve_socks(args.port, log, "upstream-socks", user if args.kind == "socks-auth" else None,
                              password if args.kind == "socks-auth" else None, dial)
    else:
        allow_set = {tuple(x.rsplit(":", 1)) for x in args.allow.split(",") if x}
        def allow(host, port, _s=allow_set):
            return not _s or (host, str(port)) in _s
        upstream = args.upstream
        ukind = args.upstream_kind
        ru = os.environ.get("RELAY_USER")
        rp = os.environ.get("RELAY_PASS")
        if ukind == "none":
            resolve = json.loads(args.map)
            def dial(host, port, _r=resolve):
                return socket.create_connection((_r.get(host, host), port), timeout=10)
        elif ukind == "socks-auth":
            def dial(host, port):
                return dial_socks_upstream(upstream, host, port, ru, rp)
        elif ukind == "socks-open":
            def dial(host, port):
                return dial_socks_upstream(upstream, host, port, None, None)
        else:
            auth = encode_basic(ru, rp) if ru is not None else None
            def dial(host, port):
                return dial_http_upstream(upstream, host, port, auth)
        srv = serve_socks(args.port, log, "relay", None, None, dial, allow)

    print(f"READY {srv.server_address[1]}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
