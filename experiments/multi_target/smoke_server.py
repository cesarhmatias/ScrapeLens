#!/usr/bin/env python3
"""Servidor smoke local para validar o harness multi-alvo antes de testserver /multi/.

Não substitui a rota oficial (testserver/). Grava JSONL com marcador ?m= na URL.
Duas origens: 127.0.0.1:PORT (principal) e 127.0.0.1:PORT+1 (OOPIF, outra porta).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SCHEMA = "scrapelens.multi.smoke/1"


def marker_from_path(path: str) -> str | None:
    q = parse_qs(urlparse(path).query)
    if "m" in q and q["m"]:
        return q["m"][0]
    return None


class Handler(BaseHTTPRequestHandler):
    evidence_path: pathlib.Path
    seq = 0
    lock = threading.Lock()

    def log_request(self, m: str, extra: dict | None = None) -> None:
        with self.lock:
            seq = Handler.seq
            Handler.seq += 1
        row = {
            "schema": SCHEMA,
            "seq": seq,
            "ts_unix_ms": int(time.time() * 1000),
            "server": self.server.server_address[0] + ":" + str(self.server.server_address[1]),
            "method": m,
            "target": self.path,
            "marker": marker_from_path(self.path),
            "headers": [[k, v] for k, v in self.headers.items()],
        }
        if extra:
            row.update(extra)
        with open(self.evidence_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def do_GET(self) -> None:
        if self.path.startswith("/multi/sw.js"):
            body = b"""
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.searchParams.get('m') === 'sw-intercept') {
    e.respondWith(fetch('/multi/echo?m=sw-fetch&via=sw'));
    return;
  }
});
"""
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/multi/worker.js"):
            body = b"self.onmessage=()=>fetch('/multi/echo?m=worker-fetch');"
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/multi/popup"):
            body = b"""<!doctype html><script>
fetch('/multi/echo?m=popup-first&order=x-seq:1,x-rep:a,x-seq:2');
</script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/multi/blank"):
            body = b"""<!doctype html><script>
fetch('/multi/echo?m=blank-first');
</script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/multi/echo"):
            self.log_request("GET")
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            q = parse_qs(urlparse(self.path).query)
            if q.get("order"):
                self.send_header("X-Order-Hint", q["order"][0])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/multi/"):
            oorig = f"http://127.0.0.1:{self.server.server_address[1] + 1}"
            body = f"""<!doctype html><meta charset=utf-8>
<h1>multi smoke</h1>
<script>
window.__multiDone = false;
(async () => {{
  window.open('/multi/popup?m=popup-nav');
  const w = document.createElement('a');
  w.href='/multi/blank?m=blank-nav'; w.target='_blank'; w.click();
  const iframe = document.createElement('iframe');
  iframe.src = '{oorig}/multi/echo?m=oophif-first';
  document.body.appendChild(iframe);
  if ('serviceWorker' in navigator) {{
    await navigator.serviceWorker.register('/multi/sw.js');
    await navigator.serviceWorker.ready;
    await fetch('/multi/echo?m=sw-intercept');
  }}
  const worker = new Worker('/multi/worker.js');
  worker.postMessage('go');
  await fetch('/multi/echo?m=page-main&order=x-seq:1,x-rep:a,x-seq:2');
  window.__multiDone = true;
}})();
</script>
""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        self.log_request("POST", {"body_len": len(raw), "body_b64": None})
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


def serve(port: int, evidence: pathlib.Path) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("")
    Handler.evidence_path = evidence
    h1 = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    h2 = ThreadingHTTPServer(("127.0.0.1", port + 1), Handler)
    t1 = threading.Thread(target=h1.serve_forever, daemon=True)
    t2 = threading.Thread(target=h2.serve_forever, daemon=True)
    t1.start()
    t2.start()
    return h1, h2


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9881)
    ap.add_argument("--evidence", type=pathlib.Path, required=True)
    args = ap.parse_args()
    serve(args.port, args.evidence)
    print(json.dumps({"h1": f"127.0.0.1:{args.port}", "oophif": f"127.0.0.1:{args.port + 1}"}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
