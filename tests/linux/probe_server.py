#!/usr/bin/env python3
"""navigator.webdriver probe for round 14 (127.0.0.1 only).

GET /          -> page that reads navigator.webdriver and sends /wd?webdriver=<value>
GET /wd?...    -> records the value in PROBE_LOG (jsonl) and replies 204.
Usage: probe_server.py <port> <log-file>
"""
import http.server, json, sys, urllib.parse

PORT = int(sys.argv[1]); LOG = sys.argv[2]
PAGE = b"<html><body>probe<script>fetch('/wd?webdriver='+navigator.webdriver)</script></body></html>"

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/wd":
            val = urllib.parse.parse_qs(u.query).get("webdriver", [""])[0]
            with open(LOG, "a") as f:
                f.write(json.dumps({"webdriver": val}) + "\n")
            self.send_response(204); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers(); self.wfile.write(PAGE)

http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
