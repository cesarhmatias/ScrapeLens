# Loopback test server: /set sets a synthetic cookie (v11 path), /set10 a legacy one (v10 path); any other path logs the Cookie header it received.
import http.server, json, sys
LOG = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/set10"):
            # Legacy cookie for the mixed-profile case: written with the basic store (v10).
            self.send_response(200)
            self.send_header("Set-Cookie", "old10=legacy10SYNTHETIC; Path=/; Max-Age=86400")
            self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(b"<html><body>set10</body></html>")
            return
        if self.path.startswith("/set"):
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=abc123SYNTHETIC; Path=/; Max-Age=86400")
            self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(b"<html><body>set</body></html>")
            return
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": self.path, "cookie": self.headers.get("Cookie")}) + "\n")
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 8765), H).serve_forever()
