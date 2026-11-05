#!/usr/bin/env python3
"""Round 11: full MCP flow as a real client, over stdio.

Independent JSON-RPC client (Python, not the Rust harness), talking to the
`scrapelens-mcp` binary over stdin/stdout. Everything on loopback: an HTTP server of
the script itself on 127.0.0.1, real headless Chrome, no external site.

Positive flow:
  start_capture (elicitation accepted) → navigate → stop_capture → list_requests →
  get_request (header order checked against what the server received on the
  wire and against the NetLog header block) → trace_value of a cookie →
  site_profile.

Negative cases:
  - elicitation declined: no capture Chrome process is created (checked by
    counting `scrapelens-chrome` processes before and after);
  - navigate outside the allowlist: refused with `url_not_allowed` and the local
    server does not receive the request;
  - reveal=true without --allow-reveal: refused;
  - no cookie/token value appears in any MCP server output without reveal.

Output: JSON on stdout with `checks` (name, ok, detail) and overall `ok`. Exit code 0 only
if everything passes. Does not terminate any process it did not start.

Usage: python3 tests/acceptance/mcp_flow.py [--binary PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_BIN = ROOT / "mcp" / "target" / "debug" / "scrapelens-mcp"

SECRET_COOKIE = "SECRET-FLOW-COOKIE-7f3a"
SECRET_TOKEN = "SECRET-FLOW-TOKEN-9c1d"
SECRETS = [SECRET_COOKIE, SECRET_TOKEN]

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    # The report never carries the synthetic secret value, not even in failure details.
    for secret in SECRETS:
        detail = detail.replace(secret, "<synthetic-secret-omitted>")
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail[:300]})
    return bool(ok)


# --------------------------------------------------------------- servidor local


class Hits:
    """Requests the local server actually received, with the header order."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.items: list[dict] = []

    def add(self, path: str, header_names: list[str], cookie: str | None) -> None:
        with self.lock:
            self.items.append({"path": path, "headers": header_names, "cookie": cookie})

    def paths(self) -> list[str]:
        with self.lock:
            return [item["path"] for item in self.items]

    def last(self, path: str) -> dict | None:
        with self.lock:
            matches = [item for item in self.items if item["path"] == path]
            return matches[-1] if matches else None


def make_handler(hits: Hits):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silent; the test log is the `hits` list
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            # self.headers keeps the order in which the headers arrived on the socket.
            names = [k for k, _ in self.headers.items()]
            cookie = self.headers.get("Cookie")
            hits.add(path, names, cookie)
            if path == "/":
                body = b"<html><body>inicio</body></html>"
                extra = [("Set-Cookie", f"sid={SECRET_COOKIE}; Path=/; HttpOnly")]
            elif path == "/page2":
                body = b"<html><body>segunda pagina</body></html>"
                extra = []
            else:
                body = b"not found"
                extra = []
            status = 200 if path in ("/", "/page2") else 404
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

    return Handler


def start_server(hits: Hits) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(hits))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ----------------------------------------------------------------- cliente MCP


class McpClient:
    """JSON-RPC client over stdio. Answers elicitation/create according to the policy."""

    def __init__(self, binary: pathlib.Path, args: list[str], policy: str) -> None:
        self.policy = policy  # "accept" | "decline" | "unsupported"
        self.proc = subprocess.Popen(
            [str(binary), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.transcript: list[str] = []  # every line the server wrote
        self.stderr_lines: list[str] = []
        self.elicitations: list[str] = []
        self.next_id = 0
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.transcript.append(line)
            self.lines.put(line)
        self.lines.put("")

    def _pump_err(self) -> None:
        for line in self.proc.stderr:
            self.stderr_lines.append(line)

    def _send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def _answer_elicitation(self, message: dict) -> None:
        self.elicitations.append(str(message.get("params", {}).get("message", "")))
        if self.policy == "accept":
            result = {"action": "accept", "content": {"confirmo": True}}
        else:
            result = {"action": "decline"}
        self._send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def request(self, method: str, params: dict, timeout: float = 240.0) -> dict:
        self.next_id += 1
        rid = self.next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(f"no response to {method}")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError(f"no response to {method}") from None
            if not line:
                raise RuntimeError(f"server exited before responding to {method}")
            message = json.loads(line)
            if message.get("method") == "elicitation/create" and "id" in message:
                self._answer_elicitation(message)
                continue
            if message.get("id") == rid and "method" not in message:
                return message

    def handshake(self) -> dict:
        caps = {} if self.policy == "unsupported" else {"elicitation": {"form": {}}}
        init = self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": caps,
            "clientInfo": {"name": "scrapelens-flow-test", "version": "1"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def tool(self, name: str, arguments: dict, timeout: float = 240.0) -> tuple[bool, dict]:
        response = self.request("tools/call", {"name": name, "arguments": arguments}, timeout)
        result = response.get("result") or {}
        is_error = bool(result.get("isError"))
        payload = result.get("structuredContent")
        if payload is None:
            text = "".join(c.get("text", "") for c in result.get("content", []))
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"text": text}
        if "error" in response:
            return True, {"error": response["error"]}
        return is_error, payload

    def close(self) -> tuple[int | None, str]:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            code = self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        time.sleep(0.2)
        return code, "".join(self.stderr_lines)


# --------------------------------------------------------------------- helpers


def chrome_capture_processes() -> list[str]:
    """Main Chrome processes that use a `scrapelens-chrome-*` profile (not Helpers)."""
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        if "scrapelens-chrome-" in line and "Helper" not in line and "Google Chrome" in line:
            found.append(line.strip()[:160])
    return found


def ordered_names_from_netlog(session_dir: pathlib.Path, path: str) -> list[list[str]]:
    """Header names of the `GET <path>` request in netlog.json, in raw order.

    The send event carries `"headers":["Host: ...", ...]` with the full list in
    send order; it is the array starting at the nearest `Host:` before the line
    `"line":"GET <path> HTTP/1.1"`. Read with the JSON decoder (without rebuilding
    the block as text).
    """
    netlog = session_dir / "netlog.json"
    if not netlog.exists():
        return []
    text = netlog.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    candidates: list[list[str]] = []
    for match in re.finditer(r'"line":"GET ' + re.escape(path) + r'(?:\?[^ \\"]*)? HTTP/1\.1', text):
        start = text.rfind('"headers":["Host:', 0, match.start())
        if start < 0:
            continue
        try:
            raw, _ = decoder.raw_decode(text, start + len('"headers":'))
        except json.JSONDecodeError:
            continue
        names = [h.split(":", 1)[0].strip() for h in raw if isinstance(h, str) and ":" in h]
        if names:
            candidates.append(names)
    return candidates


def find_session_dir(sessions: pathlib.Path, session_id: str) -> pathlib.Path | None:
    for candidate in sessions.rglob("session.json"):
        if candidate.parent.name == session_id or session_id in str(candidate.parent):
            return candidate.parent
    return None


def contains_secret(value) -> str | None:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    for secret in SECRETS:
        if secret in text:
            return secret
    return None


# ----------------------------------------------------------------- o fluxo


def run(binary: pathlib.Path) -> dict:
    work = pathlib.Path(tempfile.mkdtemp(prefix="sl-mcp-flow-"))
    os.chmod(work, 0o700)
    sessions = work / "sessions"
    hits = Hits()
    server = start_server(hits)
    port = server.server_address[1]
    host = f"localhost:{port}"
    base = f"http://localhost:{port}"
    args = ["--sessions-dir", str(sessions)]
    summary: dict = {"port": port, "host": host}
    all_outputs: list[str] = []  # everything the MCP server returned, for the secret scan

    try:
        # ----- 1. positive: elicitation accepted
        mcp = McpClient(binary, args, "accept")
        init = mcp.handshake()
        check("handshake", "result" in init and "serverInfo" in init["result"] or "result" in init,
              json.dumps(init)[:200])
        listed = mcp.request("tools/list", {})
        names = sorted(t["name"] for t in listed["result"]["tools"])
        summary["tools"] = names
        check("15 tools advertised", len(names) == 15, f"{len(names)}: {names}")
        start_tool = next(t for t in listed["result"]["tools"] if t["name"] == "start_capture")
        check("start_capture has no confirmation parameter",
              all("confirm" not in k for k in start_tool["inputSchema"]["properties"]))

        is_error, started = mcp.tool("start_capture", {
            "allowed_hosts": [host], "headless": True, "start_url": f"{base}/",
        }, timeout=240)
        all_outputs.append(json.dumps(started, ensure_ascii=False))
        check("start_capture accepted (elicitation)", not is_error, json.dumps(started)[:300])
        check("elicitation shown to the user", len(mcp.elicitations) == 1, str(mcp.elicitations)[:200])
        capture_id = started.get("captureId", "")
        check("real Chrome started", "Chrome" in str((started.get("browser") or {}).get("version", "")),
              json.dumps(started.get("browser"))[:200])

        # Outside the allowlist: does not reach the server.
        before = list(hits.paths())
        is_error, denied = mcp.tool("navigate", {
            "capture_id": capture_id, "url": f"http://127.0.0.1:{port}/outside",
        })
        all_outputs.append(json.dumps(denied, ensure_ascii=False))
        check("navigate outside the allowlist refused",
              is_error and (denied.get("error") or {}).get("code") == "url_not_allowed",
              json.dumps(denied)[:200])
        time.sleep(0.5)
        check("navigate outside the allowlist did not reach the local server",
              not any(p == "/outside" for p in hits.paths()[len(before):]),
              str(hits.paths()[len(before):]))

        # Allowed navigation, with a token in the query (must not appear in the output).
        is_error, nav = mcp.tool("navigate", {
            "capture_id": capture_id, "url": f"{base}/page2?token={SECRET_TOKEN}", "timeout_ms": 30000,
        })
        all_outputs.append(json.dumps(nav, ensure_ascii=False))
        check("allowed navigate loaded", not is_error and nav.get("loaded") is True,
              json.dumps(nav)[:200])
        time.sleep(0.8)

        is_error, status = mcp.tool("capture_status", {"capture_id": capture_id})
        all_outputs.append(json.dumps(status, ensure_ascii=False))
        check("capture_status is recording", status.get("recording") is True, json.dumps(status)[:200])

        is_error, stopped = mcp.tool("stop_capture", {"capture_id": capture_id})
        all_outputs.append(json.dumps(stopped, ensure_ascii=False))
        check("stop_capture graceful", not is_error and stopped.get("graceful") is True,
              json.dumps(stopped)[:300])
        check("NetLog complete", stopped.get("netlog") == "complete", str(stopped.get("netlog")))
        session_id = stopped.get("sessionId", "")
        summary["sessionId"] = session_id

        is_error, listing = mcp.tool("list_requests", {"session_id": session_id, "host": host})
        all_outputs.append(json.dumps(listing, ensure_ascii=False))
        items = listing.get("items", [])
        check("list_requests returns the session", not is_error and len(items) >= 2,
              f"total={listing.get('total')}")
        page2 = next((i for i in items if "/page2" in str(i.get("url", ""))), None)
        check("/page2 in the session", page2 is not None, json.dumps(items)[:200])
        check("query token absent from the listing",
              SECRET_TOKEN not in json.dumps(listing, ensure_ascii=False))

        # get_request + header order.
        is_error, detail = mcp.tool("get_request", {
            "session_id": session_id, "request_id": page2["requestId"], "verbose": True,
        })
        all_outputs.append(json.dumps(detail, ensure_ascii=False))
        req_headers = (detail.get("request") or {}).get("headers") or []
        names_mcp = []
        for h in req_headers:
            if isinstance(h, dict):
                names_mcp.append(str(h.get("name", "")))
            elif isinstance(h, list) and h:
                names_mcp.append(str(h[0]))
        check("get_request returns request headers in order", len(names_mcp) >= 3,
              f"{len(names_mcp)} headers")
        server_seen = hits.last("/page2")
        seen_names = server_seen["headers"] if server_seen else []
        check("header order = order received by the local server",
              [n.lower() for n in names_mcp] == [n.lower() for n in seen_names],
              f"mcp={names_mcp} servidor={seen_names}")
        netlog_blocks = ordered_names_from_netlog(find_session_dir(sessions, session_id) or sessions, "/page2")
        mcp_lower = [n.lower() for n in names_mcp]
        netlog_match = any([n.lower() for n in block] == mcp_lower for block in netlog_blocks)
        if not netlog_blocks:
            check("header order checked against the NetLog", False, "no GET /page2 block in the netlog")
        else:
            check("MCP header order = one raw NetLog block in the same order", netlog_match,
                  f"blocos={[len(b) for b in netlog_blocks]} mcp={names_mcp}")
        netlog_names = netlog_blocks[-1] if netlog_blocks else None
        summary["header_order"] = names_mcp
        summary["netlog_header_order"] = netlog_names

        # Cookie: the /page2 request carries the cookie set by /.
        check("cookie reached the server on the second request",
              server_seen is not None and bool(server_seen.get("cookie")) and "sid=" in server_seen["cookie"])

        is_error, trace = mcp.tool("trace_value", {"session_id": session_id, "cookie": "sid"})
        all_outputs.append(json.dumps(trace, ensure_ascii=False))
        check("trace_value of the cookie without error", not is_error, json.dumps(trace)[:200])
        check("trace_value of the cookie is masked", SECRET_COOKIE not in json.dumps(trace, ensure_ascii=False),
              json.dumps(trace)[:200])

        is_error, profile = mcp.tool("site_profile", {"session_id": session_id})
        all_outputs.append(json.dumps(profile, ensure_ascii=False))
        check("site_profile without error", not is_error, json.dumps(profile)[:200])

        # reveal without --allow-reveal: refused.
        is_error, rev = mcp.tool("get_request", {
            "session_id": session_id, "request_id": page2["requestId"], "reveal": True,
        })
        all_outputs.append(json.dumps(rev, ensure_ascii=False))
        check("reveal=true refused without --allow-reveal",
              is_error and "reveal" in json.dumps(rev).lower(), json.dumps(rev)[:200])

        code, stderr = mcp.close()
        check("server exits cleanly on EOF", code == 0, f"rc={code}")
        all_outputs.extend(mcp.transcript)
        all_outputs.append(stderr)

        # ----- 2. negative: declined elicitation does not open Chrome
        before_procs = chrome_capture_processes()
        mcp2 = McpClient(binary, args, "decline")
        mcp2.handshake()
        is_error, refused = mcp2.tool("start_capture", {
            "allowed_hosts": [host], "headless": True, "start_url": f"{base}/",
        })
        all_outputs.append(json.dumps(refused, ensure_ascii=False))
        time.sleep(1.0)
        after_procs = chrome_capture_processes()
        check("declined elicitation: start_capture fails", is_error, json.dumps(refused)[:200])
        check("declined elicitation: no capture Chrome created",
              len(after_procs) == len(before_procs),
              f"before={len(before_procs)} after={len(after_procs)}")
        check("declined elicitation: confirmation request was made", len(mcp2.elicitations) == 1)
        code2, stderr2 = mcp2.close()
        all_outputs.extend(mcp2.transcript)
        all_outputs.append(stderr2)

        # ----- 3. scan: no secret in any MCP server output
        leaks = []
        for index, chunk in enumerate(all_outputs):
            for secret in SECRETS:
                at = chunk.find(secret)
                if at >= 0:
                    leaks.append(f"output[{index}] {secret}: ...{chunk[max(0, at - 90):at + len(secret) + 20]}...")
        check("no cookie/token value in the whole MCP output (without reveal)", not leaks,
              " | ".join(leaks)[:1200])
    finally:
        server.shutdown()

    summary["checks"] = CHECKS
    summary["ok"] = all(c["ok"] for c in CHECKS)
    summary["passed"] = sum(1 for c in CHECKS if c["ok"])
    summary["failed"] = sum(1 for c in CHECKS if not c["ok"])
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(DEFAULT_BIN))
    args = parser.parse_args()
    binary = pathlib.Path(args.binary)
    if not binary.exists():
        print(json.dumps({"ok": False, "error": f"binary missing: {binary}"}))
        return 2
    summary = run(binary)
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
