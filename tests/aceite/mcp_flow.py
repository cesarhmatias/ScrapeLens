#!/usr/bin/env python3
"""Rodada 11: fluxo completo do MCP como cliente real, por stdio.

Cliente JSON-RPC independente (Python, não o harness Rust), falando com o binário
`scrapelens-mcp` por stdin/stdout. Tudo em loopback: um servidor HTTP do próprio
script em 127.0.0.1, Chrome real headless, nenhum site externo.

Fluxo positivo:
  start_capture (elicitação aceita) → navigate → stop_capture → list_requests →
  get_request (ordem dos headers conferida contra o que o servidor recebeu na
  rede e contra o bloco de headers do NetLog) → trace_value de um cookie →
  site_profile.

Casos negativos:
  - elicitação recusada: nenhum processo de Chrome da captura é criado (conferido
    pela contagem de processos com `scrapelens-chrome` antes e depois);
  - navigate fora da allowlist: recusado com `url_not_allowed` e o servidor local
    não recebe a requisição;
  - reveal=true sem --allow-reveal: recusado;
  - nenhum valor de cookie/token aparece em nenhuma saída do servidor MCP sem reveal.

Saída: JSON em stdout com `checks` (nome, ok, detalhe) e `ok` geral. Código 0 só
se tudo passar. Não encerra nenhum processo que não tenha iniciado.

Uso: python3 tests/aceite/mcp_flow.py [--binary PATH]
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

SECRET_COOKIE = "SEGREDO-FLOW-COOKIE-7f3a"
SECRET_TOKEN = "SEGREDO-FLOW-TOKEN-9c1d"
SECRETS = [SECRET_COOKIE, SECRET_TOKEN]

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    # O relatório nunca carrega o valor sintético do segredo, nem em detalhe de falha.
    for secret in SECRETS:
        detail = detail.replace(secret, "<segredo-sintetico-omitido>")
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail[:300]})
    return bool(ok)


# --------------------------------------------------------------- servidor local


class Hits:
    """Requisições que o servidor local realmente recebeu, com a ordem dos headers."""

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

        def log_message(self, *args):  # silencioso; o log do teste é a lista `hits`
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            # self.headers preserva a ordem em que os headers chegaram no socket.
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
    """Cliente JSON-RPC por stdio. Responde elicitation/create conforme a política."""

    def __init__(self, binary: pathlib.Path, args: list[str], policy: str) -> None:
        self.policy = policy  # "accept" | "decline" | "unsupported"
        self.proc = subprocess.Popen(
            [str(binary), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.transcript: list[str] = []  # toda linha que saiu do servidor
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
                raise TimeoutError(f"sem resposta a {method}")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError(f"sem resposta a {method}") from None
            if not line:
                raise RuntimeError(f"servidor encerrou antes da resposta a {method}")
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
    """Processos principais do Chrome que usam perfil `scrapelens-chrome-*` (não Helpers)."""
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        if "scrapelens-chrome-" in line and "Helper" not in line and "Google Chrome" in line:
            found.append(line.strip()[:160])
    return found


def ordered_names_from_netlog(session_dir: pathlib.Path, path: str) -> list[list[str]]:
    """Nomes dos headers da requisição `GET <path>` no netlog.json, na ordem bruta.

    O evento de envio traz `"headers":["Host: ...", ...]` com a lista completa e
    na ordem de envio; é o array que começa em `Host:` mais próximo, antes da linha
    `"line":"GET <path> HTTP/1.1"`. Lido com o decodificador JSON (sem reconstruir
    o bloco por texto).
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
    all_outputs: list[str] = []  # tudo que o servidor MCP devolveu, para a varredura de segredos

    try:
        # ----- 1. positivo: elicitação aceita
        mcp = McpClient(binary, args, "accept")
        init = mcp.handshake()
        check("handshake", "result" in init and "serverInfo" in init["result"] or "result" in init,
              json.dumps(init)[:200])
        listed = mcp.request("tools/list", {})
        names = sorted(t["name"] for t in listed["result"]["tools"])
        summary["tools"] = names
        check("14 ferramentas anunciadas", len(names) == 14, f"{len(names)}: {names}")
        start_tool = next(t for t in listed["result"]["tools"] if t["name"] == "start_capture")
        check("start_capture sem parâmetro de confirmação",
              all("confirm" not in k for k in start_tool["inputSchema"]["properties"]))

        is_error, started = mcp.tool("start_capture", {
            "allowed_hosts": [host], "headless": True, "start_url": f"{base}/",
        }, timeout=240)
        all_outputs.append(json.dumps(started, ensure_ascii=False))
        check("start_capture aceito (elicitação)", not is_error, json.dumps(started)[:300])
        check("elicitação exibida ao usuário", len(mcp.elicitations) == 1, str(mcp.elicitations)[:200])
        capture_id = started.get("captureId", "")
        check("Chrome real iniciado", "Chrome" in str((started.get("browser") or {}).get("version", "")),
              json.dumps(started.get("browser"))[:200])

        # Fora da allowlist: não chega ao servidor.
        before = list(hits.paths())
        is_error, denied = mcp.tool("navigate", {
            "capture_id": capture_id, "url": f"http://127.0.0.1:{port}/fora",
        })
        all_outputs.append(json.dumps(denied, ensure_ascii=False))
        check("navigate fora da allowlist recusado",
              is_error and (denied.get("error") or {}).get("code") == "url_not_allowed",
              json.dumps(denied)[:200])
        time.sleep(0.5)
        check("navigate fora da allowlist não chegou ao servidor local",
              not any(p == "/fora" for p in hits.paths()[len(before):]),
              str(hits.paths()[len(before):]))

        # Navegação permitida, com token na query (não deve sair na saída).
        is_error, nav = mcp.tool("navigate", {
            "capture_id": capture_id, "url": f"{base}/page2?token={SECRET_TOKEN}", "timeout_ms": 30000,
        })
        all_outputs.append(json.dumps(nav, ensure_ascii=False))
        check("navigate permitido carregou", not is_error and nav.get("loaded") is True,
              json.dumps(nav)[:200])
        time.sleep(0.8)

        is_error, status = mcp.tool("capture_status", {"capture_id": capture_id})
        all_outputs.append(json.dumps(status, ensure_ascii=False))
        check("capture_status em gravação", status.get("recording") is True, json.dumps(status)[:200])

        is_error, stopped = mcp.tool("stop_capture", {"capture_id": capture_id})
        all_outputs.append(json.dumps(stopped, ensure_ascii=False))
        check("stop_capture gracioso", not is_error and stopped.get("graceful") is True,
              json.dumps(stopped)[:300])
        check("NetLog completo", stopped.get("netlog") == "complete", str(stopped.get("netlog")))
        session_id = stopped.get("sessionId", "")
        summary["sessionId"] = session_id

        is_error, listing = mcp.tool("list_requests", {"session_id": session_id, "host": host})
        all_outputs.append(json.dumps(listing, ensure_ascii=False))
        items = listing.get("items", [])
        check("list_requests devolve a sessão", not is_error and len(items) >= 2,
              f"total={listing.get('total')}")
        page2 = next((i for i in items if "/page2" in str(i.get("url", ""))), None)
        check("/page2 na sessão", page2 is not None, json.dumps(items)[:200])
        check("token da query fora da listagem",
              SECRET_TOKEN not in json.dumps(listing, ensure_ascii=False))

        # get_request + ordem dos headers.
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
        check("get_request devolve headers de requisição em ordem", len(names_mcp) >= 3,
              f"{len(names_mcp)} headers")
        server_seen = hits.last("/page2")
        seen_names = server_seen["headers"] if server_seen else []
        check("ordem dos headers = ordem recebida pelo servidor local",
              [n.lower() for n in names_mcp] == [n.lower() for n in seen_names],
              f"mcp={names_mcp} servidor={seen_names}")
        netlog_blocks = ordered_names_from_netlog(find_session_dir(sessions, session_id) or sessions, "/page2")
        mcp_lower = [n.lower() for n in names_mcp]
        netlog_match = any([n.lower() for n in block] == mcp_lower for block in netlog_blocks)
        if not netlog_blocks:
            check("ordem dos headers conferida contra o NetLog", False, "nenhum bloco GET /page2 no netlog")
        else:
            check("ordem dos headers do MCP = um bloco bruto do NetLog na mesma ordem", netlog_match,
                  f"blocos={[len(b) for b in netlog_blocks]} mcp={names_mcp}")
        netlog_names = netlog_blocks[-1] if netlog_blocks else None
        summary["header_order"] = names_mcp
        summary["netlog_header_order"] = netlog_names

        # Cookie: a requisição de /page2 carrega o cookie definido em /.
        check("cookie chegou ao servidor na segunda requisição",
              server_seen is not None and bool(server_seen.get("cookie")) and "sid=" in server_seen["cookie"])

        is_error, trace = mcp.tool("trace_value", {"session_id": session_id, "cookie": "sid"})
        all_outputs.append(json.dumps(trace, ensure_ascii=False))
        check("trace_value do cookie sem erro", not is_error, json.dumps(trace)[:200])
        check("trace_value do cookie mascarado", SECRET_COOKIE not in json.dumps(trace, ensure_ascii=False),
              json.dumps(trace)[:200])

        is_error, profile = mcp.tool("site_profile", {"session_id": session_id})
        all_outputs.append(json.dumps(profile, ensure_ascii=False))
        check("site_profile sem erro", not is_error, json.dumps(profile)[:200])

        # reveal sem --allow-reveal: recusado.
        is_error, rev = mcp.tool("get_request", {
            "session_id": session_id, "request_id": page2["requestId"], "reveal": True,
        })
        all_outputs.append(json.dumps(rev, ensure_ascii=False))
        check("reveal=true recusado sem --allow-reveal",
              is_error and "reveal" in json.dumps(rev).lower(), json.dumps(rev)[:200])

        code, stderr = mcp.close()
        check("servidor sai limpo no EOF", code == 0, f"rc={code}")
        all_outputs.extend(mcp.transcript)
        all_outputs.append(stderr)

        # ----- 2. negativo: elicitação recusada não abre Chrome
        before_procs = chrome_capture_processes()
        mcp2 = McpClient(binary, args, "decline")
        mcp2.handshake()
        is_error, refused = mcp2.tool("start_capture", {
            "allowed_hosts": [host], "headless": True, "start_url": f"{base}/",
        })
        all_outputs.append(json.dumps(refused, ensure_ascii=False))
        time.sleep(1.0)
        after_procs = chrome_capture_processes()
        check("elicitação recusada: start_capture falha", is_error, json.dumps(refused)[:200])
        check("elicitação recusada: nenhum Chrome da captura criado",
              len(after_procs) == len(before_procs),
              f"antes={len(before_procs)} depois={len(after_procs)}")
        check("elicitação recusada: pedido de confirmação foi feito", len(mcp2.elicitations) == 1)
        code2, stderr2 = mcp2.close()
        all_outputs.extend(mcp2.transcript)
        all_outputs.append(stderr2)

        # ----- 3. varredura: nenhum segredo em qualquer saída do servidor MCP
        leaks = []
        for index, chunk in enumerate(all_outputs):
            for secret in SECRETS:
                at = chunk.find(secret)
                if at >= 0:
                    leaks.append(f"saída[{index}] {secret}: ...{chunk[max(0, at - 90):at + len(secret) + 20]}...")
        check("nenhum valor de cookie/token na saída inteira do MCP (sem reveal)", not leaks,
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
        print(json.dumps({"ok": False, "error": f"binário ausente: {binary}"}))
        return 2
    summary = run(binary)
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
