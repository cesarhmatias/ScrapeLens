#!/usr/bin/env python3
"""Simulador LOCAL e FICTÍCIO do fluxo DETRAN-PB (forma real) para validar o script de priming.

Só biblioteca padrão; escuta APENAS em 127.0.0.1 (padrão 8791). Sem rede externa, sem telemetria.
Cada GET em /servlet/easynat-app abre uma sessão NOVA (SESSIONID-prefixo, processId, STAMP, delta novos);
valores capturados em outra sessão são rejeitados (ERRORMESSAGE), então só vale quem extrai da resposta.
Modos (global; `--mode` ou GET /__sim/mode?m=...): ok | error | nocontrols | 403.
Documentação das rotas: testserver/detran-sim/README.md.
"""
from __future__ import annotations

import argparse
import html
import json
import random
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "fixtures" / "detran-pb"))
sys.path.insert(0, str(ROOT / "fixtures" / "detran-pb-real-shape"))
import build_fixtures as bf  # noqa: E402  (response_stream, jslen)
import build_real_shape as brs  # noqa: E402  (connector_html, page_html, frame html)

PREFIX = "/detran-portal-servicos"
MODES = ("ok", "error", "nocontrols", "403")
MODELS = brs.MODELS
LOCK = threading.RLock()
STATE = {"mode": "ok", "sessions": {}, "log": [], "rng": random.Random()}
PAGES = {"/cisnatural/NatLogon.html": ("NatLogon", "logon"), "/UIC-SERVICOS/SIM1000X.html": ("SIM1000X", "sim"),
         "/UIC-SERVICOS/VES0009X.html": ("VES0009X", "ves")}


def new_session() -> dict:
    r = STATE["rng"]
    head = f"CSAN{r.randrange(10**5):05d}"
    s = {"head": head, "pid": "SYNTHPID" + "".join(r.choice("0123456789ABCDEF") for _ in range(24)),
         "stamp": None, "delta": "inittini", "n": r.randrange(1000, 9000), "dp": "D" + "".join(r.choice("ABCDEFGH") for _ in range(3)),
         "dn": 0, "created": time.time()}
    STATE["sessions"][head] = s
    return s


def parse_request_xml(xml: str) -> dict | None:
    """Inverso do bf.serialize: kind, partes, props e delta."""
    widths = [2, 2, 2, 2, 2, 3, 5, 1]
    if not xml or xml[0] not in "iv" or not xml[1:1 + sum(widths)].isdigit():
        return None
    pos, lens = 1, []
    for w in widths:
        lens.append(int(xml[pos:pos + w])); pos += w
    parts = []
    for n in lens:
        parts.append(xml[pos:pos + n]); pos += n
    props = {}
    while pos < len(xml) and xml[pos] == "p":
        nl, vl = int(xml[pos + 1:pos + 3]), int(xml[pos + 3:pos + 8]); pos += 8
        name = xml[pos:pos + nl]; pos += nl
        props[name] = xml[pos:pos + vl]; pos += vl
    if pos >= len(xml) or xml[pos] != "x":
        return None
    dl = int(xml[pos + 1:pos + 3])
    return {"init": xml[0] == "i", "sid": parts[0], "pid": parts[1], "model": parts[3], "page": parts[5],
            "event": parts[6], "props": props, "delta": xml[pos + 3:pos + 3 + dl]}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "scrapelens-detran-sim"

    def log_message(self, *a):
        pass

    def _send(self, status, body: str, ctype="text/html;charset=UTF-8", extra=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _rec(self, path, status, note):
        with LOCK:
            STATE["log"].append({"t": round(time.time(), 3), "method": self.command, "path": path, "status": status,
                                 "mode": STATE["mode"], "note": note})

    def _path(self):
        u = urlsplit(self.path)
        p = u.path[len(PREFIX):] if u.path.startswith(PREFIX) else u.path
        return p, dict(parse_qsl(u.query))

    def do_GET(self):
        p, q = self._path()
        if p == "/healthz":
            return self._send(200, "ok\n", "text/plain")
        if p == "/__sim/mode":
            with LOCK:
                if q.get("m") in MODES:
                    STATE["mode"] = q["m"]
                return self._send(200, json.dumps({"mode": STATE["mode"], "modes": MODES}), "application/json")
        if p == "/__sim/log":
            with LOCK:
                return self._send(200, json.dumps({"log": STATE["log"], "sessions": len(STATE["sessions"])}), "application/json")
        if p == "/__sim/reset":
            with LOCK:
                STATE["log"].clear(); STATE["sessions"].clear(); STATE["mode"] = "ok"
            return self._send(200, "{}", "application/json")
        if p == "/servlet/easynat-app":
            with LOCK:
                s = new_session()
            page = brs.page_html("DETRAN-PB", MODELS["logon"], s["head"], s["pid"], "op=S37&xciParameters.natsession=acesso")
            self._rec(p, 200, "sessão nova " + s["head"][:4] + "…")
            return self._send(200, page)
        if p in PAGES:
            title, key = PAGES[p]
            self._rec(p, 200, "página")
            return self._send(200, brs.page_html(title, MODELS[key], None, None))
        m = re.fullmatch(r"/(cisnatural|UIC-SERVICOS)/(\w+)_JLIBS\.html", p)
        if m:
            self._rec(p, 200, "frame")
            return self._send(200, brs.jlibs_html(m.group(2)))
        if re.fullmatch(r"/(cisnatural|UIC-SERVICOS)/cscform\.html", p):
            self._rec(p, 200, "frame cscform (STAMP=INIT)")
            return self._send(200, brs.csc_html(MODELS.get({"NatLogon": "logon", "SIM1000X": "sim", "VES0009X": "ves"}.get(q.get("page", ""), "logon"))))
        if p.endswith("/aboutBlank.html"):
            return self._send(200, "<!doctype html><html><body></body></html>\n")
        if p.startswith("/TSPD/"):
            self._rec(p, 200, "ruído de proteção sintético")
            return self._send(200, "/* synthetic guard noise */\n", "text/javascript")
        if p.endswith(".js"):
            return self._send(200, brs.static_js(p.rsplit("/", 1)[-1]), "application/javascript")
        self._rec(p, 404, "rota desconhecida")
        self._send(404, "not found\n", "text/plain")

    def do_POST(self):
        p, _ = self._path()
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        if p != "/servlet/Connector":
            self._rec(p, 404, "rota desconhecida")
            return self._send(404, "not found\n", "text/plain")
        form = dict(parse_qsl(raw, keep_blank_values=True))
        with LOCK:
            mode = STATE["mode"]
            if mode == "403":
                self._rec(p, 403, "modo 403")
                return self._send(403, "<html><body><h1>403</h1><p>Request blocked (synthetic protection page)</p></body></html>\n")
            sid, head = form.get("SESSIONID", ""), form.get("SESSIONID", "").split("_")[0]
            s = STATE["sessions"].get(head)
            req = parse_request_xml(form.get("XML", ""))
            if mode == "nocontrols":
                self._rec(p, 200, "modo nocontrols: 200 sem XML/STAMP")
                return self._send(200, "<html><body><h1>Servico indisponivel</h1><p>tente novamente (sintético)</p></body></html>\n")
            problems = []
            if s is None:
                problems.append("sessão desconhecida (SESSIONID de outra sessão)")
            elif not re.fullmatch(r"\d{12}", sid.partition("_")[2]):
                problems.append("SESSIONID sem o sufixo montado no cliente (12 dígitos)")
            if req is None:
                problems.append("XML ilegível")
            if s and req:
                if req["pid"] != s["pid"]:
                    problems.append("processId diferente")
                expected = "INIT" if req["init"] else s["stamp"]
                if form.get("STAMP") != expected:
                    problems.append("STAMP inválido")
                if req["delta"] != s["delta"]:
                    problems.append("delta inválido")
            if problems or mode == "error" and req and req["event"] == "cmd_consultar_placa":
                msg = "; ".join(problems) or "Placa não encontrada (modo error, sintético)"
                xml = bf.response_stream([("nextPage", PAGES_NEXT.get(req["page"] if req else "", "/UIC-SERVICOS/VES0009X.html"))],
                                         s["delta"] if s else "inittini")
                stamp = (s["stamp"] or "INIT") if s else "INIT"
                body = brs.connector_html(1, xml, stamp).replace('<textarea id="ERRORMESSAGE" name="ERRORMESSAGE"></textarea>',
                                                                  f'<textarea id="ERRORMESSAGE" name="ERRORMESSAGE">{html.escape(msg)}</textarea>')
                self._rec(p, 200, "app-error: " + msg)
                return self._send(200, body)
            r = STATE["rng"]
            s["n"] += r.randrange(1, 9)
            s["dn"] += 1
            s["stamp"], s["delta"] = str(s["n"]), f"{s['dp']}{s['dn']:04d}{r.randrange(10**4):04d}"
            fields = [("nextPage", PAGES_NEXT.get(req["page"], "/UIC-SERVICOS/VES0009X.html"))]
            if req["event"] == "cmd_consultar_placa":
                fields = [("v_placa", req["props"].get("v_placa", "")), ("v_cpf", req["props"].get("v_cpf", "")),
                          ("v_situacao_atual", "Apreendido & Liberado <ok>"), ("vp_situacao_atual", "true"), ("v_tmp", "x")]
            xml = bf.response_stream(fields, s["delta"])
            self._rec(p, 200, f"ok evento={req['event'] or 'init'}")
            return self._send(200, brs.connector_html(s["n"], xml, s["stamp"]))


PAGES_NEXT = {"/cisnatural/NatLogon.html": "/UIC-SERVICOS/SIM1000X.html", "/UIC-SERVICOS/SIM1000X.html": "/UIC-SERVICOS/VES0009X.html",
              "/UIC-SERVICOS/VES0009X.html": "/UIC-SERVICOS/VES0009X.html"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--mode", choices=MODES, default="ok")
    ap.add_argument("--seed", type=int, help="semente (reprodutível); padrão: aleatório por execução")
    a = ap.parse_args()
    STATE["mode"] = a.mode
    if a.seed is not None:
        STATE["rng"] = random.Random(a.seed)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"detran-sim em http://127.0.0.1:{a.port}{PREFIX}/ (modo {a.mode}); Ctrl-C para sair", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
