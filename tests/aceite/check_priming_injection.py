#!/usr/bin/env python3
"""Rodada 7, Aceite 4: INJEÇÃO. Sessão sintética hostil -> script de priming -> prova de que nada além de
requisições HTTP a 127.0.0.1 é executado.

  python3 tests/aceite/check_priming_injection.py [--core BIN] [--python PY_COM_REQUESTS]

Um HAR sintético hostil (nomes e valores com newline, aspas triplas, `\\` no fim, bidi, NUL e
`__import__('os').system(...)` em query, headers, campos de form, controles HTML e valores extraídos) é importado, o script é
gerado e:
  1. ast: só os imports esperados; nenhuma chamada/nome perigoso fora do modelo; o texto do payload só existe dentro de
     literais de string ou comentários (tokenize); o código não tem NAME `__import__`/`system`;
  2. execução (python -I, cwd = diretório temporário vazio, sob um gancho de auditoria `sys.addaudithook`) contra um servidor
     local hostil e contra o detran-sim: nenhum processo filho (subprocess/os.system/exec/fork/spawn), nenhuma escrita em
     disco, nenhuma conexão fora de 127.0.0.1, nenhum arquivo novo no diretório, marcador do payload ausente.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tokenize
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402
import check_priming_sim as ps  # noqa: E402

ROOT = cb.ROOT
OUT = ROOT / "tests" / "results" / "priming" / "aceite4-injecao.json"
APP = "https://wsdetran.pb.gov.br/detran-portal-servicos"
FAILS: list[str] = []
MARK = "PWNED_MARKER_7f3a"
PAYLOAD = f"__import__('os').system('touch {MARK}')"
NASTY = "‮⁦"  # bidi (RLO, LRI)
HOSTILE = lambda tag: f"{tag}'''\"\"\"\\n{PAYLOAD}\\\u0000{NASTY}end\\"  # noqa: E731  (contém \\n literal, NUL, bidi, \ no fim)
NL = "\n"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def entry(t, method, url, status, mime, body, headers, post=None):
    req = {"method": method, "url": url, "httpVersion": "http/1.1", "headers": [{"name": k, "value": v} for k, v in headers],
           "queryString": [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True)],
           "cookies": [], "headersSize": -1, "bodySize": 0}
    if post is not None:
        text = urllib.parse.urlencode(post)
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": text, "params": [{"name": k, "value": v} for k, v in post]}
        req["headers"].append({"name": "content-type", "value": "application/x-www-form-urlencoded"})
        req["bodySize"] = len(text)
    return {"startedDateTime": f"2026-10-27T23:00:0{t}.000Z", "time": 50.0, "request": req,
            "response": {"status": status, "statusText": "OK", "httpVersion": "http/1.1", "headers": [{"name": "content-type", "value": mime}],
                         "cookies": [], "content": {"size": len(body.encode()), "mimeType": mime, "text": body}, "redirectURL": "", "headersSize": -1, "bodySize": len(body.encode())},
            "cache": {}, "timings": {"send": 1, "wait": 40, "receive": 9}, "_resourceType": "document"}


def hostile_har(value_tag, newline_headers=False, bidi_header=False):
    """E1 (produtor) traz os valores hostis em controle HTML, literal JS e textarea; E2 (consumidor) os reenvia em form."""
    v_ctrl, v_lit, v_area = HOSTILE(f"CTRL{value_tag}"), f"LIT{value_tag}-{PAYLOAD}-ABCDEFGH", HOSTILE(f"AREA{value_tag}")
    name = HOSTILE("HID").replace("\u0000", "")
    html_body = (f'<html><script>var tokenLit = "{v_lit}";</script>\n'
                 f'<input type="hidden" name="{name.replace(chr(34), "&quot;")}" value="{v_ctrl.replace(chr(34), "&quot;")}">\n'
                 f'<textarea name="AREA">{v_area}</textarea></html>\n')
    hv = HOSTILE("H").replace("\n", " ").replace("\u0000", "")
    hdrs = [("accept", "*/*"), ("x-inj", hv if bidi_header else hv.replace(NASTY, "")), ("x-" + "n" * 3, f"{PAYLOAD} \\")]
    if newline_headers:
        hdrs.append(("x-nl", f"a{NL}b\u0000c{PAYLOAD}"))
    e1 = entry(1, "GET", f"{APP}/inj/page?{urllib.parse.quote(HOSTILE('q'))}={urllib.parse.quote(PAYLOAD)}", 200, "text/html;charset=UTF-8", html_body, hdrs)
    form = [(name, v_ctrl), ("tokenLit", v_lit), ("AREA", v_area), (HOSTILE("n"), HOSTILE("v")), ("evil", PAYLOAD), ("plain", "ok")]
    e2 = entry(2, "POST", f"{APP}/inj/post", 200, "text/plain", "ok\n", hdrs[:2] + [("referer", f"{APP}/inj/page")], post=form)
    return {"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "1"}, "pages": [], "entries": [e1, e2]}}, v_ctrl, v_lit, v_area


def static_checks(script: str, label: str):
    tree = ast.parse(script)
    imports = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imports |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            imports.add(n.module)
    allowed = {"argparse", "html.parser", "json", "re", "sys", "urllib.parse", "requests"}
    check(imports <= allowed, f"{label}: imports inesperados {sorted(imports - allowed)}")
    bad_calls = {"eval", "exec", "compile", "__import__", "open", "system", "popen", "Popen", "run", "call", "spawn", "fork", "execv", "setattr", "globals", "locals"}
    found = sorted({(n.func.id if isinstance(n.func, ast.Name) else n.func.attr) for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")) in bad_calls})
    check(not found, f"{label}: chamadas perigosas no código: {found}")
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    check(not ({"__import__", "system", "os", "subprocess"} & names), f"{label}: nomes perigosos no código: {sorted({'__import__', 'system', 'os', 'subprocess'} & names)}")
    # o texto do payload só existe em strings/comentários (tokenize): nenhum token NAME/OP o contém
    leaked = [t.string for t in tokenize.generate_tokens(io.StringIO(script).readline)
              if t.type in (tokenize.NAME, tokenize.OP) and ("__import__" in t.string or "system" == t.string)]
    check(not leaked, f"{label}: payload virou código ({leaked[:3]})")
    # comentários nunca podem conter quebra de linha crua do dado (cada linha do script começa como código ou '#')
    check("\u0000" not in script, f"{label}: NUL cru no script")
    return {"imports": sorted(imports), "dangerous_calls": found, "payload_in_strings_or_comments_only": not leaked}


WRAP = r'''
import sys, runpy, json, os
EV = []
def hook(ev, args):
    try:
        if ev in ("subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn", "ctypes.dlopen", "ctypes.cdll.LoadLibrary"):
            EV.append([ev, repr(args)[:80]])
        elif ev == "open":
            path, mode, flags = args
            m = mode or ""
            if any(c in m for c in "wax+") or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)):
                EV.append(["open-write", repr(path)[:80]])
        elif ev in ("os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.symlink", "os.chmod", "shutil.copyfile", "os.truncate"):
            EV.append([ev, repr(args)[:80]])
        elif ev == "socket.connect":
            host = args[1][0] if isinstance(args[1], tuple) else str(args[1])
            if host not in ("127.0.0.1", "::1"):
                EV.append(["connect-external", repr(host)])
    except Exception as e:
        EV.append(["hook-error", repr(e)])
sys.addaudithook(hook)
script = sys.argv[1]; sys.argv = [script] + sys.argv[2:]
rc = 0
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit as e:
    rc = e.code if isinstance(e.code, int) else 1
except BaseException as e:
    sys.stderr.write("CRASH: %s: %s\n" % (type(e).__name__, str(e)[:120])); rc = 1
sys.stderr.write("\nAUDIT_JSON:" + json.dumps(EV) + "\n")
sys.exit(rc)
'''


class Hostile(BaseHTTPRequestHandler):
    page = ""
    seen: list = []

    def log_message(self, *a): pass

    def do_GET(self):
        d = self.page.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html;charset=UTF-8"); self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        Hostile.seen.append(self.rfile.read(n).decode("utf-8", "replace"))
        self.send_response(200); self.send_header("Content-Length", "3"); self.end_headers(); self.wfile.write(b"ok\n")


def execute(py, script, base, label, extra_args=()):
    work = Path(tempfile.mkdtemp(prefix="sl-inj-run-")); os.chmod(work, 0o700)
    try:
        wrap = Path(tempfile.mkdtemp(prefix="sl-inj-wrap-")) / "wrap.py"; wrap.write_text(WRAP)
        before = sorted(os.listdir(work))
        p = subprocess.run([py, "-I", str(wrap), str(script), "--confirmar", "--base-url", base, *extra_args],
                           capture_output=True, text=True, cwd=work, timeout=120,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})  # sem .pyc: qualquer escrita restante é do script
        m = re.search(r"AUDIT_JSON:(.*)", p.stderr)
        events = json.loads(m.group(1)) if m else [["sem-auditoria", p.stderr[-100:]]]
        # eventos de escrita em arquivo do próprio interpretador (ex.: __pycache__/.pyc) não existem com -I e sem import local
        after = sorted(os.listdir(work))
        marker = [str(x) for x in Path(work).rglob("*") if MARK in str(x)] + [str(x) for x in Path(tempfile.gettempdir()).glob(f"{MARK}*")] + list(Path(ROOT).glob(f"{MARK}*"))
        check(not events, f"{label}: eventos proibidos na execução: {events[:4]}")
        check(before == after, f"{label}: arquivos criados no diretório de execução: {sorted(set(after) - set(before))}")
        check(not marker, f"{label}: marcador do payload criado: {marker}")
        return {"rc": p.returncode, "forbidden_events": events, "files_created": sorted(set(after) - set(before)), "marker_files": marker,
                "stderr_last": (p.stderr.split("AUDIT_JSON")[0].strip().splitlines() or [""])[-1][:160]}, p
    finally:
        shutil.rmtree(work, ignore_errors=True); shutil.rmtree(wrap.parent, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8791)
    a = ap.parse_args()
    core, py = cb.core_bin(a.core), a.python or ps.default_python()
    tmp = Path(tempfile.mkdtemp(prefix="sl-inj-")); os.chmod(tmp, 0o700)
    res = {"payload": "__import__('os').system('touch <marcador>') + newline/aspas triplas/barra final/bidi/NUL", "cases": {}}
    sim = subprocess.Popen([sys.executable, str(ps.SIM), "--port", str(a.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv = HTTPServer(("127.0.0.1", 0), Hostile)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for variant, nlh, bidi in (("headers-latin1-hostis", False, False), ("headers-com-newline-e-NUL", True, False), ("headers-com-bidi", False, True)):
            har, v_ctrl, v_lit, v_area = hostile_har("A", nlh, bidi)
            hp = tmp / f"{variant}.har"; hp.write_text(json.dumps(har, ensure_ascii=False))
            sess = tmp / f"s-{variant}"
            r = subprocess.run([core, "import-har", hp, "--out", sess, "--label", "synthetic-fixture"], capture_output=True, text=True)
            check(r.returncode == 0, f"{variant}: import falhou: {r.stderr[:150]}")
            if r.returncode:
                continue
            ids = [x["id"] for x in json.loads((sess / "session.json").read_text())["requests"]]
            script = tmp / f"{variant}.py"
            g = subprocess.run([core, "export-priming", sess, ids[-1], "--out", script], capture_output=True, text=True)
            check(g.returncode == 0, f"{variant}: export-priming falhou: {g.stderr[:150]}")
            if g.returncode:
                continue
            text = script.read_text()
            case = {"script_bytes": len(text), "static": static_checks(text, variant)}
            # linhas do script: nenhuma linha começa com o payload solto (quebra de linha injetada)
            stray = [l for l in text.splitlines() if l.strip().startswith(("__import__", MARK))]
            check(not stray, f"{variant}: linha solta do payload no script ({len(stray)})")
            case["stray_payload_lines"] = len(stray)
            # execução 1: servidor hostil que devolve valores NOVOS hostis; 2: detran-sim
            fresh = hostile_har("B", False)[1:]
            Hostile.page = (f'<html><script>var tokenLit = "{fresh[1]}";</script>\n<input type="hidden" name="{HOSTILE("HID").replace(chr(34), "&quot;").replace(chr(0), "")}" value="{fresh[0].replace(chr(34), "&quot;")}">\n'
                            f'<textarea name="AREA">{fresh[2]}</textarea></html>\n')
            Hostile.seen.clear()
            case["run_hostile_server"], _ = execute(py, script, f"http://127.0.0.1:{srv.server_address[1]}", f"{variant}/servidor-hostil")
            case["posts_received_by_hostile_server"] = len(Hostile.seen)
            case["fresh_value_used_not_captured"] = None
            if Hostile.seen:
                body = Hostile.seen[0]
                case["fresh_value_used_not_captured"] = ("CTRLB" in urllib.parse.unquote_plus(body)) and ("CTRLA" not in urllib.parse.unquote_plus(body))
            ps.http(f"http://127.0.0.1:{a.port}", "/__sim/reset")
            case["run_detran_sim"], _ = execute(py, script, f"http://127.0.0.1:{a.port}", f"{variant}/detran-sim")
            res["cases"][variant] = case
    finally:
        sim.terminate(); srv.shutdown(); shutil.rmtree(tmp, ignore_errors=True)
    res["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f[:300]) for f in FAILS]; return 1
    print("OK: injeção — ast limpo, nada executado além de HTTP a 127.0.0.1 (sem filhos, sem escrita, sem marcador)"); return 0


if __name__ == "__main__":
    sys.exit(main())
