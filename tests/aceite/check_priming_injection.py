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
import stat
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


def hostile_har(value_tag, newline_headers=False, bidi_header=False, sim=False):
    """E1 (produtor) traz os valores hostis em controle HTML, literal JS e textarea; E2 (consumidor) os reenvia em form."""
    v_ctrl, v_lit, v_area = HOSTILE(f"CTRL{value_tag}"), f"LIT{value_tag}-{PAYLOAD}-ABCDEFGH", HOSTILE(f"AREA{value_tag}")
    name = HOSTILE("HID").replace("\u0000", "")
    html_body = (f'<html><script>var tokenLit = "{v_lit}";</script>\n'
                 f'<input type="hidden" name="{name.replace(chr(34), "&quot;")}" value="{v_ctrl.replace(chr(34), "&quot;")}">\n'
                 f'<textarea name="AREA">{v_area}</textarea></html>\n')
    if sim:  # o detran-sim não devolve controles hostis: aqui os valores hostis são constantes do código gerado
        html_body = "<html><body>ok</body></html>\n"
    hv = HOSTILE("H").replace("\n", " ").replace("\u0000", "")
    hdrs = [("accept", "*/*"), ("x-inj", hv if bidi_header else hv.replace(NASTY, "")), ("x-" + "n" * 3, f"{PAYLOAD} \\")]
    if newline_headers:
        hdrs.append(("x-nl", f"a{NL}b\u0000c{PAYLOAD}"))
    page_url = f"{APP}/UIC-SERVICOS/VES0009X.html" if sim else f"{APP}/inj/page"   # rotas que o detran-sim conhece
    post_url = f"{APP}/servlet/Connector" if sim else f"{APP}/inj/post"
    e1 = entry(1, "GET", f"{page_url}?{urllib.parse.quote(HOSTILE('q'))}={urllib.parse.quote(PAYLOAD)}", 200, "text/html;charset=UTF-8", html_body, hdrs)
    form = [(name, v_ctrl), ("tokenLit", v_lit), ("AREA", v_area), (HOSTILE("n"), HOSTILE("v")), ("evil", PAYLOAD), ("plain", "ok")]
    e2 = entry(2, "POST", post_url, 200, "text/plain", "ok\n", hdrs[:2] + [("referer", page_url)], post=form)
    return {"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "1"}, "pages": [], "entries": [e1, e2]}}, v_ctrl, v_lit, v_area


TRACE_OS_CALLS = {"open", "fchmod", "write", "close"}


def static_checks(script: str, label: str):
    tree = ast.parse(script)
    imports = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imports |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            imports.add(n.module)
    allowed = {"argparse", "html.parser", "json", "re", "sys", "urllib.parse", "requests", "os", "base64", "datetime", "time", "hashlib"}
    check(imports <= allowed, f"{label}: imports inesperados {sorted(imports - allowed)}")
    check("subprocess" not in imports and "ctypes" not in imports, f"{label}: import de subprocess/ctypes")
    # escopo: cada nó sabe em que função (de nível mais externo) está; só `trace_*` pode usar `os`
    owner: dict[int, str | None] = {}

    def walk(node, fn):
        for ch in ast.iter_child_nodes(node):
            f = fn
            if fn is None and isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                f = ch.name
            owner[id(ch)] = f
            walk(ch, f)
    walk(tree, None)
    in_trace = lambda n: (owner.get(id(n)) or "").startswith("trace_")  # noqa: E731
    bad_calls = {"eval", "exec", "compile", "__import__", "system", "popen", "Popen", "run", "call", "spawn", "fork",
                 "execv", "setattr", "globals", "locals", "check_output", "check_call"}
    found, os_misuse, open_misuse = set(), [], []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")
            if name in bad_calls:
                found.add(name)
            if isinstance(n.func, ast.Name) and n.func.id == "open" and not in_trace(n):
                open_misuse.append("open()")
            if name == "getattr" and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == "os":
                # só constantes literais `O_*` (flags de abertura) dentro de trace_*; nome dinâmico é proibido
                lit = len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str) and n.args[1].value.startswith("O_")
                if not (lit and in_trace(n)):
                    found.add("getattr(os) dinâmico")
            if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "os":
                if not (in_trace(n) and n.func.attr in TRACE_OS_CALLS):
                    os_misuse.append(f"os.{n.func.attr}() em {owner.get(id(n)) or 'nível do módulo'}")
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os":
            if not in_trace(n):
                os_misuse.append(f"os.{n.attr} em {owner.get(id(n)) or 'nível do módulo'}")
            elif n.attr not in TRACE_OS_CALLS and not n.attr.startswith("O_"):
                os_misuse.append(f"os.{n.attr} em {owner.get(id(n))}")
        elif isinstance(n, ast.Name) and n.id == "os" and isinstance(n.ctx, ast.Load) and not in_trace(n):
            if not isinstance(owner.get(id(n)), str) or not owner[id(n)].startswith("trace_"):
                os_misuse.append(f"nome os em {owner.get(id(n)) or 'nível do módulo'}")
    os_misuse = sorted(set(os_misuse))
    check(not found, f"{label}: chamadas perigosas no código: {sorted(found)}")
    check(not os_misuse, f"{label}: uso de `os` fora de trace_* ou fora das permitidas: {os_misuse[:5]}")
    check(not open_misuse, f"{label}: open() builtin fora de trace_*")
    hl_misuse = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "hashlib":
            fn = owner.get(id(n)) or ""
            if not (fn.startswith("trace_") or "plan" in fn.lower()) or n.attr != "sha256":
                hl_misuse.append(f"hashlib.{n.attr} em {fn or 'nível do módulo'}")
        elif isinstance(n, ast.Attribute) and n.attr not in ("sha256", "hexdigest", "update") and False:
            pass
    check(not hl_misuse, f"{label}: uso de hashlib fora de trace_*/plano ou além de sha256: {sorted(set(hl_misuse))[:4]}")
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    check(not ({"__import__", "system", "subprocess"} & names), f"{label}: nomes perigosos no código: {sorted({'__import__', 'system', 'subprocess'} & names)}")
    leaked = [t.string for t in tokenize.generate_tokens(io.StringIO(script).readline)
              if t.type in (tokenize.NAME, tokenize.OP) and ("__import__" in t.string or "system" == t.string)]
    check(not leaked, f"{label}: payload virou código ({leaked[:3]})")
    check("\u0000" not in script, f"{label}: NUL cru no script")
    trace_fns = sorted({f for f in owner.values() if f and f.startswith("trace_")})
    check(bool(trace_fns), f"{label}: o script não tem funções trace_* (--trace ausente?)")
    return {"imports": sorted(imports), "dangerous_calls": sorted(found), "os_fora_de_trace": os_misuse,
            "trace_functions": trace_fns, "payload_in_strings_or_comments_only": not leaked}


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
    if isinstance(e.code, int) or e.code is None:
        rc = e.code or 0
    else:
        sys.stderr.write(str(e.code) + "\n"); rc = 1   # fail('...') do script sai com texto: preserva a mensagem
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


def execute(py, script, base, label, extra_args=(), trace_name=None, expect="completed", posts=None):
    """trace_name=None: 0 escritas permitidas. Com trace_name (relativo ao cwd): exatamente 1 arquivo criado, o do trace."""
    work = Path(tempfile.mkdtemp(prefix="sl-inj-run-")); os.chmod(work, 0o700)
    try:
        wrap = Path(tempfile.mkdtemp(prefix="sl-inj-wrap-")) / "wrap.py"; wrap.write_text(WRAP)
        before = sorted(os.listdir(work))
        posts_before = posts() if posts else 0
        targs = ["--trace", trace_name] if trace_name else []
        # entradas obrigatórias que o próprio script declara (F1: placa/sessionid-cliente; hostil: campos sem origem), com
        # valores sintéticos: sem isso o argparse sai antes de executar a cadeia e a prova seria vazia
        req = ps.required_params(py, script, work) or []
        synth = {"--placa": "TST0T10", "--sessionid-cliente": "_" + "0" * 12, "--cpf": ps.CPF}
        req_args = [x for n in req for x in (n, synth.get(n, "synthetic"))]
        p = subprocess.run([py, "-I", str(wrap), str(script), "--confirmar", "--base-url", base, *req_args, *extra_args, *targs],
                           capture_output=True, text=True, cwd=work, timeout=120,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})  # sem .pyc: qualquer escrita restante é do script
        m = re.search(r"AUDIT_JSON:(.*)", p.stderr)
        events = json.loads(m.group(1)) if m else [["sem-auditoria", p.stderr[-100:]]]
        after = sorted(os.listdir(work))
        marker = [str(x) for x in Path(work).rglob("*") if MARK in str(x)] + [str(x) for x in Path(tempfile.gettempdir()).glob(f"{MARK}*")] + list(Path(ROOT).glob(f"{MARK}*"))
        created = sorted(set(after) - set(before))
        info = {"rc": p.returncode, "files_created": created, "marker_files": marker,
                "stderr_last": " | ".join(p.stderr.split("AUDIT_JSON")[0].strip().splitlines()[-3:])[:300]}
        if trace_name:
            tr_writes = [e for e in events if e[0] == "open-write" and Path(str(e[1]).strip("'\"")).name == trace_name]
            forbidden = [e for e in events if e not in tr_writes and e[0] != "os.chmod"]
            check(len(tr_writes) == 1, f"{label}: esperada exatamente 1 abertura de escrita (o trace), houve {len(tr_writes)}")
            check(created == [trace_name], f"{label}: arquivos criados {created}, esperado só [{trace_name!r}]")
            tf = work / trace_name
            if tf.exists():
                mode = stat.S_IMODE(tf.stat().st_mode)
                check(mode == 0o600, f"{label}: trace com modo {oct(mode)}, esperado 0600")
                try:
                    tj = json.loads(tf.read_text())
                    ok_json = isinstance(tj, dict)
                    raw = tf.read_text()
                    info["trace"] = {"mode": oct(mode), "json_valid": ok_json, "schema": tj.get("schema") if ok_json else None,
                                     "steps": len(tj.get("steps", [])) if ok_json else None}
                    check(ok_json and tj.get("schema") == "scrapelens.trace/1", f"{label}: trace sem schema scrapelens.trace/1")
                    # dado, não código: o payload só pode estar dentro de strings JSON (json.loads fechou) e sem NUL cru
                    check("\u0000" not in raw, f"{label}: NUL cru no trace")
                except Exception as e:
                    info["trace"] = {"mode": oct(mode), "json_valid": False}
                    check(False, f"{label}: trace não é JSON válido: {str(e)[:80]}")
            else:
                check(False, f"{label}: trace não foi criado")
        else:
            forbidden = events
            check(created == [], f"{label}: arquivos criados sem --trace: {created}")
        # Prova não-vazia (Rodada 9, achado 10): a execução tem de ter RODADA. Ou completou (rc 0) com POSTs recebidos, ou
        # falhou de forma DECLARADA (mensagem `priming:` do próprio script, sem traceback/CRASH) — nunca um crash mudo.
        text_err = "\n".join(l for l in p.stderr.split("AUDIT_JSON")[0].splitlines() if "o trace contém dados da sua sessão" not in l)
        n_posts = (posts() if posts else 0) - posts_before
        crashed = "CRASH:" in text_err or "Traceback" in text_err
        declared = p.returncode != 0 and "priming:" in text_err and not crashed
        outcome = "completed" if p.returncode == 0 else ("declared-failure" if declared else "undeclared-failure")
        info.update({"outcome": outcome, "posts_received": n_posts, "expected": expect})
        if expect == "completed":
            check(p.returncode == 0 and n_posts > 0, f"{label}: esperado rc=0 com POSTs>0; rc={p.returncode}, POSTs={n_posts}, {outcome}: {text_err.strip()[-120:]!r}")
        else:  # "declared": falha esperada e declarada (rc!=0 + `priming:`); ou completou
            check(outcome in ("completed", "declared-failure"), f"{label}: falha não declarada (sem `priming:`): rc={p.returncode} {text_err.strip()[-140:]!r}")
            if outcome == "completed":
                check(n_posts > 0, f"{label}: completou mas 0 POSTs recebidos (execução vazia)")
        info["forbidden_events"] = forbidden
        check(not forbidden, f"{label}: eventos proibidos na execução: {forbidden[:4]}")
        check(not marker, f"{label}: marcador do payload criado: {marker}")
        check(not any(e[0] == "connect-external" for e in events), f"{label}: conexão fora de 127.0.0.1")
        return info, p
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
            # execução 1: servidor hostil que devolve valores NOVOS hostis; 2: detran-sim (HAR com as rotas do sim)
            fresh = hostile_har("B", False)[1:]
            Hostile.page = (f'<html><script>var tokenLit = "{fresh[1]}";</script>\n<input type="hidden" name="{HOSTILE("HID").replace(chr(34), "&quot;").replace(chr(0), "")}" value="{fresh[0].replace(chr(34), "&quot;")}">\n'
                            f'<textarea name="AREA">{fresh[2]}</textarea></html>\n')
            Hostile.seen.clear()
            hbase = f"http://127.0.0.1:{srv.server_address[1]}"
            hposts = lambda: len(Hostile.seen)  # noqa: E731
            # header fora de latin-1 (bidi): falha DECLARADA esperada; as demais variantes têm de completar no servidor hostil
            exp_h = "declared" if bidi else "completed"
            case["run_hostile_server"], _ = execute(py, script, hbase, f"{variant}/servidor-hostil", expect=exp_h, posts=hposts)
            n0 = len(Hostile.seen)
            case["run_hostile_server_trace"], _ = execute(py, script, hbase, f"{variant}/servidor-hostil+trace", trace_name="trace.json", expect=exp_h, posts=hposts)
            case["posts_received_by_hostile_server"] = len(Hostile.seen)
            case["fresh_value_used_not_captured"] = None
            if Hostile.seen:
                body = urllib.parse.unquote_plus(Hostile.seen[0])
                case["fresh_value_used_not_captured"] = ("CTRLB" in body) and ("CTRLA" not in body)
                check(case["fresh_value_used_not_captured"], f"{variant}: o POST não usou o valor NOVO (ou usou o capturado)")
            elif not bidi:
                check(False, f"{variant}: o servidor hostil não recebeu POST")
            # detran-sim: o HAR da variante usa GET /UIC-SERVICOS/VES0009X.html e POST /servlet/Connector (rotas reais do sim)
            sbase = f"http://127.0.0.1:{a.port}"
            sim_har, *_ = hostile_har("A", nlh, bidi, sim=True)
            hp2 = tmp / f"{variant}-sim.har"; hp2.write_text(json.dumps(sim_har, ensure_ascii=False))
            sess2 = tmp / f"s-{variant}-sim"
            subprocess.run([core, "import-har", hp2, "--out", sess2, "--label", "synthetic-fixture"], capture_output=True, check=True)
            ids2 = [x["id"] for x in json.loads((sess2 / "session.json").read_text())["requests"]]
            script2 = tmp / f"{variant}-sim.py"
            g2 = subprocess.run([core, "export-priming", sess2, ids2[-1], "--out", script2], capture_output=True, text=True)
            check(g2.returncode == 0, f"{variant}/sim: export-priming falhou: {g2.stderr[:150]}")
            if g2.returncode == 0:
                case["static_sim"] = static_checks(script2.read_text(), variant + "/sim")
                sposts = lambda: sum(1 for x in ps.http(sbase, "/__sim/log")["log"] if x["method"] == "POST")  # noqa: E731
                ps.http(sbase, "/__sim/reset")
                case["run_detran_sim"], _ = execute(py, script2, sbase, f"{variant}/detran-sim", expect="declared", posts=sposts)
                ps.http(sbase, "/__sim/reset")
                case["run_detran_sim_trace"], _ = execute(py, script2, sbase, f"{variant}/detran-sim+trace", trace_name="trace.json", expect="declared", posts=sposts)
            case["placar"] = {k: (v["outcome"], v["posts_received"]) for k, v in case.items() if k.startswith("run_") and isinstance(v, dict) and "outcome" in v}
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
