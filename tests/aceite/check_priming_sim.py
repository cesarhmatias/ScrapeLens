#!/usr/bin/env python3
"""Rodada 7, Aceite 2: o script de priming (real-shape 1 rodada) RODADO POR ESTE TESTE contra o detran-sim
(127.0.0.1, sem rede externa). Quem executa é o teste, nunca o ScrapeLens.

  python3 tests/aceite/check_priming_sim.py [--core BIN] [--python PY_COM_REQUESTS] [--port 8791]

O interpretador do script precisa de `requests` (ex.: python3 -m venv /tmp/v && /tmp/v/bin/pip install requests).
Cenários: ok (cadeia completa; 2 execuções com sessões diferentes; valores capturados rejeitados pelo simulador),
error / nocontrols / 403 (o script deve falhar com mensagem clara e NÃO seguir adiante: a execução termina no
próprio passo que recebeu a resposta ruim). Resultado em tests/results/priming/aceite2-sim.json.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402

ROOT = cb.ROOT
SIM = ROOT / "testserver" / "detran-sim" / "detran_sim.py"
HAR = ROOT / "fixtures" / "detran-pb-real-shape" / "real-shape-1round.har"
OUT = ROOT / "tests" / "results" / "priming" / "aceite2-sim.json"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def default_python():
    for c in ("/tmp/sl-venv-req/bin/python", sys.executable):
        if subprocess.run([c, "-c", "import requests"], capture_output=True).returncode == 0:
            return c
    sys.exit("nenhum python com `requests`; passe --python (python3 -m venv /tmp/v && /tmp/v/bin/pip install requests)")


def http(base, path):
    return json.load(urllib.request.urlopen(base + path, timeout=5))


def run_script(py, script, base, cwd, extra=()):
    p = subprocess.run([py, "-I", str(script), "--confirmar", "--base-url", base, "--placa", "TST0T10", "--cpf", "00000000191", *extra],
                       capture_output=True, text=True, timeout=120, cwd=cwd)
    return p


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8791)
    a = ap.parse_args()
    core, py = cb.core_bin(a.core), a.python or default_python()
    base = f"http://127.0.0.1:{a.port}"
    tmp = Path(tempfile.mkdtemp(prefix="sl-prime-sim-")); os.chmod(tmp, 0o700)
    sim = subprocess.Popen([sys.executable, str(SIM), "--port", str(a.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {"base": base, "scenarios": {}}
    try:
        for _ in range(60):
            try:
                http(base, "/healthz"); break
            except Exception:
                time.sleep(0.1)
        sess = tmp / "sess"
        subprocess.run([core, "import-har", HAR, "--out", sess, "--label", "synthetic-fixture"], check=True, capture_output=True)
        man = json.loads((ROOT / "fixtures" / "detran-pb-real-shape" / "manifest.json").read_text())
        target = man["expectations"]["aceite_1_origins_chain"]["A"]["target"]
        script = tmp / "priming.py"
        g = subprocess.run([core, "export-priming", sess, target, "--out", script], capture_output=True, text=True)
        check(g.returncode == 0, f"export-priming falhou: {g.stderr[:150]}")
        plan = subprocess.run([py, "-I", str(script)], capture_output=True, text=True, cwd=tmp)
        n_plan = sum(1 for l in plan.stdout.splitlines() if l.lstrip()[:1].isdigit() and ". " in l[:6])
        check(plan.returncode == 0 and "Nada foi enviado" in plan.stdout, "modo plano deveria sair 0 e não enviar")
        check(http(base, "/__sim/log")["log"] == [], "modo plano não pode tocar o simulador")
        res["plan_steps"] = n_plan

        def scenario(mode):
            http(base, "/__sim/reset"); http(base, f"/__sim/mode?m={mode}")
            p = run_script(py, script, base, tmp)
            log = http(base, "/__sim/log")
            return p, log["log"], log["sessions"]

        # ok: 2 execuções, sessões novas, cadeia completa
        for n in (1, 2):
            p, log, sessions = scenario("ok")
            conn = [x for x in log if x["path"].endswith("/servlet/Connector")]
            notes = [x["note"] for x in conn]
            res["scenarios"][f"ok#{n}"] = {"rc": p.returncode, "requests": len(log), "connector_posts": len(conn), "sim_sessions": sessions,
                                           "events": notes}
            check(p.returncode == 0, f"ok#{n}: rc={p.returncode}: {p.stderr[-160:]}")
            check(len(log) == n_plan and len(conn) == 6 and all(x["status"] == 200 for x in log), f"ok#{n}: {len(log)} requisições / {len(conn)} POSTs (esperado {n_plan}/6, todas 200)")
            check(all(x["note"].startswith("ok") for x in conn), f"ok#{n}: o simulador registrou erro de aplicação: {notes}")
            check("Cadeia concluída" in p.stdout, f"ok#{n}: sem 'Cadeia concluída'")
        # controle negativo: replay cego com valores CAPTURADOS (HAR) deve ser rejeitado pelo simulador
        http(base, "/__sim/reset")
        cap = json.loads(HAR.read_text())
        import urllib.parse
        post = next(e for e in cap["log"]["entries"] if e["request"]["method"] == "POST")
        r = urllib.request.Request(base + "/detran-portal-servicos/servlet/Connector", data=post["request"]["postData"]["text"].encode(),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = urllib.request.urlopen(r, timeout=5).read().decode()
        check("sessão desconhecida" in body, "controle negativo: o simulador deveria rejeitar o POST capturado")
        res["negative_control_captured_post_rejected"] = "sessão desconhecida" in body

        expect = {"error": ("ERRORMESSAGE", None), "nocontrols": ("controle HTML", 4), "403": ("403", 4)}
        for mode, (word, stop_after) in expect.items():
            p, log, _ = scenario(mode)
            first_bad = next((i for i, x in enumerate(log, 1) if x["path"].endswith("/servlet/Connector") and (x["status"] != 200 or x["note"].startswith(("modo", "app-error")))), None)
            ran = len(log)
            res["scenarios"][mode] = {"rc": p.returncode, "requests_sent": ran, "first_bad_response_at_request": first_bad,
                                      "stopped_at_bad_step": ran == first_bad if first_bad else None,
                                      "message": (p.stderr.strip().splitlines() or [""])[-1][:140]}
            check(p.returncode != 0, f"{mode}: o script deveria falhar (rc={p.returncode})")
            check(p.stderr.strip().startswith("priming:") or "priming:" in p.stderr, f"{mode}: sem mensagem clara (`priming: ...`)")
            if mode == "error":
                check("ERRORMESSAGE" in p.stderr, f"{mode}: mensagem deveria citar ERRORMESSAGE: {p.stderr[-120:]}")
            check(first_bad is not None and ran == first_bad,
                  f"{mode}: o script NÃO parou na resposta ruim: ruim no pedido #{first_bad}, enviou {ran} pedidos (não pode seguir adiante)")
    finally:
        sim.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    res["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: priming × detran-sim — cadeia completa (2 sessões) e falha clara/imediata em error, nocontrols e 403"); return 0


if __name__ == "__main__":
    sys.exit(main())
