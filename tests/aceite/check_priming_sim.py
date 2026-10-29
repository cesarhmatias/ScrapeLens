#!/usr/bin/env python3
"""Rodada 7, Aceite 2: o script de priming (real-shape 1 rodada) RODADO POR ESTE TESTE contra o detran-sim
(127.0.0.1, sem rede externa). Quem executa é o teste, nunca o ScrapeLens.

  python3 tests/aceite/check_priming_sim.py [--core BIN] [--python PY_COM_REQUESTS] [--port 8791]

O interpretador do script precisa de `requests` (ex.: python3 -m venv /tmp/v && /tmp/v/bin/pip install requests).
Entradas do operador (F1, 48b3cdb): o script exige a placa e a parte do SESSIONID montada no cliente (`_` + 12
dígitos, formato que o detran-sim valida). Este check passa uma placa sintética e GERA essa parte a cada execução,
como o navegador faria, nunca um valor capturado do HAR; qualquer outra entrada obrigatória faz o check falhar
com mensagem clara.
Cenários: ok (cadeia completa; 2 execuções com sessões diferentes; valores capturados rejeitados pelo simulador),
error / nocontrols / 403 (o script deve falhar com mensagem clara e NÃO seguir adiante: a execução termina no
próprio passo que recebeu a resposta ruim). Resultado em tests/results/priming/aceite2-sim.json.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402

ROOT = cb.ROOT
SIM = ROOT / "testserver" / "detran-sim" / "detran_sim.py"
HAR = ROOT / "fixtures" / "detran-pb-real-shape" / "real-shape-1round.har"
OUT = ROOT / "tests" / "results" / "priming" / "aceite2-sim.json"
PLACA = "TST0T10"      # sintética
CPF = "00000000191"    # sintético
# Entradas do operador que o script pode exigir (F1): placa e a parte do SESSIONID montada no cliente.
# Critério do líder (Rodada 7, F1): qualquer outra entrada obrigatória — inclusive --op/--page, que são
# navegação derivável do próprio fluxo — faz o check falhar com mensagem clara. Não se passa valor do HAR
# para contornar: isso esconderia o defeito do gerador.
ALLOWED_REQUIRED = {"--placa", "--cpf", "--sessionid-cliente"}
# O detran-sim valida o formato: prefixo do easynat-app + "_" + 12 dígitos montados no cliente. A entrada do
# script é essa parte montada no cliente, com o separador.
CLIENT_RE = re.compile(r"_\d{12}")
# Valores sintéticos para uma entrada extra exigida pelo gerador (nunca um valor do HAR). A exigência em si
# continua contando como falha; isto só mantém os 4 modos medidos enquanto o gerador não deriva o valor.
EXTRA_SYNTHETIC = {"--op": "SIM", "--page": "PAGINA"}
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


def new_client_part():
    """Parte do SESSIONID montada no cliente: `_` + 12 dígitos, nova a cada execução, como no navegador."""
    return "_" + "".join(random.choice("0123456789") for _ in range(12))


def captured_clients(har_path):
    """Sufixos (12 dígitos) de SESSIONID que existem no HAR, só para provar que o check não usa nenhum."""
    parts = set()
    for e in json.loads(har_path.read_text())["log"]["entries"]:
        vals = [i.get("value", "") for i in e["request"].get("queryString", [])]
        vals += [i.get("value", "") for i in e["request"].get("headers", [])]
        vals += re.findall(r"SESSIONID=([^&\s]+)", e["request"].get("postData", {}).get("text", ""))
        for v in vals:
            tail = v.strip().partition("_")[2]
            if re.fullmatch(r"\d{12}", tail):
                parts.add(tail)
    return parts


def required_params(py, script, cwd):
    """Com `--confirmar` e sem entradas, o script falha antes de qualquer requisição listando o que exige (F1)."""
    p = subprocess.run([py, "-I", str(script), "--confirmar"], capture_output=True, text=True, timeout=60, cwd=cwd)
    m = re.search(r"parâmetros obrigatórios ausentes: (.+)", p.stderr)
    if not m:
        return None
    return [x.strip() for x in m.group(1).split(",") if x.strip()]


def run_script(py, script, base, cwd, client, confirm=True, extra=()):
    argv = [py, "-I", str(script)]
    if confirm:
        argv.append("--confirmar")
    argv += ["--base-url", base, "--placa", PLACA, "--cpf", CPF, "--sessionid-cliente", client, *extra]
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=cwd)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--sessionid-suffix", help="12 dígitos da parte montada no cliente; por padrão é gerada a cada execução")
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

        # Entradas do operador (F1): placa sintética + parte do SESSIONID montada no cliente, nova a cada
        # execução; nunca um valor do HAR. O sim valida o formato (prefixo + "_" + 12 dígitos).
        client = a.sessionid_suffix or new_client_part()
        if not client.startswith("_"):
            client = "_" + client
        check(bool(CLIENT_RE.fullmatch(client)), f"a parte do SESSIONID deveria ser _+12 dígitos: {client!r}")
        cap_tails = captured_clients(HAR)
        check(client[1:] not in cap_tails, "a parte do SESSIONID não pode ser um valor capturado do HAR")
        req = required_params(py, script, tmp)
        extra_req = sorted(set(req or []) - ALLOWED_REQUIRED) if req is not None else []
        # Entradas extras que o gerador exigir são FALHA (critério do líder), mas o check segue rodando com
        # valores sintéticos (nunca do HAR) para que os 4 modos continuem medidos e regressões apareçam.
        extra_argv = [arg for name in extra_req for arg in (name, EXTRA_SYNTHETIC.get(name, "SYNTH"))]
        res["operator_inputs"] = {"placa": "sintética", "sessionid_cliente": "_ + 12 dígitos gerados no check",
                                  "client_novo_vs_har": client[1:] not in cap_tails,
                                  "required_params": req, "required_params_extra": extra_req,
                                  "extra_synthetic_filled": sorted({n for n in extra_req})}
        check(req is not None, "o script não listou as entradas obrigatórias ao rodar com --confirmar e sem entradas")
        if req is not None:
            check("--placa" in req and "--sessionid-cliente" in req,
                  f"o script deveria exigir --placa e --sessionid-cliente; exigiu {req}")
            check(not extra_req,
                  "o script exige entrada obrigatória além de placa/sessionid-cliente (o gerador deve derivá-la): "
                  + ", ".join(extra_req))

        plan = run_script(py, script, base, tmp, client, confirm=False, extra=extra_argv)
        n_plan = sum(1 for l in plan.stdout.splitlines() if l.lstrip()[:1].isdigit() and ". " in l[:6])
        check(plan.returncode == 0 and "Nada foi enviado" in plan.stdout, f"modo plano deveria sair 0 e não enviar: {plan.stderr[-160:]}")
        check(http(base, "/__sim/log")["log"] == [], "modo plano não pode tocar o simulador")
        res["plan_steps"] = n_plan

        def scenario(mode):
            http(base, "/__sim/reset"); http(base, f"/__sim/mode?m={mode}")
            p = run_script(py, script, base, tmp, client, extra=extra_argv)
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
    print("OK: priming × detran-sim — entradas placa+parte do SESSIONID, cadeia completa (2 sessões) e falha clara/imediata em error, nocontrols e 403"); return 0


if __name__ == "__main__":
    sys.exit(main())
