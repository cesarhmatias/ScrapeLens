#!/usr/bin/env python3
"""Prova do aceite 2 e 4 da rodada 7: roda o script de priming GERADO contra o
simulador local (127.0.0.1:8791, sem rede externa). Quem executa é este
script de teste, não o ScrapeLens.

Uso: python3 run_proof.py [--python /caminho/python-com-requests]
Requer `requests` no interpretador passado em --python.
"""
import argparse, json, os, re, signal, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CLI = REPO / "core/target/debug/scrapelens-core"
SIM = REPO / "testserver/detran-sim/detran_sim.py"
HAR = REPO / "fixtures/detran-pb-real-shape/real-shape-1round.har"
PORT = 8791
BASE = f"http://127.0.0.1:{PORT}"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def sim_log():
    return json.load(urllib.request.urlopen(BASE + "/__sim/log"))["log"]


def clean(text):
    return text.replace(str(REPO), "<repo>").replace(str(Path.home()), "~")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="priming-proof-"))
    result = {"base": BASE, "checks": {}}

    sess = work / "sess"
    run([CLI, "import-har", HAR, "--out", sess])
    found = run([CLI, "search", sess, "cmd_consultar_placa", "--scope", "requestBody"])
    target = json.loads(found.stdout)["matches"][0]["requestId"]
    script = work / "priming.py"
    gen = run([CLI, "export-priming", sess, target, "--out", script])
    (HERE / "priming-real-shape-1round.py").write_text(clean(script.read_text()))
    result["target"] = target
    result["generation_warnings"] = clean(gen.stderr).strip().splitlines()

    sim = subprocess.Popen([sys.executable, SIM, "--port", str(PORT)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + "/healthz"); break
            except OSError:
                time.sleep(0.1)
        params = ["--confirmar", "--base-url", BASE, "--placa", "TST0T10", "--cpf", "00000000191"]

        plan = run([args.python, script])
        result["checks"]["plan_only_without_confirmar"] = (
            plan.returncode == 0 and "Nada foi enviado" in plan.stdout and sim_log() == [])
        (HERE / "plan-only.log").write_text(clean(plan.stdout))

        runs = []
        for i in (1, 2):
            urllib.request.urlopen(BASE + "/__sim/reset")
            r = run([args.python, script, *params])
            log = sim_log()
            stamps = [e for e in log if e["path"] == "/servlet/Connector"]
            runs.append({"returncode": r.returncode, "requests": len(log),
                         "connector_posts": len(stamps),
                         "all_200": all(e["status"] == 200 for e in log),
                         "no_error_note": not any("erro" in (e.get("note") or "").lower() or "ERROR" in (e.get("note") or "") for e in log),
                         "notes": [e["note"] for e in stamps]})
            (HERE / f"run{i}.log").write_text(clean(r.stdout + r.stderr))
        result["runs"] = runs
        result["checks"]["chain_completes_run1"] = runs[0]["returncode"] == 0 and runs[0]["connector_posts"] == 6
        result["checks"]["chain_completes_run2"] = runs[1]["returncode"] == 0 and runs[1]["connector_posts"] == 6
        result["checks"]["no_app_error_in_sim_notes"] = runs[0]["no_error_note"] and runs[1]["no_error_note"]

        # Controle negativo: reenviar os valores CAPTURADOS (STAMP/delta/sessão do
        # HAR) a uma sessão nova do simulador tem de dar ERRORMESSAGE.
        import requests
        har = json.load(open(HAR))
        entries = [e for e in har["log"]["entries"] if e["request"]["url"].endswith("/Connector")]
        last = entries[-1]["request"]
        urllib.request.urlopen(BASE + "/__sim/reset")
        s = requests.Session()
        s.get(BASE + "/detran-portal-servicos/servlet/easynat-app?op=S37", timeout=10)
        resp = s.post(BASE + "/detran-portal-servicos/servlet/Connector",
                      data=last["postData"]["text"],
                      headers={"content-type": "application/x-www-form-urlencoded; charset=UTF-8"}, timeout=10)
        m = re.search(r'name="ERRORMESSAGE"[^>]*>([^<]*)<', resp.text)
        err = (m.group(1) if m else "").strip()
        result["negative_control"] = {"http": resp.status_code, "ERRORMESSAGE": err[:120]}
        result["checks"]["captured_values_rejected_by_simulator"] = resp.status_code == 200 and bool(err)
        (HERE / "negative-control.log").write_text(
            f"POST com valores capturados -> HTTP {resp.status_code}; ERRORMESSAGE={err[:120]!r}\n")
    finally:
        sim.send_signal(signal.SIGTERM); sim.wait(timeout=5)

    result["ok"] = all(result["checks"].values())
    (HERE / "proof.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result["checks"], indent=2)); print("OK" if result["ok"] else "FALHOU")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
