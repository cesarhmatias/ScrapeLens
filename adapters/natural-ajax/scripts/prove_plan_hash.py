#!/usr/bin/env python3
"""Rodada 9: o `plan.hash` gravado no trace (calculado na geração por `validate::plan_hash`) confere no
`natural-core validate`; um plano alterado avisa "plano não confere". Só 127.0.0.1 (detran-sim).

  python3 adapters/natural-ajax/scripts/prove_plan_hash.py [--python PY_COM_REQUESTS] [--port 8801]
"""
import argparse, json, os, random, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

R = Path(__file__).resolve().parents[3]
C = str(R / "core/target/release/scrapelens-core")
N = str(R / "adapters/natural-ajax/target/release/natural-core")
OUT = R / "adapters/natural-ajax/evidence/plan-hash.json"


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8801)
    a = ap.parse_args()
    py = a.python or next((c for c in ("/tmp/sl-venv-req/bin/python", "/tmp/rev10/venv/bin/python", sys.executable)
                           if subprocess.run([c, "-c", "import requests"], capture_output=True).returncode == 0), None)
    if not py:
        sys.exit("nenhum python com requests; passe --python")
    tmp = Path(tempfile.mkdtemp(prefix="sl-planhash-")); os.chmod(tmp, 0o700)
    base = f"http://127.0.0.1:{a.port}"
    sim = subprocess.Popen([sys.executable, str(R / "testserver/detran-sim/detran_sim.py"), "--port", str(a.port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res, fails = {}, []
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1); break
            except Exception:
                time.sleep(0.1)
        man = json.load(open(R / "fixtures/detran-pb-real-shape/manifest.json"))
        target = man["expectations"]["aceite_1_origins_chain"]["A"]["target"]
        subprocess.run([C, "import-har", str(R / "fixtures/detran-pb-real-shape/real-shape-1round.har"), "--out", str(tmp / "cap")],
                       capture_output=True, check=True)
        for label, adapter, mode in (("com_adaptador", True, "strict"), ("sem_adaptador", False, "ok")):
            flag = ["--adapter", "natural-ajax"] if adapter else []
            subprocess.run([N, "export-priming", str(tmp / "cap"), target, "--out", str(tmp / "p.py"), *flag],
                           capture_output=True, check=True)
            urllib.request.urlopen(base + "/__sim/reset"); urllib.request.urlopen(base + "/__sim/mode?m=" + mode)
            tr = tmp / f"{label}.json"
            p = subprocess.run([py, "-I", str(tmp / "p.py"), "--confirmar", "--base-url", base, "--placa", "TST1A23",
                                "--cpf", "00000000191", "--sessionid-cliente", "_" + "".join(random.choice("0123456789") for _ in range(12)),
                                "--trace", str(tr)], capture_output=True, text=True)
            subprocess.run([C, "import-trace", str(tr), "--out", str(tmp / f"s_{label}")], capture_output=True, check=True)
            v = subprocess.run([N, "validate", str(tmp / "cap"), str(tmp / f"s_{label}"), *flag], capture_output=True, text=True)
            plan_warn = [w[:60] for w in json.loads(v.stdout)["warnings"] if "plano" in w.lower()]
            t = json.load(open(tr)); t["plan"]["hash"] = "0" * 16; json.dump(t, open(tr, "w"))
            subprocess.run([C, "import-trace", str(tr), "--out", str(tmp / f"z_{label}")], capture_output=True, check=True)
            z = subprocess.run([N, "validate", str(tmp / "cap"), str(tmp / f"z_{label}"), *flag], capture_output=True, text=True)
            altered = [w[:60] for w in json.loads(z.stdout)["warnings"] if "plano" in w.lower()]
            res[label] = {"script_rc": p.returncode, "resumo": v.stderr.strip()[:60], "aviso_plano_no_trace_genuino": plan_warn,
                          "aviso_plano_no_trace_alterado": bool(altered)}
            if p.returncode != 0: fails.append(f"{label}: script rc={p.returncode}")
            if plan_warn: fails.append(f"{label}: trace genuíno avisa plano: {plan_warn}")
            if not altered: fails.append(f"{label}: plano alterado não avisou")
    finally:
        sim.terminate()
    res["fails"] = fails
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(res, ensure_ascii=False, indent=2)); print("OK" if not fails else "FAIL: " + "; ".join(fails))
    sys.exit(1 if fails else 0)


main()
