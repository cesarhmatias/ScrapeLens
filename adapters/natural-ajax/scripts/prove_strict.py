#!/usr/bin/env python3
"""Acceptance 2 of round 8: the script generated WITH the adapter completes the chain against detran-sim in
`strict` (validated UTF-16 prefixes) with values of different sizes from the captured ones; the script WITHOUT the
adapter (control, round 7) fails. Only 127.0.0.1. This test is the one that runs it, never ScrapeLens.

  python3 adapters/natural-ajax/scripts/prove_strict.py [--python PY_COM_REQUESTS] [--port 8791]
"""
import argparse, json, os, random, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NATURAL = ROOT / "adapters/natural-ajax/target/release/natural-core"
CORE = ROOT / "core/target/release/scrapelens-core"
SIM = ROOT / "testserver/detran-sim/detran_sim.py"
HAR = ROOT / "fixtures/detran-pb-real-shape/real-shape-1round.har"
OUT = ROOT / "adapters/natural-ajax/evidence/strict.json"
PLACA = "TST1A23"  # synthetic Mercosul plate
CPF = "00000000191"


def http(base, path):
    return json.load(urllib.request.urlopen(base + path, timeout=5))


def pick_python(arg):
    for c in ([arg] if arg else []) + ["/tmp/sl-venv-req/bin/python", "/tmp/rev10/venv/bin/python", sys.executable]:
        if c and subprocess.run([c, "-c", "import requests"], capture_output=True).returncode == 0:
            return c
    sys.exit("no python with requests; pass --python")


def run(py, script, base, client):
    argv = [py, "-I", str(script), "--confirm", "--base-url", base, "--placa", PLACA, "--cpf", CPF,
            "--sessionid-cliente", client]
    return subprocess.run(argv, capture_output=True, text=True, timeout=120)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8791)
    a = ap.parse_args()
    py = pick_python(a.python)
    base = f"http://127.0.0.1:{a.port}"
    tmp = Path(tempfile.mkdtemp(prefix="sl-nat-strict-")); os.chmod(tmp, 0o700)
    env = dict(os.environ, SCRAPELENS_CORE_BIN=str(CORE))
    sim = subprocess.Popen([sys.executable, str(SIM), "--port", str(a.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {"base": base, "mode": "strict", "placa": "synthetic Mercosul plate", "runs": {}}
    fails = []
    try:
        for _ in range(60):
            try:
                http(base, "/healthz"); break
            except Exception:
                time.sleep(0.1)
        sess = tmp / "sess"
        subprocess.run([str(CORE), "import-har", str(HAR), "--out", str(sess), "--label", "synthetic-fixture"], check=True, capture_output=True)
        man = json.loads((ROOT / "fixtures/detran-pb-real-shape/manifest.json").read_text())
        target = man["expectations"]["aceite_1_origins_chain"]["A"]["target"]
        for label, extra in (("com_adaptador", ["--adapter", "natural-ajax"]), ("controle_sem_adaptador", [])):
            script = tmp / f"{label}.py"
            g = subprocess.run([str(NATURAL), "export-priming", str(sess), target, "--out", str(script), *extra],
                               capture_output=True, text=True, env=env)
            if g.returncode != 0:
                fails.append(f"{label}: export-priming failed: {g.stderr[:120]}")
                continue
            text = script.read_text()
            runs = []
            for i in range(2):
                http(base, "/__sim/reset"); http(base, "/__sim/mode?m=strict")
                client = "_" + "".join(random.choice("0123456789") for _ in range(12))
                p = run(py, script, base, client)
                log = http(base, "/__sim/log")["log"]
                runs.append({"rc": p.returncode, "requests": len(log),
                             "stderr_tail": p.stderr.strip().splitlines()[-1][:160] if p.stderr.strip() else ""})
            res["runs"][label] = {"usa_codificador_natural": "natural_ajax_encode" in text, "execucoes": runs}
        with_ = res["runs"].get("com_adaptador", {})
        ctrl = res["runs"].get("controle_sem_adaptador", {})
        if not with_.get("usa_codificador_natural"):
            fails.append("the script with the adapter does not use the Natural encoder")
        for r in with_.get("execucoes", []):
            if r["rc"] != 0:
                fails.append(f"with adapter: rc={r['rc']} {r['stderr_tail']}")
        if ctrl.get("execucoes") and all(r["rc"] == 0 for r in ctrl["execucoes"]):
            fails.append("the control (without adapter) should fail in strict mode")
        res["controle_falha_como_esperado"] = bool(ctrl.get("execucoes")) and all(r["rc"] != 0 for r in ctrl["execucoes"])
    finally:
        sim.terminate()
    res["fails"] = fails
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(res, ensure_ascii=False, indent=2))
    print("OK" if not fails else "FAIL: " + "; ".join(fails))
    sys.exit(1 if fails else 0)


main()
