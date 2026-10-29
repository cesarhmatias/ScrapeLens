#!/usr/bin/env python3
"""Rodada 9: o `plan.hash` gravado no trace (calculado na geração por `validate::plan_hash`) confere no
`natural-core validate`; um plano alterado avisa "plano não confere". Só 127.0.0.1 (detran-sim).

  python3 adapters/natural-ajax/scripts/prove_plan_hash.py [--python PY_COM_REQUESTS] [--port 8801]
"""
import argparse, json, os, random, subprocess, sys, tempfile, time, urllib.parse, urllib.request
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
        insp = json.loads(subprocess.run([C, "inspect", str(tmp / "cap")], capture_output=True, text=True).stdout)
        target_url = next(r["url"] for r in insp["session"]["requests"] if r["id"] == target)
        cap_origin = urllib.parse.urlsplit(target_url).scheme + "://" + urllib.parse.urlsplit(target_url).netloc
        # Mapeamento explícito da origem capturada para o sim: sem o aviso de origem automática,
        # o trace fiel fica com ZERO avisos (a meta do líder).
        map_flag = ["--map-origin", f"{cap_origin}={base}"]
        for label, adapter, mode in (("com_adaptador", True, "strict"), ("sem_adaptador", False, "ok")):
            flag = ["--adapter", "natural-ajax"] if adapter else []
            subprocess.run([N, "export-priming", str(tmp / "cap"), target, "--out", str(tmp / "p.py"), *flag],
                           capture_output=True, check=True)
            urllib.request.urlopen(base + "/__sim/reset"); urllib.request.urlopen(base + "/__sim/mode?m=" + mode)
            def run_script(name, extra):
                urllib.request.urlopen(base + "/__sim/reset"); urllib.request.urlopen(base + "/__sim/mode?m=" + mode)
                out = tmp / name
                proc = subprocess.run([py, "-I", str(tmp / "p.py"), "--confirmar", "--base-url", base, "--placa", "TST1A23",
                                       "--cpf", "00000000191", "--sessionid-cliente",
                                       "_" + "".join(random.choice("0123456789") for _ in range(12)), "--trace", str(out), *extra],
                                      capture_output=True, text=True)
                return proc, out

            def validate(trace_path, name):
                subprocess.run([C, "import-trace", str(trace_path), "--out", str(tmp / name)], capture_output=True, check=True)
                v = subprocess.run([N, "validate", str(tmp / "cap"), str(tmp / name), *flag, *map_flag], capture_output=True, text=True)
                warnings = [w[:70] for w in json.loads(v.stdout)["warnings"]]
                return v, [w for w in warnings if "plano" in w.lower()], warnings

            p, tr = run_script(f"{label}.json", [])
            v, plan_warn, genuine_warn = validate(tr, f"s_{label}")
            genuine = json.load(open(tr))
            # Parâmetro opcional sobrescrito (`--op`): `plan` igual e nenhum aviso de plano.
            p2, tr2 = run_script(f"{label}_op.json", ["--op", "S38"])
            v2, ov_warn, _ = validate(tr2, f"o_{label}")
            over = json.load(open(tr2))
            op_in_top = any(x["name"] == "op" for x in over["parameters"])
            # Plano alterado e hash copiado de outro plano.
            altered_doc = json.loads(json.dumps(genuine)); altered_doc["plan"]["hash"] = "0" * 16
            json.dump(altered_doc, open(tmp / f"{label}_alt.json", "w"))
            _, altered, _ = validate(tmp / f"{label}_alt.json", f"z_{label}")
            res[label] = {"script_rc": p.returncode, "resumo": v.stderr.strip()[:60],
                          "plan_version": genuine["plan"].get("version"),
                          "avisos_no_trace_genuino": genuine_warn,
                          "aviso_plano_no_trace_genuino": plan_warn, "aviso_plano_no_trace_alterado": bool(altered),
                          "opcional_sobrescrito": {"script_rc": p2.returncode, "plan_igual": over["plan"] == genuine["plan"],
                                                    "op_em_parameters_de_topo": op_in_top, "aviso_plano": ov_warn,
                                                    "resumo": v2.stderr.strip()[:60]}}
            if p.returncode != 0: fails.append(f"{label}: script rc={p.returncode}")
            if genuine["plan"].get("version") != 2:
                fails.append(f"{label}: plan.version = {genuine['plan'].get('version')!r}, esperado 2")
            if plan_warn: fails.append(f"{label}: trace genuíno avisa plano: {plan_warn}")
            # Meta do líder: trace fiel do gerador atual (com adaptador) -> equivalent e ZERO avisos.
            if adapter and genuine_warn:
                fails.append(f"{label}: trace genuíno com avisos: {genuine_warn}")
            if adapter and "equivalente à captura" not in v.stderr:
                fails.append(f"{label}: trace genuíno não é equivalente: {v.stderr.strip()[:80]}")
            if not altered: fails.append(f"{label}: plano alterado não avisou")
            if over["plan"] != genuine["plan"]: fails.append(f"{label}: plan mudou ao sobrescrever opcional")
            if ov_warn: fails.append(f"{label}: opcional sobrescrito avisa plano: {ov_warn}")
            if not op_in_top: fails.append(f"{label}: `op` sobrescrito não aparece em parameters")
            # Hash copiado do plano de OUTRO alvo da mesma captura: também avisa.
            insp = json.loads(subprocess.run([C, "inspect", str(tmp / "cap")], capture_output=True, text=True).stdout)
            others = [r["id"] for r in insp["session"]["requests"]
                      if r["method"] == "POST" and "Connector" in r["url"] and r["id"] != target]
            foreign = None
            for other in others:
                subprocess.run([N, "export-priming", str(tmp / "cap"), other, "--out", str(tmp / "o.py"), *flag], capture_output=True)
                if (tmp / "o.py").exists():
                    line = next((l for l in (tmp / "o.py").read_text().splitlines() if l.startswith("PLAN_HASH = ")), "")
                    cand = line.split("'")[1] if "'" in line else None
                    (tmp / "o.py").unlink()
                    if cand and cand != genuine["plan"]["hash"]:
                        foreign = cand; break
            if foreign:
                fdoc = json.loads(json.dumps(genuine)); fdoc["plan"]["hash"] = foreign
                json.dump(fdoc, open(tmp / f"{label}_foreign.json", "w"))
                _, foreign_warn, _ = validate(tmp / f"{label}_foreign.json", f"f_{label}")
                res[label]["hash_de_outro_plano_avisa"] = bool(foreign_warn)
                if not foreign_warn: fails.append(f"{label}: hash de outro plano não avisou")
            else:
                res[label]["hash_de_outro_plano_avisa"] = "sem outro alvo com hash diferente"
    finally:
        sim.terminate()
    res["fails"] = fails
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(res, ensure_ascii=False, indent=2)); print("OK" if not fails else "FAIL: " + "; ".join(fails))
    sys.exit(1 if fails else 0)


main()
