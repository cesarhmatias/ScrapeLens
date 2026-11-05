#!/usr/bin/env python3
"""Repeats the live cycle N times and records the failure rate.

usage: python3 loop_bodies.py [N=20]   → ../results/bodies/cycles.json
"""
import json, pathlib, re, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
RES = HERE.parent / "results" / "bodies"
n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
rows = []
for i in range(1, n + 1):
    t0 = time.time()
    p = subprocess.run([sys.executable, str(HERE / "run_bodies.py")], capture_output=True, text=True)
    log = (RES / "capture.log").read_text() if (RES / "capture.log").exists() else ""
    m = re.search(r"capture shutdown: (.*)", log)
    err = re.search(r"(?:captura importada|capture imported): (.*)", log)
    rows.append({"cycle": i, "ok": p.returncode == 0, "seconds": round(time.time() - t0, 1),
                 "shutdown": m.group(1) if m else None, "error": (err.group(1) if err else p.stderr.strip()[-300:] or None) if p.returncode else None})
    print(rows[-1], flush=True)
fails = sum(1 for r in rows if not r["ok"])
(RES / "cycles.json").write_text(json.dumps({"cycles": n, "failures": fails, "rows": rows}, indent=2, ensure_ascii=False))
print(f"{n} ciclos, {fails} falhas")
sys.exit(1 if fails else 0)
