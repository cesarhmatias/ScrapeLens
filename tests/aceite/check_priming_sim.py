#!/usr/bin/env python3
"""Round 7, Acceptance 2: the priming script (real-shape, 1 round) RUN BY THIS TEST against detran-sim
(127.0.0.1, no external network). The test runs it, never ScrapeLens.

  python3 tests/aceite/check_priming_sim.py [--core BIN] [--python PY_COM_REQUESTS] [--port 8791]

The script's interpreter needs `requests` (e.g.: python3 -m venv /tmp/v && /tmp/v/bin/pip install requests).
Operator inputs (F1, 48b3cdb): the script requires the plate and the SESSIONID part built on the client (`_` + 12
digits, the format detran-sim validates). This check passes a synthetic plate and GENERATES that part on each run,
as the browser would, never a value captured from the HAR; any other required input makes the check fail
with a clear message.
Scenarios: ok (full chain; 2 runs with different sessions; captured values rejected by the simulator),
error / nocontrols / 403 (the script must fail with a clear message and must NOT go on: the run ends
at the very step that received the bad response). Result in tests/results/priming/aceite2-sim.json.
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
PLACA = "TST0T10"      # synthetic
CPF = "00000000191"    # synthetic
# Operator inputs the script may require (F1): plate and the SESSIONID part built on the client.
# Leader's criterion (Round 7, F1): any other required input — including --op/--page, which are
# navigation derivable from the flow itself — makes the check fail with a clear message. No HAR value is
# passed to get around it: that would hide the generator's defect.
ALLOWED_REQUIRED = {"--placa", "--cpf", "--sessionid-cliente"}
# detran-sim validates the format: easynat-app prefix + "_" + 12 digits built on the client. The script input is
# that part built on the client, with the separator.
CLIENT_RE = re.compile(r"_\d{12}")
# Synthetic values for an extra input required by the generator (never a HAR value). The requirement itself
# still counts as a failure; this only keeps the 4 measured modes running until the generator derives the value.
EXTRA_SYNTHETIC = {"--op": "SIM", "--page": "PAGINA"}
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def default_python():
    for c in ("/tmp/sl-venv-req/bin/python", sys.executable):
        if subprocess.run([c, "-c", "import requests"], capture_output=True).returncode == 0:
            return c
    sys.exit("no python with `requests`; pass --python (python3 -m venv /tmp/v && /tmp/v/bin/pip install requests)")


def http(base, path):
    return json.load(urllib.request.urlopen(base + path, timeout=5))


def new_client_part():
    """SESSIONID part built on the client: `_` + 12 digits, new on each run, as in the browser."""
    return "_" + "".join(random.choice("0123456789") for _ in range(12))


def captured_clients(har_path):
    """SESSIONID suffixes (12 digits) that exist in the HAR, only to prove the check uses none of them."""
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
    """With `--confirmar` and no inputs, the script fails before any request, listing what it requires (F1)."""
    p = subprocess.run([py, "-I", str(script), "--confirmar"], capture_output=True, text=True, timeout=60, cwd=cwd)
    m = re.search(r"required parameters missing: (.+)", p.stderr)
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
    ap.add_argument("--sessionid-suffix", help="12 digits of the part built on the client; by default it is generated on each run")
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
        check(g.returncode == 0, f"export-priming failed: {g.stderr[:150]}")

        # Operator inputs (F1): synthetic plate + SESSIONID part built on the client, new on each
        # run; never a HAR value. The sim validates the format (prefix + "_" + 12 digits).
        client = a.sessionid_suffix or new_client_part()
        if not client.startswith("_"):
            client = "_" + client
        check(bool(CLIENT_RE.fullmatch(client)), f"the SESSIONID part should be _+12 digits: {client!r}")
        cap_tails = captured_clients(HAR)
        check(client[1:] not in cap_tails, "the SESSIONID part cannot be a value captured from the HAR")
        req = required_params(py, script, tmp)
        extra_req = sorted(set(req or []) - ALLOWED_REQUIRED) if req is not None else []
        # Extra inputs the generator requires are a FAILURE (leader's criterion), but the check keeps running
        # with synthetic values (never from the HAR) so the 4 modes stay measured and regressions show up.
        extra_argv = [arg for name in extra_req for arg in (name, EXTRA_SYNTHETIC.get(name, "SYNTH"))]
        res["operator_inputs"] = {"placa": "synthetic", "sessionid_cliente": "_ + 12 digits generated in the check",
                                  "client_novo_vs_har": client[1:] not in cap_tails,
                                  "required_params": req, "required_params_extra": extra_req,
                                  "extra_synthetic_filled": sorted({n for n in extra_req})}
        check(req is not None, "the script did not list the required inputs when run with --confirmar and no inputs")
        if req is not None:
            check("--placa" in req and "--sessionid-cliente" in req,
                  f"the script should require --placa and --sessionid-cliente; it required {req}")
            check(not extra_req,
                  "the script requires an input beyond placa/sessionid-cliente (the generator must derive it): "
                  + ", ".join(extra_req))

        plan = run_script(py, script, base, tmp, client, confirm=False, extra=extra_argv)
        n_plan = sum(1 for l in plan.stdout.splitlines() if l.lstrip()[:1].isdigit() and ". " in l[:6])
        check(plan.returncode == 0 and "Nothing was sent" in plan.stdout, f"plan mode should exit 0 and send nothing: {plan.stderr[-160:]}")
        check(http(base, "/__sim/log")["log"] == [], "plan mode must not touch the simulator")
        res["plan_steps"] = n_plan

        def scenario(mode):
            http(base, "/__sim/reset"); http(base, f"/__sim/mode?m={mode}")
            p = run_script(py, script, base, tmp, client, extra=extra_argv)
            log = http(base, "/__sim/log")
            return p, log["log"], log["sessions"]

        # ok: 2 runs, new sessions, full chain
        for n in (1, 2):
            p, log, sessions = scenario("ok")
            conn = [x for x in log if x["path"].endswith("/servlet/Connector")]
            notes = [x["note"] for x in conn]
            res["scenarios"][f"ok#{n}"] = {"rc": p.returncode, "requests": len(log), "connector_posts": len(conn), "sim_sessions": sessions,
                                           "events": notes}
            check(p.returncode == 0, f"ok#{n}: rc={p.returncode}: {p.stderr[-160:]}")
            check(len(log) == n_plan and len(conn) == 6 and all(x["status"] == 200 for x in log), f"ok#{n}: {len(log)} requests / {len(conn)} POSTs (expected {n_plan}/6, all 200)")
            check(all(x["note"].startswith("ok") for x in conn), f"ok#{n}: the simulator recorded an application error: {notes}")
            check("Chain completed" in p.stdout, f"ok#{n}: no 'Chain completed'")
        # negative control: blind replay with CAPTURED values (HAR) must be rejected by the simulator
        http(base, "/__sim/reset")
        cap = json.loads(HAR.read_text())
        import urllib.parse
        post = next(e for e in cap["log"]["entries"] if e["request"]["method"] == "POST")
        r = urllib.request.Request(base + "/detran-portal-servicos/servlet/Connector", data=post["request"]["postData"]["text"].encode(),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        body = urllib.request.urlopen(r, timeout=5).read().decode()
        # detran-sim reports this rejection in English (testserver/detran-sim/detran_sim.py:218)
        check("unknown session" in body, "negative control: the simulator should reject the captured POST")
        res["negative_control_captured_post_rejected"] = "unknown session" in body

        expect = {"error": ("ERRORMESSAGE", None), "nocontrols": ("HTML control", 4), "403": ("403", 4)}
        for mode, (word, stop_after) in expect.items():
            p, log, _ = scenario(mode)
            # detran-sim notes: "mode 403" and "nocontrols mode: ..." (testserver/detran-sim/detran_sim.py:204, 214)
            first_bad = next((i for i, x in enumerate(log, 1) if x["path"].endswith("/servlet/Connector") and (x["status"] != 200 or x["note"].startswith(("mode", "nocontrols", "app-error")))), None)
            ran = len(log)
            res["scenarios"][mode] = {"rc": p.returncode, "requests_sent": ran, "first_bad_response_at_request": first_bad,
                                      "stopped_at_bad_step": ran == first_bad if first_bad else None,
                                      "message": (p.stderr.strip().splitlines() or [""])[-1][:140]}
            check(p.returncode != 0, f"{mode}: the script should fail (rc={p.returncode})")
            check(p.stderr.strip().startswith("priming:") or "priming:" in p.stderr, f"{mode}: no clear message (`priming: ...`)")
            if mode == "error":
                check("ERRORMESSAGE" in p.stderr, f"{mode}: message should cite ERRORMESSAGE: {p.stderr[-120:]}")
            check(first_bad is not None and ran == first_bad,
                  f"{mode}: the script did NOT stop at the bad response: bad at request #{first_bad}, sent {ran} requests (must not go on)")
    finally:
        sim.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    res["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: priming × detran-sim — plate + SESSIONID part inputs, full chain (2 sessions) and clear/immediate failure on error, nocontrols and 403"); return 0


if __name__ == "__main__":
    sys.exit(main())
