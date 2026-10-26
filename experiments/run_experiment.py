#!/usr/bin/env python3
"""Orquestra um experimento completo: servidores -> Chrome -> CDP -> análise.

Uso:
  python3 run_experiment.py --exp h1-native
  python3 run_experiment.py --all
  python3 run_experiment.py --list
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PY = str(HERE / ".venv" / "bin" / "python")
NODE = shutil.which("node") or "/opt/homebrew/bin/node"
RESULTS = HERE / "results"
CERTS = HERE / "certs"

ORDERED_HEADERS = [
    ["x-rep", "a"],
    ["x-seq", "1"],
    ["X-Rep", "b"],
    ["x-seq", "2"],
    ["x-mixed-Case", "V"],
    ["x-rep", "c"],
]

EXPERIMENTS: dict[str, dict] = {
    "h1-plain": {
        "urls": ["http://127.0.0.1:8781/echo-order?case=plain"],
        "mode": "native",
        "settleMs": 800,
    },
    "h1-page": {
        "urls": ["http://127.0.0.1:8781/setcookie", "http://127.0.0.1:8781/page"],
        "mode": "native",
        "settleMs": 1800,
    },
    "h1-ordered": {
        "urls": ["http://127.0.0.1:8781/echo-order?case=ordered"],
        "mode": "ordered",
        "match": "/echo",
        "extraHeaders": ORDERED_HEADERS,
        "settleMs": 800,
    },
    "h2-plain": {
        "urls": ["https://127.0.0.1:8782/echo-order?case=plain"],
        "mode": "native",
        "settleMs": 900,
    },
    "h2-page": {
        "urls": ["https://127.0.0.1:8782/setcookie", "https://127.0.0.1:8782/page"],
        "mode": "native",
        "settleMs": 2000,
    },
    "h2-ordered": {
        "urls": ["https://127.0.0.1:8782/echo-order?case=ordered"],
        "mode": "ordered",
        "match": "/echo",
        "extraHeaders": ORDERED_HEADERS,
        "settleMs": 900,
    },
    "h3-plain": {
        "urls": ["https://127.0.0.1:8783/echo-order?case=plain"],
        "mode": "native",
        "settleMs": 2500,
    },
    "h3-page": {
        "urls": ["https://127.0.0.1:8783/setcookie", "https://127.0.0.1:8783/page"],
        "mode": "native",
        "settleMs": 3000,
    },
    "h1-cookieprobe": {
        "urls": ["http://127.0.0.1:8781/page-longcookies"],
        "mode": "native",
        "settleMs": 1200,
    },
    "h2-cookieprobe": {
        "urls": ["https://127.0.0.1:8782/page-longcookies"],
        "mode": "native",
        "settleMs": 1200,
    },
    "h1-set3": {
        "urls": ["http://127.0.0.1:8781/set3"],
        "mode": "native",
        "settleMs": 1200,
    },
    "h2-set3": {
        "urls": ["https://127.0.0.1:8782/set3"],
        "mode": "native",
        "settleMs": 1200,
    },
    "h3-set3": {
        "urls": ["https://127.0.0.1:8783/set3"],
        "mode": "native",
        "settleMs": 2500,
    },
    "h3-cookieprobe": {
        "urls": ["https://127.0.0.1:8783/page-longcookies"],
        "mode": "native",
        "settleMs": 2500,
    },
    "h3-ordered": {
        "urls": ["https://127.0.0.1:8783/echo-order?case=ordered"],
        "mode": "ordered",
        "match": "/echo",
        "extraHeaders": ORDERED_HEADERS,
        "settleMs": 2500,
    },
}


def wait_line(proc: subprocess.Popen, needle: str, timeout: float = 20.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            if needle in line:
                return line
        elif proc.poll() is not None:
            raise RuntimeError(f"processo morreu antes de '{needle}' (rc={proc.returncode})")
        else:
            time.sleep(0.05)
    raise RuntimeError(f"timeout esperando '{needle}'")


def start_servers(outdir: pathlib.Path, cert: pathlib.Path, key: pathlib.Path, base: int):
    s1 = subprocess.Popen(
        [PY, str(HERE / "servers" / "serve_all.py"), "--outdir", str(outdir), "--cert", str(cert), "--key", str(key), "--port-base", str(base)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    wait_line(s1, "READY")
    s3 = subprocess.Popen(
        [PY, str(HERE / "servers" / "h3_quic.py"), "--out", str(outdir / "server-h3.jsonl"), "--port", str(base + 2), "--cert", str(cert), "--key", str(key)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    wait_line(s3, "listening")
    return [s1, s3]


def stop(procs) -> None:
    for p in procs:
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()


def run_one(name: str, keep_profile: bool = False) -> dict:
    plan = dict(EXPERIMENTS[name])
    outdir = RESULTS / name
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    cert, key = CERTS / "localhost.pem", CERTS / "localhost-key.pem"
    if not cert.exists():
        subprocess.run([PY, str(CERTS / "gen_cert.py")], check=True, capture_output=True)
    spki = (CERTS / "spki.txt").read_text().strip()

    sys.path.insert(0, str(HERE / "capture"))
    from launch_chrome import ChromeSession  # noqa: PLC0415

    (outdir / "plan.json").write_text(json.dumps(plan, indent=2))
    servers: list[subprocess.Popen] = []
    chrome = None
    try:
        servers = start_servers(outdir, cert, key, 8781)
        chrome = ChromeSession(
            str(outdir / "chrome-profile"),
            str(outdir / "chrome-netlog.json"),
            spki=spki,
            force_quic_origin="127.0.0.1:8783",
        )
        ver = chrome.start()
        rc = subprocess.run(
            [NODE, str(HERE / "capture" / "cdp_capture.mjs"), "--port", "9222", "--outdir", str(outdir), "--plan", str(outdir / "plan.json")],
            capture_output=True, text=True, timeout=180,
        )
        if rc.returncode != 0:
            (outdir / "cdp-stderr.txt").write_text(rc.stdout + "\n" + rc.stderr)
        chrome.wait_exit(30)
    finally:
        if chrome:
            chrome.terminate()
        stop(servers)
        if not keep_profile:
            shutil.rmtree(outdir / "chrome-profile", ignore_errors=True)

    info = {"experiment": name, "plan": plan, "chrome": ver if chrome else None, "cdp_rc": rc.returncode}
    netlog = outdir / "chrome-netlog.json"
    info["netlog_bytes"] = netlog.stat().st_size if netlog.exists() else 0
    try:
        json.loads(netlog.read_text())
        info["netlog_valid_json"] = True
    except Exception as exc:  # noqa: BLE001
        info["netlog_valid_json"] = False
        info["netlog_error"] = str(exc)
    (outdir / "run.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))
    return info


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--keep-profile", action="store_true")
    args = ap.parse_args()
    if args.list:
        print("\n".join(sorted(EXPERIMENTS)))
        return
    names = sorted(EXPERIMENTS) if args.all else [args.exp]
    if not names or names == [None]:
        ap.error("use --exp NOME ou --all")
    for name in names:
        print(f"=== {name} ===")
        run_one(name, keep_profile=args.keep_profile)


if __name__ == "__main__":
    main()
