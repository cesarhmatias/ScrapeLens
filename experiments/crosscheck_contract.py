#!/usr/bin/env python3
"""Cross-check: o mesmo pipeline CDP/NetLog contra os servidores do contrato
(`testserver/`, Rust + httlib-hpack + quiche) em vez do mock Python.

Objetivo: confirmar que as conclusões da matriz não dependem da implementação
do servidor de referência.

Uso:
  .venv/bin/python crosscheck_contract.py --proto all
Saída: results/contract-<proto>/{layers.json,report.md,server-h*.jsonl,evidence/}
Somente leitura em testserver/ e fixtures/ — nada é editado lá.
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
REPO = HERE.parent
RESULTS = HERE / "results"
BIN = REPO / "testserver" / "target" / "debug" / "scrapelens-testserver"
SPKI_FILE = REPO / "fixtures" / "tls" / "spki-sha256-base64.txt"
PY = str(HERE / ".venv" / "bin" / "python")
NODE = shutil.which("node") or "/opt/homebrew/bin/node"

PORTS = {"h1": 8781, "h2": 8782, "h3": 8783}
MINE = {"h1": "http/1.1", "h2": "h2", "h3": "h3"}


def plan_for(proto: str) -> dict:
    if proto == "h1":
        base = "http://127.0.0.1:8781"
    elif proto == "h3":
        # O testserver serve h3 no mesmo origin do h2 (listener UDP extra na 8782);
        # é assim que o próprio scripts/chrome-probe.sh mede h3.
        base = "https://127.0.0.1:8782"
    else:
        base = f"https://127.0.0.1:{PORTS[proto]}"
    return {
        "urls": [f"{base}/setcookie", f"{base}/page"],
        "mode": "native",
        "settleMs": 4000 if proto == "h3" else 3000,
        "navTimeoutMs": 30000,
    }


def wait_line(proc: subprocess.Popen, needle: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            if needle in line:
                return
        elif proc.poll() is not None:
            raise RuntimeError(f"testserver morreu antes de '{needle}'")
        else:
            time.sleep(0.05)
    raise RuntimeError(f"timeout esperando '{needle}'")


def convert(src: pathlib.Path, dst: pathlib.Path, proto: str) -> int:
    rows = []
    for line in src.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        pairs = [[n, v] for n, v in r["headers"]]
        pseudo = [[n, v] for n, v in (r.get("pseudoheaders") or [])]
        regular = [p for p in pairs if not p[0].startswith(":")] if pseudo else pairs
        names = [n for n, _ in regular]
        resp = [[":status", str(r["response"]["status"])]]
        resp += [[n, v] for n, v in r["response"]["headers"]]
        rows.append(
            {
                "source": "server",
                "protocol": MINE[proto],
                "conn": r.get("conn"),
                "method": r["method"],
                "target": r["target"],
                "headers": regular,
                "pseudoheaders": pseudo,
                "header_names": names,
                "duplicate_names": sorted({n for n in names if names.count(n) > 1}),
                "body_len": r.get("body_len", 0),
                "response_headers": resp,
                "note": "testserver/ (contrato)",
            }
        )
    dst.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in rows) + "\n")
    return len(rows)


def run_proto(proto: str) -> dict:
    outdir = RESULTS / f"contract-{proto}"
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    plan = plan_for(proto)
    (outdir / "plan.json").write_text(json.dumps(plan, indent=2))
    spki = SPKI_FILE.read_text().strip()

    srv = subprocess.Popen(
        [str(BIN), "serve", "--only", ("h2,h3" if proto == "h3" else proto),
         "--evidence", str(outdir / "evidence"), "--run-id", proto],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    sys.path.insert(0, str(HERE / "capture"))
    from launch_chrome import ChromeSession  # noqa: PLC0415

    chrome = None
    try:
        wait_line(srv, f"listening on")
        chrome = ChromeSession(
            str(outdir / "chrome-profile"),
            str(outdir / "chrome-netlog.json"),
            spki=spki,
            force_quic_origin=("127.0.0.1:8782" if proto == "h3" else "127.0.0.1:8783"),
            ignore_cert_errors=(proto == "h3"),
        )
        chrome.start()
        rc = subprocess.run(
            [NODE, str(HERE / "capture" / "cdp_capture.mjs"), "--port", "9222",
             "--outdir", str(outdir), "--plan", str(outdir / "plan.json")],
            capture_output=True, text=True, timeout=240,
        )
        chrome.wait_exit(30)
    finally:
        if chrome:
            chrome.terminate()
        if srv.poll() is None:
            srv.terminate()
            try:
                srv.wait(timeout=8)
            except subprocess.TimeoutExpired:
                srv.kill()
        shutil.rmtree(outdir / "chrome-profile", ignore_errors=True)

    src = outdir / "evidence" / proto / f"{proto}.jsonl"
    if not src.exists():
        raise RuntimeError(f"evidência do contrato ausente: {src}")
    n = convert(src, outdir / f"server-{proto}.jsonl", proto)
    (outdir / "run.json").write_text(json.dumps({"experiment": outdir.name, "chrome": {"Browser": "Chrome/156.0.8078.48"}, "source": "testserver"}, indent=2))
    print(f"{proto}: {n} requisições convertidas de {src}")
    return {"proto": proto, "rows": n, "dir": str(outdir)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", default="all", choices=["h1", "h2", "h3", "all"])
    args = ap.parse_args()
    if not BIN.exists():
        raise SystemExit(f"binário ausente: {BIN} (rode `cargo build` em testserver/)")
    protos = ["h1", "h2", "h3"] if args.proto == "all" else [args.proto]
    out = [run_proto(p) for p in protos]
    sys.path.insert(0, str(HERE))
    import compare  # noqa: PLC0415

    for item in out:
        layer = compare.analyze(pathlib.Path(item["dir"]))
        pathlib.Path(item["dir"], "layers.json").write_text(json.dumps(layer, indent=2, ensure_ascii=False))
        pathlib.Path(item["dir"], "report.md").write_text(compare.report(layer))
        print(json.dumps({item["proto"]: [
            {"t": r["target"][:40], "netlog": r["b_netlog"]["verdict"], "cdp_extra": r["a_cdp"]["extra"]["verdict"]}
            for r in layer["requests"]
        ]}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
