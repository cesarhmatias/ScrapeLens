#!/usr/bin/env python3
"""Orquestra captura multi-alvo (NetLog + CDP auto-attach), variantes com/sem wait."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
CAPTURE = HERE.parent / "capture"
PY = shutil.which("python3") or "python3"
NODE = shutil.which("node") or "node"


def free_port(port: int) -> None:
    subprocess.run(
        ["bash", "-c", f"lsof -ti :{port} | xargs kill -9 2>/dev/null || true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)


def wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.15)
    raise RuntimeError(f"URL não respondeu: {url} ({last})")


def testserver_bin() -> pathlib.Path:
    for p in (
        ROOT / "testserver/target/release/scrapelens-testserver",
        ROOT / "testserver/target/debug/scrapelens-testserver",
    ):
        if p.is_file():
            return p
    raise FileNotFoundError("scrapelens-testserver não encontrado; rode cargo build em testserver/")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=HERE.parent / "results" / "multi-target")
    ap.add_argument("--port", type=int, default=9881, help="porta h1 smoke ou testserver h1")
    ap.add_argument(
        "--page-url",
        help="URL da página multi (padrão: http://127.0.0.1:PORT/multi/)",
    )
    ap.add_argument("--smoke", action="store_true", help="usa smoke_server.py local (pré-/multi/ oficial)")
    ap.add_argument("--testserver", action="store_true", help="sobe testserver serve --only h1")
    ap.add_argument("--skip-run", action="store_true", help="só escreve plan.json")
    ap.add_argument("--only-wait", action="store_true", help="só variante with-wait (debug)")
    args = ap.parse_args()

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    page_url = args.page_url or f"http://127.0.0.1:{args.port}/multi/"
    server_log = out / "server.jsonl"
    server_proc = None
    smoke_servers = None

    meta = {"pageUrl": page_url, "source": "unknown"}

    if args.smoke:
        meta["source"] = "experiments/multi_target/smoke_server.py"
        server_log.write_text("")
        smoke_proc = subprocess.Popen(
            [PY, "-u", str(HERE / "smoke_server.py"), "--port", str(args.port), "--evidence", str(server_log)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        line = smoke_proc.stdout.readline() if smoke_proc.stdout else ""
        meta["smoke_info"] = line.strip()
        server_proc = smoke_proc
        wait_http(f"http://127.0.0.1:{args.port}/multi/")
    elif args.testserver:
        meta["source"] = "testserver/"
        bin_path = testserver_bin()
        evidence_dir = out / "testserver-evidence"
        evidence_dir.mkdir(exist_ok=True)
        probe = subprocess.Popen(
            [
                str(bin_path),
                "serve",
                "--only",
                "h1",
                "--h1",
                f"127.0.0.1:{args.port}",
                "--evidence",
                str(evidence_dir),
                "--run-id",
                "multi-probe",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_http(f"http://127.0.0.1:{args.port}/healthz")
            wait_http(page_url)
            meta["multi_route"] = "ok"
        except RuntimeError:
            meta["multi_route"] = "missing"
            probe.terminate()
            print("AVISO: /multi/ ausente no testserver.", file=sys.stderr)
            sys.exit(2)
        probe.terminate()
        probe.wait(timeout=5)
        free_port(args.port)
    else:
        meta["source"] = "external"
        if not server_log.exists():
            server_log.write_text("")

    plan_base = {
        "pageUrl": page_url,
        "settleMs": 12000,
        "waitForDoneMs": 75000,
        "navTimeoutMs": 45000,
        "bypassServiceWorker": False,
        "fetchAllBodies": False,
        "bodyFetchLimit": 24,
        "expectedMarkers": 16,
    }

    sys.path.insert(0, str(CAPTURE.parent))
    from capture import launch_chrome as lc  # noqa: E402

    if not getattr(lc.build_args, "_multi_popup_patch", False):
        _build_args_orig = lc.build_args

        def _build_args_with_popups(*a, **k):
            args = _build_args_orig(*a, **k)
            args.insert(1, "--disable-popup-blocking")
            for i, item in enumerate(args):
                if item.startswith("--host-resolver-rules="):
                    args[i] = (
                        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"
                    )
                    break
            return args

        _build_args_with_popups._multi_popup_patch = True  # type: ignore[attr-defined]
        lc.build_args = _build_args_with_popups
    from capture.launch_chrome import ChromeSession  # noqa: E402

    variants = [("with-wait", True)]
    if not args.only_wait:
        variants.append(("no-wait", False))
    for variant, wait in variants:
        run_dir = out / variant
        run_dir.mkdir(parents=True, exist_ok=True)
        multi_log_path = None
        if args.testserver:
            multi_log_path = str((evidence_dir / f"multi-{variant}" / "multi.jsonl").resolve())
        plan = {
            **plan_base,
            "waitForDebuggerOnStart": wait,
            "multiLogPath": multi_log_path,
        }
        plan_path = run_dir / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n")

        if args.skip_run:
            continue

        profile = run_dir / "chrome-profile"
        netlog = run_dir / "chrome-netlog.json"
        if profile.exists():
            shutil.rmtree(profile, ignore_errors=True)

        if args.smoke:
            server_log.write_text("")
        if args.testserver:
            if server_proc and server_proc.poll() is None:
                server_proc.terminate()
                server_proc.wait(timeout=5)
            free_port(args.port)
            server_proc = subprocess.Popen(
                [
                    str(testserver_bin()),
                    "serve",
                    "--only",
                    "h1",
                    "--h1",
                    f"127.0.0.1:{args.port}",
                    "--evidence",
                    str(evidence_dir),
                    "--run-id",
                    f"multi-{variant}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_http(f"http://127.0.0.1:{args.port}/healthz")
        debug_port = 9222 if variant == "with-wait" else 9223
        chrome = ChromeSession(
            str(profile), str(netlog), port=debug_port, headless=True, ignore_cert_errors=True
        )
        try:
            chrome.start()
            cdp_script = HERE / "cdp_multi_capture.mjs"
            cmd = [
                NODE,
                str(cdp_script),
                "--port",
                str(debug_port),
                "--outdir",
                str(run_dir),
                "--plan",
                str(plan_path),
            ]
            if not wait:
                cmd.append("--no-wait-debugger")
            subprocess.run(cmd, check=True, timeout=240)
        finally:
            chrome.terminate()
            time.sleep(0.5)

        if args.smoke and server_log.exists():
            shutil.copy(server_log, run_dir / "server.jsonl")
        if args.testserver:
            ml = evidence_dir / "multi.jsonl"
            if not ml.exists():
                nested = list(evidence_dir.glob("*/multi.jsonl"))
                ml = nested[0] if nested else ml
            if ml.exists():
                shutil.copy(ml, run_dir / "server.jsonl")

        run_meta = run_dir / "run-meta.json"
        run_meta.write_text(json.dumps({**meta, "variant": variant, "waitForDebuggerOnStart": wait}, indent=2) + "\n")

    if server_proc and server_proc.poll() is None:
        server_proc.terminate()

    analyze_cmd = [PY, str(HERE / "analyze_multi.py"), "--run", str(out / "with-wait"), "--out", str(out / "analysis.json")]
    if not args.only_wait and (out / "no-wait" / "cdp-sessions.json").exists():
        analyze_cmd.insert(-2, str(out / "no-wait"))
        analyze_cmd.insert(-3, "--run-no-wait")
    analyze = subprocess.run(analyze_cmd, check=False)
    (out / "README-snippet.txt").write_text(
        f"page={page_url}\nsource={meta['source']}\nanalyze exit={analyze.returncode}\n"
    )
    print(json.dumps({"out": str(out), "source": meta["source"]}))


if __name__ == "__main__":
    main()
