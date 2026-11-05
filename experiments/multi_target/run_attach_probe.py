#!/usr/bin/env python3
"""Probes recursive setAutoAttach (OOPIF + worker) in headless/headful modes."""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
PY = shutil.which("python3") or "python3"
NODE = shutil.which("node") or "node"

sys.path.insert(0, str(HERE.parent / "capture"))
import launch_chrome as lc  # noqa: E402
from launch_chrome import ChromeSession  # noqa: E402

from run_multi import free_port, testserver_bin, wait_http  # noqa: E402

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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8782)
    ap.add_argument("--out", type=pathlib.Path, default=HERE.parent / "results" / "multi-target-attach-probe")
    ap.add_argument("--modes", default="headless,headful", help="comma-separated")
    args = ap.parse_args()

    page_url = f"http://127.0.0.1:{args.port}/multi/"
    evidence = args.out / "testserver-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    free_port(args.port)
    server = subprocess.Popen(
        [
            str(testserver_bin()),
            "serve",
            "--only",
            "h1",
            "--h1",
            f"127.0.0.1:{args.port}",
            "--evidence",
            str(evidence),
            "--run-id",
            "attach-probe",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_http(f"http://127.0.0.1:{args.port}/healthz")
        wait_http(page_url)
        results = {}
        for mode in [m.strip() for m in args.modes.split(",") if m.strip()]:
            run_dir = args.out / mode
            run_dir.mkdir(parents=True, exist_ok=True)
            profile = run_dir / "chrome-profile"
            if profile.exists():
                shutil.rmtree(profile, ignore_errors=True)
            debug_port = 9244 if mode == "headless" else 9245
            free_port(debug_port)
            chrome = ChromeSession(
                str(profile),
                str(run_dir / "chrome-netlog.json"),
                port=debug_port,
                headless=(mode == "headless"),
                ignore_cert_errors=True,
            )
            try:
                chrome.start()
                subprocess.run(
                    [
                        NODE,
                        str(HERE / "cdp_recursive_attach_probe.mjs"),
                        "--port",
                        str(debug_port),
                        "--outdir",
                        str(run_dir),
                        "--page-url",
                        page_url,
                    ],
                    check=True,
                    timeout=150,
                )
            finally:
                chrome.terminate()
                time.sleep(0.5)
            summary_path = run_dir / "probe-summary.json"
            if summary_path.exists():
                results[mode] = json.loads(summary_path.read_text())
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "compare.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps({"out": str(args.out), "modes": list(results.keys())}))
    finally:
        if server.poll() is None:
            server.terminate()


if __name__ == "__main__":
    main()
