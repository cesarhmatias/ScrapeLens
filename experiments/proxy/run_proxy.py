#!/usr/bin/env python3
"""Proxy fidelity experiment: the same synthetic page through five routes.

Variants (all targets are names: site-a.test, site-b.test, served by origin.py):
  direct            no proxy; Chrome maps the names with --host-resolver-rules
  socks-open        Chrome -> upstream SOCKS5 (no credentials), the proxy-link route without auth
  relay-open        Chrome -> relay (no auth) -> direct connect; the relay without credentials
  relay-socks-auth  Chrome -> relay -> upstream SOCKS5 with user/pass (credentials only in the relay)
  relay-http-auth   Chrome -> relay -> upstream HTTP CONNECT with Basic auth

Writes results/<variant>/ with origin.jsonl, relay/upstream logs, chrome-netlog.json,
cdp-events.jsonl, webrtc report and run.json. Test-only: loopback, synthetic names,
dedicated temporary profile, Chrome started and stopped by this script.

Usage: run_proxy.py [--variant NAME ...] [--out DIR]
Env: CHROME (default Google Chrome.app), UP_USER/UP_PASS and RELAY_USER/RELAY_PASS are set
by this script with a distinctive test password; no secret goes into Chrome's argv.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
EXP = HERE.parent
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
NODE = shutil.which("node") or "/opt/homebrew/bin/node"
ORIGIN_PORT = 18701
UP_PORT = 18702      # upstream SOCKS5 (open or with auth)
UP_HTTP_PORT = 18703 # upstream HTTP CONNECT (with auth)
RELAY_PORT = 18704
DEBUG_PORT = 19457
USER, PASSWORD = "exp-user", "Pw-Exp-7f3a9Q"
RESOLVE = {"site-a.test": "127.0.0.1", "site-b.test": "127.0.0.1"}
PAGES = ["http://site-a.test:18701/page", "http://site-a.test:18701/webrtc"]

VARIANTS = {
    "direct": dict(chrome_proxy=None),
    "socks-open": dict(chrome_proxy=f"socks5://127.0.0.1:{UP_PORT}", upstream="socks-open"),
    "relay-open": dict(chrome_proxy=f"socks5://127.0.0.1:{RELAY_PORT}", relay=("none", None)),
    "relay-socks-auth": dict(chrome_proxy=f"socks5://127.0.0.1:{RELAY_PORT}",
                             relay=("socks-auth", f"127.0.0.1:{UP_PORT}"), upstream="socks-auth"),
    "relay-http-auth": dict(chrome_proxy=f"socks5://127.0.0.1:{RELAY_PORT}",
                            relay=("http-auth", f"127.0.0.1:{UP_HTTP_PORT}"), upstream="http-auth"),
}


def spawn(args: list[str], env: dict | None = None, log: pathlib.Path | None = None) -> subprocess.Popen:
    out = open(log, "w") if log else subprocess.DEVNULL
    return subprocess.Popen(args, stdout=subprocess.PIPE if log is None else out,
                            stderr=subprocess.STDOUT, text=True, env=env)


def wait_ready(proc: subprocess.Popen, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("READY"):
            return
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early: {proc.returncode}")
    raise RuntimeError("timeout waiting for READY")


def wait_devtools(timeout: float = 45) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json/version", timeout=2):
                return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError("DevTools did not come up")


def run_variant(name: str, out: pathlib.Path) -> dict:
    spec = VARIANTS[name]
    vdir = out / name
    if vdir.exists():
        shutil.rmtree(vdir)
    vdir.mkdir(parents=True)
    origin_log = vdir / "origin.jsonl"
    proxy_log = vdir / "proxy.jsonl"
    procs: list[subprocess.Popen] = []
    chrome = None
    profile = pathlib.Path(tempfile.mkdtemp(prefix="sl-proxy-profile-", dir=vdir))
    try:
        origin = spawn([sys.executable, str(HERE / "origin.py"), "--port", str(ORIGIN_PORT), "--log", str(origin_log)])
        procs.append(origin); wait_ready(origin)
        chrome_args = [
            f"--user-data-dir={profile}",
            f"--log-net-log={vdir / 'chrome-netlog.json'}",
            "--net-log-capture-mode=Everything",
            "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--disable-default-apps",
            "--disable-extensions", "--password-store=basic", "--use-mock-keychain",
            "--disable-popup-blocking", "--enable-quic", "--metrics-recording-only",
            "--no-service-autorun", "--no-pings", "--disable-breakpad", "--disable-domain-reliability",
            "--disable-client-side-phishing-detection", "--disable-search-engine-choice-screen",
            "--disable-component-extensions-with-background-pages",
            "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions",
            f"--remote-debugging-port={DEBUG_PORT}", "--remote-debugging-address=127.0.0.1",
            "--headless=new", "about:blank",
        ]
        env = dict(os.environ, UP_USER=USER, UP_PASS=PASSWORD, RELAY_USER=USER, RELAY_PASS=PASSWORD)
        if spec.get("upstream"):
            kind = spec["upstream"]
            port = UP_HTTP_PORT if kind == "http-auth" else UP_PORT
            ukind = "http-auth" if kind == "http-auth" else ("socks-auth" if kind == "socks-auth" else "socks-open")
            up = spawn([sys.executable, str(HERE / "proxies.py"), "upstream", "--kind", ukind, "--port", str(port),
                        "--log", str(proxy_log), "--map", json.dumps(RESOLVE)], env=env)
            procs.append(up); wait_ready(up)
        if spec.get("relay"):
            rkind, upstream = spec["relay"]
            relay = spawn([sys.executable, str(HERE / "proxies.py"), "relay", "--port", str(RELAY_PORT),
                           "--log", str(proxy_log), "--upstream-kind", rkind,
                           "--upstream", upstream or "", "--map", json.dumps(RESOLVE)], env=env)
            procs.append(relay); wait_ready(relay)
        if spec["chrome_proxy"] and os.environ.get("PROXY_PREFS", "1") == "1":
            # Preferences of the dedicated profile (not system policy): secure DNS off,
            # WebRTC kept behind the proxy.
            (profile / "Local State").write_text(json.dumps({"dns_over_https": {"mode": "off"}}))
            (profile / "Default").mkdir(exist_ok=True)
            (profile / "Default" / "Preferences").write_text(json.dumps({"webrtc": {
                "ip_handling_policy": "disable_non_proxied_udp",
                "multiple_routes_enabled": False,
                "nonproxied_udp_enabled": False}}))
        chrome_args += [a for a in os.environ.get("EXTRA_CHROME_ARGS", "").split() if a]
        if spec["chrome_proxy"]:
            chrome_args.append(f"--proxy-server={spec['chrome_proxy']}")
            chrome_args.append("--proxy-bypass-list=<-loopback>")
            chrome_args.append("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        else:
            chrome_args.append("--host-resolver-rules=MAP site-a.test 127.0.0.1, MAP site-b.test 127.0.0.1")
        chrome = subprocess.Popen([CHROME, *chrome_args], stdout=subprocess.DEVNULL, stderr=open(vdir / "chrome-stderr.txt", "w"))
        wait_devtools()
        plan = vdir / "plan.json"
        plan.write_text(json.dumps({"urls": PAGES, "settleMs": 5000, "navTimeoutMs": 20000}))
        rc = subprocess.run([NODE, str(EXP / "capture" / "cdp_capture.mjs"), "--port", str(DEBUG_PORT),
                             "--outdir", str(vdir), "--plan", str(plan)], capture_output=True, text=True, timeout=180)
        (vdir / "cdp-stdout.txt").write_text(rc.stdout + rc.stderr)
    finally:
        if chrome and chrome.poll() is None:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        shutil.rmtree(profile, ignore_errors=True)
    info = {"variant": name, "chrome_proxy": spec["chrome_proxy"], "relay": spec.get("relay")}
    (vdir / "run.json").write_text(json.dumps(info, indent=2))
    return info


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", action="append", choices=sorted(VARIANTS))
    ap.add_argument("--out", default=str(HERE / "results"))
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in args.variant or list(VARIANTS):
        print("==", name, flush=True)
        print(json.dumps(run_variant(name, out)), flush=True)


if __name__ == "__main__":
    main()
