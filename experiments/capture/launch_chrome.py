#!/usr/bin/env python3
"""Chrome launcher for capture experiments.

Safety rules applied here:
  * dedicated, temporary --user-data-dir (never the personal profile);
  * debug exposed only on 127.0.0.1;
  * terminates only the PID this module started;
  * self-signed certificate waived by SPKI hash (nothing is installed).

Direct use (launcher only):
  python3 launch_chrome.py --profile /tmp/x --netlog /tmp/n.json [--headless]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
DEBUG_HOST = "127.0.0.1"
DEBUG_PORT = 9222


def build_args(
    profile_dir: str,
    netlog_path: str,
    *,
    port: int = DEBUG_PORT,
    headless: bool = True,
    spki: str | None = None,
    force_quic_origin: str | None = None,
    ignore_cert_errors: bool = False,
) -> list[str]:
    args = [
        CHROME,
        f"--user-data-dir={profile_dir}",
        f"--remote-debugging-port={port}",
        f"--remote-debugging-address={DEBUG_HOST}",
        f"--log-net-log={netlog_path}",
        "--net-log-capture-mode=Everything",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-extensions",
        "--metrics-recording-only",
        "--no-service-autorun",
        "--no-pings",
        "--disable-breakpad",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--disable-component-extensions-with-background-pages",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-search-engine-choice-screen",
        "--disable-features=Translate,MediaRouter,OptimizationHints,InterestFeedContentSuggestions",
        "--enable-quic",
        "--allow-insecure-localhost",
        "about:blank",
    ]
    if spki:
        args.insert(1, f"--ignore-certificate-errors-spki-list={spki}")
    if ignore_cert_errors:
        args.insert(1, "--ignore-certificate-errors")
    if force_quic_origin:
        args.insert(1, f"--origin-to-force-quic-on={force_quic_origin}")
    if headless:
        args.insert(1, "--headless=new")
    return args


class ChromeSession:
    def __init__(
        self,
        profile_dir: str,
        netlog_path: str,
        *,
        port: int = DEBUG_PORT,
        headless: bool = True,
        spki: str | None = None,
        force_quic_origin: str | None = None,
        ignore_cert_errors: bool = False,
    ) -> None:
        self.profile_dir = profile_dir
        self.netlog_path = netlog_path
        self.port = port
        self.args = build_args(
            profile_dir,
            netlog_path,
            port=port,
            headless=headless,
            spki=spki,
            force_quic_origin=force_quic_origin,
            ignore_cert_errors=ignore_cert_errors,
        )
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, timeout: float = 30.0) -> dict:
        pathlib.Path(self.profile_dir).mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.pop("CHROME_USER_DATA_DIR", None)
        self.proc = subprocess.Popen(
            self.args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
        deadline = time.time() + timeout
        last: Exception | None = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Chrome exited immediately (rc={self.proc.returncode})")
            try:
                with urllib.request.urlopen(f"http://{DEBUG_HOST}:{self.port}/json/version", timeout=1) as r:
                    return json.loads(r.read().decode())
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(0.2)
        raise RuntimeError(f"DevTools did not respond within {timeout}s: {last}")

    def wait_exit(self, timeout: float = 25.0) -> int | None:
        if self.proc is None:
            return None
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def terminate(self) -> None:
        """Terminates only the process started here (and its children in the same group)."""
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            return
        if self.wait_exit(10) is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.wait_exit(5)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", help="dedicated data directory (default: temporary)")
    ap.add_argument("--netlog", required=True)
    ap.add_argument("--port", type=int, default=DEBUG_PORT)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--spki")
    ap.add_argument("--force-quic-origin", default="127.0.0.1:8783")
    args = ap.parse_args()
    profile = args.profile or tempfile.mkdtemp(prefix="scrapelens-profile-")
    session = ChromeSession(
        profile,
        args.netlog,
        port=args.port,
        headless=args.headless,
        spki=args.spki,
        force_quic_origin=args.force_quic_origin,
    )
    version = session.start()
    print(json.dumps({"pid": session.proc.pid, "profile": profile, "version": version}, indent=2))
    try:
        session.proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        session.terminate()
        if args.profile is None:
            shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    main()
