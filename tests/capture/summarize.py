#!/usr/bin/env python3
"""Summarizes a tests/capture/run-cycle.sh run into run.json.

Reads the sessions imported by the core, counts requests/ambiguous/redirects and
records Chrome flags, sizes and commands. No network is used.

Usage: summarize.py RUN_DIR --chrome-version "..." --ports 9781
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "target" / "release" / "scrapelens-core"


def inspect(session_dir: pathlib.Path) -> dict:
    proc = subprocess.run([str(CORE), "inspect", str(session_dir)], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"inspect {session_dir}: {proc.stderr}")
    return json.loads(proc.stdout)["session"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir")
    parser.add_argument("--chrome-version", default="unknown")
    parser.add_argument("--ports", default="9781")
    args = parser.parse_args()
    run = pathlib.Path(args.run_dir).resolve()

    captures = []
    totals = {"requests": 0, "ambiguous": 0, "redirects": 0, "h3StreamSessions": 0,
              "verifiedViews": 0, "matched": 0, "unmatched": 0}
    for name, protocol in (("h1h2", "h2"), ("h3", "h3")):
        session_dir = run / f"session-{name}"
        meta_path = run / f"{name}.meta.json"
        if not session_dir.exists() or not meta_path.exists():
            continue
        session = inspect(session_dir)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        requests = session["requests"]
        ambiguous = sum(1 for request in requests if request.get("match") == "ambiguous")
        redirects = sum(len(request.get("redirects", [])) for request in requests)
        h3_streams = len(session.get("streamSessions", []))
        verified = sum(1 for request in requests
                       if any(entry.get("verification") == "verified"
                              for entry in request["requestHeaders"].get("headers", [])))
        totals["requests"] += len(requests)
        totals["ambiguous"] += ambiguous
        totals["redirects"] += redirects
        totals["h3StreamSessions"] += h3_streams
        totals["verifiedViews"] += verified
        totals["matched"] += sum(1 for request in requests if request.get("match") == "matched")
        totals["unmatched"] += sum(1 for request in requests if request.get("match") == "unmatched")
        captures.append({
            "name": name,
            "protocol": protocol,
            "session": f"session-{name}",
            "requests": len(requests),
            "protocols": sorted({request["protocol"] for request in requests}),
            "matched": sum(1 for request in requests if request.get("match") == "matched"),
            "ambiguous": ambiguous,
            "unmatched": sum(1 for request in requests if request.get("match") == "unmatched"),
            "redirects": redirects,
            "streamSessions": h3_streams,
            "verifiedRequestViews": verified,
            "completeness": session["session"]["completeness"]["state"],
            "netlogBytes": meta.get("netlogBytes"),
            "cdpBytes": meta.get("cdpBytes"),
            "meta": meta,
            "sessionSha256": hashlib.sha256(
                (session_dir / "session.json").read_bytes()).hexdigest(),
        })

    har = None
    har_dir = run / "session-har"
    if har_dir.exists():
        session = inspect(har_dir)
        har = {"session": "session-har", "requests": len(session["requests"]),
               "labels": session["session"].get("labels", []),
               "completeness": session["session"]["completeness"]["state"]}

    summary = {
        "runId": run.name,
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "chromeVersion": args.chrome_version.replace("Google Chrome ", "").strip(),
        "ports": int(args.ports),
        "certificateInstalled": False,
        "networkPolicy": "Chrome with --host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "captures": captures,
        "har": har,
        **{key: totals[key] for key in ("requests", "ambiguous", "redirects",
                                        "h3StreamSessions", "verifiedViews",
                                        "matched", "unmatched")},
        "requestCount": totals["requests"],
        "commands": [
            "tests/capture/run-cycle.sh",
            "node tests/capture/capture_cycle.mjs --outdir RUN --name h1h2 ...",
            "scrapelens-core import-capture RUN/h1h2.cdp-events.jsonl RUN/h1h2.chrome-netlog.json --out RUN/session-h1h2",
            "scrapelens-core import-capture RUN/h3.cdp-events.jsonl RUN/h3.chrome-netlog.json --out RUN/session-h3",
        ],
    }
    (run / "run.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n",
                                  encoding="utf-8")
    print(f"captures: {len(captures)} · requests: {totals['requests']} · "
          f"ambiguous: {totals['ambiguous']} · redirects: {totals['redirects']} · "
          f"h3 streams: {totals['h3StreamSessions']}")
    for capture in captures:
        print(f"  {capture['name']:5} {capture['protocol']:2} {capture['requests']:3} req "
              f"{capture['protocols']} completeness={capture['completeness']} "
              f"ambiguous={capture['ambiguous']} verified={capture['verifiedRequestViews']}")
    if har:
        print(f"  HAR   imported: {har['requests']} requests ({har['completeness']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
