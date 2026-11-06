#!/usr/bin/env python3
"""Checks the real captures of real_matrix.sh against the core contract (CONTRACT-V1,
"Capture proxy" and "networkState"). Reads only the session.json files and the run logs.

Usage: analyze_real.py <out-dir>  -> prints a table and writes <out-dir>/real-summary.json
"""
from __future__ import annotations

import base64
import collections
import json
import pathlib
import re
import sys

HTTP3_NOTE = "captured through a proxy: HTTP/3 is not used"
CONN_NOTE = "remote endpoint is the proxy, not the site"
PASSWORD = "Pw-Exp-7f3a9Q"
USER = "exp-user"


def describe(run: pathlib.Path) -> dict:
    info: dict = {"name": run.name}
    err = (run / "stderr.txt").read_text(errors="replace") if (run / "stderr.txt").exists() else ""
    info["route_log"] = next((l.split("route: ", 1)[1] for l in err.splitlines() if l.startswith("route: ")), "")
    info["notice"] = next((l for l in err.splitlines() if l.startswith("notice: ")), "")
    info["failure"] = next((l for l in err.splitlines() if "failed" in l or "refused" in l), "")
    sessions = list((run / "session").glob("*/session.json")) + list((run / "session").glob("session.json"))
    if not sessions:
        info["status"] = "no session"
        return info
    d = json.loads(sessions[0].read_text())
    s = d.get("session", {})
    cap = s.get("capture") or {}
    info["status"] = "imported"
    info["proxy"] = cap.get("proxy")
    info["http3_note"] = any(HTTP3_NOTE in n for n in s.get("notes", []))
    reqs = d.get("requests", [])
    info["requests"] = len(reqs)
    info["protocols"] = dict(collections.Counter(r.get("protocol", "?") for r in reqs))
    attempts = [a for r in reqs for a in r.get("attempts", [])]
    info["attempts"] = len(attempts)
    info["attempt_states"] = dict(collections.Counter(a.get("networkState", "-") for a in attempts))
    info["requests_with_netlog"] = sum(1 for r in reqs if (r.get("netlog") or {}).get("sourceIds"))
    info["requests_with_cdp"] = sum(1 for r in reqs if r.get("cdp"))
    conns = d.get("connections", [])
    info["connections"] = len(conns)
    info["connections_with_ip_or_port"] = sum(1 for c in conns if c.get("ip") or c.get("port"))
    info["connection_protocols"] = dict(collections.Counter(c.get("protocol", "?") for c in conns))
    info["connection_note"] = sum(1 for c in conns if any(CONN_NOTE in n for n in c.get("provenance", {}).get("notes", [])))
    info["warning_codes"] = dict(collections.Counter(w.get("code") for w in d.get("warnings", [])))
    args = cap.get("chromeArgs") or []
    info["chrome_proxy_args"] = [a for a in args if "proxy" in a or "webrtc" in a or "host-resolver" in a]
    # Secret scan of the whole capture folder (session, streams, logs).
    scan = {}
    for needle_name, needle in (("password", PASSWORD), ("base64", base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode())):
        hits = [str(p.relative_to(run)) for p in run.rglob("*") if p.is_file() and needle.encode() in p.read_bytes()]
        scan[needle_name] = hits
    info["secret_hits"] = scan
    return info


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    rows = [describe(p) for p in sorted((out / "real").iterdir()) if p.is_dir()]
    (out / "real-summary.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False))
    for r in rows:
        proxy = r.get("proxy") or {}
        print(f"{r['name']:20} {r['status']:9} proxy={proxy.get('scheme','-')}/{proxy.get('route','-')}/auth={proxy.get('authenticated','-')} "
              f"req={r.get('requests','-')} att={r.get('attempts','-')} states={r.get('attempt_states','-')} "
              f"proto={r.get('protocols','-')} conn={r.get('connections','-')} ip/port={r.get('connections_with_ip_or_port','-')} "
              f"h3note={r.get('http3_note','-')} secret={sum(len(v) for v in r.get('secret_hits',{}).values()) if r.get('secret_hits') else '-'}")


if __name__ == "__main__":
    main()
