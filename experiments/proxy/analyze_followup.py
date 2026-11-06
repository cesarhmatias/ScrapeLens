#!/usr/bin/env python3
"""Reads a followup.sh directory. Prints protocol, pairing and secret hits.

For each capture: session protocol counts, CDP response.protocol values, NetLog event
names that mention HTTP2 or a proxy, and which /multi/ markers were paired (CDP and
NetLog both present). Scans every file for the synthetic password and its Base64.
"""
from __future__ import annotations

import base64
import collections
import json
import pathlib
import sys

PASSWORD = "Pw-Exp-7f3a9Q"
USER = "exp-user"
MARKERS = (
    "main-1",
    "main-post-1",
    "popup-1",
    "popup-get-1",
    "popup-post-1",
    "blank-1",
    "blank-get-1",
    "blank-post-1",
    "oopif-1",
    "oopif-get-1",
    "oopif-post-1",
    "worker-get-1",
    "worker-post-1",
    "sw-intercept-1",
    "sw-own-1",
    "sw-own-post-1",
)


def load_json(path: pathlib.Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(errors="replace"))


def session_file(run: pathlib.Path):
    direct = run / "session.json"
    if direct.is_file():
        return direct
    found = sorted(run.rglob("session.json"))
    return found[0] if found else None


def netlog_names(path: pathlib.Path) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    data = load_json(path)
    if not isinstance(data, dict):
        return counts
    types = (data.get("constants") or {}).get("logEventTypes") or {}
    id_to_name = {}
    if isinstance(types, dict):
        for name, number in types.items():
            if isinstance(number, int):
                id_to_name[number] = name
    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        raw = event.get("type")
        name = raw if isinstance(raw, str) else id_to_name.get(raw, "")
        if not name:
            continue
        if "HTTP2" in name or "PROXY" in name or name.startswith("SSL_") or "TUNNEL" in name:
            counts[name] += 1
    return counts


def cdp_protocols(path: pathlib.Path) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    if not path.is_file():
        return counts
    for line in path.read_text(errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("method") != "Network.responseReceived":
            continue
        protocol = ((value.get("params") or {}).get("response") or {}).get("protocol")
        if protocol:
            counts[str(protocol)] += 1
    return counts


def describe(run: pathlib.Path) -> dict:
    info: dict = {"name": run.name}
    err = (run / "stderr.txt").read_text(errors="replace") if (run / "stderr.txt").exists() else ""
    info["notice"] = next((line for line in err.splitlines() if line.startswith("notice: ")), "")
    info["failure"] = next((line for line in err.splitlines() if "failed" in line or "refused" in line or "trust" in line), "")
    session_path = session_file(run)
    if session_path is None:
        info["status"] = "no session"
    else:
        info["status"] = "imported"
        data = json.loads(session_path.read_text())
        requests = data.get("requests") or []
        info["requests"] = len(requests)
        info["protocols"] = dict(collections.Counter(r.get("protocol", "?") for r in requests))
        info["paired"] = sum(1 for r in requests if r.get("cdp") and (r.get("netlog") or {}).get("sourceIds"))
        info["cdp_only"] = sum(1 for r in requests if r.get("cdp") and not (r.get("netlog") or {}).get("sourceIds"))
        info["warning_codes"] = dict(collections.Counter(w.get("code") for w in data.get("warnings") or []))
        markers = {}
        for marker in MARKERS:
            # The marker is a query value (`m=worker-get-1`) or the resource name.
            hits = [
                r
                for r in requests
                if f"m={marker}" in (r.get("url") or "") or f"/{marker}" in (r.get("url") or "")
            ]
            if hits:
                markers[marker] = {
                    "n": len(hits),
                    "cdp": sum(1 for r in hits if r.get("cdp")),
                    "netlog": sum(1 for r in hits if (r.get("netlog") or {}).get("sourceIds")),
                    "protocol": dict(collections.Counter(r.get("protocol", "?") for r in hits)),
                }
        info["markers"] = markers
        folder = session_path.parent
        info["cdp_response_protocol"] = dict(cdp_protocols(folder / "cdp-events.jsonl"))
        interesting = netlog_names(folder / "netlog.json")
        info["netlog_http2"] = {k: v for k, v in interesting.items() if "HTTP2" in k}
        info["netlog_proxy"] = {k: v for k, v in interesting.items() if "PROXY" in k or "TUNNEL" in k}
    scan = {}
    token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    for needle_name, needle in (("password", PASSWORD), ("base64", token)):
        hits = []
        for path in run.rglob("*"):
            if path.is_file() and needle.encode() in path.read_bytes():
                hits.append(str(path.relative_to(run)))
        scan[needle_name] = hits
    info["secret_hits"] = scan
    return info


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    rows = []
    for run in sorted(p for p in out.iterdir() if p.is_dir() and (p / "stderr.txt").is_file()):
        rows.append(describe(run))
    (out / "followup-summary.json").write_text(json.dumps(rows, indent=2))
    for row in rows:
        print(
            f"{row['name']:20} {row['status']:10} req={row.get('requests', '-')} "
            f"proto={row.get('protocols', '-')} paired={row.get('paired', '-')} "
            f"cdp_only={row.get('cdp_only', '-')} cdp_proto={row.get('cdp_response_protocol', '-')} "
            f"h2_events={row.get('netlog_http2', '-')} secrets={sum(len(v) for v in row['secret_hits'].values())}"
        )
        if row.get("markers"):
            missing_pair = [m for m, info in row["markers"].items() if info["cdp"] == 0 or info["netlog"] == 0]
            print(f"  markers={sorted(row['markers'])} unpaired={missing_pair}")
        if row.get("notice"):
            print(f"  {row['notice'][:240]}")
        if row.get("failure") and row["status"] != "imported":
            print(f"  {row['failure'][:240]}")


if __name__ == "__main__":
    main()
