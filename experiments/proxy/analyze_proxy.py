#!/usr/bin/env python3
"""Compares the proxy variants: wire header order at the origin, route coverage, WebRTC, secrets.

Usage: analyze_proxy.py --out DIR [--password X --user Y]
Output: DIR/summary.json and a printed table. Reads only the files that run_proxy.py wrote.
"""
from __future__ import annotations

import argparse
import base64
import collections
import json
import pathlib
import re

VARIANTS = ["direct", "socks-open", "relay-open", "relay-socks-auth", "relay-http-auth"]
PROXIED = VARIANTS[1:]


def origin_records(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def wire_signature(records: list[dict]) -> dict[str, list[list[str]]]:
    """request line -> list of header-name sequences, in arrival order per request."""
    out: dict[str, list[list[str]]] = collections.defaultdict(list)
    for r in records:
        out[r["request_line"]].append([name for name, _ in r["headers"]])
    return out


def wire_full(records: list[dict]) -> dict[str, list[tuple]]:
    """request line -> sorted multiset of header lists. Arrival order across concurrent
    requests is not deterministic, so requests are compared as a multiset. Content-Length
    of the WebRTC report varies with random ICE values, so it is excluded for that path."""
    out: dict[str, list[tuple]] = collections.defaultdict(list)
    for r in records:
        pairs = [[n, v] for n, v in r["headers"]
                 if not (r["request_line"].startswith("POST /report") and n.lower() == "content-length")]
        out[r["request_line"]].append(tuple(tuple(p) for p in pairs))
    return {k: sorted(v) for k, v in out.items()}


def netlog_hosts(path: pathlib.Path) -> set[str]:
    if not path.exists():
        return set()
    text = path.read_text(errors="replace")
    hosts = set()
    for m in re.finditer(r'"url"\s*:\s*"(https?|wss?)://([^"/\s]+)', text):
        host = m.group(2)
        if "@" in host:
            continue
        hosts.add(host if ":" in host.split("]")[-1] else host + (":443" if m.group(1) in ("https", "wss") else ":80"))
    return hosts


def connect_ok(path: pathlib.Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        e = json.loads(line)
        if e.get("event") == "connect" and e.get("result") == "ok":
            out.add(f"{e['host']}:{e['port']}")
    return out


def webrtc_candidates(records: list[dict]) -> dict:
    kinds = collections.Counter()
    for r in records:
        if r["request_line"].startswith("POST /report") and r["body"].strip().startswith("{"):
            body = json.loads(r["body"])
            for c in body.get("cands", []):
                m = re.search(r" typ (\w+)", c)
                kinds[m.group(1) if m else "?"] += 1
    return dict(kinds)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--password", default="Pw-Exp-7f3a9Q")
    ap.add_argument("--user", default="exp-user")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    summary: dict = {}
    base = wire_full(origin_records(out / "direct" / "origin.jsonl"))
    for v in VARIANTS:
        d = out / v
        recs = origin_records(d / "origin.jsonl")
        sig = wire_signature(recs)
        full = wire_full(recs)
        same_as_direct = full == base
        diffs = sorted(k for k in set(base) | set(full) if base.get(k) != full.get(k))
        hosts = netlog_hosts(d / "chrome-netlog.json")
        conns = connect_ok(d / "proxy.jsonl")
        missing = sorted(h for h in hosts if h not in conns) if v in PROXIED else []
        summary[v] = {
            "origin_requests": len(recs),
            "wire_identical_to_direct": same_as_direct,
            "wire_diff_request_lines": diffs,
            "netlog_hosts": len(hosts),
            "proxy_ok_connects": len(conns),
            "netlog_hosts_not_seen_by_proxy": missing,
            "webrtc_candidates": webrtc_candidates(recs),
            "site_hosts_via_proxy": sorted(h for h in conns if "site-" in h),
        }
    # secrets in every output file and stream of the variants
    needles = {"password": args.password.encode(),
               "base64_user_pass": base64.b64encode(f"{args.user}:{args.password}".encode())}
    leaks = {}
    for v in VARIANTS:
        d = out / v
        for name, needle in needles.items():
            hits = [str(p.relative_to(out)) for p in d.rglob("*") if p.is_file() and needle in p.read_bytes()]
            leaks[f"{v}:{name}"] = hits
    summary["secret_hits"] = {k: len(v) for k, v in leaks.items()}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    for v in VARIANTS:
        s = summary[v]
        print(f"{v:18} req={s['origin_requests']:3} wire_identical={s['wire_identical_to_direct']!s:5} "
              f"netlog_hosts={s['netlog_hosts']:3} proxy_ok={s['proxy_ok_connects']:3} "
              f"not_via_proxy={len(s['netlog_hosts_not_seen_by_proxy'])} webrtc={s['webrtc_candidates']}")
    print("secret hits:", summary["secret_hits"])


if __name__ == "__main__":
    main()
