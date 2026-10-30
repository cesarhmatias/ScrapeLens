#!/usr/bin/env python3
"""Analisa captura multi-alvo: NetLog × CDP × log do servidor por marcador ?m=."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import urllib.parse
from urllib.parse import parse_qs, urlparse

MARKER_RE = re.compile(r"[?&]m=([^&#]+)")

EXPECTED_MARKERS = [
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
]


def marker_from_url(url: str) -> str | None:
    m = MARKER_RE.search(url)
    return urllib.parse.unquote(m.group(1)) if m else None


def load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def load_cdp_events(path: pathlib.Path) -> list[dict]:
    return load_jsonl(path)


def netlog_urls(netlog: dict) -> list[dict]:
    types = {v: k for k, v in netlog.get("constants", {}).get("logEventTypes", {}).items()}
    out = []
    for ev in netlog.get("events", []):
        name = types.get(ev["type"], str(ev["type"]))
        if name not in (
            "URL_REQUEST_START_JOB",
            "HTTP_TRANSACTION_SEND_REQUEST_HEADERS",
            "HTTP2_SESSION_SEND_HEADERS",
            "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS",
        ):
            continue
        params = ev.get("params") or {}
        url = params.get("url") or params.get("request_url") or ""
        if not url and "headers" in params:
            for h in params["headers"]:
                if h.startswith(":path:"):
                    url = h.split(":", 2)[-1].strip()
        if url and ("127.0.0.1" in url or "localhost" in url):
            mk = marker_from_url(url)
            if mk:
                out.append({"marker": mk, "url": url, "event": name})
    seen = set()
    dedup = []
    for row in out:
        k = (row["marker"], row["url"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(row)
    return dedup


def cdp_by_marker(events: list[dict], sessions: dict) -> dict[str, list[dict]]:
    by_marker: dict[str, list[dict]] = {}
    extra_order: dict[str, list[str]] = {}
    responses: dict[tuple[str, str], dict] = {}

    for row in events:
        method = row.get("method")
        sid = row.get("session") or ""
        p = row.get("params") or {}
        if method == "Network.requestWillBeSent":
            url = p.get("request", {}).get("url", "")
            mk = marker_from_url(url)
            if not mk:
                continue
            by_marker.setdefault(mk, []).append(
                {
                    "sessionId": sid,
                    "requestId": p.get("requestId"),
                    "url": url,
                    "sessionType": sessions.get(sid, {}).get("type"),
                }
            )
        elif method == "Network.requestWillBeSentExtraInfo":
            rid = p.get("requestId")
            assoc = p.get("associatedCookies")
            headers = p.get("headers") or {}
            order = list(headers.keys()) if isinstance(headers, dict) else []
            extra_order[f"{sid}\0{rid}"] = order
        elif method == "Network.responseReceived":
            rid = p.get("requestId")
            resp = p.get("response") or {}
            responses[f"{sid}\0{rid}"] = {
                "fromServiceWorker": resp.get("fromServiceWorker"),
                "serviceWorkerResponseSource": resp.get("serviceWorkerResponseSource"),
            }

    enriched = {}
    for mk, rows in by_marker.items():
        enriched[mk] = []
        for r in rows:
            key = f"{r['sessionId']}\0{r['requestId']}"
            enriched[mk].append({**r, "extraHeaderOrder": extra_order.get(key), "response": responses.get(key)})
    return enriched


def server_markers(server_log: list[dict]) -> set[str]:
    out = set()
    for row in server_log:
        mk = row.get("marker") or row.get("m")
        if not mk:
            mk = marker_from_url(row.get("target", "") or row.get("path", ""))
        if mk:
            out.add(mk)
    return out


def classify_marker(mk: str) -> str:
    if mk.startswith("popup"):
        return "popup"
    if mk.startswith("blank"):
        return "target_blank"
    if mk.startswith("oopif") or mk.startswith("oophif"):
        return "oophif"
    if mk.startswith("worker"):
        return "dedicated_worker"
    if mk.startswith("sw-") or mk.startswith("sw_"):
        return "service_worker"
    if mk.startswith("page") or mk.startswith("main"):
        return "page"
    return "other"


def server_request_headers(server_log: list[dict], marker: str) -> list[str] | None:
    for row in server_log:
        if row.get("marker") != marker or row.get("method") not in ("GET", "POST"):
            continue
        hdrs = row.get("headers") or []
        return [h[0].lower() for h in hdrs if isinstance(h, (list, tuple)) and len(h) >= 1]
    return None


def header_order_match(server_log: list[dict], cdp_extra: list[str] | None, marker: str) -> str:
    if not cdp_extra:
        return "não verificado"
    srv = server_request_headers(server_log, marker)
    if not srv:
        return "sem referência no servidor"
    cdp_lower = [h.lower() for h in cdp_extra]
    srv_set = [h for h in srv if h in cdp_lower]
    cdp_filtered = [h for h in cdp_lower if h in srv]
    if srv_set == cdp_filtered:
        return "conjunto idêntico (ExtraInfo ordena ASCII; servidor grava ordem do fio)"
    return "conjunto difere"


def analyze_run(run_dir: pathlib.Path) -> dict:
    sessions_meta = json.loads((run_dir / "cdp-sessions.json").read_text())
    sessions = {s["sessionId"]: s for s in sessions_meta.get("sessions", [])}
    events = load_cdp_events(run_dir / "cdp-events.jsonl")
    server_log = load_jsonl(run_dir / "server.jsonl")
    bodies = load_jsonl(run_dir / "cdp-bodies.jsonl")
    netlog_path = run_dir / "chrome-netlog.json"
    netlog_hits = []
    if netlog_path.exists():
        netlog = json.loads(netlog_path.read_text())
        netlog_hits = netlog_urls(netlog)

    cdp = cdp_by_marker(events, sessions)
    server_m = server_markers(server_log)
    all_markers = sorted(server_m | set(cdp.keys()) | {r["marker"] for r in netlog_hits})

    rows = []
    for mk in all_markers:
        kind = classify_marker(mk)
        cdp_rows = cdp.get(mk, [])
        net = [r for r in netlog_hits if r["marker"] == mk]
        on_server = mk in server_m
        on_cdp = len(cdp_rows) > 0
        on_netlog = len(net) > 0
        extra = cdp_rows[0].get("extraHeaderOrder") if cdp_rows else None
        order_verdict = header_order_match(server_log, extra, mk) if extra else "n/a"
        body_row = next((b for b in bodies if marker_from_url(b.get("url", "")) == mk), None)
        srv_body = next((r for r in server_log if r.get("marker") == mk), None)
        bodies_ok = None
        if body_row and not body_row.get("skipped"):
            bodies_ok = body_row.get("responseBodyAvailable") or body_row.get("postDataAvailable")
        elif srv_body and srv_body.get("body_text"):
            bodies_ok = True
        elif srv_body and srv_body.get("body_b64"):
            bodies_ok = True

        sw_info = None
        if cdp_rows:
            sw_info = cdp_rows[0].get("response")

        rows.append(
            {
                "marker": mk,
                "target_kind": kind,
                "server": on_server,
                "netlog": on_netlog,
                "cdp": on_cdp,
                "cdp_sessions": [
                    {"sessionId": r["sessionId"][:8], "type": r.get("sessionType"), "requestId": r["requestId"]}
                    for r in cdp_rows
                ],
                "headers_extra_info": "sim" if extra else ("não" if on_cdp else "n/a"),
                "header_order_vs_server": order_verdict,
                "bodies_cdp": bodies_ok if body_row else ("n/a" if not on_cdp else False),
                "fromServiceWorker": (sw_info or {}).get("fromServiceWorker"),
                "serviceWorkerResponseSource": (sw_info or {}).get("serviceWorkerResponseSource"),
            }
        )

    srv = server_markers(server_log)
    cdp_m = {mk for mk, rs in cdp.items() if rs}
    return {
        "run_dir": str(run_dir),
        "waitForDebuggerOnStart": sessions_meta.get("waitForDebuggerOnStart"),
        "sessionCount": sessions_meta.get("sessionCount"),
        "eventCount": sessions_meta.get("eventCount"),
        "networkEventCount": sessions_meta.get("networkEventCount"),
        "elapsedMs": sessions_meta.get("elapsedMs"),
        "requestIdCollisionPairs": sessions_meta.get("requestIdCollisionPairs"),
        "expected_markers": EXPECTED_MARKERS,
        "coverage": {
            "server": {m: m in srv for m in EXPECTED_MARKERS},
            "cdp": {m: m in cdp_m for m in EXPECTED_MARKERS},
            "server_missing": [m for m in EXPECTED_MARKERS if m not in srv],
            "cdp_missing": [m for m in EXPECTED_MARKERS if m not in cdp_m],
        },
        "rows": rows,
    }


def compare_variants(with_wait: dict, without_wait: dict) -> dict:
    lost = []
    for row in with_wait["rows"]:
        mk = row["marker"]
        if not row["cdp"]:
            continue
        other = next((r for r in without_wait["rows"] if r["marker"] == mk), None)
        if other and row["cdp"] and not other["cdp"]:
            lost.append(mk)
    first_only = []
    for kind in ("popup-1", "blank-1", "oopif-1", "popup-get-1", "blank-get-1", "oopif-get-1"):
        w = next((r for r in with_wait["rows"] if r["marker"] == kind), None)
        n = next((r for r in without_wait["rows"] if r["marker"] == kind), None)
        if w and w["cdp"] and n and not n["cdp"]:
            first_only.append(kind)
    return {"cdp_lost_without_wait": lost, "first_request_lost_without_wait": first_only}


def build_summary(report: dict) -> dict:
    kinds = ["page", "popup", "target_blank", "oophif", "dedicated_worker", "service_worker"]
    out = {"by_kind": {}, "service_worker_detail": {}}
    for label, key in (("with_wait", "with_wait"), ("without_wait", "without_wait")):
        if key not in report:
            continue
        run = report[key]
        for kind in kinds:
            rows = [r for r in run["rows"] if r["target_kind"] == kind or (kind == "service_worker" and r["marker"].startswith("sw-"))]
            if kind != "service_worker":
                rows = [r for r in run["rows"] if r["target_kind"] == kind]
            out["by_kind"].setdefault(kind, {})[label] = {
                "markers_seen": sorted({r["marker"] for r in rows}),
                "server": all(r["server"] for r in rows) if rows else False,
                "netlog": any(r["netlog"] for r in rows) if rows else False,
                "cdp": any(r["cdp"] for r in rows) if rows else False,
            }
        for mk in ("sw-intercept-1", "sw-own-1", "sw-own-post-1"):
            row = next((r for r in run["rows"] if r["marker"] == mk), None)
            if row:
                out["service_worker_detail"].setdefault(mk, {})[label] = {
                    "cdp_sessions": row.get("cdp_sessions"),
                    "fromServiceWorker": row.get("fromServiceWorker"),
                    "serviceWorkerResponseSource": row.get("serviceWorkerResponseSource"),
                }
        out.setdefault("coverage", {})[label] = run.get("coverage", {})
    if "variant_compare" in report:
        out["variant_compare"] = report["variant_compare"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=pathlib.Path, required=True, help="dir with wait-debugger run")
    ap.add_argument("--run-no-wait", type=pathlib.Path, help="variant without waitForDebuggerOnStart")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    report = {"with_wait": analyze_run(args.run)}
    if args.run_no_wait:
        report["without_wait"] = analyze_run(args.run_no_wait)
        report["variant_compare"] = compare_variants(report["with_wait"], report["without_wait"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary_path = args.out.parent / "summary.json"
    summary_path.write_text(json.dumps(build_summary(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    cov = report["with_wait"]["coverage"]
    print(
        json.dumps(
            {
                "out": str(args.out),
                "summary": str(summary_path),
                "server_markers": 16 - len(cov["server_missing"]),
                "cdp_markers": 16 - len(cov["cdp_missing"]),
            }
        )
    )


if __name__ == "__main__":
    main()
