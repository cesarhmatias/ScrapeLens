#!/usr/bin/env python3
"""Generates a Markdown section for docs/02-fidelity-matrix.md from analysis.json."""
from __future__ import annotations

import argparse
import json
import pathlib

# Recorded analysis.json files may carry the legacy Portuguese values; read them as English.
LEGACY_VERDICT = {"sim": "yes", "não": "no"}

KINDS = [
    ("popup", "Popup (`window.open`)"),
    ("target_blank", "New tab (`target=_blank`)"),
    ("oophif", "OOPIF iframe (other port)"),
    ("dedicated_worker", "Dedicated worker"),
    ("service_worker", "Service worker (intercept + own fetch)"),
    ("page", "Main document"),
]


def agg(analysis: dict, key: str) -> dict[str, dict]:
    src = analysis[key]
    by_kind: dict[str, list] = {}
    for row in src.get("rows", []):
        by_kind.setdefault(row["target_kind"], []).append(row)
    out = {}
    for kind, _label in KINDS:
        rows = by_kind.get(kind, [])
        if not rows:
            out[kind] = {"server": "not verified", "netlog": "not verified", "cdp": "not verified"}
            continue
        out[kind] = {
            "server": "yes" if any(r["server"] for r in rows) else "no",
            "netlog": "yes" if any(r["netlog"] for r in rows) else "no",
            "cdp": "yes" if any(r["cdp"] for r in rows) else "no",
            "extra_info": "yes" if any(LEGACY_VERDICT.get(r.get("headers_extra_info"), r.get("headers_extra_info")) == "yes" for r in rows) else "partial",
            "bodies": "yes" if any(r.get("bodies_cdp") is True for r in rows) else "partial",
            "sw_page": any(r.get("fromServiceWorker") for r in rows),
            "sw_source": next((r.get("serviceWorkerResponseSource") for r in rows if r.get("serviceWorkerResponseSource")), None),
        }
    out["_cost"] = {
        "sessions": src.get("sessionCount"),
        "events": src.get("eventCount"),
        "network_events": src.get("networkEventCount"),
        "elapsed_ms": src.get("elapsedMs"),
        "requestId_collisions": src.get("requestIdCollisionPairs"),
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("analysis", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path)
    args = ap.parse_args()
    data = json.loads(args.analysis.read_text())
    w = agg(data, "with_wait")
    n = agg(data, "without_wait") if "without_wait" in data else {}
    cmp_ = data.get("variant_compare", {})

    lines = [
        "## Multi-target capture (CDP auto-attach × NetLog)",
        "",
        "Contract: `docs/14-multi-target-capture.md`. Harness: `experiments/multi_target/`.",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Browser | Chrome headless=new (see `cdp-sessions.json`) |",
        f"| CDP | `Target.setDiscoverTargets` + `setAutoAttach` (flatten, `waitForDebuggerOnStart` true/false) |",
        f"| Preliminary evidence | `experiments/results/multi-target-smoke/` (local smoke; **repeat** with `testserver` `GET /multi/` once the tests are published) |",
        "",
        "### Table by target type (marker `?m=`, **with** `waitForDebuggerOnStart` variant)",
        "",
        "| Target type | Server (JSONL) | NetLog | CDP (child session) | ExtraInfo (order) | CDP bodies | SW `fromServiceWorker` |",
        "|---|---|---|---|---|---|---|",
    ]
    for kind, label in KINDS:
        c = w.get(kind, {})
        if kind.startswith("_"):
            continue
        lines.append(
            f"| {label} | {c.get('server', 'not verified')} | {c.get('netlog', 'not verified')} | "
            f"{c.get('cdp', 'not verified')} | {c.get('extra_info', 'not verified')} | "
            f"{c.get('bodies', 'not verified')} | "
            f"{('yes' if c.get('sw_page') else '—') if c.get('cdp') != 'not verified' else 'not verified'} |"
        )

    lines.extend(
        [
            "",
            "### Variant **without** `waitForDebuggerOnStart`",
            "",
            f"- First request lost in CDP (markers `popup-first` / `blank-first` / `oophif-first`): "
            f"{cmp_.get('first_request_lost_without_wait') or 'not verified (smoke incomplete in this run)'}",
            f"- CDP sessions: {n.get('_cost', {}).get('sessions', 'not verified')}; "
            f"Network events: {n.get('_cost', {}).get('network_events', 'not verified')}",
            "",
            "### `requestId` collision across sessions",
            "",
            f"With wait: **{w.get('_cost', {}).get('requestId_collisions', '?')}** pairs `(requestId)` seen in more than one session "
            f"(correct correlation requires `(sessionId, requestId)`). Without wait: "
            f"**{n.get('_cost', {}).get('requestId_collisions', 'not verified')}**.",
            "",
            "### Cost (with-wait variant, smoke)",
            "",
            f"| CDP sessions | Total events | Network.* events | Capture time |",
            f"|---:|---:|---:|---:|",
            f"| {w.get('_cost', {}).get('sessions')} | {w.get('_cost', {}).get('events')} | "
            f"{w.get('_cost', {}).get('network_events')} | {w.get('_cost', {}).get('elapsed_ms')} ms |",
            "",
            "**Recommendation (1 line):** use auto-attach with `waitForDebuggerOnStart` and key `(sessionId, requestId)`; "
            "targets without a CDP session stay NetLog-only; repeat the official measurement against `testserver` `/multi/` before fixing the product.",
            "",
        ]
    )
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
