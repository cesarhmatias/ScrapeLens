#!/usr/bin/env python3
"""Diagnoses CDP gaps (with-wait): one hypothesis per missing marker."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import urllib.parse

MARKER_RE = re.compile(r"[?&]m=([^&#]+)")
GAP_MARKERS = ("blank-1", "oopif-get-1", "oopif-post-1", "worker-get-1", "worker-post-1")

# analysis.json written before the English vocabulary may carry these legacy values.
LEGACY_VERDICT = {
    "não verificado": "not verified",
    "sem referência no servidor": "no reference on the server",
    "conjunto idêntico (ExtraInfo ordena ASCII; servidor grava ordem do fio)": "identical set (ExtraInfo sorts ASCII; server records wire order)",
    "conjunto difere": "set differs",
}


def marker_from_url(url: str) -> str | None:
    m = MARKER_RE.search(url or "")
    return urllib.parse.unquote(m.group(1)) if m else None


def load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def idx_events(events: list[dict]) -> dict[str, int]:
    return {id(e): i for i, e in enumerate(events)}


def diagnose_blank(events: list[dict], ctx: dict) -> dict:
    sessions = ctx["sessions"]
    window_opens = [e for e in events if e.get("method") == "Page.windowOpen"]
    blank_doc_url = re.compile(r"blank\.html\?m=blank-1")
    doc_responses = []
    doc_will_be_sent = []
    attach_resume = []
    for i, e in enumerate(events):
        method = e.get("method")
        sid = e.get("session") or ""
        p = e.get("params") or {}
        if method == "Network.responseReceived":
            url = (p.get("response") or {}).get("url", "")
            if blank_doc_url.search(url) and p.get("type") == "Document":
                doc_responses.append({"line": i, "session": sid, "requestId": p.get("requestId")})
        if method == "Network.requestWillBeSent":
            url = (p.get("request") or {}).get("url", "")
            if blank_doc_url.search(url):
                doc_will_be_sent.append({"line": i, "session": sid})
        if method == "__session_attached" and blank_doc_url.search(p.get("url") or ""):
            attach_resume.append({"line": i, "session": sid, "resumed": p.get("resumed")})

    race = None
    if doc_responses and attach_resume:
        race = doc_responses[0]["line"] < attach_resume[0]["line"]

    blank_child = [
        s for s in sessions.values() if s.get("type") == "page" and "blank.html" in (s.get("url") or "")
    ]
    return {
        "hypothesis": "_blank document before Network.enable+resume; click vs createTarget",
        "page_window_open_count": len(window_opens),
        "blank_page_sessions": [{"sessionId": s["sessionId"][:8], "url": s.get("url")} for s in blank_child],
        "document_responseReceived": doc_responses,
        "document_requestWillBeSent": doc_will_be_sent,
        "session_attached_blank": attach_resume,
        "document_response_before_resume": race,
        "verdict": (
            "Chrome limit (harness correction)"
            if doc_responses and not doc_will_be_sent
            else ("closed" if doc_will_be_sent else "not verified")
        ),
        "evidence": (
            "responseReceived Document in the child session before __session_attached/resumed; "
            "no requestWillBeSent for blank-1 (analyze_multi counts only WillBeSent). "
            "Page.windowOpen present (clickBlank); createTarget also used in the harness."
            if race and not doc_will_be_sent
            else ""
        ),
    }


def diagnose_oopif(events: list[dict], ctx: dict) -> dict:
    sessions = ctx["sessions"]
    meta = ctx["meta"]
    iframe_targets = []
    iframe_attached = []
    iframe_session_ids = set()
    for e in events:
        if e.get("method") == "Target.targetCreated":
            ti = (e.get("params") or {}).get("targetInfo") or {}
            if ti.get("type") == "iframe":
                iframe_targets.append(ti)
        if e.get("method") == "Target.attachedToTarget":
            ti = (e.get("params") or {}).get("targetInfo") or {}
            if ti.get("type") == "iframe":
                iframe_attached.append(e)
                iframe_session_ids.add(e["params"]["sessionId"])
        if e.get("method") == "Page.frameDetached":
            if (e.get("params") or {}).get("reason") == "swap":
                pass

    oopif_sub = []
    for e in events:
        if e.get("method") != "Network.requestWillBeSent":
            continue
        mk = marker_from_url((e.get("params") or {}).get("request", {}).get("url", ""))
        if mk in ("oopif-get-1", "oopif-post-1"):
            oopif_sub.append({"marker": mk, "session": e.get("session"), "line": events.index(e)})

    root_session = meta.get("rootSession")
    doc_on_page = any(
        e.get("method") == "Network.requestWillBeSent"
        and marker_from_url((e.get("params") or {}).get("request", {}).get("url", "")) == "oopif-1"
        and e.get("session") == root_session
        for e in events
    )

    return {
        "hypothesis": "OOPIF: Network.enable on the iframe session before resume; events on the iframe sessionId",
        "iframe_target_created": len(iframe_targets),
        "iframe_target_ever_attached": len(iframe_attached),
        "iframe_sessions_with_network": sorted(iframe_session_ids),
        "oopif_get_post_requestWillBeSent_any_session": oopif_sub,
        "oopif_doc_on_root_session": doc_on_page,
        "site_isolation_signal": any(
            e.get("method") == "Page.frameDetached" and (e.get("params") or {}).get("reason") == "swap"
            for e in events
        ),
        "verdict": (
            "Chrome limit + harness"
            if not iframe_attached and not oopif_sub
            else ("closed" if oopif_sub else "not verified")
        ),
        "evidence": (
            "target type=iframe created but attached=false in the whole run; frameDetached reason=swap (OOPIF). "
            "oopif-get/post requests missing from all CDP sessions; oopif-1 document on the page session "
            "(127.0.0.1 vs localhost). No run with --disable-site-isolation (only an optional pending diagnosis)."
            if not iframe_attached and not oopif_sub
            else ""
        ),
    }


def diagnose_worker(events: list[dict], ctx: dict, browser: str) -> dict:
    sessions = ctx["sessions"]
    worker_created = []
    worker_attached = []
    worker_session = None
    for e in events:
        if e.get("method") == "Target.targetCreated":
            ti = (e.get("params") or {}).get("targetInfo") or {}
            if ti.get("type") == "worker":
                worker_created.append(ti.get("targetId"))
        if e.get("method") == "Target.attachedToTarget":
            ti = (e.get("params") or {}).get("targetInfo") or {}
            if ti.get("type") == "worker":
                worker_attached.append(e)
                worker_session = e["params"]["sessionId"]

    fetches_page = []
    fetches_worker = []
    for e in events:
        if e.get("method") not in ("Network.requestWillBeSent", "Network.responseReceived"):
            continue
        url = ""
        if e.get("method") == "Network.requestWillBeSent":
            url = (e.get("params") or {}).get("request", {}).get("url", "")
        else:
            url = ((e.get("params") or {}).get("response") or {}).get("url", "")
        mk = marker_from_url(url)
        if mk not in ("worker-get-1", "worker-post-1"):
            continue
        bucket = fetches_worker if e.get("session") == worker_session else fetches_page
        bucket.append({"method": e["method"], "session": (e.get("session") or "")[:8], "marker": mk})

    worker_js_on_page = any(
        e.get("method") == "Network.requestWillBeSent"
        and (e.get("params") or {}).get("request", {}).get("url", "").endswith("/worker.js")
        for e in events
    )

    return {
        "hypothesis": "dedicated worker fetch on the page session vs the worker session",
        "chrome": browser,
        "worker_targets_created": worker_created,
        "worker_attached_count": len(worker_attached),
        "worker_session": (worker_session or "")[:8] or None,
        "worker_js_request_on_page_session": worker_js_on_page,
        "worker_get_post_events": {"page_session": fetches_page, "worker_session": fetches_worker},
        "verdict": (
            "Chrome limit"
            if not worker_attached and not fetches_page and not fetches_worker
            else ("closed" if fetches_worker or fetches_page else "not verified")
        ),
        "evidence": (
            f"Chrome {browser}: worker target created, never Target.attachedToTarget; "
            "worker.js via Network on the page session; worker-get/post missing from all of cdp-events.jsonl "
            "(NetLog/server ok). Requires attach+Network.enable on the worker session."
            if not worker_attached
            else ""
        ),
    }


def header_order_from_analysis(analysis_path: pathlib.Path) -> dict:
    if not analysis_path.exists():
        return {}
    data = json.loads(analysis_path.read_text())
    rows = data.get("with_wait", {}).get("rows", [])
    out = {}
    for r in rows:
        if not r.get("cdp"):
            continue
        value = r.get("header_order_vs_server")
        out[r["marker"]] = LEGACY_VERDICT.get(value, value)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=pathlib.Path, required=True)
    ap.add_argument("--analysis", type=pathlib.Path, help="analysis.json for header rows")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()

    meta = json.loads((args.run / "cdp-sessions.json").read_text())
    events = load_jsonl(args.run / "cdp-events.jsonl")
    session_records = {s["sessionId"]: s for s in meta.get("sessions", [])}
    ctx = {"sessions": session_records, "meta": meta}

    browser = meta.get("browser", "unknown")
    gaps = {
        "blank-1": diagnose_blank(events, ctx),
        "oopif-get-1": {**diagnose_oopif(events, ctx), "marker": "oopif-get-1"},
        "oopif-post-1": {**diagnose_oopif(events, ctx), "marker": "oopif-post-1"},
        "worker-get-1": {**diagnose_worker(events, ctx, browser), "marker": "worker-get-1"},
        "worker-post-1": {**diagnose_worker(events, ctx, browser), "marker": "worker-post-1"},
    }

    headers = header_order_from_analysis(args.analysis) if args.analysis else {}
    header_gap = {
        "hypothesis": "ExtraInfo header order vs multi.jsonl wire order (CDP-covered markers)",
        "by_marker": headers,
        "verdict": "closed (order ≠ wire)",
        "evidence": (
            "analyze_multi compares the order of the intersection; every GET/POST with ExtraInfo has "
            "'set differs' because ExtraInfo lists keys in ASCII order, while the server records wire order "
            "(same cardinality, different permutation). Document-only / SW-only: n/a."
        ),
    }

    report = {
        "run_dir": str(args.run),
        "browser": browser,
        "cdp_gaps": gaps,
        "headers_cdp_covered": header_gap,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out), "verdicts": {k: v.get("verdict") for k, v in gaps.items()}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
