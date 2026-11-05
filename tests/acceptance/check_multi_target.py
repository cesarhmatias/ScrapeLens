#!/usr/bin/env python3
"""Round 10, wave 2 (docs/14-multi-target-capture.md): acceptance of the multi-target capture.

Runs the REAL product capture (`src-tauri` `capture::run`, via the ignored test `live_bodies_cycle`) against
`testserver /multi/`, with headless Chrome, and checks:

 (1) 16/16 `?m=` markers reach the NetLog;
 (2) >= 15/16 markers with CDP; the expected exception is the `blank-1` document;
 (3) right target type per marker (page / iframe / worker / service_worker);
 (4) POSTs: request and response bodies match the server's `body_sha256` (multi.jsonl), per target type;
 (5) no request merged between sessions by an equal `requestId`;
 (6) `/multi/sw-fetch`: two observations linked with evidence or explicit ambiguity — never a silent duplicate.

Usage:
  python3 tests/acceptance/check_multi_target.py                     # starts everything
  python3 tests/acceptance/check_multi_target.py --capture-dir DIR   # reuses a session
  python3 tests/acceptance/check_multi_target.py --port 8911 --keep  # keeps the temporary files

Output: tests/results/multi-target.json. Exit code 0 only if everything passes. It fails until the Capture
(sessionId/Target.*) and the Core (provenance/ambiguity) deliver; nothing is relaxed. Data 100% synthetic,
only 127.0.0.1/localhost.
"""
from __future__ import annotations

import argparse
import collections
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
OUT = TESTS / "results" / "multi-target.json"
SERVER_BIN = ROOT / "testserver" / "target" / "release" / "scrapelens-testserver"
SRC_TAURI = ROOT / "src-tauri"

# Markers that /multi/ fires (see testserver/README.md, "Multi-target pages").
EXPECTED = [
    "main-1", "main-post-1",
    "popup-1", "popup-get-1", "popup-post-1",
    "blank-1", "blank-get-1", "blank-post-1",
    "oopif-1", "oopif-get-1", "oopif-post-1",
    "worker-get-1", "worker-post-1",
    "sw-intercept-1", "sw-own-1", "sw-own-post-1",
]

# Expected CDP target type per marker.
TYPES = {
    "main-1": "page", "main-post-1": "page",
    "popup-1": "page", "popup-get-1": "page", "popup-post-1": "page",
    "blank-1": "page", "blank-get-1": "page", "blank-post-1": "page",
    "oopif-1": "iframe", "oopif-get-1": "iframe", "oopif-post-1": "iframe",
    "worker-get-1": "worker", "worker-post-1": "worker",
    "sw-intercept-1": "service_worker", "sw-own-1": "service_worker", "sw-own-post-1": "service_worker",
}

# target=_blank document: the current CDP does not follow the new navigation; only the NetLog remains.
CDP_EXCEPTION = {"blank-1"}

POST_MARKERS = ["main-post-1", "popup-post-1", "blank-post-1", "oopif-post-1", "worker-post-1", "sw-own-post-1"]

MARKER_RX = re.compile(r"[?&]m=([A-Za-z0-9._-]+)")

FAILS: list[str] = []
INFO: dict = {}


def check(cond: bool, msg: str) -> bool:
    if not cond:
        FAILS.append(msg)
    return cond


def sh(argv, **kw):
    return subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=kw.pop("timeout", 300), **kw)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def markers_in(text: str) -> set[str]:
    return {m for m in MARKER_RX.findall(text) if m in EXPECTED}


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def body_bytes(entry: dict) -> bytes | None:
    """Bytes of a cdp-bodies.jsonl line (utf8 or base64)."""
    if entry.get("state") not in (None, "captured", "empty"):
        return None
    data = entry.get("data")
    if data is None:
        return b"" if entry.get("state") == "empty" else None
    enc = (entry.get("encoding") or "utf8").lower()
    if enc in ("base64", "b64"):
        try:
            return base64.b64decode(data)
        except Exception:
            return None
    return str(data).encode("utf-8", errors="replace")


def deep_find(obj, keys: tuple[str, ...]):
    """First value found for any of the names, at any depth."""
    if isinstance(obj, dict):
        for k in keys:
            if k in obj and obj[k] is not None:
                return obj[k]
        for v in obj.values():
            got = deep_find(v, keys)
            if got is not None:
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = deep_find(v, keys)
            if got is not None:
                return got
    return None


# --------------------------------------------------------------------- driver


def ensure_server_bin() -> None:
    if SERVER_BIN.exists():
        return
    build = sh(["cargo", "build", "--release", "--offline"], cwd=ROOT / "testserver")
    if build.returncode != 0:
        sys.exit(f"testserver build failed: {build.stderr[-400:]}")


def start_server(port: int, evidence: Path) -> subprocess.Popen:
    evidence.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [str(SERVER_BIN), "serve", "--only", "h1", "--h1", f"127.0.0.1:{port}",
         "--evidence", str(evidence), "--run-id", "multi"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            import urllib.request
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1).read()
            return proc
        except Exception:
            time.sleep(0.1)
    proc.terminate()
    sys.exit(f"testserver did not start on 127.0.0.1:{port}")


def build_capture_test() -> None:
    """Builds the test binary before driving the capture (a cold build can take over 3 min)."""
    proc = sh(["cargo", "test", "--release", "--offline", "--no-run", "live_bodies_cycle"],
              cwd=SRC_TAURI, timeout=1800)
    if proc.returncode != 0:
        sys.exit(f"capture test build failed: {proc.stderr[-600:]}")


def drive_capture(tmp: Path, port: int) -> tuple[Path, dict]:
    """Runs the REAL product capture (capture::run) against /multi/ and returns the session."""
    session_dir = tmp / "session"
    stop_file = tmp / "stop"
    multi_log = tmp / "evidence" / "multi" / "multi.jsonl"
    env = dict(os.environ)
    env.update({
        "SL_LIVE_START_URL": f"http://127.0.0.1:{port}/multi/",
        "SL_LIVE_SESSION_DIR": str(session_dir),
        "SL_LIVE_STOP_FILE": str(stop_file),
        "CARGO_TERM_COLOR": "never",
    })
    proc = subprocess.Popen(
        ["cargo", "test", "--release", "--offline", "live_bodies_cycle", "--", "--ignored", "--nocapture"],
        cwd=SRC_TAURI, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    seen: set[str] = set()
    deadline = time.time() + 120
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            seen = markers_in(multi_log.read_text(errors="replace")) if multi_log.exists() else set()
            # All markers, or enough time for popup/worker/SW after 12 s.
            if len(seen) >= len(EXPECTED):
                time.sleep(1.0)
                break
            time.sleep(0.3)
    finally:
        stop_file.write_text("stop\n", encoding="utf-8")
    try:
        out, _ = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return session_dir, {"driver_rc": proc.returncode, "driver_log": (out or "")[-4000:],
                         "markers_during_capture": sorted(seen)}


# ------------------------------------------------------------------- analysis


def cdp_targets(events: list[dict]) -> dict:
    """sessionId -> {type, url, targetId, openerId} from the Target.* events."""
    targets: dict[str, dict] = {}
    for ev in events:
        method = ev.get("method") or ""
        params = ev.get("params") or {}
        sid = ev.get("sessionId") or params.get("sessionId")
        if method == "Target.attachedToTarget":
            info = params.get("targetInfo") or {}
            targets[str(sid)] = {
                "type": info.get("type"),
                "url": info.get("url"),
                "targetId": info.get("targetId"),
                "openerId": info.get("openerId"),
            }
        elif method == "Target.targetInfoChanged":
            info = params.get("targetInfo") or {}
            key = str(sid)
            if key in targets:
                targets[key].update({"type": info.get("type"), "url": info.get("url"), "targetId": info.get("targetId")})
    return targets


def cdp_requests(events: list[dict]) -> list[dict]:
    out = []
    for ev in events:
        if ev.get("method") != "Network.requestWillBeSent":
            continue
        params = ev.get("params") or {}
        req = params.get("request") or {}
        url = req.get("url") or ""
        m = MARKER_RX.search(url)
        out.append({
            "sessionId": ev.get("sessionId") or params.get("sessionId"),
            "requestId": params.get("requestId"),
            "url": url,
            "method": req.get("method"),
            "marker": m.group(1) if m and m.group(1) in EXPECTED else None,
        })
    return out


def body_index(entries: list[dict]) -> dict:
    idx: dict[tuple, dict] = {}
    for e in entries:
        rid = e.get("requestId")
        sid = e.get("sessionId")
        attempt = e.get("attemptIndex", 0)
        kind = e.get("kind")
        idx[(str(sid) if sid is not None else None, str(rid), attempt, kind)] = e
    return idx


def find_body(idx: dict, sid, rid, kind="request") -> dict | None:
    keys = [k for k in idx if k[1] == str(rid) and k[3] == kind and (sid is None or k[0] == str(sid))]
    if not keys:
        return None
    return idx[sorted(keys, key=lambda k: (k[2] or 0))[0]]


def session_requests(session_dir: Path, core: str) -> dict:
    """`scrapelens-core inspect` = {"session": {"session": {...}, "requests": [...], "warnings": [...]}, "report": ...}."""
    proc = sh([core, "inspect", session_dir])
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:300], "requests": [], "warnings": []}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "inspect returned invalid JSON", "requests": [], "warnings": []}
    inner = data.get("session") or {}
    if not isinstance(inner, dict):
        return {"error": "inspect: 'session' is not an object", "requests": [], "warnings": []}
    return {
        "requests": inner.get("requests") or [],
        "warnings": inner.get("warnings") or [],
        "report": data.get("report") or {},
        "session": inner.get("session") or {},
    }


def request_key(req: dict) -> tuple:
    """(sessionId, requestId) of the model (Core 2f1cc1b: `cdp.sessionId`)."""
    cdp = req.get("cdp") or {}
    sid = cdp.get("sessionId") or deep_find(req, ("sessionId", "cdpSessionId"))
    rid = cdp.get("requestId") or deep_find(req, ("requestId",))
    return (str(sid) if sid is not None else None, str(rid) if rid is not None else None)


SW_MARKERS = ("sw-intercept-1", "sw-own-1", "sw-own-post-1")


def raw_cdp_pairs(events: list[dict]) -> list[tuple]:
    """(sessionId, requestId) of each raw Network.requestWillBeSent."""
    pairs = []
    for ev in events:
        if ev.get("method") != "Network.requestWillBeSent":
            continue
        params = ev.get("params") or {}
        sid = ev.get("sessionId") or params.get("sessionId")
        rid = params.get("requestId")
        if sid is not None and rid is not None:
            pairs.append((str(sid), str(rid)))
    return pairs


def is_partial(req: dict) -> bool:
    """Request with only `responseReceived` (without requestWillBeSent): partial, declared in the model."""
    blob = json.dumps(req.get("provenance") or {}, ensure_ascii=False) + json.dumps(req.get("attempts") or [], ensure_ascii=False)
    return "responseReceived" in blob and ("without requestWillBeSent" in blob or "partial" in blob)


def model_pairs(req: dict) -> set:
    """Pairs (sessionId, requestId) that the model request represents (cdp + attempts)."""
    pairs = set()
    cdp = req.get("cdp") or {}
    if cdp.get("sessionId") is not None and cdp.get("requestId") is not None:
        pairs.add((str(cdp["sessionId"]), str(cdp["requestId"])))
    for attempt in req.get("attempts") or []:
        acdp = attempt.get("cdp") or {}
        if acdp.get("sessionId") is not None and acdp.get("requestId") is not None:
            pairs.add((str(acdp["sessionId"]), str(acdp["requestId"])))
    return pairs


def target_kind(req: dict, targets: dict) -> str | None:
    """Target type: `target.kind` of the model; otherwise the Target.attachedToTarget event."""
    kind = (req.get("target") or {}).get("kind")
    if kind and kind not in ("other", ""):
        return kind
    cdp = req.get("cdp") or {}
    info = targets.get(str(cdp.get("sessionId"))) or {}
    return info.get("type") or kind


def url_marker(req: dict) -> str | None:
    m = MARKER_RX.search(req.get("url") or "")
    return m.group(1) if m and m.group(1) in EXPECTED else None


def analyze(capture: Path, server_log: Path, core: str, driver: dict) -> list[str]:
    """Resets the state and runs the analysis; returns the failures (also used by the selftest)."""
    global FAILS, INFO
    FAILS = []
    INFO = {}
    _analyze(capture, server_log, core, driver)
    return list(FAILS)


def _analyze(capture: Path, server_log: Path, core: str, driver: dict) -> None:
    events = read_jsonl(capture / "cdp-events.jsonl")
    bodies = read_jsonl(capture / "cdp-bodies.jsonl")
    netlog_text = (capture / "netlog.json").read_text(errors="replace") if (capture / "netlog.json").exists() else ""
    server = read_jsonl(server_log)
    session = session_requests(capture, core)
    requests = session.get("requests") or []

    INFO["artifacts"] = {
        "capture": str(capture),
        "cdp_events": len(events),
        "cdp_bodies": len(bodies),
        "netlog_bytes": len(netlog_text),
        "server_lines": len(server),
        "session_requests": len(requests),
        "driver": {k: driver[k] for k in ("driver_rc",) if k in driver},
    }
    if session.get("error"):
        INFO["artifacts"]["inspect_error"] = session["error"]
    # (1) NetLog: 16/16
    netlog_markers = markers_in(netlog_text)
    # Explicit error: an empty imported session must not fail the criteria as a consequence.
    if not requests:
        check(False, "imported session has no requests (inspect.session.requests empty) with "
                     f"{len(netlog_markers)}/16 markers in the NetLog — import/format broken")
        INFO["session_vazia"] = True
    INFO["netlog"] = {"markers": sorted(netlog_markers), "missing": sorted(set(EXPECTED) - netlog_markers)}
    check(len(netlog_markers & set(EXPECTED)) == len(EXPECTED),
          f"netlog: {len(netlog_markers & set(EXPECTED))}/16 markers (missing {INFO['netlog']['missing']})")

    # (2) CDP: >= 15/16, blank-1 exception
    reqs = cdp_requests(events)
    cdp_markers = {r["marker"] for r in reqs if r["marker"]}
    INFO["cdp"] = {"markers": sorted(cdp_markers), "missing": sorted(set(EXPECTED) - cdp_markers)}
    check(len(cdp_markers & set(EXPECTED)) >= 15,
          f"cdp: {len(cdp_markers & set(EXPECTED))}/16 markers (missing {INFO['cdp']['missing']})")
    unexpected_missing = (set(EXPECTED) - cdp_markers) - CDP_EXCEPTION
    check(not unexpected_missing, f"cdp: markers missing beyond the blank-1 exception: {sorted(unexpected_missing)}")

    # (3) target type per marker (model `target.kind`; missing Target.* events as a clue)
    targets = cdp_targets(events)
    session_by_marker = {url_marker(r): r for r in requests if url_marker(r)}
    typed: dict[str, list[str]] = {}
    for r in reqs:
        if not r["marker"]:
            continue
        t = targets.get(str(r["sessionId"])) or {}
        typed.setdefault(r["marker"], []).append(t.get("type") or "?")
    model_types = {m: target_kind(req, targets) for m, req in session_by_marker.items()}
    INFO["targets"] = {"sessions": len(targets),
                       "eventos": {k: sorted(set(v)) for k, v in sorted(typed.items())},
                       "modelo": {k: v for k, v in sorted(model_types.items())}}
    if not targets and not any(model_types.values()):
        check(False, "cdp: no Target.attachedToTarget events and no target.kind in the model — no target provenance")
    # The OOPIF iframe document is reported on the PARENT target's session (frame), so
    # "page" is also acceptable for oopif-1; the sub-requests must be iframe.
    # The fetch intercepted by the SW exists in both sessions: the page observation
    # is "page" and the SW's is "service_worker" — both are correct.
    ACEITA = {"oopif-1": {"iframe", "page"}, "sw-intercept-1": {"service_worker", "page"}}
    for marker, want in TYPES.items():
        got = set(typed.get(marker, []))
        kind = model_types.get(marker)
        aceitos = ACEITA.get(marker, {want})
        if kind and kind not in ("other", ""):
            check(kind in aceitos, f"target type {marker}: model says {kind}, expected {'/'.join(sorted(aceitos))}")
        elif marker in CDP_EXCEPTION and not got:
            continue
        else:
            check(bool(got & aceitos), f"target type {marker}: expected {'/'.join(sorted(aceitos))}, got {sorted(got) or 'absent'}")

    # (4) POST bodies equal to the server's body_sha256
    idx = body_index(bodies)
    srv = {r.get("marker"): r for r in server if r.get("marker")}
    INFO["post_bodies"] = {}
    for marker in POST_MARKERS:
        row = srv.get(marker)
        if not row:
            check(False, f"post {marker}: did not reach the server")
            continue
        response = (row.get("response") or {})
        body_text = row.get("body_text") or ""
        try:
            srv_json = json.loads(response.get("body") or "{}")
        except Exception:
            srv_json = {}
        want_req = srv_json.get("body_sha256") or (sha256(body_text.encode()) if body_text else None)
        want_resp = response.get("body_sha256") or (sha256((response.get("body") or "").encode()) if response.get("body") else None)
        if not want_resp:
            check(False, f"post {marker}: multi.jsonl has no response.body_sha256 (server did not record the response)")
            continue
        found = next((r for r in reqs if r["marker"] == marker), None)
        if not found:
            INFO["post_bodies"][marker] = {"cdp": "absent"}
            check(marker in CDP_EXCEPTION, f"post {marker}: request missing in CDP")
            continue
        req_body = find_body(idx, found["sessionId"], found["requestId"], "request")
        resp_body = find_body(idx, found["sessionId"], found["requestId"], "response")
        got_req = sha256(body_bytes(req_body)) if req_body and body_bytes(req_body) is not None else None
        got_resp = sha256(body_bytes(resp_body)) if resp_body and body_bytes(resp_body) is not None else None
        INFO["post_bodies"][marker] = {"esperado_req": want_req, "cdp_req": got_req,
                                       "esperado_resp": want_resp, "cdp_resp": got_resp}
        check(got_req == want_req, f"post {marker}: request body {got_req} != server {want_req}")
        check(got_resp == want_resp, f"post {marker}: response body {got_resp} != server {want_resp}")
        # the attempt's signature must also exist in the bodies JSONL
        if req_body is None or resp_body is None:
            check(False, f"post {marker}: cdp-bodies.jsonl has no {'request' if req_body is None else 'response'} "
                         f"(sessionId={found['sessionId']}, requestId={found['requestId']})")

    # (5) no merge — compared with the RAW CDP events, not with the model itself
    raw = raw_cdp_pairs(events)
    raw_set = set(raw)
    coll = {}
    for sid, rid in raw_set:
        coll.setdefault(rid, set()).add(sid)
    coll = {rid: sorted(sids) for rid, sids in coll.items() if len(sids) > 1}
    INFO["request_id_collisions"] = {"total": len(coll), "exemplos": dict(list(coll.items())[:5])}
    model = [model_pairs(r) for r in requests]
    joined = [(r.get("id"), sorted(pairs)) for r, pairs in zip(requests, model) if len(pairs) > 1]
    # An observation with only `responseReceived` (without requestWillBeSent) is partial, declared
    # by the contract: it proves no raw pair and is not counted in the merge counts.
    partial = [r for r in requests if is_partial(r)]
    flat = [pair for r, pairs in zip(requests, model) if not is_partial(r) for pair in pairs]
    missing = sorted(raw_set - set(flat))
    extra = sorted(set(flat) - raw_set)
    dups = len(flat) - len(set(flat))
    INFO["merge"] = {
        "bruto_pares": len(raw_set),
        "modelo_pares": len(flat),
        "requisicoes_com_dois_pares": [j[0] for j in joined][:5],
        "faltando_no_modelo": missing[:5],
        "inventados_no_modelo": extra[:5],
        "pares_repetidos": dups,
        "pares_repetidos_exemplos": [ (pair, [r.get("id") for r, ps in zip(requests, model) if pair in ps]) for pair in [p for p, n in collections.Counter(flat).items() if n > 1][:3] ],
        "colisoes": len(coll),
        "parciais_sem_request": [r.get("id") for r in partial][:5],
    }
    if not check(bool(raw), "merge: no Network.requestWillBeSent in the raw cdp-events.jsonl"):
        pass
    check(not joined, f"merge: model request joins more than one pair (sessionId, requestId): {joined[:3]}")
    check(not missing, f"merge: raw pairs without a distinct request in the model: {missing[:5]}")
    check(not extra, f"merge: model has pairs that do not exist in the raw data: {extra[:5]}")
    check(dups == 0, f"merge: {dups} pair(s) (sessionId, requestId) repeated in the model")
    if not coll:
        INFO["merge"]["colisao_exercitada"] = "not exercised in this capture (legitimate after the dedupe by targetId)"

    # (6) service worker: each group with both observations and the link/warning of THAT group
    warnings = session.get("warnings") or []
    ids = {r.get("id") for r in requests}
    sw_groups = {m: [r for r in requests if url_marker(r) == m] for m in SW_MARKERS}
    info_sw = {"grupos": {}, "por_requisicao": []}
    for marker, group in sw_groups.items():
        sids = [p[0] for r in group for p in sorted(model_pairs(r))]
        kinds = sorted({(r.get("target") or {}).get("kind") or "?" for r in group})
        # A duplicate is counted by targetId: the same target can be attached to several
        # sessions (repeated attach) and each copy records the same request.
        targets_of = [(r.get("target") or {}).get("targetId") for r in group]
        sess_of = [(r.get("cdp") or {}).get("sessionId") for r in group]
        por_alvo = collections.Counter(tid for tid in targets_of if tid)
        dup_alvo = {tid: n for tid, n in por_alvo.items() if n > 1}
        sessoes_por_alvo = collections.defaultdict(set)
        for tid, sid in zip(targets_of, sess_of):
            if tid and sid:
                sessoes_por_alvo[tid].add(str(sid))
        multi_sessao = {tid: sorted(v) for tid, v in sessoes_por_alvo.items() if len(v) > 1}
        info_sw["grupos"][marker] = {"requisicoes": len(group), "tipos": kinds, "sessoes": sorted(set(sids)),
                                     "alvos": dict(por_alvo), "duplicata_por_alvo": dup_alvo,
                                     "alvos_com_varias_sessoes": multi_sessao}
        check(len(group) > 0, f"service worker: no request for {marker}")
        check(len(sids) == len(set(sids)),
              f"service worker {marker}: {len(sids) - len(set(sids))} duplicate(s) in the same session")
        check(not dup_alvo,
              f"service worker {marker}: {sum(dup_alvo.values()) - len(dup_alvo)} observation(s) repeated on the same target "
              f"(targetId): {dict(list(dup_alvo.items())[:3])} — repeated attach, not two observations")
        check(not multi_sessao,
              f"service worker {marker}: target with more than one session recording network: "
              f"{dict(list(multi_sessao.items())[:3])}")
    intercept = sw_groups.get("sw-intercept-1") or []
    ids_intercept = {r.get("id") for r in intercept}
    links_ok, warned, links_bad = [], [], []
    by_id = {r.get("id"): r for r in requests}
    from urllib.parse import urlsplit
    def _path(r):
        return urlsplit(r.get("url") or "").path
    for r in intercept:
        for l in (r.get("links") or []):
            if (l.get("kind") or "") != "service_worker":
                continue
            tgt = by_id.get(l.get("request")) or {}
            if url_marker(tgt) in ("sw-own-1", "sw-own-post-1"):
                links_bad.append({"request": r.get("id"), "to": l.get("request"), "marker": url_marker(tgt)})
                continue
            if (l.get("resolution") or "") in ("linked", "ambiguous") and l.get("request") in ids_intercept \
                    and _path(tgt) == _path(r) and tgt.get("method") == r.get("method"):
                links_ok.append({"request": r.get("id"), "to": l.get("request"),
                                 "resolution": l.get("resolution"), "evidence": l.get("evidence")})
        for w in warnings:
            blob = json.dumps(w, ensure_ascii=False) if isinstance(w, dict) else str(w)
            if "sw-intercept-1" in blob or any(i and i in blob for i in ids_intercept):
                warned.append({"request": r.get("id"), "warning": blob[:160]})
                break
    kinds_intercept = set((r.get("target") or {}).get("kind") or "" for r in intercept)
    has_both = {"page", "service_worker"} <= kinds_intercept
    info_sw.update({"intercept": {"requisicoes": len(intercept), "tipos": sorted(kinds_intercept),
                                  "links_ok": links_ok, "links_para_sw_own": links_bad, "avisos_do_grupo": warned},
                    "por_requisicao": [{"id": r.get("id"),
                                        "kind": (r.get("target") or {}).get("kind"),
                                        "links": [{"request": l.get("request"), "resolution": l.get("resolution")}
                                                  for l in (r.get("links") or [])]} for r in intercept]})
    INFO["service_worker"] = info_sw
    check(len(intercept) >= 2, f"service worker sw-intercept-1: expected the page and SW observations; there are {len(intercept)}")
    check(has_both,
          f"service worker sw-intercept-1: both observations are missing; types seen {sorted(kinds_intercept)}")
    check(not links_bad,
          f"service worker sw-intercept-1: linked to sw-own-* (must link only to the candidate with the same path): {links_bad[:2]}")
    check(bool(links_ok),
          "service worker sw-intercept-1: no link (linked/ambiguous) to the candidate with the same method and path"
          + (f" (group warning present: {warned[:1]})" if warned else ""))

    setup_w = [(w.get("code") if isinstance(w, dict) else str(w)) for w in warnings]
    setup_w = [c for c in setup_w if c and ("target_setup_timeout" in c or "setup_error" in c or "setup_aborted" in c)]
    INFO["setup_warnings"] = setup_w
    check(not setup_w, f"target setup: timeout/error warnings in the live capture: {setup_w[:4]}")

    INFO["session_warnings"] = [w.get("code") if isinstance(w, dict) else str(w) for w in warnings][:20]


def _copy_capture(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for name in ("session.json", "cdp-events.jsonl", "cdp-bodies.jsonl", "netlog.json"):
        if (src / name).exists():
            shutil.copy2(src / name, dst / name)


def _session_paths(capture: Path) -> tuple[Path, Path, Path]:
    return capture / "session.json", capture / "cdp-events.jsonl", capture / "cdp-bodies.jsonl"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")


def _req_pair(req: dict) -> tuple:
    cdp = req.get("cdp") or {}
    return (str(cdp.get("sessionId")), str(cdp.get("requestId")))


def _find_by_marker(session: dict, marker: str) -> list[dict]:
    out = []
    for r in session.get("requests") or []:
        m = MARKER_RX.search(r.get("url") or "")
        if m and m.group(1) == marker:
            out.append(r)
    return out


def _mut_fuse_two_pairs(capture: Path) -> str:
    """Merges two requests from distinct sessions (both with requestWillBeSent, outside the SW)."""
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    cands = [r for r in session.get("requests") or []
             if (r.get("cdp") or {}).get("sessionId") and (r.get("cdp") or {}).get("requestId")
             and not is_partial(r) and url_marker(r) and url_marker(r) not in SW_MARKERS]
    pair = next(((a, b) for i, a in enumerate(cands) for b in cands[i + 1:]
                 if a["cdp"]["sessionId"] != b["cdp"]["sessionId"]), None)
    if not pair:
        raise RuntimeError("no two non-partial requests from different sessions to merge")
    keep, drop = pair
    moved = [dict(att, cdp=dict(att.get("cdp") or {}, **drop["cdp"])) for att in drop.get("attempts") or []]
    keep["attempts"] = (keep.get("attempts") or []) + (moved or [{"cdp": dict(drop["cdp"])}])
    session["requests"] = [r for r in session["requests"] if r is not drop]
    _dump(sp, session)
    return (f"merged {drop.get('id')} (requestId {drop['cdp']['requestId']}) into {keep.get('id')} "
            f"(requestId {keep['cdp']['requestId']})")


def _mut_remove_sw_links(capture: Path) -> str:
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    n = 0
    for r in session.get("requests") or []:
        m = MARKER_RX.search(r.get("url") or "")
        if m and m.group(1) in SW_MARKERS and r.get("links"):
            r["links"] = []
            n += 1
    _dump(sp, session)
    return f"removed links from {n} sw-* request(s)"


def _mut_swap_kind(capture: Path) -> str:
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    for r in _find_by_marker(session, "oopif-get-1"):
        r.setdefault("target", {})["kind"] = "page"
        _dump(sp, session)
        return f"changed kind of {r.get('id')} (oopif-get-1) to page"
    raise RuntimeError("no oopif-get-1 to change the kind")


def _mut_alter_body(capture: Path) -> str:
    sp, _, bp = _session_paths(capture)
    session = _load(sp)
    target = _find_by_marker(session, "main-post-1")
    if not target:
        raise RuntimeError("no main-post-1 to alter the body")
    cdp = target[0].get("cdp") or {}
    rows = []
    changed = 0
    for line in bp.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if (e.get("requestId") == cdp.get("requestId") and e.get("kind") == "response"
                and (e.get("sessionId") in (None, cdp.get("sessionId")))):
            e["data"] = (e.get("data") or "") + " "
            changed += 1
        rows.append(json.dumps(e, ensure_ascii=False))
    bp.write_text("\n".join(rows) + "\n", encoding="utf-8")
    if not changed:
        raise RuntimeError("no response body of main-post-1 in cdp-bodies")
    return "altered the response body of main-post-1"


def _pick_two_sessions(session: dict):
    """Two requests with distinct sessionIds (preferably distinct targetIds)."""
    reqs = [r for r in session.get("requests") or []
            if (r.get("cdp") or {}).get("sessionId") and (r.get("cdp") or {}).get("requestId")
            and not is_partial(r) and url_marker(r) and url_marker(r) not in SW_MARKERS]
    for i, a in enumerate(reqs):
        for b in reqs[i + 1:]:
            if (a["cdp"]["sessionId"] != b["cdp"]["sessionId"]
                    and (a.get("target") or {}).get("targetId") != (b.get("target") or {}).get("targetId")):
                return a, b
    for i, a in enumerate(reqs):
        for b in reqs[i + 1:]:
            if a["cdp"]["sessionId"] != b["cdp"]["sessionId"]:
                return a, b
    raise RuntimeError("no two requests from different sessions")


def _inject_collision(capture: Path, fuse: bool) -> str:
    """Injects into the raw data and into the model the same requestId on two distinct targets.

    `fuse=False`: the model keeps the two observations separate (the check MUST PASS, proving the collision was
    exercised without a merge).
    `fuse=True`: the model joins the two pairs into one request (the check MUST FAIL).
    """
    sp, ep, _ = _session_paths(capture)
    session = _load(sp)
    a, b = _pick_two_sessions(session)
    rid = a["cdp"]["requestId"]
    sid_b = b["cdp"]["sessionId"]
    events = [json.loads(line) for line in ep.read_text(encoding="utf-8").splitlines() if line.strip()]
    events.append({
        "sessionId": sid_b,
        "method": "Network.requestWillBeSent",
        "params": {"requestId": rid, "request": {"url": b.get("url"), "method": b.get("method")}},
    })
    ep.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    clone = json.loads(json.dumps(b))
    clone["id"] = (b.get("id") or "cdp") + "-col"
    clone.setdefault("cdp", {})["requestId"] = rid
    for attempt in clone.get("attempts") or []:
        attempt.setdefault("cdp", {})["requestId"] = rid
    session["requests"].append(clone)
    if fuse:
        a["attempts"] = (a.get("attempts") or []) + (clone.get("attempts") or [])
        session["requests"] = [r for r in session["requests"] if r is not clone]
    _dump(sp, session)
    return (f"requestId {rid} repeated in {a['cdp']['sessionId']} and {sid_b}"
            + (" with the pairs MERGED into one request" if fuse else " kept separate"))


def _mut_collision_injected(capture: Path) -> str:
    return _inject_collision(capture, fuse=False)


def _mut_collision_fused(capture: Path) -> str:
    return _inject_collision(capture, fuse=True)


def _mut_link_intercept_to_own(capture: Path) -> str:
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    page = next((r for r in _find_by_marker(session, "sw-intercept-1") if (r.get("target") or {}).get("kind") == "page"), None)
    own = next(iter(_find_by_marker(session, "sw-own-1")), None)
    if not page or not own:
        raise RuntimeError("no sw-intercept-1 (page) or sw-own-1")
    page.setdefault("links", []).append({"kind": "service_worker", "request": own.get("id"),
                                         "resolution": "ambiguous", "evidence": ["selftest"]})
    _dump(sp, session)
    return f"linked {page.get('id')} (sw-intercept-1) to {own.get('id')} (sw-own-1)"


def _mut_duplicate_sw_other_session(capture: Path) -> str:
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    src = _find_by_marker(session, "sw-own-1")
    if not src:
        raise RuntimeError("no sw-own-1 to duplicate in another session")
    base = src[0]
    dup = json.loads(json.dumps(base))
    dup["id"] = (dup.get("id") or "cdp") + "-dup-sess"
    dup.setdefault("cdp", {})["sessionId"] = "SELFTEST0000000000000000000000FF"
    for attempt in dup.get("attempts") or []:
        attempt.setdefault("cdp", {})["sessionId"] = "SELFTEST0000000000000000000000FF"
    session["requests"].append(dup)
    _dump(sp, session)
    return f"duplicated {base.get('id')} in a second session of targetId {(base.get('target') or {}).get('targetId')}"


def _mut_duplicate_sw(capture: Path) -> str:
    sp, _, _ = _session_paths(capture)
    session = _load(sp)
    src = _find_by_marker(session, "sw-own-1")
    if not src:
        raise RuntimeError("no sw-own-1 to duplicate")
    dup = json.loads(json.dumps(src[0]))
    dup["id"] = (dup.get("id") or "cdp") + "-dup"
    session["requests"].append(dup)
    _dump(sp, session)
    return f"duplicated {src[0].get('id')} in the same session"


def self_test(capture: Path, server_log: Path, core: str, tmp: Path) -> dict:
    """Mutations that the check MUST fail. Each one runs on a copy of the recorded session."""
    global FAILS, INFO
    saved_fails, saved_info = list(FAILS), json.loads(json.dumps(INFO, ensure_ascii=False, default=str))
    st_fails: list[str] = []  # `analyze` resets FAILS on each call; the selftest accumulates separately
    base = tmp / "self-test-base"
    _copy_capture(capture, base)
    fails = analyze(base, server_log, core, {})
    if fails:
        st_fails.append(f"selftest: the session without mutation should pass; failed at {fails[:3]}")

    mutations = [
        ("merge of two pairs (sessionId, requestId)", _mut_fuse_two_pairs, "fail"),
        ("service worker links removed", _mut_remove_sw_links, "fail"),
        ("target kind changed", _mut_swap_kind, "fail"),
        ("body altered", _mut_alter_body, "fail"),
        ("duplicated copy of SW request", _mut_duplicate_sw, "fail"),
        ("SW copy in another session of the same targetId", _mut_duplicate_sw_other_session, "fail"),
        ("sw-intercept linked to sw-own-*", _mut_link_intercept_to_own, "fail"),
        # requestId collision between targets: injected into the raw data; separate must PASS,
        # merged must FAIL.
        ("injected collision between targets (separate observations)", _mut_collision_injected, "pass"),
        ("injected collision between targets (merged pairs)", _mut_collision_fused, "fail"),
    ]
    out = []
    for i, (name, fn, expected) in enumerate(mutations):
        work = tmp / f"self-test-{i}"
        _copy_capture(capture, work)
        try:
            detail = fn(work)
        except Exception as error:  # mutation not applicable = selftest failure
            out.append({"mutacao": name, "esperado": expected, "aplicada": False,
                        "erro": str(error)[:200], "falhas": []})
            st_fails.append(f"selftest: could not apply '{name}': {error}")
            continue
        mut_fails = analyze(work, server_log, core, {})
        out.append({"mutacao": name, "esperado": expected, "aplicada": True, "detalhe": detail,
                    "falhas": mut_fails[:4]})
        if expected == "fail":
            if not mut_fails:
                st_fails.append(f"selftest: mutation '{name}' did NOT fail (the check does not detect it)")
        else:
            if mut_fails:
                st_fails.append(f"selftest: mutation '{name}' should keep passing: {mut_fails[:3]}")
    FAILS, INFO = saved_fails + st_fails, saved_info
    return {"mutacoes": out, "falhas_autoteste": st_fails}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core")
    ap.add_argument("--port", type=int, default=8911)
    ap.add_argument("--capture-dir", help="session already captured (skips the driver)")
    ap.add_argument("--server-log", help="server multi.jsonl (with --capture-dir)")
    ap.add_argument("--self-test", action="store_true",
                    help="applies mutations to the captured session and requires FAIL on each")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()

    core = a.core or str(ROOT / "core" / "target" / "release" / "scrapelens-core")
    if not Path(core).exists():
        sys.exit("scrapelens-core not found; run `cargo build --release` in core/ or use --core")

    tmp = Path(tempfile.mkdtemp(prefix="sl-multi-target-"))
    os.chmod(tmp, 0o700)
    server = None
    try:
        if a.capture_dir:
            capture = Path(a.capture_dir)
            server_log = Path(a.server_log) if a.server_log else capture / "multi.jsonl"
            driver = {}
        else:
            ensure_server_bin()
            build_capture_test()
            server = start_server(a.port, tmp / "evidence")
            time.sleep(0.3)
            capture, driver = drive_capture(tmp, a.port)
            server_log = tmp / "evidence" / "multi" / "multi.jsonl"

        if not (capture / "session.json").exists():
            check(False, f"capture: {capture}/session.json missing (drv rc={driver.get('driver_rc')})")
            INFO["driver_log"] = driver.get("driver_log", "")[-1500:]
        else:
            analyze(capture, server_log, core, driver)
        if a.self_test and (capture / "session.json").exists():
            INFO["self_test"] = self_test(capture, server_log, core, tmp)
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            INFO["tmp"] = str(tmp)

    INFO["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(INFO, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):")
        for f in FAILS:
            print(" -", f)
        return 1
    print("OK: multi-target capture — 16/16 NetLog, >=15/16 CDP, types, bodies, no merge and service worker linked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
