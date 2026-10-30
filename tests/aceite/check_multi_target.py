#!/usr/bin/env python3
"""Rodada 10, onda 2 (docs/14-captura-multi-alvo.md): aceite da captura multi-alvo.

Faz a captura REAL do produto (`src-tauri` `capture::run`, via o teste ignorado
`live_bodies_cycle`) contra `testserver /multi/`, com Chrome headless, e confere:

 (1) 16/16 marcadores `?m=` chegam ao NetLog;
 (2) >= 15/16 marcadores com CDP; a exceção esperada é o documento `blank-1`;
 (3) tipo de alvo certo por marcador (page / iframe / worker / service_worker);
 (4) POSTs: corpo de requisição e de resposta batem com o `body_sha256` do
     servidor (multi.jsonl), por tipo de alvo;
 (5) nenhuma requisição fundida entre sessões por `requestId` igual;
 (6) `/multi/sw-fetch`: duas observações ligadas com evidência ou ambiguidade
     explícita — nunca duplicata silenciosa.

Uso:
  python3 tests/aceite/check_multi_target.py                     # sobe tudo
  python3 tests/aceite/check_multi_target.py --capture-dir DIR   # reusa sessão
  python3 tests/aceite/check_multi_target.py --port 8911 --keep  # preserva temporários

Saída: tests/results/multi-target.json. Código 0 só se tudo passar. Falha até a
Captura (sessionId/Target.*) e o Core (proveniência/ambiguidade) entregarem; nada
é afrouxado. Dados 100% sintéticos, só 127.0.0.1/localhost.
"""
from __future__ import annotations

import argparse
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

# Marcadores que /multi/ dispara (ver testserver/README.md, "Páginas multi-alvo").
EXPECTED = [
    "main-1", "main-post-1",
    "popup-1", "popup-get-1", "popup-post-1",
    "blank-1", "blank-get-1", "blank-post-1",
    "oopif-1", "oopif-get-1", "oopif-post-1",
    "worker-get-1", "worker-post-1",
    "sw-intercept-1", "sw-own-1", "sw-own-post-1",
]

# Tipo de alvo CDP esperado por marcador.
TYPES = {
    "main-1": "page", "main-post-1": "page",
    "popup-1": "page", "popup-get-1": "page", "popup-post-1": "page",
    "blank-1": "page", "blank-get-1": "page", "blank-post-1": "page",
    "oopif-1": "iframe", "oopif-get-1": "iframe", "oopif-post-1": "iframe",
    "worker-get-1": "worker", "worker-post-1": "worker",
    "sw-intercept-1": "service_worker", "sw-own-1": "service_worker", "sw-own-post-1": "service_worker",
}

# Documento do target=_blank: o CDP atual não acompanha a navegação nova; sobra o NetLog.
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
    """Bytes de uma linha de cdp-bodies.jsonl (utf8 ou base64)."""
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
    """Primeiro valor encontrado para qualquer um dos nomes, em qualquer profundidade."""
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
        sys.exit(f"build do testserver falhou: {build.stderr[-400:]}")


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
    sys.exit(f"testserver não subiu em 127.0.0.1:{port}")


def drive_capture(tmp: Path, port: int) -> tuple[Path, dict]:
    """Roda a captura REAL do produto (capture::run) contra /multi/ e devolve a sessão."""
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
    deadline = time.time() + 75
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            seen = markers_in(multi_log.read_text(errors="replace")) if multi_log.exists() else set()
            # Todos os marcadores, ou tempo suficiente para popup/worker/SW após 12 s.
            if len(seen) >= len(EXPECTED):
                time.sleep(1.0)
                break
            time.sleep(0.3)
    finally:
        stop_file.write_text("stop\n", encoding="utf-8")
    try:
        out, _ = proc.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return session_dir, {"driver_rc": proc.returncode, "driver_log": (out or "")[-4000:],
                         "markers_during_capture": sorted(seen)}


# ------------------------------------------------------------------- analysis


def cdp_targets(events: list[dict]) -> dict:
    """sessionId -> {type, url, targetId, openerId} a partir dos eventos Target.*."""
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
    proc = sh([core, "inspect", session_dir])
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:300]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "inspect devolveu JSON inválido"}


def request_key(req: dict) -> tuple:
    """(sessionId, requestId) do modelo (Core 2f1cc1b: `cdp.sessionId`)."""
    cdp = req.get("cdp") or {}
    sid = cdp.get("sessionId") or deep_find(req, ("sessionId", "cdpSessionId"))
    rid = cdp.get("requestId") or deep_find(req, ("requestId",))
    return (str(sid) if sid is not None else None, str(rid) if rid is not None else None)


def target_kind(req: dict, targets: dict) -> str | None:
    """Tipo do alvo: `target.kind` do modelo; senão o evento Target.attachedToTarget."""
    kind = (req.get("target") or {}).get("kind")
    if kind and kind not in ("other", ""):
        return kind
    cdp = req.get("cdp") or {}
    info = targets.get(str(cdp.get("sessionId"))) or {}
    return info.get("type") or kind


def url_marker(req: dict) -> str | None:
    m = MARKER_RX.search(req.get("url") or "")
    return m.group(1) if m and m.group(1) in EXPECTED else None


def analyze(capture: Path, server_log: Path, core: str, driver: dict) -> None:
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
    INFO["netlog"] = {"markers": sorted(netlog_markers), "missing": sorted(set(EXPECTED) - netlog_markers)}
    check(len(netlog_markers & set(EXPECTED)) == len(EXPECTED),
          f"netlog: {len(netlog_markers & set(EXPECTED))}/16 marcadores (faltam {INFO['netlog']['missing']})")

    # (2) CDP: >= 15/16, exceção blank-1
    reqs = cdp_requests(events)
    cdp_markers = {r["marker"] for r in reqs if r["marker"]}
    INFO["cdp"] = {"markers": sorted(cdp_markers), "missing": sorted(set(EXPECTED) - cdp_markers)}
    check(len(cdp_markers & set(EXPECTED)) >= 15,
          f"cdp: {len(cdp_markers & set(EXPECTED))}/16 marcadores (faltam {INFO['cdp']['missing']})")
    unexpected_missing = (set(EXPECTED) - cdp_markers) - CDP_EXCEPTION
    check(not unexpected_missing, f"cdp: marcadores ausentes além da exceção blank-1: {sorted(unexpected_missing)}")

    # (3) tipo de alvo por marcador (modelo `target.kind`; eventos Target.* em falta como pista)
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
        check(False, "cdp: sem eventos Target.attachedToTarget e sem target.kind no modelo — sem proveniência de alvo")
    for marker, want in TYPES.items():
        got = set(typed.get(marker, []))
        kind = model_types.get(marker)
        if kind and kind not in ("other", ""):
            check(kind == want, f"tipo do alvo {marker}: modelo diz {kind}, esperado {want}")
        elif marker in CDP_EXCEPTION and not got:
            continue
        else:
            check(want in got, f"tipo do alvo {marker}: esperado {want}, veio {sorted(got) or 'ausente'}")

    # (4) corpos de POST iguais ao body_sha256 do servidor
    idx = body_index(bodies)
    srv = {r.get("marker"): r for r in server if r.get("marker")}
    INFO["post_bodies"] = {}
    for marker in POST_MARKERS:
        row = srv.get(marker)
        if not row:
            check(False, f"post {marker}: não chegou ao servidor")
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
            check(False, f"post {marker}: multi.jsonl sem response.body_sha256 (servidor não registrou a resposta)")
            continue
        found = next((r for r in reqs if r["marker"] == marker), None)
        if not found:
            INFO["post_bodies"][marker] = {"cdp": "ausente"}
            check(marker in CDP_EXCEPTION, f"post {marker}: requisição ausente no CDP")
            continue
        req_body = find_body(idx, found["sessionId"], found["requestId"], "request")
        resp_body = find_body(idx, found["sessionId"], found["requestId"], "response")
        got_req = sha256(body_bytes(req_body)) if req_body and body_bytes(req_body) is not None else None
        got_resp = sha256(body_bytes(resp_body)) if resp_body and body_bytes(resp_body) is not None else None
        INFO["post_bodies"][marker] = {"esperado_req": want_req, "cdp_req": got_req,
                                       "esperado_resp": want_resp, "cdp_resp": got_resp}
        check(got_req == want_req, f"post {marker}: corpo da requisição {got_req} != servidor {want_req}")
        check(got_resp == want_resp, f"post {marker}: corpo da resposta {got_resp} != servidor {want_resp}")
        # assinatura do attempt também precisa existir no JSONL de corpos
        if req_body is None or resp_body is None:
            check(False, f"post {marker}: cdp-bodies.jsonl sem {'request' if req_body is None else 'response'} "
                         f"(sessionId={found['sessionId']}, requestId={found['requestId']})")

    # (5) nenhuma fusão entre sessões por requestId
    by_rid: dict[str, set] = {}
    for r in reqs:
        by_rid.setdefault(str(r["requestId"]), set()).add(str(r["sessionId"]))
    collisions = {rid: sorted(sids) for rid, sids in by_rid.items() if len(sids) > 1}
    INFO["request_id_collisions"] = {"total": len(collisions), "exemplos": dict(list(collisions.items())[:5])}
    pairs = [request_key(r) for r in requests if request_key(r)[1]]
    distinct_pairs = {p for p in pairs if p[0]}
    INFO["merge"] = {"pares_distintos": len(distinct_pairs), "requisicoes": len(pairs)}
    if collisions:
        check(len(distinct_pairs) >= len(collisions),
              "fusão: requestId repetido entre sessões não virou requisições distintas "
              f"({len(distinct_pairs)} pares para {len(collisions)} colisões)")
    else:
        check(False, "requestId: nenhuma colisão entre sessões observada — a captura não exercitou a chave (sessionId, requestId)")

    # (6) service worker: `links` ligados com evidência ou ambiguidade explícita
    sw = [r for r in requests if url_marker(r) in ("sw-intercept-1", "sw-own-1", "sw-own-post-1")]
    sw_intercept = [r for r in sw if url_marker(r) == "sw-intercept-1"]
    info_sw = {"requests": len(sw), "intercept": []}
    warnings = [w.get("code") if isinstance(w, dict) else str(w) for w in (session.get("warnings") or [])]
    ids = {r.get("id") for r in requests}
    for r in sw_intercept:
        links = [l for l in (r.get("links") or []) if (l.get("kind") or "") == "service_worker"]
        linked = [l for l in links if (l.get("resolution") or "") == "linked" and l.get("request") in ids]
        ambiguous = [l for l in links if (l.get("resolution") or "") == "ambiguous"]
        attempts = r.get("attempts") or []
        sids = {deep_find(a, ("sessionId", "cdpSessionId")) for a in attempts}
        sids.discard(None)
        info_sw["intercept"].append({
            "id": r.get("id"),
            "target_kind": (r.get("target") or {}).get("kind"),
            "sessions": sorted(str(s) for s in sids),
            "attempts": len(attempts),
            "links": [{"request": l.get("request"), "resolution": l.get("resolution"),
                       "evidence": l.get("evidence")} for l in links],
            "linked": bool(linked),
            "ambiguous": bool(ambiguous) or "cdp.service_worker_ambiguous" in warnings,
        })
    INFO["service_worker"] = info_sw
    if len(sw_intercept) == 0:
        check(False, "service worker: nenhuma requisição /multi/sw-fetch na sessão")
    elif len(sw_intercept) == 1:
        ok = info_sw["intercept"][0]["linked"] or info_sw["intercept"][0]["ambiguous"]
        check(ok, f"service worker: uma requisição sem link ligado nem ambiguidade: {info_sw['intercept'][0]}")
    else:
        check(any(i["linked"] or i["ambiguous"] for i in info_sw["intercept"]),
              f"service worker: {len(sw_intercept)} requisições duplicadas sem link/ambiguidade: {info_sw['intercept']}")

    INFO["session_warnings"] = warnings[:20]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core")
    ap.add_argument("--port", type=int, default=8911)
    ap.add_argument("--capture-dir", help="sessão já capturada (pula o driver)")
    ap.add_argument("--server-log", help="multi.jsonl do servidor (com --capture-dir)")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()

    core = a.core or str(ROOT / "core" / "target" / "release" / "scrapelens-core")
    if not Path(core).exists():
        sys.exit("scrapelens-core não encontrado; rode `cargo build --release` em core/ ou use --core")

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
            server = start_server(a.port, tmp / "evidence")
            time.sleep(0.3)
            capture, driver = drive_capture(tmp, a.port)
            server_log = tmp / "evidence" / "multi" / "multi.jsonl"

        if not (capture / "session.json").exists():
            check(False, f"captura: {capture}/session.json ausente (drv rc={driver.get('driver_rc')})")
            INFO["driver_log"] = driver.get("driver_log", "")[-1500:]
        else:
            analyze(capture, server_log, core, driver)
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
    print("OK: captura multi-alvo — 16/16 NetLog, >=15/16 CDP, tipos, corpos, sem fusão e service worker ligado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
