#!/usr/bin/env python3
"""Acceptance of the proxy link (v0.1.2), on the real capture paths. Test only.

What it runs (all loopback, all synthetic; no paid proxy, no real credentials):
  * origin: `scrapelens-testserver serve` (HTTP/1.1 on 18781, HTTP/2 over TLS on 18782);
    the names `site-a.test` / `site-b.test` are resolved by the TEST proxies (`--resolve`).
  * proxies: `scrapelens-testserver proxy` (HTTP, HTTPS, SOCKS5; auth, refusals, drops).
  * capture: `proxy-acceptance-driver`, which calls `scrapelens_capture::run` (App path)
    and `BrowserCapture` (controlled path behind MCP `start_capture`). Chrome is the
    installed stable Chrome, with its own dedicated profile per capture; no window.

Everything it writes goes to --out (a durable folder outside the repository). Only the
summary without paths is meant for the repository (see RESULTS.md, written by --summary).

Usage:
  python3 run_acceptance.py --out DIR            # full run
  python3 run_acceptance.py --out DIR --only failures,fidelity   # subset
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
TESTSERVER = REPO / "testserver" / "target" / "debug" / "scrapelens-testserver"
DRIVER = HERE / "driver" / "target" / "debug" / "proxy-acceptance-driver"

USER = "tester-synthetic"
PASSWORD = "p@ss-w0rd!"          # special characters on purpose
PCT_PASSWORD = "p%40ss-w0rd%21"  # the same, percent-encoded inside the link
ORIGIN_H1 = 18781
ORIGIN_H2 = 18782
SITE_A = "site-a.test"
SITE_B = "site-b.test"
CLOSED_PORT = 18899               # nothing listens here (checked at start)

PORTS = {
    "http_open": 18801,       # no credentials, no allowlist
    "http_auth": 18802,       # Basic credentials
    "https_auth": 18803,      # TLS to the proxy (fixture certificate)
    "socks_auth": 18804,      # SOCKS5 user/password
    "socks_open": 18805,      # SOCKS5 without authentication
    "http_reject": 18806,     # refuses every client (407)
    "http_auth_deny": 18807,  # credentials, refuses the origin (403)
    "http_open_deny": 18808,  # no credentials, refuses the origin (403)
}


class Results:
    def __init__(self):
        self.rows: list[dict] = []

    def add(self, section: str, criterion: str, case: str, status: str, detail: str, evidence: str = ""):
        assert status in {"passou", "falhou", "nao_executado"}, status
        self.rows.append({"section": section, "criterion": criterion, "case": case,
                          "status": status, "detail": detail, "evidence": evidence})
        print(f"[{status}] {section} | {criterion} | {case}: {detail}", flush=True)


def wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def port_free(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return False
    except OSError:
        return True


class Servers:
    """Starts and stops only the processes this run started."""

    def __init__(self, out: pathlib.Path):
        self.out = out
        self.procs: list[subprocess.Popen] = []

    def start(self, name: str, argv: list[str]) -> subprocess.Popen:
        log = open(self.out / "logs" / f"{name}.log", "w")
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.procs.append(proc)
        return proc

    def stop_all(self):
        for proc in self.procs:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)


def proxy_argv(kind: str, port: int, evidence: pathlib.Path, *, auth: bool = False,
               reject: bool = False, deny: list[str] | None = None) -> list[str]:
    argv = [str(TESTSERVER), "proxy", "--kind", kind, "--port", str(port),
            "--evidence", str(evidence), "--resolve", f"{SITE_A}=127.0.0.1",
            "--resolve", f"{SITE_B}=127.0.0.1"]
    if auth:
        argv += ["--auth-env", "SL_ACC_PROXY_AUTH"]
    if reject:
        argv += ["--reject-auth"]
    for target in deny or []:
        argv += ["--deny", target]
    return argv


def link(scheme: str, port: int, *, creds: bool) -> str:
    if creds:
        return f"{scheme}://{USER}:{PCT_PASSWORD}@127.0.0.1:{port}"
    return f"{scheme}://127.0.0.1:{port}"


def driver(argv: list[str], log_name: str, out: pathlib.Path, timeout: int = 240) -> dict:
    proc = subprocess.run([str(DRIVER), *argv], capture_output=True, text=True, timeout=timeout)
    (out / "logs" / f"{log_name}.stdout").write_text(proc.stdout)
    (out / "logs" / f"{log_name}.stderr").write_text(proc.stderr)
    lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    if not lines:
        return {"ok": False, "error": f"driver printed no result (exit {proc.returncode})"}
    return json.loads(lines[-1])


def read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class LeakSampler:
    """Samples the TCP peers of the capture's Chrome processes (macOS, indirect evidence).

    Every connection of a Chrome process must end at loopback (the proxy or the relay).
    A remote peer outside loopback is recorded as a leak candidate. DNS (UDP) and
    the proxy's own host name are outside this check, as the PO's exceptions say."""

    def __init__(self):
        self.peers: set[str] = set()
        self.samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=5)

    def _pids(self) -> list[str]:
        out = subprocess.run(["pgrep", "-f", "user-data-dir=.*scrapelens"], capture_output=True, text=True)
        return out.stdout.split()

    def _run(self):
        while not self._stop.is_set():
            pids = self._pids()
            if pids:
                self.samples += 1
                out = subprocess.run(["lsof", "-nP", "-a", "-p", ",".join(pids), "-iTCP", "-sTCP:ESTABLISHED"],
                                     capture_output=True, text=True)
                for line in out.stdout.splitlines()[1:]:
                    m = re.search(r"->(\S+)$", line.strip())
                    if m:
                        peer = m.group(1)
                        host = peer.rsplit(":", 1)[0].strip("[]")
                        if not (host.startswith("127.") or host == "::1"):
                            self.peers.add(peer)
            self._stop.wait(0.4)


def build_pinned(out: pathlib.Path):
    """Driver and core built from one committed revision (HEAD at start), not from the working tree."""
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dest = out / "build" / "pinned"
    dest.mkdir(parents=True, exist_ok=True)
    arch = subprocess.run(["git", "-C", str(REPO), "archive", head, "core", "capture"], capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(dest)], input=arch.stdout, check=True)
    driver_dir = dest / "driver"
    (driver_dir / "src").mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "driver" / "src" / "main.rs", driver_dir / "src" / "main.rs")
    (driver_dir / "Cargo.toml").write_text((HERE / "driver" / "Cargo.toml").read_text()
                                           .replace("../../../../capture", "../capture"))
    for manifest in (dest / "core" / "Cargo.toml", driver_dir / "Cargo.toml"):
        proc = subprocess.run(["cargo", "build", "-q", "--manifest-path", str(manifest),
                               *(["--bin", "scrapelens-core"] if "core" in manifest.parts else [])],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            (out / "logs" / "build-pinned.stderr").write_text(proc.stderr)
            raise SystemExit(f"pinned build failed: {manifest}")
    (out / "pinned.json").write_text(json.dumps({"head": head}, indent=2))
    return driver_dir / "target" / "debug" / "proxy-acceptance-driver", dest / "core" / "target" / "debug" / "scrapelens-core", head


def build_from_head(out: pathlib.Path, _name: str, rel_bin: str, crates: list[str]):
    """Builds the core binary from the committed HEAD (not the working tree, which others edit)."""
    dest = out / "build" / "head"
    if not (dest / "core" / "Cargo.toml").exists():
        dest.mkdir(parents=True, exist_ok=True)
        arch = subprocess.run(["git", "-C", str(REPO), "archive", "HEAD", *[f"{c}" for c in crates]],
                              capture_output=True)
        subprocess.run(["tar", "-x", "-C", str(dest)], input=arch.stdout, check=True)
    proc = subprocess.run(["cargo", "build", "-q", "--manifest-path", str(dest / "core" / "Cargo.toml"),
                           "--bin", "scrapelens-core"], capture_output=True, text=True)
    binary = dest / "core" / "target" / "debug" / "scrapelens-core"
    (out / "logs" / "build-core-head.stderr").write_text(proc.stderr)
    return binary if proc.returncode == 0 and binary.exists() else None


def build_from_archive(out: pathlib.Path, rev: str):
    """Builds the proxy-acceptance driver against a past revision's capture (regression baseline)."""
    dest = out / "build" / rev
    driver_dir = dest / "driver"
    if not (dest / "capture" / "Cargo.toml").exists():
        dest.mkdir(parents=True, exist_ok=True)
        arch = subprocess.run(["git", "-C", str(REPO), "archive", rev, "core", "capture"], capture_output=True)
        subprocess.run(["tar", "-x", "-C", str(dest)], input=arch.stdout, check=True)
    driver_dir.mkdir(exist_ok=True)
    (driver_dir / "src").mkdir(exist_ok=True)
    # The baseline predates the proxy fields: it gets the legacy `common` driver only.
    shutil.copy(HERE / "driver" / "src" / "legacy_baseline.rs", driver_dir / "src" / "main.rs")
    (driver_dir / "Cargo.toml").write_text((HERE / "driver" / "Cargo.toml").read_text()
                                           .replace("../../../../capture", "../capture"))
    proc = subprocess.run(["cargo", "build", "-q", "--manifest-path", str(driver_dir / "Cargo.toml")],
                          capture_output=True, text=True)
    (out / "logs" / f"build-{rev}.stderr").write_text(proc.stderr)
    binary = driver_dir / "target" / "debug" / "proxy-acceptance-driver"
    return binary if proc.returncode == 0 and binary.exists() else None


WIRE_PROTO = {"h1": "http/1.1", "h2": "h2"}
HOP_BY_HOP = {"connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailer",
              "transfer-encoding", "upgrade"}
PROBE = re.compile(r"probe=fid-(h1|h2)-(none|direct|relay)")


def normalized_headers(record: dict) -> list[list[str]]:
    """Origin's header list with the probe's route name removed (it differs by design)."""
    return [[name, PROBE.sub(r"probe=fid-\1-ROUTE", value)] for name, value in record["headers"]]


VOLATILE = re.compile(r"(time|Time|^id$|Id$|_id|ms$|Ms$|duration|start|End|path|Path|dir|Dir|pid|Pid|provenance|attachment|"
                      r"version|Version|sourceId|requestId|loaderId|frameId|ts$|Ts$|seq|netlog)", re.I)
UUIDISH = re.compile(r"^[0-9A-F]{16,}$|^[0-9a-f-]{20,}$|^(capture|har|netlog)-")


def strip_volatile(value):
    if isinstance(value, dict):
        return {k: strip_volatile(v) for k, v in value.items() if not VOLATILE.search(k)}
    if isinstance(value, list):
        return [strip_volatile(v) for v in value]
    if isinstance(value, str) and UUIDISH.search(value):
        return "<id>"
    return value


def compare_sessions(a: pathlib.Path, b: pathlib.Path) -> list[str]:
    """Differences between two no-proxy sessions of the same probe, ignoring volatile fields."""
    sa = json.loads((a / "session.json").read_text())
    sb = json.loads((b / "session.json").read_text())
    diffs = []
    if "proxy" in json.dumps(sa.get("session", {}).get("capture", {})) or \
       "proxy" in json.dumps(sb.get("session", {}).get("capture", {})):
        diffs.append("capture.proxy present where no proxy was given")
    ra = [strip_volatile(r) for r in sa.get("requests", []) if "probe=reg-" in str(r.get("url", ""))]
    rb = [strip_volatile(r) for r in sb.get("requests", []) if "probe=reg-" in str(r.get("url", ""))]
    if not ra or not rb:
        # an empty comparison must never pass
        diffs.append(f"no probe requests to compare ({len(ra)} vs {len(rb)})")
    if len(ra) != len(rb):
        diffs.append(f"probe requests: {len(ra)} vs {len(rb)}")
    for i, (x, y) in enumerate(zip(ra, rb)):
        if x != y:
            keys = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))
            diffs.append(f"request {i} differs in {keys}")
    # the response body bytes themselves, not only the metadata
    for ra_req, rb_req in zip([r for r in sa.get("requests", []) if "probe=reg-" in str(r.get("url", ""))],
                              [r for r in sb.get("requests", []) if "probe=reg-" in str(r.get("url", ""))]):
        ha = body_sha(a, ra_req)
        hb = body_sha(b, rb_req)
        if ha != hb:
            diffs.append(f"response body bytes differ ({ha} vs {hb})")
    return diffs


# the origin's echo carries its own connection and stream counters: they are server bookkeeping,
# not part of what the client sent, so they are left out of the body comparison
SERVER_COUNTERS = {"conn", "stream", "seq", "ts_unix_ms", "ts_rfc3339"}


def body_sha(session_dir: pathlib.Path, request: dict):
    body = request.get("responseBody") or {}
    name = body.get("attachment")
    if not name:
        return None
    found = next(session_dir.rglob(name), None)
    if not found:
        return "missing"
    raw = found.read_bytes()
    try:
        value = json.loads(raw)
    except ValueError:
        return hashlib.sha256(raw).hexdigest()

    def scrub(v):
        if isinstance(v, dict):
            return {k: scrub(x) for k, x in v.items() if k not in SERVER_COUNTERS}
        if isinstance(v, list):
            return [scrub(x) for x in v]
        return v

    canonical = json.dumps(scrub(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def netlog_check(out: pathlib.Path) -> int:
    """Direct route: the NetLog must not turn an HTTPS probe into "verified" without evidence."""
    rows_path = out / "results.json"
    rows = [r for r in json.loads(rows_path.read_text()) if r["section"] != "Fidelidade-NetLog"]
    res = Results()
    for proto in ("h2", "h1"):
        direct = json.loads((out / "sessions" / f"fid-{proto}-direct" / "session.json").read_text())
        listed = any(f"probe=fid-{proto}-direct" in r["url"] for r in direct["requests"])
        no_url = any(w["code"] == "netlog.request_without_url" for w in direct.get("warnings", []))
        none_state = state_of(out, f"fid-{proto}-none")
        direct_state = state_of(out, f"fid-{proto}-direct")
        # the direct route may never be *more* certain than the no-proxy baseline
        honest = listed and not no_url and direct_state == none_state
        res.add("Fidelidade-NetLog", "direct route: no false 'verified' from NetLog", f"{proto} direct",
                "passou" if honest else "falhou",
                f"probe listed={listed}; request_without_url raised={no_url}; "
                f"verification: no proxy={none_state}, direct={direct_state}",
                f"sessions/fid-{proto}-direct")
    rows_path.write_text(json.dumps(rows + res.rows, indent=2, ensure_ascii=False))
    print(f"netlog rows merged into {rows_path}")
    return 0


def state_of(out: pathlib.Path, name: str) -> str:
    """Header verification state, as the core exporter reports it for the probe request."""
    session = out / "sessions" / name
    data = json.loads((session / "session.json").read_text())
    probe = next(r for r in data["requests"] if "probe=" in r["url"])
    cli = BUILD_CORE if BUILD_CORE else None
    if cli is None or not cli.exists():
        return "core not built"
    out_txt = subprocess.run([str(cli), "export-curl", str(session), probe["id"]], capture_output=True, text=True).stdout
    m = re.search(r"header verification: (\w+)", out_txt)
    return m.group(1) if m else "unknown"


BUILD_CORE = None


def main() -> int:
    global BUILD_CORE
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    out = pathlib.Path(args.out).resolve()
    only = {s for s in args.only.split(",") if s}
    if only == {"netlog"}:
        # re-checks the sessions of an earlier full run in place (no new captures, nothing deleted)
        BUILD_CORE = out / "build" / "pinned" / "core" / "target" / "debug" / "scrapelens-core"
        return netlog_check(out)
    if out.exists():
        # a full run never deletes an existing folder: it may hold the evidence of an earlier run
        print(f"refusing to overwrite an existing folder; choose a new --out: {out}", file=sys.stderr)
        return 2
    (out / "logs").mkdir(parents=True)
    (out / "sessions").mkdir()
    global DRIVER
    DRIVER, BUILD_CORE, head_commit = build_pinned(out)
    print(f"pinned to {head_commit}", flush=True)

    def want(section: str) -> bool:
        return not only or section in only

    res = Results()
    if not TESTSERVER.exists():
        print("build first: testserver (cargo build) and driver (cargo build in driver/)", file=sys.stderr)
        return 2
    busy = [p for p in [ORIGIN_H1, ORIGIN_H2, CLOSED_PORT, *PORTS.values()] if not port_free(p)]
    if busy:
        # A listener left from an earlier run would answer for the origin and hide the real result.
        print(f"ports already in use, stop those processes first: {busy}", file=sys.stderr)
        return 2

    os.environ["SL_ACC_PROXY_AUTH"] = f"{USER}:{PASSWORD}"
    servers = Servers(out)
    origin_dir = out / "origin"
    try:
        servers.start("origin", [str(TESTSERVER), "serve", "--only", "h1,h2", "--evidence", str(origin_dir),
                                 "--run-id", "acc", "--h1", f"127.0.0.1:{ORIGIN_H1}",
                                 "--h2", f"127.0.0.1:{ORIGIN_H2}", "--no-h3-on-h2-port"])
        proxies = {}
        spec = {
            "http_open": ("http", {}),
            "http_auth": ("http", {"auth": True}),
            "https_auth": ("https", {"auth": True}),
            "socks_auth": ("socks5", {"auth": True}),
            "socks_open": ("socks5", {}),
            "http_reject": ("http", {"auth": True, "reject": True}),
            "http_auth_deny": ("http", {"auth": True, "deny": [f"{SITE_A}:{ORIGIN_H1}", f"{SITE_A}:{ORIGIN_H2}"]}),
            "http_open_deny": ("http", {"deny": [f"{SITE_A}:{ORIGIN_H1}", f"{SITE_A}:{ORIGIN_H2}"]}),
        }
        for name, (kind, kw) in spec.items():
            ev = out / "proxy-evidence" / f"{name}.jsonl"
            ev.parent.mkdir(exist_ok=True)
            servers.start(f"proxy-{name}", proxy_argv(kind, PORTS[name], ev, **kw))
            proxies[name] = ev
        for name, port in [("origin-h1", ORIGIN_H1), ("origin-h2", ORIGIN_H2)] + [(n, p) for n, p in PORTS.items()]:
            if not wait_port(port):
                raise SystemExit(f"{name} did not start on {port}")
        print("servers up", flush=True)

        def stamp(name: str) -> pathlib.Path:
            return out / "sessions" / name

        # ------------------------------------------------------------ failures
        if want("failures"):
            cases = [
                ("unreachable", "direct", link("http", CLOSED_PORT, creds=False)),
                ("unreachable", "relay", link("http", CLOSED_PORT, creds=True)),
                ("auth_refused", "direct", link("http", PORTS["http_reject"], creds=False)),
                ("auth_refused", "relay", link("http", PORTS["http_reject"], creds=True)),
                ("target_refused", "direct", link("http", PORTS["http_open_deny"], creds=False)),
                ("target_refused", "relay", link("http", PORTS["http_auth_deny"], creds=True)),
            ]
            for failure, route, raw in cases:
                name = f"fail-{failure}-{route}"
                r = driver(["common", str(stamp(name)), f"http://{SITE_A}:{ORIGIN_H1}/echo-order?probe=fail",
                            "6", "--link", raw], name, out)
                notice = r.get("notice") or ""
                proxy_parts = [part.strip() for part in notice.split(";") if part.strip().lower().startswith("proxy:")]
                shown = r.get("error") or (proxy_parts[0] if proxy_parts else "")
                warnings = []
                session_json = stamp(name) / "session.json"
                if session_json.exists():
                    warnings = [w.get("code", "") for w in json.loads(session_json.read_text()).get("warnings", [])]
                generic = [c for c in warnings if c == "cdp.request_failed"]
                leaks = PASSWORD in json.dumps(r) or PCT_PASSWORD in json.dumps(r)
                if leaks:
                    res.add("Falhas", failure, route, "falhou", "credential text in the result", f"logs/{name}.stdout")
                elif shown and "proxy" in shown.lower():
                    where = "error" if r.get("error") else "notice"
                    res.add("Falhas", failure, route, "passou", f"actionable, shown as {where}: {shown[:200]}",
                            f"logs/{name}.stdout")
                else:
                    res.add("Falhas", failure, route, "falhou",
                            f"no proxy-specific message; session warnings={sorted(set(warnings))}; "
                            f"generic page failures={len(generic)}", f"logs/{name}.stdout")
            # invalid link: refused before any capture, both forms
            for label, raw in [("unsupported scheme", "socks4://127.0.0.1:1080"),
                               ("path present", f"http://127.0.0.1:{PORTS['http_open']}/x"),
                               ("port out of range", "http://127.0.0.1:70000"),
                               ("control character", "http://127.0.0.1:1\x01080")]:
                r = driver(["parse", raw], f"parse-{label.replace(' ', '-')}", out)
                if not r.get("ok") and r.get("error") and raw not in r.get("error", "") :
                    res.add("Falhas", "invalid link", label, "passou", r["error"][:160], "")
                else:
                    res.add("Falhas", "invalid link", label, "falhou", json.dumps(r)[:200], "")

        # ------------------------------------------------------------ fidelity
        fidelity_runs: dict[str, dict] = {}
        if want("fidelity"):
            routes = {
                "none": None,
                "direct": link("http", PORTS["http_open"], creds=False),
                "relay": link("http", PORTS["http_auth"], creds=True),
            }
            for proto, scheme, port in (("h1", "http", ORIGIN_H1), ("h2", "https", ORIGIN_H2)):
                for route, raw in routes.items():
                    probe = f"fid-{proto}-{route}"
                    argv = ["common", str(stamp(probe)), f"{scheme}://127.0.0.1:{port}/echo-order?probe={probe}", "8"]
                    if raw:
                        argv += ["--link", raw]
                    fidelity_runs[probe] = driver(argv, probe, out)
        if fidelity_runs:
            origin_records = {}
            if not (origin_dir / "acc" / "h1.jsonl").exists():
                raise SystemExit("origin evidence missing: " + str(origin_dir / "acc"))
            for proto in ("h1", "h2"):
                recs = read_jsonl(origin_dir / "acc" / f"{proto}.jsonl")
                origin_records[proto] = recs
            for proto in ("h1", "h2"):
                per_route = {}
                for route in ("none", "direct", "relay"):
                    probe = f"fid-{proto}-{route}"
                    matches = [r for r in origin_records[proto] if f"probe={probe}" in r.get("target", "")]
                    per_route[route] = matches
                base = per_route["none"]
                for route in ("direct", "relay"):
                    got = per_route[route]
                    if not base or not got:
                        res.add("Fidelidade", f"headers {proto} vs no proxy", route, "falhou",
                                f"origin saw {len(got)} request(s), baseline {len(base)}", f"origin/acc/{proto}.jsonl")
                        continue
                    a_raw = normalized_headers(base[0])
                    b_raw = normalized_headers(got[0])
                    # hop-by-hop headers are rewritten by any HTTP proxy, so they are compared apart
                    a_end2end = [h for h in a_raw if h[0].lower() not in HOP_BY_HOP]
                    b_end2end = [h for h in b_raw if h[0].lower() not in HOP_BY_HOP]
                    same_order = [h[0].lower() for h in a_end2end] == [h[0].lower() for h in b_end2end]
                    same_values = a_end2end == b_end2end
                    # the origin reports the wire protocol: "http/1.1" for H1, "h2" for H2
                    same_proto = base[0]["proto"] == got[0]["proto"] == WIRE_PROTO[proto]
                    a_hop = {h[0].lower(): h[1] for h in a_raw if h[0].lower() in HOP_BY_HOP}
                    b_hop = {h[0].lower(): h[1] for h in b_raw if h[0].lower() in HOP_BY_HOP}
                    hop = sorted(name for name in set(a_hop) | set(b_hop) if a_hop.get(name) != b_hop.get(name))
                    ok = same_order and same_values and same_proto
                    res.add("Fidelidade", f"headers {proto} vs no proxy", route, "passou" if ok else "falhou",
                            f"end-to-end order={'same' if same_order else 'DIFF'} values={'same' if same_values else 'DIFF'} "
                            f"proto={base[0]['proto']}/{got[0]['proto']}; hop-by-hop headers rewritten by the proxy: "
                            f"{hop or 'none'} (excluded)",
                            f"origin/acc/{proto}.jsonl")
                # CONNECT and Proxy-Authorization never reach the origin as request headers
                for route in ("none", "direct", "relay"):
                    for rec in per_route[route]:
                        names = {h[0].lower() for h in rec["headers"]}
                        if names & {"proxy-authorization", "proxy-connection"} or rec.get("method") == "CONNECT":
                            res.add("Fidelidade", "no CONNECT/Proxy-Authorization as request header", f"{proto}-{route}",
                                    "falhou", f"found {sorted(names & {'proxy-authorization', 'proxy-connection'})}",
                                    f"origin/acc/{proto}.jsonl")
                            break
                    else:
                        if per_route[route]:
                            res.add("Fidelidade", "no CONNECT/Proxy-Authorization as request header", f"{proto}-{route}",
                                    "passou", f"{len(per_route[route])} request(s), none with proxy headers", "")
            for probe, r in fidelity_runs.items():
                if not r.get("ok"):
                    res.add("Fidelidade", "capture completes", probe, "falhou", str(r.get("error"))[:200], "")

        # ------------------------------------------------------------ security
        if want("security"):
            # percent-encoded password works: the relay authenticated and relayed
            enc = read_jsonl(proxies["http_auth"])
            ok_enc = [e for e in enc if e.get("auth", {}).get("ok") and e.get("result") == "relayed"]
            res.add("Seguranca", "password percent-encoded works", "relay http auth",
                    "passou" if ok_enc else "falhou",
                    f"{len(ok_enc)} authenticated relayed connection(s) in the proxy evidence", "proxy-evidence/http_auth.jsonl")

            # allowlist refuses a destination outside it, before the proxy is contacted
            allow_dir = stamp("allow-controlled")
            r = driver(["controlled", str(allow_dir), f"http://{SITE_A}:{ORIGIN_H1}/echo-order?probe=allow-ok",
                        "--allow", f"{SITE_A}:{ORIGIN_H1}", "--nav", f"http://{SITE_A}:{ORIGIN_H1}/echo-order?probe=allow-ok",
                        "--nav", f"http://{SITE_B}:{ORIGIN_H1}/echo-order?probe=allow-no",
                        "--link", link("http", PORTS["http_auth"], creds=True)], "allow-controlled", out)
            navs = {n["url"]: n for n in r.get("navigations", [])}
            refused = navs.get(f"http://{SITE_B}:{ORIGIN_H1}/echo-order?probe=allow-no", {})
            ev_b = [e for e in read_jsonl(proxies["http_auth"]) if SITE_B in e.get("target", "")]
            origin_b = [x for x in read_jsonl(origin_dir / "acc" / "h1.jsonl") if "allow-no" in x.get("target", "")]
            if refused.get("code") == "url_not_allowed" and not ev_b and not origin_b:
                res.add("Seguranca", "allowlist refuses before the proxy", "relay, controlled",
                        "passou", f"navigate refused ({refused.get('code')}); 0 proxy records and 0 origin records for {SITE_B}",
                        "logs/allow-controlled.stdout")
            else:
                res.add("Seguranca", "allowlist refuses before the proxy", "relay, controlled", "falhou",
                        f"refused={refused!r} proxy_records={len(ev_b)} origin_records={len(origin_b)}",
                        "logs/allow-controlled.stdout")

            # HTTPS proxy with a certificate the system does not trust
            r = driver(["common", str(stamp("https-untrusted")), f"http://{SITE_A}:{ORIGIN_H1}/echo-order?probe=tls",
                        "6", "--link", link("https", PORTS["https_auth"], creds=True)], "https-untrusted", out)
            msg = (r.get("error") or "").lower()
            if not r.get("ok") and ("certificate" in msg or "tls" in msg or "trust" in msg):
                res.add("Seguranca", "untrusted HTTPS proxy certificate refused", "relay", "passou",
                        f"error: {r.get('error', '')[:200]}", "logs/https-untrusted.stdout")
            else:
                res.add("Seguranca", "untrusted HTTPS proxy certificate refused", "relay", "falhou",
                        f"ok={r.get('ok')} error={r.get('error')!r}", "logs/https-untrusted.stdout")

        # ------------------------------------------------------------ secrets scan (after all runs)
        if want("security") or want("failures") or want("fidelity") or want("export") or want("regression"):
            needles = {
                "password": PASSWORD,
                "password-percent": PCT_PASSWORD,
                "base64-user-pass": base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode(),
                "base64-user-pass-pct": base64.b64encode(f"{USER}:{PCT_PASSWORD}".encode()).decode(),
            }
            hits = []
            for path in out.rglob("*"):
                if path.is_file() and path.stat().st_size < 50_000_000:
                    try:
                        text = path.read_bytes().decode("utf-8", "replace")
                    except OSError:
                        continue
                    for label, needle in needles.items():
                        if needle in text:
                            hits.append(f"{label} in {path.relative_to(out)}")
            if hits:
                res.add("Seguranca", "no password or Base64 in any output", "all files, stdout, stderr, logs",
                        "falhou", f"{len(hits)} hit(s): {hits[:5]}", "")
            else:
                n_files = sum(1 for p in out.rglob("*") if p.is_file())
                res.add("Seguranca", "no password or Base64 in any output", "all files, stdout, stderr, logs",
                        "passou", f"0 hits in {n_files} file(s) under the run folder", "")

        # ------------------------------------------------------------ export
        if want("export"):
            sess = stamp("fid-h1-relay")
            if (sess / "session.json").exists():
                s = json.loads((sess / "session.json").read_text())
                proxy_rec = (s.get("session") or {}).get("capture", {}).get("proxy")
                res.add("Exportacao", "session records the proxy (no credentials)", "relay h1",
                        "passou" if proxy_rec else "falhou",
                        f"capture.proxy={json.dumps(proxy_rec)[:200]}", "")
            else:
                res.add("Exportacao", "session records the proxy (no credentials)", "relay h1", "nao_executado",
                        "no session folder", "")

        # ------------------------------------------------------------ export (core built from the committed HEAD)
        if want("export"):
            core = BUILD_CORE if BUILD_CORE.exists() else None
            sess = stamp("fid-h1-relay")
            if core is None or not (sess / "session.json").exists():
                res.add("Exportacao", "sanitized export without host/port", "relay h1", "nao_executado",
                        "core binary or relay session missing", "")
            else:
                dst = out / "export" / "sanitized-relay"
                sh = subprocess.run([str(core), "sanitize", str(sess), str(dst)], capture_output=True, text=True)
                (out / "logs" / "export-sanitize.stdout").write_text(sh.stdout)
                (out / "logs" / "export-sanitize.stderr").write_text(sh.stderr)
                text = "".join(f.read_text(errors="replace") for f in dst.rglob("*") if f.is_file())
                s_json = json.loads((dst / "session.json").read_text()) if (dst / "session.json").exists() else {}
                proxy_rec = ((s_json.get("session") or {}).get("capture") or {}).get("proxy")
                host_port_hits = [needle for needle in (str(PORTS["http_auth"]), "127.0.0.1:" + str(PORTS["http_auth"]))
                                  if needle in text]
                clean = (proxy_rec is None or ("host" not in proxy_rec and "port" not in proxy_rec)) \
                    and not host_port_hits and PASSWORD not in text and PCT_PASSWORD not in text
                res.add("Exportacao", "sanitized export without host/port", "relay h1",
                        "passou" if clean else "falhou",
                        f"capture.proxy={json.dumps(proxy_rec)[:160]}; proxy port in output: {host_port_hits}",
                        "export/sanitized-relay")
            # the generated script says it does not use the proxy, and carries no host or credential
            raw_sess = json.loads((sess / "session.json").read_text()) if (sess / "session.json").exists() else {}
            reqs = raw_sess.get("requests") or []
            target = next((r for r in reqs if "probe=fid-h1-relay" in str(r.get("url", ""))), None)
            if core is None or target is None:
                res.add("Exportacao", "exported script warns it does not use the proxy", "curl, python", "nao_executado",
                        "core binary or request missing", "")
            else:
                for kind in ("export-curl", "export-python"):
                    r2 = subprocess.run([str(core), kind, str(sess), target["id"]], capture_output=True, text=True)
                    script = r2.stdout
                    warned = "does not use the capture proxy" in script
                    leaked = str(PORTS["http_auth"]) in script or PASSWORD in script or PCT_PASSWORD in script
                    res.add("Exportacao", "exported script warns it does not use the proxy", kind,
                            "passou" if warned and not leaked else "falhou",
                            f"warning={'yes' if warned else 'no'}; host/port/credential in script={'yes' if leaked else 'no'}",
                            f"logs/{kind}.stdout")
            # the desktop export dialog carries the same notice (source check: the UI itself is not driven)
            ui = (REPO / "app" / "src" / "Export.tsx").read_text()
            res.add("Exportacao", "export dialog shows the notice", "App Export.tsx (source)",
                    "passou" if 'data-testid="export-proxy-notice"' in ui else "falhou",
                    "notice element present in source; dialog not driven (no window)", "")

        # ------------------------------------------------------------ regression: no-proxy sessions vs f69e9dc
        if want("regression"):
            old = build_from_archive(out, "f69e9dc")
            if old is None:
                res.add("Regressao", "sessions without proxy identical to f69e9dc", "all", "nao_executado",
                        "could not build the f69e9dc driver", "")
            else:
                url = f"http://127.0.0.1:{ORIGIN_H1}/echo-order?probe=reg-h1"
                new_run = driver(["common", str(stamp("reg-new")), url, "8"], "reg-new", out)
                old_run = subprocess.run([str(old), str(stamp("reg-old")), url, "8"],
                                         capture_output=True, text=True)
                (out / "logs" / "reg-old.stdout").write_text(old_run.stdout)
                old_line = [line for line in old_run.stdout.splitlines() if line.startswith("{")]
                old_res = json.loads(old_line[-1]) if old_line else {"ok": False}
                if not (new_run.get("ok") and old_res.get("ok")):
                    res.add("Regressao", "sessions without proxy identical to f69e9dc", "h1", "falhou",
                            f"new ok={new_run.get('ok')} old ok={old_res.get('ok')}", "logs")
                else:
                    diffs = compare_sessions(pathlib.Path(new_run["session_dir"]), pathlib.Path(old_res["session_dir"]))
                    res.add("Regressao", "sessions without proxy identical to f69e9dc", "h1",
                            "passou" if not diffs else "falhou",
                            "identical (ignoring timestamps, ids, durations, paths, absent capture.proxy)"
                            if not diffs else f"{len(diffs)} difference(s): {diffs[:3]}", "sessions")

        # ------------------------------------------------------------ MCP: SCRAPELENS_PROXY_URL is ignored without "env"
        if want("mcp"):
            mcp = subprocess.run(["cargo", "test", "-q", "--manifest-path", str(REPO / "mcp" / "Cargo.toml"),
                                  "--test", "live", "proxy_env_is_read_only"], capture_output=True, text=True)
            (out / "logs" / "mcp-env-test.stdout").write_text(mcp.stdout + mcp.stderr)
            passed = "test result: ok. 1 passed" in mcp.stdout
            res.add("MCP", "SCRAPELENS_PROXY_URL ignored without \"env\"; confirmation has no secret", "mcp prepare",
                    "passou" if passed else "falhou",
                    "cargo test mcp/tests/live.rs proxy_env_is_read_only: " + ("1 passed" if passed else "FAILED"),
                    "logs/mcp-env-test.stdout")

        # ------------------------------------------------------------ host/port leak in egress sampling
        if want("egress"):
            with LeakSampler() as sampler:
                r = driver(["common", str(stamp("egress-relay")), f"http://{SITE_A}:{ORIGIN_H1}/echo-order?probe=egress",
                            "8", "--link", link("http", PORTS["http_auth"], creds=True)], "egress-relay", out)
            if r.get("ok") and not sampler.peers:
                res.add("Egress", "Chrome peers are loopback only (macOS, indirect)", "relay",
                        "passou", f"{sampler.samples} sample(s), 0 non-loopback peers", "")
            else:
                res.add("Egress", "Chrome peers are loopback only (macOS, indirect)", "relay", "falhou",
                        f"ok={r.get('ok')} peers={sorted(sampler.peers)[:5]}", "")

    finally:
        servers.stop_all()

    (out / "results.json").write_text(json.dumps(res.rows, indent=2, ensure_ascii=False))
    print(f"\nresults: {out / 'results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
