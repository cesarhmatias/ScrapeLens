#!/usr/bin/env python3
"""Live verification of cdp-bodies.jsonl (real Chrome + local testserver h1).

usage: python3 run_bodies.py [--port 9781] [--out results/bodies]
Does not use the external network. Server, Chrome and profile are temporary.
"""
import http.server, threading, shutil
import argparse, base64, gzip, hashlib, json, os, pathlib, signal, subprocess, sys, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
MAX = 5 * 1024 * 1024
GZIP_TEXT = "synthetic gzip body for ScrapeLens: cmd_consultar_placa TST0T00\n"


def sha(b): return hashlib.sha256(b).hexdigest()


def get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.status, r.read()


def line_bytes(total):
    line = b"scrapelens-big-body 0123456789abcdef synthetic line\n"
    return (line * (total // len(line) + 1))[:total]


def row_bytes(row):
    if row["data"] is None: return None
    return base64.b64decode(row["data"]) if row["encoding"] == "base64" else row["data"].encode()


LATIN1 = bytes([0x53, 0xE3, 0x6F])  # "São" in ISO-8859-1 on the wire (non-ASCII input on purpose)


class Latin1(http.server.BaseHTTPRequestHandler):
    """Experiment-specific route (testserver/ is not edited)."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=iso-8859-1")
        self.send_header("Content-Length", str(len(LATIN1)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(LATIN1)
    def log_message(self, *a): pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9781)
    ap.add_argument("--keep", action="store_true", help="do not delete session/, server/ and tmp/ (hundreds of MB)")
    ap.add_argument("--out", default=str(HERE.parent / "results" / "bodies"))
    a = ap.parse_args()
    if subprocess.run(["pgrep", "-f", "live_bodies_cycle"], capture_output=True).stdout.strip():
        sys.exit("a live_bodies_cycle capture is already running; stop it first")
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    session = out / "session"; tmp = out / "tmp"; srv = out / "server"
    for d in (session, tmp, srv):
        subprocess.run(["rm", "-rf", str(d)])
    tmp.mkdir(); stop = out / "stop"; stop.unlink(missing_ok=True)
    base = f"http://127.0.0.1:{a.port}"
    latin = http.server.ThreadingHTTPServer(("127.0.0.1", a.port + 1), Latin1)
    threading.Thread(target=latin.serve_forever, daemon=True).start()
    test = None
    server = subprocess.Popen(
        [str(ROOT / "target/debug/scrapelens-testserver"), "serve", "--only", "h1",
         "--h1", f"127.0.0.1:{a.port}", "--evidence", str(srv), "--run-id", "bodies"],
        stdout=open(out / "server.log", "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try: get(base + "/healthz"); break
            except Exception: time.sleep(0.1)
        env = dict(os.environ, TMPDIR=str(tmp), SL_LIVE_START_URL=base + "/healthz",
                   SL_LIVE_SESSION_DIR=str(session), SL_LIVE_STOP_FILE=str(stop))
        test = subprocess.Popen(
            ["cargo", "test", "live_bodies_cycle", "--", "--ignored", "--nocapture"],
            cwd=ROOT / "src-tauri", env=env, stdout=open(out / "capture.log", "w"), stderr=subprocess.STDOUT)
        drv = subprocess.run(["node", str(HERE / "drive.mjs"), str(tmp), base, str(out / "page.json"), str(stop)],
                             capture_output=True, text=True, timeout=300)
        if drv.returncode: sys.exit("driver failed: " + drv.stderr)
        if test.wait(timeout=120): sys.exit("capture failed; see capture.log")
        report = verify(out, session, base)
    finally:
        # Never leave an orphan capture behind (two captures in the same directory
        # corrupt each other): ask for a graceful shutdown and wait.
        if test is not None and test.poll() is None:
            stop.write_text("stop\n")
            try: test.wait(timeout=90)
            except Exception: test.kill()
        latin.shutdown()
        server.send_signal(signal.SIGINT)
        try: server.wait(timeout=5)
        except Exception: server.kill()
    write_sample(session, out)
    scrub_paths(out)
    if not a.keep:
        for d in ("session", "server", "tmp"): shutil.rmtree(out / d, ignore_errors=True)
        stop.unlink(missing_ok=True)
    (out / "verification.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    write_md(out, report)
    ok = all(c["ok"] for c in report["cases"])
    print(json.dumps({"ok": ok, "cases": [(c["case"], c["ok"]) for c in report["cases"]]}, ensure_ascii=False))
    sys.exit(0 if ok else 1)


def write_sample(session, out):
    """Small synthetic sample of the lines (long data shortened)."""
    lines = []
    for l in open(session / "cdp-bodies.jsonl"):
        r = json.loads(l)
        if r["data"] and len(r["data"]) > 160:
            r["data"] = r["data"][:96] + f"…<{len(r['data'])} chars omitted>"
        lines.append(json.dumps(r, ensure_ascii=False))
    (out / "sample-lines.jsonl").write_text("\n".join(lines) + "\n")


def scrub_paths(out):
    """No machine paths (user name) in the versioned artifacts."""
    home = str(pathlib.Path.home())
    for name in ("sample-lines.jsonl", "capture.log", "server.log", "page.json"):
        f = out / name
        if f.exists():
            f.write_text(f.read_text().replace(str(ROOT), "<repo>").replace(home, "~"))


def verify(out, session, base):
    page = {c["case"]: c for c in json.load(open(out / "page.json"))}
    events = [json.loads(l) for l in open(session / "cdp-events.jsonl")]
    rows = [json.loads(l) for l in open(session / "cdp-bodies.jsonl")]
    mode = oct((session / "cdp-bodies.jsonl").stat().st_mode & 0o777)
    # requestId -> case (from the query of the 1st attempt)
    case_of, urls = {}, {}
    for e in events:
        if e.get("method") != "Network.requestWillBeSent": continue
        p = e["params"]; url = p["request"]["url"]
        urls.setdefault(p["requestId"], []).append((url, p["request"]["method"], bool(p.get("redirectResponse"))))
        if "case=" in url: case_of[p["requestId"]] = url.split("case=")[1].split("&")[0]
    by_case = {}
    for r in rows:
        c = case_of.get(r["requestId"])
        if c: by_case.setdefault(c, []).append(r)
    served = {
        "gzip": gzip.decompress(get(base + "/gzip")[1]) if False else GZIP_TEXT.encode(),
        "binary_get": get(base + "/binary")[1],
        "json_get": get(base + "/json")[1],
        "big_get": line_bytes(6 * 1024 * 1024),
    }
    # gzip: the server really serves gzip; confirm by independent decompression
    req = urllib.request.Request(base + "/gzip")
    with urllib.request.urlopen(req) as r:
        raw = r.read(); assert r.headers["content-encoding"] == "gzip"
        served["gzip"] = gzip.decompress(raw)
        served["gzip_wire_len"] = len(raw)
    cases = []
    def add(name, ok, detail): cases.append({"case": name, "ok": bool(ok), **detail})
    def pick(name, kind, attempt=None):
        return [r for r in by_case.get(name, []) if r["kind"] == kind and (attempt is None or r["attemptIndex"] == attempt)]
    def summary(r):
        return {k: r[k] for k in ("state", "encoding", "originalSize", "capturedSize", "source", "reason", "attemptIndex")}
    for name in ("form", "json", "binary"):
        rq = pick(name, "request"); rs = pick(name, "response"); pg = page[name]
        b = row_bytes(rq[0]) if rq else None
        srv_sha = pg["serverReport"]["sha256"]
        add(name, rq and rq[0]["state"] == "captured" and sha(b) == pg["sentSha"] == srv_sha and len(b) == pg["sentLen"],
            {"request": summary(rq[0]) if rq else None, "bytes": len(b or b""), "cdpSha": sha(b or b""),
             "pageSentSha": pg["sentSha"], "serverSha": srv_sha, "response": summary(rs[0]) if rs else None})
    # binary echo: response = served bytes (the server returns the received body)
    pg = page["echo_binary"]; rq = pick("echo_binary", "request"); rs = pick("echo_binary", "response")
    rb = row_bytes(rs[0]) if rs else None
    add("echo_binary", rs and rs[0]["state"] == "captured" and rs[0]["encoding"] == "base64" and sha(rb) == pg["recvSha"] == pg["sentSha"] and row_bytes(rq[0]) == rb,
        {"request": summary(rq[0]), "response": summary(rs[0]) if rs else None, "responseSha": sha(rb or b"")})
    # > 5 MiB (request and response)
    pg = page["big_post"]; rq = pick("big_post", "request")
    sent = line_bytes(6 * 1024 * 1024)
    b = row_bytes(rq[0]) if rq else b""
    add("big_post", rq and rq[0]["state"] == "truncated" and rq[0]["originalSize"] == len(sent) and len(b) == MAX and b == sent[:MAX] and sha(sent) == pg["sentSha"],
        {"request": summary(rq[0]) if rq else None, "prefixEqualsSent": b == sent[:MAX], "serverReport": {k: pg["serverReport"].get(k) for k in ("len", "truncated", "sha256")}})
    # > 5 MiB binary (no postDataEntries: depends on Network.getRequestPostData)
    pg = page["big_binary_post"]; rq = pick("big_binary_post", "request")
    bb = bytes((i * 13 + 0x91) & 0xFF for i in range(6 * 1024 * 1024)); b = row_bytes(rq[0]) if rq else b""
    add("big_binary_post", rq and rq[0]["state"] == "truncated" and b == bb[:MAX] and rq[0]["originalSize"] == len(bb) and sha(bb) == pg["sentSha"],
        {"request": summary(rq[0]) if rq else None, "prefixEqualsSent": b == bb[:MAX], "cdpPrefixLen": len(b or b""),
         "nota": "if it fails: getRequestPostData returns a converted string (U+FFFD), not the exact bytes"})
    rs = pick("big_get", "response"); b = row_bytes(rs[0]) if rs else b""
    add("big_get", rs and rs[0]["state"] == "truncated" and rs[0]["originalSize"] == len(served["big_get"]) and b == served["big_get"][:MAX] and page["big_get"]["recvSha"] == sha(served["big_get"]),
        {"response": summary(rs[0]) if rs else None, "prefixEqualsServed": b == served["big_get"][:MAX]})
    # gzip, binary, json (response identical to what was served, already decoded by Chrome)
    for name in ("gzip", "binary_get", "json_get"):
        rs = pick(name, "response"); b = row_bytes(rs[0]) if rs else None
        add(name, rs and rs[0]["state"] == "captured" and b == served[name] and sha(b) == page[name]["recvSha"],
            {"response": summary(rs[0]) if rs else None, "servedSha": sha(served[name]), "cdpSha": sha(b or b""),
             **({"wireGzipBytes": served["gzip_wire_len"], "decodedBytes": len(b or b"")} if name == "gzip" else {})})
    # 302
    r0 = pick("r302", "response", 0); r1 = pick("r302", "response", 1)
    add("r302", r0 and r0[0]["state"] == "unavailable" and "redirect" in r0[0]["reason"] and r1 and r1[0]["state"] == "captured" and row_bytes(r1[0]) == served["json_get"],
        {"attempt0": summary(r0[0]) if r0 else None, "attempt1": summary(r1[0]) if r1 else None, "chain": urls.get(next((k for k, v in case_of.items() if v == "r302"), ""))})
    # 307 with body: body in each attempt
    q0 = pick("r307", "request", 0); q1 = pick("r307", "request", 1); r0 = pick("r307", "response", 0); r1 = pick("r307", "response", 1)
    pg = page["r307"]
    add("r307", q0 and q1 and row_bytes(q0[0]) == row_bytes(q1[0]) and sha(row_bytes(q0[0])) == pg["sentSha"] and r0 and r0[0]["state"] == "unavailable"
        and r1 and r1[0]["state"] == "captured" and pg["finalUrl"].endswith("/sink"),
        {"request0": summary(q0[0]) if q0 else None, "request1": summary(q1[0]) if q1 else None, "response0": summary(r0[0]) if r0 else None,
         "response1": summary(r1[0]) if r1 else None, "pageSentSha": pg["sentSha"], "cdpSha": sha(row_bytes(q0[0]) or b"")})
    # empty: only with evidence
    e = pick("empty204", "response"); z = pick("zero", "response")
    add("empty204", e and e[0]["state"] == "empty" and e[0]["data"] is None, {"response": summary(e[0]) if e else None})
    add("zero", z and z[0]["state"] in ("empty", "unavailable"), {"response": summary(z[0]) if z else None,
        "nota": "Content-Length: 0 comes from responseReceived.response.headers; if CDP omits the header, it becomes unavailable (never empty without evidence)"})
    # ISO-8859-1: wire bytes 53 e3 6f; CDP delivers text that is already decoded
    l = pick("latin1", "response")
    add("latin1", l and l[0]["state"] == "captured" and l[0]["data"].encode() == "São".encode() and l[0]["data"].encode() != LATIN1
        and l[0].get("transformed") == ["chrome-decoded", "charset:iso-8859-1->utf-8"] and page["latin1"]["recvLen"] == 3,
        {"response": summary(l[0]) if l else None, "transformed": l[0].get("transformed") if l else None,
         "wireBytesHex": LATIN1.hex(), "cdpBytesHex": l[0]["data"].encode().hex() if l else None})
    # failure
    f = pick("refused", "response")
    add("refused", f and f[0]["state"] == "unavailable" and "ERR_" in f[0]["reason"], {"response": summary(f[0]) if f else None})
    # general invariants
    bad = [r for r in rows if r["state"] in ("captured", "truncated") and r["data"] is None]
    add("invariants", not bad and mode == "0o600", {"mode": mode, "rows": len(rows), "byState": {s: sum(1 for r in rows if r["state"] == s) for s in {r["state"] for r in rows}}})
    add_session_checks(session, add, by_case)
    return {"chrome": subprocess.run(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--version"], capture_output=True, text=True).stdout.strip(), "cases": cases}


CORE = ROOT / "target/debug/scrapelens-core"


def add_session_checks(session, add, by_case):
    """The FINAL session (session.json + attachments/) holds the bodies and search finds them."""
    doc = json.load(open(session / "session.json"))
    att = session / "attachments"
    modes = {oct(p.stat().st_mode & 0o777) for p in att.iterdir()}
    by_url = {r["url"].split("case=")[-1].split("&")[0]: r for r in doc["requests"] if "case=" in r["url"]}
    def body(case, attempt, side):
        r = by_url[case]; return r["attempts"][attempt].get(side)
    def data(b): return (att / b["attachment"]).read_bytes()
    form = body("form", 0, "requestBody"); gz = body("gzip", 0, "responseBody")
    bb = body("binary_get", 0, "responseBody"); big = body("big_get", 0, "responseBody")
    r302 = by_url["r302"]["attempts"]; r307 = by_url["r307"]["attempts"]
    z = body("zero", 0, "responseBody"); e = body("empty204", 0, "responseBody"); rf = body("refused", 0, "responseBody")
    add("session_bodies", form["state"] == "captured" and data(form).startswith(b"cmd_consultar_placa=1")
        and gz["state"] == "captured" and data(gz) == GZIP_TEXT.encode() and bb["state"] == "captured" and len(data(bb)) == 4099
        and big["state"] == "truncated" and big.get("bytes") == 6 * 1024 * 1024 and big.get("truncatedAt") == MAX and len(data(big)) == MAX
        and r302[0]["responseBody"]["state"] == "unavailable" and r302[-1]["responseBody"]["state"] == "captured"
        and all(a["requestBody"]["state"] == "captured" for a in r307[:2])
        and z["state"] == "empty" and e["state"] == "empty" and rf["state"] == "unavailable" and modes == {"0o600"},
        {"attachments": len(list(att.iterdir())), "attachmentModes": sorted(modes),
         "states": {"form.req": form["state"], "gzip.resp": gz["state"], "big_get.resp": big["state"], "r302.a0.resp": r302[0]["responseBody"]["state"],
                    "zero": z["state"], "204": e["state"], "refused": rf["state"]},
         "bodiesFileAbsentWarning": any(w["code"] == "cdp.bodies_file_absent" for w in doc["warnings"])})
    add("session_label", doc["session"].get("labels") == ["live-capture"], {"labels": doc["session"].get("labels")})
    out = subprocess.run([str(CORE), "search", str(session), "cmd_consultar_placa", "--scope", "requestBody"], capture_output=True, text=True)
    matches = json.loads(out.stdout)["matches"] if out.returncode == 0 else []
    url_of = {m["requestId"]: next(r["url"] for r in doc["requests"] if r["id"] == m["requestId"]) for m in matches}
    cases = {u.split("case=")[-1].split("&")[0] for u in url_of.values()}
    url_scope = subprocess.run([str(CORE), "search", str(session), "cmd_consultar_placa", "--scope", "url"], capture_output=True, text=True)
    add("session_search", {"form", "json", "r307"} <= cases and all(m["scope"] == "requestBody" for m in matches) and not json.loads(url_scope.stdout)["matches"],
        {"matchCases": sorted(cases), "matchCount": len(matches), "urlScopeMatches": len(json.loads(url_scope.stdout)["matches"]),
         "first": matches[:1]})


def write_md(out, report):
    L = [f"# Live bodies — {report['chrome']}", "", "| case | ok | state(s) | detail |", "|---|---|---|---|"]
    for c in report["cases"]:
        states = ", ".join(f"{k}:{v['state']}" for k, v in c.items() if isinstance(v, dict) and "state" in v)
        L.append(f"| {c['case']} | {'✓' if c['ok'] else '✗'} | {states} | |")
    (out / "report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
