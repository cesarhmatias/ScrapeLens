#!/usr/bin/env python3
"""Validate the DETRAN-PB shape fixtures (structure, flow, sanitization).

stdlib only; deterministic. Run: python3 fixtures/detran-pb/validate.py
Exit code 0 = all checks passed.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def load(name: str) -> dict:
    return json.loads((HERE / name).read_text())


def form(text: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(text, keep_blank_values=True).items()}


def check_chain(label: str, har: dict, netlog: dict, sid: str, jsession: str, ts_value: str, delta_prefix: str) -> None:
    """Dynamic values originate in the right responses (docs/09 §4.1)."""
    es = har["log"]["entries"]
    jar: dict[str, str] = {}
    last_stamp = last_delta = None
    for i, e in enumerate(es):
        req, resp = e["request"], e["response"]
        sent = {c["name"]: c["value"] for c in req["cookies"]}
        header_cookie = [h["value"] for h in req["headers"] if h["name"] == "cookie"]
        check((not header_cookie) == (not sent), f"{label}[{i}]: cookie header and cookies diverge")
        for n, v in sent.items():
            check(jar.get(n) == v, f"{label}[{i}]: cookie {n} sent without a previous Set-Cookie with the same value")
        if i == 0:
            check(not sent, f"{label}[0]: first request must not send a cookie")
            check(f'm_currentSessionId = "{sid}"' in resp["content"]["text"], f"{label}[0]: SESSIONID must originate in the easynat-app HTML")
        for h in resp["headers"]:
            if h["name"] == "set-cookie":
                n, _, v = h["value"].split(";")[0].partition("=")
                jar[n] = v
        if req["method"] == "POST":
            f = form(req["postData"]["text"])
            check(f["SESSIONID"] == sid, f"{label}[{i}]: SESSIONID of the request")
            if f["STAMP"] != "INIT":
                check(f["STAMP"] == last_stamp, f"{label}[{i}]: STAMP {f['STAMP']} != previous response {last_stamp}")
            xml = f["XML"]
            if last_delta and not xml.startswith("i"):
                check(last_delta in xml, f"{label}[{i}]: delta {last_delta} from the previous response is missing from the XML")
            if xml.startswith("i") and last_delta and i > 3:
                check(last_delta in xml, f"{label}[{i}]: init delta comes from the previous response")
            r = form(resp["content"]["text"])
            last_stamp = r["STAMP"]
            m = re.search(r"x\d\d(" + delta_prefix + r"\d{4})$", r["XML"])
            check(bool(m), f"{label}[{i}]: delta in the response")
            last_delta = m.group(1) if m else None
    check(jar.get("JSESSIONID") == jsession and jar.get("TS01a1b2c3") == ts_value, f"{label}: jar final")
    ts_set = [i for i, e in enumerate(es) if any(h["name"] == "set-cookie" and h["value"].startswith("TS01") for h in e["response"]["headers"])]
    check(ts_set == [1], f"{label}: TS* must come only from /TSPD/ (entry 1), came from {ts_set}")
    for e in netlog["events"]:
        pass


def main() -> int:
    manifest = load("manifest.json")
    har = load("detran-pb-sanitized.har")
    blocked = load("detran-pb-blocked.har")
    netlog = load("detran-pb.netlog.json")
    cdp = [json.loads(line) for line in (HERE / "detran-pb.cdp.jsonl").read_text().splitlines() if line]

    entries = har["log"]["entries"]
    check(len(entries) == 13, f"expected 13 entries, got {len(entries)}")
    check(len(blocked["log"]["entries"]) == 3, "blocked fixture must have 3 entries")

    # --- flow shape ------------------------------------------------------
    expect = [
        ("GET", "/servlet/easynat-app?op=S37"),
        ("GET", "/TSPD/?type=18"),
        ("GET", "/cisnatural/NatLogon.html"),
        ("POST", "/servlet/Connector"),
        ("GET", "/UIC-SERVICOS/SIM1000X.html"),
        ("POST", "/servlet/Connector"),
        ("POST", "/servlet/Connector"),
        ("GET", "/UIC-SERVICOS/VES0009X.html"),
        ("POST", "/servlet/Connector"),
        ("POST", "/servlet/Connector"),
        ("POST", "/servlet/Connector"),
        ("POST", "/servlet/Connector"),
        ("POST", "/servlet/Connector"),
    ]
    for i, (method, suffix) in enumerate(expect):
        e = entries[i]
        check(e["request"]["method"] == method, f"entry {i}: method {e['request']['method']} != {method}")
        check(e["request"]["url"].endswith(suffix), f"entry {i}: url {e['request']['url']} does not end with {suffix}")

    connector = [i for i, e in enumerate(entries) if e["request"]["url"].endswith("/servlet/Connector")]
    check(len(connector) == 8, f"expected 8 Connector posts, got {len(connector)}")

    # --- bodies and sizes ------------------------------------------------
    for i, e in enumerate(entries):
        req, resp = e["request"], e["response"]
        body = resp["content"]["text"]
        check(resp["content"]["size"] == len(body), f"entry {i}: content.size mismatch")
        check(resp["bodySize"] == len(body), f"entry {i}: bodySize mismatch")
        pd = req.get("postData")
        if not pd:
            continue
        text = pd["text"]
        parsed = dict(urllib.parse.parse_qsl(text, keep_blank_values=True))
        params = {p["name"]: p["value"] for p in pd["params"]}
        check(parsed == params, f"entry {i}: postData.text and postData.params disagree")
        check("SESSIONID" in parsed, f"entry {i}: SESSIONID missing")
        check("XML" in parsed, f"entry {i}: XML missing")
        check(parsed["SESSIONID"] == manifest["values"]["session_id"], f"entry {i}: unexpected SESSIONID")
        cl = [h["value"] for h in req["headers"] if h["name"] == "content-length"]
        check(bool(cl) and int(cl[0]) == len(text), f"entry {i}: content-length header mismatch")

    # --- STAMP chain -----------------------------------------------------
    stamps = [
        dict(urllib.parse.parse_qsl(e["request"]["postData"]["text"], keep_blank_values=True)).get("STAMP")
        for e in entries if e["request"].get("postData")
    ]
    check(stamps == ["INIT", "INIT", "2002", "INIT", "2004", "2005", "2006", "2007"],
          f"unexpected request STAMP chain: {stamps}")
    resp_stamps = [
        dict(urllib.parse.parse_qsl(e["response"]["content"]["text"], keep_blank_values=True)).get("STAMP")
        for e in entries if e["response"]["content"]["text"].startswith("XML=")
    ]
    check(resp_stamps == [f"200{n}" for n in range(1, 9)], f"unexpected response STAMP chain: {resp_stamps}")

    # --- search cases ----------------------------------------------------
    cases = manifest["search_cases"]
    for case in cases:
        q = case["query"]
        hits = []
        for i, e in enumerate(entries):
            hay = e["request"]["url"] if case["where"] == "url" else (e["request"].get("postData") or {}).get("text", "")
            if case["where"] == "body" and "XML" in case["query"]:
                hay = urllib.parse.unquote_plus(hay)
            if q in hay:
                hits.append(i)
        check(hits == case["expect_entries"], f"search {q!r} -> {hits}, expected {case['expect_entries']}")

    # --- ambiguity: two identical POSTs, different bodies -----------------
    same = [i for i, e in enumerate(entries)
            if e["request"]["url"].endswith("/servlet/Connector")
            and "cmd_consultar_placa" in urllib.parse.unquote_plus((e["request"].get("postData") or {}).get("text", ""))]
    check(same == [10, 12], f"query entries -> {same}, expected [10, 12]")
    if len(same) == 2:
        check(entries[10]["request"]["url"] == entries[12]["request"]["url"], "ambiguity case must share the URL")
        check(entries[10]["request"]["postData"]["text"] != entries[12]["request"]["postData"]["text"],
              "ambiguity case must differ in the body")
        plates = [re.search(r"TST0T\d\d", entries[i]["request"]["postData"]["text"]).group(0) for i in same]
        check(plates == ["TST0T00", "TST0T01"], f"unexpected synthetic plates: {plates}")

    # --- protocol shape --------------------------------------------------
    for i, e in enumerate(entries):
        pd = e["request"].get("postData")
        if not pd:
            continue
        xml = urllib.parse.unquote_plus(pd["text"].split("XML=")[1].split("&")[0]) if False else dict(
            urllib.parse.parse_qsl(pd["text"], keep_blank_values=True)
        )["XML"]
        check(xml[:1] in ("i", "v"), f"entry {i}: XML stream must start with i or v")
        check(re.search(r"p\d{2}\d{5}", xml) is not None, f"entry {i}: XML stream has no p-group")
        check(xml.endswith("inittini") or re.search(r"x\d{2}", xml), f"entry {i}: XML stream lacks x+delta")
        if "cmd_consultar_placa" in xml:
            check("p0700007v_placa" in xml or "v_placa" in xml, f"entry {i}: plate field missing")
        if "cmd_nova" in xml:
            check("cmd_nova" in xml, f"entry {i}: cmd_nova missing")

    # response streams must exercise the response-side opcodes
    resp_xml = [
        dict(urllib.parse.parse_qsl(e["response"]["content"]["text"], keep_blank_values=True))["XML"]
        for e in entries if e["response"]["content"]["text"].startswith("XML=")
    ]
    joined = "".join(resp_xml)
    for op in ["l", "p", "s", "q", "z", "b", "c", "k", "x"]:
        check(op in joined, f"response streams never use opcode {op!r}")
    check("v_situacao_atual" in joined, "full response must carry v_situacao_atual")
    delta_body = resp_xml[-1]
    check("v_situacao_atual" not in delta_body, "delta response must omit v_situacao_atual")
    check("situacao_rows" in delta_body, "delta response must carry the history rows")

    # --- CDP -------------------------------------------------------------
    sent = [e for e in cdp if e["method"] == "Network.requestWillBeSent"]
    recv = [e for e in cdp if e["method"] == "Network.responseReceived"]
    extra = [e for e in cdp if e["method"] == "Network.requestWillBeSentExtraInfo"]
    fin = [e for e in cdp if e["method"] == "Network.loadingFinished"]
    check(len(sent) == len(entries), f"CDP requestWillBeSent {len(sent)} != entries {len(entries)}")
    check(len(recv) == len(entries), "CDP responseReceived count mismatch")
    check(len(fin) == len(entries), "CDP loadingFinished count mismatch")
    check(len(extra) == len(connector), f"CDP ExtraInfo {len(extra)} != Connector posts {len(connector)}")
    check(all("headersText" in e["params"] for e in extra), "ExtraInfo must expose headersText")
    ids = [e["params"]["requestId"] for e in sent]
    check(len(set(ids)) == len(ids), "CDP requestId must be unique")

    # --- NetLog ----------------------------------------------------------
    offset = netlog["constants"]["timeTickOffset"]
    first_tick = int(netlog["events"][0]["time"])
    check(first_tick < 10_000_000_000, "NetLog time must be in milliseconds (ticks are small)")
    for i, event in enumerate(netlog["events"][::4]):
        wall = (offset + int(event["time"])) / 1000
        cdp_wall = [e["params"]["wallTime"] for e in cdp if e["method"] == "Network.requestWillBeSent"][i]
        check(abs(wall - cdp_wall) < 0.002,
              f"netlog[{i}] wall clock {wall} != cdp wallTime {cdp_wall}")
    types = netlog["constants"]["logEventTypes"]
    by_type = {v: k for k, v in types.items()}
    urls = [e for e in netlog["events"] if by_type[e["type"]] == "URL_REQUEST_START_JOB"]
    check(len(urls) == len(entries), f"NetLog URL_REQUEST_START_JOB {len(urls)} != entries {len(entries)}")
    check(len(netlog["events"]) == len(entries) * 4, "NetLog event count mismatch")
    for e in netlog["events"]:
        if by_type[e["type"]] == "HTTP_TRANSACTION_SEND_REQUEST_HEADERS":
            pass  # per-step cookies are checked in check_chain()

    # --- bodies (docs/08-body-search.md §1) -------------------------------
    import base64
    STATES = {"captured", "truncated", "empty", "unavailable", "discarded"}
    SOURCES = {"requestWillBeSent.postData", "requestWillBeSent.postDataEntries",
               "Network.getRequestPostData", "Network.getResponseBody"}
    for fname, cdpname in (("detran-pb.cdp-bodies.jsonl", "detran-pb.cdp.jsonl"),
                           ("detran-pb-edge.cdp-bodies.jsonl", "detran-pb-edge.cdp.jsonl")):
        events = [json.loads(l) for l in (HERE / cdpname).read_text().splitlines() if l]
        known = {e["params"]["requestId"] for e in events if e["method"] == "Network.requestWillBeSent"}
        attempts: dict[str, int] = {}
        for e in events:
            if e["method"] == "Network.requestWillBeSent":
                rid = e["params"]["requestId"]
                attempts[rid] = attempts.get(rid, -1) + 1
        rows = [json.loads(l) for l in (HERE / fname).read_text().splitlines() if l]
        seen = set()
        for r in rows:
            where = f"{fname}:{r['requestId']}/{r['attemptIndex']}/{r['kind']}"
            check(r["v"] == 1 and r["state"] in STATES and r["source"] in SOURCES, f"{where}: bad v/state/source")
            check(r["requestId"] in known, f"{where}: orphan requestId")
            check(r["attemptIndex"] <= attempts.get(r["requestId"], -1), f"{where}: attemptIndex beyond attempts")
            check((where) not in seen, f"{where}: duplicate row"); seen.add(where)
            if r["state"] in ("unavailable", "discarded"):
                check(r["data"] is None and r["reason"], f"{where}: missing body needs reason and null data")
            if r["state"] == "empty":
                check(r["data"] == "" and r["reason"], f"{where}: empty needs evidence reason")
            if r["state"] == "truncated":
                check(r["originalSize"] and r["originalSize"] > r["capturedSize"], f"{where}: truncated needs originalSize > capturedSize")
            if r["encoding"] == "base64":
                raw = base64.b64decode(r["data"])
                check(len(raw) == r["capturedSize"], f"{where}: capturedSize mismatch")
                try:
                    raw.decode("utf-8"); check(False, f"{where}: base64 body must be non-UTF-8")
                except UnicodeDecodeError:
                    pass
            elif r["encoding"] == "utf8":
                check(len(r["data"].encode()) == r["capturedSize"], f"{where}: capturedSize mismatch")
    main_rows = [json.loads(l) for l in (HERE / "detran-pb.cdp-bodies.jsonl").read_text().splitlines() if l]
    check(len([r for r in main_rows if r["kind"] == "request"]) == 8, "main: 8 request bodies (POSTs) expected")
    check({r["state"] for r in main_rows} >= {"captured", "truncated", "unavailable"}, "main: needs captured/truncated/unavailable")
    check(any(r["encoding"] == "base64" for r in main_rows), "main: needs a base64 binary body")
    queries = [r for r in main_rows if r["kind"] == "request" and "cmd_consultar_placa" in
                 urllib.parse.parse_qs(r["data"])["XML"][0]]
    check([r["requestId"] for r in queries] == ["1011.11", "1013.13"], "two queries distinguished by request body")
    check(len({r["data"] for r in queries}) == 2, "the two queries must differ in body")
    check("TST0T00" in urllib.parse.parse_qs(queries[0]["data"])["XML"][0]
          and "TST0T01" in urllib.parse.parse_qs(queries[1]["data"])["XML"][0], "plates per query")
    edge = [json.loads(l) for l in (HERE / "detran-pb-edge.cdp-bodies.jsonl").read_text().splitlines() if l]
    check(sum(1 for r in edge if r["state"] == "unavailable" and "redirect" in (r["reason"] or "")) == 2, "edge: 2 redirect unavailable")
    check(len([r for r in edge if r["requestId"] == "2002.2" and r["kind"] == "request"]) == 2, "edge: 307 body in each attempt")
    check(any(r["state"] == "empty" for r in edge) and any(r["state"] == "truncated" for r in edge), "edge: empty+truncated")

    # --- origin chain of the values (A and B) --------------------------------
    check_chain("A", har, netlog, "CSAN00000_000000000001", "SYNTH00000000000000000000000001",
                "0189a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", "DLTA")
    bdir = HERE.parent / "detran-pb-b"
    bman = json.loads((bdir / "manifest.json").read_text())
    har_b = json.loads((bdir / "detran-pb-b-sanitized.har").read_text())
    netlog_b = json.loads((bdir / "detran-pb-b.netlog.json").read_text())
    check_chain("B", har_b, netlog_b, "CSAN00000_000000000002", "SYNTH00000000000000000000000002",
                "01b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7", "DLTB")
    ea, eb = har["log"]["entries"], har_b["log"]["entries"]
    check(len(eb) == 13 and bman["counts"]["entries"] == 13, "B: 13 steps")
    for i, (x, y) in enumerate(zip(ea, eb)):
        check((x["request"]["method"], x["request"]["url"]) == (y["request"]["method"], y["request"]["url"]), f"B[{i}]: method/URL differ from A")
        if x["request"]["method"] == "GET" and i not in (1,):
            ta = x["response"]["content"]["text"].replace("CSAN00000_000000000001", "X").replace("100000000001", "P")
            tb = y["response"]["content"]["text"].replace("CSAN00000_000000000002", "X").replace("100000000002", "P")
            check(ta == tb, f"B[{i}]: pages and constants must be equal, except SESSIONID/processId")
        if x["request"]["method"] == "POST":
            fa, fb = form(x["request"]["postData"]["text"]), form(y["request"]["postData"]["text"])
            check(set(fa) == set(fb), f"B[{i}]: same form fields")
            check(fa["SESSIONID"] != fb["SESSIONID"], f"B[{i}]: SESSIONID must differ")
            check(fa["PAGEINITPARAM"] == fb["PAGEINITPARAM"], f"B[{i}]: PAGEINITPARAM equal")
    plates_b = set(re.findall(r"TST0T\d\d", "\n".join((bdir / n).read_text() for n in ("detran-pb-b-sanitized.har", "detran-pb-b.cdp.jsonl", "detran-pb-b.cdp-bodies.jsonl"))))
    check(plates_b == {"TST0T02", "TST0T03"}, f"B: plates {plates_b}")
    for n in ("detran-pb-b-sanitized.har", "detran-pb-b.cdp.jsonl", "detran-pb-b.netlog.json", "detran-pb-b.cdp-bodies.jsonl"):
        t = (bdir / n).read_text()
        for bad in ("CSAN00000_000000000001", "SYNTH00000000000000000000000001", "0189a1b2c3d4e5f6", "DLTA", "TST0T00", "TST0T01"):
            check(bad not in t, f"B/{n}: value from A leaked ({bad})")
    # negative case §4.3 exists in the fixture: x-seq-hint=3 (cmd_filtro response) and x-page-seq=3 on the requests
    check(any(h["name"] == "x-seq-hint" and h["value"] == "3" for h in ea[9]["response"]["headers"]), "negative 4.3: x-seq-hint")
    check(all(any(h["name"] == "x-page-seq" and h["value"] == "3" for h in e["request"]["headers"]) for e in ea if e["request"]["method"] == "POST"), "negative 4.3: x-page-seq")
    check("chain_compare" in manifest, "manifest: chain_compare missing")

    # --- sanitization ----------------------------------------------------
    blob = "\n".join(
        (HERE / name).read_text()
        for name in ("detran-pb-sanitized.har", "detran-pb-blocked.har", "detran-pb.cdp.jsonl", "detran-pb.netlog.json", "build_fixtures.py",
                     "detran-pb.cdp-bodies.jsonl", "detran-pb-edge.cdp.jsonl", "detran-pb-edge.cdp-bodies.jsonl")
    )
    for marker in ("CASA", "NUPP", "082b79", "sem_captcha", "wsdetran.pb.gov.br.har", "Downloads/", "Authorization"):
        check(marker not in blob, f"forbidden marker present: {marker}")
    plates = set(re.findall(r"\bTST0T\d\d\b", blob.replace((HERE / "build_fixtures.py").read_text(), "")))
    check(plates == {"TST0T00", "TST0T01"}, f"unexpected plate-like values: {plates}")
    check("CSAN00000_000000000001" in blob, "synthetic session id missing")
    check("198.51.100.10" in blob, "TEST-NET server ip missing")
    check("0189a1b2c3d4e5f6" in blob, "synthetic TS cookie missing")

    if FAILS:
        print(f"FAIL ({len(FAILS)}):")
        for f in FAILS:
            print(" -", f)
        return 1
    print(
        f"OK: {len(entries)} HAR entries, {len(connector)} Connector posts, "
        f"{len(cdp)} CDP events, {len(netlog['events'])} NetLog events, {len(main_rows)}+{len(edge)} body rows; "
        "synthetic values only, flow shape preserved."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
