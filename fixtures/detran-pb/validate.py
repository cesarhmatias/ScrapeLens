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
    check(same == [10, 12], f"consultar entries -> {same}, expected [10, 12]")
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
            check("p0700007v_placa" in xml or "v_placa" in xml, f"entry {i}: placa field missing")
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
    for i, event in enumerate(netlog["events"][::4]):
        wall = (offset + int(event["time"]) / 1000) / 1000
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
            check(any(h.startswith("cookie:") for h in e["params"]["headers"]), "NetLog request headers must include cookie")

    # --- sanitization ----------------------------------------------------
    blob = "\n".join(
        (HERE / name).read_text()
        for name in ("detran-pb-sanitized.har", "detran-pb-blocked.har", "detran-pb.cdp.jsonl", "detran-pb.netlog.json", "build_fixtures.py")
    )
    for marker in ("CASA", "NUPP", "082b79", "sem_captcha", "wsdetran.pb.gov.br.har", "Downloads/", "Authorization"):
        check(marker not in blob, f"forbidden marker present: {marker}")
    plates = set(re.findall(r"\bTST0T\d\d\b", blob))
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
        f"{len(cdp)} CDP events, {len(netlog['events'])} NetLog events; "
        "synthetic values only, flow shape preserved."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
