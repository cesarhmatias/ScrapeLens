#!/usr/bin/env python3
"""Validates the real shape of the fixtures (stdlib). Exit 0 = ok. Run: python3 fixtures/detran-pb-real-shape/validate.py"""
from __future__ import annotations

import html
import json
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def groups(xml):
    ws = [2, 2, 2, 2, 2, 3, 5, 1]
    lens = [int(xml[1 + sum(ws[:i]):1 + sum(ws[:i + 1])]) for i in range(8)]
    pos, parts = 1 + sum(ws), []
    for l in lens:
        parts.append(xml[pos:pos + l]); pos += l
    g = {}
    while pos < len(xml) and xml[pos] == "p":
        a, b = int(xml[pos + 1:pos + 3]), int(xml[pos + 3:pos + 8]); pos += 8
        g[xml[pos:pos + a]] = xml[pos + a:pos + a + b]; pos += a + b
    return parts, g


def delta(xml):
    m = re.search(r"x(\d\d)(.{1,99})$", xml, re.S)
    return m.group(2) if m and len(m.group(2)) == int(m.group(1)) else None


def resp_controls(t):
    xm = re.search(r'<textarea[^>]*name="XML"[^>]*>(.*?)</textarea>', t, re.S)
    st = re.search(r'<input[^>]*type="hidden"[^>]*name="STAMP"[^>]*value="([^"]*)"', t)
    er = re.search(r'<textarea[^>]*name="ERRORMESSAGE"[^>]*></textarea>', t)
    return (html.unescape(xm.group(1)) if xm else None), (st.group(1) if st else None), bool(er), (xm.group(1) if xm else "")


def main():
    man = json.loads((HERE / "manifest.json").read_text())
    total_posts = total_get = 0
    for key, fname, rounds in (("1round", "real-shape-1round.har", ["a1"]), ("2rounds", "real-shape-2rounds.har", ["b1", "b2"])):
        har = json.loads((HERE / fname).read_text())
        es = har["log"]["entries"]
        check(har["log"]["creator"]["name"] == "WebInspector", f"{fname}: creator")
        check(len(es) == man["counts"][key], f"{fname}: count {len(es)}")
        check(all(not e["request"]["cookies"] and not e["response"]["cookies"] for e in es), f"{fname}: cookies[] must be empty")
        check(not any(h["name"].lower() in ("cookie", "set-cookie") for e in es for h in e["request"]["headers"] + e["response"]["headers"]),
              f"{fname}: no Cookie/Set-Cookie")
        check(all("postData" not in e["request"] for e in es if e["request"]["method"] == "GET"), f"{fname}: GET without postData")
        posts = [e for e in es if e["request"]["method"] == "POST"]
        check(len(posts) == 8 * len(rounds), f"{fname}: {len(posts)} POSTs")
        total_posts += len(posts); total_get += len(es) - len(posts)
        stamp = delta_prev = None
        events, plates, cpfs, entities = [], set(), set(), 0
        for e in posts:
            f = urllib.parse.parse_qs(e["request"]["postData"]["text"], keep_blank_values=True)
            parts, g = groups(f["XML"][0])
            events.append(parts[6] or "init")
            if parts[6] == "" and f["STAMP"][0] != "INIT":
                FAILS.append(f"{fname}: init with STAMP != INIT")
            if parts[5].endswith("NatLogon.html") and parts[6] == "":
                stamp = delta_prev = None  # new round
            if f["STAMP"][0] != "INIT":
                check(f["STAMP"][0] == stamp, f"{fname}: STAMP does not come from the previous response")
            if delta_prev:
                check(delta_prev == delta(f["XML"][0]), f"{fname}: delta does not come from the previous response")
            if "v_placa" in g: plates.add(g["v_placa"])
            if "v_cpf" in g: cpfs.add(g["v_cpf"])
            t = e["response"]["content"]["text"]
            xml, st, er, raw = resp_controls(t)
            check(xml is not None and st is not None and er, f"{fname}: Connector HTML controls")
            check(9000 <= len(t.encode()) <= 12000, f"{fname}: size {len(t.encode())} outside ~10 KB")
            check("<SYNTHETIC_GUARD_DO_NOT_TOUCH>" in t and t.index("<script") < t.index("<textarea"), f"{fname}: script before the controls")
            entities += raw.count("&amp;") + raw.count("&lt;") + raw.count("&gt;")
            stamp, delta_prev = st, delta(xml)
        check(entities >= len(rounds), f"{fname}: HTML entities missing")
        check(events.count("cmd_consultar_placa") == 2 * len(rounds) and events.count("on_interceptor") == len(rounds), f"{fname}: eventos {events}")
        check(all(re.fullmatch(r"[A-Z]{3}[0-9][A-Z0-9][0-9]{2}", p) for p in plates) and len(plates) == 2 * len(rounds), f"{fname}: plates")
        check(all(re.fullmatch(r"\d{11}", c) for c in cpfs) and len(cpfs) == 2 * len(rounds), f"{fname}: CPFs")
        check(sum(1 for e in es if "/TSPD/" in e["request"]["url"]) >= 9 * len(rounds), f"{fname}: protection noise")
        check(sum(1 for e in es if e["request"]["url"].endswith(("jquery-ui.min.js", "CIS_V1_SYNTH.js"))) == 2 * len(rounds), f"{fname}: static files")
        ren = [groups(urllib.parse.parse_qs(e["request"]["postData"]["text"])["XML"][0])[1].get("v_renavam") for e in posts]
        check([r for r in ren if r] == ["12"] * len(rounds), f"{fname}: v_renavam out of format (1 per round)")
    # real SESSIONID composition: 9-char literal (easynat-app) + "_" + 12 digits with no source; processId = 32-char literal
    for fname in ("real-shape-1round.har", "real-shape-2rounds.har"):
        es = json.loads((HERE / fname).read_text())["log"]["entries"]
        head = pidlit = None
        resp_blob = "\n".join(e["response"]["content"]["text"] for e in es)
        for e in es:
            if "easynat-app" in e["request"]["url"]:
                t = e["response"]["content"]["text"]
                head = re.search(r'm_currentSessionId = "([^"]*)"', t).group(1)
                pidlit = re.search(r'm_currentProcessId = "([^"]*)"', t).group(1)
                check(len(head) == 9 and len(pidlit) == 32, f"{fname}: literais 9/32 chars")
            elif e["request"]["method"] == "POST":
                f = urllib.parse.parse_qs(e["request"]["postData"]["text"], keep_blank_values=True)
                h, sep, tail = f["SESSIONID"][0].partition("_")
                check((h, sep) == (head, "_") and re.fullmatch(r"\d{12}", tail), f"{fname}: SESSIONID = literal(9) + '_' + 12 digits")
                check(tail not in resp_blob and not any(tail in json.dumps(x["request"]) and x["request"]["method"] == "GET" for x in es), f"{fname}: SESSIONID suffix must have no observed source")
                check(groups(f["XML"][0])[0][1] == pidlit, f"{fname}: XML processId = m_currentProcessId literal")
    comp = json.loads((HERE / "real-shape-composite.har").read_text())["log"]["entries"]
    check(len(comp) == 4 and "ALPHA0001" in comp[0]["response"]["content"]["text"] and "987654321012" in comp[1]["response"]["content"]["text"], "composite: producers")
    check("ALPHA0001_987654321012" in comp[2]["request"]["postData"]["text"] and "ALPHA0001_555555555555" in comp[3]["request"]["postData"]["text"]
          and "555555555555" not in comp[0]["response"]["content"]["text"] + comp[1]["response"]["content"]["text"], "composite: full/partial coverage")
    # manifest: IDs point to what they say
    har_a = json.loads((HERE / "real-shape-1round.har").read_text())["log"]["entries"]
    ids = man["rounds"]["a1"]["ids"]
    num = lambda i: int(i.split("-")[1]) - 1
    check(har_a[num(ids["easynat"])]["request"]["url"].endswith("easynat-app?op=S37"), "manifest: easynat")
    check(har_a[num(ids["static_jquery"])]["request"]["url"].endswith("jquery-ui.min.js"), "manifest: jquery")
    check(all("/TSPD/" in har_a[num(i)]["request"]["url"] for i in man["rounds"]["a1"]["tspd"]), "manifest: tspd")
    xml = urllib.parse.parse_qs(har_a[num(ids["consultar1"])]["request"]["postData"]["text"])["XML"][0]
    check("cmd_consultar_placa" in xml and man["values"]["a1"]["plates"][0] in xml, "manifest: consultar1")
    # only easynat-app contains SESSIONID/processId (checked on the real HARs)
    for fname in ("real-shape-1round.har", "real-shape-2rounds.har"):
        for e in json.loads((HERE / fname).read_text())["log"]["entries"]:
            body = e["response"]["content"]["text"]
            is_entry = "easynat-app" in e["request"]["url"]
            has = "m_currentSessionId" in body
            check(has == is_entry, f"{fname}: m_currentSessionId only in easynat-app ({e['request']['url'].split('/')[-1]})")
            if not is_entry and e["request"]["method"] == "GET":
                sids = [r["sid"] for r in []]
            hdr = " ".join(h["value"] for h in e["request"]["headers"]) + e["request"]["url"]
            check(not re.search(r"CSAN000\d\d_", hdr), f"{fname}: SESSIONID does not circulate in URL/headers")
    # only easynat-app contains m_currentSessionId (checked on the real HARs); SESSIONID does not circulate in URL/headers
    for fname in ("real-shape-1round.har", "real-shape-2rounds.har"):
        for e in json.loads((HERE / fname).read_text())["log"]["entries"]:
            is_entry = "easynat-app" in e["request"]["url"]
            check(("m_currentSessionId" in e["response"]["content"]["text"]) == is_entry, f"{fname}: m_currentSessionId only in easynat-app")
            hdr = " ".join(h["value"] for h in e["request"]["headers"]) + e["request"]["url"]
            check(not re.search(r"CSAN000\d\d_", hdr), f"{fname}: SESSIONID does not circulate in URL/headers")
    blob = "\\n".join((HERE / n).read_text() for n in ("real-shape-1round.har", "real-shape-2rounds.har", "manifest.json", "build_real_shape.py"))
    for bad in ("082b79", "CASA", "NUPP", "sem_captcha", "Downloads/", "APM_DO_NOT_TOUCH", "wsdetran.pb.gov.br.har"):
        check(bad not in blob, f"forbidden marker: {bad}")
    check(set(re.findall(r"TST0T\d\d", blob)) >= set(p for v in man["values"].values() for p in v["plates"]), "synthetic plates")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print(f"OK: real-shape 1round + 2rounds: {total_posts} Connector POSTs in HTML (~10 KB, XML/ERRORMESSAGE/STAMP controls, entities), "
          f"{total_get} GETs without postData, HAR without cookies, chained STAMP/delta, synthetic plates/CPF in the XML; no real values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
