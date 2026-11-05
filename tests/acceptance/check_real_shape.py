#!/usr/bin/env python3
"""Round 6 (docs/10-fidelity-case-real.md, Acceptance 1–4): fixtures with the REAL DETRAN SHAPE.

Imports fixtures/detran-pb-real-shape (DevTools HAR without cookies; Connector in HTML with
<textarea name=XML>/<input name=STAMP>) with `--label synthetic-fixture` and checks the manifest:
  1. origins (STAMP same-field strong, delta value-match in the previous textarea XML, SESSIONID possible),
     chain (steps with the Connector POSTs, pages, protection; static scripts are never steps);
  2. sanitize (plates/CPF/SESSIONID disappear from all files; warning for out-of-format values);
  3. compare A(1 round) × B(2 rounds): round without a pair and few ambiguities;
  4. HAR without cookies → warning har.cookies_absent (session, origins and chain);
  + GET without postData = empty/"not applicable" (L7).
Fails until the Core delivers L1–L8; the expectations are not relaxed.

  python3 tests/acceptance/check_real_shape.py [--core BIN]
"""
from __future__ import annotations

import argparse
import glob
import html
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402

ROOT = cb.ROOT
FIX = ROOT / "fixtures" / "detran-pb-real-shape"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run_json(core, *args):
    p = subprocess.run([core, *map(str, args)], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"`{args[0]}` falhou ({p.returncode}): {(p.stderr.strip().splitlines() or [''])[0]}")
        return None
    return json.loads(p.stdout)


def import_har(core, name, out):
    p = subprocess.run([core, "import-har", FIX / name, "--out", out, "--label", "synthetic-fixture"], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"FAIL import {name}: {p.stderr.strip()[:200]}")
    return out


def vals(doc, scope=None, field=None, parent=None, contains=None):
    return [v for v in doc["values"]
            if (scope is None or v["scope"] == scope) and (field is None or v["field"] == field)
            and (parent is None or v.get("parent") == parent) and (contains is None or contains in v["value"])]


def produced(v):
    return [e["producerRequestId"] for e in v["evidences"] if e["role"] == "produced"]


def check_import(session_dir, name, expect):
    s = json.loads((Path(session_dir) / "session.json").read_text())
    check(sorted(s["session"].get("labels", [])) == sorted(expect["label_set"]), f"{name}: labels {s['session'].get('labels')}")
    codes = [w.get("code") for w in s.get("warnings", [])]
    check(expect["warning_code"] in codes, f"{name}: warning {expect['warning_code']} missing (warnings: {codes})")
    gets = [r for r in s["requests"] if r["method"] == "GET"]
    bad = [r["id"] for r in gets
           if r["attempts"][0]["requestBody"].get("state") != "empty"
           or expect["get_request_body"]["reason_contains"] not in (r["attempts"][0]["requestBody"].get("note") or r["attempts"][0]["requestBody"].get("reason") or "")]
    check(not bad, f"{name}: GET without postData must be empty/'not applicable' (L7): {len(bad)} of {len(gets)} outside")


def check_origins_chain(core, session, label, e, cookies_warning):
    o = run_json(core, "origins", session, e["target"])
    c = run_json(core, "chain", session, e["target"])
    if o is None or c is None:
        return
    og = e["origins"]
    st = vals(o, scope="body", field="STAMP", parent=None)
    check(len(st) == 1, f"{label} STAMP: field missing")
    if st:
        v = st[0]
        ev = [x for x in v["evidences"] if x["role"] == "produced"]
        check(v["status"] == "origin" and v["label"] == og["STAMP"]["label"] and produced(v) == [og["STAMP"]["producer"]]
              and ev and ev[0]["kind"] == "same-field" and ev[0]["strength"] == "strong",
              f"{label} STAMP: expected {og['STAMP']['label']} same-field strong from {og['STAMP']['producer']}; got {v['status']} {v['label']} {[(x['kind'], x['strength'], x['producerRequestId']) for x in v['evidences']]}")
    dl = vals(o, scope="body", field="XML", parent="XML", contains=og["delta"]["value_prefix"])
    check(len(dl) == 1, f"{label} delta: XML snippet with {og['delta']['value_prefix']}… missing")
    if dl:
        v = dl[0]
        check(v["status"] in ("origin", "ambiguous") and produced(v)[:1] == [og["delta"]["producer"]] and any(x["kind"] == "value-match" for x in v["evidences"]),
              f"{label} delta: expected value-match from {og['delta']['producer']}; got {v['status']} {[(x['kind'], x['producerRequestId']) for x in v['evidences']]}")
    sid = vals(o, scope="body", field="SESSIONID", parent=None)
    sx = og["SESSIONID"]
    check(len(sid) == 1 and sid[0]["status"] in sx["status"] and sid[0]["label"].startswith(sx["label"]) and not sid[0]["evidences"],
          f"{label} SESSIONID (9 chars of easynat-app + '_' + 12 digits with no source): partial coverage => {sx['label']}; got {[(v['status'], v['label'][:50], produced(v)) for v in sid]}")
    # partial composition hint (core 127c405): points at the m_currentSessionId literal of easynat-app at the start of the value
    pc = sid[0].get("partialComposition") if sid else None
    want = sx["composition"]
    check(bool(pc) and any(h["producerRequestId"] == e["chain"]["steps_include"][0] and h["field"] == "m_currentSessionId"
                           and h["start"] == 0 and h["length"] == want["head_len"] for h in pc),
          f"{label} SESSIONID: partialComposition should point at {e['chain']['steps_include'][0]}/m_currentSessionId start 0 length {want['head_len']}; got {pc!r}")
    pl = vals(o, scope="body", field="XML", parent="XML", contains=og["v_placa"]["plate"])
    check(all(v["status"] == "none" for v in pl), f"{label} plate: no origin expected, got {[v['status'] for v in pl]}")
    ch = e["chain"]
    steps = [s["requestId"] for s in c["steps"]]
    pages = [s["requestId"] for s in c.get("pages", [])]
    prot = [s["requestId"] for s in c["protection"]]
    check("pages" in c, f"{label} chain: group `pages` missing")
    check(set(ch["steps_include"]) <= set(steps), f"{label} chain: steps missing {sorted(set(ch['steps_include']) - set(steps))}")
    check(set(ch["pages_include"]) <= set(pages), f"{label} chain: pages missing {sorted(set(ch['pages_include']) - set(pages))}")
    check(set(ch["protection_include"]) <= set(prot), f"{label} chain: protection missing {sorted(set(ch['protection_include']) - set(prot))}")
    check(not set(ch["never_steps"]) & set(steps), f"{label} chain: cannot be a step {sorted(set(ch['never_steps']) & set(steps))}")
    check(not set(ch["never_steps"][:2]) & set(pages), f"{label} chain: static scripts are not pages")
    check(not set(prot) & set(steps), f"{label} chain: protection inside steps")
    # initiator (core 1869721): pages = exactly the 4; auxiliary frames outside pages and (JLIBS/aboutBlank) outside steps
    aux = [s["requestId"] for s in c.get("auxiliaryPages", [])]
    check("auxiliaryPages" in c, f"{label} chain: group `auxiliaryPages` missing")
    check(sorted(pages) == sorted(ch["pages_exact"]), f"{label} chain: pages should be exactly {ch['pages_exact']}; got {pages}")
    check(set(ch["auxiliary_include"]) <= set(aux), f"{label} chain: auxiliaryPages missing {sorted(set(ch['auxiliary_include']) - set(aux))}")
    check(not set(aux) & set(pages), f"{label} chain: auxiliary frame also in pages {sorted(set(aux) & set(pages))}")
    check(not set(ch["frames_never_steps"]) & set(steps), f"{label} chain: JLIBS/aboutBlank frame in steps {sorted(set(ch['frames_never_steps']) & set(steps))}")
    check(not set(ch["auxiliary_not_on_path"]) & set(aux), f"{label} chain: frame off the Referer path in auxiliaryPages")
    for rid, prods in e["init_stamp"].items():
        io = run_json(core, "origins", session, rid)
        st = vals(io, scope="body", field="STAMP", parent=None) if io else []
        sj = json.loads((Path(session) / "session.json").read_text())
        url_of = {r["id"]: r["attempts"][0]["url"] for r in sj["requests"]}
        # INIT is identical in all rounds: the producer may be the cscform of an earlier round (older); being a cscform is enough
        ok = bool(st) and st[0]["status"] == "origin" and produced(st[0]) and all("cscform.html" in url_of.get(p, "") for p in produced(st[0])) \
            and all(x["kind"] == "same-field" for x in st[0]["evidences"] if x["role"] == "produced")
        check(ok, f"{label} STAMP INIT of {rid}: expected same-field from the cscform {prods}; got {[(v['status'], produced(v)) for v in st]}")
    check(not [r for st in c["steps"] for r in st.get("reasons", []) if r.get("field") == "SESSIONID"],
          f"{label} chain: no step may exist because of SESSIONID (partial coverage is not an origin)")
    check(steps == sorted(steps), f"{label} chain: steps out of flow order")
    if cookies_warning:
        for name, doc in (("origins", o), ("chain", c)):
            check(any("cookie" in w.lower() for w in doc["warnings"]), f"{label} {name}: must repeat the missing-cookies warning (har.cookies_absent)")


def forms(v):
    return {v, urllib.parse.quote(v, safe=""), html.escape(v, quote=True)}


def check_sanitize(core, session, label, values, expect, tmp):
    out = Path(tmp) / f"{label}-san"
    p = subprocess.run([core, "sanitize", session, out], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"{label} sanitize failed: {p.stderr[:200]}"); return
    report = json.loads(p.stdout)
    texts = []
    for f in glob.glob(str(out) + "/**/*", recursive=True):
        if os.path.isfile(f):
            texts.append(open(f, encoding="utf8", errors="replace").read())
    blob = "\\n".join(texts)
    leaked = [kind for kind, vs in values.items() for v in vs for form in forms(v) if form in blob]
    check(not leaked, f"{label} sanitize: fictitious values still present ({sorted(set(leaked))})")
    warns = json.dumps(report.get("warnings", [])) + json.dumps(json.loads((out / "session.json").read_text()).get("warnings", []))
    check(expect["warning_code"] in warns, f"{label} sanitize: warning {expect['warning_code']} missing")


def check_composite(core, e):
    """Composite-value rule (named field < 40 B): full coverage by >= 2 producers => composite; partial => none."""
    sess = import_har(core, e["har"], Path(tempfile.mkdtemp(prefix="sl-composite-")) / "s")
    for key in ("full_cover", "partial_cover"):
        c = e[key]
        o = run_json(core, "origins", sess, c["request"])
        if o is None:
            continue
        found = [v for v in o["values"] if v["scope"] == "body" and v["field"] == c["field"]]
        check(len(found) == 1, f"composite {key}: field {c['field']} missing")
        if not found:
            continue
        v = found[0]
        if key == "full_cover":
            ids = set(__import__("re").findall(r"har-\d{4}", json.dumps([v] + [x for x in o["values"] if x.get("parent") == c["field"]])))
            check(v["status"] == "composite" and set(c["producers"]) <= ids and "possible" in json.dumps(v).lower() + v["label"].lower(),
                  f"composite full_cover: expected composite (possible) with producers {c['producers']}; got {v['status']} {v['label'][:60]} {sorted(ids)}")
        else:
            check(v["status"] in c["status"] and v["label"].startswith(c["label"]) and not v["evidences"],
                  f"composite partial_cover: expected {c['label']} (partial prefix does not count); got {v['status']} {v['label'][:60]} {[(e['kind'], e['producerRequestId']) for e in v['evidences']]}")


def check_compare(core, a, b, e):
    m = run_json(core, "compare", a, b)
    if m is None:
        return
    check(len(m["pairs"]) > 0, "compare: no pairs")
    unp = m.get("unpairedRounds")
    check(isinstance(unp, list) and len(unp) == e["unpaired_b_rounds"], f"compare: expected {e['unpaired_b_rounds']} round without a pair in `unpairedRounds`, got {unp!r}")
    check(len(m["ambiguities"]) <= e["max_ambiguities"], f"compare: {len(m['ambiguities'])} ambiguities (max. {e['max_ambiguities']})")
    check(not m["onlyInA"], f"compare: nothing may remain only in A ({len(m['onlyInA'])})")
    cons = [p for p in m["pairs"] if p["a"]["method"] == "POST"]
    for want, klass in (("SESSIONID", "dynamic"), ("STAMP", "dynamic"), ("PAGEINITPARAM", "static")):
        got = {f["label"] for p in cons for f in p["fields"] if f["scope"] == "body" and f["field"] == want}
        check(klass in got, f"compare {want}: expected {klass} in some paired POST, got {got}")
    stamp_init = {f["label"] for p in cons for f in p["fields"] if f["scope"] == "body" and f["field"] == "STAMP"
                  and f.get("a") == "INIT"}
    check(not stamp_init or stamp_init == {"static"}, f"compare: STAMP=INIT must be static; got {stamp_init}")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--core"); a = ap.parse_args()
    core = cb.core_bin(a.core)
    man = json.loads((FIX / "manifest.json").read_text())
    ex = man["expectations"]
    tmp = tempfile.mkdtemp(prefix="sl-real-shape-")
    sa = import_har(core, man["files"]["har_1round"], Path(tmp) / "a")
    sb = import_har(core, man["files"]["har_2rounds"], Path(tmp) / "b")
    check_import(sa, "A", ex["import"]); check_import(sb, "B", ex["import"])
    check_origins_chain(core, sa, "A", ex["aceite_1_origins_chain"]["A"], True)
    check_origins_chain(core, sb, "B/rodada2", ex["aceite_1_origins_chain"]["B_round2"], True)
    vals_a = {"placa": [p for r in ("a1",) for p in man["values"][r]["plates"]], "cpf": man["values"]["a1"]["cpfs"], "sessionid": [man["values"]["a1"]["sessionid"]]}
    vals_b = {k: [x for r in ("b1", "b2") for x in (man["values"][r][{"placa": "plates", "cpf": "cpfs", "sessionid": "sessionid"}[k]] if k != "sessionid" else [man["values"][r]["sessionid"]])] for k in ("placa", "cpf", "sessionid")}
    check_sanitize(core, sa, "A", vals_a, ex["aceite_2_sanitize"], tmp)
    check_sanitize(core, sb, "B", vals_b, ex["aceite_2_sanitize"], tmp)
    check_compare(core, sa, sb, ex["aceite_3_compare"])
    check_composite(core, ex["composite_rule"])
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: real shape — origins/chain, sanitize, compare by rounds, missing cookies, GET without body"); return 0


if __name__ == "__main__":
    sys.exit(main())
