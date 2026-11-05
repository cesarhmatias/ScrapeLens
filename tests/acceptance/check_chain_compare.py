#!/usr/bin/env python3
"""Round 5 (docs/09-chain-comparison.md §4): value origins, chain and comparison.

Imports the synthetic fixtures A (fixtures/detran-pb) and B (fixtures/detran-pb-b) with
`--label synthetic-fixture`, runs `scrapelens-core origins|chain|compare` and checks
`manifest.json` → `chain_compare` (§4.1, §4.2, §4.3) and the sanitized A (§4.4).

The JSON format is the real one from the core (docs/09 e2c4da0+): origins.values[] with status/label/
evidences[]; chain.steps/protection/unresolved; compare.pairs[].fields[] with label/originLabel/parts.
Expectations are not relaxed: any deviation fails (exit 1).

  python3 tests/acceptance/check_chain_compare.py [--core BIN]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402  (core_bin, cdp_to_logical)

ROOT, FIX = cb.ROOT, cb.FIX
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run(core, *args):
    p = subprocess.run([core, *map(str, args)], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"`{args[0]}` failed ({p.returncode}): {p.stderr.strip().splitlines()[0] if p.stderr.strip() else ''}")
        return None, p.stdout
    return json.loads(p.stdout), p.stdout


def import_capture(core, folder, name, tmp, label="synthetic-fixture"):
    out = Path(tmp) / name
    p = subprocess.run([core, "import-capture", FIX.parent / folder / f"{name}.cdp.jsonl", FIX.parent / folder / f"{name}.netlog.json",
                        "--out", out, "--bodies", FIX.parent / folder / f"{name}.cdp-bodies.jsonl", "--label", label],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"FAIL import {name}: {p.stderr.strip()[:300]}")
    labels = sorted(json.loads((out / "session.json").read_text())["session"].get("labels", []))
    check(labels == ["capture-import", "synthetic-fixture"], f"{name}: labels {labels}")
    return out


# ---- checks (real core schema: docs/09, origins/chain/compare) --------------
def vals(doc, scope=None, field=None, parent=None, contains=None):
    out = []
    for v in doc["values"]:
        if scope and v["scope"] != scope:
            continue
        if field and v["field"] != field:
            continue
        if parent is not None and v.get("parent") != parent:
            continue
        if contains and contains not in v["value"]:
            continue
        out.append(v)
    return out


def produced_by(v):
    return [e["producerRequestId"] for e in v["evidences"] if e["role"] == "produced"]


def reissued_by(v):
    return sorted({e["producerRequestId"] for e in v["evidences"] if e["role"] == "reissued"})


def check_origins(core, a, ex, ids):
    target = ids[ex["target"]["requestId"]]
    doc, _ = run(core, "origins", a, target)
    if doc is None:
        return
    for f in ex["origins_4_1"]["fields"]:
        name = f["field"]
        base, _, token = name.partition(":")
        if base == "SESSIONID" or name == "STAMP":
            found = vals(doc, scope="body", field=name, parent=None)
        elif base == "cookie":
            found = vals(doc, scope="cookie", field=token)
        elif base == "XML":
            needle = f["value"]
            found = vals(doc, scope="body", field="XML", parent="XML", contains=needle)
        else:
            found = []
        check(len(found) >= 1, f"origins {name}: field missing from the output")
        if not found:
            continue
        v = found[0]
        if f["evidence"] == "no observed origin":
            check(v["status"] == "none" and not v["evidences"] and v["label"].startswith("no observed origin"),
                  f"origins {name}: expected no observed origin, got {v['status']} {v['label'][:60]}")
            continue
        kinds = {e["kind"] for e in v["evidences"]}
        check(v["status"] in ("origin", "ambiguous") and f["evidence"] in kinds, f"origins {name}: expected {f['evidence']}, got status={v['status']} kinds={kinds}")
        check(v["label"] == f["status_label"], f"origins {name}: label expected {f['status_label']!r}, got {v['label']!r}")
        strengths = {e["strength"] for e in v["evidences"] if e["role"] == "produced"}
        want_strength = "strong" if f["confidence"] == "strong" else "medium"
        check(strengths == {want_strength}, f"origins {name}: producer strength expected {want_strength}, got {strengths}")
        want = ids[f["producer"]]
        check(produced_by(v) == [want], f"origins {name}: producer expected {want} ({f['producer']}), got {produced_by(v)}")
        if f.get("reissued_by"):
            check(reissued_by(v) == sorted(ids[x] for x in f["reissued_by"]), f"origins {name}: reissued by {reissued_by(v)}")
        if f.get("literal"):
            check(any(e["field"] == f["literal"] for e in v["evidences"]), f"origins {name}: literal {f['literal']} missing")
    neg = ex["origins_4_1"]["negative_4_3"]
    es = vals(doc, scope="header", field="x-page-seq")
    check(len(es) == 1, "4.3: x-page-seq missing")
    for e in es:
        check(e["status"] in neg["status"] and not e["evidences"] and e["label"].startswith("no observed origin"),
              f"4.3: x-page-seq became an origin: {e['status']} {e['label'][:80]} {e['evidences']}")


def check_chain(core, a, ex, ids):
    target = ids[ex["target"]["requestId"]]
    doc, _ = run(core, "chain", a, target)
    if doc is None:
        return
    c = ex["chain_4_1"]
    app = [s["requestId"] for s in doc["steps"]]
    prot = [s["requestId"] for s in doc["protection"]]
    want_app = [ids[x] for x in c["application_in_flow_order"]]
    allowed = {ids[x] for x in c["allowed_extra_application"]}
    check([x for x in app if x not in allowed] == want_app, f"chain: application expected {want_app}, got {app}")
    check(set(app) - set(want_app) <= allowed, f"chain: extra steps not allowed {set(app) - set(want_app) - allowed}")
    check(app == sorted(app), f"chain: flow order violated {app}")
    check(prot == [ids[x] for x in c["protection"]], f"chain: protection expected {[ids[x] for x in c['protection']]}, got {prot}")
    got_conf = {s["requestId"]: s.get("confidence") for s in doc["steps"]}
    want_conf = {ids[k]: v for k, v in c["confidence"].items()}
    check({k: v for k, v in got_conf.items() if k in want_conf} == want_conf, f"chain: confidence expected {want_conf}, got {got_conf}")
    check(all(s.get("confidence") == "strong" for s in doc["protection"]), "chain: protection (cookie-jar) must be strong")
    check(all(s.get("class") == "protection" for s in doc["protection"]) and all(s.get("class") == "application" for s in doc["steps"]),
          "chain: classes application/protection")
    for x in c["must_exclude"]:
        check(ids[x] not in app + prot, f"chain: {x} must not appear")
    by = {s["requestId"]: s for s in doc["steps"] + doc["protection"]}
    for rid, why in c["reasons"].items():
        s = by.get(ids[rid])
        check(bool(s and s.get("reason") and s.get("reasons")), f"chain: {rid} has no reason ({why})")
    check(not any(u.get("status") == "origin" for u in doc["unresolved"]), "chain: unresolved must not contain resolved origins")


def part_with(parts, a_has=None, b_has=None):
    return [p for p in parts if (a_has is None or a_has in p["a"]) and (b_has is None or b_has in p["b"])]


def check_compare(core, a, b, ex, ida, idb):
    doc, _ = run(core, "compare", a, b)
    if doc is None:
        return
    c = ex["compare_4_2"]
    # L6 (docs/10): the default alignment only has application requests; /TSPD/ goes to groups[kind=protection]
    check(len(doc["pairs"]) == 12, f"compare: {len(doc['pairs'])} pairs (12 application expected)")
    prot = [g for g in doc.get("groups", []) if g.get("kind") == "protection"]
    check(len(prot) == 1 and len(prot[0]["a"]) == 1 and len(prot[0]["b"]) == 1 and "/TSPD/" in prot[0]["a"][0]["url"],
          f"compare: expected 1 protection group with 1 /TSPD/ on each side, got {prot}")
    allp = run(core, "compare", a, b, "--all")[0]
    check(allp is not None and len(allp["pairs"]) == 13, f"compare --all: expected 13 pairs, got {None if allp is None else len(allp['pairs'])}")
    check(not doc["onlyInA"] and not doc["onlyInB"], f"compare: unexpected only-in-A/B {doc['onlyInA']} {doc['onlyInB']}")
    check(not doc["ambiguities"], f"compare: ambiguities {doc['ambiguities']}")
    check(not any(p["outOfOrder"] for p in doc["pairs"]), "compare: pair out of order")
    for i, (ra, rb) in enumerate(c["consultas_pair_by_order"]):
        pr = [p for p in doc["pairs"] if p["a"]["requestId"] == ida[ra]]
        check(len(pr) == 1 and pr[0]["b"]["requestId"] == idb[rb], f"compare: query {ra} must pair with {rb}, got {[p['b']['requestId'] for p in pr]}")
        if len(pr) != 1:
            continue
        p = pr[0]
        fields = {(f["scope"], f["field"]): f for f in p["fields"]}
        plate_a, plate_b = c["plates"]["A"][i], c["plates"]["B"][i]
        xml_parts = fields[("body", "XML")]["parts"]
        pp = part_with(xml_parts, plate_a, plate_b)
        check(len(pp) == 1 and pp[0]["label"] == "dynamic" and pp[0]["originLabel"] == "dynamic without origin",
              f"compare pair {i} XML:v_placa: expected 'dynamic without origin', got {[(q['label'], q['originLabel']) for q in pp]}")
        if i == 0:
            check_compare_fields(c, fields, xml_parts, ida, idb)


def check_compare_fields(c, fields, xml_parts, ida, idb):
    for f in c["fields"]:
        base, _, token = f["field"].partition(":")
        if base == "XML":
            continue
        key = ("cookie", token) if base == "cookie" else ("header", token) if base == "header" else ("body", base)
        e = fields.get(key)
        check(e is not None, f"compare {f['field']}: missing")
        if e is None:
            continue
        check(e["label"] == f["class"], f"compare {f['field']}: expected {f['class']}, got {e['label']}")
        if f.get("runtime"):
            want = f"get at runtime ({'possible ' if f.get('possible') else ''}origin: {idb[f['origin']]}"
            check((e["originLabel"] or "").startswith(want), f"compare {f['field']}: expected '{want}…', got {e['originLabel']!r}")
        if f.get("value") is not None:
            check(e["a"] == f["value"] and e["b"] == f["value"], f"compare {f['field']}: static value {f['value']!r}, got {e['a']!r}/{e['b']!r}")
    for f in c["fields"]:
        if not f["field"].startswith("XML:"):
            continue
        token = f["field"].split(":", 1)[1]
        if token == "delta":
            pp = part_with(xml_parts, "DLTA0005", "DLTB0005")
            want = f"get at runtime ({'possible ' if f.get('possible') else ''}origin: {idb[f['origin']]}"
            check(len(pp) == 1 and pp[0]["label"] == "dynamic" and (pp[0]["originLabel"] or "").startswith(want),
                  f"compare XML:delta: got {[(q['label'], q['originLabel']) for q in pp]}")
        elif token == "v_placa":
            continue  # checked per pair, above
        else:
            pp = [q for q in xml_parts if token in q["a"] and token in q["b"]]
            check(bool(pp) and all(q["label"] == f["class"] for q in pp), f"compare XML:{token}: expected {f['class']}, got {[(q['label']) for q in pp]}")


def check_edge_regressions(core, ex, tmp):
    """Round 5 review: a slow overlapping producer is not an origin; a sequential control is."""
    e = ex["edge_regressions"]
    sess = cb.import_fixture(core, e["session"], tmp)
    ids = cb.cdp_to_logical(sess)
    for key, strong in (("slow_overlapping_producer", False), ("sequential_control", True)):
        c = e[key]
        doc, _ = run(core, "origins", sess, ids[c["consumer"]])
        if doc is None:
            continue
        found = vals(doc, scope="body", field=c["field"])
        check(len(found) == 1, f"edge {key}: field {c['field']} missing")
        if not found:
            continue
        v = found[0]
        if strong:
            check(v["status"] == "origin" and v["label"] == "observed origin" and produced_by(v) == [ids[c["producer"]]] and v["evidences"][0]["kind"] == "same-field",
                  f"edge {key}: expected strong origin of {c['producer']}, got {v['status']} {v['label']} {produced_by(v)}")
        else:
            check(v["status"] == "none" and not v["evidences"] and ids[c["producer"]] not in text_of(v),
                  f"edge {key}: slow producer cannot be an origin, got {v['status']} {v['label']} {v['evidences']}")


def text_of(v):
    return json.dumps(v["evidences"], ensure_ascii=False)


def check_sanitized(core, a, ex, ids, tmp):
    san = Path(tmp) / "san"
    p = subprocess.run([core, "sanitize", a, san], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"sanitize failed: {p.stderr[:200]}"); return
    d = json.loads((san / "session.json").read_text())
    sid = {r["cdp"]["requestId"]: r["id"] for r in d["requests"] if r.get("cdp", {}).get("requestId")}
    s = ex["sanitized_4_4"]
    for cmd in ("origins", "chain"):
        doc, raw = run(core, cmd, san, sid[ex["target"]["requestId"]])
        if doc is None:
            continue
        for leak in s["must_not_leak"]:
            check(leak not in raw, f"4.4 {cmd}: leaked {leak}")
        check(doc["redactedValues"] > 0 and any("cannot be traced" in w for w in doc["warnings"]),
              f"4.4 {cmd}: must state that redacted values cannot be traced")
        if cmd == "origins":
            red = {(v["scope"], v["field"]) for v in doc["values"] if v["status"] == "redacted"}
            check({("body", "SESSIONID"), ("cookie", "JSESSIONID")} <= red, f"4.4 origins: SESSIONID/JSESSIONID must be 'redacted', got {red}")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--core"); a = ap.parse_args()
    core = cb.core_bin(a.core)
    manifest = json.loads((FIX / "manifest.json").read_text())
    ex = manifest["chain_compare"]
    tmp = tempfile.mkdtemp(prefix="sl-chain-")
    sa = import_capture(core, "detran-pb", "detran-pb", tmp)
    sb = import_capture(core, "detran-pb-b", "detran-pb-b", tmp)
    ida, idb = cb.cdp_to_logical(sa), cb.cdp_to_logical(sb)
    check_origins(core, sa, ex, ida)
    check_chain(core, sa, ex, ida)
    check_compare(core, sa, sb, ex, ida, idb)
    check_edge_regressions(core, ex, tmp)
    check_sanitized(core, sa, ex, ida, tmp)
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: origins §4.1, chain, comparison §4.2, negative §4.3, edge regressions (causality) and sanitized §4.4"); return 0


if __name__ == "__main__":
    sys.exit(main())
