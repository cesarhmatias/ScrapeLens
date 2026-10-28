#!/usr/bin/env python3
"""Rodada 5 (docs/09-cadeia-comparacao.md §4): origem dos valores, cadeia e comparação.

Importa as fixtures sintéticas A (fixtures/detran-pb) e B (fixtures/detran-pb-b) com
`--label synthetic-fixture`, roda `scrapelens-core origins|chain|compare` e confere
`manifest.json` → `chain_compare` (§4.1, §4.2, §4.3) e a A sanitizada (§4.4).

O formato JSON é o real do core (docs/09 e2c4da0+): origins.values[] com status/label/
evidences[]; chain.steps/protection/unresolved; compare.pairs[].fields[] com label/originLabel/parts.
Expectativas não são afrouxadas: qualquer desvio falha (exit 1).

  python3 tests/aceite/check_chain_compare.py [--core BIN]
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
        FAILS.append(f"`{args[0]}` falhou ({p.returncode}): {p.stderr.strip().splitlines()[0] if p.stderr.strip() else ''}")
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
    check(labels == ["capture-import", "synthetic-fixture"], f"{name}: rótulos {labels}")
    return out


# ---- verificações (esquema real do core: docs/09, origins/chain/compare) --------------
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
        check(len(found) >= 1, f"origins {name}: campo ausente na saída")
        if not found:
            continue
        v = found[0]
        if f["evidence"] == "sem origem observada":
            check(v["status"] == "none" and not v["evidences"] and v["label"].startswith("sem origem observada"),
                  f"origins {name}: esperado sem origem observada, obtido {v['status']} {v['label'][:60]}")
            continue
        kinds = {e["kind"] for e in v["evidences"]}
        check(v["status"] in ("origin", "ambiguous") and f["evidence"] in kinds, f"origins {name}: esperado {f['evidence']}, obtido status={v['status']} kinds={kinds}")
        want = ids[f["producer"]]
        check(produced_by(v) == [want], f"origins {name}: produtor esperado {want} ({f['producer']}), obtido {produced_by(v)}")
        if f.get("reissued_by"):
            check(reissued_by(v) == sorted(ids[x] for x in f["reissued_by"]), f"origins {name}: reemitido por {reissued_by(v)}")
        if f.get("literal"):
            check(any(e["field"] == f["literal"] for e in v["evidences"]), f"origins {name}: literal {f['literal']} ausente")
    neg = ex["origins_4_1"]["negative_4_3"]
    es = vals(doc, scope="header", field="x-page-seq")
    check(len(es) == 1, "4.3: x-page-seq ausente")
    for e in es:
        check(e["status"] in neg["status"] and not e["evidences"] and e["label"].startswith("sem origem observada"),
              f"4.3: x-page-seq virou origem: {e['status']} {e['label'][:80]} {e['evidences']}")


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
    check([x for x in app if x not in allowed] == want_app, f"chain: aplicação esperada {want_app}, obtida {app}")
    check(set(app) - set(want_app) <= allowed, f"chain: passos extras não permitidos {set(app) - set(want_app) - allowed}")
    check(app == sorted(app), f"chain: ordem do fluxo violada {app}")
    check(prot == [ids[x] for x in c["protection"]], f"chain: proteção esperada {[ids[x] for x in c['protection']]}, obtida {prot}")
    check(all(s.get("class") == "protection" for s in doc["protection"]) and all(s.get("class") == "application" for s in doc["steps"]),
          "chain: classes application/protection")
    for x in c["must_exclude"]:
        check(ids[x] not in app + prot, f"chain: {x} não deve constar")
    by = {s["requestId"]: s for s in doc["steps"] + doc["protection"]}
    for rid, why in c["reasons"].items():
        s = by.get(ids[rid])
        check(bool(s and s.get("reason") and s.get("reasons")), f"chain: {rid} sem motivo ({why})")
    check(not any(u.get("status") == "origin" for u in doc["unresolved"]), "chain: unresolved não pode conter origens resolvidas")


def part_with(parts, a_has=None, b_has=None):
    return [p for p in parts if (a_has is None or a_has in p["a"]) and (b_has is None or b_has in p["b"])]


def check_compare(core, a, b, ex, ida, idb):
    doc, _ = run(core, "compare", a, b)
    if doc is None:
        return
    c = ex["compare_4_2"]
    check(len(doc["pairs"]) == 13, f"compare: {len(doc['pairs'])} pares (esperado 13)")
    check(not doc["onlyInA"] and not doc["onlyInB"], f"compare: só em A/B inesperado {doc['onlyInA']} {doc['onlyInB']}")
    check(not doc["ambiguities"], f"compare: ambiguidades {doc['ambiguities']}")
    check(not any(p["outOfOrder"] for p in doc["pairs"]), "compare: par fora de ordem")
    for i, (ra, rb) in enumerate(c["consultas_pair_by_order"]):
        pr = [p for p in doc["pairs"] if p["a"]["requestId"] == ida[ra]]
        check(len(pr) == 1 and pr[0]["b"]["requestId"] == idb[rb], f"compare: consulta {ra} deve parear com {rb}, obtido {[p['b']['requestId'] for p in pr]}")
        if len(pr) != 1:
            continue
        p = pr[0]
        fields = {(f["scope"], f["field"]): f for f in p["fields"]}
        plate_a, plate_b = c["plates"]["A"][i], c["plates"]["B"][i]
        xml_parts = fields[("body", "XML")]["parts"]
        pp = part_with(xml_parts, plate_a, plate_b)
        check(len(pp) == 1 and pp[0]["label"] == "dinâmico" and pp[0]["originLabel"] == "dinâmico sem origem",
              f"compare par {i} XML:v_placa: esperado 'dinâmico sem origem', obtido {[(q['label'], q['originLabel']) for q in pp]}")
        if i == 0:
            check_compare_fields(c, fields, xml_parts, ida, idb)


def check_compare_fields(c, fields, xml_parts, ida, idb):
    for f in c["fields"]:
        base, _, token = f["field"].partition(":")
        if base == "XML":
            continue
        key = ("cookie", token) if base == "cookie" else ("header", token) if base == "header" else ("body", base)
        e = fields.get(key)
        check(e is not None, f"compare {f['field']}: ausente")
        if e is None:
            continue
        check(e["label"] == f["class"], f"compare {f['field']}: esperado {f['class']}, obtido {e['label']}")
        if f.get("runtime"):
            want = f"obter em runtime (origem: {idb[f['origin']]}"
            check((e["originLabel"] or "").startswith(want), f"compare {f['field']}: esperado '{want}…', obtido {e['originLabel']!r}")
        if f.get("value") is not None:
            check(e["a"] == f["value"] and e["b"] == f["value"], f"compare {f['field']}: valor estático {f['value']!r}, obtido {e['a']!r}/{e['b']!r}")
    for f in c["fields"]:
        if not f["field"].startswith("XML:"):
            continue
        token = f["field"].split(":", 1)[1]
        if token == "delta":
            pp = part_with(xml_parts, "DLTA0005", "DLTB0005")
            check(len(pp) == 1 and pp[0]["label"] == "dinâmico" and (pp[0]["originLabel"] or "").startswith(f"obter em runtime (origem: {idb[f['origin']]}"),
                  f"compare XML:delta: obtido {[(q['label'], q['originLabel']) for q in pp]}")
        elif token == "v_placa":
            continue  # verificado por par, acima
        else:
            pp = [q for q in xml_parts if token in q["a"] and token in q["b"]]
            check(bool(pp) and all(q["label"] == f["class"] for q in pp), f"compare XML:{token}: esperado {f['class']}, obtido {[(q['label']) for q in pp]}")


def check_sanitized(core, a, ex, ids, tmp):
    san = Path(tmp) / "san"
    p = subprocess.run([core, "sanitize", a, san], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"sanitize falhou: {p.stderr[:200]}"); return
    d = json.loads((san / "session.json").read_text())
    sid = {r["cdp"]["requestId"]: r["id"] for r in d["requests"] if r.get("cdp", {}).get("requestId")}
    s = ex["sanitized_4_4"]
    for cmd in ("origins", "chain"):
        doc, raw = run(core, cmd, san, sid[ex["target"]["requestId"]])
        if doc is None:
            continue
        for leak in s["must_not_leak"]:
            check(leak not in raw, f"4.4 {cmd}: vazou {leak}")
        check(doc["redactedValues"] > 0 and any("não podem ser rastreados" in w for w in doc["warnings"]),
              f"4.4 {cmd}: deve declarar que valores redigidos não são rastreáveis")
        if cmd == "origins":
            red = {(v["scope"], v["field"]) for v in doc["values"] if v["status"] == "redacted"}
            check({("body", "SESSIONID"), ("cookie", "JSESSIONID")} <= red, f"4.4 origins: SESSIONID/JSESSIONID devem estar 'redacted', obtido {red}")


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
    check_sanitized(core, sa, ex, ida, tmp)
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: origens §4.1, cadeia, comparação §4.2, negativo §4.3 e sanitizada §4.4"); return 0


if __name__ == "__main__":
    sys.exit(main())
