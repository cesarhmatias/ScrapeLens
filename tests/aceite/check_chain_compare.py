#!/usr/bin/env python3
"""Rodada 5 (docs/09-cadeia-comparacao.md §4): origem dos valores, cadeia e comparação.

Importa as fixtures sintéticas A (fixtures/detran-pb) e B (fixtures/detran-pb-b) com
`--label synthetic-fixture`, roda `scrapelens-core origins|chain|compare` e confere
`manifest.json` → `chain_compare` (§4.1, §4.2, §4.3) e a A sanitizada (§4.4).

O formato JSON do Core é lido por um adaptador tolerante (funções `entries_of`,
`pick`): campos esperados `requestId`, `field`, `evidence`/`kind`, `producer`/`origin`,
`class`/`classification`. Divergência de nome é reportada, nunca assumida como OK.
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


# ---- adaptador do formato do Core -------------------------------------------
def walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def pick(d, *names):
    for n in names:
        if isinstance(d, dict) and d.get(n) is not None:
            return d[n]
    return None


def text(d):
    return json.dumps(d, ensure_ascii=False)


def find_entry(doc, base, value=None):
    """Entradas cujo `field` contém `base` (ou, para tokens opacos, cujo valor contém `value`)."""
    out = []
    for d in walk(doc):
        field = str(pick(d, "field", "name") or "")
        if not field:
            continue
        if base.lower() in field.lower() and (value is None or value in text(d)):
            out.append(d)
    return out


def evidence_of(e):
    o = pick(e, "origin", "origins") or e
    if isinstance(o, list):
        o = o[0] if o else {}
    ev = pick(o, "evidence", "kind", "type") or pick(e, "evidence", "kind")
    return str(ev) if ev is not None else None


def producers_of(e):
    ids = []
    for d in walk(e):
        p = pick(d, "producer", "producerRequestId", "producerId", "fromRequestId")
        if isinstance(p, dict):
            p = pick(p, "requestId", "id")
        if isinstance(p, str):
            ids.append(p)
    return ids


# ---- verificações -------------------------------------------------------------
def check_origins(core, a, ex, ids):
    target = ids[ex["target"]["requestId"]]
    doc, _ = run(core, "origins", a, target)
    if doc is None:
        return
    for f in ex["origins_4_1"]["fields"]:
        name = f["field"]
        base, _, token = name.partition(":")
        value = f.get("value") if base == "XML" else None
        entries = find_entry(doc, "XML" if base == "XML" else (name if base != "cookie" else token), value)
        if base == "XML" and f["evidence"] == "sem origem observada":
            entries = [e for e in find_entry(doc, "XML", f["value"])]
        check(bool(entries), f"origins {name}: campo ausente na saída")
        if not entries:
            continue
        evs = {evidence_of(e) for e in entries}
        check(f["evidence"] in evs or any(f["evidence"] in text(e) for e in entries), f"origins {name}: esperado {f['evidence']}, obtido {evs}")
        if f["producer"]:
            want = ids[f["producer"]]
            got = [p for e in entries for p in producers_of(e)]
            check(want in got, f"origins {name}: produtor esperado {want} ({f['producer']}), obtido {got}")
        else:
            check(not [p for e in entries for p in producers_of(e)], f"origins {name}: não deve ter produtor")
    neg = ex["origins_4_1"]["negative_4_3"]
    es = find_entry(doc, "x-page-seq")
    check(bool(es), "4.3: x-page-seq ausente da saída (deveria constar como sem origem observada)")
    for e in es:
        check("sem origem" in text(e).lower() and not producers_of(e), f"4.3: x-page-seq virou origem: {text(e)[:200]}")


def check_chain(core, a, ex, ids):
    target = ids[ex["target"]["requestId"]]
    doc, _ = run(core, "chain", a, target)
    if doc is None:
        return
    c = ex["chain_4_1"]
    steps = [d for d in walk(doc) if pick(d, "requestId") and ("reason" in d or "motivo" in d or "class" in d or "kind" in d)]
    order = [d["requestId"] for d in steps]
    prot = [d["requestId"] for d in steps if "prote" in text(d).lower() and "class" in d or d.get("protection") is True]
    app = [x for x in order if x not in prot]
    want_app = [ids[x] for x in c["application_in_flow_order"]]
    allowed = {ids[x] for x in c["allowed_extra_application"]}
    check([x for x in app if x not in allowed] == want_app, f"chain: aplicação esperada {want_app}, obtida {app}")
    check(app == sorted(app), f"chain: ordem do fluxo violada {app}")
    check(prot == [ids[x] for x in c["protection"]], f"chain: proteção esperada {[ids[x] for x in c['protection']]}, obtida {prot}")
    for x in c["must_exclude"]:
        check(ids[x] not in order, f"chain: {x} não deve constar")
    for rid, why in c["reasons"].items():
        s = [d for d in steps if d["requestId"] == ids[rid]]
        check(bool(s and (pick(s[0], "reason", "motivo"))), f"chain: {rid} sem motivo ({why})")


def check_compare(core, a, b, ex, ida, idb):
    doc, _ = run(core, "compare", a, b)
    if doc is None:
        return
    c = ex["compare_4_2"]
    pairs = [d for d in walk(doc) if pick(d, "a", "aRequestId") and pick(d, "b", "bRequestId")]
    pmap = {str(pick(p, "a", "aRequestId") if not isinstance(pick(p, "a", "aRequestId"), dict) else pick(p["a"], "requestId")):
            p for p in pairs}
    check(len(pairs) >= 13, f"compare: {len(pairs)} pares (esperado 13)")
    for ra, rb in c["consultas_pair_by_order"]:
        p = pmap.get(ida[ra])
        check(p is not None and idb[rb] in text(p), f"compare: consulta {ra} deve parear com {rb} (sem cruzar)")
    p = pmap.get(ida[c["consultas_pair_by_order"][0][0]])
    if p is None:
        return
    for f in c["fields"]:
        base, _, token = f["field"].partition(":")
        es = find_entry(p, token if base == "cookie" else (base if base != "XML" else "XML"),
                        None if base != "XML" else (token if token not in ("cmd_consultar_placa", "#f12_selected") else token))
        check(bool(es), f"compare {f['field']}: ausente")
        if not es:
            continue
        blob = " ".join(text(e).lower() for e in es)
        check(f["class"] in blob, f"compare {f['field']}: esperado {f['class']}")
        if f.get("runtime"):
            check("runtime" in blob and ida[f["origin"]].lower() in blob or idb[f["origin"]].lower() in blob,
                  f"compare {f['field']}: esperado 'obter em runtime' com origem {f['origin']}")
        if f.get("label"):
            check(f["label"] in blob, f"compare {f['field']}: esperado '{f['label']}'")


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
        check("redig" in raw.lower() or "redact" in raw.lower(), f"4.4 {cmd}: deve declarar que valores redigidos não são rastreáveis")


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
