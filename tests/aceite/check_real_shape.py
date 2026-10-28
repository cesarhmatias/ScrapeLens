#!/usr/bin/env python3
"""Rodada 6 (docs/10-fidelidade-caso-real.md, Aceite 1–4): fixtures com a FORMA REAL do DETRAN.

Importa fixtures/detran-pb-real-shape (HAR do DevTools sem cookies; Connector em HTML com
<textarea name=XML>/<input name=STAMP>) com `--label synthetic-fixture` e confere o manifest:
  1. origens (STAMP same-field forte, delta value-match no XML da textarea anterior, SESSIONID possível),
     cadeia (steps com os POSTs do Connector, pages, protection; scripts estáticos nunca são passo);
  2. sanitize (placas/CPF/SESSIONID somem em todos os arquivos; aviso para valor fora de formato);
  3. compare A(1 rodada) × B(2 rodadas): rodada sem par e poucas ambiguidades;
  4. HAR sem cookies → aviso har.cookies_absent (sessão, origens e cadeia);
  + GET sem postData = empty/"não aplicável" (L7).
Falha até o Core entregar L1–L8; as expectativas não são afrouxadas.

  python3 tests/aceite/check_real_shape.py [--core BIN]
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
    check(sorted(s["session"].get("labels", [])) == sorted(expect["label_set"]), f"{name}: rótulos {s['session'].get('labels')}")
    codes = [w.get("code") for w in s.get("warnings", [])]
    check(expect["warning_code"] in codes, f"{name}: aviso {expect['warning_code']} ausente (avisos: {codes})")
    gets = [r for r in s["requests"] if r["method"] == "GET"]
    bad = [r["id"] for r in gets
           if r["attempts"][0]["requestBody"].get("state") != "empty"
           or expect["get_request_body"]["reason_contains"] not in (r["attempts"][0]["requestBody"].get("note") or r["attempts"][0]["requestBody"].get("reason") or "")]
    check(not bad, f"{name}: GET sem postData deve ser empty/'não aplicável' (L7): {len(bad)} de {len(gets)} fora")


def check_origins_chain(core, session, label, e, cookies_warning):
    o = run_json(core, "origins", session, e["target"])
    c = run_json(core, "chain", session, e["target"])
    if o is None or c is None:
        return
    og = e["origins"]
    st = vals(o, scope="body", field="STAMP", parent=None)
    check(len(st) == 1, f"{label} STAMP: campo ausente")
    if st:
        v = st[0]
        ev = [x for x in v["evidences"] if x["role"] == "produced"]
        check(v["status"] == "origin" and v["label"] == og["STAMP"]["label"] and produced(v) == [og["STAMP"]["producer"]]
              and ev and ev[0]["kind"] == "same-field" and ev[0]["strength"] == "strong",
              f"{label} STAMP: esperado {og['STAMP']['label']} same-field strong de {og['STAMP']['producer']}; obtido {v['status']} {v['label']} {[(x['kind'], x['strength'], x['producerRequestId']) for x in v['evidences']]}")
    dl = vals(o, scope="body", field="XML", parent="XML", contains=og["delta"]["value_prefix"])
    check(len(dl) == 1, f"{label} delta: trecho do XML com {og['delta']['value_prefix']}… ausente")
    if dl:
        v = dl[0]
        check(v["status"] in ("origin", "ambiguous") and produced(v)[:1] == [og["delta"]["producer"]] and any(x["kind"] == "value-match" for x in v["evidences"]),
              f"{label} delta: esperado value-match de {og['delta']['producer']}; obtido {v['status']} {[(x['kind'], x['producerRequestId']) for x in v['evidences']]}")
    sid = vals(o, scope="body", field="SESSIONID", parent=None)
    sx = og["SESSIONID"]
    check(len(sid) == 1 and sid[0]["status"] in sx["status"] and sid[0]["label"].startswith(sx["label"]) and not sid[0]["evidences"],
          f"{label} SESSIONID (9 chars do easynat-app + '_' + 12 dígitos sem fonte): cobertura parcial => {sx['label']}; obtido {[(v['status'], v['label'][:50], produced(v)) for v in sid]}")
    pl = vals(o, scope="body", field="XML", parent="XML", contains=og["v_placa"]["plate"])
    check(all(v["status"] == "none" for v in pl), f"{label} placa: sem origem esperado, obtido {[v['status'] for v in pl]}")
    ch = e["chain"]
    steps = [s["requestId"] for s in c["steps"]]
    pages = [s["requestId"] for s in c.get("pages", [])]
    prot = [s["requestId"] for s in c["protection"]]
    check("pages" in c, f"{label} chain: grupo `pages` ausente")
    check(set(ch["steps_include"]) <= set(steps), f"{label} chain: passos faltando {sorted(set(ch['steps_include']) - set(steps))}")
    check(set(ch["pages_include"]) <= set(pages), f"{label} chain: páginas faltando {sorted(set(ch['pages_include']) - set(pages))}")
    check(set(ch["protection_include"]) <= set(prot), f"{label} chain: proteção faltando {sorted(set(ch['protection_include']) - set(prot))}")
    check(not set(ch["never_steps"]) & set(steps), f"{label} chain: não pode ser passo {sorted(set(ch['never_steps']) & set(steps))}")
    check(not set(ch["never_steps"][:2]) & set(pages), f"{label} chain: scripts estáticos não são páginas")
    check(not set(prot) & set(steps), f"{label} chain: proteção dentro de steps")
    check(steps == sorted(steps), f"{label} chain: passos fora da ordem do fluxo")
    if cookies_warning:
        for name, doc in (("origins", o), ("chain", c)):
            check(any("cookie" in w.lower() for w in doc["warnings"]), f"{label} {name}: deve repetir o aviso de cookies ausentes (har.cookies_absent)")


def forms(v):
    return {v, urllib.parse.quote(v, safe=""), html.escape(v, quote=True)}


def check_sanitize(core, session, label, values, expect, tmp):
    out = Path(tmp) / f"{label}-san"
    p = subprocess.run([core, "sanitize", session, out], capture_output=True, text=True)
    if p.returncode != 0:
        FAILS.append(f"{label} sanitize falhou: {p.stderr[:200]}"); return
    report = json.loads(p.stdout)
    texts = []
    for f in glob.glob(str(out) + "/**/*", recursive=True):
        if os.path.isfile(f):
            texts.append(open(f, encoding="utf8", errors="replace").read())
    blob = "\\n".join(texts)
    leaked = [kind for kind, vs in values.items() for v in vs for form in forms(v) if form in blob]
    check(not leaked, f"{label} sanitize: valores fictícios ainda presentes ({sorted(set(leaked))})")
    warns = json.dumps(report.get("warnings", [])) + json.dumps(json.loads((out / "session.json").read_text()).get("warnings", []))
    check(expect["warning_code"] in warns, f"{label} sanitize: aviso {expect['warning_code']} ausente")


def check_composite(core, e):
    """Regra do valor composto (campo nomeado < 40 B): cobertura total por >= 2 produtores => composite; parcial => none."""
    sess = import_har(core, e["har"], Path(tempfile.mkdtemp(prefix="sl-composite-")) / "s")
    for key in ("full_cover", "partial_cover"):
        c = e[key]
        o = run_json(core, "origins", sess, c["request"])
        if o is None:
            continue
        found = [v for v in o["values"] if v["scope"] == "body" and v["field"] == c["field"]]
        check(len(found) == 1, f"composto {key}: campo {c['field']} ausente")
        if not found:
            continue
        v = found[0]
        if key == "full_cover":
            ids = set(__import__("re").findall(r"har-\d{4}", json.dumps([v] + [x for x in o["values"] if x.get("parent") == c["field"]])))
            check(v["status"] == "composite" and set(c["producers"]) <= ids and "possible" in json.dumps(v).lower() + v["label"].lower().replace("possível", "possible"),
                  f"composto full_cover: esperado composite (possible) com produtores {c['producers']}; obtido {v['status']} {v['label'][:60]} {sorted(ids)}")
        else:
            check(v["status"] in c["status"] and v["label"].startswith(c["label"]) and not v["evidences"],
                  f"composto partial_cover: esperado {c['label']} (prefixo parcial não vale); obtido {v['status']} {v['label'][:60]} {[(e['kind'], e['producerRequestId']) for e in v['evidences']]}")


def check_compare(core, a, b, e):
    m = run_json(core, "compare", a, b)
    if m is None:
        return
    check(len(m["pairs"]) > 0, "compare: sem pares")
    unp = m.get("unpairedRounds")
    check(isinstance(unp, list) and len(unp) == e["unpaired_b_rounds"], f"compare: esperado {e['unpaired_b_rounds']} rodada sem par em `unpairedRounds`, obtido {unp!r}")
    check(len(m["ambiguities"]) <= e["max_ambiguities"], f"compare: {len(m['ambiguities'])} ambiguidades (máx. {e['max_ambiguities']})")
    check(not m["onlyInA"], f"compare: nada deve sobrar só em A ({len(m['onlyInA'])})")
    cons = [p for p in m["pairs"] if p["a"]["method"] == "POST"]
    for want, klass in (("SESSIONID", "dinâmico"), ("STAMP", "dinâmico"), ("PAGEINITPARAM", "estático")):
        got = {f["label"] for p in cons for f in p["fields"] if f["scope"] == "body" and f["field"] == want}
        check(klass in got, f"compare {want}: esperado {klass} em algum POST pareado, obtido {got}")


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
    print("OK: forma real — origens/cadeia, sanitize, compare por rodadas, cookies ausentes, GET sem corpo"); return 0


if __name__ == "__main__":
    sys.exit(main())
