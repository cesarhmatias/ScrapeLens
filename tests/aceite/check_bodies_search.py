#!/usr/bin/env python3
"""Rodada 4 (docs/08-corpos-busca.md §3.1): confere a busca no payload.

Dada a pasta de uma sessão importada, roda `scrapelens-core search` para cada
caso de fixtures/detran-pb/manifest.json (`bodies_search_cases`, e `bodies.edge.search`
com --fixture edge) e compara requestId/field/decoded esperados. Não afrouxa
expectativas: qualquer divergência falha (exit 1).

  python3 tests/aceite/check_bodies_search.py <sessao>            # DETRAN-PB
  python3 tests/aceite/check_bodies_search.py <sessao> --fixture edge
  python3 tests/aceite/check_bodies_search.py --import-fixture    # importa e confere
  python3 tests/aceite/check_bodies_search.py <sessao-sanitizada> --sanitized MARCADOR...
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "fixtures" / "detran-pb"


def core_bin(arg):
    if arg:
        return arg
    # O binário mais recente por mtime; recusa se for mais antigo que o código-fonte.
    cands = [ROOT / "core" / "target" / p / "scrapelens-core" for p in ("release", "debug")]
    cands = [c for c in cands if c.exists()]
    if not cands:
        sys.exit("scrapelens-core não encontrado; rode `cargo build` em core/ ou use --core")
    best = max(cands, key=lambda c: c.stat().st_mtime)
    newest_src = max((f.stat().st_mtime for f in (ROOT / "core" / "src").rglob("*.rs")), default=0)
    if best.stat().st_mtime < newest_src:
        sys.exit(f"{best} é mais antigo que core/src; rode `cargo build` em core/ ou use --core")
    return str(best)


def cdp_to_logical(session):
    """requestId do CDP -> id lógico da sessão, pela proveniência em session.json."""
    d = json.loads((Path(session) / "session.json").read_text())
    return {r["cdp"]["requestId"]: r["id"] for r in d["requests"] if r.get("cdp", {}).get("requestId")}


def exact_slice_failures(session, matches, query):
    """exact=true: o trecho [byteOffset, +byteLength) do anexo original é o texto buscado."""
    d = json.loads((Path(session) / "session.json").read_text())
    att = {a["id"]: a for r in d["requests"] for a in r["attempts"]}
    bad = []
    for m in matches:
        if not m.get("exact"):
            continue
        key = "requestBody" if m["scope"] == "requestBody" else "responseBody"
        name = att[m["attemptId"]][key]["attachment"]
        raw = (Path(session) / "attachments" / name).read_bytes()
        piece = raw[m["byteOffset"]:m["byteOffset"] + m["byteLength"]]
        # busca sem --case-sensitive: compara sem diferenciar maiúsculas, nos bytes
        if piece.lower() != query.encode().lower():
            bad.append(f"{m['requestId']} {m['scope']}: anexo[{m['byteOffset']}:+{m['byteLength']}]={piece!r} != {query!r}")
    return bad


def rid_of_11():
    return "1011.11"


def import_fixture(core, name, tmp):
    cdp, bodies = FIX / f"{name}.cdp.jsonl", FIX / f"{name}.cdp-bodies.jsonl"
    netlog = FIX / f"{name}.netlog.json"
    if not netlog.exists():  # edge não tem NetLog: NetLog vazio e válido
        netlog = Path(tmp) / "empty.netlog.json"
        netlog.write_text(json.dumps({"constants": {"logEventTypes": {}, "timeTickOffset": 0}, "events": []}))
    out = Path(tmp) / "session"
    p = subprocess.run([core, "import-capture", str(cdp), str(netlog), "--out", str(out), "--bodies", str(bodies),
                        "--label", "synthetic-fixture"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"FAIL import {name}: {p.stderr.strip()[:300]}")
    labels = sorted(json.loads((out / "session.json").read_text())["session"].get("labels", []))
    if labels != ["capture-import", "synthetic-fixture"]:
        sys.exit(f"FAIL rótulos da sessão importada: {labels} != ['capture-import', 'synthetic-fixture']")
    return str(out)


def search(core, session, text, scope=None):
    cmd = [core, "search", str(session), text]
    if scope:
        cmd += ["--scope", scope]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"search falhou ({p.returncode}): {p.stderr.strip()[:300]}")
    out = json.loads(p.stdout)
    return out["matches"] if isinstance(out, dict) else out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session", nargs="?")
    ap.add_argument("--core")
    ap.add_argument("--fixture", choices=["detran", "edge"], default="detran")
    ap.add_argument("--import-fixture", action="store_true", help="importa detran-pb para uma pasta temporária (usa --bodies)")
    ap.add_argument("--sanitized", nargs="+", metavar="MARCADOR", help="sessão sanitizada: nenhum marcador pode ser achado")
    a = ap.parse_args()
    core = core_bin(a.core)
    manifest = json.loads((FIX / "manifest.json").read_text())
    session = a.session
    if a.import_fixture:
        name = "detran-pb" if a.fixture == "detran" else "detran-pb-edge"
        session = import_fixture(core, name, tempfile.mkdtemp(prefix=f"sl-bodies-{a.fixture}-"))
    if not session:
        ap.error("informe a pasta da sessão ou --import-fixture")

    fails = []
    if a.sanitized:
        for m in a.sanitized:
            hits = search(core, session, m)
            if hits:
                fails.append(f"marcador sensível {m!r} achado em sessão sanitizada ({len(hits)} matches)")
        return report(fails, f"sanitização: {len(a.sanitized)} marcadores ausentes")

    if a.fixture == "detran":
        cases = manifest["bodies_search_cases"]
        norm = lambda c: (c["query"], c["scope"], [(e["requestId"], e["field"], e["decoded"]) for e in c["expect"]])
    else:
        cases = manifest["bodies"]["edge"]["search"]
        norm = lambda c: (c["query"], c["scope"], [(r, None, None) for r in c["expect"]])
    ids = cdp_to_logical(session)
    for c in cases:
        query, scope, expect = norm(c)
        try:
            expect = [(ids[r], f, d) for r, f, d in expect]
        except KeyError as e:
            fails.append(f"{c['query']!r}: requestId CDP {e} sem requisição na sessão"); continue
        try:
            got = search(core, session, query, scope)
        except Exception as e:  # noqa: BLE001
            fails.append(f"{query!r}/{scope}: {e}"); continue
        got_set = sorted({(m["requestId"], m.get("field"), m.get("decoded")) for m in got})
        if a.fixture == "edge":  # edge confere só os ids; field/decoded não fazem parte do contrato do manifest
            got_set = sorted({(m["requestId"], None, None) for m in got})
        if got_set != sorted(set(expect)):
            fails.append(f"{query!r}/{scope}: esperado {sorted(set(expect))}, obtido {got_set}")
        if scope in ("requestBody", "responseBody"):
            fails += exact_slice_failures(session, got, query)
        if a.fixture == "detran" and query == "cmd_consultar_placa" and scope == "requestBody":
            want = (ids[rid_of_11()], "XML", 159, 19, True, True)
            row = [(m["requestId"], m.get("field"), m.get("byteOffset"), m.get("byteLength"), m.get("exact"), m.get("decoded"))
                   for m in got if m["requestId"] == want[0]]
            if row != [want]:
                fails.append(f"cdp-r0011 XML: esperado {want}, obtido {row}")
        if scope == "url" and got:
            fails.append(f"{query!r}: busca por URL não deve achar corpo")
    return report(fails, f"{len(cases)} casos de busca")


def report(fails, ok):
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", f) for f in fails]; return 1
    print("OK:", ok); return 0


if __name__ == "__main__":
    sys.exit(main())
