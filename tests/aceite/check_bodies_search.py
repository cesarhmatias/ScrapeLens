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
    for p in ("release", "debug"):
        c = ROOT / "core" / "target" / p / "scrapelens-core"
        if c.exists():
            return str(c)
    sys.exit("scrapelens-core não encontrado; use --core")


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
        session = str(Path(tempfile.mkdtemp(prefix="sl-bodies-")) / "session")
        p = subprocess.run([core, "import-capture", str(FIX / "detran-pb.cdp.jsonl"), str(FIX / "detran-pb.netlog.json"),
                            "--out", session, "--bodies", str(FIX / "detran-pb.cdp-bodies.jsonl")], capture_output=True, text=True)
        if p.returncode != 0:
            print("FAIL import:", p.stderr.strip()[:300]); return 1
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
    for c in cases:
        query, scope, expect = norm(c)
        try:
            got = search(core, session, query, scope)
        except Exception as e:  # noqa: BLE001
            fails.append(f"{query!r}/{scope}: {e}"); continue
        got_set = sorted({(m["requestId"], m.get("field"), m.get("decoded")) for m in got})
        if a.fixture == "edge":
            got_set = sorted({(m["requestId"], None, None) for m in got})
        if got_set != sorted(set(expect)):
            fails.append(f"{query!r}/{scope}: esperado {sorted(set(expect))}, obtido {got_set}")
        if scope == "url" and got:
            fails.append(f"{query!r}: busca por URL não deve achar corpo")
    return report(fails, f"{len(cases)} casos de busca")


def report(fails, ok):
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", f) for f in fails]; return 1
    print("OK:", ok); return 0


if __name__ == "__main__":
    sys.exit(main())
