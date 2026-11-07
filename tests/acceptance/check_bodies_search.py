#!/usr/bin/env python3
"""Round 4 (docs/08-body-search.md §3.1): checks the search over the payload.

Given the folder of an imported session, runs `scrapelens-core search` for each
case in fixtures/detran-pb/manifest.json (`bodies_search_cases`, and `bodies.edge.search`
with --fixture edge) and compares the expected requestId/field/decoded. Expectations
are not relaxed: any divergence fails (exit 1).

  python3 tests/acceptance/check_bodies_search.py <session>            # DETRAN-PB
  python3 tests/acceptance/check_bodies_search.py <session> --fixture edge
  python3 tests/acceptance/check_bodies_search.py --import-fixture    # imports and checks
  python3 tests/acceptance/check_bodies_search.py <sanitized-session> --sanitized MARKER...
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
    # The most recent binary by mtime; refuses if it is older than the source code.
    cands = [ROOT / "target" / p / "scrapelens-core" for p in ("release", "debug")]
    cands = [c for c in cands if c.exists()]
    if not cands:
        sys.exit("scrapelens-core not found; run `cargo build` in core/ or use --core")
    best = max(cands, key=lambda c: c.stat().st_mtime)
    newest_src = max((f.stat().st_mtime for f in (ROOT / "core" / "src").rglob("*.rs")), default=0)
    if best.stat().st_mtime < newest_src:
        sys.exit(f"{best} is older than core/src; run `cargo build` in core/ or use --core")
    return str(best)


def cdp_to_logical(session):
    """CDP requestId -> logical session id, via the provenance in session.json."""
    d = json.loads((Path(session) / "session.json").read_text())
    return {r["cdp"]["requestId"]: r["id"] for r in d["requests"] if r.get("cdp", {}).get("requestId")}


def exact_slice_failures(session, matches, query):
    """exact=true: the slice [byteOffset, +byteLength) of the original attachment is the searched text."""
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
        # search without --case-sensitive: compares case-insensitively, on the bytes
        if piece.lower() != query.encode().lower():
            bad.append(f"{m['requestId']} {m['scope']}: anexo[{m['byteOffset']}:+{m['byteLength']}]={piece!r} != {query!r}")
    return bad


def rid_of_11():
    return "1011.11"


def import_fixture(core, name, tmp):
    cdp, bodies = FIX / f"{name}.cdp.jsonl", FIX / f"{name}.cdp-bodies.jsonl"
    netlog = FIX / f"{name}.netlog.json"
    if not netlog.exists():  # edge has no NetLog: an empty, valid NetLog
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
        sys.exit(f"FAIL labels of the imported session: {labels} != ['capture-import', 'synthetic-fixture']")
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
    ap.add_argument("--import-fixture", action="store_true", help="imports detran-pb into a temporary folder (uses --bodies)")
    ap.add_argument("--sanitized", nargs="+", metavar="MARKER", help="sanitized session: no marker may be found")
    a = ap.parse_args()
    core = core_bin(a.core)
    manifest = json.loads((FIX / "manifest.json").read_text())
    session = a.session
    if a.import_fixture:
        name = "detran-pb" if a.fixture == "detran" else "detran-pb-edge"
        session = import_fixture(core, name, tempfile.mkdtemp(prefix=f"sl-bodies-{a.fixture}-"))
    if not session:
        ap.error("give the session folder or --import-fixture")

    fails = []
    if a.sanitized:
        for m in a.sanitized:
            hits = search(core, session, m)
            if hits:
                fails.append(f"sensitive marker {m!r} found in sanitized session ({len(hits)} matches)")
        return report(fails, f"sanitization: {len(a.sanitized)} markers absent")

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
            fails.append(f"{c['query']!r}: CDP requestId {e} has no request in the session"); continue
        try:
            got = search(core, session, query, scope)
        except Exception as e:  # noqa: BLE001
            fails.append(f"{query!r}/{scope}: {e}"); continue
        got_set = sorted({(m["requestId"], m.get("field"), m.get("decoded")) for m in got})
        if a.fixture == "edge":  # edge checks only the ids; field/decoded are not part of the manifest contract
            got_set = sorted({(m["requestId"], None, None) for m in got})
        if got_set != sorted(set(expect)):
            fails.append(f"{query!r}/{scope}: expected {sorted(set(expect))}, got {got_set}")
        if scope in ("requestBody", "responseBody"):
            fails += exact_slice_failures(session, got, query)
        if a.fixture == "detran" and query == "cmd_consultar_placa" and scope == "requestBody":
            want = (ids[rid_of_11()], "XML", 159, 19, True, True)
            row = [(m["requestId"], m.get("field"), m.get("byteOffset"), m.get("byteLength"), m.get("exact"), m.get("decoded"))
                   for m in got if m["requestId"] == want[0]]
            if row != [want]:
                fails.append(f"cdp-r0011 XML: expected {want}, got {row}")
        if scope == "url" and got:
            fails.append(f"{query!r}: URL search must not find a body")
    return report(fails, f"{len(cases)} search cases")


def report(fails, ok):
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", f) for f in fails]; return 1
    print("OK:", ok); return 0


if __name__ == "__main__":
    sys.exit(main())
