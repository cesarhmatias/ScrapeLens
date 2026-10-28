#!/usr/bin/env python3
"""Rodada 6 (docs/10, Aceite 5): revalida o ScrapeLens nos HARs REAIS do usuário, só com AGREGADOS.

  python3 tests/aceite/check_real_detran.py <har> [<har> ...] [--core BIN]

Os HARs são lidos de onde estão (somente leitura), importados num diretório temporário 0700 (mkdtemp)
que é apagado ao fim (inclusive em erro). Imprime apenas contagens, porcentagens, nomes de campo e
rótulos: nenhum valor real (SESSIONID, STAMP, delta, placa, CPF) é impresso, gravado ou versionado.

Critérios (exit 1 se algum falhar, sem afrouxar):
  * STAMP e delta com origem na resposta anterior do Connector em >= 95% dos POSTs com resposta disponível;
  * cadeia do 1º cmd_consultar_placa com os POSTs do Connector entre os passos;
  * 0 placas depois de sanitize;
  * com >= 2 HARs: ambiguidades do compare do 1º × 2º, reportadas (limite 15% dos pares).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402

CONNECTOR = "/servlet/Connector"


def run(core, *args):
    p = subprocess.run([core, *map(str, args)], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{args[0]} falhou ({p.returncode})")
    return json.loads(p.stdout) if p.stdout.strip().startswith("{") else p.stdout


def read(sess, att):
    return (Path(sess) / "attachments" / att).read_text(encoding="utf8", errors="replace")


def xml_groups(xml):
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


def analyse(core, har, tmp, idx):
    sess = str(Path(tmp) / f"s{idx}")
    run(core, "import-har", har, "--out", sess)
    s = json.loads((Path(sess) / "session.json").read_text())
    posts = [r for r in s["requests"] if r["method"] == "POST" and r["url"].endswith(CONNECTOR)]
    plates, first_consulta, pending = set(), None, 0
    prev_ok = False
    resolved_stamp = resolved_delta = eligible = 0
    for r in s["requests"]:
        if r not in posts:
            continue
        a = r["attempts"][0]
        form = urllib.parse.parse_qs(read(sess, a["requestBody"]["attachment"]), keep_blank_values=True)
        parts, g = xml_groups(form["XML"][0])
        if g.get("v_placa"):
            plates.add(g["v_placa"])
        if parts[6] == "cmd_consultar_placa" and first_consulta is None:
            first_consulta = r["id"]
        # elegível: STAMP != INIT e a resposta do POST anterior do Connector estava disponível
        if form["STAMP"][0] != "INIT" and prev_ok:
            eligible += 1
            o = run(core, "origins", sess, r["id"])
            st = [v for v in o["values"] if v["scope"] == "body" and v["field"] == "STAMP"]
            ok_stamp = bool(st) and any(e["kind"] == "same-field" and e["role"] == "produced" for v in st for e in v["evidences"])
            m = re.search(r"x(\d\d)(.+)$", form["XML"][0], re.S)
            token = m.group(2) if m and len(m.group(2)) == int(m.group(1)) else None  # só em memória
            dl = [v for v in o["values"] if token and v["scope"] == "body" and v.get("parent") == "XML" and token in v["value"]]
            conn_ids = {x["id"] for x in posts}
            ok_delta = any(e["kind"] == "value-match" and e["role"] in ("produced", "reissued") and e["producerRequestId"] in conn_ids
                           for v in dl for e in v["evidences"])
            resolved_stamp += ok_stamp; resolved_delta += ok_delta
        rb = a.get("responseBody") or {}
        prev_ok = rb.get("state") == "captured"
    out = {"requests": len(s["requests"]), "connector_posts": len(posts), "eligible_posts": eligible,
           "stamp_resolved": resolved_stamp, "delta_resolved": resolved_delta}
    out["stamp_pct"] = round(100 * resolved_stamp / eligible, 1) if eligible else None
    out["delta_pct"] = round(100 * resolved_delta / eligible, 1) if eligible else None
    if first_consulta:
        c = run(core, "chain", sess, first_consulta)
        conn = {r["id"] for r in posts}
        out["chain"] = {"steps": len(c["steps"]), "connector_steps": sum(1 for x in c["steps"] if x["requestId"] in conn),
                        "pages": len(c.get("pages", [])), "protection": len(c["protection"]), "unresolved": len(c["unresolved"])}
        out["chain_has_connector_posts"] = out["chain"]["connector_steps"] >= 3
        out["cookies_warning"] = any("cookie" in w.lower() for w in c["warnings"])
    san = str(Path(tmp) / f"san{idx}")
    run(core, "sanitize", sess, san)
    left = 0
    blob = "\n".join(open(f, encoding="utf8", errors="replace").read() for f in glob.glob(san + "/**/*", recursive=True) if os.path.isfile(f))
    for p in plates:
        left += blob.count(p) + blob.count(urllib.parse.quote(p, safe=""))
    out["plates_distinct"] = len(plates)
    out["plates_left_after_sanitize"] = left
    return sess, out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("hars", nargs="+"); ap.add_argument("--core"); a = ap.parse_args()
    core = cb.core_bin(a.core)
    tmp = tempfile.mkdtemp(prefix="sl-real-")  # 0700 por padrão
    os.chmod(tmp, 0o700)
    fails, sessions = [], []
    try:
        for i, har in enumerate(a.hars):
            sess, o = analyse(core, har, tmp, i)
            sessions.append(sess)
            print(f"HAR #{i + 1}: {json.dumps(o, ensure_ascii=False)}")
            if o["stamp_pct"] is None or o["stamp_pct"] < 95 or o["delta_pct"] < 95:
                fails.append(f"HAR #{i + 1}: STAMP {o['stamp_pct']}% / delta {o['delta_pct']}% (mín. 95%)")
            if not o.get("chain_has_connector_posts"):
                fails.append(f"HAR #{i + 1}: cadeia sem os POSTs do Connector")
            if o["plates_left_after_sanitize"]:
                fails.append(f"HAR #{i + 1}: {o['plates_left_after_sanitize']} ocorrência(s) de placa após sanitize")
        if len(sessions) >= 2:
            m = run(core, "compare", sessions[0], sessions[1])
            pairs = len(m["pairs"])
            summary = {"pairs": pairs, "onlyInA": len(m["onlyInA"]), "onlyInB": len(m["onlyInB"]), "ambiguities": len(m["ambiguities"]),
                       "unpairedRounds": len(m.get("unpairedRounds") or []) if m.get("unpairedRounds") is not None else "n/a"}
            print("compare #1 x #2:", json.dumps(summary))
            if pairs and summary["ambiguities"] > 0.15 * pairs:
                fails.append(f"compare: {summary['ambiguities']} ambiguidades em {pairs} pares (> 15%)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("temporário removido:", not os.path.exists(tmp))
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", f) for f in fails]; return 1
    print("OK: STAMP/delta >= 95%, cadeia com POSTs do Connector, 0 placas após sanitize"); return 0


if __name__ == "__main__":
    sys.exit(main())
