#!/usr/bin/env python3
"""Rodada 7 (docs/11, Aceite 5): script de priming e assess nos HARs REAIS, só com AGREGADOS.

  python3 tests/aceite/check_real_priming.py <har> [<har> ...] [--core BIN]

HARs somente leitura; sessões e scripts em mkdtemp 0700, apagados ao fim. O script gerado NUNCA é executado
com `--confirmar` nem contra rede: só o modo plano (sem --confirmar), que imprime e sai. Nenhum valor real é
impresso/gravado: valores capturados só são usados em memória para CONTAR ocorrências literais no script.

Para o 1º cmd_consultar_placa de cada HAR: nº de passos, POSTs do Connector, ordem × fluxo manual
(easynat-app, NatLogon, init, SIM1000X, init, on_interceptor, VES0009X, init, cmd_filtro, cmd_consultar_placa),
tipo de extração de STAMP/delta/SESSIONID/placa, valores capturados literais, parâmetros (obrigatórios e com
padrão), ast.parse e saída do modo plano. E do assess: contagens por veredito e vereditos do Connector.

Critérios (exit 1, sem afrouxar): ast OK; modo plano rc 0 e sem enviar; ordem = fluxo manual; STAMP por
controle HTML; delta por trecho extraído; SESSIONID e placa como parâmetro/composição (nunca literal); 0 valores
capturados literais fora de comentários; nenhum 200 do Connector `blocked?`; respostas normais do Connector app-ok.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import urllib.parse
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402
import check_real_detran as rd  # noqa: E402

EXPECTED = ["easynat-app", "NatLogon", "init", "SIM1000X", "init", "on_interceptor", "VES0009X", "init", "cmd_filtro", "cmd_consultar_placa"]
PAGE_KEYS = ("easynat-app", "NatLogon", "SIM1000X", "VES0009X")


def code_without_comments(src):
    """Texto do script sem comentários (os comentários citam IDs e motivos, não valores executáveis)."""
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type != tokenize.COMMENT:
            out.append(tok.string)
    return " ".join(out)


def captured_values(sess, posts):
    """Valores capturados dos POSTs do Connector, só em memória: (rótulo, valor)."""
    vals = set()
    for r in posts:
        a = r["attempts"][0]
        f = urllib.parse.parse_qs(rd.read(sess, a["requestBody"]["attachment"]), keep_blank_values=True)
        sid, stamp, xml = f["SESSIONID"][0], f["STAMP"][0], f["XML"][0]
        parts, g = rd.xml_groups(xml)
        vals.add(("SESSIONID", sid))
        if "_" in sid:
            vals.add(("SESSIONID-sufixo", sid.split("_", 1)[1]))
        if stamp != "INIT":
            vals.add(("STAMP", stamp))
        vals.add(("processId", parts[1]))
        m = re.search(r"x(\d\d)(.+)$", xml, re.S)
        if m and len(m.group(2)) == int(m.group(1)):
            vals.add(("delta", m.group(2)))
        for k in ("v_placa", "v_cpf"):
            if g.get(k):
                vals.add((k, g[k]))
    return {(k, v) for k, v in vals if len(v) >= 4}


def kind_of(r, event):
    u = r["url"].split("?")[0]
    if u.endswith("/servlet/Connector"):
        return "init" if event == "" else event
    base = u.rsplit("/", 1)[-1]
    return base.replace(".html", "") if base.replace(".html", "") in PAGE_KEYS else None


def extraction_kinds(expr_src):
    names = set(re.findall(r"\b(html_control|body_field|ctx_extract|get_cookie|get_header|checked)\(", expr_src))
    kinds = []
    if "html_control" in names: kinds.append("controle HTML")
    if "ctx_extract" in names: kinds.append("trecho/literal de resposta")
    if "body_field" in names: kinds.append("campo form/JSON")
    if "get_cookie" in names: kinds.append("cookie jar")
    if re.search(r"\bP\[", expr_src): kinds.append("parâmetro")
    return kinds or ["literal"]


def target_step_fields(script):
    tree = ast.parse(script)
    last = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "STEPS" for t in n.targets))
    name = last.value.elts[-1].id
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    fields = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Tuple) and len(node.elts) == 2 and isinstance(node.elts[0], ast.Constant) and isinstance(node.elts[0].value, str):
            fields[node.elts[0].value] = ast.get_source_segment(script, node.elts[1]) or ""
    return fields


def analyse(core, har, tmp, idx):
    sess = str(Path(tmp) / f"s{idx}")
    rd.run(core, "import-har", har, "--out", sess)
    s = json.loads((Path(sess) / "session.json").read_text())
    byid = {r["id"]: r for r in s["requests"]}
    posts, events, consultas, prev_captured, ready = [], {}, [], False, {}
    for r in s["requests"]:
        if r["method"] == "POST" and r["url"].endswith(rd.CONNECTOR):
            posts.append(r)
            f = urllib.parse.parse_qs(rd.read(sess, r["attempts"][0]["requestBody"]["attachment"]), keep_blank_values=True)
            events[r["id"]] = rd.xml_groups(f["XML"][0])[0][6]
            if events[r["id"]] == "cmd_consultar_placa":
                consultas.append(r["id"]); ready[r["id"]] = prev_captured
            prev_captured = (r["attempts"][0].get("responseBody") or {}).get("state") == "captured"
    out = {"connector_posts_in_har": len(posts), "consultas": len(consultas)}
    if not consultas:
        return sess, out, ["sem cmd_consultar_placa"]
    # alvo 1: o 1º cmd_consultar_placa; alvo 2 (se o 1º não tem a resposta anterior capturada): o 1º com a resposta anterior capturada
    targets = [("primeiro", consultas[0])]
    alt = next((c for c in consultas if ready[c]), None)
    if not ready[consultas[0]] and alt:
        targets.append(("primeiro_com_resposta_anterior_capturada", alt))
    out["targets"] = {}
    fails = []
    for label, first in targets:
        o, f = analyse_target(core, sess, s, byid, posts, events, first, tmp, idx, label, strict=ready[first])
        out["targets"][label] = o
        fails += [f"[{label}] {x}" for x in f]
    a = rd.run(core, "assess", sess)
    out["assess_counts"] = a["counts"]
    cv = Counter(o["verdictKind"] for o in a["outcomes"] if o["url"].endswith(rd.CONNECTOR))
    c200 = Counter(o["verdictKind"] for o in a["outcomes"] if o["url"].endswith(rd.CONNECTOR) and o["status"] == 200)
    out["assess_connector"] = dict(cv)
    nobody = sum(1 for r in posts if (r["attempts"][0].get("responseBody") or {}).get("state") != "captured")
    out["connector_posts_without_response_body"] = nobody
    blocked_other = Counter()
    for o in a["outcomes"]:
        if o["verdictKind"] == "blocked" and not o["url"].endswith(rd.CONNECTOR):
            base = o["url"].split("?")[0].rsplit("/", 1)[-1]
            blocked_other["TSPD" if "/TSPD/" in o["url"] else (base if base in ("easynat-app", "NatLogon.html", "SIM1000X.html", "VES0009X.html") else "outro")] += 1
    out["assess_blocked_non_connector"] = dict(blocked_other)
    out["assess_blocked_with_explicit_evidence"] = all(o["appSignals"] for o in a["outcomes"] if o["verdictKind"] == "blocked")
    if c200.get("blocked"):
        fails.append(f"{c200['blocked']} 200 do Connector como blocked?")
    bad = set(cv) - {"app-ok"}
    if cv.get("app-ok", 0) + nobody != len(posts) or (bad - {"indeterminado"}):
        fails.append(f"POSTs do Connector: esperado app-ok (+ indeterminado só sem corpo capturado); obtido {dict(cv)}, sem corpo {nobody}")
    return sess, out, fails


def analyse_target(core, sess, s, byid, posts, events, first, tmp, idx, label, strict):
    out, fails = {}, []
    p = subprocess.run([core, "export-priming", sess, first], capture_output=True, text=True)
    if p.returncode != 0:
        return sess, out, [f"export-priming falhou ({p.returncode})"]
    script = p.stdout
    spath = Path(tmp) / f"priming{idx}-{label}.py"
    spath.write_text(script)
    try:
        ast.parse(script); out["ast_parse"] = "OK"
    except SyntaxError:
        out["ast_parse"] = "FALHOU"; fails.append("ast.parse falhou")
    # plano: ids dos passos
    plan = re.search(r"^PLAN = \[\n(.*?)^\]", script, re.S | re.M)
    ids = re.findall(r"^\s+\('(har-\d+)', '(GET|POST)'", plan.group(1), re.M) if plan else []
    out["steps"] = len(ids)
    conn = [rid for rid, m in ids if rid in events]
    out["connector_posts_in_script"] = len(conn)
    seq = [k for rid, _ in ids if (k := kind_of(byid[rid], events.get(rid))) is not None]
    out["order_matches_manual_flow"] = seq == EXPECTED
    out["steps_outside_flow"] = len([rid for rid, _ in ids if kind_of(byid[rid], events.get(rid)) is None])
    out["resposta_anterior_capturada"] = strict
    if seq != EXPECTED and strict:
        fails.append(f"ordem diferente do fluxo manual: {seq}")
    # extração no passo-alvo
    f = target_step_fields(script)
    out["extraction"] = {k: extraction_kinds(f.get(k, "")) for k in ("STAMP", "SESSIONID", "XML") if k in f}
    params = re.search(r"^PARAMS = \[\n(.*?)^\]", script, re.S | re.M)
    prm = re.findall(r"^\s+\('([^']*)', (None|'[^']*'|\"[^\"]*\"), ", params.group(1), re.M) if params else []
    req = [n for n, d in prm if d == "None"]
    dflt = [n for n, d in prm if d != "None"]
    out["params_required"] = req
    out["params_with_default"] = dflt
    out["placa_param_required"] = "placa" in req
    # valores capturados literais (só contagem) fora de comentários
    code = code_without_comments(script)
    vals = captured_values(sess, posts)
    short_delta = {k for k, v in vals if k == "delta" and len(v) <= 8 and v in code}
    out["delta_curto_coincidente_com_constante_do_xml_ignorado"] = len(short_delta)
    lit = Counter(k for k, v in vals if v in code and not (k == "delta" and len(v) <= 8))
    out["captured_values_checked"] = len(vals)
    out["captured_literals_in_code"] = dict(lit) or 0
    lit_in_params = Counter(k for k, v in vals if params and v in params.group(1))
    out["captured_literals_in_params_defaults"] = dict(lit_in_params) or 0
    if lit:
        fails.append(f"valores capturados literais no código: {dict(lit)}")
    if lit_in_params:
        fails.append(f"valor de sessão capturado como PADRÃO de parâmetro (deveria ser obrigatório): {dict(lit_in_params)}")
    if strict and "controle HTML" not in out["extraction"].get("STAMP", []):
        fails.append("STAMP não extraído de controle HTML")
    if strict and not any("trecho" in k for k in out["extraction"].get("XML", [])):
        fails.append("delta/XML sem trecho extraído em runtime")
    if "placa" not in req:
        fails.append("placa não é parâmetro obrigatório")
    # modo plano (sem --confirmar)
    pl = subprocess.run([sys.executable, "-I", str(spath)], capture_output=True, text=True, timeout=30)
    nlines = len(re.findall(r"^\s+\d+\. (GET|POST) ", pl.stdout, re.M))
    out["plan_mode"] = {"rc": pl.returncode, "plan_lines": nlines, "nothing_sent_notice": "Nada foi enviado" in pl.stdout}
    if pl.returncode != 0 or nlines != len(ids) or "Nada foi enviado" not in pl.stdout:
        fails.append(f"modo plano: rc={pl.returncode} linhas={nlines}/{len(ids)}")
    return out, fails


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("hars", nargs="+"); ap.add_argument("--core"); a = ap.parse_args()
    core = cb.core_bin(a.core)
    tmp = tempfile.mkdtemp(prefix="sl-prime-"); os.chmod(tmp, 0o700)
    fails = []
    try:
        for i, har in enumerate(a.hars):
            _, o, f = analyse(core, har, tmp, i)
            print(f"HAR #{i + 1}: {json.dumps(o, ensure_ascii=False)}")
            fails += [f"HAR #{i + 1}: {x}" for x in f]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("temporário removido:", not os.path.exists(tmp))
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", x) for x in fails]; return 1
    print("OK: priming e assess nos HARs reais (agregados)"); return 0


if __name__ == "__main__":
    sys.exit(main())
