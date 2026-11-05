#!/usr/bin/env python3
"""Round 7 (docs/11, Acceptance 5): priming script and assess on the REAL HARs, with AGGREGATES only.

  python3 tests/acceptance/check_real_priming.py <har> [<har> ...] [--core BIN]

Read-only HARs; sessions and scripts in mkdtemp 0700, deleted at the end. The generated script is NEVER run
with `--confirm` nor against the network: only the plan mode (without --confirm), which prints and exits. No real
value is printed or written: captured values are only used in memory to COUNT literal occurrences in the script.

For the 1st cmd_consultar_placa of each HAR: number of steps, Connector POSTs, order × manual flow
(easynat-app, NatLogon, init, SIM1000X, init, on_interceptor, VES0009X, init, cmd_filtro, cmd_consultar_placa),
kind of STAMP/delta/SESSIONID/plate extraction, captured literal values, parameters (required and with
default), ast.parse and plan mode output. And from assess: counts per verdict and Connector verdicts.

Criteria (exit 1, no relaxing): ast OK; plan mode rc 0 and sending nothing; order = manual flow; STAMP from an
HTML control; delta from an extracted excerpt; SESSIONID and plate as parameter/composition (never literal); 0 captured
literal values outside comments; required parameters ⊆ {sessionid_cliente, placa} in every target generated
through the normal path; no Connector 200 `blocked?`; normal Connector responses app-ok.
The script of the `--allow-incomplete` escape hatch (chain with a producer without a body) only has its parameters
registered as information: in it, a value without an observable producer is, by definition, operator input.
Incomplete chain (F2): if the HAR has a Connector POST without a response body, `export-priming` must REFUSE,
listing the producers without a body and the equivalent occurrence with a body; with `--allow-incomplete`, the
generated script has an explicit `fail()` and stays valid in `ast.parse`/plan mode.
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
# Operator inputs accepted in the generated script: the plate (the user's search) and the SESSIONID part built on the
# client. Everything else (STAMP, delta, processId, pageInitParam, navigation) must be extracted or derived.
ALLOWED_REQUIRED = {"sessionid_cliente", "placa"}


def code_without_comments(src):
    """Script text without comments (comments cite IDs and reasons, not executable values)."""
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type != tokenize.COMMENT:
            out.append(tok.string)
    return " ".join(out)


def captured_values(sess, posts):
    """Captured values from the Connector POSTs, in memory only: (label, value)."""
    vals = set()
    for r in posts:
        a = r["attempts"][0]
        f = urllib.parse.parse_qs(rd.read(sess, a["requestBody"]["attachment"]), keep_blank_values=True)
        sid, stamp, xml = f["SESSIONID"][0], f["STAMP"][0], f["XML"][0]
        parts, g = rd.xml_groups(xml)
        vals.add(("SESSIONID", sid))
        if "_" in sid:
            vals.add(("SESSIONID-suffix", sid.split("_", 1)[1]))
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


EXPORT = lambda core: [core]   # with --wrapper: [wrapper] (export-priming with the adapter); import/assess still use the core
EXPORT_ARGS: list[str] = []


def extraction_kinds(expr_src):
    names = set(re.findall(r"\b(html_control|body_field|ctx_extract|adapter_get|get_cookie|get_header|checked)\(", expr_src))
    kinds = []
    if "html_control" in names: kinds.append("HTML control")
    if "ctx_extract" in names or "adapter_get" in names: kinds.append("response excerpt/literal")
    if "body_field" in names: kinds.append("form/JSON field")
    if "get_cookie" in names: kinds.append("cookie jar")
    if re.search(r"\bP\[", expr_src): kinds.append("parameter")
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
        return sess, out, ["no cmd_consultar_placa"]
    # target 1: the 1st cmd_consultar_placa; target 2 (if the 1st does not have the previous response captured): the 1st with the previous response captured
    targets = [("first", consultas[0])]
    alt = next((c for c in consultas if ready[c]), None)
    if not ready[consultas[0]] and alt:
        targets.append(("first_with_previous_response_captured", alt))
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
    # F2: with a producer without a body, the refusal is the CORRECT result — and the message
    # must list the producers and the equivalent occurrence with a body.
    refused = {k: v["refused"] for k, v in out["targets"].items() if "refused" in v}
    out["refusal_for_incomplete_chain"] = sorted(k for k, v in refused.items() if v["mentions_incomplete"])
    if nobody and not out["refusal_for_incomplete_chain"]:
        fails.append(f"{nobody} Connector response(s) without a body, but export-priming did not refuse the incomplete chain")
    for label, v in refused.items():
        if v["mentions_incomplete"] and not (v["lists_producers"] and v["suggests_equivalent"] and v["allow_incomplete_script"] == "OK"):
            fails.append(f"[{label}] incomplete refusal without producers/suggestion/explicit fail(): {v}")
        elif not v["mentions_incomplete"]:
            fails.append(f"[{label}] export-priming refused for another reason: {v['message'][:200]}")
    blocked_other = Counter()
    for o in a["outcomes"]:
        if o["verdictKind"] == "blocked" and not o["url"].endswith(rd.CONNECTOR):
            base = o["url"].split("?")[0].rsplit("/", 1)[-1]
            blocked_other["TSPD" if "/TSPD/" in o["url"] else (base if base in ("easynat-app", "NatLogon.html", "SIM1000X.html", "VES0009X.html") else "other")] += 1
    out["assess_blocked_non_connector"] = dict(blocked_other)
    out["assess_blocked_with_explicit_evidence"] = all(o["appSignals"] for o in a["outcomes"] if o["verdictKind"] == "blocked")
    if c200.get("blocked"):
        fails.append(f"{c200['blocked']} Connector 200 as blocked?")
    bad = set(cv) - {"app-ok"}
    if cv.get("app-ok", 0) + nobody != len(posts) or (bad - {"undetermined"}):
        fails.append(f"Connector POSTs: expected app-ok (+ undetermined only without captured body); got {dict(cv)}, without body {nobody}")
    return sess, out, fails


def analyse_target(core, sess, s, byid, posts, events, first, tmp, idx, label, strict):
    out, fails = {}, []
    p = subprocess.run([*EXPORT(core), "export-priming", sess, first, *EXPORT_ARGS], capture_output=True, text=True)
    if p.returncode != 0:
        msg = " ".join(p.stderr.split())
        if EXPORT_ARGS and label == "first_with_previous_response_captured":
            fails.append("with --wrapper the target with a previous response captured MUST generate the script with the adapter; "
                         "refusal is not acceptable: " + msg[:160])
        out["refused"] = {
            "rc": p.returncode,
            "mentions_incomplete": "incomplete chain" in msg,
            "lists_producers": "without an observable body" in msg and "Responses without a body:" in msg,
            "suggests_equivalent": bool(re.search(r"(equivalent occurrence with a full body: har-\d{4}|no equivalent occurrence)", msg)),
            "message": msg[:400],
            "allow_incomplete_script": "FAILED",
        }
        # --allow-incomplete: script generated with an explicit fail(), still valid Python.
        p2 = subprocess.run([*EXPORT(core), "export-priming", sess, first, "--allow-incomplete", *EXPORT_ARGS], capture_output=True, text=True)
        if p2.returncode == 0:
            script = p2.stdout
            spath = Path(tmp) / f"priming{idx}-{label}-incomplete.py"
            spath.write_text(script)
            try:
                ast.parse(script)
                plan = re.search(r"^PLAN = \[\n(.*?)^\]", script, re.S | re.M)
                ids = re.findall(r"^\s+\('(har-\d+)', '(GET|POST)'", plan.group(1), re.M) if plan else []
                pl = subprocess.run([sys.executable, "-I", str(spath)], capture_output=True, text=True, timeout=30)
                out["refused"]["allow_incomplete"] = {
                    "steps": len(ids),
                    "fail_calls": len(re.findall(r"^\s+fail\(", script, re.M)),
                    "plan_mode_rc": pl.returncode,
                    "nothing_sent_notice": "Nothing was sent" in pl.stdout,
                }
                # Explicit escape hatch (incomplete chain): records what it requires, without applying the quality
                # criterion — here a value without an observable producer can only be operator input.
                ap_ = re.search(r"^PARAMS = \[\n(.*?)^\]", script, re.S | re.M)
                aprm = re.findall(r"^\s+\('([^']*)', (None|'[^']*'|\"[^\"]*\"), ", ap_.group(1), re.M) if ap_ else []
                out["refused"]["allow_incomplete"]["params_required"] = [n for n, d in aprm if d == "None"]
                if out["refused"]["allow_incomplete"]["fail_calls"] >= 1 and pl.returncode == 0 and "Nothing was sent" in pl.stdout:
                    out["refused"]["allow_incomplete_script"] = "OK"
            except SyntaxError:
                out["refused"]["allow_incomplete_script"] = "FAILED"
        return out, fails
    script = p.stdout
    spath = Path(tmp) / f"priming{idx}-{label}.py"
    spath.write_text(script)
    if EXPORT_ARGS:
        out["usa_adaptador_natural_ajax_encode"] = "natural_ajax_encode" in script
        if not out["usa_adaptador_natural_ajax_encode"]:
            fails.append("with --wrapper the generated script should use the adapter (natural_ajax_encode missing)")
    try:
        ast.parse(script); out["ast_parse"] = "OK"
    except SyntaxError:
        out["ast_parse"] = "FAILED"; fails.append("ast.parse failed")
    # plan: step ids
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
        fails.append(f"order differs from the manual flow: {seq}")
    # extraction at the target step
    f = target_step_fields(script)
    out["extraction"] = {k: extraction_kinds(f.get(k, "")) for k in ("STAMP", "SESSIONID", "XML") if k in f}
    params = re.search(r"^PARAMS = \[\n(.*?)^\]", script, re.S | re.M)
    prm = re.findall(r"^\s+\('([^']*)', (None|'[^']*'|\"[^\"]*\"), ", params.group(1), re.M) if params else []
    req = [n for n, d in prm if d == "None"]
    dflt = [n for n, d in prm if d != "None"]
    out["params_required"] = req
    out["params_with_default"] = dflt
    # Quality (leader, F1): only placa and sessionid_cliente may be required; the rest is derivable.
    out["params_required_extra"] = [n for n in req if n not in ALLOWED_REQUIRED]
    out["params_required_only_placa_e_sessionid"] = not out["params_required_extra"]
    if out["params_required_extra"]:
        fails.append("required parameters beyond sessionid_cliente/placa (the generator must derive them): "
                     + ", ".join(out["params_required_extra"]))
    out["placa_param_required"] = "placa" in req
    # captured literal values (count only) outside comments
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
        fails.append(f"captured literal values in the code: {dict(lit)}")
    if lit_in_params:
        fails.append(f"session value captured as a parameter DEFAULT (should be required): {dict(lit_in_params)}")
    if strict and "HTML control" not in out["extraction"].get("STAMP", []):
        fails.append("STAMP not extracted from an HTML control")
    if strict and not any("excerpt" in k for k in out["extraction"].get("XML", [])):
        fails.append("delta/XML without an excerpt extracted at runtime")
    if "placa" not in req:
        fails.append("placa is not a required parameter")
    # plan mode (without --confirm)
    pl = subprocess.run([sys.executable, "-I", str(spath)], capture_output=True, text=True, timeout=30)
    nlines = len(re.findall(r"^\s+\d+\. (GET|POST) ", pl.stdout, re.M))
    out["plan_mode"] = {"rc": pl.returncode, "plan_lines": nlines, "nothing_sent_notice": "Nothing was sent" in pl.stdout}
    if pl.returncode != 0 or nlines != len(ids) or "Nothing was sent" not in pl.stdout:
        fails.append(f"plan mode: rc={pl.returncode} lines={nlines}/{len(ids)}")
    return out, fails


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("hars", nargs="+"); ap.add_argument("--core")
    ap.add_argument("--wrapper", help="natural-core: runs export-priming WITH the adapter (--adapter natural-ajax)")
    a = ap.parse_args()
    if a.wrapper:
        global EXPORT, EXPORT_ARGS
        os.environ["SCRAPELENS_CORE_BIN"] = cb.core_bin(a.core)
        EXPORT = lambda core: [a.wrapper]
        EXPORT_ARGS = ["--adapter", "natural-ajax"]
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
    print("temporary removed:", not os.path.exists(tmp))
    if fails:
        print(f"FAIL ({len(fails)}):"); [print(" -", x) for x in fails]; return 1
    print("OK: priming and assess on the real HARs (aggregates)"); return 0


if __name__ == "__main__":
    sys.exit(main())
