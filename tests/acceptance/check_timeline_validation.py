#!/usr/bin/env python3
"""Round 9 (docs/13-timeline-validation.md): application timeline and validation of the script execution.

  python3 tests/acceptance/check_timeline_validation.py [--core BIN] [--wrapper natural-core] [--python PY_COM_REQUESTS]
         [--port 8793] [HAR_REAL ...]   (or SL_REAL_HARS=a.har:b.har; without it the real-HAR part is skipped)

(1) `natural-core timeline <session> --adapter natural-ajax` on the real-shape (1 and 2 rounds): application events in the
    order of the manual flow (init, init, on_interceptor, init, cmd_filtro, cmd_consultar_placa; per round), labels
    `event @ page`, protection collapsed (no standalone /TSPD/ entry). On the real HARs (H1–H3 default), aggregate only:
    counts and label order (event and page names, never values).
(2) priming script of the real-shape, run BY THIS TEST against detran-sim with `--confirm --base-url --trace`;
    `import-trace`; `validate <capture> <trace>` (scrapelens.validate/1; core 94478de): all trace steps paired, no
    Connector POST left over only in the capture, only the expected dynamic values differ (STAMP, delta, SESSIONID + what
    is inherent to the host switch), assess app-ok, and the summary "equivalent".
(3) error/nocontrols/403 modes: the trace ends at the bad step; compare points to "diverges at step N" (N = last step of
    the trace = first bad request of the sim) and assess gives the right verdict (error → app-error; 403 → blocked;
    nocontrols → not app-ok).
(4) the trace has permission 0600 and the warning "contains data from your session"; sanitize on the trace's session
    removes SESSIONID, cookies and the plate.

Formats not yet delivered (timeline, import-trace, --trace) are read tolerantly, per doc 13:
timeline = JSON with a list of entries {label, kind[, count]}; trace = JSON `scrapelens.trace/1` with a `steps` list;
compare = JSON of the current compare + a textual summary ("equivalent" | "diverges at step N") under any key.
Fails until Core/Capture deliver; nothing is relaxed. Data 100% synthetic; real HARs only in aggregate.
Result: tests/results/priming/timeline-validation.json.
"""
from __future__ import annotations

import argparse, json, os, re, shlex, shutil, stat, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402
import check_priming_sim as ps  # noqa: E402
import check_priming_injection as ci  # noqa: E402  (entry(): synthetic HAR assembly)

ROOT = cb.ROOT
OUT = ROOT / "tests" / "results" / "priming" / "timeline-validation.json"
FIX = ROOT / "fixtures" / "detran-pb-real-shape"
EVENTS = ["init", "init", "on_interceptor", "init", "cmd_filtro", "cmd_consultar_placa"]   # manual flow up to the 1st query
FIXTURE_ROUND = EVENTS + ["cmd_nova", "cmd_consultar_placa"]                                   # the fixture has a 2nd query
# Real HARs are personal: never a default path. Set SL_REAL_HARS to a list of
# files separated by os.pathsep; when it is unset the real-HAR part is skipped
# explicitly (reported as skipped, not as passed).
REAL = [h for h in os.environ.get("SL_REAL_HARS", "").split(os.pathsep) if h]
DYNAMIC_OK = re.compile(r"^XML(\.|$)|STAMP|SESSIONID|delta|processId|content-length|host|date|server|url|origin|referer|port", re.I)
PLACA = "BRA2E19"
FAILS: list[str] = []
INFO: dict = {}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def sh(argv, **kw):
    return subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def jload(p, what):
    if p.returncode != 0:
        check(False, f"{what}: rc={p.returncode}: {' '.join(p.stderr.split())[:140]}")
        return None
    try:
        return json.loads(p.stdout)
    except Exception:
        check(False, f"{what}: output is not JSON")
        return None


def entries_of(d):
    if isinstance(d, list):
        return [e for e in d if isinstance(e, dict)]
    for k in ("items", "entries", "events", "timeline"):
        if isinstance(d, dict) and isinstance(d.get(k), list):
            return [e for e in d[k] if isinstance(e, dict)]
    return []


def kind(e):
    return str(e.get("kind") or e.get("type") or "").lower()


def is_group(e):
    return e.get("type") == "group" or "group" in kind(e) or "grupo" in kind(e)  # "grupo": legacy kind name, accepted on input


def is_protection(e):
    """Standalone protection = /TSPD/ event entry; the `protection` group (type=group) is the correct collapsed form."""
    if is_group(e):
        return "protec" in kind(e)
    return "/TSPD/" in str(e.get("url", "")) + str(e.get("label", ""))


def timeline_agg(wrapper, sess, what):
    d = jload(sh([wrapper, "timeline", sess, "--adapter", "natural-ajax"]), f"{what}: timeline")
    es = entries_of(d)
    if not check(bool(es), f"{what}: timeline has no entries"):
        return None
    posts = [e for e in es if not is_group(e) and str(e.get("url", "")).endswith("/servlet/Connector")]
    labels = [str(e.get("label", "")) for e in posts]
    ev = [l.split(" @ ")[0] if " @ " in l else "?" for l in labels]
    pages = [l.split(" @ ")[1] if " @ " in l else "?" for l in labels]
    groups = [e for e in es if is_group(e) and "protec" in kind(e)]
    standalone = [e for e in es if not is_group(e) and is_protection(e)]
    agg = {"entradas": len(es), "posts_connector": len(posts), "posts_sem_rotulo_event_page": ev.count("?"),
           "sequencia_eventos": ev, "paginas": pages, "grupos_protecao": len(groups),
           "protecao_recolhida": bool(groups) and not standalone, "protecao_avulsa": len(standalone)}
    check(bool(groups) and not standalone,
          f"{what}: protection should come collapsed into groups with a count ({len(groups)} groups, {len(standalone)} standalone entries)")
    check(ev.count("?") == 0, f"{what}: {ev.count('?')} of {len(posts)} Connector POSTs without an `event @ page` label from the adapter")
    return agg


def subsequence(seq, sub):
    it = iter(seq)
    return all(any(x == y for y in it) for x in sub)


def trace_steps(path):
    t = json.loads(Path(path).read_text())
    return t, (t.get("steps") if isinstance(t, dict) else None) or []


def find_text(o, rx):
    if isinstance(o, str):
        return re.search(rx, o)
    if isinstance(o, dict):
        return next((m for v in o.values() if (m := find_text(v, rx))), None)
    if isinstance(o, list):
        return next((m for v in o if (m := find_text(v, rx))), None)
    return None


def diff_names(o, under=False, out=None):
    out = set() if out is None else out
    if isinstance(o, dict):
        for k, v in o.items():
            hit = under or re.search(r"diff|changed|differ|mudou", k, re.I)  # "mudou": legacy key name (dead helper)
            if hit and isinstance(v, (str, int)) and k not in ("count",):
                out.add(str(v)) if isinstance(v, str) else None
            diff_names(v, bool(hit), out)
            if hit and re.search(r"name|field|part|header", k, re.I) and isinstance(v, str):
                out.add(v)
    elif isinstance(o, list):
        for v in o:
            if under and isinstance(v, str):
                out.add(v)
            diff_names(v, under, out)
    return out


FORM = "application/x-www-form-urlencoded"
LOOP = "http://127.0.0.1:18791"


def rv_capture(tmp, core):
    """Synthetic 4-step capture (reviewer cases, val1.py): new STAMP on each response, long/short constants, plate."""
    A = "http://app.test"
    ent = [
        ci.entry(1, "GET", f"{A}/entry", 200, "text/html", "<html>entry</html>", []),
        ci.entry(2, "GET", f"{A}/a", 200, "text/html", '<input type=hidden name="STAMP" value="STAMPCAP1234567">', []),
        ci.entry(3, "POST", f"{A}/go", 200, "text/html",
                 '<input type=hidden name="STAMP" value="STAMPCAP7654321"><textarea name="XML">ok</textarea>', [],
                 post=[("STAMP", "STAMPCAP1234567"), ("q", "cadastro"), ("sig", "0123456789abcdef0123456789abcdef"), ("placa", "ABC1D23")]),
        ci.entry(4, "POST", f"{A}/go2", 200, "text/html",
                 '<input type=hidden name="STAMP" value="STAMPCAP0000000"><textarea name="XML">done</textarea>', [],
                 post=[("STAMP", "STAMPCAP7654321"), ("q", "consulta")]),
    ]
    har = {"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "1"}, "pages": [], "entries": ent}}
    (tmp / "rv-cap.har").write_text(json.dumps(har))
    sh([core, "import-har", tmp / "rv-cap.har", "--out", tmp / "rv-cap", "--label", "synthetic-fixture"])
    return tmp / "rv-cap"


def rv_step(method, url, req=None, resp="", status=200):
    return {"method": method, "url": url, "status": status,
            "requestHeaders": [["content-type", FORM]] if req is not None else [],
            "responseHeaders": [["content-type", "text/html"]],
            "requestBody": {"text": req, "encoding": "utf8", "truncated": False} if req is not None else None,
            "responseBody": {"text": resp, "encoding": "utf8", "truncated": False}}


def rv_cases():
    L = LOOP
    st = lambda v: f'<input type=hidden name="STAMP" value="{v}">'  # noqa: E731
    ST, ST2, ST3 = "STAMPNEW0000001", "STAMPNEW0000002", "STAMPNEW0000003"
    SIG = "sig=0123456789abcdef0123456789abcdef"
    go_resp = st(ST2) + '<textarea name="XML">ok</textarea>'
    done = rv_step("POST", f"{L}/go2", f"STAMP={ST2}&q=consulta", st(ST3) + '<textarea name="XML">done</textarea>')
    good = [rv_step("GET", f"{L}/entry", resp="<html>entry</html>"), rv_step("GET", f"{L}/a", resp=st(ST)) if False else rv_step("GET", f"{L}/a", resp=st(ST)),
            rv_step("POST", f"{L}/go", f"STAMP={ST}&q=cadastro&{SIG}&placa=XYZ9K88", go_resp), done]
    cases = {}
    cases["V1 faithful (control)"] = (good, [{"name": "placa"}], "equivalent", None, True)
    cases["V2b prefix (without the target)"] = (good[:3], [{"name": "placa"}], "not-equivalent", r"incomplet", False)
    froz = list(good)
    froz[2] = rv_step("POST", f"{L}/go", f"STAMP=STAMPCAP1234567&q=cadastro&{SIG}&placa=XYZ9K88", go_resp)
    froz[3] = rv_step("POST", f"{L}/go2", "STAMP=STAMPCAP7654321&q=consulta", done["responseBody"]["text"])
    cases["V3 frozen STAMP (captured value)"] = (froz, [{"name": "placa"}], "not-equivalent", r"frozen", True)
    sig = list(good)
    sig[2] = rv_step("POST", f"{L}/go", f"STAMP={ST}&q=cadastro&sig=ffffffffffffffffffffffffffffffff&placa=XYZ9K88", go_resp)
    cases["V5 long constant swapped (sig)"] = (sig, [{"name": "placa"}], "not-equivalent", None, True)
    forged = [good[0], good[1], rv_step("POST", f"{L}/go", "STAMP=INVENTED&q=OUTRA&sig=ffffffffffffffffffffffffffffffff&placa=XYZ9K88", go_resp), good[3]]
    cases["V7 forged parameters (q, sig, STAMP)"] = (forged, [{"name": "q"}, {"name": "sig"}, {"name": "STAMP"}, {"name": "placa"}], "not-equivalent", r"invalid parameter", True)
    wrong = list(good)   # wrong origin: step 4 uses the STAMP of step 2 (ST), not the one from the previous response (ST2)
    wrong[3] = rv_step("POST", f"{L}/go2", f"STAMP={ST}&q=consulta", done["responseBody"]["text"])
    cases["V18 wrong origin (STAMP from an old response)"] = (wrong, [{"name": "placa"}], "not-equivalent", r"different origin", True)
    other = [dict(x, url=x["url"].replace("127.0.0.1:18791", "evil.example")) for x in good]
    cases["V12 non-loopback host (evil.example), without --map-origin"] = (other, [{"name": "placa"}], "not-equivalent", None, True)
    return cases


def plano_nao_verificado_cases(core, wrapper, tmp, cap, trace_ok, target):
    """Round 9 (7410fa4): `plan.parameters` only exempts with a VERIFIED plan.

    On the authentic detran-sim trace: v1, without `version`, and v2 without `hash`, each with
    `plan.parameters += "XML.delta"`, cannot exempt a frozen or invented delta (L13–L15, N1/N3 of the
    reviewer matrix): all six must DIVERGE. A faithful v1 (no swapped value) stays `equivalent`,
    only with the warning "plan of an earlier version (v1)". If any case only warns, it is a failure: it is recorded.
    """
    info = INFO["plano_nao_verificado"] = {}
    doc = json.loads(Path(trace_ok).read_text())
    sess = json.loads((Path(cap) / "session.json").read_text(encoding="utf-8"))
    cdelta = None
    for q in sess.get("requests", []):
        if q.get("id") != target:
            continue
        for a in q.get("attempts", []):
            ref = ((a.get("requestBody") or {}) or {}).get("attachment")
            if not ref:
                continue
            captured = (Path(cap) / "attachments" / ref).read_text(errors="replace")
            m = re.search(r"x(\d{2})([^&]+)&", captured)
            if m and "STAMP=" in captured:
                cdelta = m.group(2)
                break
    info["delta_capturado"] = cdelta
    if not check(bool(cdelta), f"unverified plan: did not find the delta in the captured body of {target}"):
        return

    def last_connector(d):
        for i in range(len(d.get("steps", [])) - 1, -1, -1):
            b = ((d["steps"][i].get("requestBody") or {}).get("text") or "")
            if re.search(r"x\d{2}[^&]+&", b) and "STAMP=" in b:
                return i
        return None

    def with_delta(d, value):
        d = json.loads(json.dumps(d))
        i = last_connector(d)
        if i is None:
            return None
        b = d["steps"][i]["requestBody"]["text"]
        m = re.search(r"x(\d{2})([^&]+)&", b)
        d["steps"][i]["requestBody"]["text"] = b[:m.start()] + f"x{len(value):02d}{value}&" + b[m.end():]
        return d

    def variant(d, kind, delta_param=True, delta_value=None):
        d = json.loads(json.dumps(d))
        plan = d.setdefault("plan", {})
        if kind == "v1":
            plan["version"] = 1
        elif kind == "no-version":
            plan.pop("version", None)
        elif kind == "v2-no-hash":
            plan.pop("hash", None)
        if delta_param:
            params = plan.setdefault("parameters", [])
            if "XML.delta" not in params:
                params.append("XML.delta")
        if delta_value is not None:
            d = with_delta(d, delta_value)
        return d

    def validate(doc2, label):
        p = tmp / f"nv-{label}.json"
        p.write_text(json.dumps(doc2, ensure_ascii=False))
        s = tmp / f"nv-ses-{label}"
        shutil.rmtree(s, ignore_errors=True)
        ip = sh([core, "import-trace", p, "--out", s])
        if not check(ip.returncode == 0,
                     f"unverified plan {label}: import-trace rc={ip.returncode}: {' '.join(ip.stderr.split())[:120]}"):
            return None
        v = sh([wrapper, "validate", cap, s, "--adapter", "natural-ajax"])
        try:
            return json.loads(v.stdout)
        except Exception:
            return None

    # v1 faithful: equivalent, with the earlier-version warning and no parameter warning
    v = validate(variant(doc, "v1", delta_param=False), "v1-faithful")
    if v is not None:
        avisos = [str(w) for w in v.get("warnings", [])]
        info["v1_fiel"] = {"verdict": v.get("verdict"), "avisos": avisos}
        check(v.get("verdict") == "equivalent",
              f"unverified plan v1 faithful: should be equivalent; got {v.get('verdict')!r} "
              f"({str(v.get('summary'))[:120]!r})")
        check(any("plan of an earlier version (v1)" in w for w in avisos),
              f"unverified plan v1 faithful: missing warning 'plan of an earlier version (v1)': {avisos[:5]}")
        check(not any(re.search(r"parameter", w, re.I) for w in avisos),
              f"unverified plan v1 faithful: unexpected parameter warnings: {[w for w in avisos if re.search(r'parameter', w, re.I)][:4]}")

    for kind, rotulo, motivo_plano in (("v1", "v1", r"plan of an earlier version"),
                                       ("no-version", "no version", r"plan of an earlier version"),
                                       ("v2-no-hash", "v2 no hash", r"plan without fingerprint")):
        base = validate(variant(doc, kind), f"{kind}-base")
        if base is not None:
            info[f"{rotulo} base"] = {"verdict": base.get("verdict"),
                                      "avisos": [str(w) for w in base.get("warnings", [])]}
            check(base.get("verdict") == "equivalent",
                  f"unverified plan {rotulo}: trace without a swapped value should be equivalent; "
                  f"got {base.get('verdict')!r} ({str(base.get('summary'))[:120]!r})")
            check(any(re.search(motivo_plano, w, re.I) for w in info[f"{rotulo} base"]["avisos"]),
                  f"unverified plan {rotulo}: missing the plan warning ({motivo_plano}): "
                  f"{info[f'{rotulo} base']['avisos'][:5]}")
        for nome, valor, motivo in (("frozen", cdelta, r"frozen"),
                                    ("invented", "ZZZZ" + "0" * 8, r"no (observed )?origin")):
            v = validate(variant(doc, kind, delta_value=valor), f"{kind}-{nome}")
            if v is None:
                continue
            salvo = info[f"{rotulo} {nome}"] = {"verdict": v.get("verdict"), "step": v.get("step"),
                                                "resumo": str(v.get("summary"))[:180],
                                                "avisos": [str(w) for w in v.get("warnings", [])]}
            check(v.get("verdict") == "diverges",
                  f"unverified plan {rotulo}, delta {nome}: should DIVERGE; got {v.get('verdict')!r} "
                  f"({salvo['resumo']!r}) — plan.parameters of an unverified plan cannot exempt")
            check(bool(re.search(motivo, json.dumps(v, ensure_ascii=False), re.I)),
                  f"unverified plan {rotulo}, delta {nome}: reason without /{motivo}/: {salvo['resumo']!r}")
            check(not any("plan does not match" in w for w in salvo["avisos"]),
                  f"unverified plan {rotulo}: should not warn 'plan does not match' (the hash is not even compared): "
                  f"{salvo['avisos'][:4]}")


def fuga_cases(core, wrapper, tmp, cap, trace_ok, target):
    """Round 9 (39410bf): `parameters` only exempts the (name, part) pair that the regenerated plan produces.

    On the AUTHENTIC detran-sim trace (same capture and target as validate), with the pair forged under a plan name:
    frozen/invented delta + {cpf → XML.delta} DIVERGES; frozen/invented STAMP + {cpf → STAMP} DIVERGES;
    {sessionid_cliente → sig} only warns "parameter does not match the plan"; the faithful trace has no warning
    beyond the origin. If any case only warns, it is a core failure: it is recorded, without a mask.
    """
    info = INFO["parameters_fuga"] = {}
    doc = json.loads(Path(trace_ok).read_text())
    sess = json.loads((Path(cap) / "session.json").read_text(encoding="utf-8"))
    attempt = next((a for q in sess.get("requests", []) if q.get("id") == target
                    for a in q.get("attempts", [])), None)
    body_ref = ((attempt or {}).get("requestBody") or {}).get("attachment")
    cdelta = cstamp = None
    if body_ref:
        captured = (Path(cap) / "attachments" / body_ref).read_text(errors="replace")
        m = re.search(r"x(\d{2})([^&]+)&", captured)
        cdelta = m.group(2) if m else None
        m = re.search(r"STAMP=(\d+)", captured)
        cstamp = m.group(1) if m else None
    info["valores_capturados"] = {"XML.delta": cdelta, "STAMP": cstamp}
    if not check(bool(cdelta) and bool(cstamp), f"leak: did not find delta/STAMP in the captured body of {target}"):
        return

    # mutated step: the last Connector POST with delta and STAMP (the flow's target, step 10)
    def last_step(d):
        for i in range(len(d.get("steps", [])) - 1, -1, -1):
            b = ((d["steps"][i].get("requestBody") or {}).get("text") or "")
            if re.search(r"x\d{2}[^&]+&", b) and "STAMP=" in b:
                return i
        return None

    def mutate(d, kind, value):
        d = json.loads(json.dumps(d))
        i = last_step(d)
        if i is None:
            return None
        b = d["steps"][i]["requestBody"]["text"]
        if kind == "delta":
            m = re.search(r"x(\d{2})([^&]+)&", b)
            b = b[:m.start()] + f"x{len(value):02d}{value}&" + b[m.end():]
        else:
            b = re.sub(r"STAMP=\d+", f"STAMP={value}", b)
        d["steps"][i]["requestBody"]["text"] = b
        return d

    def with_param(d, name, part):
        d = json.loads(json.dumps(d))
        d.setdefault("parameters", []).append({"name": name, "part": part})
        return d

    def validate(doc2, label):
        p = tmp / f"leak-{label}.json"
        p.write_text(json.dumps(doc2, ensure_ascii=False))
        s = tmp / f"leak-ses-{label}"
        shutil.rmtree(s, ignore_errors=True)
        ip = sh([core, "import-trace", p, "--out", s])
        if not check(ip.returncode == 0,
                     f"leak {label}: import-trace rc={ip.returncode}: {' '.join(ip.stderr.split())[:120]}"):
            return None
        v = sh([wrapper, "validate", cap, s, "--adapter", "natural-ajax"])
        try:
            return json.loads(v.stdout)
        except Exception:
            return None

    # (e) faithful trace: no warning beyond the mapped origin
    base = validate(doc, "faithful")
    if base is not None:
        extra = [str(w) for w in base.get("warnings", []) if "different application origins" not in str(w)]
        info["fiel"] = {"verdict": base.get("verdict"), "avisos_alem_da_origem": extra}
        check(base.get("verdict") == "equivalent" and not extra,
              f"leak: faithful trace should be equivalent without warnings beyond the origin; got "
              f"{base.get('verdict')!r} and {extra[:4]}")

    casos = [
        ("frozen delta", "delta", cdelta, "cpf", "XML.delta", r"frozen"),
        ("invented delta", "delta", "ZZZZ" + "0" * 8, "cpf", "XML.delta", r"no (observed )?origin"),
        ("frozen STAMP", "stamp", cstamp, "cpf", "STAMP", r"frozen"),
        ("invented STAMP", "stamp", "9999", "cpf", "STAMP", r"no (observed )?origin"),
    ]
    for nome, kind, value, pname, part, motivo in casos:
        d = mutate(doc, kind, value)
        if d is None:
            check(False, f"leak {nome}: did not find a step with delta/STAMP in the trace")
            continue
        v = validate(with_param(d, pname, part), nome.replace(" ", "-"))
        if v is None:
            continue
        salvo = info[nome] = {"verdict": v.get("verdict"), "step": v.get("step"),
                              "resumo": str(v.get("summary"))[:180],
                              "avisos": [str(w) for w in v.get("warnings", [])]}
        check(v.get("verdict") == "diverges",
              f"leak {nome} + {pname} → {part}: should DIVERGE; got {v.get('verdict')!r} "
              f"({salvo['resumo']!r}) — parameters cannot exempt this pair")
        check(bool(re.search(motivo, json.dumps(v, ensure_ascii=False), re.I)),
              f"leak {nome}: reason without /{motivo}/: {salvo['resumo']!r}")
        check(any(f"parameter does not match the plan: {pname} → {part}" in w for w in salvo["avisos"]),
              f"leak {nome}: missing the warning 'parameter does not match the plan: {pname} → {part}': "
              f"{salvo['avisos'][:5]}")

    # warning for a pair under a plan name that it does not produce: does not exempt and does not stay silent
    v = validate(with_param(doc, "sessionid_cliente", "sig"), "sessionid-sig")
    if v is not None:
        avisos = [str(w) for w in v.get("warnings", [])]
        info["sessionid_cliente_sig"] = {"verdict": v.get("verdict"), "avisos": avisos}
        check(any("parameter does not match the plan: sessionid_cliente → sig" in w for w in avisos),
              f"leak sessionid_cliente → sig: missing the warning 'parameter does not match the plan': {avisos[:5]}")
        check(v.get("verdict") == "equivalent",
              f"leak sessionid_cliente → sig: without a swapped value it should stay equivalent; got {v.get('verdict')!r}")


def plan_cases(core, wrapper, tmp, cap, target, trace_path, val):
    """Round 9, wave B: versioned plan in the trace (`plan.version` 2, validate::PLAN_VERSION).

    Faithful v2 -> equivalent and ZERO parameter/plan warnings; without `version` -> only the "plan of an earlier
    version" warning, without diverging; `version` 2 with the hash of ANOTHER target of the SAME capture -> DIVERGES
    ("plan differs from the one generated"). If the last case only warns, it is a core failure: it is recorded, without a mask.
    """
    info = INFO["plano"] = {}
    doc = json.loads(trace_path.read_text())
    plan = doc.get("plan") or {}
    info["versao_no_trace"] = plan.get("version")
    check(plan.get("version") == 2,
          f"plan: the current script's trace should declare plan.version 2; it declares {plan.get('version')!r}")
    warns = [str(w) for w in (val or {}).get("warnings", [])]
    info["avisos_fiel"] = warns
    espurios = [w for w in warns if re.search(r"invalid parameter|plan", w, re.I)]
    check(not espurios, f"faithful plan (v2): parameter/plan warnings should not exist: {espurios[:6]}")

    def validate(doc2, label):
        p = tmp / f"plan-{label}.json"
        p.write_text(json.dumps(doc2, ensure_ascii=False))
        s = tmp / f"plan-ses-{label}"
        shutil.rmtree(s, ignore_errors=True)
        ip = sh([core, "import-trace", p, "--out", s])
        if not check(ip.returncode == 0,
                     f"plan {label}: import-trace rc={ip.returncode}: {' '.join(ip.stderr.split())[:120]}"):
            return None
        v = sh([wrapper, "validate", cap, s, "--adapter", "natural-ajax"])
        try:
            return json.loads(v.stdout)
        except Exception:
            return None

    # (b) missing version: warns and does not diverge
    old = json.loads(json.dumps(doc))
    old.get("plan", {}).pop("version", None)
    v = validate(old, "no-version")
    if v is not None:
        info["sem_versao"] = {"verdict": v.get("verdict"), "passo": v.get("step"),
                              "avisos": [str(w) for w in v.get("warnings", [])]}
        check(v.get("verdict") == "equivalent",
              f"plan without version: should be equivalent (only warns); got {v.get('verdict')!r} "
              f"({str(v.get('summary'))[:120]!r})")
        check(any("plan of an earlier version" in w for w in info["sem_versao"]["avisos"]),
              f"plan without version: missing the warning 'plan of an earlier version': {info['sem_versao']['avisos'][:6]}")

    # (c) version 2 with the hash of another target of the same capture: must diverge
    outro = next((r for r in ("har-0030", "har-0026", "har-0022", "har-0017", "har-0024") if r != target), None)
    outros = dict(os.environ)  # export-priming does not open the network; it only uses the capture and the target
    hash_outro = None
    if outro:
        script = tmp / "plan-other.py"
        g = sh([wrapper, "export-priming", cap, outro, "--out", script, "--adapter", "natural-ajax"], env=outros)
        if g.returncode == 0 and script.exists():
            m = re.search(r"^PLAN_HASH\s*=\s*['\"]([0-9a-fA-F]+)['\"]", script.read_text(errors="replace"), re.M)
            hash_outro = m.group(1) if m else None
    info["alvo_do_outro_hash"] = outro
    info["hash_do_outro_alvo"] = hash_outro
    check(bool(hash_outro), f"plan other target: did not get the PLAN_HASH of another target of the capture ({outro})")
    if hash_outro:
        check(hash_outro != plan.get("hash"),
              "plan other target: the hash of another target equals the trace target's hash (proves nothing)")
        cop = json.loads(json.dumps(doc))
        cop.setdefault("plan", {})["hash"] = hash_outro
        v = validate(cop, "hash-from-other")
        if v is not None:
            info["hash_de_outro"] = {"verdict": v.get("verdict"), "passo": v.get("step"),
                                     "resumo": str(v.get("summary"))[:160], "motivo": str(v.get("reason"))[:160],
                                     "avisos": [str(w) for w in v.get("warnings", [])]}
            check(v.get("verdict") == "diverges",
                  f"plan with the hash of another target: should DIVERGE; got {v.get('verdict')!r} "
                  f"({info['hash_de_outro']['resumo']!r}) — a warning alone is not enough")
            check(bool(re.search(r"plan differs from the one generated", json.dumps(v, ensure_ascii=False), re.I)),
                  f"plan with the hash of another target: reason without 'plan differs from the one generated…': "
                  f"{info['hash_de_outro']['resumo']!r} / {info['hash_de_outro']['motivo']!r}")


def reviewer_cases(core, wrapper, tmp, info):
    """Reviewer cases: everything that is NOT the faithful execution must DIVERGE (or error); control V1 must be equivalent."""
    cap = rv_capture(tmp, core)
    info["revisor"] = {}
    for name, (steps, params, want, reason_rx, complete) in rv_cases().items():
        doc = {"schema": "scrapelens.trace/1", "generator": "scrapelens-priming 1.0", "steps": steps, "parameters": params,
               "target": "har-0004", "complete": complete}
        tp = tmp / "rv-trace.json"; tp.write_text(json.dumps(doc))
        ts = tmp / "rv-ses"; shutil.rmtree(ts, ignore_errors=True)
        ip = sh([core, "import-trace", tp, "--out", ts])
        if ip.returncode != 0:   # refusing at import already counts as the expected "error", except for the control
            info["revisor"][name] = {"import": "error", "rc": ip.returncode}
            check(want != "equivalent", f"reviewer {name}: the control was refused at import-trace: {' '.join(ip.stderr.split())[:100]}")
            continue
        v = sh([wrapper, "validate", cap, ts, "--adapter", "natural-ajax"])
        try:
            d = json.loads(v.stdout)
        except Exception:
            d = None
        verdict = d.get("verdict") if d else f"error(rc={v.returncode})"
        info["revisor"][name] = {"verdict": verdict, "step": d.get("step") if d else None, "resumo": str(d.get("summary", ""))[:100] if d else v.stderr.strip()[:80]}
        if want == "equivalent":
            check(verdict == "equivalent", f"reviewer {name}: control should be equivalent; got {verdict} ({info['revisor'][name]['resumo']})")
        else:
            check(verdict != "equivalent", f"reviewer {name}: should DIVERGE (or error) but validate said {verdict!r}: {info['revisor'][name]['resumo']}")
            if reason_rx:
                check(re.search(reason_rx, v.stdout + v.stderr, re.I), f"reviewer {name}: reason without /{reason_rx}/: {info['revisor'][name]['resumo']!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8793)
    ap.add_argument("--wrapper", default=str(ROOT / "adapters/natural-ajax/target/release/natural-core"))
    ap.add_argument("hars", nargs="*", default=[h for h in REAL if Path(h).exists()],
                    help="real HARs (default: SL_REAL_HARS); skipped when none is given")
    a = ap.parse_args()
    core, py, wrapper = cb.core_bin(a.core), a.python or ps.default_python(), a.wrapper
    if not Path(wrapper).exists():
        sys.exit(f"wrapper not found: {wrapper}")
    os.environ["SCRAPELENS_CORE_BIN"] = core
    base = f"http://127.0.0.1:{a.port}"
    tmp = Path(tempfile.mkdtemp(prefix="sl-timeline-")); os.chmod(tmp, 0o700)
    sim = subprocess.Popen([sys.executable, str(ps.SIM), "--port", str(a.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                ps.http(base, "/healthz"); break
            except Exception:
                time.sleep(0.1)

        # ---- (1) timeline
        INFO["timeline"] = {}
        for name, n_round in (("real-shape-1round.har", 1), ("real-shape-2rounds.har", 2)):
            s = tmp / ("tl-" + name); sh([core, "import-har", FIX / name, "--out", s, "--label", "synthetic-fixture"])
            agg = timeline_agg(wrapper, s, name)
            INFO["timeline"][name] = agg
            if agg:
                check(agg["sequencia_eventos"] == FIXTURE_ROUND * n_round,
                      f"{name}: events {agg['sequencia_eventos']} != manual flow {FIXTURE_ROUND * n_round}")
        INFO["timeline_real"] = {}
        if not a.hars:
            INFO["timeline_real"]["skipped"] = "SL_REAL_HARS not set: real-HAR aggregate not run"
            print("SKIP real-HAR aggregate: set SL_REAL_HARS to run it")
        for i, h in enumerate(a.hars, 1):
            s = tmp / f"tl-real{i}"; sh([core, "import-har", h, "--out", s])
            agg = timeline_agg(wrapper, s, f"real HAR #{i}")
            if agg:
                INFO["timeline_real"][f"H{i}"] = {k: agg[k] for k in ("entradas", "posts_connector", "posts_sem_rotulo_event_page", "grupos_protecao", "protecao_avulsa", "protecao_recolhida")}
                INFO["timeline_real"][f"H{i}"]["ordem_rotulos"] = [f"{e}@{p}" for e, p in zip(agg["sequencia_eventos"], agg["paginas"])]
                check(subsequence(agg["sequencia_eventos"], EVENTS), f"real HAR #{i}: events outside the manual flow order")

        # ---- reviewer cases (Round 9): validate must not give 'equivalent' to an unfaithful execution
        reviewer_cases(core, wrapper, tmp, INFO)

        # ---- (2)/(3)/(4) script execution
        cap = tmp / "cap"; sh([core, "import-har", ps.HAR, "--out", cap, "--label", "synthetic-fixture"])
        man = json.loads((FIX / "manifest.json").read_text())
        target = man["expectations"]["aceite_1_origins_chain"]["A"]["target"]
        script = tmp / "priming.py"
        g = sh([wrapper, "export-priming", cap, target, "--out", script, "--adapter", "natural-ajax"])
        check(g.returncode == 0, f"export-priming: {g.stderr.strip()[:140]}")
        INFO["cenarios"] = {}
        for mode in ("ok", "error", "nocontrols", "403"):
            ps.http(base, "/__sim/reset"); ps.http(base, f"/__sim/mode?m={mode}")
            client = ps.new_client_part()
            trace = tmp / f"trace-{mode}.json"
            p = sh([py, "-I", script, "--confirm", "--base-url", base, "--placa", PLACA, "--cpf", ps.CPF,
                    "--sessionid-cliente", client, "--trace", trace], cwd=tmp)
            log = ps.http(base, "/__sim/log")["log"]
            first_bad = next((i for i, x in enumerate(log, 1) if x["path"].endswith("/servlet/Connector") and
                              (x["status"] != 200 or x["note"].startswith(("mode", "nocontrols", "app-error")))), None)  # detran-sim notes (detran_sim.py:204, 214)
            sc = INFO["cenarios"][mode] = {"script_rc": p.returncode, "pedidos_no_sim": len(log), "primeiro_ruim": first_bad}
            if not check(trace.exists(), f"{mode}: the script did not create the trace (--trace)"):
                continue
            mode_bits = stat.S_IMODE(trace.stat().st_mode)
            sc["trace_modo"] = oct(mode_bits)
            check(mode_bits == 0o600, f"{mode}: trace should be 0600, is {oct(mode_bits)}")
            raw = trace.read_text()
            try:
                t, steps = trace_steps(trace)
            except Exception:
                check(False, f"{mode}: trace is not JSON"); continue
            check(t.get("schema") == "scrapelens.trace/1", f"{mode}: schema {t.get('schema')!r} != scrapelens.trace/1")
            check("contains data from your session" in raw or "contains data from your session" in p.stdout + p.stderr,
                  f"{mode}: no warning 'contains data from your session; do not share without sanitizing'")
            sc["trace_passos"] = len(steps)
            ts = tmp / f"ts-{mode}"
            ip = sh([core, "import-trace", trace, "--out", ts])
            if not check(ip.returncode == 0, f"{mode}: import-trace: rc={ip.returncode}: {' '.join(ip.stderr.split())[:120]}"):
                continue
            assess = jload(sh([core, "assess", ts]), f"{mode}: assess of the trace")
            val = jload(sh([wrapper, "validate", cap, ts, "--adapter", "natural-ajax"]), f"{mode}: validate")
            sc["validate_doc"] = val if mode == "ok" else None
            outs = (assess or {}).get("outcomes", [])
            conn = [o for o in outs if o.get("url", "").endswith("/servlet/Connector")]
            sc["assess_connector"] = [o.get("verdictKind") for o in conn]
            vsteps = (val or {}).get("steps", []) if isinstance(val, dict) else []
            sc["validate"] = {"verdict": (val or {}).get("verdict"), "step": (val or {}).get("step"),
                              "summary": str((val or {}).get("summary", ""))[:140], "passos": len(vsteps)}
            if val is not None:
                check(val.get("schema") == "scrapelens.validate/1", f"{mode}: validate schema {val.get('schema')!r}")
            if mode == "ok":
                check(p.returncode == 0, f"ok: script rc={p.returncode}")
                check(len(steps) == len(log), f"ok: trace with {len(steps)} steps, sim saw {len(log)} requests")
                check(conn and all(o.get("verdictKind") == "app-ok" for o in conn), f"ok: assess of the trace is not app-ok on every POST: {sc['assess_connector']}")
                check(not any(o.get("verdictKind") in ("app-error", "blocked") for o in outs), "ok: some trace step with app-error/blocked")
                if val:
                    g = lambda d, *k: next((d[x] for x in k if x in d), None)  # noqa: E731
                    unpaired = [x for x in vsteps if not g(x, "captureRequestId", "capture_request_id")]
                    unexpected = [(g(x, "step"), n.get("field")) for x in vsteps for n in x.get("unexpected", [])]
                    expected = sorted({str(n.get("field")) for x in vsteps for n in x.get("expected", [])})
                    missing = g(val, "missingInTrace", "missing_in_trace") or []
                    sc["validate"].update({"nao_pareados": len(unpaired), "inesperados": len(unexpected), "esperados_campos": expected,
                                           "missingInTrace": len(missing), "mappedOrigin": bool(g(val, "mappedOrigin", "mapped_origin"))})
                    check(val.get("verdict") == "equivalent", f"ok: verdict {val.get('verdict')!r}, expected equivalent ({sc['validate']['summary']})")
                    check("equivalent" in str(val.get("summary", "")), "ok: summary without 'execution equivalent to capture'")
                    check(len(vsteps) == len(steps) and not unpaired, f"ok: steps not paired 1:1 ({len(vsteps)} steps validated, {len(steps)} in the trace, {len(unpaired)} without a pair)")
                    check(not unexpected, f"ok: unexpected differences (step, field): {unexpected[:6]}")
                    extra = [n for n in expected if not DYNAMIC_OK.search(n)]
                    check(not extra, f"ok: expected differences outside STAMP/delta/SESSIONID: {extra[:8]}")
                    check(not missing, f"ok: {len(missing)} request(s) from the capture missing in the trace")
                    check(all(str(g(x, "verdictTrace", "verdict_trace")) in ("app-ok", "not-assessed") for x in vsteps),
                          "ok: some step with a trace verdict different from app-ok/not-assessed")
            else:
                want = {"error": {"app-error"}, "403": {"blocked"}, "nocontrols": {"indeterminate", "undetermined", "blocked", "not-assessed", "app-error"}}[mode]
                check(p.returncode != 0, f"{mode}: the script should fail")
                check(first_bad is not None and len(steps) == first_bad,
                      f"{mode}: the trace should end at the bad step #{first_bad}; it has {len(steps)} steps")
                last = outs[-1].get("verdictKind") if outs else None
                sc["veredito_ultimo_passo"] = last
                check(last in want and last != "app-ok", f"{mode}: verdict of the bad step {last!r}, expected one of {sorted(want)}")
                if val:
                    m = re.search(r"diverges at step (\d+)", str(val.get("summary", "")))
                    check(val.get("verdict") == "diverges", f"{mode}: verdict {val.get('verdict')!r}, expected diverges")
                    check(val.get("step") == first_bad and m is not None and int(m.group(1)) == first_bad,
                          f"{mode}: validate should point to step {first_bad}; it pointed to step={val.get('step')} summary={sc['validate']['summary']!r}")
                    hint = {"error": r"app-error|ERRORMESSAGE", "403": r"403|blocked"}.get(mode)
                    if hint:
                        check(re.search(hint, str(val.get("summary", "")) + str(val.get("reason", "")), re.I),
                              f"{mode}: reason without {hint!r}: {sc['validate']['summary']!r}")
            # ---- (4) sanitize (ok scenario)
            if mode == "ok":
                san = tmp / "san"
                sp = sh([core, "sanitize", ts, san])
                check(sp.returncode == 0, f"sanitize of the trace: rc={sp.returncode}")
                body = "".join(f.read_text(errors="replace") for f in san.rglob("*") if f.is_file()) if san.exists() else ""
                sid = set(re.findall(r"SESSIONID=([A-Za-z0-9_]+)", raw))
                cookies = set()
                for h_ in re.findall(r'"(?:cookie|set-cookie)"\s*:\s*"([^"]+)"', raw, re.I):
                    cookies |= {c.split("=", 1)[1].strip() for c in h_.split(";") if "=" in c and len(c.split("=", 1)[1].strip()) >= 6}
                leaks = {"SESSIONID": [v for v in sid if v and v in body], "placa": [PLACA] if PLACA in body else [],
                         "cookies": [v for v in cookies if v in body], "parte_cliente": [client[1:]] if client[1:] in body else []}
                sc["sanitize_vazamentos"] = {k: len(v) for k, v in leaks.items()}
                sc["sanitize_valores_testados"] = {"SESSIONID": len(sid), "cookies": len(cookies)}
                check(bool(body), "sanitize: empty output")
                check(len(sid) > 0, "sanitize: no SESSIONID in the trace to test the removal")
                check(not any(leaks.values()), f"sanitize: sensitive values still present: { {k: len(v) for k, v in leaks.items() if v} }")
        # ---- (5) versioned plan in the trace (Round 9, wave B)
        trace_ok = tmp / "trace-ok.json"
        if check(trace_ok.exists(), "plan: the trace of the ok scenario does not exist"):
            plan_cases(core, wrapper, tmp, cap, target, trace_ok, INFO["cenarios"].get("ok", {}).get("validate_doc"))
        # ---- (6) `parameters` does not exempt a pair that the plan does not produce (39410bf)
        if trace_ok.exists():
            fuga_cases(core, wrapper, tmp, cap, trace_ok, target)
        # ---- (7) `plan.parameters` only exempts with a verified plan (7410fa4)
        if trace_ok.exists():
            plano_nao_verificado_cases(core, wrapper, tmp, cap, trace_ok, target)
    finally:
        sim.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    INFO["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(INFO, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: timeline + execution validation (trace, import-trace, compare, sanitize)"); return 0


if __name__ == "__main__":
    sys.exit(main())
