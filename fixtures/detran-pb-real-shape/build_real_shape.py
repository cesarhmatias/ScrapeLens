#!/usr/bin/env python3
"""Fixtures with the REAL SHAPE of the DETRAN-PB case (docs/10-fidelity-case-real.md). 100% fictitious values.

The shape was taken from the STRUCTURE of the real HARs (no value or byte copied):
  * Connector responses = ~10 KB HTML with a fictitious script before, then
    <textarea name="XML">, <textarea name="ERRORMESSAGE"> and <input type="hidden" name="STAMP" value>;
    the payload inside the textarea uses HTML entities (&amp; &lt; &gt; &quot; &#x27;);
  * DevTools HAR: creator WebInspector, WITHOUT Cookie/Set-Cookie/cookies[];
  * protection noise (/TSPD/...) between the steps and static resources (jquery-ui, cis*) that
    CONTAIN protocol constants (L3 noise);
  * fictitious plate and CPF inside the XML (L5) and a value out of format (short v_renavam);
  * GETs without postData (L7);
  * captures: A = 1 round; B = 2 complete rounds (like the real H2).

Outputs: real-shape-1round.har, real-shape-2rounds.har, manifest.json.
Run: python3 fixtures/detran-pb-real-shape/build_real_shape.py
"""
from __future__ import annotations

import html
import json
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detran-pb"))
import build_fixtures as bf  # noqa: E402  (jslen, serialize, response_stream, form_body)

BASE, APP, HOST = bf.BASE, bf.APP, bf.HOST
MODELS = {"logon": "SA90001_CSAN00000", "sim": "SA90002_CSAN00000", "ves": "SA90003_CSAN00000"}
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
START_MS = 1_793_132_400_000  # 2026-10-27T23:00:00Z, fixed
STEP_MS = 250
# Shape of the DevTools `_initiator` (checked only by structure in the real HARs):
#   other  -> {type}                          (navigation/entry, form POST)
#   parser -> {type, url, lineNumber}         (resource/frame initiated by the HTML parser of the page `url`)
#   script -> {type, stack:{callFrames:[{functionName,scriptId,url,lineNumber,columnNumber}]}}
INIT_OTHER = {"type": "other"}


def init_parser(url: str, line: int = 12) -> dict:
    return {"type": "parser", "url": url, "lineNumber": line}


def init_script(url: str) -> dict:
    return {"type": "script", "stack": {"callFrames": [{"functionName": "_load", "scriptId": "88", "url": url,
                                                         "lineNumber": 41, "columnNumber": 7}]}}


def csc_html(model: str) -> str:
    """Auxiliary cscform frame: client form with the initial STAMP (INIT)."""
    return (f'<!doctype html>\n<html><body>\n<form name="cscform" method="post" data-model="{model}">\n'
            '<input type="hidden" name="STAMP" id="STAMP" value="INIT">\n</form>\n</body></html>\n')


def jlibs_html(model: str) -> str:
    return f"<!doctype html>\n<html><body><script>/* {model}_JLIBS: frame de bibliotecas fictício */</script></body></html>\n"


def fake_guard_script(seed: int, size: int = 9700) -> str:
    """Fictitious script in place of F5: deterministic filler, without STAMP/XML/ERRORMESSAGE."""
    x, out = seed, ["<SYNTHETIC_GUARD_DO_NOT_TOUCH>\n<script type=\"text/javascript\">\n(function(){"]
    while sum(len(s) for s in out) < size:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        n = f"_g{x % 99991:05d}"
        out.append(f"var {n}=function(a,b){{return (a^{x % 255})+b*{x % 7}}};{n}({x % 100},{x % 13});")
        if x % 5 == 0:
            out.append("\n")
    out.append("})();\n</script>\n")
    return "".join(out)


def connector_html(seed: int, xml: str, stamp: str) -> str:
    return (fake_guard_script(seed) + '<html>\n<body>\n<form name="f" method="post">\n'
            f'<textarea id="XML" name="XML">{html.escape(xml, quote=True)}</textarea>\n'
            '<textarea id="ERRORMESSAGE" name="ERRORMESSAGE"></textarea>\n'
            f'<input type="hidden" name="STAMP" id="STAMP" value="{stamp}">\n'
            "</form>\n</body>\n</html>\n")


def page_html(title: str, model: str, sid: str | None, pid: str | None, init_param: str = "") -> str:
    """Only the entry page (easynat-app) defines m_currentSessionId/m_currentProcessId.

    In the real HARs (checked only by structure) NatLogon/SIM1000X/VES0009X do NOT contain the SESSIONID nor the
    processId, and no request between the easynat-app response and the NatLogon one carries the value: the SESSIONID
    has a single producer. The other pages only load the model (a protocol constant)."""
    ids = ""
    if sid is not None:
        ids = f'var m_currentSessionId = "{sid}";\nvar m_currentProcessId = "{pid}";\nvar pageInitParam = "{init_param}";\n'
        call = f'C.initWithModelIdAndSessionIdAndProcessId("{model}", m_currentSessionId, m_currentProcessId);\n'
    else:
        call = f'C.initWithModelId("{model}");\n'
    return f'<!doctype html>\n<html><head><meta charset="utf-8"><title>{title}</title></head>\n<body>\n<script>\n{ids}{call}</script>\n</body></html>\n'


def static_js(name: str) -> str:
    return (f"/* {name}: biblioteca fictícia (ruído L3) */\n"
            'var CIS_CONST = {"nextPage":"/UIC-SERVICOS/VES0009X.html","focusProject":"cISAddons.focusProject",'
            f'"modelLogon":"{MODELS["logon"]}","modelSim":"{MODELS["sim"]}","modelVes":"{MODELS["ves"]}",'
            '"interceptor":"interceptor_params.items","situacao":"situacao_rows.items","dummy":"dummy"};\n'
            + "function _lib(){return 1}\n" * 40)


class Har:
    def __init__(self, creator="WebInspector"):
        self.entries, self.t, self.ids = [], 0, {}
        self.creator = creator

    def add(self, key, method, url, status, mime, body, resource_type, referer, post=None, protection=False, initiator=None):
        self.t += STEP_MS
        n = len(self.entries) + 1
        self.ids[key] = f"har-{n:04d}"
        headers = [("accept", "*/*"), ("accept-language", "pt-BR,pt;q=0.9"), ("user-agent", UA)]
        if referer:
            headers.append(("referer", referer))
        if post is not None:
            text = bf.form_body(post)
            headers += [("content-type", "application/x-www-form-urlencoded; charset=UTF-8"),
                        ("origin", APP), ("x-requested-with", "XMLHttpRequest"),
                        ("content-length", str(bf.jslen(text)))]
        req = {"method": method, "url": url, "httpVersion": "http/1.1",
               "headers": [{"name": a, "value": b} for a, b in headers],
               "queryString": [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)],
               "cookies": [], "headersSize": -1, "bodySize": len(text.encode()) if post is not None else 0}
        if post is not None:
            req["postData"] = {"mimeType": "application/x-www-form-urlencoded; charset=UTF-8", "text": text,
                               "params": [{"name": k, "value": v} for k, v in post]}
        size = len(body.encode())
        resp = {"status": status, "statusText": "OK" if status == 200 else "", "httpVersion": "http/1.1",
                "headers": [{"name": "content-type", "value": mime}, {"name": "cache-control", "value": "no-cache"}],
                "cookies": [], "content": {"size": size, "mimeType": mime, "text": body},
                "redirectURL": "", "headersSize": -1, "bodySize": size}
        secs, ms = divmod(self.t, 1000)
        self.entries.append({
            "startedDateTime": time_iso(START_MS + self.t), "time": 100.0, "request": req, "response": resp, "cache": {},
            "timings": {"blocked": 1.0, "dns": -1, "connect": -1, "ssl": -1, "send": 0.4, "wait": 80.0, "receive": 10.0},
            "serverIPAddress": "198.51.100.10", "connection": "412", "_resourceType": resource_type,
            "_initiator": initiator or INIT_OTHER})

    def doc(self):
        return {"log": {"version": "1.2", "creator": {"name": self.creator, "version": "537.36"},
                        "pages": [], "entries": self.entries}}


def time_iso(ms: int) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def tspd(h: Har, tag: str, referer: str, kind: int = 9):
    h.add(f"tspd:{tag}", "GET", f"{BASE}/TSPD/0000SYNTHGUARD?type={kind}", 200, "text/javascript",
          "/* synthetic guard noise */\n", "script", referer, protection=True, initiator=init_script(referer))


def frame(h: Har, k: str, name: str, page_url: str, base: str, title: str, model: str, blank: bool = False):
    """Auxiliary frames (initiated by the parser) of the page `page_url`: *_JLIBS.html and cscform.html
    (with <input hidden STAMP value=INIT>); optionally aboutBlank.html. Referer = the page."""
    jl, csc = f"{base}/{title}_JLIBS.html", f"{base}/cscform.html?page={title}"
    h.add(f"{k}:jlibs_{name}", "GET", jl, 200, "text/html;charset=UTF-8", jlibs_html(title), "document", page_url,
          initiator=init_parser(page_url, 21))
    h.add(f"{k}:csc_{name}", "GET", csc, 200, "text/html;charset=UTF-8", csc_html(model), "document", page_url,
          initiator=init_parser(page_url, 22))
    bl = None
    if blank:
        bl = f"{base}/aboutBlank.html"
        h.add(f"{k}:blank_{name}", "GET", bl, 200, "text/html;charset=UTF-8", "<!doctype html><html><body></body></html>\n",
              "document", page_url, initiator=init_parser(page_url, 23))
    return jl, csc, bl


def round_flow(h: Har, r: dict, seed: int) -> dict:
    """One complete flow. Returns logical IDs per role (with the round prefix)."""
    k = r["tag"]
    sid, pid, sb, dp = r["sid"], r["pid"], r["stamp_base"], r["delta_prefix"]
    dseq = [0]

    def nd():
        dseq[0] += 1
        return f"{dp}{dseq[0]:04d}"

    state = {"delta": "inittini", "stamp": None}
    logon_url, sim_url, ves_url = f"{APP}/cisnatural/NatLogon.html", f"{APP}/UIC-SERVICOS/SIM1000X.html", f"{APP}/UIC-SERVICOS/VES0009X.html"
    con = f"{APP}/servlet/Connector"
    stamp_n = [sb]

    def post(key, referer, page, model, event, props, resp_fields, init=False):
        body = bf.serialize(sid, pid, model, page, event, props, state["delta"], init=init)
        stamp = "INIT" if (init or state["stamp"] is None) else state["stamp"]
        fields = [("SESSIONID", sid), ("PAGEINITPARAM", ""), ("XML", body)]
        if not init:
            fields.append(("ERRORMESSAGE", ""))
        fields.append(("STAMP", stamp))
        stamp_n[0] += 1
        new_stamp, new_delta = str(stamp_n[0]), nd()
        xml = bf.response_stream(resp_fields, new_delta)
        h.add(f"{k}:{key}", "POST", con, 200, "text/html;charset=UTF-8", connector_html(seed + stamp_n[0], xml, new_stamp),
              "xhr", referer, post=fields)
        state["delta"], state["stamp"] = new_delta, new_stamp
        return new_stamp, new_delta

    h.add(f"{k}:easynat", "GET", f"{APP}/servlet/easynat-app?op=S37", 200, "text/html;charset=UTF-8",
          page_html("DETRAN-PB", MODELS["logon"], r["head"], pid, "op=S37&xciParameters.natsession=acesso"), "document", None, initiator=INIT_OTHER)
    tspd(h, f"{k}1", f"{APP}/servlet/easynat-app?op=S37", 18)
    h.add(f"{k}:static_jquery", "GET", f"{APP}/cisnatural/jquery-ui.min.js", 200, "application/javascript", static_js("jquery-ui"), "script", f"{APP}/servlet/easynat-app?op=S37", initiator=init_parser(f"{APP}/servlet/easynat-app?op=S37", 7))
    h.add(f"{k}:static_cis", "GET", f"{APP}/ciscentral/CIS_V1_SYNTH.js", 200, "application/javascript", static_js("cis"), "script", f"{APP}/servlet/easynat-app?op=S37", initiator=init_parser(f"{APP}/servlet/easynat-app?op=S37", 8))
    h.add(f"{k}:page_logon", "GET", logon_url, 200, "text/html;charset=UTF-8", page_html("NatLogon", MODELS["logon"], None, None), "document", f"{APP}/servlet/easynat-app?op=S37", initiator=init_script(f"{APP}/cisnatural/jquery-ui.min.js"))
    tspd(h, f"{k}2", logon_url)
    jl_logon, csc_logon, blank = frame(h, k, "logon", logon_url, f"{APP}/cisnatural", "NatLogon", MODELS["logon"], blank=True)
    post("init_logon", csc_logon, "/cisnatural/NatLogon.html", MODELS["logon"], "",
         {"pageInitParam": "op=S37", "pagePixelHeight": "0", "pagePixelWidth": "0", "timeZoneOffset": "-180"},
         [("nextPage", "/UIC-SERVICOS/SIM1000X.html")], init=True)
    tspd(h, f"{k}3", logon_url, 17)
    h.add(f"{k}:page_sim", "GET", sim_url, 200, "text/html;charset=UTF-8", page_html("SIM1000X", MODELS["sim"], None, None), "document", logon_url, initiator=init_script(f"{APP}/ciscentral/CIS_V1_SYNTH.js"))
    jl_sim, csc_sim, _ = frame(h, k, "sim", sim_url, f"{APP}/UIC-SERVICOS", "SIM1000X", MODELS["sim"])
    post("init_sim", csc_sim, "/UIC-SERVICOS/SIM1000X.html", MODELS["sim"], "",
         {"pageInitParam": "", "pagePixelHeight": "0", "pagePixelWidth": "0", "timeZoneOffset": "-180"},
         [("nextPage", "/UIC-SERVICOS/SIM1000X.html")], init=True)
    tspd(h, f"{k}4", sim_url, 17)
    props = {"interceptor_is_active": "false"}
    props.update({f"interceptor_params.items[{i}].interceptor_value": "S37" if i == 1 else "" for i in range(6)})
    post("on_interceptor", jl_sim, "/UIC-SERVICOS/SIM1000X.html", MODELS["sim"], "on_interceptor", props,
         [("nextPage", "/UIC-SERVICOS/VES0009X.html")])
    tspd(h, f"{k}5", sim_url)
    h.add(f"{k}:page_ves", "GET", ves_url, 200, "text/html;charset=UTF-8", page_html("VES0009X", MODELS["ves"], None, None), "document", sim_url, initiator=init_script(f"{APP}/ciscentral/CIS_V1_SYNTH.js"))
    jl_ves, csc_ves, _ = frame(h, k, "ves", ves_url, f"{APP}/UIC-SERVICOS", "VES0009X", MODELS["ves"])
    post("init_ves", csc_ves, "/UIC-SERVICOS/VES0009X.html", MODELS["ves"], "",
         {"pageInitParam": "", "pagePixelHeight": "0", "pagePixelWidth": "0", "timeZoneOffset": "-180"},
         [("nextPage", "/UIC-SERVICOS/VES0009X.html")], init=True)
    tspd(h, f"{k}6", ves_url, 17)
    post("cmd_filtro", jl_ves, "/UIC-SERVICOS/VES0009X.html", MODELS["ves"], "cmd_filtro",
         {"v_filtro_sel": "2.0", "#f12_selected": "2.0"}, [("v_filtro_sel", "2.0")])
    tspd(h, f"{k}7", ves_url, 17)
    post("consultar1", jl_ves, "/UIC-SERVICOS/VES0009X.html", MODELS["ves"], "cmd_consultar_placa",
         {"v_filtro_error": "", "v_placa": r["plates"][0], "v_cpf": r["cpfs"][0], "#f12_selected": "2.0"},
         [("v_placa", r["plates"][0]), ("v_cpf", r["cpfs"][0]), ("v_situacao_atual", "Apreendido & Liberado <ok>"),
          ("vp_situacao_atual", "true"), ("v_tmp", "x")])
    tspd(h, f"{k}8", ves_url, 17)
    post("cmd_nova", jl_ves, "/UIC-SERVICOS/VES0009X.html", MODELS["ves"], "cmd_nova",
         {"#f12_selected": "2.0"}, [("v_situacao_atual", "")])
    tspd(h, f"{k}9", ves_url, 17)
    post("consultar2", jl_ves, "/UIC-SERVICOS/VES0009X.html", MODELS["ves"], "cmd_consultar_placa",
         {"v_filtro_error": "", "v_placa": r["plates"][1], "v_cpf": r["cpfs"][1], "v_renavam": "12", "#f12_selected": "2.0"},
         [("v_placa", r["plates"][1]), ("v_cpf", r["cpfs"][1]), ("vp_situacao_atual", "true"), ("v_tmp", "y")])
    out = {key.split(":", 1)[1]: v for key, v in h.ids.items() if key.startswith(k + ":")}
    out.update({key: v for key, v in h.ids.items() if key.startswith(f"tspd:{k}")})
    return out


# Real SESSIONID = m_currentSessionId literal (9 chars, from easynat-app) + "_" + 12-digit suffix with NO observed source
# (checked in the real HARs, by structure only: the suffix does not appear in any response/request before the
# 1st POST; the body processId is the m_currentProcessId literal, 32 chars). Fictitious values, same composition.
def mk(tag, head, tail, pidn, base, dp, plates, cpfs):
    return dict(tag=tag, head=head, tail=tail, sid=f"{head}_{tail}", pid="SYNTHPID" + f"{pidn:024d}",
                stamp_base=base, delta_prefix=dp, plates=plates, cpfs=cpfs)


ROUNDS = {
    "a1": mk("a1", "CSAN00011", "700000000011", 11, 4100, "DLTC", ["TST0T10", "TST0T11"], ["00000000191", "00000000272"]),
    "b1": mk("b1", "CSAN00021", "700000000021", 21, 5100, "DLTD", ["TST0T12", "TST0T13"], ["00000000353", "00000000434"]),
    "b2": mk("b2", "CSAN00022", "700000000022", 22, 6100, "DLTE", ["TST0T14", "TST0T15"], ["00000000515", "00000000606"]),
}


def build_composite():
    """Composite value rule (named field < 40 B): it only gets an origin by decomposition if covered ENTIRELY
    by >= 2 producer values + separators; a partial prefix does not count."""
    h = Har()
    h.add("part_a", "GET", f"{APP}/compose/a", 200, "text/html;charset=UTF-8",
          '<html><script>var part_a = "ALPHA0001";</script></html>\n', "document", None)
    h.add("part_b", "GET", f"{APP}/compose/b", 200, "application/json", '{"part_b":"987654321012"}', "xhr", f"{APP}/compose/a")
    h.add("use_full", "POST", f"{APP}/compose/use", 200, "text/plain", "ok\n", "xhr", f"{APP}/compose/a", post=[("token", "ALPHA0001_987654321012")])
    h.add("use_partial", "POST", f"{APP}/compose/use", 200, "text/plain", "ok\n", "xhr", f"{APP}/compose/a", post=[("token2", "ALPHA0001_555555555555")])
    (HERE / "real-shape-composite.har").write_text(json.dumps(h.doc(), indent=1, ensure_ascii=False) + "\n")
    return h.ids


def build():
    a, b = Har(), Har()
    ids_a = round_flow(a, ROUNDS["a1"], 11)
    ids_b1 = round_flow(b, ROUNDS["b1"], 21)
    ids_b2 = round_flow(b, ROUNDS["b2"], 31)
    cids = build_composite()
    (HERE / "real-shape-1round.har").write_text(json.dumps(a.doc(), indent=1, ensure_ascii=False) + "\n")
    (HERE / "real-shape-2rounds.har").write_text(json.dumps(b.doc(), indent=1, ensure_ascii=False) + "\n")

    def expect(ids, r):
        return {
            "target": ids["consultar1"],
            "origins": {
                "STAMP": {"status": "origin", "label": "observed origin", "kind": "same-field", "strength": "strong",
                          "producer": ids["cmd_filtro"], "note": "<input type=hidden name=STAMP> from the previous HTML response"},
                "delta": {"parent": "XML", "value_prefix": r["delta_prefix"], "kind": "value-match", "producer": ids["cmd_filtro"],
                          "note": "fragment of the XML in the <textarea> of the previous response (HTML entities decoded)"},
                "SESSIONID": {"status": ["none", "repeated"], "label": "no observed origin",
                              "composition": {"head_len": 9, "separator": "_", "tail_len": 12, "head_source": ids["easynat"] + " (literal m_currentSessionId)", "tail_source": None},
                              "justification_composite": "composite-value rule: a named field < 40 B gets an origin by decomposition only if it is covered ENTIRELY by >= 2 producer values + separators (_ - . : |); a partial prefix does not count. In the real case SESSIONID = the 9-char literal of easynat-app + '_' + 12 digits with no observed source: partial coverage => 'no observed origin' (the 9-char prefix does not count as the field's origin).",
                              "justification": "canonical rule (docs/09 R5): 'reissued' only if the value circulated in a request between the 1st producer and the next one; 'ambiguous' + oldest if there are 2+ producers. In the real HARs only easynat-app contains the value (the NatLogon/SIM1000X/VES0009X pages do not), and no request between the easynat-app response and the NatLogon response carries it (neither in the URL nor in the Referer): single producer => origin, no reissued. The fixture reflects that."},
                "v_placa": {"status": "none", "plate": r["plates"][0]},
            },
            "chain": {
                "steps_include": [ids["easynat"], ids["init_logon"], ids["init_sim"], ids["on_interceptor"], ids["init_ves"], ids["cmd_filtro"]],
                "pages_include": [ids["page_logon"], ids["page_sim"], ids["page_ves"]],
                "protection_include": sorted(v for k, v in ids.items() if k.startswith("tspd:") and v < ids["consultar1"]),
                "never_steps": [ids["static_jquery"], ids["static_cis"], ids["consultar1"], ids["cmd_nova"], ids["consultar2"]],
                "never_in_steps_or_pages_as_producer": "scripts estáticos viram no máximo `context`",
                "pages_exact": [ids["easynat"], ids["page_logon"], ids["page_sim"], ids["page_ves"]],
                "auxiliary_include": [ids["csc_logon"], ids["csc_sim"], ids["csc_ves"], ids["jlibs_sim"], ids["jlibs_ves"]],
                "auxiliary_not_on_path": [ids["jlibs_logon"], ids["blank_logon"]],
                "frames_never_steps": [ids["jlibs_logon"], ids["jlibs_sim"], ids["jlibs_ves"], ids["blank_logon"]],
                "note_cscform": "cscform entra em steps SÓ como produtor do STAMP=INIT (same-field); JLIBS/aboutBlank nunca",
            },
            "init_stamp": {ids["init_logon"]: [ids["csc_logon"]], ids["init_sim"]: [ids["csc_sim"]], ids["init_ves"]: [ids["csc_ves"]]},
        }

    def tspd_of(h, tag):
        return sorted(v for k, v in h.ids.items() if k.startswith(f"tspd:{tag}"))
    manifest = {
        "schema": "scrapelens.fixture.case/1", "id": "detran-pb-real-shape",
        "label": "sanitized-shape-real-case",
        "origin": "FORMA dos HARs reais do DETRAN-PB (estrutura, nunca valores); valores 100% fictícios",
        "files": {"har_1round": "real-shape-1round.har", "har_2rounds": "real-shape-2rounds.har", "har_composite": "real-shape-composite.har"},
        "shape": {
            "connector_response": "HTML ~10 KB: script fictício + <textarea name=XML> (com entidades) + <textarea name=ERRORMESSAGE> + <input hidden STAMP>",
            "har": "WebInspector; sem Cookie/Set-Cookie/cookies[]",
            "rounds": {"1round": ["a1"], "2rounds": ["b1", "b2"]},
            "static_noise": "jquery-ui/cis* com constantes do protocolo (modelos, nextPage, focusProject)",
            "business_values": "placa, CPF e RENAVAM fictícios dentro do XML; v_renavam=12 é fora de formato",
            "get_without_postdata": "todos os GETs",
        },
        "counts": {"1round": len(a.entries), "2rounds": len(b.entries), "connector_posts_per_round": 8},
        "rounds": {"a1": {"ids": ids_a, "tspd": tspd_of(a, "a1")},
                   "b1": {"ids": ids_b1, "tspd": tspd_of(b, "b1")}, "b2": {"ids": ids_b2, "tspd": tspd_of(b, "b2")}},
        "values": {r: {"sessionid": v["sid"], "plates": v["plates"], "cpfs": v["cpfs"], "stamp_base": v["stamp_base"],
                       "delta_prefix": v["delta_prefix"], "unmatched_business": {"v_renavam": "12"}} for r, v in ROUNDS.items()},
        "expectations": {
            "import": {
                "warning_code": "har.cookies_absent",
                "get_request_body": {"state": "empty", "reason_contains": "not applicable"},
                "label_set": ["har-import", "synthetic-fixture"],
            },
            "aceite_1_origins_chain": {"A": {**expect(ids_a, ROUNDS["a1"])},
                                       "B_round2": {**expect(ids_b2, ROUNDS["b2"])}},
            "aceite_2_sanitize": {
                "must_vanish_everywhere": "todas as placas, CPFs e SESSIONIDs fictícios (cru, url-encoded e entidades)",
                "warning_code": "sanitize.business_field_unmatched", "for": "v_renavam=12 (fora de formato; não redigido em silêncio)",
            },
            "aceite_3_compare": {
                "a": "1round", "b": "2rounds",
                "a_round_pairs_with_one_b_round": True, "unpaired_b_rounds": 1, "max_ambiguities": 5,
                "dynamic_fields": ["SESSIONID", "STAMP"], "static_fields": ["PAGEINITPARAM", "ERRORMESSAGE"],
            },
            "composite_rule": {
                "har": "real-shape-composite.har",
                "full_cover": {"request": cids["use_full"], "field": "token", "status": "composite", "confidence": "possible",
                               "producers": [cids["part_a"], cids["part_b"]], "why": "token = ALPHA0001 (literal from part_a) + '_' + 987654321012 (JSON leaf from part_b): fully covered by 2 producers"},
                "partial_cover": {"request": cids["use_partial"], "field": "token2", "status": ["none", "repeated"], "label": "no observed origin",
                                  "why": "only the prefix ALPHA0001 has a producer; the 12-digit suffix has no observed source: partial coverage does not count"},
            },
            "aceite_4_cookies": {"warning_code": "har.cookies_absent", "origins_and_chain_repeat_warning": True},
        },
        "sanitization": {"synthetic": "tudo fictício; nenhum byte dos HARs reais", "rule": "HAR bruto nunca entra no repositório"},
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {HERE}: 1round={len(a.entries)} entries, 2rounds={len(b.entries)} entries")


if __name__ == "__main__":
    build()
