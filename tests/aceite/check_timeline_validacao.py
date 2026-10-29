#!/usr/bin/env python3
"""Rodada 9 (docs/13-timeline-validacao.md): linha do tempo da aplicação e validação da execução do script.

  python3 tests/aceite/check_timeline_validacao.py [--core BIN] [--wrapper natural-core] [--python PY_COM_REQUESTS]
         [--port 8793] [HAR_REAL ...]

(1) `natural-core timeline <sessão> --adapter natural-ajax` na real-shape (1 e 2 rodadas): eventos da aplicação na ordem
    do fluxo manual (init, init, on_interceptor, init, cmd_filtro, cmd_consultar_placa; por rodada), rótulos
    `event @ page`, proteção recolhida (nenhuma entrada /TSPD/ avulsa). Nos HARs reais (H1–H3 padrão), só agregado:
    contagens e ordem de rótulos (nomes de evento/página, nunca valores).
(2) script de priming da real-shape rodado POR ESTE TESTE contra o detran-sim com `--confirmar --base-url --trace`;
    `import-trace`; `validate <captura> <trace>` (scrapelens.validate/1; core 94478de): todos os passos do trace pareados, nenhum POST do Connector sobrando só na
    captura, só dinâmicos esperados diferem (STAMP, delta, SESSIONID + o inerente à troca de host), assess app-ok, e o
    resumo "equivalente".
(3) modos error/nocontrols/403: o trace termina no passo ruim; compare aponta "diverge no passo N" (N = último passo do
    trace = primeiro pedido ruim do sim) e o assess dá o veredito certo (error → app-error; 403 → blocked; nocontrols →
    não app-ok).
(4) o trace tem permissão 0600 e o aviso "contém dados da sua sessão"; sanitize sobre a sessão do trace remove
    SESSIONID, cookies e placa.

Formatos ainda não entregues (timeline, import-trace, --trace) são lidos de forma tolerante, conforme o doc 13:
timeline = JSON com lista de entradas {label, kind[, count]}; trace = JSON `scrapelens.trace/1` com lista `steps`;
compare = JSON do compare atual + um resumo textual ("equivalente" | "diverge no passo N") em qualquer chave.
Falha enquanto Core/Captura não entregarem; nada é afrouxado. Dados 100% sintéticos; HARs reais só em agregado.
Resultado: tests/results/priming/timeline-validacao.json.
"""
from __future__ import annotations

import argparse, json, os, re, shlex, shutil, stat, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402
import check_priming_sim as ps  # noqa: E402

ROOT = cb.ROOT
OUT = ROOT / "tests" / "results" / "priming" / "timeline-validacao.json"
FIX = ROOT / "fixtures" / "detran-pb-real-shape"
EVENTS = ["init", "init", "on_interceptor", "init", "cmd_filtro", "cmd_consultar_placa"]   # fluxo manual até a 1ª consulta
FIXTURE_ROUND = EVENTS + ["cmd_nova", "cmd_consultar_placa"]                                   # a fixture traz uma 2ª consulta
REAL = ["/Users/cesar/Projects/scripts/detran_scraper/detran_paraiba/inputs/sem_captcha.har",
        "/Users/cesar/Downloads/wsdetran.pb.gov.br.har.txt.har",
        "/Users/cesar/Downloads/wsdetran.fluxo.captcha.solve.pgEvy4.har.txt.har"]
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
        check(False, f"{what}: saída não é JSON")
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
    return e.get("type") == "group" or "group" in kind(e) or "grupo" in kind(e)


def is_protection(e):
    """Proteção avulsa = entrada de evento /TSPD/; o grupo `protection` (type=group) é a forma recolhida correta."""
    if is_group(e):
        return "protec" in kind(e)
    return "/TSPD/" in str(e.get("url", "")) + str(e.get("label", ""))


def timeline_agg(wrapper, sess, what):
    d = jload(sh([wrapper, "timeline", sess, "--adapter", "natural-ajax"]), f"{what}: timeline")
    es = entries_of(d)
    if not check(bool(es), f"{what}: timeline sem entradas"):
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
          f"{what}: proteção deveria vir recolhida em grupos com contagem ({len(groups)} grupos, {len(standalone)} entradas avulsas)")
    check(ev.count("?") == 0, f"{what}: {ev.count('?')} de {len(posts)} POSTs do Connector sem rótulo `event @ page` com o adaptador")
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
            hit = under or re.search(r"diff|changed|differ|mudou", k, re.I)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8793)
    ap.add_argument("--wrapper", default=str(ROOT / "adapters/natural-ajax/target/release/natural-core"))
    ap.add_argument("hars", nargs="*", default=[h for h in REAL if Path(h).exists()])
    a = ap.parse_args()
    core, py, wrapper = cb.core_bin(a.core), a.python or ps.default_python(), a.wrapper
    if not Path(wrapper).exists():
        sys.exit(f"wrapper não encontrado: {wrapper}")
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
                      f"{name}: eventos {agg['sequencia_eventos']} != fluxo manual {FIXTURE_ROUND * n_round}")
        INFO["timeline_real"] = {}
        if not a.hars:
            check(False, "nenhum HAR real encontrado para o agregado da timeline")
        for i, h in enumerate(a.hars, 1):
            s = tmp / f"tl-real{i}"; sh([core, "import-har", h, "--out", s])
            agg = timeline_agg(wrapper, s, f"HAR real #{i}")
            if agg:
                INFO["timeline_real"][f"H{i}"] = {k: agg[k] for k in ("entradas", "posts_connector", "posts_sem_rotulo_event_page", "grupos_protecao", "protecao_avulsa", "protecao_recolhida")}
                INFO["timeline_real"][f"H{i}"]["ordem_rotulos"] = [f"{e}@{p}" for e, p in zip(agg["sequencia_eventos"], agg["paginas"])]
                check(subsequence(agg["sequencia_eventos"], EVENTS), f"HAR real #{i}: eventos fora da ordem do fluxo manual")

        # ---- (2)/(3)/(4) execução do script
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
            p = sh([py, "-I", script, "--confirmar", "--base-url", base, "--placa", PLACA, "--cpf", ps.CPF,
                    "--sessionid-cliente", client, "--trace", trace], cwd=tmp)
            log = ps.http(base, "/__sim/log")["log"]
            first_bad = next((i for i, x in enumerate(log, 1) if x["path"].endswith("/servlet/Connector") and
                              (x["status"] != 200 or x["note"].startswith(("modo", "app-error")))), None)
            sc = INFO["cenarios"][mode] = {"script_rc": p.returncode, "pedidos_no_sim": len(log), "primeiro_ruim": first_bad}
            if not check(trace.exists(), f"{mode}: o script não criou o trace (--trace)"):
                continue
            mode_bits = stat.S_IMODE(trace.stat().st_mode)
            sc["trace_modo"] = oct(mode_bits)
            check(mode_bits == 0o600, f"{mode}: trace deveria ter 0600, tem {oct(mode_bits)}")
            raw = trace.read_text()
            try:
                t, steps = trace_steps(trace)
            except Exception:
                check(False, f"{mode}: trace não é JSON"); continue
            check(t.get("schema") == "scrapelens.trace/1", f"{mode}: schema {t.get('schema')!r} != scrapelens.trace/1")
            check("contém dados da sua sessão" in raw or "contém dados da sua sessão" in p.stdout + p.stderr,
                  f"{mode}: sem o aviso 'contém dados da sua sessão; não compartilhe sem sanitizar'")
            sc["trace_passos"] = len(steps)
            ts = tmp / f"ts-{mode}"
            ip = sh([core, "import-trace", trace, "--out", ts])
            if not check(ip.returncode == 0, f"{mode}: import-trace: rc={ip.returncode}: {' '.join(ip.stderr.split())[:120]}"):
                continue
            assess = jload(sh([core, "assess", ts]), f"{mode}: assess do trace")
            val = jload(sh([core, "validate", cap, ts]), f"{mode}: validate")
            outs = (assess or {}).get("outcomes", [])
            conn = [o for o in outs if o.get("url", "").endswith("/servlet/Connector")]
            sc["assess_connector"] = [o.get("verdictKind") for o in conn]
            vsteps = (val or {}).get("steps", []) if isinstance(val, dict) else []
            sc["validate"] = {"verdict": (val or {}).get("verdict"), "step": (val or {}).get("step"),
                              "summary": str((val or {}).get("summary", ""))[:140], "passos": len(vsteps)}
            if val is not None:
                check(val.get("schema") == "scrapelens.validate/1", f"{mode}: schema do validate {val.get('schema')!r}")
            if mode == "ok":
                check(p.returncode == 0, f"ok: script rc={p.returncode}")
                check(len(steps) == len(log), f"ok: trace com {len(steps)} passos, sim viu {len(log)} pedidos")
                check(conn and all(o.get("verdictKind") == "app-ok" for o in conn), f"ok: assess do trace não é app-ok em todos os POSTs: {sc['assess_connector']}")
                check(not any(o.get("verdictKind") in ("app-error", "blocked") for o in outs), "ok: algum passo do trace com app-error/blocked")
                if val:
                    g = lambda d, *k: next((d[x] for x in k if x in d), None)  # noqa: E731
                    unpaired = [x for x in vsteps if not g(x, "captureRequestId", "capture_request_id")]
                    unexpected = [(g(x, "step"), n.get("field")) for x in vsteps for n in x.get("unexpected", [])]
                    expected = sorted({str(n.get("field")) for x in vsteps for n in x.get("expected", [])})
                    missing = g(val, "missingInTrace", "missing_in_trace") or []
                    sc["validate"].update({"nao_pareados": len(unpaired), "inesperados": len(unexpected), "esperados_campos": expected,
                                           "missingInTrace": len(missing), "mappedOrigin": bool(g(val, "mappedOrigin", "mapped_origin"))})
                    check(val.get("verdict") == "equivalent", f"ok: verdict {val.get('verdict')!r}, esperado equivalent ({sc['validate']['summary']})")
                    check("equivalente" in str(val.get("summary", "")), "ok: resumo sem 'execução equivalente à captura'")
                    check(len(vsteps) == len(steps) and not unpaired, f"ok: passos não pareados 1:1 ({len(vsteps)} passos validados, {len(steps)} no trace, {len(unpaired)} sem par)")
                    check(not unexpected, f"ok: diferenças inesperadas (passo, campo): {unexpected[:6]}")
                    extra = [n for n in expected if not DYNAMIC_OK.search(n)]
                    check(not extra, f"ok: diferenças esperadas fora de STAMP/delta/SESSIONID: {extra[:8]}")
                    check(not missing, f"ok: {len(missing)} requisição(ões) da captura ausentes no trace")
                    check(all(str(g(x, "verdictTrace", "verdict_trace")) in ("app-ok", "not-assessed") for x in vsteps),
                          "ok: algum passo com veredito do trace diferente de app-ok/não-avaliado")
            else:
                want = {"error": {"app-error"}, "403": {"blocked"}, "nocontrols": {"indeterminate", "indeterminado", "blocked", "not-assessed", "app-error"}}[mode]
                check(p.returncode != 0, f"{mode}: o script deveria falhar")
                check(first_bad is not None and len(steps) == first_bad,
                      f"{mode}: o trace deveria terminar no passo ruim #{first_bad}; tem {len(steps)} passos")
                last = outs[-1].get("verdictKind") if outs else None
                sc["veredito_ultimo_passo"] = last
                check(last in want and last != "app-ok", f"{mode}: veredito do passo ruim {last!r}, esperado um de {sorted(want)}")
                if val:
                    m = re.search(r"diverge no passo (\d+)", str(val.get("summary", "")))
                    check(val.get("verdict") == "diverges", f"{mode}: verdict {val.get('verdict')!r}, esperado diverges")
                    check(val.get("step") == first_bad and m is not None and int(m.group(1)) == first_bad,
                          f"{mode}: validate deveria apontar o passo {first_bad}; apontou step={val.get('step')} resumo={sc['validate']['summary']!r}")
                    hint = {"error": r"app-error|ERRORMESSAGE", "403": r"403|blocked"}.get(mode)
                    if hint:
                        check(re.search(hint, str(val.get("summary", "")) + str(val.get("reason", "")), re.I),
                              f"{mode}: motivo sem {hint!r}: {sc['validate']['summary']!r}")
            # ---- (4) sanitize (cenário ok)
            if mode == "ok":
                san = tmp / "san"
                sp = sh([core, "sanitize", ts, san])
                check(sp.returncode == 0, f"sanitize do trace: rc={sp.returncode}")
                body = "".join(f.read_text(errors="replace") for f in san.rglob("*") if f.is_file()) if san.exists() else ""
                sid = set(re.findall(r"SESSIONID=([A-Za-z0-9_]+)", raw))
                cookies = set()
                for h_ in re.findall(r'"(?:cookie|set-cookie)"\s*:\s*"([^"]+)"', raw, re.I):
                    cookies |= {c.split("=", 1)[1].strip() for c in h_.split(";") if "=" in c and len(c.split("=", 1)[1].strip()) >= 6}
                leaks = {"SESSIONID": [v for v in sid if v and v in body], "placa": [PLACA] if PLACA in body else [],
                         "cookies": [v for v in cookies if v in body], "parte_cliente": [client[1:]] if client[1:] in body else []}
                sc["sanitize_vazamentos"] = {k: len(v) for k, v in leaks.items()}
                sc["sanitize_valores_testados"] = {"SESSIONID": len(sid), "cookies": len(cookies)}
                check(bool(body), "sanitize: saída vazia")
                check(len(sid) > 0, "sanitize: nenhum SESSIONID no trace para testar a remoção")
                check(not any(leaks.values()), f"sanitize: valores sensíveis ainda presentes: { {k: len(v) for k, v in leaks.items() if v} }")
    finally:
        sim.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    INFO["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(INFO, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: timeline + validação da execução (trace, import-trace, compare, sanitize)"); return 0


if __name__ == "__main__":
    sys.exit(main())
