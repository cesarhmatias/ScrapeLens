#!/usr/bin/env python3
"""Rodada 8 (docs/12-adaptador-natural.md), aceite 1–2: adaptador Natural for Ajax × detran-sim em modo `strict`.

  python3 tests/aceite/check_natural_adapter.py [--core BIN] [--python PY_COM_REQUESTS] [--port 8792]
         [--adapter-args "--adapter natural-ajax"] [--roundtrip-cmd "adapter-roundtrip"]

(a) CONTROLE: script de priming SEM o adaptador contra o sim `strict` (valores de tamanhos diferentes das fixtures:
    SESSIONID e delta mais longos, delta com acento; placa Mercosul) deve FALHAR com ERRORMESSAGE de gramática.
(b) COM o adaptador (`export-priming ... <adapter-args>`): cadeia completa, 2 sessões novas, nenhum ERRORMESSAGE.
(c) round-trip do adaptador nas fixtures (`scrapelens-core <roundtrip-cmd> <sessão>` deve imprimir JSON
    {"fields": N, "divergences": 0}); N é conferido contra um oráculo independente (gramática de consultar_patio.serialize
    lida em Python, UTF-16) sobre os mesmos XML.
Enquanto o adaptador não existir, (b) e (c) FALHAM com mensagem clara (não são afrouxados). Dados 100% sintéticos.
Resultado: tests/results/priming/natural-adapter.json.
"""
from __future__ import annotations

import argparse, json, os, random, re, shlex, shutil, subprocess, sys, tempfile, time, urllib.parse, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_bodies_search as cb  # noqa: E402
import check_priming_sim as ps  # noqa: E402

ROOT = cb.ROOT
OUT = ROOT / "tests" / "results" / "priming" / "natural-adapter.json"
PLACA_MERCOSUL = "BRA2E19"  # sintética, formato Mercosul
FAILS: list[str] = []
INFO: dict = {}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def jslen(v):
    return len(v.encode("utf-16-le", "surrogatepass")) // 2


def oracle_fields(xml: str):
    """Oráculo independente: lê o XML de REQUISIÇÃO por unidades UTF-16 e devolve (nº de campos, canônico==xml)."""
    u = xml.encode("utf-16-le", "surrogatepass"); n = len(u) // 2; pos = 0

    def take(k):
        nonlocal pos
        t = u[pos * 2:(pos + k) * 2].decode("utf-16-le", "surrogatepass"); pos += k; return t
    kind = take(1)
    lens = [int(take(w)) for w in (2, 2, 2, 2, 2, 3, 5, 1)]
    parts = [take(k) for k in lens]
    fields, props = 8, []
    while True:
        op = take(1)
        if op == "p":
            nl = int(take(2)); vl = int(take(5)); props.append((take(nl), take(vl))); fields += 2
        elif op == "x":
            delta = take(int(take(2))); fields += 1; break
        else:
            raise ValueError("op")
    canon = kind + "".join(str(jslen(v)).zfill(w) for v, w in zip(parts, (2, 2, 2, 2, 2, 3, 5, 1))) + "".join(parts)
    for a, b in props:
        canon += "p" + str(jslen(a)).zfill(2) + str(jslen(b)).zfill(5) + a + b
    canon += "x" + str(jslen(delta)).zfill(2) + delta
    return fields, canon == xml and pos == n


def request_xmls(har: Path):
    out = []
    for e in json.loads(har.read_text())["log"]["entries"]:
        txt = (e["request"].get("postData") or {}).get("text") or ""
        if "XML=" in txt:
            out.append(urllib.parse.parse_qs(txt, keep_blank_values=True)["XML"][0])
    return out


def run(py, script, base, cwd, client, extra=()):
    argv = [py, "-I", str(script), "--confirmar", "--base-url", base, "--placa", PLACA_MERCOSUL, "--cpf", ps.CPF,
            "--sessionid-cliente", client, *extra]
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=cwd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core"); ap.add_argument("--python"); ap.add_argument("--port", type=int, default=8792)
    ap.add_argument("--adapter-args", default="--adapter natural-ajax")
    ap.add_argument("--roundtrip-cmd", default="adapter-roundtrip")
    a = ap.parse_args()
    core, py = cb.core_bin(a.core), a.python or ps.default_python()
    base = f"http://127.0.0.1:{a.port}"
    tmp = Path(tempfile.mkdtemp(prefix="sl-natural-")); os.chmod(tmp, 0o700)
    sim = subprocess.Popen([sys.executable, str(ps.SIM), "--port", str(a.port), "--mode", "strict"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                ps.http(base, "/healthz"); break
            except Exception:
                time.sleep(0.1)
        har = ps.HAR
        sess = tmp / "sess"
        subprocess.run([core, "import-har", har, "--out", sess, "--label", "synthetic-fixture"], check=True, capture_output=True)
        man = json.loads((ROOT / "fixtures" / "detran-pb-real-shape" / "manifest.json").read_text())
        target = man["expectations"]["aceite_1_origins_chain"]["A"]["target"]

        # --- (a) controle: sem adaptador
        plain = tmp / "plain.py"
        g = subprocess.run([core, "export-priming", sess, target, "--out", plain], capture_output=True, text=True)
        check(g.returncode == 0, f"(a) export-priming sem adaptador falhou: {g.stderr[:150]}")
        client = ps.new_client_part()
        ps.http(base, "/__sim/reset"); ps.http(base, "/__sim/mode?m=strict")
        p = run(py, plain, base, tmp, client)
        log = ps.http(base, "/__sim/log")["log"]
        errs = [x["note"] for x in log if x["note"].startswith("app-error")]
        INFO["a_sem_adaptador"] = {"rc": p.returncode, "requests": len(log), "app_errors": [e[:110] for e in errs],
                                   "stderr": (p.stderr.strip().splitlines() or [""])[-1][:140]}
        check(p.returncode != 0, "(a) controle: o script SEM adaptador deveria falhar no sim strict (rc=0)")
        check(any("gramática" in e or "prefixo" in e or "delta" in e or "sid" in e for e in errs) or p.returncode != 0,
              "(a) controle: a falha deveria vir do sim strict")

        # --- (b) com adaptador, 2 sessões
        ad = tmp / "adapted.py"
        g = subprocess.run([core, "export-priming", sess, target, "--out", ad, *shlex.split(a.adapter_args)], capture_output=True, text=True)
        INFO["b_export_rc"] = g.returncode
        check(g.returncode == 0, f"(b) adaptador indisponível: `export-priming {a.adapter_args}` rc={g.returncode}: {g.stderr.strip()[:140]}")
        if g.returncode == 0:
            plan_n = None
            for n in (1, 2):
                ps.http(base, "/__sim/reset"); ps.http(base, "/__sim/mode?m=strict")
                client = ps.new_client_part()
                p = run(py, ad, base, tmp, client)
                log = ps.http(base, "/__sim/log")
                conn = [x for x in log["log"] if x["path"].endswith("/servlet/Connector")]
                INFO[f"b_sessao_{n}"] = {"rc": p.returncode, "requests": len(log["log"]), "connector_posts": len(conn),
                                         "sim_sessions": log["sessions"], "app_errors": [x["note"][:110] for x in conn if x["note"].startswith("app-error")]}
                check(p.returncode == 0, f"(b) sessão {n}: rc={p.returncode}: {p.stderr.strip()[-160:]}")
                check(len(conn) == 6 and all(x["status"] == 200 and x["note"].startswith("ok") for x in conn),
                      f"(b) sessão {n}: {len(conn)} POSTs; erros={INFO[f'b_sessao_{n}']['app_errors']}")
                check("Cadeia concluída" in p.stdout, f"(b) sessão {n}: sem 'Cadeia concluída'")

        # --- (c) round-trip nas fixtures
        total_fields = total_div = 0
        fixtures = sorted((ROOT / "fixtures").glob("detran-pb*/*.har"))
        for f in fixtures:
            xmls = request_xmls(f)
            exp_fields = 0
            for x in xmls:
                try:
                    k, ok = oracle_fields(x)
                except Exception:
                    k, ok = 0, False
                exp_fields += k
                check(ok, f"(c) oráculo não fecha a gramática em {f.name} (fixture inválida?)")
            s2 = tmp / ("rt-" + f.stem)
            subprocess.run([core, "import-har", f, "--out", s2, "--label", "synthetic-fixture"], capture_output=True)
            r = subprocess.run([core, *shlex.split(a.roundtrip_cmd), s2], capture_output=True, text=True)
            try:
                j = json.loads(r.stdout)
            except Exception:
                j = None
            INFO.setdefault("c_roundtrip", {})[f.name] = {"oraculo_campos": exp_fields, "xml": len(xmls),
                                                          "adapter": j, "rc": r.returncode}
            if j is None or r.returncode != 0:
                check(False, f"(c) round-trip indisponível em {f.name}: `{a.roundtrip_cmd}` rc={r.returncode} {r.stderr.strip()[:100]}")
                continue
            total_fields += j.get("fields", 0); total_div += j.get("divergences", -1)
            check(j.get("divergences") == 0, f"(c) {f.name}: {j.get('divergences')} divergências")
            check(j.get("fields") == exp_fields, f"(c) {f.name}: adaptador contou {j.get('fields')} campos, oráculo {exp_fields}")
        INFO["c_total"] = {"fixtures": len(fixtures), "fields": total_fields, "divergences": total_div}
    finally:
        sim.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
    INFO["fails"] = FAILS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(INFO, indent=1, ensure_ascii=False) + "\n")
    if FAILS:
        print(f"FAIL ({len(FAILS)}):"); [print(" -", f) for f in FAILS]; return 1
    print("OK: adaptador Natural — controle sem adaptador falha no strict; com adaptador 2 sessões completas; round-trip 0 divergências")
    return 0


if __name__ == "__main__":
    sys.exit(main())
