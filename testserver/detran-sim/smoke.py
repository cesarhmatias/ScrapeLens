#!/usr/bin/env python3
"""Smoke do detran-sim: percorre o fluxo extraindo valores novos em runtime (como o priming deve fazer),
confere que valores de outra sessão são rejeitados e que os modos de erro respondem como documentado.
Sobe o simulador em porta livre, sem rede externa.   python3 testserver/detran-sim/smoke.py"""
import html, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import detran_sim as ds  # noqa: E402
import build_fixtures as bf  # noqa: E402

PORT = 8799
B = f"http://127.0.0.1:{PORT}{ds.PREFIX}"
FAILS = []


def req(path, data=None):
    r = urllib.request.Request(B + path, data=urllib.parse.urlencode(data).encode() if data else None)
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def ctl(m): return req(f"/__sim/mode?m={m}")


def control(body, name):
    m = re.search(rf'<(?:textarea|input)[^>]*name="{name}"[^>]*?(?:value="([^"]*)")?>(.*?)(?:</textarea>|\n)', body, re.S)
    return html.unescape(m.group(1) if m and m.group(1) is not None else (m.group(2) if m else ""))


def session():
    _, page = req("/servlet/easynat-app?op=S37")
    head, pid = (re.search(rf'm_current{k} = "([^"]+)"', page).group(1) for k in ("SessionId", "ProcessId"))
    return {"sid": f"{head}_{head[-5:]}0000000", "pid": pid, "stamp": "INIT", "delta": "inittini"}


def post(s, page, model, event, props, init=False):
    xml = bf.serialize(s["sid"], s["pid"], model, page, event, props, s["delta"], init=init)
    f = {"SESSIONID": s["sid"], "PAGEINITPARAM": "", "XML": xml, "STAMP": "INIT" if init else s["stamp"]}
    if not init:
        f["ERRORMESSAGE"] = ""
    st, body = req("/servlet/Connector", list(f.items()))
    return st, body


def absorb(s, body):
    xml, st = control(body, "XML"), control(body, "STAMP")
    d = re.search(r"x(\d{2})(\S+)$", xml)
    s["stamp"], s["delta"] = st, d.group(2) if d else s["delta"]


def ok(cond, msg):
    if not cond: FAILS.append(msg)


def main():
    p = subprocess.Popen([sys.executable, str(HERE / "detran_sim.py"), "--port", str(PORT), "--seed", "7"], stdout=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try: req("/healthz"); break
            except Exception: time.sleep(0.1)
        V = ("/UIC-SERVICOS/VES0009X.html", ds.MODELS["ves"])
        sa, sb = session(), session()
        ok(sa["sid"][:9] != sb["sid"][:9] and sa["pid"] != sb["pid"], "sessões devem ter valores novos")
        for s in (sa,):
            st, b = post(s, *V, "", {"pageInitParam": ""}, init=True); ok(st == 200 and control(b, "ERRORMESSAGE") == "", "init deve passar"); absorb(s, b)
            st, b = post(s, *V, "cmd_filtro", {"v_filtro_sel": "2.0"}); ok(control(b, "ERRORMESSAGE") == "", "cmd_filtro com STAMP/delta novos deve passar: " + control(b, "ERRORMESSAGE")); absorb(s, b)
            stale = dict(s); st, b = post(s, *V, "cmd_consultar_placa", {"v_placa": "TST0T99", "v_cpf": "00000000191"})
            ok(control(b, "ERRORMESSAGE") == "" and "TST0T99" in control(b, "XML"), "consultar com valores novos deve ecoar a placa")
            absorb(s, b)
        # valor capturado (STAMP/delta antigos) deve ser rejeitado
        st, b = post({**sa, "stamp": "1", "delta": "inittini"}, *V, "cmd_nova", {})
        ok("STAMP inválido" in control(b, "ERRORMESSAGE"), "STAMP antigo deve dar ERRORMESSAGE")
        # SESSIONID/pid de outra sessão
        st, b = post({**sb, "sid": sa["sid"], "pid": sb["pid"]}, *V, "", {}, init=True)
        ok("processId diferente" in control(b, "ERRORMESSAGE"), "pid de outra sessão deve dar ERRORMESSAGE")
        st, b = post({"sid": "CSAN00000_000000000000", "pid": sa["pid"], "stamp": "INIT", "delta": "x"}, *V, "", {}, init=True)
        ok("sessão desconhecida" in control(b, "ERRORMESSAGE"), "sessão desconhecida deve dar ERRORMESSAGE")
        # modos
        ctl("error"); s = session(); post(s, *V, "", {}, init=True)
        st, b = post(sb, *V, "cmd_consultar_placa", {"v_placa": "TST0T98"}); ok(st == 200 and control(b, "ERRORMESSAGE") != "", "modo error: ERRORMESSAGE preenchido")
        ctl("nocontrols"); st, b = post(sa, *V, "cmd_filtro", {}); ok(st == 200 and "name=\"XML\"" not in b and "STAMP" not in b, "modo nocontrols: 200 sem controles")
        ctl("403"); st, b = post(sa, *V, "cmd_filtro", {}); ok(st == 403, "modo 403: HTTP 403")
        ctl("ok"); st, _ = req("/TSPD/0000SYNTH?type=17"); ok(st == 200, "TSPD sintético")
    finally:
        p.terminate()
    if FAILS:
        print("FAIL:"); [print(" -", f) for f in FAILS]; return 1
    print("OK: detran-sim — sessões novas, valores antigos rejeitados, modos error/nocontrols/403"); return 0


if __name__ == "__main__":
    sys.exit(main())
