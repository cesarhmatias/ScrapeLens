# detran-sim — local fictitious simulator of the DETRAN-PB flow (Round 7, Acceptance 2–3)

Python 3 standard library only, `127.0.0.1` only, no external network and no telemetry.
It imitates the **shape** of the real flow (pages, frames, Connector in HTML with `XML`/`ERRORMESSAGE`/`STAMP`);
all values are fictitious and **new in every session**. It serves so that the Testing agent can run the generated
priming script (not ScrapeLens) with `--confirmar` and prove that the chain uses new values, never the captured ones.

```sh
python3 testserver/detran-sim/detran_sim.py [--port 8791] [--mode ok|error|nocontrols|403] [--seed N]
python3 testserver/detran-sim/smoke.py       # self-test (port 8799): OK / FAIL
```

Base: `http://127.0.0.1:8791/detran-portal-servicos` (the prefix is optional in the routes). The generated script carries the
captured URLs (`https://wsdetran.pb.gov.br/detran-portal-servicos/...`); to run against the simulator,
change only the scheme/host/port (e.g. a base parameter or `sed`), never the path.

## Routes

| Route | Behavior |
|---|---|
| `GET /servlet/easynat-app?op=S37` | **Opens a new session**: new `m_currentSessionId` (9 chars, `CSANnnnnn`) and `m_currentProcessId` (32 chars) |
| `GET /cisnatural/NatLogon.html`, `/UIC-SERVICOS/SIM1000X.html`, `/UIC-SERVICOS/VES0009X.html` | pages (model only; no SESSIONID) |
| `GET /{cisnatural,UIC-SERVICOS}/<Pagina>_JLIBS.html`, `/.../cscform.html?page=<Pagina>`, `/.../aboutBlank.html` | auxiliary frames; `cscform` carries `<input hidden STAMP value=INIT>` |
| `GET /TSPD/...`, `GET /**/*.js` | synthetic protection/static noise |
| `POST /servlet/Connector` | ~10 KB HTML with `<textarea name=XML>` (HTML entities), `<textarea name=ERRORMESSAGE>`, `<input hidden STAMP>`; STAMP and delta are **new in every response** |
| `GET /healthz` · `GET /__sim/mode?m=<mode>` · `GET /__sim/log` · `GET /__sim/reset` | health · switches the global mode · JSON log of requests (no bodies) · clears sessions |

### Connector validation (`app-error` response when it fails)
`SESSIONID` = prefix issued by easynat-app + `_` + **12 digits built on the client** (the part with no source);
the XML `processId` = the one issued; `STAMP` = `INIT` at init or the one from the last response; the XML delta = the one from the last response.
Any divergence (including values from another session/HAR) returns 200 with `ERRORMESSAGE` filled
(`unknown session`, `processId mismatch`, `invalid STAMP`, `invalid delta`, `SESSIONID without the suffix...`).

### Error modes (global; `--mode` or `/__sim/mode?m=`)
| Mode | Effect on `POST /servlet/Connector` | Expected verdict in assess |
|---|---|---|
| `ok` | normal response | `app-ok` |
| `error` | `cmd_consultar_placa` responds 200 with `ERRORMESSAGE` filled (other events normal) | `app-error` |
| `nocontrols` | 200 with HTML lacking `XML`/`STAMP`/`ERRORMESSAGE` | `undetermined` (or `blocked?` by heuristic) |
| `403` | HTTP 403 with a synthetic block page | `blocked?` |
| `strict` | like `ok`, but validates the grammar of the received `XML` with prefixes in **UTF-16** units (`serialize`/`jslen`): type `i`/`v`, widths 2/2/2/2/2/3/5/1, XML sid == `SESSIONID`, fixed fields, `p` groups (2/5), `x` (2), no leftover bytes. Wrong prefix → 200 with `ERRORMESSAGE` (`XML grammar: …`). Generates values of a different size than the fixtures: SESSIONID with a 15-char prefix (+`_`+12), a 20-char delta with an accent (`Dé…`), a response with accents | `app-ok` / `app-error` |

`--seed N` makes the values reproducible (tests); without it, every run is random.
