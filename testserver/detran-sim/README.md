# detran-sim — simulador local fictício do fluxo DETRAN-PB (Rodada 7, Aceite 2–3)

Só Python 3 (biblioteca padrão), apenas `127.0.0.1`, sem rede externa e sem telemetria.
Imita a **forma** do fluxo real (páginas, frames, Connector em HTML com `XML`/`ERRORMESSAGE`/`STAMP`);
todos os valores são fictícios e **novos a cada sessão**. Serve para o agente de Testes rodar o script de
priming gerado (não o ScrapeLens) com `--confirmar` e provar que a cadeia usa valores novos, nunca os capturados.

```sh
python3 testserver/detran-sim/detran_sim.py [--port 8791] [--mode ok|error|nocontrols|403] [--seed N]
python3 testserver/detran-sim/smoke.py       # autoteste (porta 8799): OK / FAIL
```

Base: `http://127.0.0.1:8791/detran-portal-servicos` (o prefixo é opcional nas rotas). O script gerado traz as
URLs capturadas (`https://wsdetran.pb.gov.br/detran-portal-servicos/...`); para rodar contra o simulador,
troque só o esquema/host/porta (ex.: parâmetro de base ou `sed`), nunca o caminho.

## Rotas

| Rota | Comportamento |
|---|---|
| `GET /servlet/easynat-app?op=S37` | **Abre sessão nova**: `m_currentSessionId` (9 chars, `CSANnnnnn`) e `m_currentProcessId` (32 chars) novos |
| `GET /cisnatural/NatLogon.html`, `/UIC-SERVICOS/SIM1000X.html`, `/UIC-SERVICOS/VES0009X.html` | páginas (só o modelo; sem SESSIONID) |
| `GET /{cisnatural,UIC-SERVICOS}/<Pagina>_JLIBS.html`, `/.../cscform.html?page=<Pagina>`, `/.../aboutBlank.html` | frames auxiliares; `cscform` traz `<input hidden STAMP value=INIT>` |
| `GET /TSPD/...`, `GET /**/*.js` | ruído de proteção/estáticos sintéticos |
| `POST /servlet/Connector` | HTML ~10 KB com `<textarea name=XML>` (entidades HTML), `<textarea name=ERRORMESSAGE>`, `<input hidden STAMP>`; STAMP e delta **novos a cada resposta** |
| `GET /healthz` · `GET /__sim/mode?m=<modo>` · `GET /__sim/log` · `GET /__sim/reset` | saúde · troca o modo global · log JSON das requisições (sem corpos) · zera sessões |

### Validação do Connector (resposta `app-error` quando falha)
`SESSIONID` = prefixo emitido pelo easynat-app + `_` + **12 dígitos montados no cliente** (a parte sem fonte);
`processId` do XML = o emitido; `STAMP` = `INIT` no init ou o da última resposta; delta do XML = o da última resposta.
Qualquer divergência (inclusive valores de outra sessão/HAR) devolve 200 com `ERRORMESSAGE` preenchido
(`sessão desconhecida`, `processId diferente`, `STAMP inválido`, `delta inválido`, `SESSIONID sem o sufixo...`).

### Modos de erro (global; `--mode` ou `/__sim/mode?m=`)
| Modo | Efeito no `POST /servlet/Connector` | Veredito esperado no assess |
|---|---|---|
| `ok` | resposta normal | `app-ok` |
| `error` | `cmd_consultar_placa` responde 200 com `ERRORMESSAGE` preenchido (demais eventos normais) | `app-error` |
| `nocontrols` | 200 com HTML sem `XML`/`STAMP`/`ERRORMESSAGE` | `indeterminado` (ou `blocked?` por heurística) |
| `403` | HTTP 403 com página de bloqueio sintética | `blocked?` |

`--seed N` torna os valores reprodutíveis (testes); sem ele, cada execução é aleatória.
