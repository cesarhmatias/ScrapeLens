# Relatório final de aceite — ScrapeLens

- **HEAD testado:** 6a85676 (`fix(priming): placa com hífen, chassi, +55, ...`)
- **Data:** 2026-10-29
- **Máquina:** macOS arm64, Chrome 156.0.8078.73, sem rede externa (Chrome restrito a 127.0.0.1).
- **Dados:** sintéticos; HARs reais só em agregados, lidos em modo somente leitura (temporários 0700 apagados).

## Critério 9 — feito AO VIVO nesta rodada
`tests/capture/run-cycle.sh live-final` rodou o ciclo real (Chrome + testserver h1/h2/h3, CDP + NetLog) no HEAD acima
e `run_acceptance.py --capture tests/capture/runs/live-final` o consumiu — não é replay da captura antiga.
Captura: 2 pernas, 27 requisições, 4 ambíguas, 6 redirects, 14 streams h3; HAR nativo importado: 15 requisições (complete);
nenhum certificado instalado. `initiator` nos eventos CDP crus: presente (19 eventos em h1h2, tipo `other`);
o Core ainda mexe no iniciador em paralelo — qualquer divergência na sessão importada é esperada até o commit dele.
(O diretório `runs/live-final` fica fora do git, 12 MB; a cópia estável está em `tests/results/capture-latest/`.)

## Placar
| Bateria | Resultado |
|---|---|
| run_acceptance (10 critérios, com captura ao vivo) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 asserções, 0 falhas) |
| check_bodies_search | OK, 5 casos |
| check_chain_compare | OK |
| check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK |
| tests/exportacao (cargo test) | 19 passaram, 0 falhas |
| cargo test core | 250 passaram, 0 falhas (1 ignorado) |
| cargo test src-tauri | 42 passaram, 0 falhas (6 ignorados) |
| check_real_detran (H1, H2, H3) | OK: STAMP e delta 100%, 0 placas após sanitize |
| check_real_priming (H1, H2, H3) | OK: params_required = [sessionid_cliente, placa], 0 literais capturados |

Resultado: **tudo verde, 0 falhas.**

## Nota de execução
O primeiro passe da bateria rodou com `core/target/release` mais antigo que `core/src` e `check_real_detran`/`check_real_priming`
recusaram (rc 1); depois de `cargo build --release` a bateria inteira foi repetida e é a que consta acima.

## Rodada 8 — adaptador Natural for Ajax

- **HEAD testado:** dc14ac3 (`feat(priming): event/page/model do cabeçalho são estrutura do protocolo no modo estrito`)
- **Data:** 2026-10-29
- **Build:** `core` e `adapters/natural-ajax` (natural-core) recompilados em release antes da bateria.
- **Dados:** sintéticos; HARs reais só em agregados (H1/H2/H3), temporários apagados.

| Bateria | Resultado |
|---|---|
| run_acceptance (captura ao vivo da rodada final, `live-final`) | 10/10 OK |
| check_bodies_search | OK, 5 casos |
| check_chain_compare | OK |
| check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK |
| check_natural_adapter (detran-sim `strict`) | OK: (a) controle sem adaptador falha; (b) com adaptador 2 sessões completas; (c) round-trip 0 divergências |
| prove_strict (adapters/natural-ajax/scripts) | OK, `fails: []` |
| tests/exportacao | 19 passaram, 0 falhas |
| cargo test core / src-tauri / natural-ajax | 259 / 45 / 28 passaram, 0 falhas |
| check_real_detran (H1, H2, H3) | OK |
| check_real_priming sem `--wrapper` | OK |
| check_real_priming com `--wrapper` (natural-core) | OK: alvo com resposta anterior capturada gera script com `natural_ajax_encode`; "primeiro" de H2/H3 segue recusado (respostas sem corpo) |

Resultado: **tudo verde, 0 falhas.** O critério 9 do run_acceptance usa a captura ao vivo de 2026-10-29 (`live-final`); não foi refeita nesta rodada.

## Rodada 10 — captura multi-alvo

- **HEAD testado:** d60c1ae (`Pipeline CDP setup for paused targets before runIfWaitingForDebugger`)
- **Data:** 2026-10-30
- **Build:** worktree limpo em d60c1ae; `core`, `testserver` e `adapters/natural-ajax` recompilados em release.
- **Dados:** sintéticos; HARs reais (H1–H3) só em agregados.

### Aceite multi-alvo — 5 rodadas

`python3 tests/aceite/check_multi_target.py --port 891N` numa captura real do produto
(`capture::run` via `live_bodies_cycle`, Chrome headless, página `testserver /multi/`).

| Rodada | Porta | NetLog | CDP | `blank-1` no CDP | `oopif-get`/`oopif-post` | Colisões de `requestId` | Requisições | Falhas |
|---|---|---|---|---|---|---|---|---|
| 1 | 8912 | 16/16 | 16/16 | ✓ (com `requestWillBeSent`) | iframe / iframe | 4 | 30 | 0 |
| 2 | 8913 | 16/16 | 16/16 | ✓ | iframe / iframe | 4 | 30 | 0 |
| 3 | 8914 | 16/16 | 16/16 | ✓ | iframe / iframe | 4 | 33 | 0 |
| 4 | 8915 | 16/16 | 16/16 | ✓ | iframe / iframe | 4 | 33 | 0 |
| 5 | 8916 | 16/16 | 16/16 | ✓ | iframe / iframe | 4 | 33 | 0 |

- `blank-1` só entra na contagem porque tem `Network.requestWillBeSent` real — o check não conta
  `responseReceived` nem NetLog para o critério do CDP.
- `oopif-1` (documento do iframe) é reportado na sessão do alvo pai e o check aceita
  `page`/`iframe`; `oopif-get-1` e `oopif-post-1` vêm com `target.kind = iframe`, sem
  reatribuição por frameId.
- Colisão de `requestId` entre sessões existe nas 5 rodadas (4 ids em 3 sessões cada); as
  observações continuam requisições distintas no modelo.
- Service worker: duas observações ligadas por `links` com `resolution: "ambiguous"` e
  evidência registrada (mesma URL/método, sessão do SW, Δt=0 como pista); nada de duplicata
  silenciosa.
- O driver do check agora compila o binário de teste antes (`cargo test --no-run`) e espera
  até 120 s pelos marcadores / 300 s pelo fim da captura; sem isso um build frio estourava o
  prazo e matava a captura antes de começar.

### Bateria completa (nada regrediu)

| Bateria | Resultado |
|---|---|
| run_acceptance (10 critérios) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 asserções) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 casos / OK / OK) |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK |
| prove_strict (adapters/natural-ajax) | OK, `fails: []` |
| tests/exportacao | 19 passaram, 0 falhas |
| cargo test core / src-tauri / natural-ajax | 302 / 48 / 32 passaram, 0 falhas (1 / 8 / 0 ignorados) |
| check_real_detran (H1–H3) | OK |
| check_real_priming sem / com `--wrapper` (H1–H3) | OK / OK |
| ciclo real de uma aba (`live_bodies_cycle`) | OK: 3030 eventos CDP+NetLog, sessão importada com 5 avisos |

Resultado: **tudo verde, 0 falhas.** Saída por rodada em
`tests/results/multi-target-rodada10.json`; última captura em `tests/results/multi-target.json`.

## Rodada 9, onda B — bundle final, plano versionado e `parameters`/`plan.parameters` sem isenção indevida

- **HEAD testado:** bf0a41b (`build(app): bundle recompilado no HEAD 7410fa4 (plan.parameters só com plano verificado)`)
- **Data:** 2026-10-29
- **Build:** `core` e `adapters/natural-ajax` (natural-core) recompilados em release antes da bateria.
- **Bundle aceito:** `d1136cbbedf32a3a9d73504196be35db1aa8885b4e6f9250a197672d477b7c1f`
  (16.384.352 bytes, arm64, ad-hoc), conferido por `shasum -a 256` no executável do `.app`; `tests/aceite/run_acceptance.py`
  (`EXPECTED_APP_SHA256`) e `src-tauri/EMPACOTAMENTO.md` apontam o mesmo hash.
- **Dados:** sintéticos; HARs reais (H1–H3) só em agregados.

| Bateria | Resultado |
|---|---|
| run_acceptance (10 critérios, com `app-latest`) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 asserções, 0 falhas) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 casos / OK / OK) |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK; `hashlib` proibido (o script usa `PLAN_HASH`); `os` só em `trace_*`; 12 corridas não vazias por variante |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK, com `plan.version`, fuga de `parameters` e plano não verificado (abaixo) |
| prove_strict (adapters/natural-ajax) | OK, `fails: []` |
| tests/exportacao | 19 passaram, 0 falhas |
| cargo test core / src-tauri / natural-ajax | 298 / 48 / 32 passaram, 0 falhas (1 / 8 / 0 ignorados) |
| check_real_detran (H1–H3) | OK |
| check_real_priming sem / com `--wrapper` (H1–H3) | OK / OK |

**Ciclo real do app refeito no bundle final.** `Iniciar sessão` → `Encerrar` no `ScrapeLens.app` d1136cbb:
captura `capture-1793302372326`, 11 requisições, `complete`, `cdp+netlog`, 2 ambíguas, 154 headers verificados,
14 linhas no testserver h1; HAR e NetLog reimportados pela UI no mesmo bundle (`har-3dbc391c02a985c5-5`, 24 requisições
complete, e `netlog-1704043c442dcbd1-5`, 32 requisições partial). Prints novos em
`tests/results/app-latest/screenshot-app-live.png` e `screenshot-app-imports.png`; `run.json` regenerado por
`tests/capture/app_validate.py` (bundle novo, sessões novas, `testserver/app-20261029c`).

**Plano versionado (`plan.version` 2) no `check_timeline_validacao`:**
- trace fiel gerado pelo script atual declara `plan.version: 2` → `equivalent`, ZERO avisos de parâmetro ou de plano;
- `plan.version` ausente → `equivalent` + aviso "plano de versão anterior (v1): gere o script de novo…", sem divergir;
- `plan.version: 2` com o `PLAN_HASH` de outro alvo da MESMA captura (har-0030, `26fdb4657a22511f`) → `diverges`
  no passo 1, "plano diferente do gerado a partir desta captura" (não ficou em aviso).

**Fuga de `parameters` (39410bf): a isenção vale só para o par (name, part) que o plano produz.**
Sobre a trace autêntica do detran-sim (captura `real-shape-1round`, alvo har-0026; delta capturado `DLTC0005`,
STAMP `4105`), com o par forjado sob um nome do plano:
- delta congelado + `{cpf → XML.delta}` → `diverges` no passo 10, "valor congelado: igual ao capturado e ausente da resposta pareada";
- delta inventado + o mesmo item → `diverges`, "valor sem origem no trace";
- STAMP congelado ou inventado + `{cpf → STAMP}` → `diverges` nos dois, com "valor congelado" e "sem origem";
- `{sessionid_cliente → sig}` → só aviso "parâmetro não corresponde ao plano: sessionid_cliente → sig", `equivalent`;
- trace fiel → `equivalent`, nenhum aviso além do de origem mapeada.

**`plan.parameters` só isenta com plano verificado (7410fa4 — L13–L15, N1/N3).**
Na mesma trace autêntica, `plan.parameters += "XML.delta"` com o plano não verificado:
- v1 (`plan.version: 1`) + delta congelado ou inventado → `diverges` no passo 10 ("valor congelado" / "valor sem origem");
- sem `plan.version` + delta congelado ou inventado → `diverges`, mesmos motivos;
- v2 sem `plan.hash` + delta congelado ou inventado → `diverges`, mesmos motivos (aviso "plano sem impressão");
- nas três variantes, a trace sem valor trocado fica `equivalent` (o `XML.delta` do plano passa a gerar
  "parâmetro inválido: `XML.delta` tem origem na captura", provando que não foi isentado);
- v1 fiel (sem o item de `plan.parameters`) → `equivalent`, só com o aviso "plano de versão anterior (v1)".

Resultado: **tudo verde, 0 falhas.** O critério 9 do run_acceptance usa `tests/results/app-latest` regenerado nesta
rodada; a captura `live-final` de 2026-10-29 segue como evidência do ciclo CDP/NetLog do `run-cycle.sh`.

## Rodada 9 — linha do tempo e validação da execução

- **HEAD testado:** a37cd60 (`feat(priming): plan.hash calculado na geração por validate::plan_hash (sem hashlib no script)`)
- **Data:** 2026-10-29
- **Build:** `core` e `adapters/natural-ajax` (natural-core) recompilados em release antes da bateria.
- **Dados:** sintéticos; HARs reais só em agregados.

| Bateria | Resultado |
|---|---|
| run_acceptance (captura ao vivo `live-final`) | 10/10 OK |
| check_bodies_search / check_chain_compare / check_real_shape | OK |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK; `hashlib` volta a ser proibido (import falha); `os` só em `trace_*`; 12 corridas não vazias por variante (completed com POSTs>0 ou falha declarada `priming:`) |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK: timeline com `event @ page` (incl. `init`) e proteção recolhida; validate equivalent/diverges nos 4 modos do sim; trace 0600 + sanitize; casos do revisor V1–V18 com o motivo esperado |
| prove_strict (adapters/natural-ajax) | OK |
| tests/exportacao | 19 passaram |
| cargo test core / src-tauri / natural-ajax | 292 / 47 / 31 passaram, 0 falhas |
| check_real_detran (H1–H3) | OK |
| check_real_priming sem / com `--wrapper` (H1–H3) | OK / OK |

Resultado: **tudo verde, 0 falhas.** Critério 9 do run_acceptance segue com a captura ao vivo de 2026-10-29 (`live-final`), não refeita nesta rodada.
