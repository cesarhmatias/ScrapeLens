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

## Rodada 9, onda B — bundle final, plano versionado e `parameters` sem isenção indevida

- **HEAD testado:** 0d28d04 (`build(app): bundle recompilado no HEAD 39410bf (isenção de parameters por (name, part))`)
- **Data:** 2026-10-29
- **Build:** `core` e `adapters/natural-ajax` (natural-core) recompilados em release antes da bateria.
- **Bundle aceito:** `a4fe000af5e94a1a25c4146b2e58e94cdc410268850c2ee341429e01dbe313e9`
  (16.371.376 bytes, arm64, ad-hoc), conferido por `shasum -a 256` no executável do `.app`; `tests/aceite/run_acceptance.py`
  (`EXPECTED_APP_SHA256`) e `src-tauri/EMPACOTAMENTO.md` apontam o mesmo hash.
- **Dados:** sintéticos; HARs reais (H1–H3) só em agregados.

| Bateria | Resultado |
|---|---|
| run_acceptance (10 critérios, com `app-latest`) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 asserções, 0 falhas) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 casos / OK / OK) |
| check_priming_sim | OK (ok 2×, error, nocontrols, 403) |
| check_priming_injection | OK; `hashlib` proibido (o script usa `PLAN_HASH`); `os` só em `trace_*`; 12 corridas não vazias por variante |
| check_natural_adapter (sim `strict`) | OK |
| check_timeline_validacao | OK, com `plan.version` e os casos de fuga de `parameters` (abaixo) |
| prove_strict (adapters/natural-ajax) | OK, `fails: []` |
| tests/exportacao | 19 passaram, 0 falhas |
| cargo test core / src-tauri / natural-ajax | 297 / 48 / 32 passaram, 0 falhas (1 / 8 / 0 ignorados) |
| check_real_detran (H1–H3) | OK |
| check_real_priming sem / com `--wrapper` (H1–H3) | OK / OK |

**Ciclo real do app refeito no bundle final.** `Iniciar sessão` → `Encerrar` no `ScrapeLens.app` a4fe000a:
captura `capture-1793300173556`, 11 requisições, `complete`, `cdp+netlog`, 2 ambíguas, 154 headers verificados,
14 linhas no testserver h1; HAR e NetLog reimportados pela UI no mesmo bundle (`har-3dbc391c02a985c5-4`, 24 requisições
complete, e `netlog-1704043c442dcbd1-4`, 32 requisições partial). Prints novos em
`tests/results/app-latest/screenshot-app-live.png` e `screenshot-app-imports.png`; `run.json` regenerado por
`tests/capture/app_validate.py` (bundle novo, sessões novas, `testserver/app-20261029b`).

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
- Em todos os casos de fuga o aviso "parâmetro não corresponde ao plano: <name> → <part>" também aparece; nada ficou em aviso.

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
