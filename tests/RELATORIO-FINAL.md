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

## Rodada 10 — captura multi-alvo (rodada oficial final, bundle definitivo)

- **HEAD testado:** 0d98615 (captura em f1493ab, core em 66e97e3, bundle em 0d98615)
- **Data:** 2026-10-31
- **Build:** `core`, `testserver` e `adapters/natural-ajax` recompilados em release antes da bateria.
- **Bundle aceito:** `7a46fa4c52ca90d2d720edcd1fe6b39da8bf390968bbd667952bb376005d2b7c` (16.582.144 bytes, arm64, ad-hoc, binário único),
  conferido por `shasum -a 256` e pelo caminho do processo em execução; `EXPECTED_APP_SHA256` em `tests/aceite/run_acceptance.py` aponta o mesmo hash.
- **Dados:** sintéticos; HARs reais (H1–H3) só em agregados.

### Aceite multi-alvo — 5 rodadas com `--self-test`

`python3 tests/aceite/check_multi_target.py --port 896N --self-test` (captura real do produto, Chrome headless, `testserver /multi/`).

| Rodada | NetLog | CDP | Requisições | SW por `targetId` | Link página↔SW | `attachFailed` | avisos `target_setup_timeout`/`setup_error` | Autoteste | Falhas |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0014 ↔ cdp-r0016 `ambiguous`, mesmo caminho | 0 | 0 | 9/9 como esperado | 0 |
| 2 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0004 ↔ cdp-r0013 `ambiguous`, mesmo caminho | 0 | 0 | 9/9 como esperado | 0 |
| 3 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0010 ↔ cdp-r0016 `ambiguous`, mesmo caminho | 0 | 0 | 9/9 como esperado | 0 |
| 4 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0014 ↔ cdp-r0019 `ambiguous`, mesmo caminho | 0 | 0 | 9/9 como esperado | 0 |
| 5 | 16/16 | 16/16 | 22 | 1 + 1 | cdp-r0012 ↔ cdp-r0018 `ambiguous`, mesmo caminho | 0 | 0 | 9/9 como esperado | 0 |

- **Critério 6 endurecido:** o `sw-intercept-1` da página tem de estar ligado ao candidato de mesmo método e mesmo caminho (`/multi/sw-fetch`) e a nenhum `sw-own-*`;
  link para `sw-own-*` reprova (`links_para_sw_own` registrado). Nas 5 rodadas: `links_para_sw_own` vazio e o link é só com o `sw-fetch` do SW
  (evidência "possível correspondência no service worker (pista: janela de tempo, origem, caminho); não confirmada").
- **Critério novo:** qualquer aviso `cdp.target_setup_timeout`, `setup_error` ou `setup_aborted` na captura ao vivo reprova. As 5 rodadas: 0 avisos (nas anteriores eram 1–2 por rodada).
- **9 mutações do autoteste** (esperado → obtido, iguais nas 5): fusão de dois pares FAIL→FAIL; links do SW removidos FAIL→FAIL; `kind` trocado FAIL→FAIL; corpo alterado FAIL→FAIL;
  cópia de SW na mesma sessão FAIL→FAIL; cópia de SW em outra sessão do mesmo `targetId` FAIL→FAIL; **`sw-intercept` ligado a `sw-own-*` FAIL→FAIL (nova)**;
  colisão injetada separada PASS→PASS; colisão injetada fundida FAIL→FAIL.
- **Defeito meu achado pelo próprio autoteste:** a primeira versão do critério endurecido parava no primeiro link válido (`break`) e deixava passar um segundo link para `sw-own-*`;
  o autoteste reprovou nas 5 rodadas ("NÃO falhou"), corrigi o laço e refiz as 5.
- **Rodada 1 descartada uma vez:** um `testserver` órfão na porta 8961 (de uma execução que eu interrompi) respondeu no lugar do servidor da rodada ("POST não chegou ao servidor");
  foi causa do harness, não da captura. Servidor morto, rodada refeita em outra porta: OK.

Saída por rodada em `tests/results/multi-target-rodada10-final.json`; última captura em `tests/results/multi-target.json`.

### Bateria completa (HEAD 0d98615)

| Bateria | Resultado |
|---|---|
| run_acceptance (10 critérios, com `app-latest` do bundle novo) | 10/10 OK (29+26+19+12+16+14+23+19+118+7 asserções, 0 falhas) |
| check_bodies_search / check_chain_compare / check_real_shape | OK (5 casos / OK / OK) |
| check_priming_sim / check_priming_injection | OK / OK |
| check_natural_adapter (sim `strict`) / check_timeline_validacao / prove_strict | OK / OK / OK |
| tests/exportacao | 19 passaram, 0 falhas |
| cargo test core / src-tauri / natural-ajax | 316 / 52 / 32 passaram, 0 falhas (1 / 8 / 0 ignorados) |
| check_real_detran (H1–H3) | OK |
| check_real_priming sem / com `--wrapper` (H1–H3) | OK / OK |
| ciclo real de uma aba (`live_bodies_cycle`) | OK, exercitado 5× (+1) pelo check multi-alvo |

Resultado: **tudo verde, 0 falhas.**

### Ciclo real no bundle definitivo

`ScrapeLens.app` (`7a46fa4c…05d2b7c`): **Iniciar sessão** → `testserver` h1 em `127.0.0.1:8781/page` → **Encerrar**.
Captura `capture-1793454692088`: 11 requisições, `complete`, `cdp+netlog`, 2 ambíguas, 154 headers verificados, 14 linhas no testserver h1
(`tests/results/app-latest/testserver/app-20261031a`). HAR e NetLog reimportados pela UI (`har-3dbc391c02a985c5-7`, 24 requisições, `complete`;
`netlog-1704043c442dcbd1-7`, 32 requisições, `partial`). O painel nativo "Open" é instável sob automação; o HAR foi escolhido por clique e o NetLog por teclado (seta + Return).
**Incidente:** com o Brave do usuário em primeiro plano, alguns cliques de tela meus (coordenadas de desktop) caíram nele e navegaram uma aba para uma página do Ratos de IA;
nada foi enviado ou alterado além da navegação/rolagem. Cópias sintéticas temporárias em `~/Desktop` removidas. Prints em `tests/results/app-latest/`.


### Bundle final (fechamento)

- **Bundle final:** `b3e12edcfecd78ec703fa31ba2a53096a21a2e440617b148a8ce34b05c6b5157` (App b684c1a, `capture::cleanup_orphans` no setup), HEAD de origem b684c1a; `EXPECTED_APP_SHA256` e `app-latest` atualizados; o item 9 recalcula o hash em disco. Ciclo real refeito só por AX e teclado, sem cliques de desktop (`capture-1793456763837`: 11 req, complete, cdp+netlog; HAR `-8` 24 req complete; NetLog `-8` 32 req partial). run_acceptance 10/10 (item 9: 121 asserções), check_multi_target --self-test OK (9/9 mutações como esperado, 0 avisos de setup), cargo test core 316 / src-tauri 59 / natural-ajax 32, 0 falhas.

- **Bundle com assinatura estável (c2d2b8f):** SHA `1901f3b499bbf4e946aa7b995ab70cad5027d25087ccbbe6d282302d5b94605a`, identidade local "ScrapeLens Local Signing"; `EXPECTED_APP_SHA256` e `app-latest` atualizados. O item 9 aceita ad-hoc ou identidade local e exige `codesign --verify --deep --strict` (registrado no run.json e recalculado em disco). Ciclo real refeito por AX e teclado (`capture-1793464319852`: 11 req, complete; HAR `-9` 24 req; NetLog `-9` 32 req partial). run_acceptance 10/10 (item 9: 123 asserções).

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
