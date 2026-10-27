# tests/ — aceite do MVP ScrapeLens

Bateria que consome o **CLI do core** (`core/target/release/scrapelens-core`), as
fixtures sintéticas de `fixtures/aceite/` e, no critério 9, uma captura real de
Chrome no macOS orquestrada por `tests/capture/run-cycle.sh`.

## Comandos

```sh
python3 tests/aceite/fixtures.py              # regenera fixtures/aceite (determinístico)
python3 tests/aceite/run_acceptance.py       # 10 critérios; usa a última captura registrada
tests/capture/run-cycle.sh                   # ciclo real Chrome/CDP/NetLog h1+h2+h3
python3 tests/capture/app_validate.py --run-dir tests/capture/runs/app-<id> \
  --capture-id capture-<ts> --har-id har-<id> --netlog-id netlog-<id> \
  --screenshot tests/results/app-latest/screenshot-app-live.png
python3 tests/aceite/run_acceptance.py --capture tests/capture/runs/<id>
```

Resultados: `tests/results/aceite.json` e o relatório `tests/RELATORIO.md`
(promovível a `docs/05-aceite.md`). Código de saída ≠ 0 se algum critério falhar.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `aceite/fixtures.py` | gerador das fixtures sintéticas (HAR, NetLog, CDP e sessões v1) |
| `aceite/run_acceptance.py` | os 10 critérios, asserções e geração do relatório |
| `capture/capture_cycle.mjs` | Chrome dedicado + CDP + NetLog; sem certificado instalado, QUIC intacto |
| `capture/run-cycle.sh` | sobe testserver, captura h1/h2/h3, importa com o core e resume |
| `capture/summarize.py` | métricas da captura real em `run.json` |
| `capture/app_validate.py` | valida o ciclo ao vivo pelo `ScrapeLens.app` e as sessões HAR/NetLog que ele gravou |
| `.work/` | sessões pequenas da execução corrente (não commitado) |
| `capture/runs/` | sessões brutas da captura real (não commitado; regerável) |

O critério 9 cobre duas pernas: (a) captura própria do harness em h1/h2/h3 e
(b) o app empacotado (`src-tauri/target/release/bundle/macos/ScrapeLens.app`),
com Iniciar/Encerrar pela UI, sessão gravada pelo app e importações HAR/NetLog
reais. O resumo da perna (b) fica em `tests/results/app-latest/run.json`; o
harness o lê por padrão (ou via `--app-run`).

Tudo offline: domínios `.invalid`, servidores em `127.0.0.1`, Chrome com
`--host-resolver-rules` bloqueando o resto. Nenhuma telemetria; nada publicado.
As fixtures são 100% sintéticas e cada diretório traz `fixture.json` com
`label: synthetic-fixture`.
