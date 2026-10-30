# Captura multi-alvo (Rodada 10, onda 1)

Contrato: [`docs/14-captura-multi-alvo.md`](../../docs/14-captura-multi-alvo.md).

Harness Chrome + NetLog + CDP com `Target.setDiscoverTargets`, `Target.setAutoAttach`
(flatten, `waitForDebuggerOnStart` configurável) e `Network.enable` antes de
`Runtime.runIfWaitingForDebugger` em cada sessão filha.

## Reproduzir

Smoke local (até `testserver` expor `GET /multi/`):

```bash
cd experiments
python3 multi_target/run_multi.py --smoke --out results/multi-target-smoke
python3 multi_target/analyze_multi.py \
  --run results/multi-target-smoke/with-wait \
  --run-no-wait results/multi-target-smoke/no-wait \
  --out results/multi-target-smoke/analysis.json
```

Quando a Testes publicar `/multi/`:

```bash
python3 multi_target/run_multi.py --testserver --port 8781 --out results/multi-target
```

Saídas por variante (`with-wait`, `no-wait`):

- `cdp-events.jsonl`, `cdp-sessions.json`, `cdp-bodies.jsonl`
- `chrome-netlog.json`, `plan.json`, `server.jsonl`
- `analysis.json` (comparativo)
