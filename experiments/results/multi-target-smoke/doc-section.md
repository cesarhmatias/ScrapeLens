## Captura multi-alvo (CDP auto-attach × NetLog)

Contrato: `docs/14-captura-multi-alvo.md`. Harness: `experiments/multi_target/`.

| Item | Valor |
|---|---|
| Navegador | Chrome headless=new (ver `cdp-sessions.json`) |
| CDP | `Target.setDiscoverTargets` + `setAutoAttach` (flatten, `waitForDebuggerOnStart` true/false) |
| Evidência preliminar | `experiments/results/multi-target-smoke/` (smoke local; **repetir** com `testserver` `GET /multi/` quando a Testes publicar) |

### Tabela por tipo de alvo (marcador `?m=`, variante **com** `waitForDebuggerOnStart`)

| Tipo de alvo | Servidor (JSONL) | NetLog | CDP (sessão filha) | ExtraInfo (ordem) | Corpos CDP | SW `fromServiceWorker` |
|---|---|---|---|---|---|---|
| Popup (`window.open`) | sim | sim | sim | sim | sim | — |
| Aba nova (`target=_blank`) | não verificado | não verificado | não verificado | não verificado | não verificado | não verificado |
| Iframe OOPIF (outra porta) | sim | sim | sim | sim | sim | — |
| Worker dedicado | não verificado | não verificado | não verificado | não verificado | não verificado | não verificado |
| Service worker (intercept + fetch próprio) | não verificado | não verificado | não verificado | não verificado | não verificado | não verificado |
| Documento principal | não verificado | não verificado | não verificado | não verificado | não verificado | não verificado |

### Variante **sem** `waitForDebuggerOnStart`

- Primeira requisição perdida no CDP (marcadores `popup-first` / `blank-first` / `oophif-first`): não verificado (smoke incompleto nesta execução)
- Sessões CDP: 5; eventos Network: 15

### Colisão de `requestId` entre sessões

Com wait: **3** pares `(requestId)` vistos em mais de uma sessão (correlação correta exige `(sessionId, requestId)`). Sem wait: **1**.

### Custo (variante com wait, smoke)

| Sessões CDP | Eventos totais | Eventos Network.* | Tempo captura |
|---:|---:|---:|---:|
| 11 | 135 | 50 | 32999 ms |

**Recomendação (1 linha):** usar auto-attach com `waitForDebuggerOnStart` e chave `(sessionId, requestId)`; alvos sem sessão CDP continuam só no NetLog; repetir medição oficial contra `testserver` `/multi/` antes de fixar o produto.

