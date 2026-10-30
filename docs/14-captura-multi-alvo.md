# Rodada 10 — captura multi-alvo (contrato inicial)

Data: 2026-10-29. Dono: líder. Princípio: provar a fidelidade antes de
implementar.

## Problema

A captura ao vivo acompanha um único target CDP. O NetLog vê o tráfego do
navegador inteiro, mas requisições de popups, abas novas (`window.open`,
`target=_blank`), iframes fora do processo (OOPIF, outra origem), workers
dedicados e service workers ficam sem headers/corpos CDP. Isso afeta a
correlação (especificação: "considere ... service workers").

## Onda 1 — experimento (sem código de produção)

Servidor de teste (Testes, `testserver/`): uma página que abre um popup
(`window.open`), um link `target=_blank`, um iframe de OUTRA origem (outra
porta em 127.0.0.1 e um nome em /etc/hosts não; use `localhost` × `127.0.0.1`
ou duas portas), um worker dedicado que faz `fetch`, e um service worker que
intercepta e faz `fetch` próprio. Cada requisição com marcador único na URL.

Experimento (Captura, `experiments/`): Chrome com NetLog + CDP via
`Target.setDiscoverTargets` e `Target.setAutoAttach {autoAttach, flatten:
true, waitForDebuggerOnStart: true}` (com `Runtime.runIfWaitingForDebugger`
depois de `Network.enable` em cada sessão filha), também aplicado
recursivamente nas sessões filhas. Medir, por tipo de alvo:
- requisições vistas pelo NetLog × pelo CDP (por marcador);
- se a primeira requisição do alvo novo é perdida sem `waitForDebuggerOnStart`;
- headers transmitidos (`requestWillBeSentExtraInfo`) e corpos
  (`getResponseBody`) disponíveis por sessão filha;
- `requestId` colide entre sessões? (chave = sessionId + requestId);
- requisições do service worker: aparecem no target do SW, na página, ou nos
  dois? `fromServiceWorker`/`serviceWorkerResponseSource` no response;
- custo: nº de sessões, eventos e tempo.

Saída: tabela em `docs/02-matriz-fidelidade.md` (nova seção) e evidência
em `experiments/`. Nenhuma alteração em `src-tauri/` ou `core/` nesta onda.

## Decisões já tomadas

- Chave de requisição CDP passa a ser (sessionId CDP, requestId); o targetId
  e o tipo de alvo ficam registrados como proveniência.
- Alvo não acompanhado continua visível só pelo NetLog, marcado como tal,
  nunca com headers inventados.
- O desenho final (core/app) só é fixado depois da tabela da onda 1.
