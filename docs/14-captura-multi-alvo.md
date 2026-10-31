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

## Resultado da onda 1 (Captura, 9a6021d/5d46a8a)

Chrome 156.0.8078.74, headless e headful, receita: `Target.setAutoAttach
{autoAttach, waitForDebuggerOnStart, flatten}` na sessão da página E em cada
sessão filha recebida em `Target.attachedToTarget`, depois `Network.enable`
nela e `Runtime.runIfWaitingForDebugger`. Resultado: página, popup, OOPIF,
worker dedicado e service worker com rede CDP no `sessionId` do alvo. Limite
do Chrome: documento de aba aberta por `target=_blank` só tem
`responseReceived` na sessão filha (sem `requestWillBeSent`); o NetLog cobre.
Sem `waitForDebuggerOnStart` perde-se metade dos marcadores. `requestId`
colide entre sessões. Ordem do ExtraInfo não é a do fio (sem mudança na
matriz).

## Onda 2 — contrato de implementação (decisão do líder)

Gravação (`src-tauri/src/capture.rs`, dono: Captura):
- Receita acima, recursiva, com fila de comandos por sessão; `browser_ui` e
  alvos não-rede ignorados. Alvo que não anexar fica registrado como tal.
- `cdp-events.jsonl`: toda linha ganha `sessionId` (string; a sessão da
  página inicial também tem o seu). Os eventos `Target.attachedToTarget`,
  `Target.detachedFromTarget` e `Target.targetInfoChanged` são gravados.
- `cdp-bodies.jsonl`: cada linha ganha `sessionId`.
- Captura sem eventos de nenhum alvo continua erro; alvo que falhou ao anexar
  vira aviso, não erro.

Modelo e importação (`core/`, dono: Core):
- Chave da requisição CDP: (`sessionId`, `requestId`); corpos mapeados por
  (`sessionId`, `requestId`, `attemptIndex`). Arquivo antigo sem `sessionId`
  = uma sessão implícita (compatível com as sessões já gravadas).
- Proveniência por requisição: `targetId`, tipo (`page`, `iframe`, `worker`,
  `service_worker`, `shared_worker`, outro), URL do alvo e `openerId`
  /sessão pai, a partir dos eventos Target.
- Requisição interceptada pelo service worker aparece em duas sessões: as
  duas observações ficam ligadas como a mesma requisição lógica só com
  evidência explícita (ex.: `fromServiceWorker`, mesma URL/método e
  janela de tempo como pista, nunca prova); sem evidência suficiente,
  ambiguidade registrada.
- Correlação com NetLog: a requisição do NetLog sem par CDP continua
  NetLog-only, com o tipo do alvo desconhecido; o documento do `_blank`
  (só `responseReceived`) liga ao NetLog se a evidência permitir, senão
  fica parcial com nota.

Aceite (`tests/`, dono: Testes), sobre `testserver /multi/` com a captura
REAL do produto (não o harness do experimento):
- 16/16 marcadores no NetLog; ≥ 15/16 com CDP (exceção esperada: documento
  `blank-1`), cada um com o tipo de alvo certo;
- POSTs com corpo de requisição e resposta iguais ao `body_sha256` do
  servidor, por tipo de alvo;
- nenhuma requisição fundida entre sessões por `requestId` igual;
- sw-intercept: duas observações ligadas ou ambiguidade explícita, nunca
  duplicata silenciosa;
- sessões ao vivo antigas e fixtures atuais importam sem mudança de
  resultado (aceites existentes verdes).

Interface (App) fica para a onda 3: filtro/coluna de alvo e aviso de limite.

## Teste manual do usuário (2026-10-30)

Captura de várias abas no bundle final 02e6ef30… (HEAD 8cfe828, commit 18cbb01): APROVADO pelo usuário ("aprovado").

## Fechamento da rodada 10 (2026-10-31)

APROVADA COM RESSALVAS BAIXAS (revisor, HEAD 9f4003b; /tmp/rev24/VEREDITO.md).
Bundle de referência: 7a46fa4c52ca90d2d720edcd1fe6b39da8bf390968bbd667952bb376005d2b7c
(commit 0d98615). Aceite multi-alvo 5/5 (Testes) e 3/3 (revisor): 16/16 NetLog
e CDP, 0 avisos de setup, SW sem cópias, ligação ao SW sempre "não confirmada"
e só ao candidato de mesmo método/caminho; 9 mutações do autoteste reprovam.
Decisões finais:
- Primária = primeira sessão por targetId; duplicatas: resume + detach.
- Setup em pipeline sem bloqueio; comando sem resposta só vira aviso no
  encerramento, em qualquer sessão; erro de comando essencial = aviso
  `cdp.target_setup_error`; alvo encerrado = nota, sem aviso.
- Ligação página↔SW: sempre `ambiguous`, mesmo método, preferência por mesmo
  caminho; `linked` só com evidência explícita do CDP.
- Arquivo sem eventos Target.* = sem proveniência de alvo (sessões antigas).
Ressalvas baixas FECHADAS: run_acceptance recalcula o hash do bundle em disco (05f586b); limpeza de Chrome/perfil órfão na partida (8fd4f6d, b684c1a). Bundle final b3e12edcfecd78ec703fa31ba2a53096a21a2e440617b148a8ce34b05c6b5157 (0be3bc0). Texto original: run_acceptance não recomputa o hash do
bundle em disco; Chrome/perfil órfão quando o processo pai é morto por SIGKILL
(sem limpeza na partida).
