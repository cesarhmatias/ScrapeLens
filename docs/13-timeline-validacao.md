# Rodada 9 — linha do tempo da aplicação e validação da execução

## Motivo

Caso DETRAN-PB, requisitos 8 e 10 (`docs/05-caso-referencia-detran.md`):
- ver o ciclo de eventos da aplicação (init, on_interceptor, cmd_filtro,
  cmd_consultar_placa, cmd_nova…) numa linha do tempo, sem o ruído da
  proteção;
- validar o script exportado comparando, lado a lado, uma execução dele com
  a captura.

O ScrapeLens nunca executa o script nem faz rede. Quem executa é o usuário
(ou o agente de Testes, contra o detran-sim em 127.0.0.1).

## Ondas e propriedade

| Dono | Caminhos |
|---|---|
| Core | `core/` (timeline, importador do trace) |
| Captura | `core/src/export/priming.rs`, `adapters/natural-ajax/` (opção `--trace` no script) |
| Testes | `testserver/`, `tests/`, `fixtures/` |
| App | `app/`, `src-tauri/src/commands.rs`, `lib.rs` |

## 1. Linha do tempo (core)

`timeline(session, body_source, opts) -> Timeline`, com uma entrada por
requisição da aplicação, na ordem da sessão:
- tempo relativo e rodada;
- tipo: página, POST da aplicação, recurso estático ou proteção;
- rótulo: com adaptador, o `event` e a `page` das partes do `XML`
  (`cmd_consultar_placa @ VES0009X`); sem adaptador, método + caminho;
- veredito do assess;
- valores-chave consumidos/produzidos, só nomes (`STAMP`, `XML.delta`).
Proteção e estáticos entram recolhidos em grupos com contagem, entre os
eventos da aplicação. CLI: `timeline <sessao>` (JSON) e, no natural-core,
`timeline --adapter natural-ajax`.

## 2. Trace de execução (script) e importação

- O script de priming ganha `--trace <arquivo>`. Ele grava um JSON
  `scrapelens.trace/1` com, por passo: método, URL, headers e corpo
  enviados, status, headers e corpo recebidos (com limite de tamanho e
  estado truncated), tempos e o resultado das verificações do passo. O
  arquivo é criado com 0600 e um aviso: "contém dados da sua sessão; não
  compartilhe sem sanitizar".
- Core: `import-trace <trace.json> --out <sessao>` importa como sessão
  (rótulo `script-trace`, fonte "execução do script", headers sem garantia
  de ordem do fio), com corpos e assess. A sanitização funciona sobre ela
  como sobre qualquer sessão.

## 3. Validação lado a lado (app e CLI)

- `compare <captura> <sessao-do-trace>` já funciona. A tela "Validar
  execução" pareia passo a passo e mostra:
  - o que mudou (dinâmico esperado: STAMP, delta, SESSIONID);
  - o que deveria ser igual e não é (constantes, ordem de passos);
  - o veredito do assess em cada lado.
  Resumo: "execução equivalente à captura" ou "diverge no passo N
  (<motivo>)".
- A timeline das duas sessões fica lado a lado.

## Aceite

1. Timeline da fixture real-shape (1 e 2 rodadas) e dos 3 HARs reais
   (agregado): os eventos da aplicação aparecem na ordem do fluxo manual,
   com rótulos `event @ page` via adaptador, e a proteção fica recolhida.
2. Script contra o detran-sim com `--trace`; import-trace; compare com a
   captura (real-shape): passos pareados 1:1, só os dinâmicos esperados
   diferem, assess app-ok em todos; resumo "equivalente".
3. Modos error/nocontrols/403 do sim: o trace termina no passo ruim, e a
   validação aponta "diverge no passo N" com o veredito certo.
4. O trace tem 0600 e o aviso; sanitize sobre a sessão do trace remove
   SESSIONID/cookies/placa.
5. Bateria sem regressão.

## Revisão da rodada 9 (2026-10-29) — decisões

Veredito: reprovado para fechar; o trace é seguro, mas o `validate` dá
falso "equivalente". Princípios do validate:
- Proveniência equivalente: para cada campo que na captura tinha origem na
  resposta R_k, o valor no trace tem de estar na resposta pareada de R_k
  dentro do trace. Valor igual ao capturado com produtor diferente no trace
  → "diverge (valor congelado)". Valor vindo de outra resposta → "diverge
  (origem diferente)".
- Completude: o script grava `target` (o requestId do alvo na captura) e
  `complete` (bool). O validate exige o alvo pareado e `complete=true`; senão
  dá "incompleta".
- `parameters` só vale para campos SEM origem na captura e que não sejam
  constantes. Um campo com origem ou constante declarado como parâmetro é
  ignorado e gera aviso "parâmetro inválido". O script também grava a
  impressão do plano (hash dos passos e nomes dos parâmetros); o validate
  recalcula a partir da captura e avisa quando não confere.
- "Identificador gerado no cliente" só quando a captura marca o campo como
  sem origem com composição/cliente; uma constante (repetida na captura ou
  estática) que muda é divergência.
- Mapeamento automático de origem só para loopback (127.0.0.1, ::1,
  localhost). Outro host exige `--map-origin` explícito, e o resumo cita o
  mapeamento.
Outros:
- Timeline com custo O(n log n): 4 mil requisições < 2 s, e a sessão grande
  de 20 mil termina.
- Script: erro de transporte grava o trace com `error` no passo; `--trace ""`
  é erro; argv inválido falha antes de rodar.
- import-trace: limite de 20 mil passos e de headers por passo, e memória
  reduzida. Corpo de requisição em base64 é aceito. URL/`startedAt` são
  validados.
- App: a sessão importada do trace vive em pasta temporária apagada ao
  fechar a validação, a não ser que o usuário peça para guardá-la.
- check_priming_injection exige rc e POSTs > 0 por variante (ou a falha
  esperada no passo declarado).
