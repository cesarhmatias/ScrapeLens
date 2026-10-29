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
