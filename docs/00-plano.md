# ScrapeLens — Plano (vivo)

App open source macOS para inspeção de sessões HTTP para desenvolvedores de
scraping. Especificação completa:
`/Users/cesar/Documents/Codex/2026-10-26/meu-x20/outputs/ScrapeLens-especificacao.txt`

## Estado

- Fase: 9 — pacote local arm64 recompilado e validado; documentação final.
- Rodada de exportação na UI (docs/07) concluída: F1/F2 (links em ancestrais)
  corrigidos em 16015a1, adapter tolerante em 0d4dbab, bridge 16/16. Prova
  nativa no bundle 9c04b98b (salvar/cancelar, cópia, sanitizar e reabrir)
  feita pelo líder com diálogos em primeiro plano e verificada por Testes
  (adc56ab).
- Rodada 4 (docs/08), corpos CDP e busca no payload: concluída e aprovada na
  re-revisão independente (até 71eef98; bundle 0e2754f4…). Corpos gravados ao
  vivo com estado explícito e `transformed`; busca em 6 escopos com visão
  decodificada e intervalo exato; sanitização por propagação de valor
  (fail-closed); rótulos de origem; NetLog truncado reparado; busca com
  anexos sob demanda (pico 1,75 GB → 257 MB). Acabamento não bloqueante em
  curso.
- Rodada 5 (docs/09), origem dos valores, cadeia de priming e comparação entre
  capturas: concluída e aprovada na re-revisão (bundle ac7213b2…). Próximo:
  validação no caso real DETRAN (HARs locais, sem dados no repositório) e
  rodada 6 (script de priming e sucesso da aplicação × HTTP).
- Rodada 6 (docs/10), fidelidade ao caso real DETRAN-PB: APROVADA (7a11441).
  O caso é identificável e analisável nos 3 HARs reais do usuário.
- Rodada 7 (docs/11), script de priming e sucesso da aplicação × HTTP:
  implementada e em revisão independente. Nos 3 HARs reais: 11 passos na ordem
  do fluxo manual, só placa e sufixo do SESSIONID como parâmetros, 0 valores
  capturados no código; prova no detran-sim nos 4 modos.
- Aceite automatizado: 10/10 critérios (283 checks em 229b623).
- Captura nova e importações HAR/NetLog pela UI do bundle final validadas.
  Seleção manual do usuário e conferência independente dos arquivos persistidos.
- Relatório de fechamento: `docs/06-entrega.md`; nada publicado.
- Repositório criado em `/Users/cesar/Projects/scrapelens`.

## Modelos em uso

Em 2026-10-28, por decisão do usuário, todos os agentes do canal, exceto o
líder, usam Claude Sonnet 5.5 (`claude-sonnet-5-5`, esforço low), com reserva
automática `opencode/deepseek-v4.1-flash-free` se a cota acabar. Histórico:
GLM-5.3/DeepSeek V4.1 Flash (OpenCode Go) → gpt-6.1-sol (líder/revisor/docs) →
Sonnet 5.5 low. Em 2026-10-28, por decisão do usuário, todos os agentes não decisores
(Documentação, Captura, Core, Testes e App) passaram para
`opencode-go/deepseek-v4.1-flash` (OpenCode Go, esforço high), com reserva
automática `opencode/deepseek-v4.1-flash-free` quando a cota acabar. Os
decisores (Líder e Revisor independente) não mudaram de modelo. Em 2026-10-29 o
`opencode-go/deepseek-v4.1-flash` falhou: as tarefas eram encerradas em ~1 s,
sem trabalho, e a chamada direta pelo CLI não respondeu em 3 min. Os
executores voltaram temporariamente para Sonnet 5.5 low até o DeepSeek ser
diagnosticado. Diagnóstico (log do OpenCode): "Go usage limit exceeded"
(cota da assinatura OpenCode Go esgotada), e a reserva automática não
entrou. Em 2026-10-29, a pedido do usuário, os não decisores (Core, Testes,
App, Captura e Documentação) passaram para `opencode/deepseek-v4.1-flash-free`
(esforço high), testado e respondendo. Vale a partir da próxima tarefa de cada
um. Revisor e Líder sem mudança. Em 2026-10-29 03:14 a cota gratuita também
acabou ("Free usage limit reached"); os executores voltaram para Sonnet 5.5 low,
e as tarefas perdidas foram reenviadas. Sem substituição silenciosa de modelo.

Equipe (seção OpenBot "ScrapeLens"):

| Agente | ID |
|---|---|
| Líder e arquitetura | `agent-88cccd6b…a41` |
| Captura e protocolos | `agent-05db9236…4c23` |
| Testes e integração | `agent-e9324ddd…4b1f` |
| Core e importadores | `agent-d66aa8db…8d71` |
| App macOS e interface | `agent-466e334c…66b9` |
| Revisor independente | `agent-ffb4d60c…ad63` |
| Documentação Obsidian | `agent-636cf76c…cde3` (rotina diária 09:00, America/Sao_Paulo) |

## Ondas (máx. 3 executores simultâneos)

- Onda 1 (concluída): Captura/protocolos + Testes/servidores — experimentos de
  fidelidade HTTP/1.1, h2, h3; matriz `docs/02-matriz-fidelidade.md`.
- Onda 2 (concluída): contratos consolidados → Core/importadores +
  App/interface + Testes (fatia completa: launch Chrome → captura → UI).
- Onda 3 (implementação/revisão concluídas; ressalvas no relatório final): comparação, exportação, sanitização; revisão independente;
  empacotamento e documentação.

## Critérios de aceite

Conforme especificação (10 itens). Ver `docs/05-aceite.md` quando criado.
