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
  curso. Próxima rodada: cadeia de priming e comparação entre capturas (caso
  DETRAN, docs/05-caso-referencia-detran.md).
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
Sonnet 5.5 low. Sem substituição silenciosa de modelo.

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
