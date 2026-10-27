# ScrapeLens — Plano (vivo)

App open source macOS para inspeção de sessões HTTP para desenvolvedores de
scraping. Especificação completa:
`/Users/cesar/Documents/Codex/2026-10-26/meu-x20/outputs/ScrapeLens-especificacao.txt`

## Estado

- Fase: 3 — Prova de captura e fidelidade ( marco gate ; nada de interface
  antes do veredito).
- Repositório criado em `/Users/cesar/Projects/scrapelens`.

## Modelos resolvidos (assinatura OpenCode Go, provedor `opencode-go`)

| Papel | Modelo | ID |
|---|---|---|
| Líder/arquiteto | GLM-5.3 | `opencode-go/glm-5.3` |
| Executores (código) | DeepSeek V4.1 Flash | `opencode-go/deepseek-v4.1-flash` |
| Revisor independente | GLM-5.3 | `opencode-go/glm-5.3` |

OpenCode 1.19.4. Sem substituição silenciosa de modelo.

Equipe (seção OpenBot "ScrapeLens"):

| Agente | ID | Modelo |
|---|---|---|
| Líder e arquitetura | `agent-88cccd6b…a41` | `gpt-6.1-sol` (codex, medium) — trocado de GLM-5.3 em 2026-10-27 por decisão do usuário |
| Captura e protocolos | `agent-05db9236…4c23` | `opencode-go/deepseek-v4.1-flash` (high) |
| Testes e integração | `agent-e9324ddd…4b1f` | `opencode-go/deepseek-v4.1-flash` (high) |
| Core e importadores | `agent-d66aa8db…8d71` | `opencode-go/deepseek-v4.1-flash` (high) — standby pós-matriz |
| App macOS e interface | `agent-466e334c…66b9` | `opencode-go/deepseek-v4.1-flash` (high) — standby pós-matriz |
| Revisor independente | `agent-ffb4d60c…ad63` | `gpt-6.1-sol` (codex, medium) — trocado de GLM-5.3 em 2026-10-27 |
| Documentação Obsidian | `agent-636cf76c…cde3` | `gpt-6.1-sol` (codex, medium); rotina diária 09:00 (America/Sao_Paulo) |

## Ondas (máx. 3 executores simultâneos)

- Onda 1 (ativa): Captura/protocolos + Testes/servidores — experimentos de
  fidelidade HTTP/1.1, h2, h3; matriz `docs/02-matriz-fidelidade.md`.
- Onda 2 (após matriz): contratos consolidados → Core/importadores +
  App/interface + Testes (fatia completa: launch Chrome → captura → UI).
- Onda 3: comparação, exportação, sanitização; revisão independente;
  empacotamento e documentação.

## Critérios de aceite

Conforme especificação (10 itens). Ver `docs/05-aceite.md` quando criado.
