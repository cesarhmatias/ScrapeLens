# Entrega local e recuperação do empacotamento — 2026-10-27

## Resultado e escopo

Empacotamento local concluído. Bundle arm64 recompilado com o core atual,
assinatura ad-hoc válida, abertura e nova captura pela UI comprovadas.
Bateria automatizada: 10/10 critérios e 282/282 asserções, sem SKIP.
Novas importações HAR/NetLog pela UI do mesmo bundle também confirmadas:
seleção manual do usuário no painel nativo, seguida de verificação independente
por Testes dos arquivos persistidos, origem, contagens, permissões e releitura.
O bloqueio de automação do seletor ficou registrado como limitação do ambiente;
não há verificação de importação pendente nesta entrega.

Isso encerra a recuperação do pacote e registra o estado real. Não equivale
à conclusão integral de todos os requisitos de produto da especificação:
exportação/sanitização ainda são CLI, e os requisitos derivados do DETRAN
listados abaixo não foram integrados à UI. Nenhum código de produção foi
alterado nesta recuperação; nenhuma proposta de UX foi integrada.

## Estado preservado e trabalhos retomados

No início, HEAD `1581376`, árvore limpa. LICENSE, CONTRIBUTING, comentário de
commands e nota do Origin CDP já estavam em `e443076`; não foram refeitos.
O bundle antigo era anterior à calibração do relógio NetLog (`f6c6bdd`).

App retomou somente build/validação e comandos de contribuição:
`febdd2f`, `fbce3e4`, `453d717`. Build fonte `1581376`, core até `b5846be`,
incluindo `98293e2` (sanitização) e `f6c6bdd` (NetLog).

A reexecução do líder revelou três falhas no critério 3. Testes demonstrou
que a fixture declarava wallTime incompatível com timestamp monotônico;
corrigiu a equação sem reduzir as exigências de ambiguidade. Commits
`87d7b61` e `364bddb`; falha original preservada em
`tests/results/aceite-criterio3-falha-lider.json` e relatório correspondente.
Não foi necessária correção adicional do core nem novo build do produto.

## Artefato e instalação

- Pacote: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
- Tamanho aproximado: 13,2 MiB; um executável Mach-O arm64, 13.119.296 bytes.
- SHA-256 do executável assinado:
  `a7004d4e95e86e2d53750a76b0579d345cabf6e53cb25c3b15c446d25ec522c0`.
- Assinatura ad-hoc verificada com `codesign --verify --deep --strict` pelo
  App e novamente pelo líder; sem Developer ID/notarização. Gatekeeper rejeita
  distribuição normal deste artefato. Intel e outros macOS não testados.
- Abra pelo Finder ou `open src-tauri/target/release/bundle/macos/ScrapeLens.app`
  a partir da raiz. Pode copiar o bundle para `/Applications`.
- Chrome externo necessário para captura; Node/Python/Rust não necessários
  para executar o app. CLI de exportação é ferramenta separada.

Comandos de build/assinatura e ambiente em `src-tauri/EMPACOTAMENTO.md`.
O hash identifica este artefato, não garante build byte a byte reproduzível.

## Validação confirmada

| Verificação | Resultado e origem |
|---|---|
| Core `cargo test --offline` | App: 88 passam, 1 benchmark ignorado |
| Shell `cargo test` | App: 6 passam, 1 teste live ignorado; captura exercitada separadamente pela UI |
| TypeScript e Vite | App: typecheck e build passam |
| Build Tauri | App: exit 0, core recompilado como dependência crate |
| Assinatura/hash/arquitetura | App + líder: codesign válido, SHA-256 acima, arm64 |
| Bateria de aceite | Testes: 282/282, 10/10, commit 77c32a7; promovida a docs/05-aceite.md |
| Nova captura no bundle final | Testes: Iniciar/Encerrar pela UI, sessão capture-1793085113332 |
| HAR/NetLog novos | UI do bundle final: HAR 24 e NetLog 32 requisições, fontes conferidas |
| Inspeção visual | App: prints 22/23; líder inspecionou print 23; Testes gravou screenshot-app-live.png e screenshot-app-imports.png |

Sessão nova: 11 requisições, complete, cdp+netlog, 154 entradas de headers
verificadas via NetLog h1, 9 matched, 2 ambíguas (2 candidatos cada), zero
unmatched, 2 redirects, 8 linhas Set-Cookie, Cookie sc_dup preservado.
Diretório 0700, arquivos 0600. Corpos CDP unavailable com nota.

Nova captura do harness: 27 requisições, h1/h2/h3, evidência estável em
`tests/results/capture-latest/run.json`. A matriz histórica mede Chrome
156.0.8078.48, 15 experimentos e 60 requisições, com h3 observado em aioquic e
cenário quiche bloqueado. Não se declara cobertura completa de HTTP/3.

Importação grande atual: 20.000 requisições, HAR 16,6 MiB em 0,96 s;
20.000 anexos pequenos em 3,30 s. Inspect chega a 2.415 MiB RSS ao serializar
JSON completo; responsividade/perfil de memória ainda merece atenção.

## Funcionalidades disponíveis

Captura Chrome dedicado, parada/flush, gravação e reabertura de sessão v1,
importadores HAR/NetLog, lista com filtros e busca, detalhe e comparação de
requisições com duplicatas. Headers na sequência da fonte; proveniência e
verificação por informação. HAR/objetos CDP não comprovam ordem transmitida;
NetLog e headersText h1 fornecem evidências específicas. Empates ficam
ambíguos. Exportação cURL/Python e sanitização funcionam no core/CLI e, desde
a rodada seguinte, também pela interface (resultado em `docs/07-exportacao-ui.md`).

## Limitações e prioridades restantes

1. Exportação/sanitização na UI: concluída na rodada seguinte (`docs/07`).
   Busca no corpo, cadeia de priming,
   campos dinâmicos e comparação entre sessões do caso DETRAN seguem pendentes;
   fixtures e correlação 13/13 não comprovam essas funções da interface.
2. Completar avisos/licenças transitivas para redistribuição. Código próprio
   MIT e lockfiles presentes; inventário completo não auditado.
3. Captura só um target; não baixa corpos CDP; zero eventos gera erro em vez
   de sessão vazia; Origin CDP aberto por --remote-allow-origins=* durante a
   sessão local. Sanitização continua heurística, com omissão de anexos/eventos
   não sanitizáveis; exportação não garante fingerprint/transporte.
4. Assinatura Developer ID/notarização e teste Intel antes de distribuição
   ampla. Nada publicado, nenhum push/release nesta tarefa.

A pasta `~/Projects/scrapelens-import-tmp/` e as sessões duplicadas foram
preservadas; nenhuma exclusão foi realizada. Instruções de uso/build no README.

## Fechamento das importações manuais

A permissão macOS foi concedida pelo usuário. O seletor continuou inacessível
à automação (AX vazio e teclas sem efeito); registro histórico em
`docs/validation/import-picker-blocker.json`. Nenhuma permissão foi contornada.
Após uma tentativa com JSON sem a estrutura HAR, Testes confirmou que o arquivo
preparado era válido. O usuário selecionou os dois caminhos exatos e confirmou
a importação. Testes verificou as novas sessões antes de aprovar (77c32a7):

- HAR `har-3dbc391c02a985c5-2`: 24 requisições h1/h2, complete, 24 sourceEvents,
  sem DEMO e zero headers classificados como verificados. Sequência método/URL
  idêntica às 24 entradas do HAR preparado.
- NetLog `netlog-1704043c442dcbd1-2`: 32 requisições h1/h2/h3, 36 tentativas,
  9 conexões, 4 redirects, 15 StreamSessions e 5.354 sourceEvents. Partial com
  motivo explícito pela ausência de CDP; aviso de unidade temporal assumida.
  Artefato NetLog persistido byte a byte idêntico à fonte preparada.
- Diretórios 0700 e arquivos 0600; inspect relê 24/32 requisições sem modificar
  session.json. Cópias duplicadas preservadas.
- Print `tests/results/app-latest/screenshot-app-imports.png`: sessão NetLog
  importada, 32 requisições e linhas h1/h2/h3. Metadados e verificação em
  `tests/results/app-latest/run.json`.

Bateria consolidada reexecutada: 282/282 (critério 9: 118/118). Captura e build
não foram repetidos nessa última passada. O hash do bundle permaneceu o mesmo.
