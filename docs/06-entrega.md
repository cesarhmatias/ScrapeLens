# Entrega local e recuperação do empacotamento — 2026-10-27

## Resultado e escopo

Empacotamento local concluído. Bundle arm64 recompilado com o core atual,
assinatura ad-hoc válida, abertura e nova captura pela UI comprovadas.
Bateria automatizada: 10/10 critérios e 260/260 asserções, sem SKIP.
A validação manual de novas importações HAR/NetLog pela UI permanece parcial:
o usuário concedeu a permissão macOS, mas o seletor nativo continua
inacessível à automação (AX vazio e teclas sem efeito). A evidência pela UI é histórica,
feita no bundle anterior; as importações novas foram verificadas pelo CLI.

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
| Bateria de aceite | Testes: 260/260, 10/10, commit 364bddb; promovida a docs/05-aceite.md |
| Nova captura no bundle final | Testes: Iniciar/Encerrar pela UI, sessão capture-1793085113332 |
| HAR/NetLog novos | CLI aprovado; repetição pela UI requer seleção humana no painel nativo |
| Inspeção visual | App: prints 22/23; líder inspecionou print 23; Testes gravou screenshot-app-live.png |

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
ambíguos. Exportação cURL/Python e sanitização funcionam no core/CLI.

## Limitações e prioridades restantes

1. Repetir importações frescas HAR/NetLog pela UI do bundle final quando o
   usuário selecionar os arquivos no painel nativo. Permissão macOS já concedida;
   a automação continua sem acesso ao seletor. Isso não altera a aprovação histórica
   das importações, mas falta evidência atual desse caminho no pacote final.
2. Conectar exportação/sanitização à UI. Busca no corpo, cadeia de priming,
   campos dinâmicos e comparação entre sessões do caso DETRAN seguem pendentes;
   fixtures e correlação 13/13 não comprovam essas funções da interface.
3. Completar avisos/licenças transitivas para redistribuição. Código próprio
   MIT e lockfiles presentes; inventário completo não auditado.
4. Captura só um target; não baixa corpos CDP; zero eventos gera erro em vez
   de sessão vazia; Origin CDP aberto por --remote-allow-origins=* durante a
   sessão local. Sanitização continua heurística, com omissão de anexos/eventos
   não sanitizáveis; exportação não garante fingerprint/transporte.
5. Assinatura Developer ID/notarização e teste Intel antes de distribuição
   ampla. Nada publicado, nenhum push/release nesta tarefa.

O painel de importação foi deixado para seleção manual do usuário.
A pasta `~/Projects/scrapelens-import-tmp/` foi preservada; nenhuma exclusão
foi realizada. Instruções de uso/build estão no README da raiz.

## Atualização do bloqueio após a permissão

Testes tentou novamente após a resposta do usuário “Concedi a permissão; continue”.
Em 2026-10-27T09:58Z, o OpenAndSavePanelService retornou zero elementos
(`ax_window_unresolved`). Teclas em background e foreground não alteraram a
captura. Nenhum clique absoluto foi realizado sobre a janela do usuário.
Nenhuma nova sessão foi importada. Registro em
`docs/validation/import-picker-blocker.json`; a bateria anterior permanece
260/260 com o escopo histórico explicitado. Não se deve repetir a mesma
automação nem contornar o bloqueio.

Para liberar a verificação restante, no painel Importar HAR use ⌘⇧G e selecione
`~/Projects/scrapelens-import-tmp/har-derived.json`. Depois importe NetLog com
`~/Projects/scrapelens-import-tmp/h1h2h3.chrome-netlog.json`. Ao confirmar as duas
importações, Testes pode validar as sessões geradas e atualizar a evidência.
