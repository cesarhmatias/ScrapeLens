# Validação independente — exportação/sanitização na UI

Status: **APROVADA (adendo final abaixo)**. Corpo original = rodada 1, parcial; ver "Adendo". Não houve edição de código
de produção. Bundle observado: `a58db574771fcd6058bc63a8080e0ba2f9bdf1aeb671bf9c56d4bf221fab26cf`,
13.969.728 bytes, assinatura ad-hoc verificada (exit 0). Fonte auditada: `2c6765e`.

## Resultado executado

| Verificação | Resultado | Evidência |
|---|---|---|
| Testes independentes compilando a ponte real | **14 passam, 2 falham** (9 testes internos + 7 novos) | independent-bridge.log |
| Unitários do shell | 15 passam, 1 live ignorado | tauri-tests.log |
| Core | 91 passam, 1 benchmark ignorado | core-tests.log |
| TypeScript | passa | typecheck.log |
| Preview/core/arquivo cURL e Python | idênticos em bytes, arquivo 0600 | preview_matches_core_and_saved_file_for_both_formats |
| Corpos captured/truncated/unavailable/discarded/empty | estado preservado; anexo obsoleto não exportado | states_are_explicit_and_do_not_export_stale_attachment |
| ID/formato/pasta inválidos | recusados sem escrever | invalid_request_format_and_source_fail_without_writes |
| Sanitização | marcadores próprios de URL/Auth/Cookie/body/raw ausentes, raws omitidos, origem byte-idêntica e saída relida | sanitized_output_removes_markers_raw_events_and_preserves_original |
| Origem/destino ocupado/link direto | recusados; conteúdo existente intacto | occupied_source_descendant_and_direct_symlinks_are_refused |
| Link em ancestral do destino | **aceito indevidamente em ambas as operações** | duas regressões abaixo |
| Bundle GUI | janela renderizada, DEMO rotulada e Sanitizar desabilitado | bundle-observed.png |
| Diálogo nativo Salvar/Cancelar e clipboard real | **não testados independentemente** | bloqueio anterior conhecido, não repetido |
| Harness UI do App | artefato revisado; usa stub Tauri, diálogo/clipboard simulados e tem 3 erros unregisterListener | não foi reexecutado nem promovido a prova nativa |

Nenhum código cURL/Python gerado foi executado, nenhuma chamada HTTP foi
repetida e nenhum certificado/permissão foi alterado. Build de produção não
foi repetido: o executável/hash e assinatura foram verificados diretamente.
A bateria histórica 282/282 permanece intacta; não prova esta nova funcionalidade
nem o novo bundle. Não reexecutei a matriz h1/h2/h3 sem necessidade.

## Falhas confirmadas — contrato de destino (bloqueantes da rodada)

**F1 — arquivo exportado segue link em ancestral.**
`src-tauri/src/export.rs:215` só chama reject_symlink no pai imediato, e l.225
no arquivo. Com `alias -> real`, `real/sub` existente, a chamada
`write_text_file(alias/sub/out.sh, "SYNTHETIC")` retorna Ok e grava em
`real/sub/out.sh`. Viola a recusa de links simbólicos do contrato §5 e a
promessa do doc-comment de não seguir links. Severidade média: grava novo
arquivo privado em caminho resolvido pelo link; não houve sobrescrita.

**F2 — sanitização segue link em ancestral.**
`src-tauri/src/export.rs:318-321` verifica só o pai imediato antes de
canonicalizá-lo. `sanitize_to(source, alias/sub/output)` retorna Ok e cria
`real/sub/output`. A origem permaneceu intacta, mas o destino por link não foi
recusado como contratado. Severidade média, mesmo mecanismo de F1.

Reprodução sem GUI/rede, em pastas temporárias próprias:

```sh
cargo test --manifest-path tests/exportacao/Cargo.toml --offline --test bridge export_rejects_symlink_in_ancestor
cargo test --manifest-path tests/exportacao/Cargo.toml --offline --test bridge sanitization_rejects_symlink_in_ancestor
```

Ambos falham em 2c6765e porque receberam Ok. Não foram ignorados nem tiveram
asserts afrouxados. Corrigir validação de caminho em toda a cadeia escolhida,
com política explícita para aliases conhecidos do macOS, sem apenas remover
a garantia. Testar novamente os caminhos normais, ocupados, links diretos e
ancestrais. Este relatório não afirma resistência completa a corridas de troca
de diretórios: não foram exercitadas.

## Fluxo nativo e próximos passos

1. App corrige F1/F2, executa regressões, recompila e registra novo hash/bundle.
2. Executar o roteiro único de `tests/exportacao/README.md`. A fixture privada
   com corpo capturado e marcadores fictícios já foi preparada em
   `tests/.work/exportacao-manual/source`. Código salvo e sessão sanitizada
   podem ser conferidos por `verify_manual.py` sem executar exportações.
3. Conferir clipboard nativo após Copiar e comparar com a prévia. Em separado,
   comprovar Salvar, Cancelar e Abrir sessão sanitizada no bundle corrigido.
   Não repetir automação já bloqueada do NSSavePanel; solicitar seleção humana
   se não houver rota acessível. Ainda não há prova desse ciclo nesta validação.

## Preservação

O arquivo pré-existente modificado
`tests/results/app-latest/testserver/app-20261027/h1.jsonl` continua fora dos
commits desta rodada (39 linhas adicionais). Não houve exclusão de sessões,
temporários de outros agentes, mudanças em app/, src-tauri/ ou core/, nem
publicação/push. Metadados do run em result.json. O screenshot do bundle foi
capturado via computer_use em janela específica; não houve ação de foreground.

## Adendo — fechamento com prova nativa (bundle final)

Bundle: executável SHA-256 `9c04b98b30b3d6451ee53fa5eee589aaba0cd4e5d3185894e39facb0335bdbe5`
(HEAD b226f9b; fixes `16015a1` symlink ancestral e `0d4dbab` adapter tolera campos
omitidos), `codesign --verify --deep --strict` ok. O bundle `5934556c…` falhava ao
abrir a fixture (`TypeError s.attempts.map`); corrigido em `0d4dbab`.

Prova nativa: operada pelo líder via computer_use (NSOpenPanel/NSSavePanel em
primeiro plano, ⌘⇧G), 23:27–23:30. Verificação dos arquivos: Testes, de forma
independente (sem executar native.sh/native.py, sem rede).

| Item antes "não testado" | Status |
|---|---|
| NSOpenPanel abrir captura (fixture sem attempts/redirects/cookie) | **aprovado** (prova nativa pelo líder) |
| NSSavePanel salvar cURL (`native.sh`, 753 B) | **aprovado**; 0600, `cmp` idêntico a `expected.sh` (Testes) |
| NSSavePanel salvar Python (`native.py`, 1157 B) | **aprovado**; 0600, `cmp` idêntico a `expected.py` (Testes) |
| Cancelar Salvar | **aprovado**: UI "Salvamento cancelado; nada foi gravado"; nenhum `captured.sh/.py` existe (Testes) |
| Clipboard nativo (Copiar) | **aprovado** pelo líder: `pbpaste` com UTF-8 idêntico a `expected.py`. Sem LANG UTF-8 o `pbpaste` difere no travessão: artefato do pbpaste. Não reverificado por Testes (clipboard volátil) |
| Sanitizar → salvar → reabrir | **aprovado**: pasta 0700; `session.json` e `attachments/sanitized-request.json` 0600; sem `cdp-events.jsonl`/`netlog.json`; nenhum `ONLY_SYNTHETIC`; URL reaberta `https://fixture.invalid/echo?sid=%5BREDACTED%5D` (Testes lê o session.json). Print `docs/screenshots/24-exportacao-sanitizada-aberta.png` |
| Origem intacta | **aprovado**: SHA dos 3 arquivos do manifesto idênticos |

Regressões: `cargo test --manifest-path tests/exportacao/Cargo.toml --offline`
→ **16/16 passam** após `16015a1` (F1/F2 fechados).

`verify_manual.py` agora ignora explicitamente apenas arquivos chamados `.DS_Store`
na origem (metadado do Finder criado às 23:18 por navegação do usuário, antes do
app rodar; o app não grava ali). Qualquer outro arquivo novo/alterado/ausente
continua reprovando. Resultado: APROVADO. Nenhum `.DS_Store` foi apagado.

Observação cosmética (líder, não bloqueante): sessões com label `synthetic-fixture`
mostram título "Demonstração — vitrine sintética" e barra "sessão de demonstração"
em vez do id da sessão.

Limites: exportação não executa/reproduz requisições; clipboard e diálogos
dependem de operação em primeiro plano; sem notarização/Intel.

## Rodada 3 — revalidação independente em HEAD 387d799

**Testado (reexecutado por Testes, offline):**

| Verificação | Resultado |
|---|---|
| Ponte (`tests/exportacao`) | **18/18** (16 anteriores + 2 novas de política de aliases) |
| src-tauri | 15 ok, 1 ignorado |
| core | 91 ok, 1 ignorado |
| typecheck (`tsc --noEmit`) | passa |
| Bundle `…/macos/ScrapeLens.app` | executável SHA-256 `9c04b98b…bdbe5` (o mesmo da prova nativa final; o `5934556c…` citado pelo líder é anterior à `0d4dbab`); `codesign --verify --deep --strict` exit 0 |

Novas regressões: `symlink_policy_final_file_dangling_and_relative_aliases` (link no próprio
arquivo de destino para alvo existente e pendente, link para arquivo como pasta pai, link pendente
como destino de sanitização, ancestral relativo `../rel/`, controle `../real/` aceito) e
`symlink_policy_macos_system_aliases_only_at_root` (`/private/var/tmp` e `/var/tmp` reais aceitos;
link criado pelo usuário dentro de `/var/tmp` recusado). Todas passam: **nenhum bug novo** na
política de `16015a1`. Link em `/Users/...` coberto pela regressão de ancestral existente
(mesmo mecanismo: qualquer ancestral que não seja `/var`,`/tmp`,`/etc`).

**Não testado nesta rodada:**
- GUI/clipboard via computer_use: abrir a fixture depende do NSOpenPanel (`bridge.ts` `openDialog`),
  então a parte foi interrompida conforme instruído; clipboard não lido. Prova nativa do clipboard
  permanece a do adendo (operada pelo líder, `pbpaste` UTF-8 idêntico).
- Salvar/Cancelar nativo: registrado como **pendente de seleção humana** nesta rodada (já aprovado
  na prova do líder no adendo); não bloqueia o fechamento automatizado.
- Corridas de troca de diretório (TOCTOU) entre a checagem e a gravação: não exercitadas; a
  validação é por checagem prévia, não por `openat`/`O_NOFOLLOW` em toda a cadeia.
