# Validação independente — exportação/sanitização na UI

Status: **parcial; não aprovada para fechamento**. Não houve edição de código
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

O App cita `cargo run --example export_dump` em EMPACOTAMENTO.md, mas o exemplo
foi removido: o comando de regeneração precisa de atualização. Isso é uma
lacuna documental menor, separada das duas falhas reproduzidas.

## Preservação

O arquivo pré-existente modificado
`tests/results/app-latest/testserver/app-20261027/h1.jsonl` continua fora dos
commits desta rodada (39 linhas adicionais). Não houve exclusão de sessões,
temporários de outros agentes, mudanças em app/, src-tauri/ ou core/, nem
publicação/push. Metadados do run em result.json. O screenshot do bundle foi
capturado via computer_use em janela específica; não houve ação de foreground.
