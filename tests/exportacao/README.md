# Validação independente da exportação UI

`cargo test --manifest-path tests/exportacao/Cargo.toml --offline` compila o
módulo `src-tauri/src/export.rs` sem editá-lo, em um crate de testes separado.
Os nove testes internos desse módulo também são executados; sete testes novos
cobrem equivalência com o core, estados de corpo, erros, sanitização e links
simbólicos em ancestrais. Nenhum código exportado é executado e não há rede.

No commit de validação inicial, dois testes **falham intencionalmente para
registrar bugs reproduzidos**; não se deve removê-los ou marcá-los ignorados
para aprovar a funcionalidade. Relatório em `tests/results/exportacao/RELATORIO.md`.

## Roteiro manual único (depois da correção e novo bundle)

Fixture preparada sem dados pessoais: `python3 tests/exportacao/prepare_manual.py`.
Ela já existe em `tests/.work/exportacao-manual/source/`; o script recusa
sobrescrevê-la. As credenciais são marcadores fictícios, domínio `.invalid`.

1. No bundle corrigido, **Abrir captura…** → selecione a pasta
   `/Users/cesar/Projects/scrapelens/tests/.work/exportacao-manual/source`.
   Selecione `captured` (POST `/echo`) e abra **Exportar…**.
2. Em cURL, **Copiar** e **Salvar…** no caminho novo
   `/Users/cesar/Projects/scrapelens/tests/.work/exportacao-manual/native.sh`.
   Repita em Python no mesmo diretório com nome `native.py`. Não execute nada.
   Cancele uma tentativa de salvar e confira que não indica arquivo salvo.
3. Feche a exportação. **Sanitizar…** → **Escolher destino e salvar…** →
   `/Users/cesar/Projects/scrapelens/tests/.work/exportacao-manual/sanitized`.
   Clique **Abrir sessão sanitizada** e confira que a sessão está rotulada
   sintética e os valores sensíveis estão redigidos.
4. Execute `python3 tests/exportacao/verify_manual.py` para conferir os arquivos,
   permissões e SHA dos originais. A cópia real deve ser conferida separadamente
   com leitura do clipboard imediatamente após cada clique em Copiar, sem
   substituir o clipboard por ferramenta: o script não prova essa ação.

Os seletores nativos ficaram fora da prova automatizada, por bloqueio já
observado do NSSavePanel. Nenhuma tentativa de foreground foi repetida nesta
validação. Screenshots do harness do App e seu clipboard simulado não são
prova do diálogo/clipboard reais.
