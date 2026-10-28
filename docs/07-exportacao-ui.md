# Próxima rodada — exportação pela interface

## Escopo autorizado

Pedido de 2026-10-27: avançar ao próximo passo proposto, exportação cURL/Python
com prévia/cópia/salvamento e exportação de sessão sanitizada. Reutilizar o
core existente. Sem captura de corpos CDP, redesign ou implementação dos
requisitos DETRAN nesta rodada. Não publicar nem executar código exportado.

## Propriedade

- App: app/, src-tauri/ e evidências de prints da funcionalidade.
- Testes: tests/ e fixtures/, depois da implementação.
- Líder: docs/, README e revisão da entrega.
- Core: sem mudanças previstas; se houver bloqueio, reportar antes de alterar.

## Contrato funcional

1. Ação de exportação na requisição selecionada da sessão persistida aberta.
   cURL/Python gerados no Rust a partir de import_session_dir, requestId e
   attachment do corpo; chamar export::curl::to_curl e python::to_python com
   ExportOptions::default. Não recriar exportador no frontend nem confiar em
   texto editado/normalizado da UI como fonte.
2. Prévia somente texto; alternância cURL/Python, copiar via clipboard e salvar
   por diálogo nativo. Exibir warnings, skipped_headers, body_included/body_note
   retornados pelo core. Estado de corpo indisponível não vira corpo vazio
   apresentado como completo. Não prometer TLS/fingerprint/HTTP2/HTTP3 idênticos.
3. Aviso conciso: exportação pode conter cookies/credenciais da sessão; nunca
   executar código nem fazer replay/rede. Demo sem pasta persistida pode ficar
   desabilitada com motivo explícito; não produzir resultado fictício.
4. Sanitizar sessão inteira por ação própria: sanitize_bundle com opções padrão
   (keep_raw_events=false), prévia de contagens de redações, warnings e anexos
   omitidos; salvar por escolha nativa de destino em pasta nova/vazia, privada.
   Preservar origem e nunca reutilizar pasta com dados não sanitizados.
   Usar SanitizedExport::write_to e a política conservadora do core.
5. Novo destino deve ser distinto da origem; recusar sobrescrita e links
   simbólicos nos destinos da nova integração. Código salvo com permissão 0600;
   sessão sanitizada 0700/0600. Cancelamento não grava nem altera a sessão.
   Operações pesadas fora da thread da UI, com busy/erro acionável.
6. A prévia deve corresponder ao conteúdo copiado/salvo; impedir exportar
   silenciosamente outra requisição se a seleção mudar enquanto gera/salva.
   Sessão original nunca é modificada. Nenhuma credencial em logs/relatórios.

## Validação da rodada

Testes úteis na ponte: requisição inexistente, pasta ausente, corpo disponível
vs unavailable, escaping, destino ocupado/origem/symlink, cancelamento e
preservação da origem. Reutilizar testes do core; não duplicar implementação.
Fluxo real no bundle: abrir sessão persistida, selecionar requisição, prévia
cURL/Python, copiar e comparar com arquivo salvo, sanitizar/abrir nova sessão
com marcadores sintéticos e verificar ausência em todos os arquivos. Novo
bundle assinado ad-hoc e hash específico. Registrar fatos vs não testados.

## Base preservada

Base de produto 7d25bc7, último aceite 282/282 (77c32a7). Há modificação prévia
em tests/results/app-latest/testserver/app-20261027/h1.jsonl no início desta
rodada: preservar, não incluir em commit de exportação sem entender a origem.
A proposta outputs/ux-review continua isolada. Conventional Commits para cada
entrega concluída, sem push/release/publicação.

## Resultado da rodada — 2026-10-27

Concluída. Bundle arm64 ad-hoc, SHA-256 do executável
`9c04b98b30b3d6451ee53fa5eee589aaba0cd4e5d3185894e39facb0335bdbe5`
(fonte e assinatura em `src-tauri/EMPACOTAMENTO.md`).

- Implementação (App): `eaf5471`…`2c6765e`; sem alterações no core.
- Validação independente (Testes, `a83d985`/`ffc7fc1`): 14/16 na primeira
  passada. Falharam F1/F2: destino que passava por link simbólico em pasta
  ancestral era aceito. Corrigido em `16015a1`: qualquer link na cadeia do
  destino é recusado, exceto os aliases de sistema `/var`, `/tmp` e `/etc`
  quando apontam para `/private/...`. Regressões: 16/16.
- A prova nativa revelou que sessões v1 mínimas, aceitas pelo core, travavam a
  UI (`s.attempts.map`). Corrigido em `0d4dbab`: o adapter aplica os mesmos
  defaults do core, com teste próprio.
- Prova nativa no bundle `9c04b98b…` (líder, a pedido do usuário; diálogos
  nativos operados em primeiro plano), com verificação de arquivos por Testes
  (`adc56ab`): abrir sessão, salvar cURL e Python (0600, idênticos à prévia),
  cancelar sem gravar, cópia idêntica à prévia, sanitizar em pasta nova
  0700/0600 sem eventos brutos nem marcadores, reabrir a sanitizada com URL
  redigida, origem byte-idêntica. Relatório: `tests/results/exportacao/RELATORIO.md`;
  print `docs/screenshots/24-exportacao-sanitizada-aberta.png`.

Pendências e limitações: corridas de diretório não testadas; sanitização segue
heurística; exportação não replica TLS/JA3/JA4/HPACK; sessões rotuladas
`synthetic-fixture` mostram o título da demonstração em vez do id (cosmético).
Próximas rodadas do roadmap: corpos CDP e busca no payload, caso DETRAN ponta a
ponta, distribuição (licenças, notarização, Intel).
