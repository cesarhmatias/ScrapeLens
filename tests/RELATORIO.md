# Relatório de aceite — ScrapeLens MVP

Execução: 2026-10-28T03:35:49Z · binário do core `0cb3d8394374` (2309504 bytes) · commit `d9aba1c`

Ambiente: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Critério da spec | Status | Asserções |
|---|---|---|---|
| 1 | Headers repetidos e cookies preservados nas fixtures | **aprovado** | 29/29 |
| 2 | HAR e NetLog válidos, incompletos e com eventos desconhecidos | **aprovado** | 26/26 |
| 3 | Requisições simultâneas idênticas sem associação falsa | **aprovado** | 19/19 |
| 4 | Redirects e múltiplas tentativas | **aprovado** | 12/12 |
| 5 | Corpos ausentes/truncados/descartados explícitos | **aprovado** | 16/16 |
| 6 | Diff sem perder duplicatas | **aprovado** | 14/14 |
| 7 | Exportação cURL/Python com caracteres especiais | **aprovado** | 23/23 |
| 8 | Sanitização incluindo eventos brutos | **aprovado** | 19/19 |
| 9 | Ciclo real de captura no macOS | **aprovado** | 118/118 |
| 10 | Importação grande com tamanho documentado | **aprovado** | 7/7 |

Resumo: 10/10 critérios aprovados; 283/283 asserções passaram.

Critérios do pedido: (1) headers repetidos/cookies, (2) HAR/NetLog válidos/incompletos/desconhecidos, (3) simultâneas idênticas sem associação falsa, (4) redirects/tentativas, (5) corpos explícitos, (6) diff com duplicatas, (7) escaping cURL/Python, (8) sanitização com eventos brutos, (9) ciclo real macOS, (10) importação grande medida.

Escopo das evidências:

- Novo nesta rodada: captura CLI `tests/capture/runs/20261027T0730Z` (2026-10-27T07:11:07Z), com os dois legs (h1h2 e h3) e o HAR derivado do CDP.
- Novo nesta rodada: sessão ao vivo `capture-1793085113332` iniciada e encerrada pelo bundle final (`a7004d4e95e8`).
- Novo nesta rodada: importações HAR/NetLog pela UI do bundle final (har `har-3dbc391c02a985c5-2`, netlog `netlog-1704043c442dcbd1-2`), com seleção manual do usuário e verificação por SHA-256/sequência contra os arquivos preparados em `~/Projects/scrapelens-import-tmp`.

## 1. Headers repetidos e cookies preservados nas fixtures — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/headers-cookies/headers-cookies.har --out tests/.work/run/item1/har`
- `scrapelens-core import-netlog fixtures/aceite/headers-cookies/headers-cookies.netlog.json --out tests/.work/run/item1/netlog`
- asserções: sequência/caixa/duplicatas, Cookie bruto+pares, Set-Cookie bruto+parseado, verificação por fonte

Asserções: 29 passaram, 0 falharam (0.10 s).

## 2. HAR e NetLog válidos, incompletos e com eventos desconhecidos — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/parsers/incomplete.har --out tests/.work/run/item2/incomplete-har`
- `scrapelens-core import-netlog fixtures/aceite/parsers/unknown-events.netlog.json --out tests/.work/run/item2/unknown`
- `scrapelens-core import-netlog fixtures/aceite/parsers/no-constants.netlog.json --out tests/.work/run/item2/no-constants`
- casos inválidos: retorno ≠ 0 com `erro:` no stderr (HAR sem entries, NetLog truncado)

> HAR não comprova ordem/duplicatas: entradas importadas ficam `unverified`, como no contrato.

> Contagens `completeness.counts.sourceEvents*` agora são persistidas e sobrevivem à releitura (correção do core nesta onda); os avisos continuam trazendo amostras dos tipos desconhecidos.

Asserções: 26 passaram, 0 falharam (0.17 s).

## 3. Requisições simultâneas idênticas sem associação falsa — aprovado

Evidência:

- `scrapelens-core import-capture fixtures/aceite/ambiguous/cdp-ambiguous.jsonl fixtures/aceite/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

> A ordem/duplicata do NetLog é preservada, mas não vira visão primária enquanto há ambiguidade.

> Diagnóstico da falha do líder: a fixture declarava `wallTime` sem o `timestamp` monotônico (`1793046000.0`), e o core de `f6c6bdd` calibrava `time` como microssegundos; o NetLog ficava 2 s à frente e as duas requisições viravam `unmatched`. O Chrome real satisfaz `wallTime = timeTickOffset/1000 + timestamp` (desvio medido < 1 ms), equação agora usada na fixture. Era defeito da fixture, não do core; a falha original está preservada em `tests/results/aceite-criterio3-falha-lider.json` e `RELATORIO-criterio3-falha-lider.md`.

> Asserções novas nesta rodada: coerência do relógio da fixture (CDP×NetLog) e unidade calibrada `milliseconds`. O teste de ambiguidade segue rigoroso: as duas requisições a 20 ms continuam ambíguas, cada uma com os mesmos 2 candidatos e 2 avisos `correlate.ambiguous`.

Asserções: 19 passaram, 0 falharam (0.05 s).

## 4. Redirects e múltiplas tentativas — aprovado

Evidência:

- `scrapelens-core import-netlog fixtures/aceite/redirects/redirect-chain.netlog.json --out tests/.work/run/item4/netlog`
- `scrapelens-core import-har fixtures/aceite/redirects/redirect-chain.har --out tests/.work/run/item4/har`

> O redirect é um elo entre tentativas, não uma requisição separada.

Asserções: 12 passaram, 0 falharam (0.05 s).

## 5. Corpos ausentes/truncados/descartados explícitos — aprovado

Evidência:

- `scrapelens-core inspect fixtures/aceite/bodies/session`

> `empty` só é usado quando a fonte afirma zero bytes; ausência vira `unavailable` com nota.

Asserções: 16 passaram, 0 falharam (0.01 s).

## 6. Diff sem perder duplicatas — aprovado

Evidência:

- `scrapelens-core diff fixtures/aceite/diff/session har-0001 har-0002`

> O diff compara ocorrências; `reordered` usa os índices originais de A e B.

Asserções: 14 passaram, 0 falharam (0.01 s).

## 7. Exportação cURL/Python com caracteres especiais — aprovado

Evidência:

- `scrapelens-core export-curl fixtures/aceite/export-special/session har-0001` → `bash -n` + execução com stub que registra argv
- `scrapelens-core export-python fixtures/aceite/export-special/session har-0001` → `python3 -m py_compile` + AST com literais
- comandos gerados: tests/.work/run/item7/export.sh, tests/.work/run/item7/export.py

> Os exportadores prometem a requisição HTTP, não TLS/fingerprint (JA3/JA4, frames, HPACK).

Asserções: 23 passaram, 0 falharam (0.17 s).

## 8. Sanitização incluindo eventos brutos — aprovado

Evidência:

- `scrapelens-core sanitize fixtures/aceite/sanitize/session tests/.work/run/item8/sanitized`
- permissões: `0o700` no diretório e `0o600` no session.json
- varredura recursiva por 10 marcadores SECRET-* + e-mail: nenhuma ocorrência

> Sanitização não promete detectar tokens em path/HTML livre; esses corpos são omitidos com aviso.

Asserções: 19 passaram, 0 falharam (0.04 s).

## 9. Ciclo real de captura no macOS — aprovado

Evidência:

- execução real: `tests/capture/runs/20261027T0730Z` (gerada por `tests/capture/run-cycle.sh`); cópia estável em `tests/results/capture-latest/run.json`
- app empacotado: `ScrapeLens.app` 13.23 MiB, arm64, ad-hoc, binário único, executável `a7004d4e95e86e2d53750a76b0579d345cabf6e53cb25c3b15c446d25ec522c0`; captura ao vivo capture-1793085113332 (11 req, 154 headers verificados, 2 ambíguas); importação HAR pela UI `har-3dbc391c02a985c5-2` (24 req, ['h1', 'h2'], 24 sourceEvents); importação NetLog pela UI `netlog-1704043c442dcbd1-2` (32 req, ['h1', 'h2', 'h3', 'unknown'], 15 StreamSessions, 5354 sourceEvents).
- sessões reais do app: `/Users/cesar/Library/Application Support/app.scrapelens.desktop/sessions` · prints `tests/results/app-latest/screenshot-app-live.png` e `tests/results/app-latest/screenshot-app-imports.png`
- CLI: Chrome 156.0.8078.48; 27 requisições; 14 StreamSessions h3; 2 ambíguas; redirects=6

> A página real `/page` exercitou redirects e POSTs.

> O HAR do ciclo é reconstruído do CDP (`experiments/har_from_cdp.mjs`), porque o Chrome 156 não expõe `Network.getHAR`; o creator declara a origem e a ordem não é comprovada (unverified).

> O ciclo real usa CDP, que não busca corpos: todos os corpos ficam `unavailable` com nota. A captura de corpo (Network.getResponseBody) ainda não está no caminho ao vivo.

> Nesta rodada o ciclo Iniciar/Encerrar foi refeito no bundle final (`a7004d4e95e8`, compilado em 2026-10-27 04:00 UTC−03 com o core até `b5846be`, incluindo `f6c6bdd`); a sessão ao vivo acima é nova, não reaproveitada.

> As importações HAR e NetLog também foram refeitas no bundle final (`har-3dbc391c02a985c5-2` e `netlog-1704043c442dcbd1-2`), agora pela UI: o usuário selecionou os arquivos manualmente porque o painel nativo de arquivos não é alcançável por clique sintético neste ambiente (o TCC foi concedido; a limitação é do seletor). A verificação é independente da confirmação do usuário: o HAR gravado reproduz a sequência método/URL de `har-derived.json` (24 entradas) e o `netlog.json` persistido é byte-idêntico ao `h1h2h3.chrome-netlog.json` (SHA-256). O usuário importou cada arquivo duas vezes; as cópias repetidas têm `session.json` idêntico e ficam em `har-3dbc391c02a985c5` e `netlog-1704043c442dcbd1`, sem efeito na validação. O NetLog isolado avisa `netlog.time_unit_assumed` porque, sem CDP, a unidade do relógio do NetLog não pode ser calibrada — a limitação fica explícita na sessão.

Asserções: 118 passaram, 0 falharam (0.11 s).

## 10. Importação grande com tamanho documentado — aprovado

Evidência:

- `/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` → HAR 16.6 MiB, 20,000 requisições, 1.08 s, pico 786 MiB RSS
- sessão gravada: session.json 225.8 MiB
- `/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` → 4.05 s, pico 2158 MiB RSS
- complementar, 20,000 anexos de 20 B: import 3.72 s, pico 795 MiB, sessão 228.9 MiB

> HAR principal: 20,000 requisições, 16.6 MiB, sem corpos (o caminho patológico com 20 mil anexos é medido à parte).

> `inspect` materializa o JSON pretty da sessão inteira (225.8 MiB); o pico de 2158 MiB vem da serialização, não do parser.

> Correção do core confirmada: acima de 256 anexos o `fsync` passa a ser em lote por diretório — 20,000 anexos de 20 B importam em 3.72 s (eram 128 s na bateria anterior). Sessões pequenas mantêm `fsync` por arquivo.

Asserções: 7 passaram, 0 falharam (10.83 s).

## Como reproduzir

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/aceite/run_acceptance.py --build-fixtures
python3 tests/aceite/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/aceite/run_acceptance.py   # usa a última captura registrada
```

Tudo offline: fixtures sintéticas em `fixtures/aceite/`, domínios `.invalid`; o critério 9 usa Chrome com perfil temporário dedicado e servidores locais. Nada é publicado e nenhuma telemetria é gerada.
