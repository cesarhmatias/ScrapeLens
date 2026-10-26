# Relatório de aceite — ScrapeLens MVP

Execução: 2026-10-26T23:29:01Z · binário do core `4e0edc61b02d` (2155344 bytes) · commit `7011792`

Ambiente: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Critério da spec | Status | Asserções |
|---|---|---|---|
| 1 | Headers repetidos e cookies preservados nas fixtures | **aprovado** | 29/29 |
| 2 | HAR e NetLog válidos, incompletos e com eventos desconhecidos | **aprovado** | 22/22 |
| 3 | Requisições simultâneas idênticas sem associação falsa | **aprovado** | 15/15 |
| 4 | Redirects e múltiplas tentativas | **aprovado** | 12/12 |
| 5 | Corpos ausentes/truncados/descartados explícitos | **aprovado** | 16/16 |
| 6 | Diff sem perder duplicatas | **aprovado** | 14/14 |
| 7 | Exportação cURL/Python com caracteres especiais | **aprovado** | 23/23 |
| 8 | Sanitização incluindo eventos brutos | **aprovado** | 19/19 |
| 9 | Ciclo real de captura no macOS | **aprovado** | 47/47 |
| 10 | Importação grande com tamanho documentado | **aprovado** | 7/7 |

Critérios do pedido: (1) headers repetidos/cookies, (2) HAR/NetLog válidos/incompletos/desconhecidos, (3) simultâneas idênticas sem associação falsa, (4) redirects/tentativas, (5) corpos explícitos, (6) diff com duplicatas, (7) escaping cURL/Python, (8) sanitização com eventos brutos, (9) ciclo real macOS, (10) importação grande medida.

## 1. Headers repetidos e cookies preservados nas fixtures — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/headers-cookies/headers-cookies.har --out tests/.work/run/item1/har`
- `scrapelens-core import-netlog fixtures/aceite/headers-cookies/headers-cookies.netlog.json --out tests/.work/run/item1/netlog`
- asserções: sequência/caixa/duplicatas, Cookie bruto+pares, Set-Cookie bruto+parseado, verificação por fonte

Asserções: 29 passaram, 0 falharam (0.05 s).

## 2. HAR e NetLog válidos, incompletos e com eventos desconhecidos — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/parsers/incomplete.har --out tests/.work/run/item2/incomplete-har`
- `scrapelens-core import-netlog fixtures/aceite/parsers/unknown-events.netlog.json --out tests/.work/run/item2/unknown`
- `scrapelens-core import-netlog fixtures/aceite/parsers/no-constants.netlog.json --out tests/.work/run/item2/no-constants`
- casos inválidos: retorno ≠ 0 com `erro:` no stderr (HAR sem entries, NetLog truncado)

> HAR não comprova ordem/duplicatas: entradas importadas ficam `unverified`, como no contrato.

> Observação: importadores HAR/NetLog isolados não gravam `completeness.counts.sourceEvents*` (fica 0 após reler); a contagem de eventos desconhecidos permanece auditável no aviso e nos eventos brutos.

Asserções: 22 passaram, 0 falharam (0.11 s).

## 3. Requisições simultâneas idênticas sem associação falsa — aprovado

Evidência:

- `scrapelens-core import-capture fixtures/aceite/ambiguous/cdp-ambiguous.jsonl fixtures/aceite/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

> A ordem/duplicata do NetLog é preservada, mas não vira visão primária enquanto há ambiguidade.

Asserções: 15 passaram, 0 falharam (0.04 s).

## 4. Redirects e múltiplas tentativas — aprovado

Evidência:

- `scrapelens-core import-netlog fixtures/aceite/redirects/redirect-chain.netlog.json --out tests/.work/run/item4/netlog`
- `scrapelens-core import-har fixtures/aceite/redirects/redirect-chain.har --out tests/.work/run/item4/har`

> O redirect é um elo entre tentativas, não uma requisição separada.

Asserções: 12 passaram, 0 falharam (0.04 s).

## 5. Corpos ausentes/truncados/descartados explícitos — aprovado

Evidência:

- `scrapelens-core inspect fixtures/aceite/bodies/session`

> `empty` só é usado quando a fonte afirma zero bytes; ausência vira `unavailable` com nota.

Asserções: 16 passaram, 0 falharam (0.00 s).

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

Asserções: 23 passaram, 0 falharam (0.14 s).

## 8. Sanitização incluindo eventos brutos — aprovado

Evidência:

- `scrapelens-core sanitize fixtures/aceite/sanitize/session tests/.work/run/item8/sanitized`
- permissões: `0o700` no diretório e `0o600` no session.json
- varredura recursiva por 10 marcadores SECRET-* + e-mail: nenhuma ocorrência

> Sanitização não promete detectar tokens em path/HTML livre; esses corpos são omitidos com aviso.

Asserções: 19 passaram, 0 falharam (0.03 s).

## 9. Ciclo real de captura no macOS — aprovado

Evidência:

- execução real: `tests/capture/runs/20261026T232758Z` (gerada por `tests/capture/run-cycle.sh`); cópia estável em `tests/results/capture-latest/run.json`
- Chrome 156.0.8078.48; 27 requisições; 14 StreamSessions h3; 4 ambíguas; redirects=6

> A página real `/page` exercitou redirects e POSTs.

> O HAR do ciclo é reconstruído do CDP (`experiments/har_from_cdp.mjs`), porque o Chrome 156 não expõe `Network.getHAR`; o creator declara a origem e a ordem não é comprovada (unverified).

> O ciclo real usa CDP, que não busca corpos: todos os corpos ficam `unavailable` com nota. A captura de corpo (Network.getResponseBody) ainda não está no caminho ao vivo.

Asserções: 47 passaram, 0 falharam (0.10 s).

## 10. Importação grande com tamanho documentado — aprovado

Evidência:

- `/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` → HAR 16.6 MiB, 20,000 requisições, 0.88 s, pico 783 MiB RSS
- sessão gravada: session.json 225.8 MiB
- `/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` → 2.64 s, pico 2344 MiB RSS
- complementar, 20,000 anexos de 20 B: import 128.05 s, pico 565 MiB, sessão 228.9 MiB

> HAR principal: 20,000 requisições, 16.6 MiB, sem corpos (o caminho patológico com 20 mil anexos é medido à parte).

> `inspect` materializa o JSON pretty da sessão inteira (225.8 MiB); o pico de 2344 MiB vem da serialização, não do parser.

> Pior caso de anexos: um `fsync` por arquivo em `store::write_file` domina (128.1 s para 20,000 anexos 20 B). O parser gasta <1 s de CPU; é custo de I/O da gravação. Recomendo batching/adiar fsync no core.

Asserções: 7 passaram, 0 falharam (8.11 s).

## Como reproduzir

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/aceite/run_acceptance.py --build-fixtures
python3 tests/aceite/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/aceite/run_acceptance.py   # usa a última captura registrada
```

Tudo offline: fixtures sintéticas em `fixtures/aceite/`, domínios `.invalid`; o critério 9 usa Chrome com perfil temporário dedicado e servidores locais. Nada é publicado e nenhuma telemetria é gerada.
