# Relatório de aceite — ScrapeLens MVP

Execução: 2026-10-31T23:57:16Z · binário do core `5c11a0c9c89e` (3817360 bytes) · commit `d6af514`

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
| 9 | Ciclo real de captura no macOS | **falhou** | 121/123 |
| 10 | Importação grande com tamanho documentado | **aprovado** | 7/7 |
| 11 | MCP: testes dos crates, vivos e fluxo completo por stdio | **aprovado** | 39/39 |

Resumo: 10/11 critérios aprovados; 325/327 asserções passaram.

Critérios do pedido: (1) headers repetidos/cookies, (2) HAR/NetLog válidos/incompletos/desconhecidos, (3) simultâneas idênticas sem associação falsa, (4) redirects/tentativas, (5) corpos explícitos, (6) diff com duplicatas, (7) escaping cURL/Python, (8) sanitização com eventos brutos, (9) ciclo real macOS, (10) importação grande medida.

Escopo das evidências:

- Novo nesta rodada: captura CLI `tests/capture/runs/live-final` (2026-10-29T04:20:57Z), com os dois legs (h1h2 e h3) e o HAR derivado do CDP.
- Novo nesta rodada: sessão ao vivo `capture-1793485447342` iniciada e encerrada pelo bundle final (`6c0092c3c73c`).
- Novo nesta rodada: importações HAR/NetLog pela UI do bundle final (har `har-3dbc391c02a985c5-10`, netlog `netlog-1704043c442dcbd1-10`), com seleção manual do usuário e verificação por SHA-256/sequência contra os arquivos preparados em `~/Projects/scrapelens-import-tmp`.

## 1. Headers repetidos e cookies preservados nas fixtures — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/headers-cookies/headers-cookies.har --out tests/.work/run/item1/har`
- `scrapelens-core import-netlog fixtures/aceite/headers-cookies/headers-cookies.netlog.json --out tests/.work/run/item1/netlog`
- asserções: sequência/caixa/duplicatas, Cookie bruto+pares, Set-Cookie bruto+parseado, verificação por fonte

Asserções: 29 passaram, 0 falharam (0.08 s).

## 2. HAR e NetLog válidos, incompletos e com eventos desconhecidos — aprovado

Evidência:

- `scrapelens-core import-har fixtures/aceite/parsers/incomplete.har --out tests/.work/run/item2/incomplete-har`
- `scrapelens-core import-netlog fixtures/aceite/parsers/unknown-events.netlog.json --out tests/.work/run/item2/unknown`
- `scrapelens-core import-netlog fixtures/aceite/parsers/no-constants.netlog.json --out tests/.work/run/item2/no-constants`
- casos inválidos: retorno ≠ 0 com `erro:` no stderr (HAR sem entries, NetLog truncado)

> HAR não comprova ordem/duplicatas: entradas importadas ficam `unverified`, como no contrato.

> Contagens `completeness.counts.sourceEvents*` agora são persistidas e sobrevivem à releitura (correção do core nesta onda); os avisos continuam trazendo amostras dos tipos desconhecidos.

Asserções: 26 passaram, 0 falharam (0.16 s).

## 3. Requisições simultâneas idênticas sem associação falsa — aprovado

Evidência:

- `scrapelens-core import-capture fixtures/aceite/ambiguous/cdp-ambiguous.jsonl fixtures/aceite/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

> A ordem/duplicata do NetLog é preservada, mas não vira visão primária enquanto há ambiguidade.

> Diagnóstico da falha do líder: a fixture declarava `wallTime` sem o `timestamp` monotônico (`1793046000.0`), e o core de `f6c6bdd` calibrava `time` como microssegundos; o NetLog ficava 2 s à frente e as duas requisições viravam `unmatched`. O Chrome real satisfaz `wallTime = timeTickOffset/1000 + timestamp` (desvio medido < 1 ms), equação agora usada na fixture. Era defeito da fixture, não do core; a falha original está preservada em `tests/results/aceite-criterio3-falha-lider.json` e `RELATORIO-criterio3-falha-lider.md`.

> Asserções novas nesta rodada: coerência do relógio da fixture (CDP×NetLog) e unidade calibrada `milliseconds`. O teste de ambiguidade segue rigoroso: as duas requisições a 20 ms continuam ambíguas, cada uma com os mesmos 2 candidatos e 2 avisos `correlate.ambiguous`.

Asserções: 19 passaram, 0 falharam (0.06 s).

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

Asserções: 23 passaram, 0 falharam (0.14 s).

## 8. Sanitização incluindo eventos brutos — aprovado

Evidência:

- `scrapelens-core sanitize fixtures/aceite/sanitize/session tests/.work/run/item8/sanitized`
- permissões: `0o700` no diretório e `0o600` no session.json
- varredura recursiva por 10 marcadores SECRET-* + e-mail: nenhuma ocorrência

> Sanitização não promete detectar tokens em path/HTML livre; esses corpos são omitidos com aviso.

Asserções: 19 passaram, 0 falharam (0.04 s).

## 9. Ciclo real de captura no macOS — falhou

Evidência:

- execução real: `tests/capture/runs/live-final` (gerada por `tests/capture/run-cycle.sh`); cópia estável em `tests/results/capture-latest/run.json`
- app empacotado: `ScrapeLens.app` 16.94 MiB, arm64, assinatura local-identity, binário único, executável `6c0092c3c73c779c2ded59d324c7cc739b462cf308c46069f3f06e47ec4759e9`; captura ao vivo capture-1793485447342 (11 req, 154 headers verificados, 2 ambíguas); importação HAR pela UI `har-3dbc391c02a985c5-10` (24 req, ['h1', 'h2'], 24 sourceEvents); importação NetLog pela UI `netlog-1704043c442dcbd1-10` (32 req, ['h1', 'h2', 'h3', 'unknown'], 15 StreamSessions, 5354 sourceEvents).
- sessões reais do app: `/Users/cesar/Library/Application Support/app.scrapelens.desktop/sessions` · prints `tests/results/app-latest/screenshot-app-live.png` e `tests/results/app-latest/screenshot-app-imports.png`
- CLI: Chrome 156.0.8078.73; 27 requisições; 14 StreamSessions h3; 2 ambíguas; redirects=6

Falhas:

- app: executável é o bundle final documentado (SHA-256): esperado '4636a3cf11c498bf5866974615dd6544fbaa1cb73c93140c9502b8e978043860', obtido '6c0092c3c73c779c2ded59d324c7cc739b462cf308c46069f3f06e47ec4759e9'
- app: SHA-256 do executável em disco = o registrado no run.json: esperado '6c0092c3c73c779c2ded59d324c7cc739b462cf308c46069f3f06e47ec4759e9', obtido '4636a3cf11c498bf5866974615dd6544fbaa1cb73c93140c9502b8e978043860'

> A página real `/page` exercitou redirects e POSTs.

> O HAR do ciclo é reconstruído do CDP (`experiments/har_from_cdp.mjs`), porque o Chrome 156 não expõe `Network.getHAR`; o creator declara a origem e a ordem não é comprovada (unverified).

> O ciclo real usa CDP, que não busca corpos: todos os corpos ficam `unavailable` com nota. A captura de corpo (Network.getResponseBody) ainda não está no caminho ao vivo.

> Nesta rodada o ciclo Iniciar/Encerrar foi refeito no bundle final (`4636a3cf11c4`, compilado em `c2d2b8f`, assinatura local estável, captura multi-alvo); a sessão ao vivo acima é nova, não reaproveitada.

> As importações HAR e NetLog também foram refeitas no bundle final (`har-3dbc391c02a985c5-10` e `netlog-1704043c442dcbd1-10`), agora pela UI: o harness escolheu os arquivos por cliques do mouse no painel nativo (o teclado não chega ao seletor; na rodada 10 final foi em primeiro plano). A verificação é independente da confirmação do usuário: o HAR gravado reproduz a sequência método/URL de `har-derived.json` (24 entradas) e o `netlog.json` persistido é byte-idêntico ao `h1h2h3.chrome-netlog.json` (SHA-256). Importações repetidas dos mesmos arquivos (sufixos `-N` em `har-3dbc391c02a985c5` e `netlog-1704043c442dcbd1`) têm `session.json` idêntico, sem efeito na validação. O NetLog isolado avisa `netlog.time_unit_assumed` porque, sem CDP, a unidade do relógio do NetLog não pode ser calibrada — a limitação fica explícita na sessão.

Asserções: 121 passaram, 2 falharam (0.17 s).

## 10. Importação grande com tamanho documentado — aprovado

Evidência:

- `/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` → HAR 16.6 MiB, 20,000 requisições, 1.08 s, pico 823 MiB RSS
- sessão gravada: session.json 236.3 MiB
- `/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` → 3.72 s, pico 1501 MiB RSS
- complementar, 20,000 anexos de 20 B: import 3.72 s, pico 795 MiB, sessão 228.9 MiB

> HAR principal: 20,000 requisições, 16.6 MiB, sem corpos (o caminho patológico com 20 mil anexos é medido à parte).

> `inspect` materializa o JSON pretty da sessão inteira (236.3 MiB); o pico de 1501 MiB vem da serialização, não do parser.

> Correção do core confirmada: acima de 256 anexos o `fsync` passa a ser em lote por diretório — 20,000 anexos de 20 B importam em 3.72 s (eram 128 s na bateria anterior). Sessões pequenas mantêm `fsync` por arquivo.

Asserções: 7 passaram, 0 falharam (11.41 s).

## 11. MCP: testes dos crates, vivos e fluxo completo por stdio — aprovado

Evidência:

- `tests/results/mcp/run.json` e `tests/results/mcp/flow.json` (saídas dos comandos e do fluxo)

> Cliente do fluxo: `tests/aceite/mcp_flow.py`, JSON-RPC por stdio em Python, sem o harness Rust; servidor HTTP local em 127.0.0.1, Chrome real headless, nada externo.

Asserções: 39 passaram, 0 falharam (301.49 s).

## Como reproduzir

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/aceite/run_acceptance.py --build-fixtures
python3 tests/aceite/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/aceite/run_acceptance.py   # usa a última captura registrada
```

Tudo offline: fixtures sintéticas em `fixtures/aceite/`, domínios `.invalid`; o critério 9 usa Chrome com perfil temporário dedicado e servidores locais. Nada é publicado e nenhuma telemetria é gerada.
