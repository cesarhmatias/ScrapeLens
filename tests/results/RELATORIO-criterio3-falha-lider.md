# Relatório de aceite — ScrapeLens MVP

Execução: 2026-10-27T07:08:05Z · binário do core `10f3b76b637b` (2176608 bytes) · commit `453d717`

Ambiente: macOS 26.5.2 · arm64 · Python 3.14.8

| # | Critério da spec | Status | Asserções |
|---|---|---|---|
| 3 | Requisições simultâneas idênticas sem associação falsa | **falhou** | 4/7 |

Critérios do pedido: (1) headers repetidos/cookies, (2) HAR/NetLog válidos/incompletos/desconhecidos, (3) simultâneas idênticas sem associação falsa, (4) redirects/tentativas, (5) corpos explícitos, (6) diff com duplicatas, (7) escaping cURL/Python, (8) sanitização com eventos brutos, (9) ciclo real macOS, (10) importação grande medida.

## 3. Requisições simultâneas idênticas sem associação falsa — falhou

Evidência:

- `scrapelens-core import-capture fixtures/aceite/ambiguous/cdp-ambiguous.jsonl fixtures/aceite/ambiguous/netlog-ambiguous.json --out tests/.work/run/item3/capture`

Falhas:

- ambas marcadas match=ambiguous (nenhuma associação silenciosa): esperado 2, obtido 0
- as duas requisições veem o mesmo conjunto de candidatos (não houve escolha cruzada): esperado 1, obtido 0
- dois avisos correlate.ambiguous persistidos: esperado 2, obtido 0

> A ordem/duplicata do NetLog é preservada, mas não vira visão primária enquanto há ambiguidade.

Asserções: 4 passaram, 3 falharam (0.06 s).

## Como reproduzir

```sh
cd /Users/cesar/Projects/scrapelens
python3 tests/aceite/run_acceptance.py --build-fixtures
python3 tests/aceite/run_acceptance.py
tests/capture/run-cycle.sh
python3 tests/aceite/run_acceptance.py   # usa a última captura registrada
```

Tudo offline: fixtures sintéticas em `fixtures/aceite/`, domínios `.invalid`; o critério 9 usa Chrome com perfil temporário dedicado e servidores locais. Nada é publicado e nenhuma telemetria é gerada.
