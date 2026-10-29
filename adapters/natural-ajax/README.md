# scrapelens-natural-ajax

Adaptador do protocolo **Natural for Ajax** (campo `XML` do Connector) para o
ScrapeLens. Vive fora do core: depende de `scrapelens-core` só pelo trait
`ProtocolAdapter`.

- `grammar`: gramática independente do trait (comprimentos em unidades UTF-16,
  análise linear, erro em vez de panic). Requisição: `i`/`v` + larguras
  `2,2,2,2,2,3,5,1`, `p` (2/5) e `x` (2). Resposta: `l s p q z w b c k x`.
- `NaturalAjax`: implementa o trait. Partes: `op` (estrutura crua), cabeçalho
  `sid pid model page event` (valor) e `empty dummy flag` (estrutura),
  `p.<nome>` (valor), `s.<chave>` (nome), `delta`. Os prefixos de comprimento
  nunca são partes: o `encode` os recalcula.
- `PYTHON_ENCODER` / `PYTHON_DECODER`: o codificador (e o decodificador usado
  para extrair partes das respostas) que o script de priming inclui,
  equivalentes ao Rust (testados lado a lado).
- `natural-core`: wrapper do CLI do core com o adaptador registrado
  (`export-priming`; os outros subcomandos vão ao `scrapelens-core`).
  `--sem-adaptador` gera o script pelo caminho por trechos (controle).

Testes: `cargo test` (round-trip nas fixtures e, se existirem, nos 3 HARs
reais, só agregados), `python3 scripts/prove_strict.py` (detran-sim em modo
`strict`, só 127.0.0.1).
