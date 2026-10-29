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
  O adaptador só vale com `--adapter natural-ajax`; sem a flag, o script sai
  pelo caminho por trechos (controle). Padrão **estrito** nas partes do adaptador: literal só para papel Structure,
  constante comprovada (≥ 2 requisições da sessão ou contexto estático),
  navegação ou *constante de UI* (booleanos e números de até 4 caracteres com
  sinal/decimal: `true`, `-180`, `2.0`) ou nome de comando/recurso do
  cabeçalho (`event`, `page`, `model`, como `cmd_filtro`) sem cara de
  identificador nem PII; qualquer outra parte sem origem vira
  parâmetro obrigatório, e valor com origem em outra rodada nunca é literal.
  `--lenient-parts` (intermediário): só valor com cara de identificador,
  segredo ou carimbo de tempo (UUID, hex, ULID, base64, timestamp,
  alfanumérico misto) vira parâmetro. `adapter-roundtrip <sessao>` imprime
  `{"fields", "divergences", "divergenceKinds", ...}` (só agregados).

Testes: `cargo test` (round-trip nas fixtures e, se existirem, nos 3 HARs
reais, só agregados), `python3 scripts/prove_strict.py` (detran-sim em modo
`strict`, só 127.0.0.1).
