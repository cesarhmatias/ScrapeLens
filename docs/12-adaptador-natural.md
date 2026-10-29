# Rodada 8 — adaptador de protocolo Natural for Ajax (fora do core)

## Motivo

O script de priming (rodada 7) troca trechos do campo `XML` por valores
extraídos em runtime, mas não recalcula os prefixos de comprimento do
protocolo Natural for Ajax. Quando o valor novo tem outro tamanho (delta,
SESSIONID, placa), o servidor real pode rejeitar a requisição. A
especificação manda manter decodificadores de protocolo fora do core, como
extensão. O usuário já tem a gramática implementada à mão em
`/Users/cesar/Projects/scripts/detran_scraper/detran_paraiba/consultar_patio.py`
(`serialize`, `decode_stream`, `jslen`: comprimentos em unidades UTF-16).
Usar esse arquivo só como referência de leitura da gramática, sem copiar
dados.

## Arquitetura

- core: só o ponto de extensão. Trait `ProtocolAdapter { id(); detect(campo,
  contexto) -> bool; decode(&str) -> Result<Estrutura>; encode(&Estrutura) ->
  Result<String> }` e um registro passado por opção a origins/priming/app. Sem
  nenhum conhecimento de Natural no core.
- `adapters/natural-ajax/` (crate novo no workspace): implementa o trait para
  o campo `XML` do Connector.
  - Requisição: cabeçalho `i`/`v` com larguras fixas; operações `p` (nome e
    valor com larguras 2/5); `x` (delta com largura 2).
  - Resposta: operações l/p/q/z/b/c/s/k/x de `decode_stream`.
  - Comprimentos em unidades UTF-16 (`jslen`).
  - Round-trip exato: encode(decode(x)) == x em todos os XML das fixtures e
    dos HARs reais (agregado).
- Visão estruturada: o app mostra o campo decodificado (sessão, processo,
  modelo, página, evento, propriedades nome→valor, delta), marcada como
  "visão do adaptador Natural (derivada)", com o bruto como primário.
- Priming: quando um adaptador reivindica o campo, o script não troca
  trechos. Ele monta a estrutura com os valores (constantes + extraídos em
  runtime + parâmetros) e chama um codificador Python gerado (equivalente ao
  `encode`, com `jslen` UTF-16), recalculando todos os prefixos. Os valores
  passam pelo mesmo filtro de PII/literais da rodada 7.
- Origens: o adaptador expõe os campos internos (ex.: `XML.p.v_placa`,
  `XML.delta`) com offsets no original, para origins/compare usarem nomes
  em vez de trechos.

## Propriedade

| Dono | Caminhos |
|---|---|
| Core | `core/` (trait, registro, integração em origins/compare) |
| Captura | `adapters/natural-ajax/`, `core/src/export/priming.rs` (integração) |
| Testes | `fixtures/`, `testserver/` (detran-sim valida prefixos), `tests/` |
| App | `app/`, `src-tauri/src/commands.rs`, `lib.rs` |

## Aceite

1. Round-trip exato do adaptador em todas as fixtures e nos 3 HARs reais
   (agregado: N campos, 0 divergências).
2. detran-sim em modo estrito (rejeita prefixo de comprimento errado): o
   script gerado completa a cadeia com valores de tamanhos diferentes dos
   capturados (delta e SESSIONID mais longos, placa Mercosul). O script da
   rodada 7, sem o adaptador, falha nesse modo; registrar como controle.
3. Origins/compare mostram nomes internos (`XML.delta`, `XML.p.v_placa`).
4. App mostra a visão estruturada; o bruto continua primário.
5. Sem regressão: bateria completa e check_real_priming (só placa e sufixo
   do SESSIONID; 0 literais).
