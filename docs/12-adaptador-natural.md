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

## Revisão da rodada 8 (2026-10-29) — decisões

Veredito: parcial (2 falhas altas). A gramática é correta e o round-trip é
exato.
- Limites do adaptador (Rust e Python gerado): profundidade de escopo ≤ 32,
  chaves de dicionário ≤ 10 mil, path guardado como pilha de índices e
  montado sob demanda, nomes em mapa. Custo linear: `b01a`×40 mil em < 1 s e
  < 100 MB. `detect` é barato (cabeçalho e no máximo um parse curto, com o
  resultado reaproveitado); o app limita o tamanho do campo decodificado.
- O priming com adaptador aplica `is_sensitive_name`/`is_pii_name` ao último
  componente do nome da parte (`XML.p.v_senha` → senha) e às mesmas listas do
  caminho sem adaptador. Uma parte sensível vira parâmetro obrigatório ou
  recusa.
- Nomes genéricos (id, type, lang, q, page, flag, …) são avaliados pelo
  último componente dos nomes internos, e o same-field forte fica rebaixado.
- O adaptador não pode piorar a cobertura: quando a origem de uma parte está
  numa resposta sem corpo, o gerador segue a regra da rodada 7 (recusa só
  com a cadeia de fato incompleta, e o alvo alternativo com resposta
  anterior capturada deve gerar). O check exige o gerador COM adaptador
  nesse alvo.
- O decodificador Python gerado é tão estrito quanto o Rust (escopo aberto
  no fim, par substituto cortado → erro).
- Re-revisão em b0ce0f0: as 2 altas anteriores foram aprovadas. Decisões
  novas: (1) nenhum valor com origem observada (forte ou possível) pode
  virar literal. Se uma parte do adaptador tem produtor fora do plano, o
  produtor entra no plano (mesma rodada, na ordem da sessão, junto da cadeia
  base); se o produtor está fora da rodada ou sem corpo, a geração segue a
  regra de incompletude. (2) Limite de operações por campo (≤ 200 mil) e
  `Item` compacto: `l`×8 MiB < 500 MB. O app corta a visão em 2 000 partes
  por campo ("N partes omitidas"). (3) As listas de nomes sensíveis/PII
  passam a incluir abreviações: pwd, pass, psw, pswd, pin, otp, passcode,
  seguranca, cookie, nm_*, aniversario, filiacao, logradouro, bairro,
  titular, proprietario, razaosocial, conta, sexo. As mesmas listas valem nos
  dois caminhos. (4) O wrapper conta a profundidade de re-execução por
  variável de ambiente e recusa quando o fallback for ele mesmo. (5) `flag`
  entra na lista de genéricos.
- Re-revisão em 5d2c6e6: hid2, custo, abreviações e wrapper aprovados.
  Decisões de princípio para as partes do adaptador:
  (1) Produtor fora do plano, em qualquer rodada: com evidência forte, o
  produtor sobe para o plano (como na cadeia); com evidência possível, ou
  produtor sem corpo, a parte vira parâmetro obrigatório com nota. Nunca
  literal em silêncio.
  (2) Literal numa parte do adaptador só para: papel Structure; valor
  constante comprovado (o mesmo valor em ≥ 2 ocorrências da sessão, inclusive
  entre rodadas, ou presente em contexto estático); ou valor de navegação
  (nome de página/recurso da própria cadeia). Qualquer outra parte vira
  parâmetro obrigatório. Medir nos 3 HARs reais: os valores repetidos (ex.:
  timeZoneOffset, #f12_selected) seguem constantes; só valores únicos e sem
  origem viram parâmetro.
  (3) Lista de nomes: acrescentar pw, pswrd, passw, pwrd, 2fa, mfa, totp,
  salt, hash, assinatura, login, usuario, uid, pai, responsavel,
  beneficiario, agencia, banco, iban, whatsapp, rua, complemento, municipio,
  documento. Falsos positivos de nome (ex.: conta_corrente) são aceitos
  como erro do lado seguro: viram parâmetro, nunca vazam.
  (4) Passo produtor que não fornece nenhum valor referenciado sai do plano.
- Decisão do líder sobre o princípio (2), medido pela Captura em b4511fb: o
  estrito por padrão transformaria estado de UI (`v_filtro_sel`,
  `interceptor_is_active`, `#f12_selected`, `pagePixelHeight/Width`) em
  parâmetros obrigatórios nos HARs reais, sem ganho de segurança. Padrão:
  modo intermediário. Toda parte sem origem e sem prova que tenha cara de
  identificador, segredo ou carimbo de tempo (UUID, hex, ULID/KSUID, base64,
  timestamp, alfanumérico misto, senha-padrão) vira parâmetro obrigatório.
  Constantes de UI ficam literais, definidas explicitamente: booleanos,
  números de até 4 caracteres (com sinal e decimal) e valores
  repetidos/navegação. Nomes sensíveis e detectores de PII continuam valendo.
  O modo estrito fica disponível por `--strict-parts`. O produtor de outra
  rodada só sobe para o plano com ValueMatch forte; SameField de campo
  repetido não sobe, para não puxar a rodada anterior.
