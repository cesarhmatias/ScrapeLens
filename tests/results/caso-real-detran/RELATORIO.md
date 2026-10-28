# Caso real DETRAN-PB com o ScrapeLens — validação (HEAD 7e4cc9b, core release)

Dados agregados apenas: sem valores reais (SESSIONID, cookies, STAMP, delta, placas), sem HAR bruto.
Diretório de trabalho temporário `/tmp/sl-real` (0700), apagado ao fim. Sem rede, replay nem execução de
código exportado. Rótulos das sessões importadas: `har-import` (sem `synthetic-fixture`). Os HARs são
`WebInspector` (DevTools).

Siglas: **H1** = `sem_captcha.har` (1 página); **H2** = `wsdetran.pb.gov.br.har.txt.har` (3 páginas);
**H3** = `wsdetran.fluxo.captcha.solve…har.txt.har` (5 páginas). IDs lógicos do core: `har-NNNN`.

## 1. Import (`import-har`)

| HAR | Tamanho | Requisições | GET/POST | Avisos | Corpos de resposta | postData (POSTs) | Tempo | Pico de memória |
|---|---|---|---|---|---|---|---|---|
| H1 | 12,6 MiB | 135 | 127/8 | 0 | 126 captured, 9 empty | 8/8 captured | 1,26 s | 50 MiB |
| H2 | 19,2 MiB | 209 | 190/19 | 0 | 182 captured, 12 empty, 15 unavailable | 19/19 captured | 1,55 s | 76 MiB |
| H3 | 31,8 MiB | 346 | 323/23 | 0 | 313 captured, 16 empty, 17 unavailable | 23/23 captured | 0,35 s | 125 MiB |

- Nenhum truncado/descartado. Completeness `complete` nas três. Uma única tentativa por requisição (sem redirects).
- `unavailable` nas respostas = HAR sem `content.text` ("response.content sem text"): 4 POSTs do Connector em H2/H3
  (primeira rodada de `cmd_filtro`, `cmd_consultar_placa` ×2 e `cmd_nova`) e GETs de proteção.
- `requestBody` dos GETs aparece como `unavailable` ("HAR não fornece postData") em 127/190/323 requisições, sem ser
  um corpo realmente ausente (ver lacuna L7).
- H3 contém as 209 primeiras requisições de H2 (IDs, métodos e caminhos iguais; `compare H2 H3` = 209 pares
  100% estáticos) mais 137 requisições de novas rodadas: H3 **não é uma 2ª captura independente**.
- Os HARs vêm de "Export HAR" do DevTools: **0 headers `Cookie`/`Set-Cookie` e 0 `cookies[]` em todas as
  entradas** (removidos pela exportação). Por isso nenhuma origem `cookie-jar` é possível (L2).

## 2. Busca `cmd_consultar_placa` (escopo requestBody)

| HAR | POSTs achados | field | exact | decoded | url |
|---|---|---|---|---|---|
| H1 | 2 (`har-0127`, `har-0133`) | `XML` | sim (19 B) | sim | 0 |
| H2 | 5 (`har-0093/0096/0192/0198/0207`) | `XML` | sim (19 B) | sim | 0 |
| H3 | 5 (mesmos IDs de H2) | `XML` | sim (19 B) | sim | 0 |

Busca de `on_interceptor`, `cmd_filtro`, `cmd_nova` e `m_currentSessionId` também acha as requisições certas.
Cada comando de busca: ~0,10 s, 8–14 MiB. **Atende o requisito 1 do caso** (achar a consulta pelo corpo, não pela URL).

## 3. Origens e cadeia do 1º `cmd_consultar_placa`

Alvos: H1 `har-0127`; H2/H3 `har-0093` (resposta do `cmd_filtro` anterior indisponível no HAR) e `har-0192`
(2ª rodada, completa). Tempos: origins 0,24 s/17 MiB (H1), 0,63 s/26 MiB (H2), 1,27 s/35 MiB (H3);
chain 0,08 s, 0,29 s, 0,21 s (≤ 37 MiB).

**Fluxo reconhecido?** Sim, na sequência de eventos do corpo: `easynat-app?op=S37` (har-0001) → `NatLogon.html` →
`init` NatLogon → `SIM1000X.html` → `init` → `on_interceptor` → `VES0009X.html` → `init` → `cmd_filtro` →
`cmd_consultar_placa` (→ `cmd_nova` → 2ª consulta). A **cadeia devolvida pelo core NÃO corresponde** a esse fluxo:

| Item | Resultado | Avaliação |
|---|---|---|
| SESSIONID | `possível origem (value-match)`, produtor `har-0001` (easynat-app, literal `m_currentSessionId`) em H1 e H2 (`har-0104` = easynat-app da 2ª rodada em H2/H3); composite com trecho no XML também `possível` | correto, força média por desenho |
| STAMP | **`sem origem observada`** (H1) / `repeated` (H2, H3) | **ERRO de cobertura (L1)**: o STAMP do POST == STAMP da resposta do POST anterior em 100% dos POSTs com resposta disponível (H1 5/5, H2 10/10; primeira linha = POSTs não-`init`) |
| delta (trecho `x…` do XML) | sem produtor (nenhum trecho do XML aponta para a resposta anterior do Connector); trechos `possível` apontam para páginas/JS (`har-0001`, `har-0098`, `har-0007`) e 1 `ambíguo` (`har-0029`, jquery-ui) | **ERRO (L1)** + ruído (L3): continuidade do delta anterior→resposta confirmada fora da ferramenta (mesmos 5/5 e 10/10) |
| cookies TS*/JSESSIONID | **não aparecem** (HAR sem cookies) | limite do dado (L2) |
| PAGEINITPARAM, ERRORMESSAGE | `none` (vazios) | correto |
| placa (`v_placa` no XML) | sem origem (entrada do usuário) | correto |
| `/TSPD/` e scripts do F5 | 70 (H1) e 85 (H2) passos classificados `protection` (motivo só `initiator`/`complement`) e nenhum na lista de aplicação | **correto**: a separação proteção × aplicação funcionou; mas sem cookie (L2) não há prova forte |

Cadeia de aplicação devolvida: H1 = 5 passos (`easynat-app`, 2 scripts `ciscentral/cisadvanced…`, `jquery-ui.min.js`,
`VES0009X.html`), H2 = 6 (mais o 2º `easynat-app`). **Faltam** NatLogon, SIM1000X e, principalmente, os 4–5 POSTs do
Connector (`init`, `on_interceptor`, `init`, `cmd_filtro`) que fornecem STAMP e delta (o "priming de 9 requisições" do
usuário). **Excesso**: scripts estáticos (`jquery-ui`, `cis*`) entram por value-match de constantes curtas/modelos
dentro do XML (confiança `possible`). `unresolved`: 4–5 campos (SESSIONID `repeated`, STAMP `none`, `If-Modified-Since`,
`If-None-Match`, query `op`).

Causa-raiz de L1: nas respostas reais do Connector o payload não vem como `application/x-www-form-urlencoded` e sim
como **HTML (10–15 KB, com script do F5 antes) contendo `<textarea name="XML">`, `<textarea name="ERRORMESSAGE">` e
`<input type="hidden" name="STAMP" value="…">`**. O extrator de origens só lê campos form-urlencoded/JSON/literais
de script; controles de formulário HTML não são lidos. As fixtures sintéticas da R5 usavam resposta form-urlencoded
(forma diferente da real): a verde das fixtures **não** provou o caso real.

## 4. Compare entre HARs

Compatíveis: H1×H2 (mesmo fluxo, capturas distintas). H2×H3 não serve (H3 ⊃ H2).
H1×H2: 108 pares, `alignedBy=model`, 0 fora de ordem, 20 reordered, **27 só em A, 101 só em B, 51 ambiguidades**
(H2 tem 2 rodadas completas; o pareamento monotônico casa H1 com a **2ª rodada de H2** a partir do `init` SIM1000X e
deixa a 1ª rodada como "só em B"); contagem de campos: 70 estáticos, 61 dinâmicos (17 runtime, 44 sem origem), 1 só em B.
Tempo 0,25 s / 36 MiB.

Por POST do Connector pareado (7 pares):

| Campo | Resultado | Avaliação |
|---|---|---|
| SESSIONID | `dinâmico` + `dinâmico sem origem (valor já circulava)` em 6 de 7 pares; no 1º par `dinâmico sem origem` | dinâmico: correto. Origem: **incompleta** — deveria ser `obter em runtime (origem possível: har-0001/0104)` |
| STAMP | `estático` nos pares de `init` (ambos `INIT`), `dinâmico` + `sem origem` nos demais | dinâmico: correto. "sem origem": ERRO (L1) |
| delta / trechos do XML | partes `dinâmico` com `obter em runtime (origem possível…)` (ex. 2–4 por par) e partes `dinâmico sem origem` (1–4 por par) | misto: partes certas (modelo/página) e delta/placa sem origem (placa correta; delta ERRO L1) |
| PAGEINITPARAM / ERRORMESSAGE | `estático` (vazios), exceto 1 par com PAGEINITPARAM dinâmico `possível` | correto |
| placa | dentro do XML: parte `dinâmico sem origem` | correto |
| cookies | ausentes (HAR) | limite do dado |

## 5. Sanitize

`sanitize` de H1 (0,16 s, 26 MiB) e H2 (0,34 s, 39 MiB); verificação feita por mim sobre o diretório sanitizado
inteiro (session.json + anexos), sem citar valores:

| Valor | H1 antes → depois | H2 antes → depois |
|---|---|---|
| SESSIONID (1 e 2 valores distintos) | 32 → **0** ocorrências | 76 → **0** |
| placas (2 valores distintos) | 8 → **4** (2 de 2 ainda presentes) | 16 → **10** (2 de 2 ainda presentes) |

As placas remanescentes estão nos **anexos de corpo de requisição** (`*.request.bin`), dentro do campo opaco `XML`
(`v_placa`); as respostas deixam de conter a placa. Rótulos da saída: `har-import`, `sanitized`. SESSIONID some
(propagação por valor funciona); **placas de terceiros não somem** (L5).

## 6. Tempos e memória (macOS arm64, core release)

| Comando | H1 | H2 | H3 |
|---|---|---|---|
| import-har | 1,26 s / 50 MiB | 1,55 s / 76 MiB | 0,35 s / 125 MiB |
| search | 0,10 s / 8 MiB | 0,10 s / 11 MiB | 0,11 s / 14 MiB |
| origins | 0,24 s / 17 MiB | 0,63 s / 26 MiB (0,14 s no alvo `har-0192`) | 1,27 s / 35 MiB (0,22 s) |
| chain | 0,08 s / 19 MiB | 0,29 s / 24 MiB (0,08 s) | 0,21 s / 37 MiB (0,11 s) |
| compare | H1×H2: 0,25 s / 36 MiB | H2×H3: 0,12 s / 20 MiB | — |
| sanitize | 0,16 s / 26 MiB | 0,34 s / 39 MiB | não executado |

Todos abaixo de 1,6 s e 130 MiB; sem problema de desempenho.

## Veredito

**Parcial: o caso é identificável, mas só parcialmente analisável com a ferramenta.**
- ✔ Importa os três HARs sem aviso, acha as consultas pelo corpo (`XML`, exact, decoded, 0 por URL), separa
  `/TSPD/` e scripts do F5 como proteção, resolve SESSIONID (possível) e compara dinâmico × estático.
- ✘ Não reconstrói a cadeia que o usuário fez à mão: **faltam os POSTs do Connector** (STAMP/delta) e entram
  scripts estáticos; STAMP e delta saem "sem origem", embora a continuidade resposta→requisição seja de 100% nos dados.
- ✘ Sanitização deixa placas de terceiros.

## Lacunas → requisitos

| ID | Lacuna | Requisito proposto |
|---|---|---|
| L1 | Respostas HTML com controles de formulário (`<input name=STAMP value>`, `<textarea name=XML>`) não geram candidatos de origem | Extrair pares nome/valor de `<input>`, `<textarea>` e `<select>` de respostas HTML como campos de resposta (same-field para STAMP; value-match dentro do XML para o delta); suportar entidades HTML; fixtures sintéticas devem usar essa forma real |
| L2 | HAR do DevTools não traz Cookie/Set-Cookie (exportação sem cookies) | Declarar na importação/UI que o HAR não contém cookies e a origem de cookies não é avaliável; sugerir captura CDP/NetLog |
| L3 | Excesso: scripts estáticos (`jquery-ui`, `cis*`) como produtores `possible`/`ambíguo` por constantes/modelos no XML | Filtrar produtores que são recursos estáticos (JS/CSS/imagens) ou rebaixar/agrupar; separar "constante do protocolo" de "valor de sessão" |
| L4 | Cadeia sem os POSTs do Connector e sem NatLogon/SIM1000X | Depende de L1; adicionar passos de página (`html`) por iniciador/Referer quando o POST é "carregado" por ela |
| L5 | Sanitização não cobre placas (campos de negócio no XML opaco) | Lista configurável de campos sensíveis do protocolo (`v_placa`, etc.) com propagação por valor dentro do XML; relatório de redações |
| L6 | Pareamento do compare com capturas de 2 rodadas deixa a 1ª rodada "só em B" e dá 51 ambiguidades | Alinhar por fase/ocorrência do modelo (rodada) e mostrar rodadas como grupos; permitir escolher a faixa de requisições a comparar |
| L7 | `requestBody` de GET aparece como `unavailable` ("HAR não fornece postData") | GET sem corpo deve ser `none/não aplicável`, reservando `unavailable` para corpo realmente indisponível |
| L8 | Unavailable de respostas do Connector em H2/H3 (1ª rodada) bloqueia a origem do 1º `cmd_consultar_placa` | Na UI, indicar qual produtor está indisponível e sugerir a ocorrência equivalente na rodada seguinte |
