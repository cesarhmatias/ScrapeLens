# Rodada 6 — fidelidade ao caso real DETRAN-PB

## Motivo

A validação nos HARs reais do usuário (`tests/results/caso-real-detran/RELATORIO.md`,
fa54020) deu veredito parcial: o caso é identificável, mas só em parte
analisável. As fixtures sintéticas tinham respostas form-urlencoded, e as
reais trazem HTML com controles de formulário. O verde das rodadas 4 e 5 não
provou o caso real. Esta rodada fecha as lacunas L1–L8 do relatório.

Fora do escopo: decodificador Natural for Ajax, burlar /TSPD/ ou CAPTCHA,
replay, rede externa e publicação.

## Ondas e propriedade

- 6a: Core (`core/`) e Testes (`fixtures/`, `tests/`): fixtures com a forma
  real e aceite.
- 6b: App (`app/`, `commands.rs`, `lib.rs`), revalidação nos HARs reais
  (Testes) e revisão independente.

## Decisões

L1 — Controles de formulário HTML como campos de resposta. Um tokenizador HTML
tolerante (sem executar nada e sem DOM completo) extrai de respostas
text/html: `<input name value>` (todos os tipos; checkbox/radio só se
`checked`), `<textarea name>conteúdo</textarea>` e `<select name>` com a
`<option selected>`. As entidades HTML são decodificadas na visão
decodificada, com offsets mapeados para o original. Esses controles viram
campos `responseBody` com `field` = nome, `htmlControl: true`, e alimentam
same-field (STAMP) e value-match (incluindo trechos do `XML` de textarea ≥ 40
bytes, que é onde está o delta). A busca também passa a enxergar esses campos
por nome.

L2 — HAR sem cookies: na importação, se nenhuma entrada traz Cookie,
Set-Cookie ou `cookies[]`, o aviso de sessão é `har.cookies_absent`: "o HAR não
contém cookies (exportação do DevTools os remove); origem de cookies não
avaliável — use captura ao vivo (CDP/NetLog)". As origens e a cadeia repetem o
aviso.

L3 — Recursos estáticos (script, stylesheet, font, image e media, por tipo do
recurso ou MIME) não são produtores na cadeia. Uma evidência value-match vinda
deles vira `context` ("valor também presente em recurso estático: provável
constante do protocolo") e não cria passo. Um valor presente em recurso
estático e em respostas dinâmicas mantém só os produtores dinâmicos.

L4 — Páginas de contexto: a cadeia ganha o grupo `pages`, com as requisições
de documento que carregaram a página de onde cada passo foi emitido (por
Referer ou iniciador). O rótulo é "página de contexto"; elas não são
produtoras de valor. Com L1, os POSTs do Connector (init, on_interceptor,
cmd_filtro) devem entrar como passos por STAMP/delta.

L5 — Campos de negócio sensíveis: a lista configurável tem como padrão
placa, v_placa, plate, renavam, cpf, cnpj, chassi e vin (case-insensitive,
inclusive como sufixo do nome). Em campos nomeados, o valor é redigido e
propagado. Em campos opacos, cada ocorrência de um desses nomes seguida do
valor no formato do tipo é redigida: placa `[A-Z]{3}[0-9][A-Z0-9][0-9]{2}`,
CPF de 11 dígitos, CNPJ de 14, RENAVAM de 9 a 11 e chassi de 17
alfanuméricos sem I/O/Q. Os valores achados entram na propagação por valor
da sessão inteira. O relatório conta as redações por tipo, sem mostrar os
valores. Um valor que não segue o formato não é redigido em silêncio:
gera o aviso `sanitize.business_field_unmatched`.

L6 — Compare por rodadas: a opção padrão é alinhar só as requisições de
aplicação (sem proteção nem recursos estáticos), que entram depois como
grupos próprios. Rodadas: segmentação automática pela requisição de entrada
(o 1º documento da aplicação que se repete, ex.: easynat-app). Cada rodada de
A é alinhada à rodada mais parecida de B, e as rodadas sem par são listadas.
Opção explícita de faixa (`--a-range`, `--b-range`). As ambiguidades devem
cair drasticamente em H1×H2.

L7 — Corpo de requisição de método sem corpo (GET/HEAD/OPTIONS) sem postData
no HAR fica `empty`, com o motivo "não aplicável: método sem corpo".
`unavailable` só quando um corpo era esperado e não veio.

L8 — Quando a origem de um valor depende de uma resposta `unavailable`, o
`unobservable` aponta a ocorrência equivalente na rodada seguinte, se houver
(mesmo modelo), como sugestão.

## Aceite

1. Fixtures com a forma real (Testes): respostas do Connector em HTML com
   script antes, `<textarea name="XML">`, `<textarea name="ERRORMESSAGE">` e
   `<input type="hidden" name="STAMP">`, com entidades; variante HAR do
   DevTools sem cookies; captura com 2 rodadas. Origens: STAMP same-field
   forte (resposta anterior); delta value-match no trecho do XML vindo da
   textarea anterior; SESSIONID possível; scripts estáticos sem passo. Cadeia
   com os POSTs do Connector (init, on_interceptor, init, cmd_filtro), as
   páginas NatLogon/SIM1000X/VES0009X em `pages` e /TSPD/ em proteção.
2. Sanitize: placas e CPF fictícios dentro do XML somem em todos os arquivos;
   os avisos aparecem para valores fora do formato.
3. Compare A(1 rodada) × B(2 rodadas): a rodada de A pareia com uma rodada de
   B, a outra rodada aparece como rodada sem par, e há poucas ambiguidades.
4. HAR sem cookies → aviso `har.cookies_absent`.
5. Revalidação nos 3 HARs reais (agregada, sem valores): STAMP e delta com
   origem na resposta anterior do Connector em ≥ 95% dos POSTs com resposta
   disponível; cadeia com os POSTs do Connector; placas 0 após sanitize.
6. Bateria sem regressão.
