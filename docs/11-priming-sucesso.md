# Rodada 7 — script de priming e sucesso da aplicação × HTTP

## Motivo

Caso DETRAN-PB (`docs/05-caso-referencia-detran.md`), requisitos derivados 4
e 5. O usuário precisa de um ponto de partida que recrie a sessão nova, sem
congelar valores do HAR, e de saber quando um HTTP 200 não é sucesso da
aplicação (resposta sem XML/STAMP, com ERRORMESSAGE, ou página de bloqueio).
Pré-requisito: rodada 6 aprovada.

Fora do escopo: executar o script, fazer replay, rede, burlar /TSPD/ ou
CAPTCHA, decodificar o Natural for Ajax no core e publicar.

## Ondas e propriedade

- 7a: Core (`core/`): gerador do script e avaliador de sucesso. Testes
  (`fixtures/`, `tests/`): expectativas e aceite.
- 7b: App (`app/`, `commands.rs`, `lib.rs`): UI. Depois, revisão
  independente e validação agregada nos HARs reais.

## 1. Script de priming (Python, cliente mantido)

`export::priming::to_python(session, body_source, target_request_id, opts)`
usa `priming_chain` + `value_origins`:
- Passos na ordem da cadeia (só `steps`, nunca `protection`, `pages` de
  contexto ou estáticos). Cada passo é uma função com a requisição capturada
  (método, URL, headers suportados, corpo) e um comentário com o motivo e a
  confiança (`strong`/`possible`), passando por `export::comment`.
- Valores com origem observada/possível são extraídos em runtime da resposta
  do produtor, pelo mesmo tipo de evidência: Set-Cookie (via o cookie jar do
  cliente), controle HTML (nome), campo form/JSON (chave/caminho), literal
  (o contexto antes e depois capturado, gerado como regex escapada) ou
  trecho de campo opaco (substituição do trecho capturado pelo valor
  extraído, com os limites do contexto). Cada extração confere se achou o
  valor e, se não achou, falha com uma mensagem clara. Nunca cai em silêncio
  no valor capturado.
- Valores sem origem observada (placa, entrada do usuário, constantes) viram
  parâmetros do script, com o valor capturado como exemplo só se não for
  sensível. Os sensíveis/redigidos viram parâmetros obrigatórios, sem padrão.
  `partialComposition` vira comentário "montado no cliente: complete aqui".
- Cliente: `requests.Session` (cookie jar). Cabeçalho do script: "reprodução
  semântica; ordem de headers e fidelidade de transporte (TLS, HTTP/2,
  fingerprint) NÃO são garantidas"; "não executado pelo ScrapeLens";
  "passos que alteram estado exigem `--confirmar`". Requisições não
  idempotentes (POST/PUT/PATCH/DELETE) só rodam com a flag explícita;
  sem ela, o script imprime o plano e sai.
- Escaping: strings Python por `repr`; dados capturados nunca entram em
  código fora de literais ou comentários escapados. O script gerado é
  validado por `ast.parse` nos testes.
- CLI: `scrapelens-core export-priming <sessao> <requestId> [--out f]`.

## 2. Sucesso da aplicação × HTTP

`assess::response_outcome(request, body_source, rules)` devolve, por resposta:
`httpOk` (2xx/3xx), `appSignals[]` (ex.: controle `XML` presente e não
vazio, `STAMP` presente, `ERRORMESSAGE` não vazio, página sem os controles
esperados, marcador de proteção) e `verdict`: `app-ok`,
`app-error (<sinal>)`, `blocked? (<sinal>)` ou `indeterminado`.
- Regras padrão genéricas e conservadoras. Um ERRORMESSAGE/erro não vazio
  num controle ou campo dá `app-error`. Uma resposta de aplicação que vem sem
  os campos que a mesma rota trouxe noutras respostas (aprendido na própria
  sessão) dá `indeterminado`, com a lista de campos ausentes.
- `blocked?` só com evidência explícita (página de proteção conhecida pela
  regra de /TSPD/, 403/429, ou resposta HTML que substitui a esperada por
  outra sem os controles). Sempre com "?", nunca afirmado.
- Regras configuráveis por arquivo JSON da sessão (nome de campo → sinal),
  sem código executável.
- Na cadeia e no compare, cada passo/par mostra o veredito.
- CLI: `scrapelens-core assess <sessao> [requestId]`.

## Aceite

1. Fixture real-shape (1 rodada): o script de priming para o 1º
   cmd_consultar_placa tem só os passos da aplicação na ordem e extrai STAMP
   do controle HTML, delta do trecho da textarea, SESSIONID com o comentário
   de composição parcial e a placa como parâmetro. `ast.parse` passa. Sem
   `--confirmar`, só imprime o plano. Nenhum valor sensível capturado como
   padrão.
2. Simulação offline: um servidor local fictício (testserver) que emite os
   mesmos controles com valores novos. O script, rodado pelo agente de Testes
   (não pelo ScrapeLens) contra 127.0.0.1 com `--confirmar`, completa a
   cadeia usando os valores novos, nunca os capturados. Sem rede externa.
3. assess: na fixture de bloqueio do DETRAN (200 sem XML/STAMP, Connector sem
   modelo, 403), os vereditos são `app-error`/`indeterminado`/`blocked?`
   coerentes. Respostas normais dão `app-ok`.
4. Injeção: nomes e valores hostis (newline, aspas triplas, `\`, bidi) no
   script não escapam de literais nem de comentários. Teste com `ast` e
   execução contra o servidor local mostrando que nada além das requisições é
   executado.
5. Validação agregada nos HARs reais: o script para o 1º cmd_consultar_placa
   é gerado. Os passos e extrações batem com o fluxo manual do usuário. Os
   vereditos de assess (contagens) são coerentes. Nenhum valor real no
   relatório.
6. Bateria sem regressão.

## Andamento (2026-10-29)

- assess (Captura, c28533b). A decisão de acrescentar `não-avaliado`
  (`not-assessed`) para respostas sem sinal da aplicação e sem expectativa na
  rota tira o ruído de páginas, estáticos e /TSPD/.
- Gerador de priming (Captura, f858b17). Prova offline no detran-sim: a
  cadeia de 13 passos (6 POSTs) completou 2× com valores novos, e o controle
  negativo com os valores capturados recebeu ERRORMESSAGE.
- Limite conhecido: o Natural for Ajax usa prefixos de comprimento. Quando o
  trecho extraído muda de tamanho, o script avisa em stderr, mas não recalcula
  o prefixo. Um servidor real pode rejeitar. Recalcular exige conhecer o
  protocolo (fora do core; candidato a extensão/plugin).

## Revisão da rodada 7 (2026-10-29) — decisões

Veredito: parcial, com 1 falha alta.
- Redirect: o script usa `allow_redirects=False`. Um 3xx só é seguido se o
  Location for do MESMO origin da base (esquema+host+porta), e o redirect
  conta como passo verificado. Location para outro origin vira
  `fail("priming: passo N: redirect para outro origin (<host>) recusado")`.
  Nenhum corpo, parâmetro ou header sai para outro origin.
- Origins: com `--base-url`, todo passo cujo origin capturado difere do origin
  do alvo é recusado na geração (com lista) ou exige
  `--allow-origin <host>` explícito. A reescrita compara origin exato, sem
  `startswith` sem fronteira.
- Dados de sessão/PII nunca viram literal nem padrão: parâmetros de caminho
  (`;nome=valor`) são tratados como dados; a lista de nomes sensíveis inclui
  nome, email, telefone/celular, endereço, nascimento, rg, token, sid,
  session e callback (JSONP). Constante estrutural só para o caminho e o
  valor de query de navegação que não sejam PII e não tenham cara de ID
  dinâmico (dígitos longos, hex ou base64).
- Extração em runtime linear: `str.find` dos contextos antes/depois, nunca
  regex com `.+?` sobre a resposta.
- assess: rejeição (F5) só com ausência dos controles esperados da rota (ou
  sem expectativa e sem controles). Um 200 com XML/STAMP presentes é app-ok,
  mesmo citando "Request Rejected". Na rota de proteção, 403/429 continuam
  `blocked?` (evidência explícita); 200 de handshake é `não-avaliado`.
- Saída de erro do script: o texto vindo da resposta é sanitizado (controles,
  ESC, bidi), com `repr` ou filtro.
- Regras JSON: `schema` obrigatório, chaves desconhecidas recusadas, e um
  aviso quando as regras desligam todas as detecções ou marcam `/` como
  proteção.
- App: `blocked?` não é "falha da aplicação". A contagem e o filtro ficam
  separados ("falhas da aplicação" × "possíveis bloqueios").

## Re-revisão da rodada 7 (2026-10-29) — decisões

Redirect, origins, ReDoS, erro no terminal, F5, /TSPD/ e regras estritas foram
aprovados. Restam 2 falhas altas.
- Headers: o gerador reutiliza `is_sensitive_header` da sanitização, mais os
  nomes com key, token, csrf, xsrf, session, sess, jwt, secret, auth,
  signature, user e device. Um header desses nunca sai literal: se tem
  origem, é extraído em runtime (CSRF/XSRF); senão, vira parâmetro
  obrigatório sem padrão; o resto é omitido com nota. O Referer é montado
  em runtime com a URL real do passo anterior correspondente (mesmo
  origin+caminho); sem correspondência, é omitido. Nunca sai a query
  capturada.
- Corpo não-form: JSON é decomposto em campos e recebe o mesmo tratamento do
  form (extração, parâmetros, constantes, sensíveis). Outros tipos
  (texto/XML/binário) são recusados por padrão; `--allow-literal-body`
  inclui o corpo, mas os valores detectados como sensíveis/de negócio viram
  parâmetros obrigatórios, e o script avisa que o resto foi congelado.
- IDs dinâmicos nunca são constante estrutural: JWT (`eyJ…`), ULID/KSUID,
  datas ISO/timestamps, números de 5+ dígitos, alfanuméricos de 6+ com
  letras e dígitos misturados, e nomes que contêm sess/token/key/sid.
  Valores curtos de navegação (ex.: `op=S37`) continuam permitidos.
- Regras do assess: marcador vazio recusado; `blockedStatuses` só 4xx/5xx.
- Script: `S.trust_env = False` por padrão (sem proxy/.netrc do ambiente);
  `--usar-proxy-do-ambiente` habilita. Aviso quando o Python é < 3.13
  (HTMLParser com casos quadráticos conhecidos).
- Re-revisão final (732f6b5): as 2 falhas altas anteriores foram aprovadas;
  sobrou 1 alta nova. Decisões: (1) o corpo é classificado pelo conteúdo e
  não só pelo Content-Type. JSON válido sob content-type de form recebe o
  tratamento de JSON, e um campo de form sem `=` com mais de 40 caracteres
  nunca sai literal (recusa). (2) Detecção pelo valor de esquemas
  `Bearer`/`Basic`/`Digest`/`Negotiate` em qualquer header; os nomes hmac,
  bearer, digest e nonce entram na lista; `x-forwarded-for` é omitido (PII
  leve). (3) Referer para outro origin (`--allow-origin`) leva só o origin,
  como no navegador. (4) Regras do assess: nomes/caminhos vazios são
  recusados.
- Re-revisão em e74ecb0: falta 1 alta, JSON como VALOR de campo (form ou
  string JSON). Decisão de princípio, para parar de tapar caso a caso: (a)
  valores de campo que são JSON válido, inclusive JSON dentro de string JSON,
  são decompostos recursivamente (profundidade limitada); (b) um filtro FINAL
  e único de literais: todo literal de string que o gerador vai emitir
  (corpo, campos, trechos opacos, headers e query) passa pelos detectores de
  PII/segredo (e-mail, CPF, CNPJ, cartão com Luhn, telefone BR, placa, JWT,
  esquemas Bearer/Basic, dígitos longos e nomes de negócio/PII no contexto).
  Um trecho detectado vira parâmetro obrigatório no lugar exato. Se não der
  para mapear, a geração é recusada com a lista do que foi achado. Os
  avisos das regras também cobrem "nenhuma detecção configurada". O app lê
  `assess-rules.json` como arquivo regular, sem symlink, com limite de
  tamanho.

## Fechamento (2026-10-29)

Revisão final em 1bdd8b9: APROVADA com ressalvas. Script de priming:
- sem redirect para outro origin;
- origin exato, injeção fechada e extração linear;
- credenciais e PII nunca literais em JSON, form nomeado ou campo opaco;
- filtro final de literais;
- Referer em runtime;
- parada no passo da resposta ruim;
- recusa de cadeia incompleta.

Assess: vereditos coerentes, regras estritas com avisos, sem falso bloqueio
no handshake da proteção. Nos 3 HARs reais: 11 passos na ordem do fluxo
manual, só placa e sufixo do SESSIONID como parâmetros, 0 literais e nenhum
falso positivo do filtro. detran-sim aprovado nos 4 modos.

Acabamento delegado: detectores para placa com hífen (ABC-1234), VIN/chassi
de 17 caracteres, telefone +55 com 12–13 dígitos, cartão da série 2 (2221–2720)
e de 19 dígitos, e dígitos fullwidth; filtro aplicado também a segmentos de
caminho, chaves de form e valores de header. Limite aceito: texto livre sem
formato (nome, endereço, e-mail ofuscado) em query, header e caminho, e
qualquer conteúdo sob `--allow-literal-body` (avisado no script).
