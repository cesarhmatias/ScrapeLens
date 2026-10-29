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
