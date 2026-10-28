# Rodada 5 — origem dos valores (priming) e comparação entre capturas

## Motivo

Caso DETRAN-PB (`docs/05-caso-referencia-detran.md`), requisitos derivados 2,
3 e 4: não dá para começar pela consulta. É preciso saber de onde veio cada
valor do POST (SESSIONID, STAMP, delta, cookies) e quais valores mudam entre
duas capturas do mesmo fluxo, para não congelar valores do HAR.

Fora do escopo: decodificar o Natural for Ajax, burlar /TSPD/ ou CAPTCHA,
replay, rede externa, gerar script de priming executável (fica para a rodada
6) e publicação.

## Ondas (máx. 3 executores)

- 5a: Core (origem dos valores + comparação entre capturas) e Testes (2ª
  captura sintética do fluxo DETRAN + expectativas + script de aceite).
- 5b: App (UI da cadeia e da comparação), depois revisão independente.

## Propriedade

| Dono | Caminhos |
|---|---|
| Core | `core/` |
| Testes | `fixtures/`, `testserver/`, `tests/` |
| App (5b) | `app/`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs` |
| Líder | `docs/` |

## 1. Origem dos valores (core, `provenance` ou `flow`)

API: `value_origins(session, request_id, options) -> ValueOrigins`. Para a
requisição alvo, extrair os valores consumidos: parâmetros da query, valores
de header (exceto os de protocolo: host, content-length, accept-*,
user-agent, sec-*), cookies enviados e campos do corpo (form e folhas JSON).
Em campos opacos (ex.: `XML`), os valores são procurados como substring (§1.2).

1.1 Candidatos produtores. Só valores observados ANTES da requisição alvo
(tempo de início da tentativa, com empates explícitos) em:
- `Set-Cookie` das respostas e cookies na URL de redirect;
- headers de resposta (Location e headers customizados);
- corpos de resposta: campos form-urlencoded, folhas JSON e literais de
  string entre aspas em texto/HTML/JS, com comprimento ≥ 8;
- requisições anteriores (valor que já circulava: origem "repetido de
  cdp-rNNNN", não "produzido").

1.2 Evidências, sem confundir os tipos:
- `cookie-jar`: cookie enviado cujo valor foi definido por Set-Cookie
  anterior (nome + valor iguais). Forte.
- `same-field`: mesmo nome de campo e mesmo valor entre um campo de resposta e
  um campo da requisição (ex.: STAMP). Forte. Vale para valores curtos (≥ 1),
  porque o nome amarra.
- `value-match`: valor de resposta com ≥ 8 caracteres encontrado na
  requisição (inteiro ou substring de campo opaco). Médio. Registrar onde
  apareceu (campo, offset).
- `initiator`: iniciador do CDP (script/parser) apontando para um recurso
  anterior. Complementar, nunca prova de origem de um valor.
- Sem candidato: `sem origem observada`. Pode ser constante, entrada do
  usuário (placa) ou valor gerado no cliente (JS). Nunca inventar a origem.
- Vários candidatos: listar todos, marcar `ambíguo` e indicar o mais antigo,
  sem escolher em silêncio.

1.3 Cadeia de priming: `priming_chain(session, request_id)` = fecho
transitivo das origens fortes e médias (cada produtor traz as próprias
dependências). Devolve a lista mínima ordenada de requisições necessárias,
com o motivo de cada uma (qual valor ela fornece), e separa as requisições de
proteção (`/TSPD/`, cookies TS*) das da aplicação por regra explícita
(domínio/caminho/cookie), marcadas como `proteção` e não como `irrelevante`.

1.4 CLI: `scrapelens-core origins <sessao> <requestId>` e
`scrapelens-core chain <sessao> <requestId>`, com saída JSON. Funciona com
LazySession (corpos sob demanda) e com sessões sanitizadas (valores
`[REDACTED]` não casam entre si; declarar isso).

## 2. Comparação entre duas capturas (core)

API: `compare_sessions(a, b, options) -> SessionComparison`.
- Alinhamento das requisições A↔B: método + host + caminho normalizado +
  conjunto de nomes de campos do corpo + ordem relativa dentro do mesmo
  modelo. Requisições com o mesmo modelo são pareadas em ordem. Sobras ficam
  `só em A` ou `só em B`. Ambiguidade é explícita, sem pareamento por horário
  absoluto.
- Por par e por campo (query, headers, cookies, campos do corpo; os campos
  opacos são comparados por valor inteiro e por tokens ≥ 8 caracteres
  diferentes): `estático` (igual), `dinâmico` (difere), `só em A` ou
  `só em B`. Campos repetidos são pareados por ocorrência, sem ordenação
  alfabética silenciosa (regra da especificação).
- Classificação útil: um campo dinâmico cuja origem (§1) em B é uma resposta
  anterior de B vira `obter em runtime (origem: …)`. Dinâmico sem origem
  observada vira `dinâmico sem origem` (gerado no cliente ou entrada).
- CLI: `scrapelens-core compare <sessaoA> <sessaoB>`, com saída JSON.

## 3. Exportação

cURL/Python passam a anotar, em comentário junto do valor, os campos
`obter em runtime` (com a origem) quando a sessão tiver essa análise
disponível. Os valores continuam sendo os capturados. Nada de valor
inventado, e o código gerado não muda de comportamento.

## 4. Aceite da rodada

1. Fixture DETRAN (A): para o 1º `cmd_consultar_placa`, as origens são
   SESSIONID → resposta HTML do easynat-app (`value-match`, literal
   `m_currentSessionId`); STAMP → resposta do POST anterior (`same-field`);
   delta `DLTA…` no XML → resposta anterior (`value-match` no XML); cookies
   TS*/JSESSIONID → Set-Cookie (`cookie-jar`); placa → `sem origem observada`.
   A cadeia lista as requisições mínimas da aplicação na ordem do fluxo, e
   /TSPD/ aparece separado como `proteção`.
2. Comparação A × B (2ª captura sintética com SESSIONID, STAMP, delta e
   cookies diferentes, e páginas e constantes iguais): SESSIONID, STAMP, delta
   e cookies `dinâmico` + `obter em runtime` com origem certa; `cmd`,
   PAGEINITPARAM vazio e as constantes do XML `estático`; placa `dinâmico sem
   origem`; as duas consultas com mesma URL/método pareadas pela ordem, sem
   cruzar.
3. Nenhuma origem inventada: caso negativo em que um valor curto coincide por
   acaso (< 8 sem mesmo nome) não vira origem.
4. Sessão sanitizada: a análise roda, declara que valores redigidos não podem
   ser rastreados e não vaza valores.
5. Bateria sem regressão (cargo test, tests/exportacao, run_acceptance,
   check_bodies_search) e desempenho aceitável na sessão grande (medido).

Commits Conventional Commits por dono, sem push nem publicação, sem rede
externa. Preservar `tests/results/app-latest/testserver/app-20261027/h1.jsonl`.
