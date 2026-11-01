# 17 — Revisão independente de segurança do MCP (Rodada 11)

- **HEAD revisado:** `3c49b4d`, num clone em `/tmp/rev25/repo`. O repositório original não foi alterado, exceto por este arquivo.
- **Escopo:**
  - `mcp/`, de `c6bc508` a `6cca5aa`;
  - `capture/src/{allowlist,browser}.rs`, mais `capture/src/{lib,chrome}.rs` quando o fluxo passa por eles;
  - `recon/`;
  - o sanitizador em `core/src/export/sanitize.rs`, commits `85e7c13` e `e37d42d`.
- **Contratos:** `docs/16-mcp-contrato.md` e `docs/16b-mcp-navegador.md`.
- **Método:** leitura do código e PoCs executados.
  - Os PoCs rodam pelo servidor stdio real (`fake_server`), passando por `reply()` e `scrub_output`.
  - Para rodar alguns testes, eles foram copiados temporariamente para o clone e apagados depois. O `git status` do clone terminou limpo.
  - O Chrome rodou somente contra 127.0.0.1/localhost. Nenhum site real foi acessado e nada foi baixado.
- **Evidências:**
  - `/tmp/rev25/poc-secrets/`: `poc_secrets.rs`, `poc_oracle2.rs`, `poc_secrets_live.rs` e as saídas `*.out`;
  - `/tmp/rev25/poc-fs/`: `poc_orphan.py`, `poc_fs.py`, `poc_race.py` e as saídas `*.out`;
  - `/tmp/rev25/poc-allow/`: `elicit_poc.py` e os testes de allowlist e recon.
  - Os relatórios parciais estão em `/tmp/rev25/{secrets,fs-cdp-chrome,allow-recon}.md`.

**Legenda:**
- **CONFIRMADO:** reproduzido por execução.
- **PLAUSÍVEL:** visto só na leitura do código.

## Veredito

**REPROVADO para fechamento:** há uma falha crítica confirmada (C1), que anula a "dupla trava" do reveal para qualquer valor da sessão. Os portões principais estão corretos:
- o portão do `expose_cdp`;
- o slot único de captura;
- o parser da allowlist;
- os limites de `session_id` e `name`.

Os demais achados são altos, médios ou baixos.

## Os 5 mais graves

| # | Gravidade | Estado | Achado |
|---|---|---|---|
| C1 | Crítico | CONFIRMADO | `trace_value(value=…)` funciona como oráculo de substring sobre a sessão original |
| A1 | Alto | CONFIRMADO | Com `--allow-unconfirmed-capture`, uma elicitação com erro ou malformada abre a captura |
| A2 | Alto | CONFIRMADO | A varredura final e o sanitizador só reconhecem `?nome=valor`. A correção do `e37d42d` fica incompleta para fragmento, `;jsessionid`, userinfo e `nome=` sem `?` |
| M1 | Médio | CONFIRMADO | Chrome fica órfão se chegar EOF de stdin ou SIGTERM durante `start_capture` |
| M2 | Médio | CONFIRMADO | O navegador não impõe a porta da allowlist: a aba chega a `localhost:<outra porta>` por 8 vetores |

## Achados confirmados

### Crítico

**C1. `trace_value` é um oráculo sem reveal.**
- **Local:** `mcp/src/tools.rs:1112-1118`, onde o cálculo usa sempre `View::original`, e `tools.rs:1277-1299`, com uma busca literal `case_sensitive` em URL, headers e corpos.
- **Cenário:** o agente chama `trace_value(value="Bearer O")`, `"Bearer OR"` e assim por diante, e lê `producersTotal`/`consumersTotal`. Com isso reconstrói, sem reveal:
  - `Authorization: Bearer ORACLE16SECRETxyz`, que `get_request` mostra como `[REDACTED]`, em 452 chamadas;
  - um valor dentro de um corpo HTML retido, em 364 chamadas;
  - o valor do cookie `sid` de um Set-Cookie, em 352 chamadas.
- **Contraste:** `search_bodies` já fecha esse oráculo (total=0 no controle); `trace_value` não.
- **Evidência:** `poc-secrets/poc_secrets.out`, linha "ORÁCULO trace_value: reconstruído … em 452 chamadas (sem reveal)", e `poc_oracle2.out`.

### Alto

**A1. A confirmação de `start_capture` é contornada com a flag.**
- **Local:** `mcp/src/server.rs:74` (`Err(other) => Unavailable`) e `mcp/src/live.rs:184`.
- **Cenário:** o servidor roda com `--allow-unconfirmed-capture` e o cliente suporta elicitação. O cliente responde com:
  - um erro JSON-RPC ("User rejected"); ou
  - `accept` com `{}`, `{"confirmo":"false"}` ou `0`.

  Qualquer dessas respostas é tratada como "indisponível", e a captura abre com `confirmation=unconfirmed-flag`.
- **Contrato violado:** o contrato 16 diz que recusa ou caixa desmarcada não abre nada, "mesmo com a flag". Sem a flag, todos os casos dão `confirmation_unavailable`, como esperado.
- **Evidência:** `python3 -I poc-allow/elicit_poc.py …/fake_server` → `flag=True JSON-RPC error -> captureId=cap-d141… unconfirmed-flag`.

**A2. O sanitizador e a varredura final só reconhecem `?nome_sensível=valor`.**
- **Local:** `core/src/export/sanitize.rs`:
  - `sanitize_text`, linhas 739-799, que alimenta o `scrub_output` em `mcp/src/tools.rs:1459`;
  - `sanitize_url`, linhas 692-725, que não trata o path;
  - `sanitize_url_reference`/`sanitize_path_and_query`, linhas 684-690 e 727-732, que ignoram `#`;
  - `collect_query`, linha 1448, que corta no `#`.
- **Itens que passam sem redação** em `list_requests`, `get_request` e `diff_requests`:
  - `Location: /cb#access_token=X` (fragmento numa URL relativa);
  - `…/home;jsessionid=MATRIXSID01?x=1` (parâmetro matriz no path);
  - `X-Original-Url: https://admin:SEGREDO@…` (userinfo);
  - `Refresh: 0; url=…#access_token=…`;
  - `token=…` sem `?`, `token%3D…` e base64.
- **Sobre o `e37d42d`:** a correção cobre o `startLine` com `?token=`, verificado nas linhas de requisição e de resposta. Os formatos acima continuam vazando.
- **Teste de regressão:** o teste do `6cca5aa` usa somente `?token=MARK`, que é o único formato que a varredura reconhece, e por isso não detecta nenhum desses casos.
- **Evidência:** `poc-secrets/poc_secrets.out`.

### Médio

**M1. Chrome órfão quando chega EOF ou SIGTERM durante o `start_capture`.**
- **Local:** `mcp/src/app.rs:63-74`, `mcp/src/live.rs:472-478` e `mcp/src/main.rs:15`.
- **Causa:** `stop_all` só para `Slot::Running`. No slot `Starting`, o Chrome já foi criado dentro do `spawn_blocking`, mas o `process::exit` roda sem passar por `ChromeProcess::drop` nem `OrphanMarker::drop`. O servidor MCP também nunca chama `cleanup_orphans`.
- **O que sobra:**
  - o Chrome, com CDP aberto em 127.0.0.1, gravando NetLog em `capture-<ms>`;
  - o perfil e o marcador.
- **Evidência:** `poc-fs/orphan_eof.out` e `orphan_sigterm.out` registram "chrome procs left after server exit: 8 / 7", e `/json/version` do órfão devolveu `webSocketDebuggerUrl`. O controle, com EOF depois do start, registrou 0 processos.

**M2. A porta não é imposta no navegador.**
- **Local:** `capture/src/lib.rs:466` e `capture/src/allowlist.rs:215`.
- **Cenário:** com `allowed_hosts=["localhost:P1"]`, a página alcançou `localhost:P2` por 8 vetores: 302 de topo, `location=`, meta refresh, `window.open`, iframe, fetch, WebSocket e maiúsculas. A aba fica num host:porta não aprovado e sob controle do agente.
- **Aviso ao usuário:** a elicitação mostra só "localhost:P1", sem avisar que as outras portas locais (Redis, admin) continuam acessíveis.
- **Situação no contrato:** é uma lacuna declarada, mas sem aviso ao usuário.

**M3. `binary_path` executa qualquer arquivo.**
- **Local:** `capture/src/chrome.rs:48` e `:80`, que só checam `is_file()`.
- **Cenário:** `normalize_binary_path("/bin/echo")` devolve `Some`, e `detect` dá `found=true`.
- **Contrato violado:** o §2.1 diz "só Chrome estável".
- **Atenuante:** o caminho aparece na elicitação, mas sem escape. Com A1, ou sem elicitação, nem isso chega a ser visto.

**M4. O spill do `get_body` escreve fora do `--out-dir` por meio de um symlink.**
- **Local:** `mcp/src/tools.rs:778-795`. O nome temporário é fixo (`.tmp-<pid>`) e abre com `create|truncate`, sem `O_NOFOLLOW` nem `O_EXCL`.
- **Cenário:** um processo do mesmo usuário com escrita no out-dir planta o symlink. O corpo é escrito no alvo externo com modo 0644, e o `rename` move o próprio symlink para o `path` devolvido.
- **Evidência:** `poc-fs/poc_fs.py` T2.

**M5. Nomes de credencial óbvios ficam fora das listas de nomes sensíveis.**
- **Local:** `sanitize.rs:892-940` (`is_sensitive_header`) e `949-1020` (`is_sensitive_key`).
- **O que vaza:**
  - na query, `jwt`, `auth_key`, `ticket` e `SAMLResponse`;
  - no formulário, `senha` e `pwd`, com `search_bodies` devolvendo `snippet:"SENHAFORM03"`;
  - no JSON, `pin`, `otp` e `auth_key`;
  - nos headers, `Ocp-Apim-Subscription-Key` e `X-VTEX-API-AppKey`.

**M6. O `parseError` de Set-Cookie repete o valor cru.**
- **Local:** `sanitize.rs:426-445`, que não toca em `parse_error`; a mensagem vem de `core/src/model/cookies.rs:219-222` e é emitida em `mcp/src/project.rs:128-130`.
- **Cenário:** `Set-Cookie: NAMELESS29xx; Path=/` produz `"raw":"[REDACTED]","parseError":"…\"NAMELESS29xx\""`.

**M7. O site_profile dá `media` para presença só no corpo ou na query.**
- **Local:** `recon/src/detect.rs:358-400` e `:442`.
- **Cenário:**
  - texto refletido `name="cf-turnstile-response"` numa página de busca dá `cf-008 captcha Media [response-body]`;
  - `?g-recaptcha-response=1` dá `rc-003 Media`.

  Os dois são controláveis pelo atacante.
- **Contrato violado:** o §5.1 manda `baixa`.

**M8. `x-amzn-waf-action: challenge` com status 200 dá `Alta` e `CandidatoACloakbrowser`.**
- **Local:** `detect.rs:490-502`.
- **Contrato violado:** o §5.1 exige 202 ou 405. A divergência vira só um texto em `limits`.

**M9. Um bloqueio num subrecurso de outro host decide a recomendação.**
- **Local:** `detect.rs:220` e `recon/src/recommend.rs:67-74`.
- **Cenário:** `cf-mitigated: challenge` numa imagem em `cdn.other.test/pixel.png`, com o documento e o XHR em 200, gera `CandidatoACloakbrowser`.
- **Contrato violado:** o §5.3 exige o bloqueio na navegação principal ou numa rota da aplicação.

**M10. "Desafio resolvido" com `Alta` a partir de evidência fraca.**
- **Local:** `detect.rs:413`, onde `is_success` aceita 3xx, e `:419-440`.
- **Cenários:**
  - (a) um 403 seguido de `302 Location: /__challenge` produz `PrecisaDePriming Alta`;
  - (b) `cf_clearance` definido por outro host marca como resolvido o desafio de `app.test`.

### Baixo

- **B1. `ensure_private_dir` age antes do `is_within`.** Local: `tools.rs:758-769` e `core/src/store.rs:52-57`. Com `bodies/` como symlink, ele faz `create_dir_all` e chmod 0700 no alvo externo antes de devolver `outside_allowed_dir` (`poc_fs.py` T1).
- **B2. Corrida no `.tmp-<pid>` compartilhado entre chamadas concorrentes de `get_body`.** Em 400 spills concorrentes, 390 deram ENOENT e 10 devolveram arquivos com conteúdo de outro recorte (`poc_race.py`). Pode misturar bytes de uma chamada com reveal num arquivo `.masked`.
- **B3. `session.json` como symlink lê fora das raízes.** Local: `mcp/src/registry.rs:159-168`; só o diretório é canonicalizado (T3).
- **B4. `slug` colide nomes de handle.** Local: `mcp/src/config.rs:74-91`. `x.y` e `x-y` compartilham o diretório de spill e um sobrescreve o arquivo devolvido ao outro (T5).
- **B5. O esquema de autenticação só é reconhecido com a caixa exata.** Local: `sanitize.rs:672-681`. `"bearer …"` no JSON vazou em `get_body`; `ApiKey`, `OAuth` e `SharedKey` não são reconhecidos.
- **B6. `--remote-allow-origins=*`.** Local: `capture/src/lib.rs:437`. Um handshake WS com `Origin: https://evil.example` recebeu 101. `/json/version` não manda ACAO, então isso é só defesa em profundidade. Além disso:
  - a porta escuta em 127.0.0.1, ao alcance de outros usuários do sistema;
  - `chromePid` sai mesmo com `expose_cdp=false`, e o contrato aceita isso.
- **B7. WebSocket fora do `session.json`.** O WS aparece no NetLog e no CDP, mas se perde na importação e por isso fica fora das `violations`.
- **B8. IP literal na allowlist é aceito, mas nunca carrega.** `resolver_rules` pula IPs (`allowlist.rs:219`) e `MAP * ~NOTFOUND` nega o acesso, o que dá `ERR_NAME_NOT_RESOLVED`. Contradiz o §2.2.
- **B9. Cookie só no pedido dá `media`.** Um cookie que aparece só na requisição, e que pode vir de `document.cookie`, dá `media` para DataDome e HUMAN.

## Adendo: confirmações tardias da frente de filesystem e CDP

Estes resultados chegaram depois do commit `f7cb0fa`.

- **M4 ficou mais amplo (Médio, CONFIRMADO):**
  - **Locais:** o mesmo padrão aparece em `core/src/store.rs:59-78` (`write_atomic`) e em `capture/src/lib.rs:1903-1917` (`open_private`). Os dois abrem um nome fixo com create+truncate, sem `O_NOFOLLOW`/`O_EXCL`.
  - **Efeito:** com um symlink plantado no diretório da sessão, os eventos CDP da captura ao vivo (4745 B) e o `session.json` completo foram gravados fora do `--sessions-dir`.
  - **Evidência:** `poc-fs/poc_capture_symlink.py`.
- **B6 sobe para Baixo/Médio (CONFIRMADO):** a porta DevTools fica acessível desde o lançamento, antes do portão (`capture/src/lib.rs:435-437`).
  - **Teste:** `curl 127.0.0.1:<porta>/json/version` devolveu `webSocketDebuggerUrl` antes de `Network.enable`/autoAttach.
  - **Efeito:** qualquer processo local, inclusive de outro usuário do sistema, pode varrer a porta efêmera e controlar o navegador. O portão impede só que o *MCP* entregue o endereço cedo; ele não impede acesso direto à porta.
  - **Contrato:** o §4.1 do 16b se apoia no perfil 0700, que não protege a porta.
- **P2 confirmado (Baixo):** o teste em `poc-fs/poc_cancel.py` cancela a confirmação e depois aceita. A captura abre, o cliente nunca recebe `capture_id` e todo `start_capture` seguinte devolve `capture_already_running`. O comentário em `server.rs:44-46` diz que o slot é liberado no cancelamento, mas o rmcp 3.8 não descarta o handler.

## Achados plausíveis (só leitura)

- **P1 (Médio).** `stop_capture.warnings` traz a URL crua da violação.
  - A mensagem é montada em `capture/src/lib.rs:381-391` e usa `allowlist.rs:321-323`.
  - `mask_urls`, em `mcp/src/live.rs:504-519`, só trata as chaves `url`, `exampleUrl` e `pageUrl`.
  - Por isso `violations[].url` sai mascarada, mas `warnings[]` mantém query, `;jsessionid` e fragmento.
  - Já confirmado: o `scrub_output` deixa essa string intacta. Faltou o teste ponta a ponta, porque o fake_server não gera violações.
- **P2 (Baixo).** Se o cliente desiste do `start_capture` (até 5 min de elicitação mais 90 s de start), o future não é cancelado e o Chrome abre mesmo assim.
  - O cliente nunca recebe o `capture_id`, e não há ferramenta para listar capturas.
  - Até o servidor reiniciar, cada `start_capture` devolve `capture_already_running`, e a captura segue gravando por até 30 min.
  - Local: `mcp/src/server.rs:241-289`.
- **P3 (Médio).** Um script pode levar a aba de topo para um host de `third_party_hosts`, que o usuário aprovou só como origem de subrecursos. É a mesma classe de M2.
- **P4 (Baixo).** No APFS, `name:"VICTIMSESS"` colide com `victimsess` já existente, o que leva a `exists` ou a um handle que não abre.
- **P5 (Baixo).** Token num segmento de path (`/reset/<token>`) ou numa chave JSON neutra passa. É um limite da heurística.

## Verificado e limpo

- **Portão do `expose_cdp`** (`capture/src/lib.rs:206-250`):
  - o endpoint só é preenchido depois de `wait_initial_target_ready`, e o `StartInfo` só é montado com o target pronto;
  - nos caminhos de erro, timeout e stop, o Chrome é morto sem que a URL do WS passe adiante;
  - `CaptureStatus`, `StopReport` e stderr não carregam o endpoint;
  - `cargo test --offline --lib initial_target_gate`: 2 passaram.
- **Uma captura por vez:** o `prepare` verifica e insere sob o mutex, e o cancelamento não libera o slot. Erros em `stop` e `navigate` e panics na thread matam o Chrome; no panic, só o perfil fica para trás.
- **Caminhos:**
  - `valid_name` só aceita ASCII, recusa `.` inicial e limita o tamanho a 128, o que bloqueia `..`, `/`, caminho absoluto, NUL e Unicode;
  - os symlinks de `sessions-dir` e `out-dir` são canonicalizados na partida;
  - um diretório de sessão que é symlink para fora é recusado;
  - os anexos têm nome validado, recusam symlink e conferem ino/dev de novo;
  - a importação usa arquivo temporário mais rename e nunca sobrescreve.
- **Permissões:** diretórios 0700 e arquivos 0600; o perfil do Chrome é 0700, no TMPDIR do usuário.
- **Allowlist (parser, 49 URLs):** recusa:
  - userinfo, `%40` e `\`;
  - ponto final e hosts não ASCII;
  - IPv4 decimal, octal, hex e curto;
  - os esquemas `ws`, `blob`, `filesystem`, `javascript`, `data`, `file`, `chrome`, `view-source` e `about:` (exceto `about:blank`).

  O curinga não casa a base, `evil-allowed.com` nem `allowed.com.evil.com`. No Chrome, a camada 1 nega `0.0.0.0`, `[::]`, `[::ffff:7f00:1]`, `foo.localhost` e `localhost.`. `navigate` e `start_url` passam por `permits_url`.
- **Elicitação:**
  - os hosts são ASCII estritos, então o texto não pode ser forjado com Unicode ou userinfo;
  - campos extras no `accept` são ignorados;
  - `cancel`, `decline` e timeout dão `denied`.
- **Segredos:**
  - `Authorization`, `Cookie` e `Set-Cookie` (`raw`/`pairs`/`wireLines`);
  - `startLine` de requisição e de resposta com `?token=`;
  - `api%5Fkey` e variações de caixa;
  - `Location`, `Referer` e `Origin` absolutos;
  - `target`, `initiator`, notas, `failure` e warnings;
  - corpos HTML, texto e multipart;
  - `search_bodies` não serve de oráculo;
  - `site_profile` sai com `[redigido, N bytes]`;
  - `start_url` com userinfo é recusada;
  - `revealed:true` exige `--allow-reveal`.

## Não verificado

- Proxy do sistema e WebRTC contornando o resolvedor do Chrome.
- Se a confiança do site_profile considera a procedência da evidência (HAR × CDP/NetLog).
- O teste ponta a ponta de P1 com uma violação real.

---

## Adendo 2: confirmação das correções (Rodada 11)

- **HEAD:** a revisão foi feita no clone novo `/tmp/rev26/repo`, em `eb66afa`, que inclui as correções:
  - core: `3bcbd20`, `7637bac`, `b0c0596`, `dd6cf7a`, `6840670`, `3939881`, `071d132`;
  - captura: `485f6a3`, `d3f194f`, `3e6ad05`, `3c7e4af`, `8e0e575`, `eb66afa`.
- **Evidências:**
  - testes de reprodução e saídas em `/tmp/rev26/poc-secrets`, `/tmp/rev26/poc-fs` e `/tmp/rev26/poc-allow`;
  - relatórios parciais em `/tmp/rev26/{secrets,fs-cdp-chrome,allow-recon}.md`.
- **Restrições respeitadas:** o Chrome só rodou contra 127.0.0.1 e localhost. As cópias do Chrome.app ficaram em `/tmp`, e `/Applications` não foi alterado.

### Veredito: REPROVADO

Todos os achados anteriores estão corrigidos ou passaram a ser reportados como previsto no contrato. Mesmo assim, a nova validação "só Chrome estável" tem **dois contornos altos confirmados**, e o texto da elicitação não traz o aviso do §2.5 que o 16b exige.

### Estado dos testes de reprodução anteriores

| Achado | Estado | Evidência |
|---|---|---|
| C1 oráculo do `trace_value` | Corrigido | O prefixo para após 62 chamadas e a saída diz `exact-value-match`. O oráculo de substring está fechado: partes de JWT, itens de `a=b; c=d` e variação de caixa não casam. |
| A1 elicitação com erro ou malformada | Corrigido | Com e sem a flag, só `confirmo:true` abre; o resto dá `confirmation_denied`. |
| A2 fragmento, matriz, userinfo, `token=` sem `?`, `%3D` | Corrigido | Os marcadores saem mascarados (ex.: `;JSESSIONID=%5BREDACTED%5D`). |
| M5 nomes de credencial | Corrigido | Os 20 marcadores saem mascarados. |
| M6 `parseError` de Set-Cookie | Corrigido | Sai mascarado. |
| B5 esquemas de autenticação | Corrigido, com exceção | Um TAB depois do esquema ainda escapa (R6). |
| P1 avisos do `stop_capture` | Corrigido | O aviso sai sem query. |
| M1 Chrome órfão por EOF ou SIGTERM no start | Corrigido | Não sobra nenhum processo, perfil ou marcador. |
| M4 escrita por symlink (spill, `write_atomic`, `open_private`) | Corrigido | Os arquivos de fora ficam intactos; o NetLog ainda vaza (R3). |
| B1–B4 (chmod antes do `is_within`, corrida, `session.json` por symlink, colisão de slug) | Corrigido | 400 chamadas concorrentes sem nenhum erro; o slug ganhou sufixo de hash. |
| B6 porta DevTools e `remote-allow-origins=*` | Corrigido com o pipe | Com `expose_cdp=false` não há porta. Com `expose_cdp=true`, a porta responde antes do portão (aos 0,78 s; o start retorna aos 6,52 s), um risco aceito. Origin forjado recebe 403. |
| P2 cancelar e depois aceitar | Corrigido | O slot é liberado e o aceite tardio é ignorado. |
| SIGKILL do servidor | Corrigido com o pipe | O Chrome sai em menos de 1 s. No modo porta, ele fica vivo até o próximo start limpar. |
| M3 `binary_path=/bin/echo` | Corrigido | `NotABundle`. Os contornos novos estão em R1 e R2. |
| M7–M10 e B9 (confiança do site_profile) | Corrigido | Os sinais fracos saem com `Baixa`, e `resolvedLater=false` nos casos (a) e (b). |
| B7 WebSocket fora da sessão | Corrigido | Agora entra em `violations`. |
| B8 IP literal | Corrigido | `EXCLUDE 127.0.0.1` está nas regras e o navigate carrega. |
| M2 porta (8 vetores) e P3 | Permitido pelo contrato e reportado | Os 8 vetores, inclusive WS, iframe, fetch e `window.open`, e a navegação de topo para um terceiro aparecem em `violations`. |

### Achados que restam

#### Alto

**R1. A validação de assinatura é enganada por uma quebra de linha no caminho (CONFIRMADO de ponta a ponta).**
- **Local:** `capture/src/chrome.rs:287-306` lê `Identifier=` e `TeamIdentifier=` da primeira linha que casa na saída de `codesign -dv`, e a linha `Executable=<caminho>` vem antes delas. O `codesign --verify` não checa nenhum requisito (`-R`).
- **Cenário:** um bundle assinado ad hoc em `inj\nIdentifier=com.google.Chrome\nTeamIdentifier=EQHXZ8M8AV\nx/Google Chrome.app` passa pelo `validate_chrome`. Pelo `scrapelens-mcp` real, depois da confirmação, o binário marcador executou (`PWNED-inj argc=28`).
- **Na elicitação:** o caminho também aparece sem escape (`mcp/src/live.rs:327/343`), e a quebra de linha injeta linhas falsas no texto.
- **PLAUSÍVEL:** um certificado autoassinado com OU=EQHXZ8M8AV passaria mesmo sem a quebra de linha. Não testei, porque exigiria mudar o keychain.
- **Sugestão:** `codesign --verify --deep --strict -R='anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'`, sem fazer parse do `-dv`, e recusar caracteres de controle no caminho.

**R2. Uma cópia assinada com um helper trocado passa, e o helper executa (CONFIRMADO).**
- **Local:** `chrome.rs:277-281` verifica sem `--deep`, como o 16b §2.1 (linha 43) manda.
- **Cenário:** uma cópia do Chrome.app em `/tmp` com `Helpers/Google Chrome Helper.app/.../Google Chrome Helper` trocado por um script passa na validação, e o script roda como processo do serviço de rede (marcador `PWNED-helper`). Com `--deep --strict`, a troca é detectada.
- **Contrato:** a afirmação do 16b (linha 47) de que o script nunca roda é falsa nesse caso.
- **Efeito colateral:** o crashpad da cópia apontou para a pasta Crashpad real do Chrome do usuário.

#### Médio

**R3. O Chrome escreve o NetLog através de um symlink (CONFIRMADO).**
- **Local:** `capture/src/lib.rs:173` cria e fecha o `netlog.json`, depois o Chrome abre o arquivo pelo caminho (`lib.rs:479`, seguindo symlink); `lib.rs:366` o relê pelo caminho.
- **Cenário:** com `poc_netlog_race.py`, um processo do mesmo usuário trocou o arquivo por um symlink. Um arquivo de fora, com modo 0644, recebeu 236.913 bytes de NetLog completo, com cookies e headers. É a classe M4 de novo, por outro caminho.

**R4. O texto da elicitação não avisa da falta de autenticação no `expose_cdp=true`.**
- **O que o contrato exige:** o 16b §2.5 diz "A porta não tem autenticação…" e "a elicitação deve mostrar este aviso" (linha 209).
- **O que aparece:** o texto real só mostra "CDP entregue ao agente (controle do navegador): SIM", e não há aviso equivalente em `mcp/src`.
- **Outras lacunas:** a linha 417 do 16 omite a falta de autenticação, e a tabela do 16b §2.3 cita o aviso do §2.4, mas não o do §2.5.
- **Porta:** está clara no 16b §2.2, no 16 (linha 384) e no texto da elicitação (`live.rs:328`, "aprova, para a página, esse host em QUALQUER porta…"). Só falta dizer que as violações são reportadas, não bloqueadas, e que a navegação de topo para um terceiro é permitida.

**R5. Força bruta do valor inteiro no `trace_value` (CONFIRMADO).**
- **Local:** `mcp/src/tools.rs:1458` (`trace_exact`). Não há limite de taxa, e um acerto nomeia o campo.
- **Cenário:** 10.000 palpites de 4 dígitos levaram 10,8 s (build debug) e acharam `4821@requestBody:pin` e `7351@cookies:sid`. Um código de 6 dígitos leva cerca de 18 min.
- **Agravante:** `trace_value(cookie)` também expõe `valueLength` (`tools.rs:1272/1295`).

**R6. URL aninhada com percent-encoding não é redigida (CONFIRMADO; lacuna antiga).**
- **Local:** `core/src/export/sanitize.rs:818` e `:916`.
- **Cenário:** `?next=%2Fcb%3Ftoken%3DNESTED01x` e `redirect_uri=…%23access_token%3DNESTED05x` vazam em `list_requests` e `get_request`; o mesmo vale para Location e `X-Note`. Esse é o formato normal de redirect_uri e returnTo no OAuth.

#### Baixo

- **R7. Panic de UTF-8 introduzido pela correção (CONFIRMADO).**
  - **Local:** `mcp/src/tools.rs:1479` fatia `text[..scheme.len()]` por byte.
  - **Cenário:** um header com caractere multibyte entre os bytes 6 e 7 (ex.: acento em pt-BR) faz todo `trace_value(value)` falhar naquela sessão. A mensagem do panic expõe 1 caractere cru.
- **R8. TAB depois do esquema de autenticação escapa (CONFIRMADO).** Local: `sanitize.rs:694`. Exemplo: `Bearer\t…` em JSON ou num header.
- **R9. Uso de file descriptors (CONFIRMADO).** Local: `lib.rs:540-555`. Os descriptors que o servidor herda de quem o lançou vazam para o Chrome; por exemplo, um fd 7 de `launcher-secret.log` aparece aberto no Chrome. Os fds do próprio servidor não vazam, e o Chrome só tem os pipes em 3 e 4.
- **R10. SIGTERM durante `stop_capture` perde a sessão (CONFIRMADO 3/3).**
  - **Local:** `mcp/src/live.rs:559` remove o slot antes, então `stop_all` (`:588`) não espera. Só sobram `cdp-bodies.jsonl` e `netlog.json`, sem `session.json`.
  - **Mesma lacuna:** a thread de stop do `abandon()` (`live.rs:379`).
  - **PLAUSÍVEL:** um Chrome órfão no modo porta.
- **R11. Corrida entre a validação e a execução do binário (CONFIRMADO, 1 em 60).** Local: `browser.rs:212` e `lib.rs:534`. O R2 torna a corrida desnecessária.
- **R12. Mensagens do pipe sem limite de tamanho, e timeout do navigate não imposto.**
  - **Pipe:** `transport.rs:154` não tem teto; o WebSocket antigo tinha 64 MiB.
  - **Navigate:** com o Chrome travado, `navigate(timeout_ms=3000)` levou 30,4 s.
- **R13. Redação demais (CONFIRMADO).** Local: `sanitize.rs:1136-1142`. Um objeto `ticket` de suporte inteiro, `pin: true`, `jwtExpiresIn` e `shotp` são redigidos.
- **R14. A varredura final `scrub_output` ficou para trás.** Local: `tools.rs:1809`; ela só olha strings com `?`. Nenhuma saída real depende dela hoje.
- **Informativos:**
  - os descriptors do pipe ficam sem CLOEXEC antes do dup2 (`transport.rs:242-258`). Isso pode vazar para um `codesign` concorrente, mas é PLAUSÍVEL e não confirmado no macOS;
  - `ps` e `kill` ainda são achados pelo PATH (`lib.rs:715-741`).

### Verificado e limpo

- **Estados Starting, Opening e Running:**
  - um start concorrente recebe `capture_already_running`;
  - cancelar com o Chrome subindo libera o slot depois do open sem deixar Chrome;
  - a flag de desligamento e o contador de starts em andamento estão ordenados corretamente.
- **Transporte por pipe:**
  - uma mensagem sem terminador ou um Chrome que morre no meio de uma mensagem encerram a captura limpa;
  - com o Chrome parado por SIGSTOP, o stop termina em 22,5 s matando o processo;
  - os processos auxiliares do Chrome não herdam os pipes.
- **Chrome aceito na validação:**
  - symlink para o `.app` ou para o binário resolve para `/Applications`;
  - um caminho começando com `-` vira absoluto e não injeta argumento;
  - `codesign` e `plutil` são chamados por caminho absoluto;
  - Info.plist alterado, executável principal trocado e arquivo extra em MacOS são recusados;
  - Beta, Canary, Chromium e Chrome for Testing são recusados pelo bundle ID exato (só por leitura de código, porque não estão instalados).
- **`--remote-allow-origins=*` removido:** Origin forjado, `127.0.0.1` e `localhost` recebem 403, e `/json` não manda ACAO.

---

## Adendo 3: confirmação do adendo 2 (Rodada 11)

- **HEAD:** a revisão foi feita no clone novo `/tmp/rev27/repo`, em `03ee85c`, que inclui as correções:
  - core: `5cdac78`, `f4f5c63`, `f276ba8`, `e5e45c1`;
  - captura: `f437051`, `288b2d3`, `03ee85c`.
- **Evidências:**
  - testes de reprodução e saídas em `/tmp/rev27/poc-secrets` e `/tmp/rev27/poc-cap`;
  - relatórios parciais em `/tmp/rev27/{secrets,cap}.md`.
- **Restrições respeitadas:** o Chrome só rodou contra loopback. As cópias do Chrome.app ficaram em `/tmp`, e `/Applications` não foi alterado.

### Veredito: REPROVADO

Há dois achados **médios confirmados**, e um deles é uma regressão introduzida pelo `5cdac78`. Não há nenhum achado alto. Os riscos aceitos não pesaram no veredito.

### R1–R14

| Item | Estado | Evidência |
|---|---|---|
| R1 quebra de linha no codesign e na elicitação | Corrigido | O caminho é recusado antes da elicitação (`browser_invalid … inj\nIdentifier=…`) e o marcador não roda. |
| R2 Helper trocado | Corrigido | `codesign --verify --deep -R='anchor apple generic and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'` (`chrome.rs:314-318`) devolve `BadSignature`. A decisão usa só o código de saída, sem parse de texto. |
| R3 NetLog através de symlink | Corrigido | O NetLog fica no perfil 0700 e a cópia usa `create_new` + `O_NOFOLLOW` + rename. O arquivo vítima ficou intacto e o destino sai com 0600. |
| R4 aviso de CDP sem autenticação | Corrigido | Texto real: "SIM — ATENÇÃO: a porta CDP não tem autenticação; qualquer processo local pode controlar o Chrome inteiro (todas as abas, cookies, sessões abertas)". |
| R5 força bruta no `trace_value` | Parcial | `value_too_short` abaixo de 16 caracteres e `value_query_limit` na consulta 51 funcionam, mas o teto é contornável (A3-M1). |
| R6 URL aninhada com percent-encoding | Corrigido em um nível | NESTED01–05 saem mascarados. A3-M2 e A3-B1 seguem abertos. |
| R7 panic de UTF-8 | Corrigido | `abcdé€€€€` devolve erro, sem panic. |
| R8 TAB depois do esquema | Corrigido em headers e JSON | Em texto livre, `bearer SEC4` e `Basic\tSEC9` ainda passam (Baixo). |
| R9 fds herdados | Corrigido | `launcher-secret` não aparece em nenhum pid do Chrome; no modo pipe, os fds 3 e 4 continuam sendo pipes. |
| R10 SIGTERM durante o stop | Corrigido | Com pipe, com porta e com EOF, o `session.json` é gravado e nenhum Chrome sobra. A espera tem teto de 120 s (`live.rs:617`), sem deadlock. |
| R11 TOCTOU entre a verificação e o exec | Ainda reproduz (risco aceito) | Venceu 2 de 5 tentativas. Está documentado no 16b, linhas 64-70. |
| R12 pipe e navigate | Corrigido | O navigate com o Chrome parado falha em 3,3 s (antes, 30,4 s). Uma mensagem de 140 MB bate no teto. |
| R13 redação demais | Parcial | `pin:true`, `jwtExpiresIn` e `shotp:1` já aparecem. O objeto `ticket:{id,title}` continua todo redigido (Baixo). |
| R14 `scrub_output` | Corrigido | `#id_token=`, `token=` sem `?` e userinfo saem mascarados. |

### Achados que restam

#### Médio

**A3-M1. O teto de 50 consultas do `trace_value` volta a zero ao reimportar a sessão (CONFIRMADO).**
- **Causa:** o contador vive em memória, por handle (`mcp/src/registry.rs:137`), e `import_session` (`mcp/src/tools.rs:243`) aceita reimportar `sessions_dir/<handle>` com qualquer novo `name`.
- **Por que o mínimo de 16 caracteres não basta:** quando um segredo curto vem dentro de uma estrutura conhecida, o palpite inclui essa parte conhecida, por exemplo:
  - `Basic base64("admin:PIN")`, que tem exatamente 16 caracteres;
  - um id com prefixo fixo, como `acct-000000000000-NNNN`.
- **Evidência:** 11.064 consultas e 222 reimportações em 34,8 s recuperaram `4821` do Authorization e `5531` de X-Session.
- **Efeitos colaterais:**
  - cada reimportação grava uma cópia completa da sessão no disco;
  - `trace_value(cookie)` ainda expõe `valueLength` sem reveal (`tools.rs:1282/1305`).

**A3-M2. Regressão do `5cdac78`: um `nome=valor` não sensível sem `%` é copiado inteiro (CONFIRMADO).**
- **Local:** `core/src/export/sanitize.rs:952-965`. O `?token=` ou `pin=` que estiver dentro do valor nunca é examinado.
- **Antes do `5cdac78`** (binário r26): `Refresh: 0;url=/d?pin=%5BREDACTED%5D&…&shotp=%5BREDACTED%5D`.
- **Agora:** `Refresh: 0;url=/d?pin=1234&page=2&opinion=good&shotp=1&ticket_type=vip`.
- **Também vazam agora:**
  - `X-Note: redirect=https://h/cb?access_token=RAWNEST09x`;
  - `go next=/cb?token=RAWNEST10x`;
  - a string JSON `"note":"next=/cb?token=RAWNEST01x"`.
- **Já vazavam antes, em `sanitize_query` (`:1024-1034`):** `?next=/cb?token=URL1x` e `Location: /cb?next=/x?access_token=RAWNEST11x`.
- **Evidência:** `/tmp/rev27/poc-secrets/zz_sec27_r27.out` (atual) comparado com `zz_sec27_r26b.out` (antes).

#### Baixo

- **A3-B1. Valor com codificação dupla no primeiro nível não é redigido (CONFIRMADO).**
  - **Local:** `sanitize.rs:896`.
  - **Exemplos:** `c=%2Fcb%253Ftoken%253DX`, `X-Dbl: x%253D1%2526token%253DX` e `token+%3DX`.
  - **Funciona:** `%3d` minúsculo e o aninhamento de 4 níveis.
- **A3-B2. Uma mensagem acima de 128 MiB no pipe encerra a captura como `complete` (CONFIRMADO).**
  - **Cenário:** `console.log("x".repeat(140e6))`. `TooLarge` é tratado como `Close` (`capture/src/transport.rs:238`), o Chrome sai com `Graceful(0)` e `mark_incomplete` retorna cedo (`lib.rs:1946`), o que dá `completeness.state="complete"` com `reasons=[]`. O único sinal é `graceful:false` no StopReport.
  - **Contrato:** contradiz o 16b, linha 222 ("a sessão sai marcada como incompleta").
  - **Também:** o laço de espera do navigate (`browser.rs:440-446`) não sai quando o transporte fecha; esperou 60 s e devolveu Ok com `loaded:false`.
- **A3-B3. Um symlink plantado em `netlog.json` depois da cópia faz o `stop_capture` falhar (CONFIRMADO, mesmo usuário).**
  - **Causa:** o core regrava o arquivo com `write_atomic` (`core/src/store.rs:197`), que recusa symlink.
  - **Resultado:** `stop_failed … recusado` e nenhum `session.json`. O arquivo vítima fica intacto; o efeito é só negação de serviço.
- **A3-B4. Bearer e Basic com TAB ou minúsculas em texto livre ainda passam (CONFIRMADO).**
- **A3-B5. O objeto `ticket:{id:42,title:"Suporte"}` continua todo redigido (CONFIRMADO).**

#### Informativo

- **Caracteres invisíveis no `escape_display`** (`mcp/src/live.rs:666`): U+061C, U+180E, U+00AD, U+206A-206F, U+3164, U+2800, as tags U+E00xx, U+00A0/U+3000 e marcas combinantes passam.
  - Só o `binary_path` pode trazê-los, e ele precisa ser um Chrome assinado válido.
  - Não há injeção de linha; o risco é só de falsificação visual limitada (PLAUSÍVEL).
- **Bidi e largura zero no caminho:** passam pelo `chrome.rs:233`, a elicitação os escapa, mas a mensagem `NotFound` (`chrome.rs:246`) não.
- **Código de erro do navigate:** com o Chrome congelado, sai `navigate_failed`, não `navigate_timeout`.
- **Tempo da validação:** o codesign leva 9–13 s por verificação.

### Riscos aceitos: a documentação está clara

O 16b descreve todos, com uma exceção:

| Risco | Onde | Texto |
|---|---|---|
| TOCTOU | linhas 64-70 | "O `--deep` torna a janela pequena, mas não a fecha" |
| Mesmo usuário com o perfil temporário | linhas 204-206 | "um processo do mesmo usuário que ache o perfil pelo nome ainda pode mexer nele" |
| Fila do pipe | linha 225 | "sem limite de contagem de propósito" |
| Janela sem CLOEXEC | linhas 86-89 | "Não medi nem reproduzi" |
| NetLog parcial após SIGKILL | linha 207 | confirmado: os 208 KB foram apagados na partida seguinte |

A exceção é a **linha 222**, que é inexata (ver A3-B2).

### Verificado e limpo

- **codesign:**
  - aceita o Chrome de `/Applications` e uma cópia intacta;
  - recusa arquivo extra (Frameworks, MacOS ou raiz), symlink novo, recurso trocado por symlink, Info.plist editado, executável trocado e framework editado;
  - o `-R` é aplicado de fato (OU errado dá rc=3);
  - recusa `\n`, `\r`, `\t`, NUL, ESC, DEL e C1 no caminho.
- **CLOEXEC:** fds a partir do 5 fecham no exec.
- **stops_in_flight:**
  - um segundo stop dá `capture_not_found`;
  - SIGTERM, SIGTERM e SIGINT durante o stop esperam a sessão ser gravada.
- **Perfil:** é removido depois do stop.
- **Desempenho:** o sanitizador fica linear com 1 MB de entrada adversarial (pior caso 715 ms).

---

## Adendo 4: confirmação do adendo 3 (Rodada 11)

- **HEAD revisado:** `61ad875`, num clone novo em `/tmp/rev28/repo`.
- **Correções conferidas:** `419c207`, `d2a0ca6`, `4c5aed0`, `61ad875` e `62afa63`.
- **Evidências:**
  - PoCs e saídas em `/tmp/rev28/poc-secrets` e `/tmp/rev28/poc-cap`;
  - relatórios parciais em `/tmp/rev28/{secrets,cap}.md`.
- **Restrições respeitadas:** Chrome só em loopback; `/Applications` intacto.

### Veredito: REPROVADO

Há uma **regressão média confirmada** (A4-M1), introduzida pelo `d2a0ca6`. Os demais itens estão corrigidos ou foram aceitos. A3-B5, o `"device":"dev-…-7319"` e os riscos do 16b não foram reavaliados, porque foram aceitos.

### Itens do adendo 3

| Item | Estado | Evidência |
|---|---|---|
| A3-M1 (força bruta no `trace_value`) | Corrigido | Sem reveal, `trace_value(value)` sempre devolve `reveal_required`, inclusive depois de reimportar; a força bruta do r27 (10.000 consultas, 200 reimportações) não achou nada. Com `reveal=true` sem `--allow-reveal`, devolve `reveal_disabled`. O modo cookie não traz mais `valueLength`. |
| A3-M2 (regressão do `5cdac78`) | Corrigido nos casos relatados | Sai `Refresh: 0;url=/d?pin=%5BREDACTED%5D&page=2`. Também saem mascarados o redirect do X-Note, `next=/cb?token=` em JSON e em texto livre, `?next=/cb?token=URL1x` e o Location. |
| A3-B1 (codificação dupla) | Corrigido | `%253F`, codificação tripla e quádrupla, `token+%3D`, `token%20%3D` e `token%2B%3D` saem mascarados. Com 5 níveis de codificação ainda passa, porque o teto é de 4 rodadas (informativo). |
| A3-B2 (mensagem grande no pipe) | Corrigido no modo pipe | O navigate falha em 2,6 s com `frame_too_large`, a sessão sai `partial` e a razão é `capture.cdp_transport_closed`. |
| A3-B3 (symlink no `netlog.json`) | Corrigido para os 3 nomes | O stop termina com o aviso "havia um link simbólico", grava o `netlog.json` como arquivo regular 0600 a partir da memória, e o arquivo vítima fica intacto. |
| A3-B4 (Bearer/Basic em texto livre) | Corrigido | `bearer\t`, `BEARER  x`, `Basic` seguido de U+3000 e `basic` minúsculo saem mascarados. |
| navigate_timeout | Corrigido | Com o Chrome parado por SIGSTOP, devolve `navigate_timeout` em 3,3 s. |
| escape_display | Parcial | Ver A4-I1. |
| Regressões de r25/r26/r26b e R1–R12 | Sem regressão | Saídas comparadas com o r27; R1, R2, R3, R4, R9, R10 e R12 passam. Não há redação demais em `page`, `opinion`, `ticket_type`, `sort` e `q`. |

### Custo da recursão nova

O crescimento é linear nas 25 entradas adversariais: com 4× a entrada, o tempo fica cerca de 4×. Não houve panic nem estouro de pilha, porque há teto de 4 níveis de aninhamento e de 4 rodadas de decodificação. Tempos no build release:

| Entrada | 1 MB | 4 MB |
|---|---|---|
| `a=%3Fb%3Dc&` (pior caso) | 147 ms | 602 ms |
| `a=/?a=` | 144 ms | 528 ms |
| `%253F` aninhado | 89 ms | 352 ms |
| aninhamento de 10k níveis | 5 ms | — |

### Achados que restam

#### Médio

**A4-M1. Regressão do `d2a0ca6`: valor com codificação mista vaza (CONFIRMADO).**
- **Local:** `core/src/export/sanitize.rs:1061` e `:1074`.
- **Causa:**
  - O valor agora termina no primeiro `=` cru, então só `%2Fcb%3Ftoken` é decodificado, e ele não tem nada a redigir.
  - A nova varredura recomeça no meio da palavra, e `%3F` não conta como fronteira. Com isso, `token=` nunca é reconhecido.
- **Antes, no core `35a8a62`:** `next=%2Fcb%3Ftoken%3D%255BREDACTED%255D`.
- **Agora:** `next=%2Fcb%3Ftoken=MIX1x`.
- **Onde vaza de ponta a ponta:**
  - header `X-Note3`;
  - campos JSON `mix1`/`mix2`, por exemplo `redirect=https%3A%2F%2Fh%2Fcb%3Faccess_token=MIXED02x`.
  - A query da URL segue mascarada.
- **Evidência:** `/tmp/rev28/poc-secrets/zz_sec28_poc_r28.out` ("MARK MIXED02x: VAZA") e a mesma entrada rodada no core `35a8a62`.

#### Baixo

**A4-B1. `trace_value(request_id)` sem reveal ainda devolve `"length":N` (CONFIRMADO).**
- **Local:** `mcp/src/tools.rs:1440-1466`, que mascara só o `value`; o `length` vem de `core/src/flow.rs:253`.
- **Exemplos:** `sid` aparece com 4 e `X-Session` com 22.
- É o mesmo vazamento que o `419c207` tirou do modo cookie.

**A4-B2. No modo porta (`expose_cdp=true`), a mensagem grande perde a razão (CONFIRMADO).**
- **Local:** `abnormal_close_reason` só trata o pipe (`capture/src/transport.rs:132-134`), então `transport_closed` fica `None` (`capture/src/lib.rs:339`).
- **No release:** a sessão sai `partial`, mas só pelo `chrome_killed`, com `warnings:[]`.
- **No debug:** um `debug_assert` do tungstenite 0.28 entra em panic na thread de captura, o stop dá `stop_failed`, nenhuma sessão é gravada e `recording` fica `true`.

**A4-B3. Um symlink plantado em `session/attachments` ainda derruba o stop (CONFIRMADO, mesmo usuário).**
- **Local:** `write_session_resilient` limpa só os 3 nomes (`capture/src/lib.rs:2001`), e `core/src/store.rs:168-176` recusa o link.
- **Resultado:** `stop_failed` e nenhum `session.json`. É só negação de serviço; o alvo fica intacto.

**A4-B4. Um processo que replanta o `session.json` em laço vence as 3 tentativas (CONFIRMADO 3/3, mesmo usuário).**
- **Local:** `capture/src/lib.rs:2028-2045`.
- É só negação de serviço; o alvo fica intacto.

**A4-B5. O diretório da sessão não é reconferido no stop (CONFIRMADO, mesmo usuário).**
- **Local:** a checagem de symlink do diretório só roda no start (`capture/src/lib.rs:151`).
- **Cenário:** com `capture-X` trocado por um symlink para outro diretório, a sessão é gravada lá com 0600, e a limpeza nova apaga um symlink `session.json` fora da pasta da sessão.
- **Atenuantes:** nada é escrito através de um link, e a escrita pelo diretório trocado já era possível antes do `62afa63`; o que é novo é a remoção.

#### Informativo

- **A4-I1. O `escape_display` (`mcp/src/live.rs:674-676`) não cobre os seletores de variação U+E0100–E01EF**, embora o `61ad875` diga que cobre; a faixa `0xE0000..=0xE007F` só pega tags.
  - Também passam crus: U+05B4, U+064B, U+0489, U+115F/1160, U+FFA0, U+1680, U+17B4, U+0600, U+070F, U+1D173, U+13430 e U+1BCA0.
  - Sugestão: filtrar pelas categorias Unicode Mn/Me/Cf/Zs em vez de faixas.
- **Já existiam antes:**
  - `a=b=token=X` e o parâmetro de matriz `;next=/cb%3Ftoken=X` passam;
  - um valor JSON que começa com "Basic …" é redigido inteiro;
  - valores com codificação múltipla saem normalizados, sem bater com os bytes originais (não é vazamento).
- **Textos novos:** as razões e os avisos de incompletude usam só strings fixas, sem URL, query ou conteúdo.

---

## Adendo 5: confirmação do adendo 4 (Rodada 11)

- **HEAD:** `d8ad643`, num clone novo em `/tmp/rev29/repo`, que inclui as correções:
  - core: `d12158b`, `d8ad643`, `c441634`;
  - captura: `23bcba6`, `0997a3b`.
- **Comparação:** o comportamento anterior é o do core `bacdc30`, compilado à parte (arquivos `*_bacdc30.out`). O `fake_server` em cache estava desatualizado e foi recompilado antes de qualquer teste de ponta a ponta.
- **Evidências:**
  - testes de reprodução e saídas em `/tmp/rev29/poc-secrets` e `/tmp/rev29/poc-cap`;
  - relatórios parciais em `/tmp/rev29/{secrets,cap}.md`.

### Veredito: REPROVADO

Há dois achados **médios confirmados** e nenhum alto:
- **A5-M1:** uma regressão de fidelidade introduzida pelo `d12158b`.
- **A5-M2:** um vazamento parcial que já existia antes destas correções e que nenhuma revisão anterior tinha encontrado.

Todos os itens do adendo 4 estão corrigidos.

### Itens do adendo 4

| Item | Estado | Evidência |
|---|---|---|
| A4-M1 (codificação mista) | Corrigido | `X-Note3`, `mix1`, `mix2` e `next=%2Fcb%3Ftoken=MIX1x` saem como `…token=%5BREDACTED%5D`. |
| `a=b=token=X`, `;next=/cb%3Ftoken=X` e 5 a 8 níveis de codificação | Corrigido | Saem mascarados. A partir de 9 níveis ainda passa, porque o teto é de 8 rodadas (Info). |
| A4-B1 (`length` no `trace_value`) | Corrigido | Saíram `length`, `offset`, `consumedOffset`, `consumedLength` e `start`. Ficou `evidences[].producerOffset`: a diferença entre duas posições no mesmo HTML revela o comprimento de um valor (Info). |
| A4-I1 (`escape_display`) | Corrigido | Todos os pontos de código das duas listas saem escapados. Info: escapar todas as marcas `Mn` deixa ilegível texto em hebraico, árabe e línguas índicas. |
| A4-B2 (mensagem grande no modo porta) | Corrigido | Debug e release: `navigate_failed …(frame_too_large)`; o stop termina com o aviso `cdp_transport_closed`; a sessão sai `partial`, sem panic; o status seguinte devolve `capture_not_found`. O teto age antes de alocar: 140 MB não passam de 18 MB de RSS. |
| A4-B3 (symlink em `attachments`) | Corrigido | O stop termina com aviso; `attachments` vira diretório 0700; o `session.json` sai com 0600; a vítima fica intacta. |
| A4-B5 (pasta da sessão trocada) | Corrigido | `stop_failed` informa o caminho do perfil de resgate. Nada é escrito no alvo da troca, os links não são tocados e a vítima segue com 0644. |
| A4-B4 (link replantado em laço) | Risco aceito, ainda acontece | O stop falha em 3 de 3 tentativas e a vítima fica intacta. Documentado no 16b, linha 224. |
| R1, R2, R3, R4, R9, R10, R12, A3-B2, A3-B3 e `navigate_timeout` | Passam | — |
| Formas r25 a r28 | Nenhum valor mascarado antes vaza agora | Ver A5-M1 sobre fidelidade. |

### Custo das 8 rodadas de decodificação (release, entrada de 4 MB)

| Entrada | HEAD | bacdc30 |
|---|---|---|
| matriz `;a=%3Fb%3D` (pior caso) | 3,0 s | 204 ms |
| matriz `;a=b=c` | 2,2 s | 348 ms |
| `%25` aninhado | 1,4 s | 42 ms |
| `a=%3Fb%3Dc&` | 1,2 s | 593 ms |
| `a=` repetido | 1,0 s | 8,4 ms |
| codificação com 4, 8 e 9 níveis | 457 / 315 / 172 ms | 250 / 88 / 84 ms |
| aninhamento de 100 mil níveis | 50 ms | — |

O custo cresce de forma linear em todas as entradas, sem panic e sem estouro de pilha. O pior caso é cerca de 3,6× o do r28. As 8 rodadas não são a causa do aumento; ele vem de três pontos:
- a varredura recomeça a cada `=` (`sanitize.rs:1110`);
- `effective_name` aloca memória para cada candidato;
- a matriz passa duas vezes pelo texto.

Gravidade: Baixo.

### Achados que restam

#### Médio

**A5-M1. Regressão do `d12158b`: os segmentos do caminho depois de um parâmetro de matriz sensível somem (CONFIRMADO).**
- **Local:** `core/src/export/sanitize.rs:874-875`. O `sanitize_matrix` roda o `sanitize_text` de novo sobre o caminho inteiro, e o valor sensível vai até um terminador ou `&` (`:1122`). A barra `/` não é nenhum dos dois.
- **Exemplos:**

  | Entrada | Saída |
  |---|---|
  | `/a;jsessionid=X/b/c?x=1` | `/a;jsessionid=%5BREDACTED%5D?x=1` (no `bacdc30`, `/b/c` ficava) |
  | `/users;token=abc/profile/123` | perde `/profile/123` |
  | `/a;v=2/session=keep/b` | perde `session=keep` e `/b` |

- **Efeito:** nada vaza, mas as URLs que as ferramentas devolvem perdem segmentos sem nenhum aviso. Isso fere a fidelidade do que é exibido.

**A5-M2. Vazamento parcial de um segredo com `+`, espaço, `&` ou `#` codificados dentro de uma URL aninhada (CONFIRMADO; já existia no `bacdc30`).**
- **Local:** `sanitize.rs:1216` e `:977`. O `percent_decode` transforma `+` em espaço a cada rodada, e a decodificação se repete até estabilizar. O espaço passa então a terminar o valor.
- **Exemplo:** `?redirect_uri=…%3Faccess_token%3DAAA%2BQPLUS2x` sai como `…%255BREDACTED%255D%20QPLUS2x`.
- **Alcance:**
  - num token base64, tudo depois do primeiro `+` vaza;
  - o mesmo acontece com `%2520`, `%2526` e `%2523`;
  - confirmado de ponta a ponta num header (`HDRPLUS6x`) e num corpo (`BODYPLUS9x`).

#### Baixo

- **A5-B1. Valor que começa com um terminador (CONFIRMADO; já existia).** Em `token="X"`, `token='X'`, `token=(X)` e `token= X`, só o valor vazio é mascarado. Confirmado de ponta a ponta (`HDRQUOT5x`, `BODYQUOT10x`).
- **A5-B2. Troca da pasta durante a escrita final perde o resgate (CONFIRMADO, 9 de 13).**
  - A escrita do core depois da última reconferência leva de 10 a 16 ms, não microssegundos.
  - A troca nessa janela faz o rename falhar com ENOENT, e o erro segue o caminho genérico (`capture/src/lib.rs:479`). Com isso:
    - o perfil é apagado;
    - a mensagem não indica nenhum resgate;
    - sobra um `.tmp-*`.
  - Nada foi escrito no alvo da troca em 13 tentativas.
- **A5-B3. O resgate mantém o perfil inteiro do Chrome sem limpeza (CONFIRMADO).**
  - São 8,7 MB, incluindo Cookies, Login Data e History.
  - As permissões estão corretas (0700/0600), e o caminho não pode ser plantado antes porque o diretório é criado novo.
  - O marcador de órfão é removido no fim da captura, então o `cleanup_orphans` nunca apaga esse perfil. A única pista dele é a mensagem de erro.
  - O `cdp-bodies.jsonl` não é resgatado.
- **A5-B4. O `cdp-events.jsonl` vazio é criado seguindo symlink (PLAUSÍVEL; já existia).** Local: `capture/src/lib.rs:377`. Só acontece quando a captura termina com zero eventos CDP; nesse caso, truncaria o alvo do link.
- **A5-B5. Excesso de redação (já existia).** `key=`, `tokens=5` e `{token=X}` são redigidos; neste último, o fechamento `}` some junto.
- **Tentativas de contorno da nova lógica de fronteira:**
  - mascarados corretamente: `token%3d`, `t%6Fken=`, `tok%00en=` e `token =x`;
  - fora do contrato `nome=valor`: `token\t=X`, `token:=X` e `token&#61;X` passam;
  - inconsistentes com a regra de texto: `;token%3DX` sem outro `=` no caminho, e `&token%3DX` na query;
  - um CSRF de input oculto reaproveitado num header de nome neutro (`X-Form`) não é propagado.

#### Informativo

- Na porta, com o socket morto, o Chrome espera 20 s até ser morto.
- Uma mensagem fragmentada pode chegar a cerca de 2× o teto.

### Documentação do 16b §2.4

| Item | Situação |
|---|---|
| A4-B4 | Claro na linha 224. |
| TOCTOU entre a reconferência e o rename | Inexato. As linhas 245-248 falam em "janela de microssegundos", o que vale para a escrita no alvo da troca, mas a janela de perda do resgate tem cerca de 15 ms (A5-B2). A afirmação de que o `canonicalize` reduz a janela também não procede: ele resolve uma string, e as escritas seguintes resolvem o caminho de novo. |
| Perfil | Contraditório. A linha 174 diz "perfil temporário descartado ao fim", e a linha 237 diz "perfil 0700, que não é apagado". Nenhuma das duas diz que os cookies ficam guardados, que nenhuma limpeza o remove ou que os corpos não são resgatados. |
| Campo `device` | Aceito, como pedido. É o valor `"device":"dev-…-7319"` que fica visível no corpo JSON. |

---

## Adendo 6: confirmação do adendo 5 (Rodada 11)

- **HEAD revisado:** `d50a19f`, num clone novo em `/tmp/rev30/repo`.
- **Correções conferidas:**
  - core: `e6a9edd`, `952921a`, `d50a19f`;
  - captura: `daa3414`.
- **Base de comparação:** o core `49f79ef`, compilado à parte. O `fake_server` foi recompilado.
- **Evidências:**
  - testes de reprodução e saídas em `/tmp/rev30/poc-secrets` (pares `*_head.out` / `*_49f.out`, `confirm_*.out`, `zz_sec30_*`) e `/tmp/rev30/poc-cap`;
  - relatórios parciais em `/tmp/rev30/{secrets,cap}.md`.

### Veredito: REPROVADO

Há uma **regressão média confirmada** (A6-M1) e uma **perda de fidelidade média confirmada** (A6-M2). A6-M2 é o resto do A5-M1 no caminho de texto. Todos os itens do adendo 5 estão corrigidos nas URLs.

### Itens do adendo 5

| Item | Estado | Evidência |
|---|---|---|
| A5-M1 (caminho truncado após matriz) | Corrigido nas URLs | `/b/c?x=1`, `/profile/123` e `session=keep/b` são preservados. O caminho de texto ainda trunca (A6-M2). |
| A5-M2 (`%2B`, `%2520`, `%2526`, `%2523`) | Corrigido | Mascarado por inteiro; `HDRPLUS6x` e `BODYPLUS9x` também, de ponta a ponta. |
| A5-B1 (aspas, parênteses, `= X`) | Corrigido | O valor é mascarado e os delimitadores ficam. |
| A5-B5 (excesso de redação) | Corrigido | `key=` e `{token=X}` são preservados. |
| Informativos anteriores | Corrigidos | 9 ou mais níveis, `;token%3DX`, `&token%3DX`, `token\t=`, `token:=`, `&#61;`, CSRF em `X-Form`, `nonce`, `sessionKey`. |
| A5-B2 (troca da pasta na escrita final) | Parcial | Em 20 tentativas, 16 foram resgatadas sem sobrar `.tmp-*`. Nas outras 3, os dados foram escritos no alvo da troca (A6-B5). |
| A5-B3 (o que o resgate guarda) | Corrigido | O resgate guarda só `cdp-bodies`, `cdp-events`, `netlog` e `motivo.txt`, com 0700/0600 e marcador. O prazo de 7 dias usa `createdMs`: com 6 dias fica, com 7 dias e 1 s sai. A limpeza roda na partida do MCP (`live.rs:82`) e do App. |
| A5-B4 (`cdp-events` vazio) | Corrigido | Conferido no código e no teste unitário; o caminho com 0 eventos não foi alcançado ao vivo. |
| A4-B4 (link replantado) | Aceito | Agora vai para o resgate, e a vítima fica intacta. |
| R1–R4, R9, R10, R12, A3-B2, A3-B3, A4-B2 (debug e release), A4-B3, A4-B5, `navigate_timeout` | Passam | — |

### Tokenizador novo (`core/src/export/scrub.rs`)

**Fuzz, em release:**
- **150 mil casos estruturados:** 0 panics, 0 perdas de fidelidade, 0 saídas não idempotentes. Houve 14.417 vazamentos, todos com exatamente 8 níveis de codificação (A6-B1). O `49f` tinha 89.757 vazamentos em todas as profundidades.
- **300 mil entradas aleatórias:** 0 panics, 0 vazamentos e 5 saídas não idempotentes (Info: dois placeholders adjacentes).

**Fronteiras:** limpas para UTF-8 dividido, `%FF`, codificações overlong, escapes que formam escapes novos, escapes truncados, fim de string, espaços Unicode e formas de placeholder.

**Custo, em release:**

| Entrada | HEAD | 49f |
|---|---|---|
| matriz `;a=%3Fb%3D`, 4 MB | 0,32 s | 3,0 s |
| `a=` repetido, 4 MB | 0,04 s | 1,0 s |
| `%25` aninhado, 16 MB | 1,2 s | 5,7 s |
| `%25`×8 com `3D`, `=` e `&` em URL, 4 MB | **0,95 s** | 0,30 s |
| cadeia `%`+`25`×n, 16 MB | **1,4 s** | 0,44 s |

O teto anunciado de 324 ms não vale para entradas de URL com 4 MB. A causa provável, não verificada, é o `sanitize_query` (`sanitize.rs:903`) chamar `scrub()` uma vez por par `&`.

### Achados que restam

#### Médio

**A6-M1. Regressão do `e6a9edd`: um segmento `token=X` no caminho vaza quando o caminho tem `;` (CONFIRMADO).**
- **Local:** `core/src/export/sanitize.rs:852-856`. O `sanitize_matrix` só examina segmentos que contêm `%`.
- **Cenário de ponta a ponta:**
  - a URL da requisição `https://h.invalid/x;v=1/token=SEGURL3x/next?page=2` sai em claro em `list_requests` e `get_request`;
  - o header Link `</p;a=1/token=LNK6x>` também sai em claro.
- **Antes:** o `49f` mascarava os dois (`confirm_49f.out`: "MARK SEGURL3x: mascarado"; `confirm_head.out`: "VAZA").
- **Observação:** caminhos sem `;`, como `/x/token=X`, já vazavam no `49f`.

**A6-M2. O caminho de texto trunca URLs (CONFIRMADO; resto do A5-M1).**
- **O que acontece:**
  1. o passo de URL acerta e produz `…jsessionid=%5BREDACTED%5D/b/c?x=1`;
  2. em seguida, o `sanitize_text` (`sanitize.rs:688`) consome `/b/c?x=1`.
- **Causa:** o valor vai até o fim do grupo (`scrub.rs:439`), e o `is_placeholder` (`scrub.rs:190`) só reconhece o placeholder exato.
- **Onde aparece:** corpos JSON, a linha de requisição (`:381`) e headers que não são URL (`:362`).
- **Efeito:** a URL exibida perde segmentos sem aviso, e a idempotência anunciada no `952921a` deixa de valer.

#### Baixo

- **A6-B1. Regressão de baixa probabilidade (CONFIRMADO).** Com exatamente 8 níveis de codificação, a cauda depois de um separador codificado vaza (`…%20CDLEAK8x`); o `49f` a mascarava. Local: `scrub.rs:290-300`.
- **A6-B2. Regressão de baixa probabilidade (CONFIRMADO).** `|`, `[` ou `{` crus dentro do valor deixam a cauda vazar: `token=AB|X`, `AB[X]`, `AB{X}` e `token=[abc]TAIL`. Local: `scrub.rs:113-133`. O `49f` mascarava; tokens base64 e JWT não usam esses caracteres.
- **A6-B3. Memória com codificação profunda (CONFIRMADO).** Locais: `scrub.rs:140-165` e `281-304`.

  | Entrada de 16 MB | HEAD | 49f |
  |---|---|---|
  | `%2525…` | 1,31 GB | 197 MB |
  | construção aninhada | 2,19 GB | 1,05 GB |

  Os corpos têm teto de 8 MB (cerca de 0,65 GB); headers e URLs só são limitados pelo tamanho do HAR.
- **A6-B4. Formas que já vazavam antes:**
  - entidades HTML de `=`: `&#0061;`, `&#x003D;`, `&#61` sem `;`, `&amp;#61;` e `token &#61; X` (`scrub.rs:542`);
  - o `＝` de largura total;
  - `Bearer ab%2B…`;
  - `//user:pass@host`.
- **A6-B5. A troca da pasta entre gravações escreve no alvo, e o stop diz OK (CONFIRMADO, 3 de 20, só mesmo usuário).**
  - **Local:** cada `write_atomic` resolve o caminho de novo (`core/src/store.rs:194-213`), e nada reconfere a identidade depois de `write_session_resilient` (`capture/src/lib.rs:476`).
  - **Cenário:** com a troca aos 8, 12 e 15 ms, o `session.json` ou os corpos foram gravados no diretório do atacante. Isso substitui um arquivo regular de mesmo nome lá, e a sessão dividida é reportada como OK.
  - **Sugestão:** reconferir a identidade depois da escrita, ou escrever relativo a um descritor de diretório.
- **A6-B6. Quando o próprio resgate falha, os eventos CDP se perdem (CONFIRMADO).**
  - **Local:** o fallback (`capture/src/lib.rs:536-544`) só chama `keep()` sobre o perfil, que tem Cookies, History e Login Data e não expira.
  - **Mensagem:** "os dados ficaram no perfil temporário", sem avisar que os eventos CDP faltam.
  - **Gatilho realista:** disco cheio. O teste usou a raiz de estado trocada por um arquivo.
- **A6-B7. O nome do arquivo do marcador não é amarrado ao `dir` (CONFIRMADO, só mesmo usuário).**
  - **Local:** `capture/src/lib.rs:986-1018`.
  - **Cenário:** um `rescue-evil.json` forjado com `dir:"rescue-111-222"` e `createdMs:0` apaga um resgate recente.
  - **Limite:** nada fora da raiz de estado foi apagado. Foram testados symlinks, `..`, `/` e nomes sem o prefixo.
- **Info:**
  - cada falha guarda mais uma cópia, sem teto total;
  - a partida do MCP não registra `rescues_removed`;
  - 5 saídas não idempotentes com dois placeholders adjacentes.

### Documentação do 16b §2.4

| Linhas | Situação | O que diz e por quê |
|---|---|---|
| 224-227 | Desatualizadas | Falam de "link simbólico replantado repetidamente". A mensagem real é outra, e os dados agora vão para o resgate. |
| 274-275 | Erradas | Dizem que, "com 12 ms o `rename` já passou". Aos 12 ms, o `session.json` foi gravado no alvo da troca. |
| 280-282 | Falsas | Dizem "0/13 do Revisor" e "microssegundos". Houve 3 de 20 com escrita no alvo (A6-B5). |
| 258 | Falsa contra marcador forjado | Diz que "o resgate não some antes do prazo" (A6-B7). |
| 259-260 | Incompletas | Não dizem que o fallback perde os eventos CDP (A6-B6). |
| 174-175 e 241-256 | Corretas | — |

---

## Adendo 7: confirmação do adendo 6 (Rodada 11)

- **HEAD revisado:** `868127b`, num clone novo em `/tmp/rev31/repo`, com as correções:
  - core: `0b94424`, `39826a3` e `868127b`;
  - captura: `93361b8` e `e6fc955`.
- **Comparação:** o core `d50a19f`, compilado à parte em `/tmp/rev31/before`.
- **Evidências:**
  - testes de reprodução em `/tmp/rev31/poc-secrets` e `/tmp/rev31/poc-cap`;
  - relatórios em `/tmp/rev31/{secrets,cap}.md`.
- **Restrições:** Chrome só em loopback; `/Applications` intacto.

### Veredito: APROVADO, com ressalvas baixas

Não há achado alto nem médio confirmado. As decisões do líder não contam como achado:
- `session=[REDACTED]/b`, porque `session` é nome sensível;
- a redação de um irmão quando há 8 níveis de codificação, por falha fechada.

Também não contam os riscos aceitos: a lacuna depois da reconferência final, o campo `device` e a redação a mais por falha fechada.

### Itens do adendo 6

| Item | Estado | Evidência |
|---|---|---|
| A6-M1 (`token=X` no caminho com `;`) | Corrigido | De ponta a ponta, `SEGURL3x`, `LNK6x`, `LNKA1x`, `LNKB2x` e `LNKUI3x` saem mascarados e `/next?page=2` é preservado. O `d50` vazava. |
| A6-M2 (truncamento no caminho de texto) | Parcial | O texto não altera mais uma URL já sanitizada, e a idempotência voltou. Texto cru ainda perde `/b/c?x=1` (A7-B5). |
| A6-B1 (8 níveis de codificação) | Corrigido | Do 8º ao 10º nível sai mascarado, com o sufixo e o `&page` externo preservados. |
| A6-B2 (`\|`, `[`, `{` no valor) | Corrigido | `AB\|X`, `AB[X]`, `AB{X}` e `[abc]TAIL` saem mascarados. |
| A6-B3 (memória) | Corrigido | Pico de RSS com 16 MB: 34 MB na cadeia, 34 MB na construção e 125 MB nos grupos de cerca de 1 MB. Parte dos 2,19 GB do r30 era do gerador de entrada. |
| A6-B4 (entidades e variantes de `=`) | Parcial | 6 formas corrigidas; `&amp;#61;` e `＝` sozinho ainda vazam (A7-B1, A7-B2). |
| A6-B5 (troca da pasta) | Corrigido | Em 32 trocas (16 debug, 16 release, de 0 a 30 ms), **nada foi escrito no alvo**. Em 31 o stop falha e o conteúdo vai para `.moved` e para o resgate. 1 passou depois da reconferência final, que é a lacuna aceita. |
| A6-B6 (falha do resgate) | Corrigido | ENOSPC real num RAM disk de 64 MB. O plano B apaga Cookies, History, Login Data e Local State e mantém eventos, corpos, NetLog e `motivo.txt` (0700/0600) com marcador. Com 8 dias, a partida seguinte apaga a pasta. |
| A6-B7 (marcador forjado) | Corrigido | Marcadores forjados não apagam um resgate recente. `touch -t` na pasta apaga, mas isso exige o mesmo usuário e está documentado (16b, l.269-271). |
| Custo | OK | Crescimento linear. Pior caso: 438 ms com 4 MB (a promessa era menos de 400 ms; o `d50` dava 433 ms) e 1,7 s com 16 MB. |
| Regressões da captura | Todas passam | R1–R4, R9, R10, R12, A3-B2, A3-B3, A4-B2 a A4-B5, A5-B2 a A5-B4 e `navigate_timeout`. |

### Fuzz (release, 4 sementes)

Cada semente rodou 150 mil casos estruturados e 900 mil entradas aleatórias:
- 0 vazamentos e 0 panics;
- 0 saídas não idempotentes nos casos estruturados;
- cerca de 18,3 mil perdas de fidelidade por semente, todas dentro da falha fechada aceita: só o irmão interno se perde com 8 níveis (7 com contexto de redirect);
- entre 76 e 104 saídas não idempotentes por semente nas entradas aleatórias (menos de 0,1 %).

Para comparação, o `d50` teve 14.417 vazamentos na semente 1.

### Cobertura do corpus

- `cargo test --offline --release --test corpus --test corpus_fuzz` passa 4/4.
- `cases.jsonl` tem 309 linhas e `benign.jsonl` tem 49; o anúncio falava em 320.
- **Faltam cerca de 45 entradas dos PoCs:**
  - o conjunto B4 do r30 (`token&#0061;E1x` a `E8x`, `token＝FW1x` e `Bearer ab%2B…`);
  - `/a;v=2/session=keep/b`;
  - `https://h/a;token=AB,CD/e`;
  - os casos de placeholder.
- **Limites da verificação:**
  - em entradas com forma de URL, o `keep` só é verificado na saída de URL (`corpus.rs:97`), então o truncamento em texto não é testado;
  - os casos de 8 níveis estão gravados já decodificados, e só o fuzz os exercita.

### Achados que restam (todos baixos)

- **A7-B1. `token＝X` vaza (CONFIRMADO de ponta a ponta; já existia).** Local: `scrub.rs:104`. O retorno antecipado só olha `= % @ &`. Vaza no header `X-FW` e no `search_bodies`.
- **A7-B2. Entidade HTML de `=` com `&amp;` vaza (CONFIRMADO de ponta a ponta).** Local: `scrub.rs:827-835`. Só `&amp;&#61;` é tratado; `&amp;#61;`, `&amp;#x3D;` e `&amp;equals;` vazam.
- **A7-B3. Valor que começa com um delimitador forte não é redigido (CONFIRMADO; já existia).** Local: `scrub.rs:449-450`. Exemplos: `token=\X`, `token="X` e `token=&#61;X`.
- **A7-B4. Texto colado depois de fechar aspas ou colchetes vaza, se começa com outra abertura (CONFIRMADO; já existia).** Local: `scrub.rs:347`. Exemplos: `token='a'"X`, `"a"(X)`, `[a][X]` e `(token=AB(c)X)`.
- **A7-B5. Fidelidade: texto cru ainda perde segmentos (CONFIRMADO; igual ao `d50`).**
  - **Local:** `scrub.rs:479-515` e `sanitize.rs:362/381/688`.
  - **Exemplos:** perde `/b/c?x=1` na linha de requisição, em headers que não são URL e em caminhos relativos dentro de JSON. Também `/a;v=2/session=keep/b` perde o `/b`, ao contrário da decisão do líder, que previa `session=[REDACTED]/b`.
- **A7-B6. Fidelidade: um grupo acima de 1 MiB com `%XX` é apagado por inteiro, inclusive o nome do parâmetro (CONFIRMADO; novo).**
  - **Local:** `scrub.rs:527-531`.
  - **Exemplo:** um `a=%3Fb%3D…` de 4 MB vira 14 B, sem nada sensível nele; o `d50` mantinha o conteúdo.
  - **Sugestão:** aplicar isso só quando houver um nome sensível.
- **A7-B7. O `cdp-bodies.jsonl` ainda é aberto pelo caminho (PLAUSÍVEL; 0 em 6 tentativas).**
  - **Local:** `capture/src/lib.rs:166`, seguido de `177-179`, logo depois da verificação do descritor.
  - **Cenário:** uma troca nessa janela de microssegundos mandaria os corpos para a pasta do atacante.
  - **Sugestão:** usar `fdio::create_new_at`.
- **Informativo:**
  - **Plano B:** um marcador de órfão remanescente pode apagar o perfil mantido, que é a única cópia dos eventos (`lib.rs:939-977`). A montagem é artificial.
  - **Pastas de resgate nunca limpas:** uma com mtime no futuro (`lib.rs:1017-1023`) e outra sem marcador depois de um SIGKILL.
  - **Lockfile:** o `868127b` não atualizou o `capture/Cargo.lock` para o rustix, e o build offline reescreve o arquivo.
  - **JSON com `\ud800`:** o corpo é omitido por inteiro, como no `d50`.

### `fdio.rs`

Está limpo:
- cada chamada usa um único nome, com O_NOFOLLOW, O_DIRECTORY e O_CLOEXEC;
- as permissões são definidas na criação (0600/0700);
- o `unlinkat` não segue links;
- o temporário é removido nos erros;
- depois de 20 capturas, 5 delas com falha forçada, a contagem de fds continua em 12 e não sobra `.tmp-*`.

### Documentação do 16b §2.4

| Linhas | Situação |
|---|---|
| 224-225 | Desatualizadas. O core já expõe `write_session_dir_at`, mas a captura não o usa (`lib.rs:2151`). |
| 213-218 | Omitem que o arquivo de corpos é criado pelo caminho (A7-B7). |
| 244-247 | A mensagem de erro se contradiz ("nada foi gravado nela" e "a sessão foi gravada na pasta original") e não dá o caminho `.moved`. |
| 269-271, 278-281, 293-301, 303-307 | Corretas. |
