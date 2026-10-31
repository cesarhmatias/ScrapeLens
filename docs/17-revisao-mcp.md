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
