# Rodada 11, onda 1 — ferramentas de navegador e reconhecimento do site (contrato)

Data: 2026-10-31. Dona: Captura. Complementa `docs/16-mcp-contrato.md` (Core:
ferramentas de leitura) e parte da decisão D6 (`docs/01-decisoes.md`) e da fase
A (`docs/15-mcp-cloakbrowser.md`). **Escreve-se o contrato antes do código.**
Este documento não define o servidor MCP (transporte, rmcp, elicitação): isso
não está atribuído à Captura. Define o que o servidor MCP chamará.

## 1. Fluxo e limites

Um agente de IA usa o MCP do ScrapeLens com o **Chrome normal** para entender a
configuração de um site. O CloakBrowser só volta à pauta se `site_profile`
recomendar "candidato a CloakBrowser" (D6, item 6). Fora do escopo desta onda:
baixar ou rodar o CloakBrowser, proxy MITM, `--no-sandbox`, qualquer contorno do
Gatekeeper, resolver CAPTCHA ou desafio.

Ferramentas desta seção: `start_capture`, `navigate`, `capture_status`,
`stop_capture` e `site_profile`. **`act` não existe nesta onda**: seguindo a D6
(item 3), o ScrapeLens abre o Chrome e **entrega o acesso CDP em loopback**; o
agente age com a própria ferramenta (por exemplo `--cdp-endpoint` do Playwright
MCP ou o Chrome DevTools MCP). Motivos: (a) não reimplementamos uma API de
entrada; (b) o ScrapeLens fica só como observador. Consequência assumida: as
ações do agente no navegador **não passam pela confirmação do ScrapeLens**; o
que as limita é a allowlist de rede (§2.2), aplicada pelo próprio Chrome.

## 2. Modelo de segurança

### 2.1 Perfil e processo

Perfil dedicado e temporário: nunca o perfil pessoal; depuração só em
`127.0.0.1`; encerra somente o processo que o ScrapeLens iniciou
(`ChromeProcess` + marcador de órfãos). `--no-sandbox` nunca é passado.

**Só o Chrome estável da Google** (revisão de segurança, achado M3). O
`binary_path` do agente nunca vira o executável sem passar por
`chrome::validate_chrome`, que **não executa o binário**: `start` recusa com
`browser_invalid` tudo o que não for um `.app` com
(1) `CFBundleIdentifier = com.google.Chrome`, (2) o executável do bundle como
`Contents/MacOS/<CFBundleExecutable>` (symlinks resolvidos, bit de execução),
(3) `CFBundleShortVersionString` presente (a versão lida), e
(4) `codesign --verify --deep -R='anchor apple generic and identifier
"com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV"'` com
**código de saída 0** (`chrome::CHROME_REQUIREMENT`). Nada da saída de texto do
`codesign` é interpretado (o parse de `-dv` foi enganado por uma quebra de linha
no caminho, R1 da revisão). O `--deep` cobre os bundles aninhados (Helpers,
frameworks): uma cópia assinada pela Google com um Helper trocado é recusada
(R2) e o Helper nunca roda. O requisito exige a âncora Apple e o Team ID da
Google no certificado folha, então um bundle ad hoc com o identificador do
Chrome também é recusado. **Não usa `--strict`**: o Chrome instalado nesta
máquina tem atributos de Finder ("resource fork, Finder information, or similar
detritus not allowed") que o `--strict` rejeita; sem ele, o `--deep` com o
requisito explícito passa no Chrome real (exit 0, cerca de 9 s). **Sem cache**:
cada `validate_chrome` refaz a verificação. Caminho com caractere de controle
(`\n`, `\r`, TAB, NUL, DEL, C1) ou não UTF-8 é recusado (`UnsafePath`, código
`browser_invalid`) antes de qualquer leitura, para o caminho dado e para o
canônico. Leitura por `plutil` e `codesign` do sistema, por caminho absoluto.
Recusados (testes): `/bin/echo`, `/bin/sh`, script executável chamado `chrome`,
`.app` falso com `Info.plist` mentindo, bundle ad hoc com a identidade do
Chrome, caminho com quebra de linha (PoC da revisão), cópia do Chrome com o
Helper trocado, bundle de outro produto, caminho inexistente.

**Execução do caminho validado (R11).** `BrowserCapture::start` valida e passa
ao launcher exatamente `ValidatedChrome.binary` (caminho canônico, symlinks
resolvidos), nunca o caminho que o agente informou. **Lacuna que resta:** entre a
verificação e o `exec` há uma janela em que um processo do mesmo usuário, com
escrita no bundle, poderia trocar um arquivo (TOCTOU). Em `/Applications` o
bundle é do grupo `admin`; uma cópia em pasta do usuário é do próprio usuário,
que já poderia executar qualquer coisa como ele. O `--deep` torna a janela
pequena, mas não a fecha; fechá-la exigiria executar por descritor de arquivo,
que o macOS não oferece para `.app`.
Fora do macOS o erro é `UnsupportedPlatform`. O `chrome::detect` do App
(escolha do usuário na interface) não mudou. O caminho de `StartInfo.browser`
é o já resolvido. O servidor MCP deve escolher e mostrar o navegador na
confirmação com `chrome::resolve_stable_chrome(explícito)` (valida o caminho do
agente e nunca o substitui), não com `normalize_binary_path`/`detect`, que
aceitam qualquer arquivo; até lá `start` ainda recusa com `browser_invalid`,
mas só depois da elicitação.

**Descritores herdados (R9).** O Chrome é lançado com todo descritor `>= 3`
marcado `FD_CLOEXEC` no filho (`fcntl` entre o fork e o exec; com pipe, só o 3
e o 4 do CDP ficam abertos). Um log ou socket que o lançador do servidor
herdou sem CLOEXEC não chega ao Chrome nem aos helpers. A varredura vai até
`min(getdtablesize(), 65536)`; um fd acima disso não é coberto (nenhum valor
prático). Teste vivo `live_inherited_fds_do_not_leak_into_chrome` (pipe e porta,
processo principal e helpers; sem a correção o fd vaza). Os descritores do pipe
são criados com `F_DUPFD_CLOEXEC`, mas entre o `pipe()` e a duplicação há uma
janela mínima sem CLOEXEC (o macOS não tem `pipe2`): um `plutil`/`codesign`
lançado por outra thread nesse instante poderia herdar uma ponta do pipe. Não
medi nem reproduzi; o filho é de vida curta e só segura a ponta até sair.
Informativo, sem correção.

### 2.1b Captura comum do App: rede aberta por padrão (`NetworkMode`)

Defeito achado pelo usuário: no App, `Iniciar sessão` com `https://google.com.br`
abria o Chrome com `DNS_PROBE_FINISHED_NXDOMAIN`. A captura comum levava
`--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost` e
`--allow-insecure-localhost`: só loopback resolvia, nenhum site real carregava.
Agora `CaptureConfig.network` escolhe:
- `NetworkMode::Open` (**padrão**): sem `--host-resolver-rules` e sem
  `--allow-insecure-localhost`; o Chrome resolve e acessa a rede normalmente;
- `NetworkMode::LoopbackOnly`: o comportamento antigo, **só para testes**
  (nada além de `127.0.0.1`/`localhost` resolve). As suítes ligam com
  `SCRAPELENS_CAPTURE_NETWORK=loopback` (o App lê isso via `NetworkMode::from_env()`)
  ou, nos testes Rust, `network: NetworkMode::LoopbackOnly`.
A captura **controlada** do MCP (allowlist) não mudou: a allowlist
(`resolver_rules`) vale no lugar do modo, sem relaxamento de certificado; a
`BrowserCapture` passa `LoopbackOnly` só como falha fechada caso a allowlist faltasse.
Testes: `network_mode_defaults_to_open`, `open_mode_passes_no_dns_rules_and_no_localhost_relaxation`,
`loopback_only_mode_keeps_the_lab_restrictions`,
`the_controlled_capture_allowlist_overrides_the_network_mode`,
`ignore_cert_is_the_only_certificate_relaxation_in_open_mode` e o vivo
`live_open_mode_resolves_a_local_name_and_loopback_only_does_not` (um servidor local
acessado por `sl-open-mode.localhost`, que o Chrome resolve sozinho: no modo aberto o
servidor vê a requisição e a sessão tem status 200; no `LoopbackOnly` o servidor não
vê nada). Nenhum site real foi acessado.

**Revisão dos demais argumentos do launcher em sites reais** (nenhum impede
carregar um site; os que alteram o que o servidor vê):

| Argumento | Efeito em site real |
|---|---|
| `--ignore-certificate-errors` (só com `ignore_cert`/`SCRAPELENS_CAPTURE_IGNORE_CERT=1`) | esconde erros de TLS: o Chrome deixa de mostrar o interstício e a captura de um site com certificado ruim parece normal. **Só para laboratório**; o padrão é desligado |
| `--allow-insecure-localhost` | só afeta `localhost`; removido do modo aberto |
| `--no-pings` | desliga o `ping` de `<a ping>` (hyperlink auditing): a beacon que o site esperaria não é enviada. Raro; **muda o tráfego** |
| `--disable-popup-blocking` | deixa `window.open` sem gesto abrir abas (anúncios, OAuth). Bom para capturar multi-alvo; o usuário pode ver mais popups |
| `--disable-features=OptimizationHints,Translate,MediaRouter,InterestFeedContentSuggestions` | evita requisições do próprio Chrome (hints, tradutor); não muda os recursos da página |
| `--disable-background-networking`, `--disable-component-update`, `--disable-sync`, `--metrics-recording-only`, `--disable-domain-reliability`, `--disable-client-side-phishing-detection`, `--disable-breakpad`, `--no-service-autorun` | silenciam tráfego do navegador (não da página) para o NetLog ficar só com o que interessa; sem efeito no que o site vê |
| `--enable-quic` | QUIC já é o padrão; mantido para h3 (a regra do projeto é não desabilitar QUIC) |
| `--disable-extensions`, `--disable-default-apps`, `--password-store=basic`, `--use-mock-keychain`, `--no-first-run`, `--no-default-browser-check`, `--disable-search-engine-choice-screen`, `--disable-component-extensions-with-background-pages` | UI/perfil/chaveiro; sem efeito de rede |
| `--net-log-capture-mode=Everything`, `--log-net-log` | só registram (cookies e cabeçalhos no NetLog: ver §2.4) |
| `--remote-debugging-pipe` (ou porta com `expose_cdp`) | **liga `navigator.webdriver = true`** na página (medido, `docs/20-captcha-google.md` §4.2); o D7 passa a flag da linha seguinte para desfazer isso |
| `--disable-blink-features=AutomationControlled` (**D7, sempre**) | `navigator.webdriver` volta a `false`, mesmo com o CDP ligado. Não mexe na rede nem no que é capturado. Ver o parágrafo abaixo |
| `--headless=new` (só com `headless`) | o User-Agent e a impressão digital do navegador mudam (`HeadlessChrome`); o padrão do App é janela visível. **Relevante ao `site_profile`**: um desafio anti-bot sob headless pode não ocorrer com o Chrome normal |

**Aviso de automação suprimido por padrão (D7, 2026-11-03).** Por decisão do usuário
(`docs/01-decisoes.md` D7), **toda** captura leva `--disable-blink-features=AutomationControlled`:
a comum do App e a controlada do MCP, no pipe e na porta (`expose_cdp`), em qualquer
`NetworkMode`, com ou sem `headless`. A flag entra em `chrome_args()`; se já houver um
`--disable-blink-features` com outros valores, os valores são **combinados numa só flag**
(`merge_blink_features`, sem duplicar a flag nem os valores). Medido: sem ela a página lê
`navigator.webdriver === true` com o CDP por pipe; com ela, `false` na captura completa e
na controlada, nos dois transportes. O `session.json` registra o contexto para quem lê:
`capture.chromeArgs` traz os argumentos do lançamento (sem os caminhos temporários e sem
a URL inicial, com a flag) e `capture.notes` diz em texto que o aviso foi suprimido; o
`site_profile` expõe isso em `captureContext.automationFlagSuppressed` (`true`, `false`,
ou `null` quando a sessão não informa, como as importadas de HAR/NetLog), para um desafio
anti-bot ser lido sabendo que o site NÃO viu o aviso de automação. **Resolver CAPTCHA
continua fora do escopo**, e **nenhuma outra técnica de anti-detecção** (User-Agent
falso, remendo de impressão digital, ocultar o CDP etc.) entra sem decisão nova.
Testes: `automation_flag_is_always_present_exactly_once_in_every_mode` (rede, allowlist,
headless, `ignore_cert`, pipe e porta), `merge_blink_features_combines_without_duplicating_the_flag_or_the_values`,
`recorded_args_keep_the_automation_flag_and_drop_temp_paths_and_the_url`, os vivos
`live_full_capture_hides_navigator_webdriver_on_both_transports` e
`live_controlled_capture_hides_navigator_webdriver_on_both_transports` (página em loopback
que grava `navigator.webdriver` no servidor) e, no `recon`,
`capture_context_reports_whether_the_automation_flag_was_suppressed`.

### 2.2 Allowlist obrigatória, em duas camadas

`start_capture` **sem `allowed_hosts` não vazio é erro** (`allowlist_required`).

**Semântica oficial (decisão do líder após a revisão de segurança, achado M2):
o navegador impõe o HOST (todas as portas); a PORTA só é imposta no
`navigate`.** Não interceptamos a rede (`Fetch`) para impor porta, porque isso
altera a fidelidade da captura. Quem aprova `localhost:P1` aprova, para a
página, `localhost` em qualquer porta (Redis local, admin, outros serviços): o
servidor MCP deve dizer isso na elicitação.

| Camada | Mecanismo | O que cobre | O que não cobre |
|---|---|---|---|
| 1. Navegador | `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE h1, EXCLUDE h2…"` com `allowed_hosts` + `third_party_hosts` (IPv4 literal da lista também ganha `EXCLUDE`) | qualquer host por nome **e IP literal** (medido: `127.0.0.1`, `127.1`, `2130706433` e `[::1]` falharam com `ERR_NAME_NOT_RESOLVED` no Chrome 156), em qualquer aba, iframe, worker ou cliente CDP, inclusive redirects | **a porta**: a regra conhece só o nome |
| 2. API | `navigate` recusa antes de enviar; mesma função de decisão (`Allowlist::permits_url`) | esquema, host, **porta**, userinfo (`http://permitido@outro/`) | navegação feita por script ou clique da página/agente |

Medido com o PoC da revisão (`live_port_gap_is_reported_on_all_paths`, Chrome
156): com `localhost:P1` aprovado, a página alcançou `localhost:P2` por **8
caminhos**: 302 de topo, `location=`, meta refresh, `window.open`, iframe,
fetch, WebSocket e host em maiúsculas. **Todos os 8 aparecem em
`stop_capture.allowlist.violations`** (e como aviso `capture.allowlist_violation`
na sessão), porque o relatório vem dos **eventos CDP** (`Network.requestWillBeSent`
de cada salto de redirect, de cada iframe e popup, e `Network.webSocketCreated`),
não da sessão importada, que perde o WebSocket. Também é violação a navegação de
topo para um host aprovado só em `third_party_hosts` (aprovado para subrecursos,
não como destino). Regra de violação: host fora das duas listas sem falha de
resolução, ou porta diferente da escrita no padrão (`host:porta`); padrão sem
porta aceita qualquer porta. O que é reportado não é bloqueado. As URLs de
violações, hosts bloqueados e avisos saem **sem consulta, fragmento,
`;parâmetros` de caminho nem userinfo**.

Regras de `allowed_hosts` e `third_party_hosts` (strings):
- nome exato (`exemplo.com`), curinga de subdomínio (`*.exemplo.com`, não casa
  `exemplo.com`), IPv4 literal escrito de forma explícita (`127.0.0.1:8080`);
  **IPv6 literal é recusado** (`allowlist_unsupported`): o resolvedor não o
  trata de forma confiável; porta opcional (`exemplo.com:8443`; sem porta =
  qualquer porta do host; a porta vale só no `navigate` e no relatório);
- sem esquema, sem caminho; maiúsculas normalizadas; entrada com ponto final,
  `%`, espaço, barra invertida ou não ASCII é **inválida** (`allowlist_invalid`;
  punycode só em ASCII); `*` sozinho, `*.com` e IPs com curinga são
  `allowlist_too_broad`; lista vazia é `allowlist_required`. IPv4 só na forma
  `a.b.c.d` canônica (`127.1`, `2130706433`, `0x7f.0.0.1` são recusados). Não há
  lista de sufixos públicos: `*.co.uk` passa, e o operador responde por isso;
- só `http` e `https` navegam; `file:`, `data:`, `javascript:`, `chrome:`,
  `blob:`, `view-source:`, `about:` (exceto `about:blank`) são recusados. O
  analisador de URL é **mais estrito que o do Chrome de propósito** (recusa
  barra invertida, controle, não ASCII, `%` no host, host com ponto final,
  qualquer `@` na autoridade, IPv4 fora da forma canônica) para que o que passa
  seja lido igual pelo Chrome.

`allowed_hosts` = alvos onde o agente pode **navegar/agir** (consentidos pelo
usuário na confirmação de `start_capture`). `third_party_hosts` = hosts
adicionais que a página precisa carregar (CDN de scripts, desafios de
proteção). Tudo o que não está em nenhuma das duas listas **não resolve**.

**Consequência a conhecer (decisão do líder se mudar):** com a allowlist
estrita, scripts de proteção de terceiros (`challenges.cloudflare.com`,
`js.datadome.co`, `js.hcaptcha.com`…) não carregam enquanto não forem
declarados. O Chrome registra `net::ERR_NAME_NOT_RESOLVED` para eles, e isso
**vira evidência**: `site_profile` lista `blocked_hosts` ("a página tentou
carregar X; bloqueado pela allowlist; a proteção pode estar escondida") e
recomenda reiniciar com esses hosts em `third_party_hosts` (nova
confirmação). Recomendação padrão: primeira passada estrita; segunda passada
com os terceiros que o próprio `site_profile` apontou.

### 2.3 Confirmação

A confirmação (elicitação MCP) acontece **na camada do servidor MCP**, não nesta
API Rust, que recebe o pedido já confirmado. Nenhum parâmetro `confirmed:true`
existe (o modelo poderia preenchê-lo). Classes de efeito, para o servidor MCP
aplicar:

| Ferramenta | Efeito | Confirmação |
|---|---|---|
| `start_capture` | inicia um processo Chrome; tráfego de saída para os hosts listados; opcionalmente abre a porta CDP ao agente | **sempre**; o texto deve mostrar `allowed_hosts`, `third_party_hosts`, `expose_cdp`, binário e o aviso de §2.4 |
| `navigate` | GET de topo para host da allowlist | **não por chamada** (coberta pela confirmação do início); recusa fora da allowlist |
| `stop_capture` | encerra o Chrome iniciado e grava a sessão | não |
| `capture_status`, `site_profile` | leitura | não |

### 2.4 Dados sensíveis

O NetLog (`--net-log-capture-mode=Everything`) e o CDP guardam **cookies,
cabeçalhos de autorização e corpos**. Por isso: perfil temporário descartado ao
fim (exceto o resgate de arquivos da captura descrito abaixo, que NÃO é o perfil); `start_capture` devolve `sensitive_notice` (texto fixo) que o servidor MCP
deve mostrar; **o agente nunca digita credenciais** (não há `act`; se o agente
usar o CDP exposto para digitar, o valor aparece no corpo POST capturado);
as ferramentas de leitura e `site_profile` **redigem por padrão** valores de
cookie e de cabeçalhos (nomes, URLs, status e tamanhos aparecem; valores viram
`[redigido, N bytes]`), com opt-in explícito pela Core.

Escritas na pasta da sessão **não seguem symlink** (revisão, achado F2): os
arquivos que a captura grava (`cdp-bodies.jsonl`, `netlog.json`,
`cdp-events.jsonl`, `netlog.original.json`, marcador de órfãos) usam
`O_NOFOLLOW` + `create_new` (0600); um nome já existente, inclusive um symlink
plantado, tem o **nome** removido e recriado, nunca o alvo escrito;
`cdp-events.jsonl` e o marcador são gravados num temporário novo e trocados por
`rename`, que substitui o próprio link; uma pasta de sessão que é symlink é
recusada, e depois de `ensure_private_dir` ela é conferida **já aberta**
(`O_NOFOLLOW|O_DIRECTORY`, dono = nosso usuário, modo exatamente 0700).

**NetLog (R3).** O Chrome abre o `--log-net-log` pelo caminho, seguindo
symlink; pré-criar o arquivo na pasta da sessão deixava uma janela para um
processo do mesmo usuário trocá-lo por um link (PoC `poc_netlog_race.py`: 236 KB
de NetLog completo, com cookies, num arquivo de fora). Agora o NetLog é gravado
**dentro do perfil temporário**, que criamos 0700 desde a criação
(`DirBuilder`, sem `recursive`, falha se o nome existir) e conferimos aberto
(dono, 0700, não-link), com nome `scrapelens-chrome-<pid>-<ns>` em `$TMPDIR`
(por usuário no macOS). Só depois que o Chrome sai o ScrapeLens o lê com
`O_NOFOLLOW` (só arquivo regular do nosso usuário, conferido no descritor) e o
grava em `<sessão>/netlog.json` por `write_private` (temporário `create_new` +
`rename`, que substitui um link plantado sem escrever no alvo). Teste vivo
`live_netlog_swap_race_does_not_write_through_a_symlink`: um atacante planta ou
troca `netlog.json` por um link durante a captura e o alvo fica intacto. **Lacuna
que resta:** um processo do **mesmo usuário** que ache o perfil pelo nome ainda
pode mexer nele (mesmo uid; fora do modelo, como a porta do `expose_cdp`). Um
`SIGKILL` do servidor deixa o NetLog parcial só no perfil, que a limpeza de
órfãos apaga: não sobra `netlog.json` parcial na pasta da sessão.

**Gravação da sessão relativa ao descritor (A3-B3, A4-B3, A4-B4, A6-B5).** No
início abrimos a pasta da sessão (`O_NOFOLLOW|O_DIRECTORY`, nossa, 0700) e
guardamos o **descritor** e a identidade (dispositivo + inode, que não aparece em
nenhuma saída). Depois do encerramento do Chrome, NENHUMA escrita resolve o
caminho da pasta de novo:
- `cdp-bodies.jsonl` é **criado** relativo ao descritor, no início da captura
  (`fdio::create_replacing_at`: `openat(O_EXCL|O_NOFOLLOW)`; um nome já ocupado,
  inclusive por symlink plantado, tem o NOME removido e é recriado, nunca o alvo),
  então uma troca do nome da pasta logo depois da verificação não manda os corpos
  para a pasta do atacante (A7-B7: antes era `open_private(caminho)`); durante a
  captura ele é escrito pelo próprio descritor e, no fim, relido por ele (não
  pelo caminho). Teste `fdio::tests::create_replacing_at_never_writes_through_a_planted_link_nor_into_a_swapped_dir`
  e o vivo `live_planted_symlinks_are_not_followed`;
- `cdp-events.jsonl`, `netlog.json` e `netlog.original.json` são gravados com
  `openat(O_EXCL|O_NOFOLLOW)` + `renameat` relativos ao descritor
  (`fdio::write_private_at`);
- o core grava o resto (`session.json`, `attachments/`) num **diretório de
  preparo** novo e 0700 dentro do perfil temporário (`write_session_fd`), e cada
  item é movido para a pasta da sessão com `renameat` relativo ao descritor
  (`attachments/`, `cdp-events.jsonl`, `netlog.json` e `session.json` por
  último). Entre sistemas de arquivos diferentes (EXDEV) copia pelo mesmo
  descritor. Quando a Core expuser `write_session_dir_at(dirfd, …)` este preparo
  pode ser trocado por ela, sem mudar o contrato.
Efeitos: (1) um symlink plantado em `cdp-events.jsonl`, `netlog.json`,
`session.json` ou `attachments` é **substituído** pelo `renameat` (o NOME muda,
o alvo nunca é escrito) e vira o aviso `capture.planted_symlink_removed` na
sessão e uma linha em `warnings` do stop; (2) o laço que replanta o link (antes
A4-B4, que vencia as 3 tentativas e derrubava o stop) não faz mais diferença,
porque não há tentativas: o `rename` é atômico; (3) se o NOME da pasta for
trocado durante a gravação, tudo continua indo para a pasta ORIGINAL (a que o
descritor representa) e nada cai na pasta do atacante. Testes
`fdio::tests::*` (nomes inválidos, escrita após mover a pasta, link substituído,
`attachments` como link ou já povoado, pasta movida, diretório no lugar de arquivo),
`a3_b3_planted_symlinks_after_the_copy_do_not_fail_the_stop` (4 nomes, inclusive
`attachments`) e `a4_b5_swapped_session_dir_is_detected_and_nothing_is_written_or_removed`
(a sessão vai inteira para a pasta original, nada em OUT, links de OUT intactos).

**Pasta da sessão reconferida (A4-B5, A6-B5).** `recheck_session_dir` reabre a
pasta pelo NOME (`O_NOFOLLOW|O_DIRECTORY`) e exige diretório, nosso, 0700 e a
MESMA identidade, **antes de gravar e depois de gravar**. Trocada por um link,
por outro diretório (mesmo 0700 e nosso) ou com o modo afrouxado, o stop **falha**:
**antes** de gravar com "A pasta da sessão foi trocada ou deixou de ser nossa
durante a captura (…); nada foi gravado nela e nada fora dela foi apagado."; **depois**
de gravar (a troca aconteceu DURANTE a gravação) com uma mensagem própria, que
não repete o "nada foi gravado": "A pasta da sessão foi trocada durante a
gravação (…). A sessão foi gravada inteira na pasta ORIGINAL, agora em
`<caminho.moved>`; nada foi gravado na pasta que tomou o lugar dela e nada fora da
pasta original foi apagado." O caminho vem de `F_GETPATH` no descritor aberto
no início (o lugar ATUAL da pasta original, mesmo movida); se o sistema não
informar, a mensagem diz "que não conseguimos localizar". Em ambos os casos os
arquivos da captura também vão para o resgate. Nunca devolve OK com a pasta
trocada durante a gravação. Teste
`a7_message_after_a_swap_during_the_write_names_the_moved_dir_and_does_not_contradict_itself`.

**Resgate quando a sessão não pôde ser gravada (A5-B2, A5-B3, A6-B6, A6-B7).**
*Toda* falha depois do encerramento do Chrome (pasta trocada, o core recusar um
arquivo, `rename` com ENOENT, falha de importação) resgata os arquivos da captura
**antes** de o perfil temporário ser apagado:
- **O que fica:** só `cdp-events.jsonl`, `cdp-bodies.jsonl` (relido pelo
  descritor, mesmo com a pasta trocada), `netlog.json` e `motivo.txt` (a mensagem
  de erro, que pode ter o caminho da sessão), numa pasta **0700 nova**
  `scrapelens-capture-state/rescue-<pid>-<ns>/` dentro do `TMPDIR`, com um
  marcador `rescue-<pid>-<ns>.json` ao lado. O erro do `stop_capture` cita a
  pasta. Esses arquivos **contêm cookies, cabeçalhos e corpos** (a captura crua,
  como o NetLog `Everything`): trate a pasta como sensível.
- **O que NÃO fica:** o resto do perfil do Chrome (Cookies, Login Data, History,
  Local State...) é apagado como sempre.
- **Limpeza e prazo (A6-B7):** `cleanup_orphans` (no início do App e do servidor
  MCP) apaga a pasta de resgate e o marcador quando o **próprio diretório** tem
  mais de **7 dias** (mtime do diretório, que só muda quando entradas são
  criadas ou removidas nele). A idade **não** vem do marcador: um marcador forjado
  (com `createdMs` antigo ou com o `dir` de outro resgate) não faz um resgate
  recente parecer vencido. O marcador só vale se o nome do arquivo for `<dir>.json`,
  com `dir` filho direto do `state_root`, prefixo `rescue-`, sem `/` nem `..`, e o
  diretório não for symlink. `OrphanCleanup.rescues_removed` conta. Um usuário
  que reescreva o mtime do diretório (mesmo usuário) pode antecipar a limpeza:
  fora do modelo, ele poderia apagar a pasta direto. Teste
  `a6_b7_forged_marker_cannot_delete_a_recent_rescue`.
- **Plano B (A6-B6):** se a pasta de resgate normal não puder ser criada (ENOSPC,
  `TMPDIR` cheio), o PRÓPRIO perfil vira o resgate: tudo o que não é da captura
  (Cookies, Login Data, History, o que também libera espaço) é apagado, os
  eventos CDP, os corpos e o motivo são gravados nele, e ele é movido para o
  `state_root` com marcador, entrando no mesmo prazo de 7 dias. Se nem mover ou
  marcar for possível, o perfil fica onde está, JÁ LIMPO e COM os eventos, e o
  erro diz "SEM prazo automático … apague quando recuperar"; só se até isso
  falhar o erro avisa que o perfil mantido pode estar incompleto e que contém
  dados do Chrome. Testes `a6_b6_fallback_adopts_the_profile_with_events_and_a_ttl_marker`
  e `a6_b6_fallback_keeps_events_in_place_when_it_cannot_be_moved`.
- **`.tmp-*`:** o temporário que uma gravação deixa (`.session.json.tmp-…`…) é
  removido pelo descritor da pasta ORIGINAL, esteja ela no lugar ou movida.
Testes `a5_b3_rescue_keeps_only_the_capture_files_in_a_private_dir_with_a_marker`,
`a5_b3_cleanup_removes_only_expired_rescues_that_the_marker_really_names`,
`a5_b2_remove_stale_tmp_cleans_the_original_dir_even_after_it_was_moved` e os
vivos `live_swapped_session_dir_fails_the_stop_without_touching_outside` (o PoC:
a pasta vira um link para OUT; OUT fica com os mesmos 3 nomes, links intactos e
alvo igual) e `live_any_write_failure_rescues_the_capture_files` (um diretório no
nome de `session.json`: resgate com os 4 arquivos, sem `.tmp-*`, com marcador).

**Resultado do PoC de janela (`a5b2_toctou.py`, Revisor).** Contra o binário
atual da mcp, 8 rodadas com a troca disparada assim que `attachments/` aparece
(atraso 0) e 9 com atrasos de 2 a 30 ms: nada caiu em OUT em nenhuma (só o
`attachments/` vazio que o próprio atacante criou). Com atraso 0 a troca pega a
gravação no meio: o stop **falha** com resgate (os arquivos já movidos estão na
pasta original, o resto dos dados no resgate); com 2 ms ou mais a gravação (agora
alguns `renameat`) já terminou e o stop devolve OK, com a sessão inteira na pasta
original, e a troca acontece depois. Antes (daa3414): 3 de 20 rodadas escreviam
`session.json` e corpos em OUT e o stop dizia OK.

**Lacuna que resta.** Entre o `recheck` posterior à gravação e o retorno ao
chamador a pasta ainda pode ser trocada por quem tem o mesmo usuário; o stop
reportou a verdade no instante da verificação e a sessão está na pasta original.
É o mesmo limite de qualquer arquivo de usuário (ele pode mover a pasta quando
quiser) e fora do modelo.

**Links plantados antes da captura (F2).** Teste vivo
`live_planted_symlinks_are_not_followed` (o PoC da revisão: links para
`netlog.json`, `cdp-bodies.jsonl` e `cdp-events.jsonl`; nenhum alvo recebe dado
nem muda de modo). O temporário previsível do `write_atomic` do core, que era o
segundo vetor desse PoC, foi corrigido pela Core (commit 3939881).

### 2.5 Porta de depuração: pipe por padrão, porta só com `expose_cdp`

**Teto de mensagem do pipe (R12).** Uma mensagem do Chrome (JSON terminado em
NUL) acima de `transport::MAX_PIPE_MESSAGE_BYTES` (128 MiB; o WebSocket antigo
tinha 64 MiB e um corpo legítimo cabe, `maxResourceBufferSize` ≈ 67 MB) encerra
o transporte sem nunca guardar mais que o teto. O Chrome sai em seguida de forma
graciosa e o NetLog parece completo, então o fechamento anormal é registrado à
parte (A3-B2): `stop_capture` devolve `graceful:false` e o aviso
`cdp_transport_closed: frame_too_large: …`; a sessão ganha o aviso
`capture.cdp_transport_closed` e o motivo `capture.cdp_transport_closed:
cdp_transport_closed: frame_too_large: …` em `completeness.reasons`, e
`completeness.state` deixa de ser `complete`. O `navigate` em espera de carga
percebe o canal fechado e volta na hora com `navigate_failed` ("o CDP fechou
durante o navigate (frame_too_large)"), em vez de girar até o prazo (eram 60 s).
**Modo porta (A4-B2).** O WebSocket tem o mesmo teto (`max_message_size` e
`max_frame_size` = 128 MiB; o padrão da biblioteca era 64/16 MiB). O erro de
capacidade vira o mesmo `frame_too_large` e a mesma captura incompleta; depois de
qualquer erro de leitura o socket **nunca mais é lido** (o tungstenite deixa o
buffer de entrada cheio e uma nova leitura derrubava a thread em builds de
debug, com `stop_failed` e `recording:true`). Testes
`a4_b2_websocket_message_cap_closes_with_a_reason_and_never_panics` e o vivo
`live_oversized_websocket_message_marks_the_capture_incomplete`.
Testes `r12_read_frame_enforces_the_message_cap_without_buffering_past_it`,
`r12_oversized_pipe_message_closes_the_transport_and_smaller_ones_still_pass`,
`a3_b2_closed_transport_marks_the_session_incomplete_with_an_explicit_reason` e o
vivo `live_oversized_pipe_message_marks_the_capture_incomplete` (o PoC do
`console.log` de 140 MB: `navigate` em 2,7 s, `graceful:false`, estado ≠ complete).
A fila entre a thread de leitura e o laço continua **sem limite de contagem**
de propósito: limitá-la bloquearia a leitura e travaria os dois lados do pipe
(o laço escreve, o Chrome escreve), então a memória segue o ritmo do laço.

Revisão de segurança (docs/17, achado F3): a porta DevTools aceitava conexão
de qualquer processo local desde o lançamento, antes de `Network.enable`.
Decisão do líder e estado atual:

- **Sem `expose_cdp` (padrão): `--remote-debugging-pipe`.** O Chrome herda dois
  descritores (lê comandos no fd 3, escreve no fd 4, mensagens JSON terminadas
  em NUL) e **não abre porta alguma**: nenhum outro processo, do mesmo usuário
  ou não, consegue falar com ele; não existe `DevToolsActivePort`. Teste
  `live_pipe_opens_no_port_and_exposed_port_is_loopback_only`: a linha de
  comando tem `--remote-debugging-pipe` e não tem `--remote-debugging-port`, e
  `lsof -iTCP -sTCP:LISTEN` no processo do navegador não lista nada. Vale também
  para `BrowserCapture::start` e para o `run()` do App (ver abaixo).
- **Fidelidade medida antes de trocar** (`tests/aceite/check_multi_target.py`,
  que roda a captura real do App contra `testserver /multi/`; Chrome 156,
  macOS arm64; a escolha vai por `SCRAPELENS_CDP_TRANSPORT=pipe|port`):

  | Transporte | Corridas | NetLog | CDP | Alvos por marcador | Service worker | Avisos de setup |
  |---|---|---|---|---|---|---|
  | porta (antes) | 2 | 16/16 | 16/16 | page, iframe, worker, service_worker | página + SW ligados, sem duplicata | 0 |
  | **pipe** | **6** | **16/16** | **16/16** | **idênticos** (13 sessões; mesmos tipos por marcador) | **página + SW ligados, sem duplicata** | **0** |

  Todas as corridas passaram o aceite completo (16/16 NetLog, ≥15/16 CDP, tipos,
  corpos, sem fusão, SW ligado). Sem perda de fidelidade, então **o `run()` do
  App passou a usar o pipe por padrão** (`SCRAPELENS_CDP_TRANSPORT=port` volta ao
  WebSocket); o resto do App não mudou, e os testes do `src-tauri` seguem
  verdes. Os testes vivos de `capture/` sem `expose_cdp` (allowlist por eventos,
  8 caminhos de porta, symlinks, cenários do `site_profile`) também rodam em
  pipe.
- **Com `expose_cdp: true` a porta é inerente ao recurso.** Fica assim: porta
  efêmera, `--remote-debugging-address=127.0.0.1` e **sem
  `--remote-allow-origins`**. O `lsof` do mesmo teste mostra o `LISTEN` só em
  `127.0.0.1:<porta>` (nada em `*` nem `[::]`). Um WebSocket com
  `Origin: https://evil.example` recebe **403**; sem `Origin` (nós, Playwright,
  Chrome DevTools MCP) recebe **101**. Páginas web, portanto, não alcançam a
  porta.
- **Risco que fica com `expose_cdp:true` (documentado, não mitigável aqui).** A
  porta não tem autenticação. Qualquer processo que alcance
  `127.0.0.1:<porta>`, **do mesmo usuário ou de outro usuário da mesma
  máquina**, lê `GET /json/version` (que devolve a URL do WebSocket do
  navegador) e passa a controlar o Chrome inteiro: executar JavaScript nas
  páginas, ler cookies e corpos da sessão, navegar dentro da allowlist (a rede
  continua limitada aos hosts aprovados, mas o processo age com a sessão
  aberta). A janela vai do lançamento ao `stop_capture`; o número da porta fica
  visível em `ps`, em varredura de portas e no `DevToolsActivePort` do perfil
  temporário (0700). O portão do §4.1 protege contra o agente, não contra
  terceiros locais. Recomendação: `expose_cdp:true` só em máquina de um único
  usuário, por capturas curtas, e a elicitação deve mostrar este aviso. Sem
  `expose_cdp` não há porta e o risco não existe.

## 3. Ferramentas

Convenções: JSON; erros `{ "error": { "code", "message", "details"? } }`;
`capture_id` é o handle (uma captura ativa por vez nesta onda, erro
`capture_already_running`).

### 3.1 `start_capture`

Entrada (snake_case, como as ferramentas da Core):

```json
{
  "allowed_hosts": ["exemplo.local:8080"],      // obrigatório, >= 1
  "third_party_hosts": ["js.exemplo-cdn.net"],  // opcional
  "start_url": "http://exemplo.local:8080/",    // opcional, precisa passar na allowlist
  "binary_path": null,                           // opcional; senão detecção automática
  "headless": false,                             // padrão false (modo real); true para testes
  "expose_cdp": false                            // padrão false
}
```

Saída (`StartInfo`, camelCase como as saídas da Core; o `capture_id` é do
servidor MCP, que guarda o `BrowserCapture` num mapa):

```json
{
  "sessionDir": "/…/session",
  "chromePid": 1234,
  "browser": { "path": "…", "version": "Chrome/156.0.…", "userAgent": "…" },
  "allowlist": { "allowedHosts": [], "thirdPartyHosts": [], "resolverRules": "MAP * ~NOTFOUND, EXCLUDE …" },
  "cdp": null | { "http": "http://127.0.0.1:PORT", "browserWs": "ws://127.0.0.1:PORT/devtools/browser/…", "pageTargetId": "…" },
  "sensitiveNotice": "…",
  "warnings": []
}
```

Erros (`code`): `allowlist_required`, `allowlist_too_broad`, `allowlist_invalid`,
`allowlist_unsupported` (IPv6), `start_url_not_allowed`, `browser_invalid` (o
`binary_path` não é o Chrome estável, §2.1), `browser_start_failed`,
`session_dir`; `capture_already_running` é do servidor MCP.

`cdp` só aparece com `expose_cdp:true` e só depois do portão de §4.1. Sem
`expose_cdp` o Chrome nem abre a porta (pipe, §2.5); com ele a porta escuta só
em `127.0.0.1` e tem o risco descrito em §2.5. `pageTargetId` é a aba da captura (a que
`navigate` usa): o agente anexa a ela.

### 3.2 `navigate`

```json
{ "url": "http://exemplo.local:8080/p", "wait": "load", "timeout_ms": 15000 }
```

Navega a **aba principal** da captura (`Page.navigate`). `wait`: `"load"`
(padrão; espera `Page.loadEventFired` ou o prazo) ou `"none"`. Saída
(`NavigateResult`): `{ "frameId", "loaderId", "loaded": true|false, "errorText": null|"net::ERR_…" }`.
Erros: `url_not_allowed` (com o motivo), `capture_stopped`, `navigate_failed`,
`navigate_timeout` (o navegador não respondeu no prazo; a captura continua).
`loaded:false` não é erro (prazo ou navegação sem evento de carga).

**Prazo (R12).** `timeout_ms` vale para o `navigate` inteiro (o comando
`Page.navigate` e a espera da carga dividem um só prazo), com piso de 2 s e
folga de 5 s para o chamador. Com o Chrome parado (`SIGSTOP`), o
`navigate(timeout_ms=3000)` que levava 30,4 s agora volta em 3,3 s com
`navigate_timeout` (o `Page.navigate` sem resposta no prazo); `navigate_timeout`
também cobre o caso em que o próprio laço da captura não responde. Teste vivo
`live_navigate_honours_its_timeout_when_chrome_is_frozen`. Efeito colateral: a
espera da carga conta o tempo que o `Page.navigate` já gastou.

### 3.3 `capture_status`

`BrowserCapture::status() → CaptureStatus` (`recording`, `events`, `pageUrl`,
`lastError`): reuso do tipo do App.

### 3.4 `stop_capture`

Saída (`StopReport`):

```json
{
  "sessionDir": "…",
  "requests": 31,
  "netlog": "complete" | "repaired" | "unusable",
  "graceful": true,
  "waitedMs": 105,
  "allowlist": {
    "blockedHosts": [ { "host": "challenges.exemplo.net", "requests": 2, "exampleUrl": "…" } ],
    "violations": [ { "requestId": "cdp-r0007", "url": "…", "host": "…", "reason": "porta 9000 fora da allowlist" } ]
  },
  "warnings": ["…"]
}
```

Encerramento gracioso (`Browser.close` + espera + NetLog fechado); se não for
gracioso, a sessão sai marcada incompleta (comportamento atual).
`allowlist.violations[].requestId` é o id lógico da sessão importada quando a
requisição existe nela, senão `cdp:<sessão>/<requestId>` (ex.: WebSocket, que
a importação não guarda). A sessão importada fica em `sessionDir`, com `capture.third_party_blocked` (informativo)
e `capture.allowlist_violation` (aviso) nos `warnings` do `session.json`, para
as ferramentas da Core e para `site_profile`. Se o chamador descartar o
`BrowserCapture` sem `stop`, o `Drop` encerra o Chrome do mesmo modo.

### 3.5 Segundo cliente CDP

Com `expose_cdp:true`, o agente conectará seu próprio cliente ao mesmo Chrome.
O nosso dedupe por `targetId` só vale para a nossa conexão. Medido em loopback
(testes ignorados `second_cdp_client_cooperative` e
`second_cdp_client_never_resumes`, Chrome 156, headless): o segundo cliente
conecta no meio da sessão, anexa à aba, faz `Target.setAutoAttach
{flatten:true, waitForDebuggerOnStart:true}` e a página cria um worker.

| Cenário | Resultado |
|---|---|
| A. segundo cliente retoma o alvo (`runIfWaitingForDebugger`) | worker recebido por **ambos** com `waitingForDebugger:true`; carga completa; worker chega ao servidor e entra na nossa sessão; encerramento gracioso |
| B. segundo cliente pede `waitForDebuggerOnStart` e **nunca** retoma | idêntico: o **nosso** `runIfWaitingForDebugger` libera o alvo (a retomada vale para o alvo, não para a sessão); nada trava |

Limites da medição: uma execução de cada (repetida 3× sem divergência), um tipo
de alvo (worker dedicado), cliente escrito por nós. **Fechado por
desenho (§4.1):** o agente só recebe o endereço depois que o nosso
`Network.enable` e o auto-attach estão ativos na aba inicial; alvos criados
depois (workers, popups) seguem o pipeline de setup medido acima. **Não
medido:** clientes que usam `Fetch` ou depuração com pausa, e a corrida em
alvos filhos criados *depois*, em que o agente retoma antes do nosso
`Network.enable` chegar (ficou dentro nos testes). Consequência de produto: a
nossa retomada também libera alvos que o agente quisesse manter pausados.

## 4. Crate `scrapelens-capture` e API pública (para o servidor MCP)

A captura vive em **`capture/`** (crate `scrapelens-capture`, **sem Tauri**:
`cargo tree` mostra só `scrapelens-core`, `serde`, `serde_json` e `tungstenite`;
0 ocorrências de `tauri`). `src-tauri/src/capture.rs` e `chrome.rs` são
adaptadores finos do App (`SessionPayload`, `CaptureSession`, `run()` com o
mesmo comportamento e a mesma `CaptureConfig`). O servidor MCP depende de
`capture/` sem puxar a janela.

API pública (`use scrapelens_capture::…`):

```text
// captura comum (a do App)
CaptureConfig { chrome, session_dir, start_url, headless, ignore_cert, network: NetworkMode }
NetworkMode { Open /* padrão */, LoopbackOnly }   // from_env(): SCRAPELENS_CAPTURE_NETWORK=loopback
CaptureStatus { recording, events, chrome_pid, session_id, session_dir, started_at, page_url, last_error }
CaptureOutcome { session: Value, session_dir: PathBuf, notice: String }
run(config, status: Arc<Mutex<CaptureStatus>>, stop: Receiver<()>, ready: Sender<Result<(),String>>)
    -> Result<CaptureOutcome, String>
default_state_root() -> PathBuf          // marcadores de captura (órfãos)
cleanup_orphans(&Path) -> OrphanCleanup  // chamada pelo App na partida
chrome::{detect, normalize_binary_path, candidates, ChromeInfo}   // do App, permissivos
chrome::{validate_chrome, resolve_stable_chrome, ValidatedChrome, ChromeError}  // estritos (§2.1)
transport::CdpTransport { Port, Pipe }     // pipe por padrão; SCRAPELENS_CDP_TRANSPORT=port|pipe

// captura controlada (MCP)
allowlist::Allowlist                      // new(allowed, third_party) -> Result<_, AllowlistError>
  permits_url(&str) -> Result<AllowedUrl, UrlDenied>
  host_allowed(&str) -> bool
  resolver_rules() -> String
  report(&SessionV1) -> AllowlistReport   // blockedHosts + violations
browser::BrowserCaptureConfig { chrome, session_dir, start_url, headless,
                                allowed_hosts, third_party_hosts, expose_cdp }
browser::BrowserCapture
  start(config) -> Result<(BrowserCapture, StartInfo), StartError>
  navigate(&self, url, wait_load, timeout) -> Result<NavigateResult, NavigateError>
  status(&self) -> CaptureStatus
  stop(self) -> Result<StopReport, String>     // StopReport.outcome: Option<CaptureOutcome>
browser::{StartInfo, CdpAccess, NavigateResult, StopReport, StartError, NavigateError, SENSITIVE_NOTICE}
```

A thread de captura continua dona do soquete CDP; `navigate` e `stop` são
mensagens num canal consumido pelo laço de gravação (latência ≤ ~250 ms).

### 4.1 Portão do CDP exposto

`start` com `expose_cdp:true` só devolve `cdp` (`http`, `browserWs`,
`pageTargetId`) **depois** que o nosso cliente está ligado na aba inicial:
`Network.enable` e `Target.setAutoAttach` com **ACK de sucesso**, sessão
configurada e nenhum comando de setup pendente nela. Se isso não acontecer em
15 s, `start` falha (`browser_start_failed`) e o Chrome é encerrado; o
endereço nunca é entregue. Assim o agente não consegue agir (nem retomar alvos
pausados) antes de nós. Cobertura: testes unitários do portão
(`initial_target_gate_*`), teste vivo `agent_first_action_is_captured` (a
primeira ação do agente, anexar à aba da captura e navegar sem esperar, aparece
em `Network.requestWillBeSent` na nossa sessão) e um controle por mutação (com o
portão forçado a fechar, `start` falha e nada é entregue). Limite: com
`expose_cdp:true` a porta existe desde o lançamento (também no
`DevToolsActivePort` do perfil temporário, 0700); um processo local que a
encontre contorna o portão. O risco é o de §2.5 e fica fora do modelo; sem
`expose_cdp` não há porta (pipe).

## 5. `site_profile`

Crate independente `recon/` (`scrapelens-recon`, depende só de
`scrapelens-core`), com as assinaturas em **dados** (`recon/signatures.json`) e
testes sem rede. Entrada: uma sessão capturada (`SessionV1` + `BodySource`
para corpos HTML/JS) e opções. Saída (camelCase, como a Core):

```json
{
  "schema": "scrapelens.site-profile/1",
  "sessionId": "…",
  "captureContext": { "automationFlagSuppressed": true | false | null, "headless": false | true | null },
  "sample": { "requests": 31, "documents": 3, "appRequests": 12, "partial": false,
              "protocols": { "https://exemplo.test": ["h2"] } },
  "findings": [
    {
      "id": "F001",
      "category": "protecao" | "desafio" | "captcha" | "bloqueio" | "cookie" | "token" | "protocolo" | "terceiro-bloqueado",
      "vendor": "cloudflare" | null,
      "kind": "cookie" | "response-header" | "request-header" | "script-host" | "form-field" | "path" | "status" | "protocol" | "cookie-flow" | "token-origin" | "blocked-host",
      "signatureId": "cf-005" | null,
      "summary": "texto PT-BR",
      "confidence": "alta" | "media" | "baixa",
      "occurrences": 3,
      "evidence": [ { "requestId": "cdp-r0004", "attemptId": "cdp-r0004-a1", "scope": "response-header",
                      "field": "cf-mitigated", "value": "challenge", "url": "…", "status": 403, "source": "netlog",
                      "thirdParty": false } ],
      "source": { "kind": "fornecedor" | "secundaria" | "projeto", "url": "…" } | null,
      "resolvedLater": true | false | null,
      "limits": ["…"]
    }
  ],
  "recommendation": {
    "value": "chrome-normal-basta" | "precisa-de-priming" | "candidato-a-cloakbrowser" | "indeterminado",
    "confidence": "alta" | "media" | "baixa",
    "reasons": ["…"], "limits": ["…"], "basedOn": ["F002"]
  },
  "warnings": []
}
```

- `evidence[].requestId`/`attemptId` são os ids da Core (`LogicalRequest.id`,
  `Attempt.id`) e resolvem em `get_request`. Valores: nomes e URLs sempre;
  **valores de cookie/cabeçalho redigidos** (`"[redigido, 32 bytes]"`), salvo
  valores de enumeração documentados (`challenge`, `captcha`, `protected`,
  `403`), que são o sinal.
- `indeterminado` é acréscimo ao pedido do líder (três valores): sessão
  parcial/vazia, sem documento principal, ou evidência insuficiente. Dizer que
  "Chrome normal basta" sem evidência seria inventar.

### 5.1 Confiança de um achado

Segue o modelo de `core/src/assess.rs`: **um marcador sozinho nunca é
bloqueio**.

| Nível | Regra |
|---|---|
| `alta` | assinatura de **fonte do fornecedor** que, pela própria documentação, indica ação de proteção na resposta, **no site-alvo** e **com o status documentado** (ex.: `cf-mitigated: challenge`; `x-amzn-waf-action: challenge` com **202** ou `captcha` com **405**; `x-datadomeresponse` ≠ 200) |
| `media` | assinatura de fornecedor que mostra que o produto **está presente** (cookie de `Set-Cookie`, script, cabeçalho) no site-alvo, sem prova de bloqueio; ou dois indícios independentes de fonte secundária; ou campo de formulário corroborado por script/cabeçalho/cookie do mesmo fornecedor |
| `baixa` | um único indício de fonte secundária (ex.: `bm_sz`, `incap_ses_*`); **presença só em corpo, consulta ou cookie do pedido** (texto refletido, `?g-recaptcha-response=1`, cookie criado por `document.cookie`); **valor de bloqueio com status diferente do documentado** (ex.: AWS WAF `challenge` em 200: presença do produto, não desafio); **cookie, cabeçalho ou bloqueio visto só em recurso de outro host** |

Regras da revisão de segurança (docs/17, R1 a R4), cada uma com teste em
`recon/tests/profile.rs` (`r1_…` a `r4_…`):

- **Site-alvo** = hosts dos documentos de topo da sessão (iframes de terceiros
  não contam). Um host é do alvo se for igual ou subdomínio (ou domínio-pai) de
  um desses; não há lista de sufixos públicos. Evidência de outro host sai com
  `thirdParty: true`, o achado fica `baixa` com o limite escrito, e **não entra
  na recomendação**. Script (`script-host`) e campo de formulário são
  referências embutidas pela própria página e ficam fora desta regra.
- **Desafio resolvido** só por resposta **2xx** depois, na mesma rota (um 3xx
  pode levar ao próprio desafio), ou por cookie de liberação (`cf_clearance`,
  `aws-waf-token`) definido depois **pelo mesmo site**; cookie de outro host não
  libera.

### 5.2 Achados genéricos (sem nome de fornecedor)

- **Status de bloqueio**: 403, 429 e 503 em rotas da aplicação (documento ou
  XHR/fetch); com `Retry-After` quando existir (RFC 9110). `alta` só quando a
  rota não tem resposta bem-sucedida depois; senão `media`.
- **Protocolo observado** (`h1`/`h2`/`h3` por origem, com o estado de
  verificação da Core): "**observado**", não "exigido". Provar exigência
  precisaria de uma tentativa em h1 que falhasse; uma captura só não prova.
- **Cookies definidos pelo servidor e reenviados** (`Set-Cookie` na resposta N
  e `Cookie` com o mesmo nome depois): "cookie de sessão/guarda **observado**"
  (até 10, os mais reenviados). "Obrigatório" **não** é afirmável por uma
  captura (exige remover e testar, `validate_run`): o achado diz isso em `limits`.
- **Tokens dinâmicos e origem**: para as últimas requisições XHR/fetch bem
  sucedidas (até 5, ou o `target_request_id` dado), usa `flow::value_origins`
  (Core) e relata valores de cabeçalho, consulta e corpo (≥ 8 bytes) com origem
  em resposta anterior: `strong` → confiança `media`; `possible` (mesmo valor,
  campo com outro nome) → `baixa`. Valores de cookie ficam de fora (já são o
  achado de cookies). Nada é re-derivado aqui e o valor nunca sai.
- **Ordem no tempo**: `session.requests` **não é cronológica** (a Core ordena
  por id; medido numa sessão real: `cdp-r0004` era a primeira requisição). "Antes"
  e "depois" usam o início da tentativa (`startedAt`) quando todas têm tempo, e a
  ordem da sessão só como reserva. Sugestão à Core: documentar isso em
  `docs/16-mcp-contrato.md` para quem lê `list_requests`.
- **Hosts de terceiros bloqueados pela allowlist** (`ERR_NAME_NOT_RESOLVED`):
  achado `terceiro-bloqueado` (§2.2).

### 5.3 Recomendação

Determinística, por regras (ordem de avaliação):

1. `indeterminado`: sessão marcada parcial/incompleta pela Core, ou nenhum
   documento HTML principal com resposta, ou menos de 2 requisições.
2. `candidato-a-cloakbrowser`: o **Chrome normal foi bloqueado** na navegação
   principal ou numa rota da aplicação **e não houve resposta bem-sucedida
   depois da mesma rota** (nem após desafio), com pelo menos um achado de
   bloqueio de confiança `alta` (desafio/captcha/403 de fornecedor, ou
   403/429/503 no documento principal). Quando só há script de CAPTCHA
   presente e a página carregou, **não** é candidato. O texto diz: "o Chrome
   normal foi barrado; isto **não prova** que o CloakBrowser passaria".
3. `precisa-de-priming`: nada barrou o Chrome, mas (a) um desafio foi servido e
   **resolvido no próprio navegador** (resposta bem-sucedida depois na mesma
   rota, ou cookie de liberação depois dele: `cf_clearance`, `aws-waf-token`) →
   confiança `alta`; (b) um **cookie de liberação** definido por uma requisição
   foi reenviado nas seguintes; (c) há **token dinâmico** com origem em resposta
   anterior (`token-origin`). Confiança `media` com (b) ou token `strong`;
   `baixa` se o único indício for "possível origem". Cookie de **presença**
   (`__cf_bm`, `datadome`, `_px3`, `bm_sv`…) reenviado **não** dispara priming
   (qualquer cliente com cookie jar o reenvia): vira linha em `reasons`.
4. `chrome-normal-basta`: documento principal respondeu, nenhum bloqueio nas
   rotas da aplicação, nenhum desafio resolvido e nenhum token. Proteção
   presente passiva (cookie/script) não muda isso, mas aparece nos achados.
   Confiança `media` com ≥ 5 requisições, senão `baixa`; **nunca `alta`** (uma
   navegação não prova).

Limites sempre declarados em `recommendation.limits`: amostra (uma navegação),
site visto só com a allowlist usada, ausência de interação humana, e que
"bloqueado" é sobre esta captura.

## 6. Assinaturas (fonte obrigatória)

Regra: **só entra na tabela entregue assinatura com fonte consultada**
(documentação do fornecedor, ou fonte secundária citável, ou fixture do
projeto). Sem fonte confirmada: fora, listada em §6.2. Fontes consultadas em
2026-10-31 (leitura de documentação pública, cada página aberta diretamente; nenhum site de terceiro foi
testado nem contatado para detectar proteção).

### 6.1 Entregues

`kind`: **F** = documentação do fornecedor; **S** = fonte secundária (limita a
confiança a `baixa`/`media`); **P** = fixture do projeto.

| id | Fornecedor | Sinal | Papel | Fonte | Citação |
|---|---|---|---|---|---|
| cf-001 | Cloudflare | cookie `__cf_bm` | gestão de bots (presença) | F https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/ | "`__cf_bm` … Bot Management, Bot Fight Mode" |
| cf-002 | Cloudflare | cookie `cf_clearance` | desafio resolvido | F (mesma) | "Records that a visitor completed a challenge" |
| cf-003 | Cloudflare | cookie `__cfseq` | ordem/tempo de requisições (produtos de bot) | F (mesma) | "Tracks the order and timing of a user's requests" |
| cf-004 | Cloudflare | cookies `cf_chl_rc_i`, `cf_chl_rc_ni`, `cf_chl_rc_m` | plataforma de desafio | F (mesma) | "Challenge Platform" |
| cf-005 | Cloudflare | resposta `cf-mitigated: challenge` | **desafio servido** | F https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/ | "present and set to `challenge`" |
| cf-006 | Cloudflare | resposta `cf-ray` | passa pela Cloudflare (fraco) | F https://developers.cloudflare.com/fundamentals/reference/http-headers/ | "`Cf-Ray` … Added response headers" |
| cf-007 | Cloudflare | script `challenges.cloudflare.com/turnstile/v0/api.js` | widget Turnstile | F https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/ | "https://challenges.cloudflare.com/turnstile/v0/api.js" |
| cf-008 | Cloudflare | campo `cf-turnstile-response` | token do Turnstile | F (mesma) | "`cf-turnstile-response`" |
| aw-001 | AWS WAF | resposta `x-amzn-waf-action: challenge` com 202, ou `captcha` com 405 | **desafio/CAPTCHA servido** | F https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html | "header `x-amzn-waf-action` with a value of `challenge` … `202`"; "`captcha` … `405 Method Not Allowed`" |
| aw-002 | AWS WAF | cookie `aws-waf-token` | token de desafio | F https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-details.html | "stored in a cookie named `aws-waf-token`" |
| dd-001 | DataDome | cookie `datadome` | identificador/token | F https://docs.datadome.co/reference/validate-request | "`Set-Cookie: datadome=…`" |
| dd-002 | DataDome | resposta `x-datadome: protected` | passa pelo DataDome | F (mesma) | "`X-DataDome: protected`" |
| dd-003 | DataDome | resposta `x-datadomeresponse: 403` | **decisão de bloqueio/desafio** | F (mesma) | "`X-DataDomeResponse: 403` … allow (200) or challenge (any other status)" |
| dd-004 | DataDome | requisição `x-datadome-clientid` | id de cliente enviado pelo navegador/módulo | F (mesma) | "request header checked first … ClientID" |
| dd-005 | DataDome | script `js.datadome.co/tags.js` | JS tag | F https://docs.datadome.co/docs/javascript-tag | "`<script src=\"https://js.datadome.co/tags.js\" async>`" |
| dd-006 | DataDome | requisição `api-js.datadome.co/js/` | coleta de sinais | F (mesma) | "`api-js.datadome.co/js/` … fingerprint endpoint, POST" |
| dd-007 | DataDome | host `*.captcha-delivery.com` | página/iframe de bloqueio | F (mesma) | "`ct.captcha-delivery.com` … `frame-src … *.captcha-delivery.com`" |
| hm-001 | HUMAN (PerimeterX) | cookies `_px`, `_px2`, `_px3`, `_pxhd`, `_pxvid`, `pxcts`, `_pxde`, `_pxac`, `_pxttld`, prefixo `_pxff_` | sensor/sessão de detecção de bots | F https://docs.humansecurity.com/applications-and-accounts/docs/use-of-cookies-web-storage | tabela "Browser cookies" |
| ak-001 | Akamai | cookie `bm_sv` | Bot Manager (presença) | F https://techdocs.akamai.com/identity-cloud/docs/hosted-login-cookies-and-local-storage-1 | "Cookie used by Akamai Bot Manager to help differentiate … humans and … bots" |
| ak-002 | Akamai | cookie `_abck` | provável Bot Manager | S (lista de cookies da própria Akamai: https://www.akamai.com/legal/manage-cookie-preferences confirma que o cookie existe, **não** descreve a função; função em https://scrapfly.io/blog/posts/akamai-bot-manager-understanding-abck-cookies-and-sensor-data) | "_abck … First Party … Strictly necessary" |
| ak-003 | Akamai | cookie `bm_sz` | provável Bot Manager | S https://www.mayoclinic.org/es/about-this-site/privacy-policy/cookie-list | "bm_sz … bot/human analysis" |
| im-001 | Imperva | cookies `incap_ses_*`, `visid_incap_*` | sessão/visitante (Incapsula) | S https://www.fundacionbancosantander.com/en/cookies | "incap_ses_* … maintain current sessions"; "Visid_incap_# … tracks the HTTP request" |
| rc-001 | Google reCAPTCHA | script `www.google.com/recaptcha/api.js` | widget v2/v3 | F https://developers.google.com/recaptcha/docs/display | "https://www.google.com/recaptcha/api.js" |
| rc-002 | Google reCAPTCHA | script `www.google.com/recaptcha/enterprise.js` | widget Enterprise | F https://docs.cloud.google.com/recaptcha/docs/instrument-web-pages | "https://www.google.com/recaptcha/enterprise.js?render=KEY_ID" |
| rc-003 | Google reCAPTCHA | campo `g-recaptcha-response` | token | F https://developers.google.com/recaptcha/docs/display | "g-recaptcha-response POST parameter" |
| hc-001 | hCaptcha | script `js.hcaptcha.com/1/api.js` | widget | F https://docs.hcaptcha.com/ | "https://js.hcaptcha.com/1/api.js" |
| hc-002 | hCaptcha | campo `h-captcha-response` | token | F (mesma) | "adds an `h-captcha-response` token to the form submission" |
| f5-001 | F5 | caminho `/TSPD/` | proteção (referência sozinha não bloqueia) | P `core/src/assess.rs` (regras `marker("/TSPD/")`) e `docs/05-caso-referencia-detran.md` (captura do caso de referência) | "Separar proteção (/TSPD/, cookies TS*) da aplicação" |

Fixtures sintéticas (loopback) que **imitam** cada sinal acima para os testes
são rotuladas como tal (`synthetic`): elas provam o detector, não a existência
da proteção em nenhum site real.

### 6.2 Fora da tabela (fonte não confirmada)

Não entram até haver fonte do fornecedor ou captura própria autorizada:
Kasada (`x-kpsdk-ct`, `x-kpsdk-cd`, `x-kpsdk-v`, `ips.js`: só fontes de
terceiros que vendem contorno); Imperva `reese84`, `X-Iinfo`, `nlbi_*`; Akamai
`ak_bmsc` (fontes divergem sobre o dono do cookie); hosts de coletor
PerimeterX/HUMAN (`*.px-cdn.net`, `client.perimeterx.net`: não confirmados);
Cloudflare `/cdn-cgi/challenge-platform/` e `server: cloudflare` (não aparecem
na documentação consultada); `challenge.js` do AWS WAF (o host é por cliente);
HUMAN/PerimeterX com `_px3` isolado já está coberto por hm-001.

## 7. Interface com a Core

Combinada só a interface; a Core não precisa mudar o modelo:

1. `site_profile` consome `SessionV1` + `&dyn BodySource` (já existentes,
   `core/src/model`, `core/src/search.rs`) e `core::flow::value_origins`.
2. Os ids de evidência são os de `LogicalRequest.id`/`Attempt.id`.
3. A redação de valores segue a política da Core (padrão redigido).
4. Pedido à Core: expor `site_profile` como ferramenta de leitura em
   `docs/16-mcp-contrato.md` (`site_profile(session_id, target_request_id?)`),
   chamando `scrapelens_recon::site_profile`. A Captura entrega a função; o
   registro da ferramenta no servidor MCP é da Core/servidor.

## 8. Testes e critérios de aceite

Só loopback e fixtures sintéticas; nada de site real de terceiros.

- Unitários (`capture.rs`): `Allowlist` (curingas, portas, IP literal,
  userinfo, esquemas, listas largas), regras do resolvedor, `start` sem
  allowlist, classes de efeito.
- `recon/`: um teste por assinatura entregue (sessão sintética em memória),
  regra "marcador sozinho não bloqueia", recomendação nos quatro valores,
  redação, sessões parciais.
- Vivos (`#[ignore]`, Chrome headless, servidor loopback do próprio teste):
  `live_allowlist_cycle` (`navigate` permitido/recusado, subrecurso de host não
  listado e IP literal em `blockedHosts`, outra porta em `violations`,
  encerramento gracioso com NetLog completo), `second_cdp_client_cooperative` e
  `second_cdp_client_never_resumes`, `agent_first_action_is_captured`, e a cadeia captura → importação →
  `site_profile` (`recon/scripts/live_e2e.sh`: três servidores em loopback que
  imitam sinais documentados da Cloudflare: site comum, desafio sem solução,
  desafio resolvido no navegador).

## 9. Resultados e decisões abertas

Placar (2026-10-31, macOS arm64, Chrome 156.0.8078.74), depois da extração da
crate `capture/`, do portão do CDP exposto e da correção dos achados da
revisão de segurança (M2, M3, R1 a R4):

| Suíte | Resultado |
|---|---|
| `capture/` `cargo test` | 53 passed, 8 ignored (vivos); `clippy --all-targets -D warnings` limpo; `cargo tree`: só `scrapelens-core`, `serde`, `serde_json`, `tungstenite` e `libc` (0 `tauri`) |
| `capture/` vivos (`--ignored`, Chrome headless) | `live_allowlist_cycle`, `live_port_gap_is_reported_on_all_paths` (os 8 caminhos do PoC), `live_planted_symlinks_are_not_followed` (PoC de symlink), `live_netlog_swap_race_does_not_write_through_a_symlink` (R3), `live_swapped_session_dir_fails_the_stop_without_touching_outside` (A4-B5, A6-B5), `live_any_write_failure_rescues_the_capture_files` (A5-B2), `live_inherited_fds_do_not_leak_into_chrome` (R9), `live_navigate_honours_its_timeout_when_chrome_is_frozen` (R12), `live_oversized_pipe_message_marks_the_capture_incomplete` e `live_oversized_websocket_message_marks_the_capture_incomplete` (A3-B2, A4-B2), `live_pipe_opens_no_port_and_exposed_port_is_loopback_only`, `second_cdp_client_*`, `agent_first_action_is_captured`: 8/8 passam; `live_recon_scenarios` só roda com `SL_RECON_E2E_DIR` (é o passo do `live_e2e.sh`) |
| `recon/` `cargo test` | 26 passed (tabela = §6.1, uma fixture por assinatura, confiança, recomendação nos 4 valores, redação, ordem no tempo, R1 a R4); clippy limpo |
| `recon/scripts/live_e2e.sh` | 3/3: site comum → `chrome-normal-basta`; desafio sem solução → `candidato-a-cloakbrowser` (alta); desafio resolvido → `precisa-de-priming` (alta) |
| `src-tauri` `cargo test --lib` | 31 passed, 8 ignored; clippy limpo (adaptador fino do App) |
| `tests/aceite/check_multi_target.py` (captura comum, via `live_bodies_cycle` do App) | OK: 16/16 NetLog, ≥15/16 CDP |

Achados que mudaram o contrato: (1) o resolvedor do Chrome 156 **também nega IP
literal** (§2.2); (2) a lacuna real é a **porta**; (3) `session.requests` não é
cronológica (§5.2); (4) cookie de presença reutilizado não é priming (§5.3);
(5) a retomada do alvo por qualquer cliente libera o alvo (§3.5).

Limites desta entrega: as sessões do `live_e2e` vêm de servidores que **imitam**
os sinais; elas provam o detector, não a presença de proteção em site algum.
Nenhum site real de terceiros foi acessado: os servidores são loopback e o script de terceiro do cenário "desafio sem solução" aponta para um host fictício (`turnstile.blocked.invalid.test`), que a allowlist nega. As assinaturas de fornecedor vêm de
documentação lida em 2026-10-31; os fornecedores mudam sinais sem aviso. O
`site_profile` ainda não está registrado como ferramenta do servidor MCP (é da
Core/servidor), e o encadeamento `start_capture`→`navigate`→`stop_capture` ainda
não tem o servidor MCP que guarda o `capture_id` e faz a confirmação.

Perguntas ao líder, com a recomendação da Captura:

1. **Allowlist estrita vs. terceiros** (§2.2): manter estrita com 2 passadas
   (`terceiro-bloqueado` indica o que liberar).
2. **`act`** fora desta onda (§1): manter assim; o agente age pela porta CDP.
3. **`indeterminado`** como quarto valor da recomendação: aceitar.
4. **Crate novo `recon/`** fora de `src-tauri` e `core`: aceitar (testes rápidos,
   reaproveitável pelo servidor MCP sem puxar o Tauri).
5. **Quem guarda o `capture_id` e confirma `start_capture`**: o servidor MCP
   (Core ou outro agente a definir); a Captura entrega `BrowserCapture`.
