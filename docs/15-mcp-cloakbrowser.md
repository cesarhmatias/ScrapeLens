# Rodada 11 — agente de IA + CloakBrowser + ScrapeLens (MCP)

Data: 2026-10-31. Dono: líder. Este documento começa pela viabilidade do
navegador; o desenho do MCP entra depois, em seção própria.

## Viabilidade CloakBrowser (fase A)

Autora: Captura. Método: **só leitura**. Clone raso de
`https://github.com/CloakHQ/CloakBrowser` em `/tmp/cloak-study/repo`,
commit `b860957` (2026-10-31, wrapper 0.6.5). Nenhum script do repositório foi
executado, nenhum binário baixado ou executado, nada instalado. Os únicos
acessos externos foram o clone e leituras de metadados de releases pela API do
GitHub (`gh api .../releases`, mais `SHA256SUMS` e `SHA256SUMS.sig` do release
`chromium-v145.0.7632.109.2`, que são arquivos de texto pequenos). O repositório
é tratado como dado não confiável; as citações abaixo são `arquivo:linha` do
clone acima. **O binário é fechado: o que o repositório afirma sobre ele é
alegação do fornecedor, e só a fase B mede.**

### Veredito

| Pergunta | Resposta da fase A | Confiança |
|---|---|---|
| Dá para lançar o binário com as nossas flags e conectar o nosso CDP? | Provavelmente sim: o `cloakserve` do próprio projeto lança o binário direto com `--remote-debugging-port`, `--remote-debugging-address=127.0.0.1` e `--user-data-dir` | média; `--log-net-log` não aparece em lugar nenhum do repositório |
| O stealth exige "sem CDP"? | Não há indício disso: todo o produto é desenhado com CDP conectado (Playwright). Mas o próprio README admite que **certo tráfego CDP é detectável** | média; o que o **nosso** perfil de CDP provoca só se mede |
| Dá para usar de graça no macOS arm64 com o benefício anunciado? | **Não de graça e sem conta.** O build sem chave é Chromium 145 com 26 patches; o build anunciado (155/156, 87 patches) exige chave (grátis com login no GitHub, 1 sessão, ou paga) | alta |
| Dá para empacotar no ScrapeLens? | **Não.** A licença do binário proíbe redistribuir/embutir | alta |

Conclusão: viável como **navegador opcional, instalado pelo usuário**, a medir na
fase B antes de qualquer integração. Nada do que li impede o NetLog nem o CDP;
nada prova que o CDP completo do ScrapeLens preserva o stealth.

### 1. O que é e a licença

- **É um Chromium com patches em C++, distribuído como binário fechado, mais um
  wrapper aberto.** README.md:21-22 ("A real Chromium binary with fingerprints
  modified at the C++ source level"); README.md:39 ("87 source-level C++
  patches"); README.md:280-288 (o wrapper baixa o binário e inicia
  Playwright/Puppeteer com ele e com os argumentos de stealth).
- **Base:** Chromium + componentes do ungoogled-chromium (BINARY-LICENSE.md:15 e
  :142). Não é extensão nem injeção de JavaScript (README.md:288-289).
- **Partes do repositório:** wrapper Python (`cloakbrowser/`), JS
  (`js/src/`), .NET (`dotnet/`), `bin/cloakserve` (multiplexador CDP em
  Python), `bin/cloaktest`, Dockerfile. Dependências Python: `playwright`,
  `httpx`, `cryptography` (pyproject.toml, bloco `dependencies`).
- **Licenças em dois níveis.**
  - Wrapper: **MIT** (LICENSE; pyproject `license = "MIT"`).
  - Binário: **proprietário, "all rights reserved"**, `BINARY-LICENSE.md` v1.3
    (jul/2026). Pontos que afetam o ScrapeLens:
    - proíbe redistribuir, revender, empacotar, modificar e fazer engenharia
      reversa (BINARY-LICENSE.md:69-72);
    - uso interno de scraping/automação é permitido sem licença OEM
      (BINARY-LICENSE.md:79-81), mas **licença OEM/SaaS é exigida** se o binário
      for embutido, "exposto por API" ou der a terceiros controle sobre o
      navegador (BINARY-LICENSE.md:93-97);
    - listar o CloakBrowser como dependência não é redistribuição, porque o
      usuário baixa o binário dos canais oficiais (BINARY-LICENSE.md:91);
    - o build mais novo exige assinatura (BINARY-LICENSE.md:25);
    - usos proibidos: acesso não autorizado a sistemas financeiros, de saúde ou
      governamentais, força bruta, criação automática de contas, fraude,
      contornar autenticação em sistema que não é seu (BINARY-LICENSE.md:113-122).
  - Consequência de produto: o ScrapeLens é open source, então **só pode
    apontar para um binário que o próprio usuário instalou** (como já fazemos com
    o Chrome). Um MCP que ofereça o navegador a terceiros cai na cláusula OEM/SaaS.
    Para o nosso uso (sessões sintéticas ou de sistemas próprios/autorizados) a
    cláusula de acesso não autorizado é compatível, mas fica registrada.

### 2. Plataformas e builds para macOS arm64

README.md:850-858 (tabela "Platforms") e `cloakbrowser/config.py:20-31`:

| | Sem chave | Com chave (grátis via login no GitHub, ou paga) |
|---|---|---|
| macOS arm64 | **Chromium 145.0.7632.109.2, 26 patches** | **Chromium 155 (README.md:155, 87 patches); o README diz que o build grátis "latest" já é o 156 (README.md:189, :219)** |

- Release sem chave, macOS arm64: tag `chromium-v145.0.7632.109.2` (2026-03-04),
  `cloakbrowser-darwin-arm64.tar.gz`, **147.384.149 bytes**, SHA-256
  `505582aa1bd3971c577f70e0cbbe016431702bdb693529abfd943b5bd9120c1c` (do
  `SHA256SUMS` publicado no release; consultado, não baixado).
- Os releases Pro no GitHub só têm `SHA256SUMS`/`.sig`; o binário Pro sai de
  `https://cloakbrowser.dev/api/download/<versão>` com a chave
  (`cloakbrowser/download.py:540-560`).
- O build sem chave está **~11 versões major atrás** do Chrome estável desta
  máquina (156.0.8078.74). Um binário fechado sem correções de segurança por
  meses é risco, e uma versão antiga é por si só um sinal para anti-bot. Logo o
  teste sem chave serve para **viabilidade técnica** (flags, CDP, NetLog), não
  para medir o benefício de stealth anunciado.
- **Assinatura do macOS:** "ad-hoc signed"; o Gatekeeper bloqueia a primeira
  execução (README.md:860). O wrapper contorna isso com `xattr -cr` sobre o
  diretório extraído (`cloakbrowser/download.py:1045-1056`). Não faremos
  isso. Arquivos baixados com `curl`/`gh` não recebem o atributo de quarentena e
  rodam por linha de comando sem prompt.
- O app fica em `~/.cloakbrowser/chromium-<versão>/Chromium.app/Contents/MacOS/Chromium`
  (`cloakbrowser/config.py:280-286`), com `CLOAKBROWSER_BINARY_PATH` para
  apontar um binário próprio (`config.py:414-419`).

### 3. Como é lançado; aceita as nossas flags?

- **No wrapper:** Playwright lança o executável (`executable_path=binary_path`,
  `cloakbrowser/browser.py:395`, `:530`, `:697`) com `ignore_default_args`
  = `--enable-automation` e `--enable-unsafe-swiftshader`
  (`cloakbrowser/config.py:52`) e estes argumentos de stealth
  (`config.py:155-177`): **`--no-sandbox`**, `--fingerprint=<semente>`,
  `--fingerprint-platform=macos` (no macOS). O README menciona outros:
  `--fingerprint-timezone`, `--fingerprint-locale`, `--fingerprint-webrtc-ip`,
  `--proxy-server` (`browser.py:1117-1500`).
  - O Playwright (comportamento do Playwright, não do repositório) fala com o
    navegador por **pipe**, sem porta: não há `--remote-debugging-port` nesse
    caminho. Para o ScrapeLens precisamos lançar o binário nós mesmos.
- **Lançamento direto com porta, no próprio projeto:** `bin/cloakserve:380-397`
  faz `subprocess.Popen([binário] + args base + stealth + ["--remote-debugging-port=<p>",
  "--remote-debugging-address=127.0.0.1", "--user-data-dir=<dir>"])`. Os args
  base (`bin/cloakserve:54-63`) incluem `--disable-background-networking`,
  `--disable-extensions`, `--disable-popup-blocking`, `--metrics-recording-only`.
  O README documenta o mesmo caminho: "launch com `--remote-debugging-port=9242`
  e conecte o framework" (README.md:816-821). O CHANGELOG registra patch do
  binário para `--remote-debugging-address` (CHANGELOG.md, entradas `[binary]`
  sobre `cloakserve`).
- **Flags do ScrapeLens** (`src-tauri/src/capture.rs`, `spawn_chrome`):
  - `--remote-debugging-port=0`, `--remote-debugging-address=127.0.0.1`,
    `--user-data-dir`, `--disable-component-update`,
    `--disable-background-networking` e `--no-first-run`: padrão do Chromium, sem
    conflito visível com o que o `cloakserve` já passa.
  - **`--log-net-log` e `--net-log-capture-mode=Everything`: não há nenhuma
    menção no repositório.** O binário é Chromium e o NetLog fica no código de
    rede, que não aparece em nenhum patch descrito; mas **não está provado**. A
    fase B precisa conferir que o arquivo é gerado e está completo (bytes de
    socket, `Everything`).
  - **Conflito:** o nosso `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE
    127.0.0.1, EXCLUDE localhost` bloqueia todos os hosts fora do loopback.
    Isso quebra qualquer teste contra sites reais e **bloquearia a validação de
    licença** do build com chave (item 7). A integração real precisa de um modo
    de captura sem essa regra.
  - **`--no-sandbox` nos argumentos padrão do wrapper (config.py:165),
    inclusive no macOS.** Não devemos repeti-lo: sem o sandbox do Chromium, uma
    falha no renderizador de uma página hostil comprometeria a conta do
    usuário. A fase B verifica se o binário funciona sem esse flag no macOS
    (o sandbox do macOS é seatbelt, não precisa de setuid).

### 4. O CDP é completo?

Nada no repositório remove ou restringe domínios CDP. Evidências:

- O produto inteiro roda em cima de CDP: Playwright, `Page.createIsolatedWorld`,
  `Input.dispatchKeyEvent`, `DOM.getFrameOwner`, `Page.getFrameTree`
  (`cloakbrowser/human/world.py:1-12`, `human/keyboard.py:3-8`).
- `connect_over_cdp` com navegador lançado por nós é documentado (README.md:816-821,
  :901-935); `cloakserve` encaminha o WebSocket CDP e reescreve só a URL
  (`README.md:928-946`).
- O CHANGELOG lista "CDP input stealth" (4 patches de eventos de entrada) e
  "CDP detection vector audit and hardening" (CHANGELOG.md, entradas `[binary]`
  de 0.3.x); são correções de sinais, não remoção de domínios.
- Sobre `Network.*` (incl. `ExtraInfo`), `Network.getResponseBody`,
  `Target.setAutoAttach {flatten, waitForDebuggerOnStart}` e
  `Runtime.runIfWaitingForDebugger`: **nenhuma evidência a favor nem contra**, o
  repositório não testa esses métodos. O que há é indireto: o Playwright usa
  `Target.setAutoAttach` com `flatten` e `waitForDebuggerOnStart` e o
  `humanize` mapeia frames OOPIF por sessão (`human/world.py:432-475`), o que
  só funciona se o auto-attach de filhos funcionar. É a base de Chromium 145/155,
  mas **o ScrapeLens precisa da bateria completa**: `check_multi_target` (16/16
  marcadores), corpos POST e ordem de headers.
- **Diferenças que podem afetar fidelidade** (README.md:166 e CHANGELOG.md,
  entradas `[binary]` de proxy): com **proxy ativo**, o binário "zera" os tempos
  de DNS/conexão/SSL, remove cabeçalhos de cache do proxy e o vazamento de
  `Proxy-Connection`, e normaliza metadados de rede. Sem proxy não há indício de
  alteração de tempos ou cabeçalhos, mas **ninguém comparou a ordem e a
  capitalização de headers do binário com a do Chrome**: é medida da fase B
  (HTTP/1.1, h2, h3 contra o `experiments/` que já temos). O README ainda afirma
  TLS/ja3/ja4/akamai "idênticos ao Chrome" (README.md:236), o que, se verdadeiro,
  indica que a pilha de rede não foi alterada.

### 5. O "stealth" depende de não haver CDP? **Crítico**

Resposta curta: **o repositório não diz que o stealth exige a ausência de CDP,
e não esconde o CDP; ao contrário, diz que a proteção vale com o CDP do
Playwright conectado. Mas admite que o tráfego CDP pode ser detectado, e a
nossa conexão é bem mais intrusiva que a de um script Playwright típico.**

A favor de "CDP conectado funciona":

- Tabela de testes: "CDP detection | Detected | **Not detected** |
  `isAutomatedWithCDP: false`", medindo o Playwright conectado (README.md:235).
- A abordagem declarada é patch no binário, não dependência de ausência de
  protocolo: "automation signals, CDP input behavior" (README.md:39, :288).

Contra, ou sem prova:

- **README.md:1265-1300** (reCAPTCHA): `page.wait_for_timeout()` e
  `page.evaluate()` "enviam tráfego CDP que o reCAPTCHA detecta"; Puppeteer
  "vaza sinais de automação do CDP" (README.md:533); a recomendação é minimizar
  chamadas CDP antes do desafio. Ou seja, **o stealth degrada conforme o que o
  cliente CDP faz**.
- O teste do projeto para "CDP não detectado" é fraco: só procura chaves
  `cdc_*`/`__webdriver` em `window` (`tests/test_stealth.py:65-80`). Não há
  teste do vetor clássico de `Runtime.enable` (erro com getter de `stack` /
  serialização de `console.*`), nem de `Network.enable`, `Page.enable` ou
  auto-attach com `waitForDebuggerOnStart`.
- Perfil do ScrapeLens, que difere do script típico: em cada alvo enviamos
  `Network.enable`, `Page.enable`, **`Runtime.enable`**,
  `Target.setAutoAttach {flatten, waitForDebuggerOnStart}` e
  `Runtime.runIfWaitingForDebugger` (`capture.rs`, `setup_attached_target`),
  mais `Target.setDiscoverTargets` na raiz, **em todos os alvos incluindo
  workers e iframes**. `Runtime.enable` e a pausa por depurador são sinais
  clássicos. O Playwright também envia `Runtime.enable`, e o fornecedor afirma
  que passa; não há prova de que o resto do nosso perfil também passe.

Consequência para o desenho (só hipóteses a medir, em ordem de preferência):

1. **CDP reduzido** quando o alvo for protegido: `Network.enable` +
   `Target.setAutoAttach` apenas (sem `Runtime.enable`/`Page.enable`; o
   `Network.*` e os corpos não dependem deles). Ainda preserva eventos, corpos e
   `ExtraInfo`.
2. **CDP completo** se a medição mostrar que o binário o tolera.
3. **Só NetLog** (sem porta de depuração): preserva bytes e ordem de headers no
   nível de rede e a correlação por tempo, mas perde corpos pela via CDP,
   `ExtraInfo` por requisição e a atribuição por alvo (ver
   `docs/02-matriz-fidelidade.md`). Um agente de IA ainda precisa de **um canal
   de controle** do navegador; se ele usa CDP (Playwright/MCP), o CDP já estará
   conectado de qualquer forma, e a pergunta passa a ser só se o nosso segundo
   cliente soma sinais.
4. **Proxy**: fora do nosso escopo, que veda MITM e certificados próprios
   (`docs/01-decisoes.md`, linha 9). Um proxy que não decifra TLS não vê cabeçalhos HTTPS.
   Só o líder pode mudar essa decisão.

### 6. Versão, atualização, telemetria e riscos

- **Cadência (GitHub Releases):** o Pro sai semanalmente, cada release com sufixo
  incremental. Observado: `155.0.8059.39.2` (27/out), `155.0.8059.39.1` (20/out),
  `154.0.8037.57.2` (13/out), `154.0.8037.57.1` (6/out), `152.0.7977.82.1`
  (23/set), `151.0.7922.108.6` (12/set). A linha sem chave (145 no macOS)
  está parada desde 04/03/2026.
- **Divergência de versões nos documentos do próprio repositório:** `config.py:23`
  deixa o padrão em 146, o macOS em 145; o README fala em 155 (Pro, 87 patches)
  e 156 (grátis com chave). Tratar todos os números como alegação até a fase B
  imprimir `--version` e a UA reais.
- **Download automático:** o wrapper baixa o binário no primeiro uso
  (README.md:127; `download.py:194-348`) e **atualiza em segundo plano**
  (thread daemon a cada hora: `download.py:1319-1330`), além de consultar o PyPI
  (`download.py:1256-1283`) e a API do GitHub (`download.py:1202-1222`).
  Desligável com `CLOAKBROWSER_AUTO_UPDATE=false`. Se não usarmos o wrapper,
  nada disso roda.
- **Verificação de integridade:** Ed25519 sobre `SHA256SUMS`, com a chave
  pública fixa em `config.py:42-44`
  (`MKFKwIhUcKWq5xTuNA0Ovg99njcDEcEJvmWYYhApvaU=`), verificação obrigatória e sem
  bypass no caminho oficial (README.md:292; `download.py:578-640`,
  `:758-800`). Bom: a fase B pode verificar assim, à mão, sem o wrapper.
- **Telemetria:** a licença do binário diz não haver telemetria, **exceto
  "validação de licença e contagem de sessões simultâneas"**
  (BINARY-LICENSE.md:140). Isso é tráfego de saída do próprio binário:
  `cloakbrowser.dev/api/license/validate` e `.../license/session/count`
  (`cloakbrowser/license.py:26-28`; a chave vai no POST: `license.py:404-409`),
  e o binário **sai com código 76-79 se a licença for negada ou o servidor não
  responder** (`license.py:102-123`). O build sem chave não deve ter essa
  checagem, mas **só o NetLog da fase B dirá**. Riscos para nós:
  - o NetLog da captura vai registrar esse tráfego do próprio navegador
    (ruído e dado do usuário: a chave) — precisa ser rotulado/filtrado como
    "tráfego do navegador, não do site";
  - o build com chave exige conta (login no GitHub para a chave grátis, dado
    pessoal) e limita sessões; a chave nunca pode ir para o repositório, para a
    sessão exportada nem para argumentos de linha de comando (o wrapper a passa
    por variável de ambiente, `license.py:299-349`).
- **Binário fechado em macOS, assinado ad-hoc, com sandbox desligado por
  padrão** (`--no-sandbox`), baixado de dois hosts (`cloakbrowser.dev` e
  GitHub). Mitigação: verificar assinatura do manifesto, rodar com perfil
  descartável, sem `--no-sandbox` se funcionar, e **sem rede** nos testes
  locais.
- **Risco de dependência:** o projeto tem ~1 semana de releases pesadas e nasceu
  em 22/02/2026; a faixa grátis para macOS não recebe o build atual. O ScrapeLens
  não deve depender dele: navegador **opcional**, com o Chrome como padrão.

### 7. Confirmação dos pontos de `docs/15a-mercado-mcp.md`

Complemento pedido pelo líder. Cada ponto da pesquisa de mercado foi conferido
no clone `b860957` (e, para as issues, na API pública do GitHub, só leitura). As
declarações de mantenedores abaixo são do **fornecedor**, não verificadas.

| Ponto da pesquisa | Veredito | Evidência |
|---|---|---|
| O README diz que comandos CDP vazam sinais que o reCAPTCHA detecta | **Confirmado, com escopo menor**: fala de `page.wait_for_timeout()`, de `page.evaluate()` antes do desafio e do Puppeteer, não de `Network.enable` ou auto-attach | README.md:533, :1265-1300; CHANGELOG.md:603 ("replace `page.wait_for_timeout()` … to avoid timing leak") |
| Build grátis no macOS = Chromium 145 | **Confirmado** (sem chave) | README.md:854-855; `config.py:28-29`; release `chromium-v145.0.7632.109.2` (04/03/2026) |
| Da v148 em diante, chave de licença | **Confirmado, com uma ressalva importante**: a chave **grátis** (login no GitHub, 1 sessão) entrega o build mais novo; só a **fixação de versão** é paga | CHANGELOG.md:227, :259, :264 ("Pro license required; v146 stays free"); README.md:189; `download.py:236-241` ("Free tier always gets the latest build"); issue #614 (resposta: fixar versão é recurso pago) |
| Validação em cloakbrowser.dev | **Confirmado** | `license.py:26-28`, `:404-409`; BINARY-LICENSE.md:140; saída 76-79 (`license.py:102-123`) |
| Checagem de atualização automática | **Confirmado**; desligável | `download.py:1319-1330` (thread por hora), `:1182-1200`, `:1256-1283`; `CLOAKBROWSER_AUTO_UPDATE=false` (README.md:648). Sem o wrapper não roda |
| Licença própria, sem redistribuição | **Confirmado** | BINARY-LICENSE.md:69-72, :93 |
| Assinatura ad-hoc no macOS | **Confirmado** | README.md:860 ("ad-hoc signed … Gatekeeper will block it"); o wrapper roda `xattr -cr` (`download.py:1045-1056`) |
| `--log-net-log` com captura de bytes funciona via args | **Não verificado, sem nenhuma evidência a favor ou contra**: nenhum arquivo do repositório contém `net-log`/`netlog` (busca sem resultado). O que existe é passagem de argumentos arbitrários: `build_args` repassa `args=` (`browser.py:1461-1466`) e o `cloakserve` os anexa à linha do binário (`bin/cloakserve:380-390`). É flag do Chromium e não há patch descrito na rede, então é provável, mas só a B1 prova | fase B, item B1.1 |
| Issues #575, #614, #598, #611, #602, #632 | ver tabela abaixo | API pública do GitHub, consultada em 31/10 |

Issues (todas abertas em 31/10; texto de mantenedor = alegação do fornecedor):

| # | Assunto | O que a issue e o mantenedor dizem | Impacto para o ScrapeLens |
|---|---|---|---|
| 575 | **Crash no macOS arm64** | Build `154.0.8037.57.1` (Pro, chave grátis): o renderizador cai em ~1,5 s em todas as páginas do Google Maps (caminho de GPU); `--disable-gpu` evita. Mantenedor (06/10): "bug no nosso build 154"; correção "no próximo release do macOS". O relato confirma que o wrapper passa `--no-sandbox --fingerprint=… --fingerprint-platform=macos` | O manifesto do macOS lista `155.0.8059.39.1` (20/10), mas o `…39.2` (27/10) saiu só para Linux. **Ninguém confirmou na issue que o 155 corrige.** A B1 deve incluir uma página pesada de GPU/WebGL, além do loopback |
| 614 | **Detecção** (Fingerprint.com: `ChromiumAutomation`) | Reproduzido em `155.0.8059.39.1`. Mantenedor: corrigido no `…39.3`, "sem release ainda, cerca de uma semana"; assinantes podem fixar; o grátis recebe automaticamente. Um usuário teve 404 ao pedir `…39.3` (22/10) | Detecção é corrida contínua e o grátis anda atrás do pago. O benefício anunciado tem prazo curto |
| 598 | **Detecção** (Outlook, GitHub, Facebook) | Era registro de contas. Mantenedor: "não é caso de uso suportado", proibido pela licença (criação automática de contas) | Nada técnico. Reforça que o uso fica restrito a alvos próprios ou autorizados (BINARY-LICENSE.md:113-122) |
| 611 | **Detecção** (Cloudflare) | Relato sem conteúdo (modelo vazio). Mantenedor pediu o fluxo "best-flow" com chave, proxy e canal `preview` | Sem evidência técnica |
| 602 | **Detecção** (pixelscan "Masking detected") | Mantenedor: acompanha o recurso de ruído (`--fingerprint-noise`); com `--fingerprint-noise=false` some; correção "no próximo Preview" (18/10). A flag está documentada (README.md:708; CHANGELOG.md:409) | O ruído de fingerprint muda canvas/WebGL/áudio, não rede. Para a captura convém `--fingerprint-noise=false` para não somar variáveis |
| 632 | **`Runtime.addBinding` não persiste após navegação** | Em Chrome for Testing 155 o binding continua após `reload`; no CloakBrowser (155 e 146) some. Mantenedor (29/10): "não é bug, é recurso … remove sinais de automação no nível do motor; **de propósito e não vai mudar**, porque manter hooks injetados por CDP entre navegações torna o navegador mais fácil de detectar". Contorno: adicionar de novo após cada navegação | **O CDP do binário diverge do Chrome por projeto.** O ScrapeLens não usa `Runtime.addBinding` (nenhuma ocorrência em `capture.rs`), mas isso prova que cada domínio que usamos (`Network.*`, `Target.*`, `Page.*`, corpos) precisa ser medido contra o Chrome, e que um agente/MCP que dependa de bindings quebra |

#### O que se perde ao capturar só pelo NetLog (passivo)

A hipótese da pesquisa é razoável **como modo para alvos protegidos**, com
duas ressalvas: (a) o próprio agente de IA já falará CDP com o navegador (é
assim que Playwright/MCP o dirige), então "sem CDP" só retira **o nosso**
cliente, não o canal de controle; (b) sem `Browser.close` o NetLog só é
finalizado se o Chrome encerrar de forma graciosa (o `cloakserve` usa SIGINT
por isso, CHANGELOG.md:17); capturas parciais já são marcadas incompletas.
Comparação, com base em `docs/02-matriz-fidelidade.md` e `docs/14`:

| Item | Com CDP (hoje) | Só NetLog |
|---|---|---|
| Ordem, caixa e duplicatas de headers | NetLog é a fonte oficial; ExtraInfo **não** preserva a ordem do fio (matriz, linhas 63-76 e 244) | **igual**: nada se perde |
| Alcance multi-alvo | CDP por `sessionId` (auto-attach recursivo), 16/16 | o NetLog vê o tráfego de todos os processos (`docs/14`, linha 8), mas **sem tipo de alvo, frame ou iniciador** |
| Corpos de requisição e resposta | `Network.getResponseBody` / `getRequestPostData` (`cdp-bodies.jsonl`) | **perdidos** no produto atual. Em tese os bytes de socket do modo `Everything` carregam o conteúdo, mas decodificar quadros h2/h3 e descompactar é trabalho novo, hoje fora do escopo |
| `requestId` e cadeia de redirecionamentos | presente | **ausente** (o evento do NetLog não traz o id do CDP, matriz linha 63); casar por URL, método e horário vira pista, não prova, e a ambiguidade aumenta |
| `ExtraInfo` (cookies associados/bloqueados, endereço de IP, `resourceIPAddressSpace`) | presente | **perdido** (parte vem no NetLog como cabeçalho de fio) |
| Tipo de recurso, `frameId`, `loaderId`, `initiator`, falhas com motivo | presente | motivo de rede existe no NetLog; o resto **perdido** |
| Service workers: página × worker | duas observações ligadas | só o que passa pela rede, sem atribuição |

Recomendação: o modo protegido deve ser **escalonado**, não binário: (1) só
NetLog quando o alvo não puder ser tocado; (2) CDP reduzido (`Network.enable` +
`Target.setAutoAttach`, sem `Runtime.enable` nem `Page.enable`) quando for
possível; (3) CDP completo no resto. A B1 decide em quais condições o binário
tolera cada nível.

## Fase B — proposta de medição (NÃO executada; depende de autorização do usuário)

A fase B executa **binário de terceiros** e baixa dados da internet; por isso
fica parada até autorização expressa. Tudo abaixo é local, descartável e reversível.

### B0. O que seria baixado (e só isto)

| # | Artefato | Origem | Tamanho | Verificação |
|---|---|---|---|---|
| 1 | `cloakbrowser-darwin-arm64.tar.gz` | `https://github.com/CloakHQ/cloakbrowser/releases/download/chromium-v145.0.7632.109.2/cloakbrowser-darwin-arm64.tar.gz` | 147.384.149 bytes | SHA-256 `505582aa…120c1c` conferido contra o `SHA256SUMS` do release; **assinatura Ed25519 do `SHA256SUMS.sig`** contra a chave de `config.py:42` (Python `cryptography` com `python3 -I`, ou `openssl` 3) |
| 2 | `SHA256SUMS` e `SHA256SUMS.sig` | mesmo release | 412 e 88 bytes | já lidos na fase A |

- Baixar com `gh release download` ou `curl`, **não** com `pip install
  cloakbrowser`/`npm install` (que traria o wrapper, o agendamento de
  atualização e o `xattr -cr`).
- Destino: pasta nova e vazia, fora do projeto (ex.:
  `/tmp/cloak-study/bin/`). Antes de extrair: `tar -tzf` para checar caminhos
  absolutos e `..`; depois `codesign -dv --verbose=4` e `spctl -a -vv` só para
  registrar a assinatura (nenhuma alteração de atributos).
- **Não** usar chave de licença na B1. Build 155/156 (o que de fato mostra o
  benefício) entra numa B2, que exige decisão do usuário sobre login no GitHub
  (dado pessoal) e sobre os termos do item 1.

### B1. O que seria executado

Sempre com `--user-data-dir` novo em `/tmp`, sem `--no-sandbox` na primeira
tentativa, `CLOAKBROWSER_AUTO_UPDATE=false` (irrelevante sem wrapper, mas
registrado), e **sem credenciais**. Cada execução do binário sob
`sandbox-exec` com rede apenas em loopback e escrita só em `/tmp/cloak-study`
(a ser validado; se o perfil de sandbox impedir o navegador, registrar e cair
para execução comum com o monitoramento do item 5):

1. **Sanidade e telemetria:** `Chromium --version`; abrir `about:blank` com
   `--log-net-log` e `--net-log-capture-mode=Everything`, sem rede externa,
   por 60 s. Entregar: o NetLog está completo? Há tentativa de saída (licença,
   atualização, telemetria)? Conferir com `nettop`/`lsof -i` em paralelo.
2. **`experiments/` de ordem de headers** (já existente) contra o binário, em
   HTTP/1.1, h2 e h3 locais: a ordem e a capitalização no fio são as do Chrome?
   Diferença = achado de fidelidade.
3. **`tests/aceite/check_multi_target.py`** com `CaptureConfig.chrome` apontando
   para o binário (hoje a captura aceita qualquer executável do tipo Chrome):
   16/16 NetLog, ≥15/16 CDP, tipos de alvo, corpos POST, service worker. Roda só
   em loopback, como o teste atual.
4. **Detecção de CDP, local e sem terceiros:** uma página sintética em
   `testserver/`-style (pedir às Testes) com as sondas conhecidas: `navigator.webdriver`,
   `window.chrome`, o getter de `stack` em `Error` + `console.debug` (sinal de
   `Runtime.enable`), duração de `debugger`, `Notification.permission`/plugins.
   Rodar a mesma página em **cinco condições**, cada uma com Chrome estável
   como controle:
   - A: sem CDP (só NetLog; `--remote-debugging-port` ausente);
   - B: CDP mínimo (`Network.enable` + `Target.setAutoAttach`);
   - C: CDP completo, como o ScrapeLens faz hoje;
   - D: C com `waitForDebuggerOnStart: false`;
   - E: Playwright puro (`connect_over_cdp`), só como referência de "o que o
     fornecedor testa".
   Saída: tabela sonda × condição × (CloakBrowser, Chrome).
5. **Contenção:** executar em conta/ambiente do usuário sem acesso a
   Keychain real (`--use-mock-keychain`, `--password-store=basic` como já
   passamos), sem as pastas do perfil pessoal, e encerrar só o PID iniciado,
   por `cleanup_orphans` se algo sobrar.

### B2. Opcional, só com autorização separada

- Detectores públicos de terceiros (sannysoft, incolumitas,
  deviceandbrowserinfo, browserscan) com e sem CDP, para comparar com a
  tabela do README. São **sites de terceiros recebendo tráfego do usuário**;
  leitura apenas, sem login, e sem o `--host-resolver-rules` do item 3.
- Build 155/156 com a chave grátis (login no GitHub), repetindo B1.
- Qualquer site real protegido (Cloudflare, reCAPTCHA): **fora de escopo**
  sem autorização do dono do site; a licença do binário proíbe uso não autorizado.

### B3. Critérios de decisão

| Resultado | Decisão sugerida |
|---|---|
| NetLog completo, CDP 16/16, headers iguais ao Chrome, sem sondas extras nas condições A–C | integrar como navegador opcional (CDP completo) |
| Tudo igual, mas a condição C acusa e B não acusa | integrar com **CDP reduzido** para o modo protegido |
| Só A passa | modo **somente NetLog** para esse navegador; avisar a perda de corpos/atribuição |
| Headers diferem do Chrome ou o NetLog sai incompleto | **não** usar como fonte de fidelidade; registrar na matriz como limite |
| Tráfego de saída não declarado do binário | não adotar sem decisão do usuário |

## Decisões e perguntas para o líder

1. **Escopo da B1:** autorizar o usuário a baixar o build 145 (147 MB) e executá-lo
   em contenção? Recomendo sim: é a única forma de saber se flags, NetLog e
   CDP funcionam, sem login nem chave.
2. **B2/build novo:** o benefício real só existe no 155/156, que exige chave
   (login no GitHub). Só o usuário decide isso. Recomendo adiar até a B1 passar.
3. **Proxy:** o pedido mencionou "NetLog ou um proxy". O escopo atual veda
   MITM. Manter? Recomendo manter: a fidelidade de headers HTTPS vem do NetLog.
4. **Bundling:** o ScrapeLens aponta para o binário do usuário (como com o Chrome)
   e nunca o embute; o MCP não deve ser oferecido a terceiros como serviço sem
   licença OEM. Recomendo registrar isso em `docs/01-decisoes.md`.
5. **Dois clientes CDP:** o agente de IA (Playwright/MCP) e o ScrapeLens vão
   precisar do mesmo navegador. Isso força `--remote-debugging-port` (o
   Playwright padrão usa pipe). O desenho do MCP precisa decidir quem lança o
   navegador (recomendo: o ScrapeLens lança e expõe a porta ao agente) e como
   evitar que ambos peçam `waitForDebuggerOnStart`.
