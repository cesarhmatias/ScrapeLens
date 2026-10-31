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

Perfil dedicado e temporário (já é assim em `capture.rs`): nunca o perfil
pessoal; depuração só em `127.0.0.1`; encerra somente o processo que o
ScrapeLens iniciou (`ChromeProcess` + marcador de órfãos). Só Chrome estável
instalado (detectado por `chrome.rs` ou `binary_path` explícito). `--no-sandbox`
nunca é passado.

### 2.2 Allowlist obrigatória, em duas camadas

`start_capture` **sem `allowed_hosts` não vazio é erro** (`allowlist_required`).

| Camada | Mecanismo | O que cobre | O que não cobre |
|---|---|---|---|
| 1. Navegador | `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE h1, EXCLUDE h2…"` com `allowed_hosts` + `third_party_hosts` | qualquer host por nome **e IP literal** (medido: `127.0.0.1`, `127.1`, `2130706433` e `[::1]` falharam com `ERR_NAME_NOT_RESOLVED` no Chrome 156), em qualquer aba, iframe, worker ou cliente CDP, inclusive redirects | **a porta**: a regra conhece só o nome. Outra porta de um host permitido passa pelo resolvedor (medido: um subrecurso `localhost:OUTRA_PORTA` chegou ao segundo servidor) |
| 2. API | `navigate` recusa antes de enviar; mesma função de decisão (`Allowlist::permits_url`) | esquema, host (incl. IP literal), porta, userinfo (`http://permitido@outro/`) | navegação feita por script ou clique da página/agente |

Além disso, `stop_capture` traz `allowlist.violations`: toda requisição da
sessão cujo host/porta não está na lista e **não falhou na resolução** (hoje, na
prática, **porta diferente** de um host permitido; IP literal também, se uma
versão futura do Chrome deixar de cobri-lo). A lacuna é **declarada**: o que
passa por ela é reportado e vira aviso `capture.allowlist_violation` na própria
sessão, não bloqueado. A regra de porta (`host:porta`) só vale na camada 2 e no
relatório; as regras do resolvedor ignoram porta.

Regras de `allowed_hosts` e `third_party_hosts` (strings):
- nome exato (`exemplo.com`), curinga de subdomínio (`*.exemplo.com`, não casa
  `exemplo.com`), IPv4/IPv6 literal só se escrito de forma explícita; porta
  opcional (`exemplo.com:8443`; sem porta = qualquer porta do host);
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
fim; `start_capture` devolve `sensitive_notice` (texto fixo) que o servidor MCP
deve mostrar; **o agente nunca digita credenciais** (não há `act`; se o agente
usar o CDP exposto para digitar, o valor aparece no corpo POST capturado);
as ferramentas de leitura e `site_profile` **redigem por padrão** valores de
cookie e de cabeçalhos (nomes, URLs, status e tamanhos aparecem; valores viram
`[redigido, N bytes]`), com opt-in explícito pela Core.

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
`start_url_not_allowed`, `browser_start_failed` (inclui binário inexistente),
`session_dir`; `capture_already_running` é do servidor MCP.

`cdp` só aparece com `expose_cdp:true` e só depois do portão de §4.1 (a porta
existe sempre, em loopback, como já é hoje; `expose_cdp` controla apenas se o
endereço é entregue ao agente). `pageTargetId` é a aba da captura (a que
`navigate` usa): o agente anexa a ela.

### 3.2 `navigate`

```json
{ "url": "http://exemplo.local:8080/p", "wait": "load", "timeout_ms": 15000 }
```

Navega a **aba principal** da captura (`Page.navigate`). `wait`: `"load"`
(padrão; espera `Page.loadEventFired` ou o prazo) ou `"none"`. Saída
(`NavigateResult`): `{ "frameId", "loaderId", "loaded": true|false, "errorText": null|"net::ERR_…" }`.
Erros: `url_not_allowed` (com o motivo), `capture_stopped`, `navigate_failed`.
`loaded:false` não é erro (prazo ou navegação sem evento de carga).

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
gracioso, a sessão sai marcada incompleta (comportamento atual). A sessão
importada fica em `sessionDir`, com `capture.third_party_blocked` (informativo)
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
CaptureConfig { chrome, session_dir, start_url, headless, ignore_cert }
CaptureStatus { recording, events, chrome_pid, session_id, session_dir, started_at, page_url, last_error }
CaptureOutcome { session: Value, session_dir: PathBuf, notice: String }
run(config, status: Arc<Mutex<CaptureStatus>>, stop: Receiver<()>, ready: Sender<Result<(),String>>)
    -> Result<CaptureOutcome, String>
default_state_root() -> PathBuf          // marcadores de captura (órfãos)
cleanup_orphans(&Path) -> OrphanCleanup  // chamada pelo App na partida
chrome::{detect, normalize_binary_path, candidates, ChromeInfo}

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
portão forçado a fechar, `start` falha e nada é entregue). Limite: o endereço
da porta existe no `DevToolsActivePort` do perfil temporário (0700) desde o
lançamento; um processo local do mesmo usuário que o leia contorna o portão, e
isso está fora do modelo (qualquer processo do usuário já alcança o loopback).

## 5. `site_profile`

Crate independente `recon/` (`scrapelens-recon`, depende só de
`scrapelens-core`), com as assinaturas em **dados** (`recon/signatures.json`) e
testes sem rede. Entrada: uma sessão capturada (`SessionV1` + `BodySource`
para corpos HTML/JS) e opções. Saída (camelCase, como a Core):

```json
{
  "schema": "scrapelens.site-profile/1",
  "sessionId": "…",
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
                      "field": "cf-mitigated", "value": "challenge", "url": "…", "status": 403, "source": "netlog" } ],
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
| `alta` | assinatura de **fonte do fornecedor** que, pela própria documentação, indica ação de proteção na resposta (ex.: `cf-mitigated: challenge`; `x-amzn-waf-action: challenge|captcha` com 202/405; `x-datadomeresponse` ≠ 200; resposta 403 com `x-datadome`) |
| `media` | assinatura de fornecedor que mostra que o produto **está presente** (cookie, script, campo de formulário) sem prova de bloqueio; ou dois indícios independentes de fonte secundária |
| `baixa` | um único indício de fonte secundária (ex.: cookie `bm_sz`, `incap_ses_*`), ou presença só no corpo |

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
crate `capture/` e do portão do CDP exposto:

| Suíte | Resultado |
|---|---|
| `capture/` `cargo test` | 41 passed, 5 ignored (vivos); `clippy --all-targets -D warnings` limpo; `cargo tree`: 0 ocorrências de `tauri` |
| `Allowlist` (7 testes) | esquemas, userinfo, barra invertida, `%`, ponto final, IPv4 curto/decimal/hex/octal, curinga, porta, terceiros, regras do resolvedor, relatório |
| `BrowserCapture` + portão | `start` sem allowlist/larga/inválida/URL fora/binário inexistente; `initial_target_gate_*` (2 testes) |
| `capture/` vivos (`--ignored`, Chrome headless) | `live_allowlist_cycle`, `second_cdp_client_cooperative`, `second_cdp_client_never_resumes`, `agent_first_action_is_captured`: 4/4; mais `live_recon_scenarios` (usado pelo `live_e2e.sh`) |
| `recon/` `cargo test` | 23 passed (tabela = §6.1: 28 assinaturas com fonte, uma fixture sintética por assinatura, confiança, recomendação nos 4 valores, redação, ordem no tempo); clippy limpo |
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
