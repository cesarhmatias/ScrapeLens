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
| 1. Navegador | `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE h1, EXCLUDE h2…"` com `allowed_hosts` + `third_party_hosts` | qualquer host por nome, em qualquer aba, iframe, worker ou cliente CDP, inclusive redirects | **host por IP literal** (a regra só atua em resolução de nome) |
| 2. API | `navigate` recusa antes de enviar; mesma função de decisão (`Allowlist::permits_url`) | esquema, host (incl. IP literal), porta, userinfo (`http://permitido@outro/`) | navegação feita por script ou clique da página/agente |

Além disso, `stop_capture` traz `allowlist.violations`: toda requisição da
sessão cujo host não está na lista e **não falhou na resolução** (exemplo:
IP literal). Lacuna conhecida e declarada: um IP literal alcançado por redirect
não é bloqueado, só **reportado**.

Regras de `allowed_hosts` e `third_party_hosts` (strings):
- nome exato (`exemplo.com`), curinga de subdomínio (`*.exemplo.com`, não casa
  `exemplo.com`), IPv4/IPv6 literal só se escrito de forma explícita; porta
  opcional (`exemplo.com:8443`; sem porta = qualquer porta do host);
- sem esquema, sem caminho; maiúsculas normalizadas; ponto final removido;
  punycode comparado em ASCII; `*` sozinho, `*.com`/sufixo público e lista
  vazia são rejeitados (`allowlist_too_broad`);
- só `http` e `https` navegam; `file:`, `data:`, `javascript:`, `chrome:`,
  `blob:`, `about:` (exceto `about:blank`) são recusados.

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

Resposta:

```json
{
  "capture_id": "cap-…",
  "session_dir": "/…/session",
  "chrome_pid": 1234,
  "browser": { "path": "…", "version": "156.0.…" },
  "allowlist": { "allowed_hosts": [], "third_party_hosts": [], "resolver_rules": "MAP * ~NOTFOUND, EXCLUDE …" },
  "cdp": null | { "http": "http://127.0.0.1:PORT", "browser_ws": "ws://127.0.0.1:PORT/devtools/browser/…" },
  "sensitive_notice": "…",
  "warnings": []
}
```

Erros: `allowlist_required`, `allowlist_too_broad`, `start_url_not_allowed`,
`browser_not_found`, `capture_already_running`, `browser_start_failed`.

`cdp` só aparece com `expose_cdp:true` (a porta existe sempre, em loopback, como
já é hoje; `expose_cdp` controla apenas se o endereço é entregue ao agente).

### 3.2 `navigate`

```json
{ "capture_id": "…", "url": "http://exemplo.local:8080/p", "wait": "load", "timeout_ms": 15000 }
```

Navega a **aba principal** da captura (`Page.navigate`). `wait`: `"load"`
(padrão; espera `Page.loadEventFired` ou o prazo) ou `"none"`. Resposta:
`{ "frame_id", "loader_id", "loaded": true|false, "error_text": null|"net::ERR_…" }`.
Erros: `url_not_allowed` (com o motivo), `capture_not_found`,
`capture_stopped`, `navigate_failed`. `loaded:false` não é erro (prazo).

### 3.3 `capture_status`

`{ "capture_id" } → { "recording": bool, "events": n, "page_url": "…", "last_error": null|"…" }` (reuso de `CaptureStatus`).

### 3.4 `stop_capture`

`{ "capture_id" } →`

```json
{
  "session_dir": "…",
  "requests": 31,
  "netlog": "complete" | "repaired" | "unusable",
  "shutdown": { "graceful": true, "waited_ms": 812 },
  "allowlist": { "blocked_hosts": ["challenges.exemplo.net"], "violations": [] },
  "warnings": ["…"]
}
```

Encerramento gracioso (`Browser.close` + espera + NetLog fechado); se não for
gracioso, a sessão sai marcada incompleta (comportamento atual). Idempotente.
A sessão importada fica em `session_dir` para as ferramentas da Core
(`list_sessions`/`import_capture`).

### 3.5 Segundo cliente CDP (a medir, não assumido)

Com `expose_cdp:true`, o agente conectará seu próprio cliente ao mesmo Chrome. O
nosso dedupe por `targetId` só vale para a nossa conexão. **Não se sabe** se dois
clientes com `Target.setAutoAttach {waitForDebuggerOnStart:true}` coexistem
(quem retoma o alvo; alvo pausado por um cliente que nunca retoma). Teste
ignorado em loopback (`second_cdp_client_*`, §8) mede os cenários: (A) segundo
cliente cooperativo, (B) segundo cliente com `waitForDebuggerOnStart` que nunca
retoma. Resultado entra na seção 9 deste documento depois da medição.

## 4. API Rust (para o servidor MCP)

Em `src-tauri/src/capture.rs`, sem alterar `run`, `CaptureConfig` nem
`CaptureStatus` (usados pelo App):

```text
pub struct Allowlist                      // new(allowed, third_party) -> Result<_, AllowlistError>
  permits_url(&str) -> Result<Url, UrlDenied>
  host_allowed(&str) -> bool
  resolver_rules() -> String
pub struct BrowserCaptureConfig { chrome, session_dir, start_url, headless, allowlist, expose_cdp }
pub struct BrowserCapture
  start(config) -> Result<(BrowserCapture, StartInfo), String>
  navigate(&self, url, wait, timeout) -> Result<NavigateResult, NavigateError>
  status(&self) -> CaptureStatus
  stop(self) -> Result<StopReport, String>
```

A thread de captura continua dona do soquete CDP; `navigate` e `stop` são
mensagens num canal consumido pelo laço de gravação (latência ≤ ~250 ms).

## 5. `site_profile`

Crate independente `recon/` (`scrapelens-recon`, depende só de
`scrapelens-core`), com as assinaturas em **dados** (`recon/signatures.json`) e
testes sem rede. Entrada: uma sessão capturada (`SessionV1` + `BodySource`
para corpos HTML/JS) e opções. Saída:

```json
{
  "schema": "scrapelens.site-profile/1",
  "session_id": "…",
  "sample": { "requests": 31, "documents": 3, "app_requests": 12, "partial": false },
  "findings": [
    {
      "id": "F001",
      "category": "protecao" | "bloqueio" | "captcha" | "cookie" | "token" | "protocolo" | "terceiro-bloqueado",
      "vendor": "cloudflare" | null,
      "kind": "cookie" | "response-header" | "request-header" | "script-host" | "form-field" | "path" | "status" | "protocol" | "token-origin" | "blocked-host",
      "signature_id": "cf-005" | null,
      "summary": "texto PT-BR",
      "confidence": "alta" | "media" | "baixa",
      "occurrences": 3,
      "evidence": [ { "request_id": "r0004", "attempt_id": "r0004.a1", "scope": "response_header", "field": "cf-mitigated", "value": "challenge", "url": "…", "status": 403, "source": "cdp|netlog" } ],
      "source": { "kind": "fornecedor" | "secundaria" | "projeto", "url": "…" }
    }
  ],
  "recommendation": {
    "value": "chrome-normal-basta" | "precisa-de-priming" | "candidato-a-cloakbrowser" | "indeterminado",
    "confidence": "alta" | "media" | "baixa",
    "reasons": ["…"],
    "limits": ["…"]
  },
  "warnings": []
}
```

- `evidence[].request_id`/`attempt_id` são os ids da Core (`LogicalRequest.id`,
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
  e `Cookie` com o mesmo nome em N+k): "cookie de sessão/guarda **observado**".
  "Obrigatório" **não** é afirmável por uma captura (exige remover e testar,
  `validate_run`): o achado diz isso em `limits`.
- **Tokens dinâmicos e origem**: para requisições da aplicação, usa
  `flow::value_origins` (Core) e relata valores de cabeçalho/cookie/corpo com
  origem `strong`/`possible` em resposta anterior; nada é re-derivado aqui.
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
3. `precisa-de-priming`: nada barrou o Chrome, mas há valores obrigatórios
   gerados pelo servidor/proteção que a aplicação reenvia (`token-origin`
   `strong`, ou cookie de proteção definido por uma requisição e enviado nas
   seguintes), ou um desafio foi resolvido no próprio navegador (cookie de
   liberação depois de resposta de desafio, ex.: `cf_clearance`).
4. `chrome-normal-basta`: documento principal 2xx, nenhum bloqueio nas rotas da
   aplicação e nenhum token de origem forte. Proteção presente passiva
   (cookie/script) não muda isso, mas aparece nos achados.

Limites sempre declarados em `recommendation.limits`: amostra (uma navegação),
site visto só com a allowlist usada, ausência de interação humana, e que
"bloqueado" é sobre esta captura.

## 6. Assinaturas (fonte obrigatória)

Regra: **só entra na tabela entregue assinatura com fonte consultada**
(documentação do fornecedor, ou fonte secundária citável, ou fixture do
projeto). Sem fonte confirmada: fora, listada em §6.2. Fontes consultadas em
2026-10-31 (leitura de documentação pública; nenhum site de terceiro foi
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
  captura com allowlist (`navigate` permitido/recusado, subrecurso de host não
  listado vira `blocked_hosts`, IP literal vira `violations`), encerramento
  gracioso com NetLog fechado, cadeia completa
  captura → importação → `site_profile` contra um servidor que imita cada
  sinal; `second_cdp_client_cooperative` e `second_cdp_client_never_resumes`.

## 9. Resultados e decisões abertas

(Preenchido depois da implementação: placar dos testes, comportamento de dois
clientes CDP, lacunas.)

Perguntas ao líder, com a recomendação da Captura:

1. **Allowlist estrita vs. terceiros** (§2.2): manter estrita com 2 passadas.
2. **`act`** fora desta onda (§1): manter assim.
3. **`indeterminado`** como quarto valor da recomendação: aceitar.
4. **Crate novo `recon/`** fora de `src-tauri` e `core`: aceitar (testes rápidos,
   reaproveitável pelo servidor MCP sem puxar o Tauri).
