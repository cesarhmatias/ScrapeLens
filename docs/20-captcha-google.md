# 20. CAPTCHA do Google na captura do App: o que medimos

Rodada 13. **Só medição**: nenhum código de produção foi alterado. As flags
testadas abaixo foram aplicadas apenas num snapshot descartável fora do repositório.

## 1. Pergunta

No App, `Iniciar sessão` com `https://google.com.br` mostrava um CAPTCHA do Google.
Numa aba anônima do Brave, na mesma máquina e na mesma rede, não aparece. A
hipótese: a nossa instrumentação seria detectada (CDP, `Runtime.enable`, a pausa
`waitForDebuggerOnStart`), mais o perfil vazio e os argumentos de laboratório. Qual
peça, se alguma, causa o CAPTCHA?

## 2. Autorização e limites (cumpridos, com um desvio: §5)

O usuário autorizou carregar `https://www.google.com.br/` de verdade, só para isto:

- no máximo 2 rodadas de 4 condições (até 8 carregamentos), **só a página inicial**;
- pelo menos 60 s entre carregamentos; sem busca, sem login, sem resolver o CAPTCHA,
  sem outros sites;
- um perfil temporário novo por carregamento, Chrome com janela visível (sem
  `--headless`), sem o wrapper;
- PARAR e avisar se o Google mostrasse "tráfego incomum" ou bloqueasse o IP.

Foram feitos **8 carregamentos** do Google (duas rodadas de A, B, C, D), mais cargas
só em loopback para ler `navigator.webdriver`. Nenhuma busca, nenhum login. O
Google não mostrou `/sorry/`, 429 nem reCAPTCHA em nenhuma carga; a regra de
parada nunca disparou.

## 3. Método

Chrome 156 estável, macOS, NetLog ligado em todas as condições. Os argumentos do
launcher são os de `capture/src/lib.rs` `chrome_args` no modo `Open` (HEAD `3dda266`),
sem `--headless`.

| Cond. | O que é |
|---|---|
| **A** | Chrome **sem nenhum cliente CDP** (sem `--remote-debugging-*`), com **os mesmos argumentos do launcher** (incluindo os de laboratório). A URL vai na linha de comando |
| **B** | Como A, mas **sem os argumentos de laboratório**: só `--user-data-dir`, `--log-net-log`, **mais `--no-first-run --no-default-browser-check`** (ver desvio abaixo). A URL vai na linha de comando |
| **C** | **CDP reduzido** por pipe: `Target.setDiscoverTargets`, `Target.setAutoAttach` **sem** `waitForDebuggerOnStart`, `Target.createTarget about:blank`, `Network.enable` e `Target.setAutoAttach` (sem espera) na aba, `Page.navigate`. **Sem** `Page.enable`, **sem** `Runtime.enable`, sem `Network.setCacheDisabled`. Argumentos do launcher |
| **D** | A **captura completa de hoje** (`scrapelens_capture::run`, rede aberta): `Network.enable` + `Page.enable` + `Runtime.enable`, `setAutoAttach` com `waitForDebuggerOnStart`, `Network.setCacheDisabled`, corpos. Argumentos do launcher |

Desvio em B: o literal "só user-data-dir e NetLog" **não carrega a URL**. Sem
`--no-first-run`, o Chrome mostra o fluxo de boas-vindas e ignora a URL da linha de
comando (medido: nenhuma requisição à sonda local). As duas flags só afetam a
interface.

**Como cada resultado foi lido** (sem print e sem dados pessoais): do NetLog, só URL
sem consulta e status. CAPTCHA = alguma requisição para `/sorry/` ou status 429 ou
URL de `recaptcha`. Status da página principal = os status da requisição de
`https://www.google.com.br/` (a cadeia 301 → 200).
**`navigator.webdriver`** foi lido **sem `Runtime.evaluate`** e **sem tocar o
Google**: uma página local em loopback faz `fetch('/wd?webdriver='+navigator.webdriver)`,
carregada com os mesmos argumentos de cada condição (em D, pela captura completa).

## 4. Resultados

### 4.1 O que o Google fez (8 carregamentos)

| Rodada | Ordem | Cond. | Início | Página principal | `/sorry/` | 429 | reCAPTCHA | Requisições no NetLog |
|---:|---:|---|---|---|---|---|---|---:|
| 1 | 1º | A | 23:02:24 | 301 → 200 | não | não | não | 50 |
| 1 | 2º | B | 23:04:18 | 301 → 200 | não | não | não | 73 |
| 1 | 3º | C | 23:05:54 | 301, página renderizada (¹) | não | não | não | 59 |
| 1 | 4º | D | 23:07:32 | 301 → 200 | não | não | não | 56 |
| 2 | 1º | D | 23:08:16 | 301 → 200 | não | não | não | 55 |
| 2 | 2º | C | 23:10:04 | 301, página renderizada (¹) | não | não | não | 57 |
| 2 | 3º | B | 23:11:41 | 301 → 200 | não | não | não | 71 |
| 2 | 4º | A | 23:13:17 | 301 → 200 | não | não | não | 50 |

(¹) Em C o NetLog mostra a requisição da página só com o 301 (termina em
`ERR_ABORTED`); a página renderizou mesmo assim, com as dezenas de scripts `/xjs/` e
recursos do Google devolvendo 200 nas duas rodadas.

**Nenhuma condição, nas duas rodadas, mostrou CAPTCHA.** Inclusive D, a captura
completa de hoje. O CAPTCHA que o usuário viu **não reproduziu** com 8 cargas.

### 4.2 `navigator.webdriver` (local, sem Google)

| Cond. | CDP | `navigator.webdriver` |
|---|---|---|
| A | nenhum | **false** |
| B | nenhum | **false** |
| C | pipe, reduzido | **true** |
| D | pipe, completo | **true** |
| C + `--disable-blink-features=AutomationControlled` | pipe, reduzido | **false** |
| D + `--disable-blink-features=AutomationControlled` | pipe, completo | **false** |

O `webdriver` fica `true` **com qualquer `--remote-debugging-pipe`**, reduzido ou
completo: não depende de `Runtime.enable` nem de `waitForDebuggerOnStart`. A flag
`--disable-blink-features=AutomationControlled` o desfaz mesmo com CDP completo
(medido na captura completa num snapshot local, fora do repositório). Em C e D o
`User-Agent` é o mesmo de A e B (`Chrome/156.0.0.0`, sem `HeadlessChrome`), com 5
plugins e 4 idiomas.

### 4.3 Outras observações

- **B gera mais tráfego do Google** (71 a 73 requisições contra 50): sem
  `--disable-background-networking` e companhia, o Chrome consulta
  `accounts.google.com/ListAccounts`, atualizações, `clientservices` etc. Os
  argumentos de laboratório reduzem o ruído do navegador; **não mudaram o que a
  página principal recebeu**.
- Com NetLog, o encerramento por `SIGTERM` (A e B, sem CDP) fecha o arquivo; um
  NetLog sem CDP é viável.
- Em todas as condições o NetLog registra o carregamento completo da página inicial
  (cadeia 301 → 200, scripts, fontes e `gen_204`).

## 5. Limites desta medição (leia antes de concluir)

1. **O CAPTCHA não reproduziu**, então **não se pode apontar a peça que o causa**.
   Em 8 cargas, nem a captura completa (D) o provocou. Não há evidência de que
   `Runtime.enable`, a pausa por depurador, o perfil vazio ou os argumentos de
   laboratório sejam a causa; também não há evidência de que não sejam: a amostra é
   pequena (2 por condição) e o Google decide por risco (IP, histórico, horário), não
   por uma peça isolada.
2. O CAPTCHA do usuário pode ter ocorrido num momento em que o IP já tinha sido
   marcado (várias cargas automatizadas seguidas, repetidas pelos testes do
   projeto); isso não foi testado, e testar exigiria forçar o bloqueio, o que a
   autorização proíbe.
3. **Desvio no intervalo mínimo.** O pedido era ≥ 60 s entre carregamentos. Entre o
   fim da rodada 1 (D, 23:07:32) e o início da rodada 2 (D, 23:08:16) o intervalo
   entre inícios foi de **44 s**; os demais ficaram entre 96 e 114 s. Foi falha do meu
   encadeamento (a rodada 2 começou sem esperar). Não houve efeito visível (nenhum
   `/sorry/`, 429 nem reCAPTCHA), mas o limite foi violado uma vez.
4. Um sinal comprovadamente diferente existe e é detectável por qualquer script do
   site: `navigator.webdriver === true` na captura (C e D), contra `false` num Chrome
   sem CDP (A e B). Se o Google usa isso no CAPTCHA, não foi medido.

## 6. Recomendação

O que as medições sustentam, em ordem de custo:

1. **Adicionar `--disable-blink-features=AutomationControlled` ao launcher**
   (captura comum e controlada). Medido: `navigator.webdriver` volta a `false`,
   mesmo com a captura completa, e a flag não mexe na rede nem no que é capturado.
   É a diferença visível mais barata entre a captura e um Chrome normal, e remove
   um sinal que qualquer site lê. Não prova que cura o CAPTCHA (§5.1).
2. **Modo discreto escalonado** (opção por captura), do menos ao mais intrusivo:
   - **nível 1, só NetLog** (condição A): nenhum cliente CDP, o navegador é o Chrome
     normal com perfil e NetLog; perde o CDP (corpos, ExtraInfo, alvos) e a
     correlação CDP×NetLog, e a navegação é feita pelo usuário;
   - **nível 2, CDP reduzido** (condição C + a flag do item 1): `Network.enable` e
     `setAutoAttach` sem `waitForDebuggerOnStart`, sem `Page` nem `Runtime.enable`;
     mantém corpos e ExtraInfo; perde a garantia de anexar a workers e iframes
     antes de a primeira requisição sair;
   - **nível 3, completo** (D, hoje): a fidelidade total que o projeto exige.
   Usar o nível mais baixo que atenda o objetivo; subir só quando o `site_profile`
   (ou o usuário) precisar do que ele não dá.
3. **Se o CAPTCHA reaparecer no App**, repetir uma vez com a flag do item 1 e
   comparar com o NetLog (`/sorry/`, 429); só então vale a pena testar `Runtime.enable`
   e `waitForDebuggerOnStart` isoladamente, com cuidado para não esgotar o IP.
4. **Não mudar** os argumentos de laboratório por causa disto: A e B (com e sem eles)
   se comportaram igual para o Google; eles servem para reduzir ruído do NetLog.

Pendências para quem for implementar (fora desta rodada): onde o nível é escolhido
(`CaptureConfig` ou parâmetro do `start_capture`), e como a captura sem CDP (nível 1)
gera a sessão (importar o NetLog sozinho, com `import_netlog`).

## 7. Dados

Os NetLogs (com `--net-log-capture-mode=Everything` nas condições A, C e D, que
inclui cookies do Google), os perfis temporários e as sessões ficaram em `/tmp` fora
do repositório e **foram apagados** no fim. Nenhuma sessão ou NetLog do Google foi
commitado. Os scripts (um cliente CDP mínimo por pipe, o servidor da sonda local e o
leitor de NetLog) ficaram fora do repositório por instrução; o método acima basta para
repeti-los.
