# 18. Memória ao abrir sessões grandes: onde está o pico e como reduzi-lo

Rodada 12, onda 1. **Só medição**: nenhum código de `core/`, `mcp/` ou `src-tauri/`
foi alterado. Este documento mede onde está o pico de memória ao abrir uma sessão
muito grande (a pendência "cerca de 2,4 GB", `docs/06-entrega.md`) e propõe
reduções, cada uma com a estimativa e o que foi de fato medido.

## 1. Como foi medido

- **Sessão sintética por captura real em loopback.** `capture/examples/capture_big.rs`
  sobe um servidor HTTP/1.1 em `127.0.0.1` (std, keep-alive) que serve uma página
  com `N` `fetch` de `/r/<i>` (JSON de ~1,5 KiB, um `Set-Cookie` a cada 50, cabeçalhos
  variados). O Chrome estável é controlado por `BrowserCapture` (CDP + NetLog
  `Everything`, allowlist só `localhost:<porta>`, pipe). Dados sintéticos
  (`bigfixture-*`); nenhum site de terceiros; sem proxy; sem CloakBrowser.
- **Harness por etapa.** `experiments/memoria-sessao/` (crate independente, só
  leitura) roda **uma etapa por processo** e imprime o pico de RSS (`getrusage`
  `ru_maxrss`) e o RSS atual (`ps`) a cada checkpoint, mais o tempo. Cada etapa
  imita um consumidor real:

  | Etapa | Quem faz isso hoje |
  |---|---|
  | `app-open`, `app-open-ipc` | App: `read_session_payload` (`src-tauri/src/commands.rs`): `read_to_string` + `serde_json::Value`, depois o payload é serializado para o front-end |
  | `lazy`, `lazy-search` | App: busca (`cached_session` → `open_session_dir_lazy`) |
  | `import-eager`, `import-eager-pretty`, `import-eager-sanitize` | MCP: primeira chamada mascarada (`registry.rs` `Entry::masked`: `import_session_dir` + `sanitize_bundle`); CLI `inspect` (`import_session_dir` + `json!` + `to_string_pretty`) |
  | `netlog-only`, `cdp-only`, `capture-full`, `capture-write` | `stop_capture` / `import-capture`: parse de CDP e NetLog + correlação (+ gravação) |
  | `validate-value` / `validate-ignored`, `eager-ignored`, `import-eager-stream` | Variantes da **proposta** (§4), medidas à parte |

- **Máquina:** macOS arm64, 64 GiB, Chrome 156, binários `--release`. Os números de
  memória são **picos de RSS** e repetíveis (±1 %); os de tempo variam com o cache
  de disco (±30 % nas etapas curtas).
- **Reproduzir:**
  ```
  cd capture && cargo build --release --example capture_big
  ./target/release/examples/capture_big /tmp/big20k 20000     # ~5 min
  cd ../experiments/memoria-sessao && cargo build --release
  ./target/release/memoria-sessao import-eager /tmp/big20k   # uma etapa por vez
  ```
  Obs.: as medições foram feitas num snapshot limpo do `HEAD` (`git archive`) porque
  o working tree do core estava em edição por outro agente.

## 2. Tamanhos das sessões medidas

| Requisições | `session.json` | `netlog.json` | `cdp-events.jsonl` | `cdp-bodies.jsonl` | Anexos |
|---:|---:|---:|---:|---:|---:|
| 2.002 | 113 MiB | 31 MiB | 9,0 MiB | 2,7 MiB | 2.002 arquivos |
| 5.002 | 283 MiB | 78 MiB | 22,5 MiB | 6,7 MiB | 5.002 arquivos |
| 20.002 | **1.133 MiB** | 313 MiB | 90 MiB | 27 MiB | 20.002 arquivos (18 MiB) |

Uma requisição capturada pesa **~59 KiB no `session.json`** (pretty) e ~34 KiB em
JSON compacto. A referência de `docs/06-entrega.md` (20.000 requisições de HAR,
`inspect` a 2.415 MiB) é de uma sessão muito mais leve por requisição; o mesmo
`inspect` sobre 20.000 requisições **capturadas** pica em 9.305 MiB (3,9×), e
o 2,4 GB equivale a só ~**5 mil** requisições capturadas (2.611 MiB em
`import-eager-pretty` com N = 5.002). O número de requisições sozinho não define o
risco: o formato da sessão (captura com NetLog e `headerEvidence` contra HAR) pesa
tanto quanto.

Composição de uma requisição (amostra de 200, JSON compacto, bytes):

| Campo | Bytes | Observação |
|---|---:|---|
| `attempts` (total) | 25.711 | dentro dele: `headerEvidence` **16.282**, `requestHeaders` 4.512, `responseHeaders` 1.272 |
| `requestHeaders` (nível da requisição) | 4.828 | **cópia** do que já está na tentativa |
| `responseHeaders` (nível da requisição) | 1.291 | **cópia** |
| `cookie`, `requestBody`, `responseBody`, `provenance`, `timings`, `cdp`, `target`, resto | ~2.100 | |
| **Total** | **~33.900** | `headerEvidence` = 48 %; cópias de cabeçalhos = 18 % |

## 3. Resultados: pico de RSS por etapa (MiB)

| Etapa | N = 2.002 | N = 5.002 | N = 20.002 | MiB por 1.000 req. (5k→20k) |
|---|---:|---:|---:|---:|
| `lazy` (sessão tipada + anexos preguiçosos) | 121 | 293 | **1.154** | 57 |
| `app-open` (App: texto + `Value`) | 648 | 1.615 | **6.453** | 322 |
| `app-open-ipc` (+ serialização para o front-end) | 714 | 1.778 | **7.101** | 355 |
| `import-eager` (MCP máscara / CLI) | 481 | 1.186 | **4.727** | 236 |
| `import-eager-sanitize` (+ cópia mascarada) | 569 | 1.415 | **5.654** | 283 |
| `import-eager-pretty` (CLI `inspect`) | 1.057 | 2.611 | **9.305** | 606 |
| `capture-full` (parse + correlação) | 715 | 1.784 | **6.993** | 347 |
| `capture-write` (+ `write_session_dir`) | — | — | **9.189** | — |
| *Proposta:* `eager-ignored` | 163 | 399 | **1.576** | 78 |
| *Proposta:* `import-eager-stream` | — | 1.186 | **4.727** | — |

Tempo (ms): `import-eager` 1.154 / 2.890 / 17.795; `import-eager-sanitize` 1.960 /
6.964 / 25.764; **`capture-full` 2.767 / 20.512 / 248.911**.

O crescimento da **memória é linear** em N. O do **tempo de `capture-full` não é**:
2.002 → 5.002 requisições (×2,5) leva ×7,4 do tempo; 5.002 → 20.002 (×4) leva ×12,1.

## 4. Onde está o pico (por consumidor)

### 4.1 Importar uma sessão inteira (`import_session_dir`): 4,7 GiB, dos quais ~3,1 GiB são um DOM descartado

`import_session_dir` lê `session.json` tipado (1,15 GiB), lê `cdp-events.jsonl` (90 MiB)
e `netlog.json` (313 MiB) inteiros e, **só para saber se o netlog é JSON válido**,
faz `serde_json::from_slice::<Value>(&bytes)` (`core/src/parse/own.rs`, linha 42):
um DOM completo que é descartado em seguida. Medido isoladamente sobre o mesmo
`netlog.json`: **`validate-value` 3.464 MiB contra `validate-ignored` 315 MiB**
(só os bytes), em 2,5 s contra 0,36 s. O pico de 4.727 MiB é exatamente
1.154 (sessão) + 90 + 313 (bytes) + ~3.150 (DOM) + 18 (anexos).

### 4.2 `inspect` do CLI: o dobro, por `json!` + `String`

`print_json(&json!({"session": ..., "report": ...}))` converte a sessão tipada em um
DOM (`json!` chama `to_value`) e depois a serializa numa `String` de 1,16 GiB:
**9.305 MiB** (4.727 do import + 4.578 do DOM e da `String`). Serializar uma struct
tipada direto com `to_writer_pretty` num fluxo **não soma nada**: o pico
continua 4.727 MiB (`import-eager-stream`, medido).

### 4.3 Abrir no App: `Value` custa 5,6 vezes a sessão tipada

`read_session_payload` faz `read_to_string` (1.133 MiB) e `serde_json::from_str::<Value>`:
**6.453 MiB**, contra **1.154 MiB** do mesmo arquivo tipado (`lazy`). O payload
serializado para o front-end tem 649 MiB; o pico passa a **7.101 MiB** (o comando move o
`Value`, sem clonar; um `json!` o clonaria e subiria para 10,9 GiB, o que o código
real não faz). Com 20 mil requisições capturadas o App precisaria de ~7 GiB
só para abrir e o webview ainda receberia 649 MiB de JSON.

### 4.4 Importar uma captura (`stop_capture`, `import-capture`): 7,0 GiB e 4 minutos

Divisão medida em 20.002 requisições:

| Parte | Pico | Tempo |
|---|---:|---:|
| Parse do NetLog (`import_netlog`) | 4.662 MiB | 4,6 s |
| Parse do CDP (`import_capture` sem NetLog) | 1.966 MiB | 2,7 s |
| **Correlação CDP×NetLog** (o resto de `capture-full`) | — | **~241 s** |
| `capture-full` inteiro | 6.993 MiB | 248,9 s |
| + `write_session_dir` | 9.189 MiB | 263 s |

- **Tempo:** `find_candidates` (`core/src/correlate.rs`, linha 220) percorre **todos**
  os pares (tentativa CDP × tentativa NetLog) para cada tentativa CDP; para cada par
  monta `format!("netlog-r{:04}-a{}")` e, em `score_candidate`, chama
  `canonical_url` duas vezes. São 20.002 × 20.029 ≈ **4,0 × 10⁸ pares**; 248,9 s ÷
  4,0 × 10⁸ = **0,62 µs por par** (com N = 5.002: 20,5 s ÷ 2,5 × 10⁷ = 0,8 µs): é o
  custo quadrático. Um `sample` de 12 s com N = 5.002 confirma: `attach_netlog` →
  `canonical_url` + `format!` + `malloc/free` dominam.
  Isso também é o que o `stop_capture` roda **dentro do servidor MCP e do App** ao
  encerrar uma captura grande: 4 minutos parado e ~9 GiB.
- **Memória:** o pico de 4,66 GiB do NetLog é, como em 4.1, um DOM (`Value`) de
  3,1 GiB do arquivo de 313 MiB, antes de virar o modelo.

### 4.4b Primeira chamada mascarada do MCP

`import-eager` (4.727) + `sanitize_bundle` sobre a referência (+927 MiB de cópia
mascarada) = **5.654 MiB** de pico, e a cópia mascarada (~1,1 GiB) fica retida em
cache pela sessão. O custo do `sanitize_bundle` é ~14 s com 20 mil requisições.

## 5. Proposta de redução, com estimativa

Ordem por (ganho ÷ esforço). **Medido** = os números vêm do harness; **estimado** =
extrapolação dos números medidos, a confirmar quando o item for implementado.

| # | Mudança | Onde | Ganho | Esforço | Risco |
|---|---|---|---|---|---|
| P1 | Validar o `netlog.json` em fluxo: `serde_json::from_slice::<serde::de::IgnoredAny>` em vez de `Value` | `core/src/parse/own.rs:42` | `import-eager` **4.727 → 1.576 MiB (−67 %)**, 17,8 → 9,2 s. **Medido** (`eager-ignored`: mesmo trabalho sem o DOM). Vale também para o MCP mascarado (5.654 → ~2.500 MiB, **estimado**: 1.576 + 927 da cópia) | 1 linha + teste | nenhum: mesmo veredito de validade |
| P2 | `inspect` e outros `print_json`: struct tipada + `to_writer_pretty` em fluxo no lugar de `json!` + `String` | `core/src/bin/scrapelens-core.rs` | `inspect` **9.305 → 4.727 MiB (−49 %)**; com P1 **1.576 MiB (−83 %)**. **Medido** (`import-eager-stream`) | pequeno | nenhum |
| P3 | Indexar o NetLog antes de correlacionar: `HashMap<(método em minúsculas, canonical_url), Vec<(requisição, tentativa)>>`, com `canonical_url` e o id calculados uma vez por tentativa. O candidato exige método e URL canônica iguais (`score_candidate` devolve `None` senão), então o conjunto de candidatos é **idêntico** | `core/src/correlate.rs` `find_candidates` | `capture-full` de **249 s para ~12 s** a 20 mil requisições (**estimado**: 7,4 s de parse medidos + correlação linear com ~1 µs por tentativa); o `stop_capture` deixa de congelar por minutos. A memória quase não muda | médio | baixo: a saída tem de ser igual (testes de correlação existentes + comparação do `session.json` antes/depois) |
| P4 | Parse do NetLog em fluxo: um `Visitor` sobre o array `events`, guardando só os campos usados, em vez de `Value` | `core/src/parse/netlog.rs` | pico de `import_netlog` **4.662 → ~1.500 MiB** (**estimado**: remove o DOM de 3.150 MiB medido em `validate-value`); `capture-full` 6.993 → ~3.800 MiB. **Medido na rodada 16 (§8): `netlog-only` 4.759 → 1.615 MiB; `capture-full` 7.110 → 4.200 MiB** | grande | médio (o parser é grande; exige o corpus e o `check_multi_target`) |
| P5 | App: **não** montar `Value` nem mandar a sessão inteira ao front-end. Parse tipado (`SessionV1`, 1.154 MiB, 5,6× menos) e uma lista paginada/virtualizada: o comando devolve o resumo por requisição (~100 a 200 B) e o detalhe sob demanda | `src-tauri/src/commands.rs` + front-end | abrir **7.101 → ~1.200 MiB (−83 %)**, **estimado** (tipada medida em 1.154 MiB; resumos de 20 mil linhas ≈ 4 MiB) e menos 649 MiB no IPC | médio/grande (muda o contrato do comando) | médio |
| P6 | Escrever `session.json` compacto quando passa de um limite (ex.: 50 MiB); manter pretty abaixo | `core/src/store.rs` | arquivo **1.133 → ~650 MiB (−43 %)** (**medido**: é o `wireMiB` de 649); `app-open` e `read_to_string` caem na mesma proporção do texto (−480 MiB no pico de `app-open`) | pequeno | baixo (legibilidade em editor só para sessões enormes) |
| P7 | `sanitize_bundle` consumindo o bundle (ou sanitizando in place) em vez de copiar | `core/src/export/sanitize.rs`, `mcp/src/registry.rs` | −927 MiB no pico mascarado e na memória retida por sessão (**medido** como o delta de `import-eager-sanitize`) | médio | baixo |
| P8 | Esquema: não repetir `requestHeaders`/`responseHeaders` no nível da requisição quando há uma só tentativa; guardar `headerEvidence` só como diferença entre fontes | modelo `SessionV1` (v2) | ~−65 % do tamanho por requisição (59 → ~20 KiB pretty), **estimado** a partir da composição de §2 (48 % + 18 %); tipada e DOM caem junto | grande (versão de esquema) | alto (compatibilidade, todos os consumidores) |

**Projeção combinada (20 mil requisições capturadas, estimada a partir das medidas):**

| Consumidor | Hoje | P1+P2 (+P7) | + P3/P4 | + P5/P6 |
|---|---:|---:|---:|---:|
| `inspect` (CLI) | 9,3 GiB | **1,6 GiB** | — | — |
| 1ª chamada mascarada do MCP | 5,7 GiB | **~2,5 GiB** (P1) / ~1,6 (com P7) | — | — |
| `stop_capture` (importa a captura) | 7,0 GiB, 249 s | 7,0 GiB, 249 s | **~3,8 GiB, ~12 s** | — |
| Abrir no App | 7,1 GiB | 7,1 GiB | 7,1 GiB | **~1,2 GiB** |

Recomendação: **P1, P2 e P3 primeiro**. São pequenos, medidos ou com mecanismo
claro, e resolvem o pior sintoma para quem usa o MCP: o `stop_capture` de uma
captura grande deixa de levar minutos (P3) e a abertura mascarada cai a um terço
da memória (P1). P5 é o que resolve o App, mas muda o contrato do comando e o
front-end.

## 6. Limites do que foi medido

- A carga é sintética e uniforme (mesmo tamanho de corpo, 1 host, HTTP/1.1, sem
  redirecionamentos nem WebSocket); sessões reais têm cabeçalhos maiores e menos
  repetição de URL (o que diminui o custo da correlação sem índice, mas não o
  de memória).
- `ru_maxrss` mede o pico do processo inteiro, incluindo o alocador; o RSS
  retido depois do pico é menor (e o macOS devolve páginas aos poucos).
- O tempo de etapas curtas depende do cache de disco; os de `capture-full` não.
- Estimativas de P3 a P8 não foram implementadas **nesta rodada** (proibido então); P1 e P2 têm
  as variantes medidas no harness, mas usando a API atual do core, não um patch. Depois disso, P1,
  P2, P3, P4, P6 e P7 foram implementados e medidos (§7 e §8), e P5 foi feito pelo App.
- O captura do Chrome em si (processo `capture_big`) não teve a memória medida à
  parte; o `stop` roda o mesmo import de `capture-write` (9,2 GiB de pico).

## 7. Resultado depois das correções (rodada 13, onda 1)

Implementados no `core/` e no `mcp/` (um commit por item): **P1** (`87bd164`: validação do
`netlog.json` e das linhas do CDP em fluxo, sem DOM, com o mesmo veredito do `Value`, inclusive o
limite de recursão de 128 níveis: `IgnoredAny` não serve porque o pula), **P2** (`752230e`:
`inspect` e `assess` escrevem em fluxo com struct emprestada; saída byte a byte igual), **P3**
(`4d82e36`: índice por (método em minúsculas, URL canônica) e por id de origem do NetLog; as chaves
explícitas também indexadas), **P6** (`2550041`: `session.json` compacto quando o JSON identado passa
de 50 MiB) e **P7** (`b438945`: `sanitize_bundle_owned` consome o bundle e sanitiza no lugar; CLI
`sanitize` e registry do MCP usam). **P4** ficou para a rodada 16 e está medido em §8 (`ad4f5c1`);
**P5** foi feito pelo App e também está medido (`docs/19-contrato-app.md`: 1.161 MiB ao abrir a
sessão de 20 mil). **P8 não foi feito.**

**Requisito de P3, saída idêntica.** `core/tests/correlation_identity.rs` importa as 29 capturas e
fixtures versionadas (HTTP/1.1, h2, h3, contratos, multi-alvo, `src-tauri/evidence`, adapters) e
confere o `session.json` identado e os anexos, byte a byte (FNV-1a 64 bits + tamanho), contra os
hashes gravados ANTES da mudança (commit `aefacc9`); passa igual depois. Mais um teste unitário em
`correlate.rs` mostra que o índice nunca descarta um par que a varredura de todos os pares aceitaria,
e o `tests/aceite/check_multi_target.py` (captura real multi-alvo) passou.

**Medido depois** (mesmas sessões sintéticas de §2, mesmo harness, `--release`, picos de RSS em MiB;
a etapa nova `import-eager-sanitize-owned` foi acrescentada ao harness; `inspect` é o binário
`scrapelens-core inspect` medido com `/usr/bin/time -l`). N = 2.002 não foi medido de novo.

| Etapa | N = 5.002 antes → depois | N = 20.002 antes → depois | Tempo a 20.002 |
|---|---:|---:|---:|
| `import-eager` (MCP máscara / CLI) — P1 | 1.186 → **400** | 4.727 → **1.580** (−67 %) | 17,8 s → 10,1 s |
| `inspect` (CLI) — P1+P2 | 2.611 → **419** | 9.305 → **1.656** (−82 %) | n/m → 11,5 s |
| 1ª chamada mascarada do MCP — P1+P7 (`import-eager-sanitize-owned`) | 1.415 → **415** | 5.654 → **1.649** (−71 %) | 25,8 s → 22,8 s |
| `capture-full` (parse + correlação) — P3 | 1.784 → 1.783 | 6.993 → 7.110 | **20,5 s → 2,2 s** (5k); **248,9 s → 9,3 s** (20k) |
| `capture-write` (+ `write_session_dir`) — P3+P6 | — → 1.903 | 9.189 → **7.580** | 263 s → **16,2 s** |
| `netlog-only` (parse do NetLog; P4 pendente nesta rodada) | — → 1.194 | 4.662 → 4.759 | 4,6 s → 5,0 s |
| `session.json` gravado (5.002 req.) — P6 | 283 MiB → **162 MiB** (−43 %) | 1.133 MiB → ~650 MiB (estimado, igual proporção) | — |

As linhas de `netlog-only`, `capture-full` e `capture-write` desta tabela são o estado **antes do
P4**; os números com P4 estão em §8.

Leitura:

- O **tempo** de importar uma captura grande caiu de forma linear: `capture-full` a 20 mil requisições
  de ~4 min para 9,3 s (27×); o `stop_capture` do MCP e do App deixa de congelar por minutos. A
  memória de `capture-full` não mudava naquela rodada (o DOM do NetLog, P4, continuava: 4,7 GiB só
  no parse); com P4, §8 mostra 4,2 GiB e 8,1 s.
- A memória de `import-eager`, `inspect` e da 1ª chamada mascarada do MCP caiu para ~1,6 GiB (−67 a
  −82 %): é o custo da sessão tipada (1,15 GiB) mais os bytes do CDP e do NetLog, sem o DOM nem a cópia
  mascarada. A estimativa de §5 (≈1,6 GiB) se confirmou; a do MCP mascarado (≈1,6 GiB com P7) também.
- `capture-write` caiu de 9,2 para 7,6 GiB e de 263 para 16 s; o que resta é o parse do NetLog
  (P4), resolvido na rodada 16 (§8).
- Variação: ±1 % na memória; os tempos curtos variam com o cache de disco (±30 %).
- Reproduzir: `cd experiments/memoria-sessao && cargo build --release && ./target/release/memoria-sessao
  <etapa> /tmp/big20k` (uma etapa por processo); `inspect`: `/usr/bin/time -l
  core/target/release/scrapelens-core inspect /tmp/big20k > /dev/null`.

**Depois de P4 e P5 (20 mil requisições capturadas, medido):**

| Consumidor | Antes (rodada 12) | P1–P3/P6 (rodada 13) | Com P4/P5 |
|---|---:|---:|---:|
| `inspect` (CLI) | 9,3 GiB | **1,6 GiB** | 1,6 GiB (P4 não é do `inspect`) |
| 1ª chamada mascarada do MCP | 5,7 GiB | **1,6 GiB** | 1,6 GiB |
| `stop_capture` (importa a captura) | 7,0 GiB, 249 s | **7,1 GiB, 9,3 s** | **4,2 GiB, 8,1 s** (§8; com a gravação, 4,6 GiB, 17,1 s) |
| Abrir no App (P5) | 7,1 GiB | 7,1 GiB | **1,16 GiB** (`docs/19-contrato-app.md`) |

## 8. Rodada 16: P4 medido (parser de NetLog em fluxo)

P4 foi implementado no `core/` no commit `ad4f5c1`: o array `events` do NetLog é lido por um
`Visitor` que guarda só os campos usados, sem montar o `serde_json::Value` do arquivo inteiro.
A saída é idêntica: `core/tests/correlation_identity.rs` continua com os **29/29 hashes** iguais
aos gravados antes (referência `aefacc9`), e o corpus de NetLog e o `check_multi_target` do Core
passaram.

Medição refeita nesta rodada para conferir os números do Core: mesmas sessões de §2
(`/tmp/big5k` e `/tmp/big20k`), mesmo harness, `--release`, uma etapa por processo, pico de RSS
em MiB. As duas execuções concordam dentro de 1 %.

| Etapa | N = 5.002 antes → P4 | N = 20.002 antes → P4 | Tempo a 20.002 |
|---|---:|---:|---:|
| `netlog-only` (parse do NetLog) — **P4** | 1.194 → **407** (−66 %) | 4.759 → **1.615** (−66 %) | 5,0 s → **3,5 s** |
| `capture-full` (parse + correlação) — P3+P4 | 1.783 → **1.055** (−41 %) | 7.110 → **4.200** (−41 %) | 9,3 s → **8,1 s** |
| `capture-write` (+ `write_session_dir`) — P3+P4+P6 | 1.903 → **1.229** (−35 %) | 7.580 → **4.629** (−39 %) | 16,2 s → ~16 s |

Leitura:

- **P4 removeu o DOM do NetLog.** `netlog-only` a 20 mil caiu de 4.759 para 1.615 MiB (−66 %):
  o DOM de ~3,1 GiB medido em §4.1/§4.4 deixou de existir, e o que resta é o modelo tipado (~1,15
  GiB) mais o texto do arquivo e as estruturas transitórias do parse. A estimativa de §5 (~1.500
  MiB) ficou 8 % abaixo do medido.
- **Contra a linha de base da rodada 12**, `capture-full` a 20 mil foi de 6.993 para 4.200 MiB
  (−40 %) e `capture-write` de 9.189 para 4.629 MiB (−50 %); `capture-full` a 5 mil caiu 41 %, o
  mesmo percentual do arquivo grande — o ganho escala com o NetLog, não com o número de requisições.
- **Tempo:** o parse em fluxo também é mais rápido (`netlog-only` 5,0 → 3,5 s; `capture-full`
  9,3 → 8,1 s). `capture-write` continua dominado pela gravação (14,7 s dos ~17 s), então o tempo
  total não muda de forma perceptível (15,9 s na execução do Core, 17,1 s nesta, dentro da
  variação de cache de disco de ±30 % já registrada em §7).
- **P5 (App), medido:** abrir a sessão de 20 mil no App caiu de 7.108 para **1.161 MiB** (−84 %)
  com o caminho tipado + lista paginada, e o que vai ao front-end caiu de 681 MB para ~5,4 MB
  (`docs/19-contrato-app.md`, `src-tauri/examples/mem_open.rs`). É a linha "Abrir no App" da
  tabela de §7.
- **O que sobra:** o piso agora é a sessão tipada (~1,15 GiB a 20 mil) e o `session.json` de
  ~650 MiB escrito por P6. O próximo item de memória é **P8** (esquema, ~−65 % do tamanho por
  requisição), que exige versão nova de esquema e não foi feito.

Reproduzir (uma etapa por processo):

```
cd experiments/memoria-sessao && cargo build --release
./target/release/memoria-sessao netlog-only   /tmp/big20k
./target/release/memoria-sessao capture-full  /tmp/big20k
./target/release/memoria-sessao capture-write /tmp/big20k
```
