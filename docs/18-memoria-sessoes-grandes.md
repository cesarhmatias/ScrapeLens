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
| P4 | Parse do NetLog em fluxo: um `Visitor` sobre o array `events`, guardando só os campos usados, em vez de `Value` | `core/src/parse/netlog.rs` | pico de `import_netlog` **4.662 → ~1.500 MiB** (**estimado**: remove o DOM de 3.150 MiB medido em `validate-value`); `capture-full` 6.993 → ~3.800 MiB | grande | médio (o parser é grande; exige o corpus e o `check_multi_target`) |
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
- Estimativas de P3 a P8 não foram implementadas (proibido nesta rodada); P1 e P2 têm
  as variantes medidas no harness, mas usando a API atual do core, não um patch.
- O captura do Chrome em si (processo `capture_big`) não teve a memória medida à
  parte; o `stop` roda o mesmo import de `capture-write` (9,2 GiB de pico).
