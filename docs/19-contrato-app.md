# 19 — Contrato de sessão do App (P5)

Rodada 13, onda 1. Aplica a proposta P5 de `docs/18-memoria-sessoes-grandes.md` §5:
o App deixa de montar `serde_json::Value` da sessão e de mandá-la inteira ao front-end.

## Princípio

- O backend lê `session.json` **tipado** (`SessionV1`) por `open_session_dir_lazy` do
  core e o guarda no cache `cached_session` (até duas sessões; o mesmo cache de busca,
  origens, cadeia, comparação e exportação). Corpos e brutos CDP/NetLog continuam em
  disco.
- O front recebe só o **cabeçalho**, pede a lista em **páginas de resumos** e o
  **detalhe** de uma requisição quando ela é aberta.
- Busca rápida, filtros e contagens rodam no backend (`src-tauri/src/listing.rs`).
  A busca no payload continua no `search_session`; os ids achados entram no filtro.

## Comandos

### `open_session(path)` → `SessionPayload`

Também devolvido por `import_har`, `import_netlog` e `stop_session`.

```jsonc
{
  "session": {               // SessionHeader
    "schemaVersion": 1,
    "session": { /* SessionMeta v1: id, startedAt, browser, completeness, labels, capture… */ },
    "requests": [],          // sempre vazio no contrato paginado
    "warnings": [ /* só avisos de sessão (sem `entity`) */ ],
    "requestCount": 20002,   // presença deste campo = sessão paginada
    "sources": ["cdp", "netlog"]
  },
  "sessionDir": "/…/sessions/capture-…",
  "synthetic": false,
  "notice": "Sessão aberta: 20002 requisição(ões).",
  "pending": false
}
```

`demo_session` e o `start_session` (captura em andamento) continuam devolvendo o
documento v1 em memória, sem `requestCount`: o front os trata como sessões em memória.

### `list_requests(sessionDir, offset, limit, filter?)` → `RequestPage`

`limit` vai de 1 a 2000. `filter` (todos opcionais):

| Campo | Valores | Regra |
|---|---|---|
| `typeFilter` | `all` `fetch` `document` `media` `error` | `fetch` = fetch+xhr; `media` = image+font; `error` = status ≥ 400 |
| `protocol` | `all` `HTTP/1.1` `HTTP/2` `HTTP/3` `desconhecido` | rótulo de `protocol` (h1/h2/h3) |
| `target` | `all` `page` `popup` `iframe` `worker` `service_worker` `shared_worker` `netlog_unknown` | só vale quando a sessão mostra alvos |
| `query` | texto | URL, id, método (igual) ou status; minúsculas |
| `payloadSearch` + `matchIds` | bool + ids | com busca no payload ativa, a URL deixa de valer e os ids achados pelo `search_session` passam |
| `restrictIds` | ids ou `null` | filtros de veredito (falha da aplicação / possível bloqueio) |

```jsonc
{
  "total": 20002, "matched": 20002, "offset": 0,
  "items": [
    { "id": "cdp-r0001", "url": "http://localhost:58304/r/8?v=1", "method": "GET",
      "status": 200, "protocol": "h1", "resourceType": "Fetch",
      "wallTime": "2026-11-02T18:40:35.707Z", "totalMs": 10.008,
      "initiator": { "kind": "script" }, "target": 0, "source": "cdp", "warningCount": 0 }
  ],
  "targets": [ { "targetId": "…", "kind": "page", "url": "http://localhost:58304/", "attached": true } ],
  "counts": { "all": 20002, "fetch": 20002, "document": 0, "media": 0, "error": 0 },
  "targetCounts": { "all": 20002, "page": 20002, "…": 0 },
  "hasTargets": true
}
```

- Os campos do resumo são **crus** do v1. Rótulos (domínio, caminho, tipo, protocolo,
  alvo, "alvo desconhecido (só NetLog)") são derivados no front por `summaryFromRaw`
  (`app/src/v1/adapter.ts`), com as mesmas regras de `adaptSession`.
- `target` é o índice em `targets`: o alvo repetido vai uma vez por página.
- `estimated: true` aparece quando `timings.estimated`; a lista mostra "≈".
- `counts`, `targetCounts` e `hasTargets` são da sessão inteira, sem filtro.

### `get_request(sessionDir, id)` → `RequestDetail`

```jsonc
{ "request": { /* LogicalRequest v1 completo */ },
  "warnings": [ /* avisos com entity = id */ ],
  "streamSessions": [ /* StreamSessions das tentativas, para a verificação de protocolo */ ] }
```

O front adapta com `adaptRequestDetail(cabeçalho, detalhe)`, que chama o mesmo
`adaptSession` sobre uma sessão de uma requisição. O teste `npm run test:paged`
confere, na fixture de demonstração, que o detalhe e o resumo são iguais ao
resultado do adaptador da sessão inteira.

## Front-end

- A lista virtualizada já existente (linhas de 34 px, overscan 6) passa a renderizar
  os resumos. O front carrega todos os resumos da sessão em páginas de 2000 para
  seletores, linha do tempo e "Limites" (~5 MiB a 20 mil requisições) e pede a lista
  filtrada ao backend a cada mudança de filtro (debounce de 120 ms).
- Detalhe, exportação e comparação lado a lado usam o `RequestRecord` completo,
  carregado por `get_request` (a comparação carrega A e B).
- Sessões em memória (demonstração, modo navegador, `?demo=large`) usam os mesmos
  resumos, derivados localmente por `summaryOfRecord`, e o filtro local equivalente.

## Memória (sessão de 20.002 requisições capturadas, docs/18)

Medido com `src-tauri/examples/mem_open.rs` (um modo por processo, `--release`,
macOS arm64, pico de RSS por `getrusage`), em `/tmp/big20k` (`session.json` de 1,19 GB):

| Caminho | Pico de RSS | Enviado ao front |
|---|---:|---:|
| antigo (`read_to_string` + `Value` + serialização) | **7.108 MiB** | 681 MB |
| novo: abrir tipado + cabeçalho + todas as páginas + um detalhe | **1.161 MiB** | 1,4 KB + 5,4 MB (todas as páginas) + 32 KB |

- Meta da rodada: abrir a sessão de 20 mil com menos de 1,5 GiB de pico. Cumprida
  no backend (1.161 MiB, −84 %).
- Resumo: 268 B por linha em média, com a sobra da página; uma linha sozinha tem
  ~240 B (URL e `wallTime` dominam). Fica acima da estimativa de 100 a 200 B do docs/18.
- Tempo: a leitura tipada leva ~9,9 s, contra ~4,4 s do caminho antigo, que usa mais
  memória. As 11 páginas de `list_requests`, com cabeçalho e detalhe, levam ~70 ms.
  `open_session`, `import_*` e `stop_session` ainda são comandos síncronos; passá-los
  para `spawn_blocking` fica como próximo passo.
- O que domina é a `SessionV1` tipada (~1.160 MiB, como o `lazy` do docs/18). P6/P8
  reduziriam isso no core.
- Não medido: a memória do WebView. Os resumos de 20 mil requisições somam ~5 MB de
  JSON na transferência.

Reproduzir:

```
cd src-tauri && cargo build --release --example mem_open
./target/release/examples/mem_open paged  /tmp/big20k
./target/release/examples/mem_open legacy /tmp/big20k
```
