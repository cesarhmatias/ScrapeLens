# Experimento `h2-ordered` — h2

- Navegador: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- URL inicial: `https://127.0.0.1:8782/echo-order?case=ordered`

## `GET /echo-order?case=ordered`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | divergente |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept-encoding, accept-language, cache-control, pragma, priority, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, user-agent, x-mixed-case, x-rep, x-seq` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | idêntica (nome e caixa) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 1).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=1.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /favicon.ico`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (13 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | idêntica (nome e caixa) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 1).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=1.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
