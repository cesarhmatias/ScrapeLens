# Experimento `contract-h2` — h2

- Navegador: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- URL inicial: `https://127.0.0.1:8782/setcookie`

## `GET /setcookie`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicatas 7).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.

## `GET /favicon.ico`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /page`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (15 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /setcookie`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicatas 7).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.

## `GET /setcookie?via=img`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicatas 7).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /echo-order?repeated=1`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-order, x-scrapelens-tag, User-Agent, x-dup` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-dup, x-order, x-scrapelens-tag` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /echo-order?concurrent=1`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.

## `GET /echo-order?concurrent=1`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.

## `GET /echo-order?after=cookies`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /redirect?n=2`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).

## `GET /redirect?n=1`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).

## `GET /redirect?n=0`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `User-Agent, Referer` | subconjunto (17 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `POST /echo`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `x-order, sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (16 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-order` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.

## `POST /echo`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (16 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | referência |
| (a) leitura | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 0).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 4 eventos NetLog casaram com este caminho.
