# Experiment `contract-h2` — h2

- Browser: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- Initial URL: `https://127.0.0.1:8782/setcookie`

## `GET /setcookie`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | reordenada (mesmo multiconjunto) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicates 7).
- CDP headers object: duplicatas fundidas (mesmo conjunto de nomes); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /favicon.ico`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /page`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (15 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /setcookie`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicates 7).
- CDP headers object: duplicatas fundidas (mesmo conjunto de nomes); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /setcookie?via=img`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, x-scrapelens-order, set-cookie, set-cookie, set-cookie, set-cookie, x-scrapelens-endpoint, cache-control, server, content-length` | reordenada (mesmo multiconjunto) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: reordenada (mesmo multiconjunto) (duplicates 7).
- CDP headers object: duplicatas fundidas (mesmo conjunto de nomes); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /echo-order?repeated=1`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, user-agent, x-dup, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-order, x-scrapelens-tag, User-Agent, x-dup` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-dup, x-order, x-scrapelens-tag` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /echo-order?concurrent=1`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?concurrent=1`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?after=cookies`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /redirect?n=2`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).

## `GET /redirect?n=1`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).

## `GET /redirect?n=0`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `User-Agent, Referer` | subconjunto (17 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `POST /echo`

Server reference (decoded order): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, x-order, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `x-order, sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (16 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-order` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `POST /echo`

Server reference (decoded order): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority`
Observed duplicates: ['cookie']

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, cookie, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (16 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length` | idêntica (nome e caixa) |
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicates 0).
- CDP headers object: reordenada (mesmo multiconjunto); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.
