# Experiment `h1-cookieprobe` — h1

- Browser: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- Initial URL: `http://127.0.0.1:8781/page-longcookies`

## `GET /page-longcookies`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | idêntica (nome e caixa) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (11 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User, Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (raw): idêntica (nome e caixa).
- CDP headers object: duplicatas fundidas (mesmo conjunto de nomes); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=longcookies`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (raw): idêntica (nome e caixa).
- CDP headers object: duplicatas fundidas (mesmo conjunto de nomes); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).
