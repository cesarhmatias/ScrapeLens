# Experiment `contract-h1` — h1

- Browser: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- Initial URL: `http://127.0.0.1:8781/setcookie`

## `GET /setcookie`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User, Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /favicon.ico`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /page`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subset (12 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User, Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /setcookie`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /setcookie?via=img`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?repeated=1`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-order, x-scrapelens-tag, User-Agent, x-dup` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-dup, x-order, x-scrapelens-tag` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?concurrent=1`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?concurrent=1`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?after=cookies`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /redirect?n=2`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `-` | not observed |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `-` | not observed |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |

## `GET /redirect?n=1`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `-` | not observed |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `-` | not observed |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |

## `GET /redirect?n=0`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `User-Agent, Referer` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `POST /echo`

Server reference (decoded order): `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `x-order, sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subset (13 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, content-type, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-order` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `POST /echo`

Server reference (decoded order): `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subset (13 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, content-type, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: reordered (same multiset); ASCII-sorted=True; merged values=0.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).
