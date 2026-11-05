# Experiment `h1-page` — h1

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=afterjs`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=page`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=page2`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `POST /echo`

Server reference (decoded order): `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile` | subset (13 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Content-Type, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=jsheaders`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `x-zeta, x-alpha, sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-alpha, x-dup, x-mid, x-zeta` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=afterjs`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=page`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=page2`

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
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `POST /echo`

Server reference (decoded order): `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile` | subset (13 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Content-Type, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).

## `GET /echo-order?from=jsheaders`

Server reference (decoded order): `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | reference |
| (b) encoder | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `x-zeta, x-alpha, sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup` | subset (11 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-alpha, x-dup, x-mid, x-zeta` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | reference |
| (a) read | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | identical (name and case) |
- CDP `headersText` (raw): identical (name and case).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 2 NetLog events matched this path.
- `responseReceivedExtraInfo.headersText` present (raw response order in h1).
