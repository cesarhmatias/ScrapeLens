# Experiment `h2-page` — h2

- Browser: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- Initial URL: `https://127.0.0.1:8782/setcookie`

## `GET /setcookie`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | identical (name and case) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 2).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=2.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /echo-order?from=afterjs`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=page`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=page2`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `POST /echo`

Server reference (decoded order): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile` | subset (16 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=jsheaders`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `x-zeta, x-alpha, sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-alpha, x-dup, x-mid, x-zeta` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /page`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subset (15 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /echo-order?from=afterjs`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=page`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=page2`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `POST /echo`

Server reference (decoded order): `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, content-length, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, content-type, sec-ch-ua-mobile, accept, origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, Content-Type, sec-ch-ua-mobile` | subset (16 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, content-length, content-type, cookie, origin, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.

## `GET /echo-order?from=jsheaders`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority, cookie` | reference |
| (b) encoder | NetLog `HTTP2_SESSION_SEND_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-zeta, x-alpha, sec-ch-ua-platform, sec-ch-ua, sec-ch-ua-mobile, x-mid, user-agent, x-dup, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | reordered (same multiset) |
| (a) source | CDP `requestWillBeSent.headers` | `x-zeta, x-alpha, sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-mid, User-Agent, x-dup` | subset (14 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent, x-alpha, x-dup, x-mid, x-zeta` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `HTTP2_SESSION_RECV_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
- Ambiguity: 4 NetLog events matched this path.
