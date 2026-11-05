# Experiment `h3-ordered` — h3

- Browser: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- Initial URL: `https://127.0.0.1:8783/echo-order?case=ordered`

## `GET /echo-order?case=ordered`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | reference |
| (b) encoder | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | identical (name and case) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, x-rep, x-seq, x-mixed-case, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, user-agent, accept-encoding, accept-language, priority` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | divergent |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept-encoding, accept-language, cache-control, pragma, priority, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, user-agent, x-mixed-case, x-rep, x-seq` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.

## `GET /favicon.ico`

Server reference (decoded order): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority`
Observed duplicates: none

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) decoded | server JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | reference |
| (b) encoder | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | identical (name and case) |
| (b) pre-session | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, priority` | identical (name and case) |
| (a) source | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subset (13 names missing) |
| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | reordered (same multiset) |

Response (Set-Cookie / duplicates):

| Layer | Source | Order | Verdict |
|---|---|---|---|
| (c) written | server JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | reference |
| (a) read | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | identical (name and case) |

- NetLog at session level merged duplicate values with `\x00`.
- Alternative event `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: identical (name and case) (duplicates 1).
- CDP headers object: duplicates merged (same name set); ASCII-sorted=True; merged values=1.
- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.
