# Experimento `h3-set3` — h3

- Navegador: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- URL inicial: `https://127.0.0.1:8783/set3`

## `GET /set3`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | referência |
| (b) codificador | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, pragma, priority, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, upgrade-insecure-requests, user-agent` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, set-cookie, content-length` | referência |
| (a) leitura | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, set-cookie, set-cookie, set-cookie, content-length` | idêntica (nome e caixa) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 3).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.

## `GET /echo-order?from=set3`

Referência do servidor (ordem decodificada): `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority`
Duplicatas observadas: ['cookie']

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, cookie, cookie, priority` | referência |
| (b) codificador | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (b) pré-sessão | NetLog `HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS` | `:method, :authority, :scheme, :path, pragma, cache-control, sec-ch-ua-platform, user-agent, sec-ch-ua, sec-ch-ua-mobile, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, referer, accept-encoding, accept-language, cookie, priority` | duplicatas fundidas (mesmo conjunto de nomes) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `:authority, :method, :path, :scheme, accept, accept-encoding, accept-language, cache-control, cookie, pragma, priority, referer, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, user-agent` | duplicatas fundidas (mesmo conjunto de nomes) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | referência |
| (a) leitura | NetLog `QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length` | idêntica (nome e caixa) |

- NetLog no nível de sessão fundiu valores duplicados com `\x00`.
- Evento alternativo `HTTP_TRANSACTION_READ_RESPONSE_HEADERS`: idêntica (nome e caixa) (duplicatas 1).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=1.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
