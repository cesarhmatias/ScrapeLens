# Experimento `h1-plain` — h1

- Navegador: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- URL inicial: `http://127.0.0.1:8781/echo-order?case=plain`

## `GET /echo-order?case=plain`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User, Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=1.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /favicon.ico`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (10 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, x-resp-order, x-resp-order, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=1.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).
