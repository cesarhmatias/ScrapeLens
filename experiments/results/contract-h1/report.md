# Experimento `contract-h1` — h1

- Navegador: `Chrome/156.0.8078.48`
- User-Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36`
- URL inicial: `http://127.0.0.1:8781/setcookie`

## `GET /setcookie`

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
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /favicon.ico`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /page`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | subconjunto (12 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User, Upgrade-Insecure-Requests, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /setcookie`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /setcookie?via=img`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, set-cookie, x-scrapelens-order, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: duplicatas fundidas (mesmo conjunto de nomes); ordenado ASCII=True; valores fundidos=2.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /echo-order?repeated=1`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, x-order, sec-ch-ua-platform, x-scrapelens-tag, sec-ch-ua, User-Agent, x-dup, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, sec-ch-ua, sec-ch-ua-mobile, x-order, x-scrapelens-tag, User-Agent, x-dup` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-dup, x-order, x-scrapelens-tag` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /echo-order?concurrent=1`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /echo-order?concurrent=1`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /echo-order?after=cookies`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, sec-ch-ua-mobile` | subconjunto (11 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-proto, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `GET /redirect?n=2`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |

## `GET /redirect?n=1`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `-` | não observada |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `-` | não observada |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, location, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |

## `GET /redirect?n=0`

Referência do servidor (ordem decodificada): `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, sec-ch-ua-mobile, Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `User-Agent, Referer` | subconjunto (14 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Cookie, Host, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-redirects, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `POST /echo`

Referência do servidor (ordem decodificada): `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, x-order, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `x-order, sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (13 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, content-type, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, x-order` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).

## `POST /echo`

Referência do servidor (ordem decodificada): `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie`
Duplicatas observadas: nenhuma

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) decodificada | servidor JSONL | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | referência |
| (b) codificador | NetLog `HTTP_TRANSACTION_SEND_REQUEST_HEADERS` | `Host, Connection, Content-Length, Pragma, Cache-Control, sec-ch-ua-platform, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Referer, Accept-Encoding, Accept-Language, Cookie` | idêntica (nome e caixa) |
| (a) fonte | CDP `requestWillBeSent.headers` | `sec-ch-ua-platform, Referer, User-Agent, sec-ch-ua, content-type, sec-ch-ua-mobile` | subconjunto (13 nomes ausentes) |
| (a) fonte | CDP `requestWillBeSentExtraInfo.headers` | `Accept, Accept-Encoding, Accept-Language, Cache-Control, Connection, Content-Length, Cookie, Host, Origin, Pragma, Referer, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, User-Agent, content-type, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform` | reordenada (mesmo multiconjunto) |

Resposta (Set-Cookie / duplicatas):

| Camada | Fonte | Ordem | Veredito |
|---|---|---|---|
| (c) escrita | servidor JSONL | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | referência |
| (a) leitura | NetLog `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` | `content-type, x-scrapelens-echo-len, x-scrapelens-body-truncated, x-scrapelens-endpoint, cache-control, server, content-length, connection` | idêntica (nome e caixa) |
- CDP `headersText` (bruto): idêntica (nome e caixa).
- CDP objeto de headers: reordenada (mesmo multiconjunto); ordenado ASCII=True; valores fundidos=0.
- `ExtraInfo.headers` está em ordem ASCII/case-sensitive, não na ordem do fio.
- Ambiguidade: 2 eventos NetLog casaram com este caminho.
- `responseReceivedExtraInfo.headersText` presente (ordem bruta da resposta em h1).
