# -*- coding: utf-8 -*-
# ScrapeLens — export Python (http.client) da requisição har-0002
# NÃO reproduz TLS nem fingerprint do navegador (JA3/JA4, frames, HPACK); apenas a requisição HTTP.
# Preserva ordem e duplicatas de headers; pseudoheaders HTTP/2 não existem em HTTP/1.1.
# protocolo capturado: h1 · verificação dos headers: unverified
# ATENÇÃO: sequência de headers NÃO verificada.
# corpo: corpo não incluído: estado Unavailable (HAR não fornece postData)
# Contém credenciais/cookies se a sessão não foi sanitizada.

import http.client

conn = http.client.HTTPConnection("127.0.0.1", 8781, timeout=30)
conn.putrequest("GET", "/setcookie", skip_host=True, skip_accept_encoding=True)
conn.putheader("Accept", "*/*")
conn.putheader("Accept-Encoding", "gzip, deflate, br, zstd")
conn.putheader("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
conn.putheader("Cache-Control", "no-cache")
conn.putheader("Connection", "keep-alive")
conn.putheader("Cookie", "sc_page=fromjs")
conn.putheader("Host", "127.0.0.1:8781")
conn.putheader("Pragma", "no-cache")
conn.putheader("Referer", "http://127.0.0.1:8781/page")
conn.putheader("Sec-Fetch-Dest", "empty")
conn.putheader("Sec-Fetch-Mode", "cors")
conn.putheader("Sec-Fetch-Site", "same-origin")
conn.putheader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36")
conn.putheader("sec-ch-ua", "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"")
conn.putheader("sec-ch-ua-mobile", "?0")
conn.putheader("sec-ch-ua-platform", "\"macOS\"")
conn.endheaders()
resp = conn.getresponse()
print(resp.status, resp.reason)
print(resp.read().decode("utf-8", "replace"))
conn.close()
