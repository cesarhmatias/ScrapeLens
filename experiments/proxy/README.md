# experiments/proxy/ — proxy route fidelity (test only)

Question: does a proxied capture keep the bytes the origin receives, and does every
target go through the proxy? Routes compared, against the same synthetic page:

| variant | Chrome gets | relay / upstream |
|---|---|---|
| `direct` | no proxy (host rules map the names) | none |
| `socks-open` | `socks5://` upstream, no credentials | upstream SOCKS5, open |
| `relay-open` | `socks5://` local relay | relay connects directly (control for the relay) |
| `relay-socks-auth` | `socks5://` local relay | relay → upstream SOCKS5 with user/pass |
| `relay-http-auth` | `socks5://` local relay | relay → upstream HTTP CONNECT with Basic auth |

Everything is synthetic: `origin.py` (raw HTTP/1.1, wire order kept) serves `/page`
with an iframe, a worker, a popup and a WebRTC page. The names `site-a.test` and
`site-b.test` exist only inside the test proxies (`proxies.py`); they never resolve
on this machine. `proxies.py` is stdlib-only; the relay is a stand-in for the Rust one.

## Run

    cd experiments/proxy
    python3 run_proxy.py --out <dir>          # ~2 min, Chrome from CHROME or the default path
    python3 analyze_proxy.py --out <dir>      # summary.json and the table

Ports: 18701 origin, 18702 upstream SOCKS, 18703 upstream HTTP, 18704 relay, 19457 DevTools.
Chrome runs with a temporary profile inside `<dir>` and is stopped by the script.

## Result (Chrome 156, macOS, headless)

| variant | origin requests | wire identical to direct | netlog hosts | CONNECTs ok | site targets via proxy |
|---|---|---|---|---|---|
| direct | 12 | — | 10 | 0 | — |
| socks-open | 12 | yes | 10 | 8 | site-a.test, site-b.test |
| relay-open | 12 | yes | 10 | 8 | site-a.test, site-b.test |
| relay-socks-auth | 12 | yes | 10 | 8 | site-a.test, site-b.test |
| relay-http-auth | 12 | yes | 10 | 8 | site-a.test, site-b.test |

- **Wire:** request lines and header names/values, with duplicates, are identical to the
  direct run for every request (compared as a multiset per request line, since concurrent
  requests arrive in any order; the WebRTC report's Content-Length is excluded because its
  ICE values are random). The SOCKS5 tunnel is opaque, so no header is added or rewritten.
- **Protocol:** Chrome sends domain names (ATYP 0x03) to SOCKS5, so the relay and the
  upstream resolve names; no target IP is seen. Plain `http://` targets work through the
  same tunnel.
- **Credentials:** the password and its Base64 `user:pass` appear in zero files of any
  variant (`summary.json` → `secret_hits`), including the NetLog and Chrome's stderr.
  Chrome's command line has only the relay address.
- **Every target via proxy:** all `site-a.test` and `site-b.test` requests (page, iframe,
  worker, popup) reached the proxy.

### Not confirmed (decisions needed)

1. **Chrome's own traffic bypasses the proxy.** `dns.google:443` (secure-DNS requests) and
   `csp.withgoogle.com:443` go direct in every proxied variant. The DoH queries decoded
   only `www.gstatic.com`; the synthetic target names never went to DoH. Neither
   `--disable-async-dns` nor `--dns-over-https-mode=off` with `--disable-features=DnsOverHttps`
   stopped it. A managed Chrome policy is probably needed (not tried).
2. **WebRTC.** `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` did not remove
   the host candidates in any variant. The candidates are mDNS names (`*.local`), so no raw
   IP is in the SDP, and no server-reflexive candidate was gathered (no ICE servers). The
   UDP socket still exists, so "does not bypass the proxy" is unproven.
3. **Not tested:** h2 over the tunnel (the origin is HTTP/1.1 only), HTTP/3 (expected
   absent through a proxy: the contract's session note covers it), CDP multi-session
   pairing for iframes/workers (`cdp_capture.mjs` attaches to the page only; coverage here
   comes from NetLog URLs and the origin log).
