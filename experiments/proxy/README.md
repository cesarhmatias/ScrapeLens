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

1. **Chrome's own traffic (corrected).** Secure DNS (`dns.google:443`) left directly in the
   first run. `csp.withgoogle.com` was a false positive of the host extraction (it appeared
   only inside `report-to` response headers); the extraction now reads `params.url` only.
   The dedicated profile's `Local State` `dns_over_https.mode = "off"` removes the
   `dns.google` requests (see the prefs run below).
2. **WebRTC (resolved by the profile preferences, see below).** The flag alone did not remove
   the host candidates (mDNS names only). With the profile preferences the candidate list
   is empty.
3. **Not tested:** h2 over the tunnel (the origin is HTTP/1.1 only), HTTP/3 (expected
   absent through a proxy: the contract's session note covers it), CDP multi-session
   pairing for iframes/workers (`cdp_capture.mjs` attaches to the page only; coverage here
   comes from NetLog URLs and the origin log).

## Live check of the product path

`live_check.sh <out>` runs the controlled capture (`capture/examples/proxy_live.rs`:
stable Chrome, CDP + NetLog, allowlist `site-a.test` and `site-b.test`) through the Rust
relay to a SOCKS5 test upstream that requires `exp-user` / a test password. It then
scans every output for the password and its Base64 (`secret hits total: 0` is the pass
condition). Last run: 9 CONNECTs through the upstream, 9 requests at the origin (page,
iframe, worker, popup), the session carries `capture.proxy` with `authenticated: true`,
`route: relay`, and the HTTP/3 note from core.

The upstream logs `error ConnectionError` twice: those are the two preflight connections
(the browser start and the capture each check that the proxy is reachable), closed at once.

## Follow-up (leader decisions): profile preferences, egress proof, real imports

Preferences in the dedicated profile only (no system policy): `Local State`
`dns_over_https.mode = "off"`; `Default/Preferences` `webrtc.ip_handling_policy =
"disable_non_proxied_udp"`, `webrtc.multiple_routes_enabled = false`,
`webrtc.nonproxied_udp_enabled = false`. The capture writes them into its temporary profile
when a proxy is set (`write_proxy_profile_prefs`).

### Egress proof (Docker, Chrome 157 linux/amd64, packet counters)

`docker/egress_check.sh` runs Chrome in a container whose OUTPUT chain drops everything
except the proxy (and UDP to a probe on the host, outside loopback, in the WebRTC cases).
The counters of the drop rules show what tried to leave by another route. Each case is
one headless `--dump-dom` of a synthetic page.

| case | route | what it proves | packets leaving other than the proxy | UDP to the STUN probe |
|---|---|---|---|---|
| `prefs-https` | HTTP proxy, prefs + WebRTC flag | HTTPS target | 0 | — |
| `bare-https` | HTTP proxy, no prefs | control | 0 | — |
| `socks-prefs-https` | SOCKS5 proxy, prefs | HTTPS target | 0 | — |
| `socks-bare-https` | SOCKS5 proxy, no prefs | control | 0 | — |
| `rules-direct-http` | HTTP proxy direct + fail-closed rule | plain HTTP target, loopback and proxy excluded | 0 | — |
| `prefs-webrtc-stun` | HTTP proxy, prefs + flag | WebRTC with a STUN server outside loopback, UDP allowed by the firewall | 0 | 0 |
| `bare-webrtc-stun` | HTTP proxy, no prefs | the same page, control | 1 (mDNS multicast) | **1 STUN binding request left directly** (48 bytes) |
| `noproxy-control` | no proxy | the observer works: a direct page to another host | 180 UDP/53 + 33 TCP | — |

The probe source appears as 127.0.0.1 because of Docker Desktop's NAT, so the packet is
evidence of an outgoing UDP datagram to the STUN address, not of the source IP.
`bare-https` and `socks-bare-https` show no DoH in the container; the DoH leak was
seen on macOS with SOCKS5 and default preferences (run `prefs1`, `dns.google` requests
in the NetLog) and removed by the preference. Known limit: the container runs Chrome 157
under emulation; the macOS runs use Chrome 156.

### Real captures through the App path, imported by the current core

`real_matrix.sh` runs `capture/examples/proxy_import.rs` (the common `run()` path,
`ignore_cert` for the synthetic TLS origin) on 14 routes: none; SOCKS5 and HTTP proxies
without and with credentials (the relay); HTTPS proxy without credentials (direct); HTTPS
proxy with credentials (refused). `analyze_real.py` reads `session.json`.

| route | target | route in session | auth | requests / attempts | protocol | connections with ip/port | HTTP/3 note |
|---|---|---|---|---|---|---|---|
| none | http / https | — | — | 10 / 10 | h1 | 1 of 2 (direct: kept) | no |
| socks5 open | http / https | direct | no | 10 / 10 | h1 | 0 of 2 | yes |
| socks5 + creds | http / https | relay | yes | 10 / 10 | h1 | 0 of 2 | yes |
| http open | http / https | direct | no | 10 / 10 | h1 | 0 of 2 | yes |
| http + creds | http / https | relay | yes | 10 / 10 | h1 | 0 of 2 | yes |
| https open | http / https | direct | no | 10 / 10 | h1 | 0 of 2 | yes |
| https + creds | http / https | refused at start | yes | — | — | — | — (message: "an https:// proxy cannot be used with credentials or an allowlist yet…"; exit 3; the password does not appear) |

All sessions: `networkState` absent (every request was sent), 9 of 10 requests paired with
NetLog in every route (the same as direct), no `secret` in any file of any capture.
The `https + creds` row is the first round, before the relay spoke TLS. The follow-up
below replaces that refusal.

Divergences from the contract (for core), first round, origin was HTTP/1.1:
- **Protocol.** Those proxied HTTPS requests report `h1`, from CDP. That matches the
  origin: the follow-up against an HTTP/2 origin reports `h2` from both CDP and NetLog.
- **`netlog.request_without_url`.** The first-round importer, before `0768d74`,
  reported 10 warnings per HTTP-proxy direct capture: "URL_REQUEST … has no URL in
  URL_REQUEST_START_JOB; not imported". The requests still came from CDP. That same
  importer reported the warning on the follow-up direct route and not on the relay.
  Reparsing those raw netlogs with `parse_netlog` after `0768d74` emits none. Core
  skips CONNECT headers logged on the socket source, so the warning is gone on the
  direct route as well.

### Fixtures

The synthetic fixtures of core (`core/tests/fixtures/netlog-proxy.json`) were not compared
line by line; the real captures above are the reference for the divergences listed.

### Follow-up (https credentials, HTTP/2, multi-target, direct-route failure)

`followup.sh` plus `analyze_followup.py`. Chrome is the capture's dedicated profile.
The HTTP/2 listener is `testserver serve --only h1,h2 --no-h3-on-h2-port` (h1
`127.0.0.1:18781`, h2 `127.0.0.1:18782`). Proxies: open HTTP `18791`, HTTP with
credentials `18792`, HTTPS with credentials `18793` (fixture CA via
`SCRAPELENS_TEST_PROXY_CA`; checks stay on). Every run exited 0. A scan of the
password and of the Base64 of `user:pass` in every output file was 0 hits.

| run | proxy | target | session proxy | imported requests | CDP `response.protocol` | match |
|---|---|---|---|---|---|---|
| `direct-http-page` | HTTP open, direct | `http://127.0.0.1:18781/page` | http direct, not authenticated | 11, all `h1` | `http/1.1` ×11 | 9 matched, 2 `ambiguous` (`/echo-order?concurrent=1`) |
| `direct-h2` | HTTP open, direct | `https://127.0.0.1:18782/page` | http direct, not authenticated | 11, all `h2` | `h2` ×11 | 9 matched, 2 `ambiguous` (same URL) |
| `relay-h2` | HTTP + credentials, relay | the same h2 page | http relay, authenticated, port 18792 | 11, all `h2` | `h2` ×11 | 11 matched |
| `direct-multi` | HTTP open, direct | `http://127.0.0.1:18781/multi/` | http direct | 22, all `h1` | `http/1.1` ×21 | 20 matched, 2 unmatched |
| `relay-multi` | HTTP + credentials, relay | the same `/multi/` | http relay, authenticated | 22, all `h1` | `http/1.1` ×21 | 20 matched, 2 unmatched (the same two) |
| `https-relay` | `https://` + credentials | `http://127.0.0.1:18781/healthz` | https relay, authenticated, port 18793 | 2, both `h1` | `http/1.1` ×2 | 2 matched |
| `direct-down` | `http://127.0.0.1:1`, direct | healthz | http direct, port 1 | 6, protocol `unknown` | — | 3 matched, 3 unmatched `data:image/png` (Chrome error page) |

HTTP/2. NetLog event names on `direct-h2` and `relay-h2` include `HTTP2_SESSION`,
`HTTP2_SESSION_INITIALIZED`, `HTTP2_SESSION_SEND_HEADERS`, `HTTP2_SESSION_RECV_HEADERS`
and `HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS` (18 on each run). CDP and NetLog
both say h2 when the origin is h2, through an HTTP proxy, direct and relay. The
first-round `h1` was the origin protocol. The raw NetLog of an h1 page also contains
`HTTP2_SESSION` events; those are not the imported page requests (those stay `h1` /
`http/1.1`).

`netlog.request_without_url` in the session files written at capture time, before
`0768d74`: 10 on `direct-http-page`, 11 on `direct-h2`, 9 on `direct-multi`, and
none on `relay-h2`, `relay-multi` or `https-relay`. Reparsing each saved `netlog.json`
with current `parse_netlog` emits 0 of that warning on every run, direct and relay.
The only NetLog warning left on each file is `netlog.time_unit_assumed` (1). The
two `ambiguous` rows on the direct page runs are both `/echo-order?concurrent=1`.
The relay pairs that h2 page 11/11.

Multi-target. All 16 markers (`main`, `popup`, `blank`, `oopif`, `worker`, `sw-own`,
`sw-intercept`, each GET and POST where the page sends both) have CDP and NetLog on
both routes. The two unmatched requests are the same on both routes: one empty URL,
and `GET /multi/sw-fetch?m=sw-intercept-1`. Both routes also warn
`cdp.service_worker_ambiguous` (1), `cdp.extra_info_without_request` (2) and
`cdp.response_extra_without_request` (2). The proxy does not add a pairing gap.
The 9 `netlog.request_without_url` warnings on the direct-multi session file are
from that pre-`0768d74` import. The reparse of its netlog emits 0, the same as the relay.

Direct-route failure. `direct-down` notice ends with
`; proxy: the proxy http://127.0.0.1:1 could not be reached: check the host name, the port and the network, then try again`.
Warning `capture.proxy_failure` (1) carries that sentence. The three unmatched
documents are Chrome's `data:image/png` error-page images, not a generic
`loadingFailed: net::ERR_*` reason.

The direct HTTP-proxy captures Core asked for (`direct-http-page` and `direct-h2`:
`session.json`, `netlog.json`, `cdp-events.jsonl`, `cdp-bodies.jsonl`) are handed
off outside the repo. They are not committed.
