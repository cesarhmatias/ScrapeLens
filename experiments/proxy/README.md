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
Divergences from the contract (for core):
- **Protocol.** The proxied HTTPS requests report `h1`, from CDP ("structure from CDP;
  checked by information only"). The contract says the protocol inside a tunnel is
  `unknown` unless the NetLog shows it. The NetLog here does not show the protocol inside the tunnel.
- **`netlog.request_without_url`.** The HTTP proxy direct route (absolute-URI requests)
  gives 10 warnings per capture: "URL_REQUEST … has no URL in URL_REQUEST_START_JOB; not
  imported". The requests still come from CDP.

### Fixtures

The synthetic fixtures of core (`core/tests/fixtures/netlog-proxy.json`) were not compared
line by line; the real captures above are the reference for the divergences listed.
