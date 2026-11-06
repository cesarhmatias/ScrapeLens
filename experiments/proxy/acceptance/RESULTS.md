# Proxy acceptance: results (v0.1.2)

Run: `run_acceptance.py` (full, all sections), driver and core built from one committed
revision, `17cffdfdba6ed9badfba7738bbe046594a7bdab1`. Synthetic data only: loopback origin, local
test proxies (`testserver/`), a dedicated Chrome profile per capture, no window. Not verified
against commercial providers.

## Findings

1. **Direct route: refused credentials and refused destination give no proxy message.**
   With the HTTP proxy on the direct route (`--proxy-server`), a `407` or a `403` from the proxy
   reaches the session as `ERR_INVALID_AUTH_CREDENTIALS` and `ERR_HTTP_RESPONSE_CODE_FAILURE`.
   Neither code is in the mapping, so the session carries only a generic `cdp.request_failed`.
   The same refusals on the relay route give the actionable message. Cause: the code table in
   `capture/src/relay.rs` (`chrome_proxy_failure`) has no entry for those two codes; the
   consumer is `capture/src/lib.rs` (`proxy_failures_from_cdp`). Not fixed here (capture owner).
2. **Unreachable proxy is not treated alike on the two routes.** On the relay route the
   start fails with the actionable error. On the direct route the start succeeds and the
   message is a notice (`capture.proxy_failure`). Both messages are actionable; the difference
   in outcome is for the capture owner to decide.
3. **Exported scripts** carry the notice that they do not use the proxy. It was added by Core
   in `03b3238`; before that commit the cURL export had no such notice. Checked here on the pinned
   revision: `export-curl` and `export-python` both carry it, with no host, port or credential.
4. **The sanitized export has no proxy host or port** (`capture.proxy` keeps `scheme` and
   `authenticated`). The proxy port does not appear anywhere in the sanitized files.

## Comparisons and how they were made

- **Fidelity** compares what the origin received for the same probe URL, with no proxy, a direct
  route and a relay route, for HTTP/1.1 and HTTP/2. The probe name in the path is normalized
  (it differs by design). Hop-by-hop headers (`Connection`, `Proxy-*`, ...) are compared apart: on the
  direct HTTP/1.1 route the test proxy rewrites `Connection` (`keep-alive` to `close`); this is
  the proxy's rewriting, not the product's. Everything else is compared by name, order and value.
- **Regression** compares a no-proxy session from this commit with one from `f69e9dc`,
  ignoring timestamps, ids, durations, paths, attachment file names (they embed request ids),
  provenance metadata and the origin's connection and stream counters. The response body
  is compared by its canonical JSON. A mutation control and an empty-match control were run
  on the comparison itself: both are detected.
- **Egress** is indirect on macOS: the TCP peers of the capture's Chrome processes were sampled
  every 0.4 s during a relay capture (30 samples). The Docker packet observer
  (`experiments/proxy/docker/`) was not run.

## Not run

- The App window, the **Proxy** field and the preference file: the export dialog was checked in the
  source only (its row is marked not executed).
- The Docker packet observer for egress.
- The MCP confirmation dialog: the controlled path is called directly, after the same checks.
- `netlog.request_without_url`: not triggered in these captures. The honest-state check
  (probe listed, not more certain than the no-proxy baseline) passed on the direct route.

## Details

Totals: falhou 2, não executado 1, passou 31.


## Falhas

| Criterion | Case | Result | Detail |
|---|---|---|---|
| unreachable | direct | passou | actionable, shown as notice: proxy: the proxy http://127.0.0.1:18899 could not be reached: check the host name, the port and the network, then try again |
| unreachable | relay | passou | actionable, shown as error: the proxy http://127.0.0.1:18899 could not be reached: check the host name, the port and the network, then try again |
| auth_refused | direct | falhou | no proxy-specific message; session warnings=['cdp.request_failed', 'cdp.unhandled_events', 'correlate.netlog_unmatched', 'netlog.time_unit_detected']; generic page failures=1 |
| auth_refused | relay | passou | actionable, shown as notice: proxy: the proxy http://127.0.0.1:18806 refused the credentials (HTTP 407) |
| target_refused | direct | falhou | no proxy-specific message; session warnings=['cdp.request_failed', 'cdp.unhandled_events', 'correlate.netlog_unmatched', 'correlate.unmatched', 'netlog.time_unit_detected']; generic page failures=1 |
| target_refused | relay | passou | actionable, shown as notice: proxy: the proxy http://127.0.0.1:18807 refused site-a.test:18781 (HTTP 403) |
| invalid link | unsupported scheme | passou | socks4 is not supported: use socks5 or socks5h |
| invalid link | path present | passou | the proxy link must not have a path, query or fragment (percent-encode special characters in credentials) |
| invalid link | port out of range | passou | the proxy port must be a number from 1 to 65535 |
| invalid link | control character | passou | the proxy link contains a control character |

## Fidelidade

| Criterion | Case | Result | Detail |
|---|---|---|---|
| headers h1 vs no proxy | direct | passou | end-to-end order=same values=same proto=http/1.1/http/1.1; hop-by-hop headers rewritten by the proxy: ['connection'] (excluded) |
| headers h1 vs no proxy | relay | passou | end-to-end order=same values=same proto=http/1.1/http/1.1; hop-by-hop headers rewritten by the proxy: none (excluded) |
| no CONNECT/Proxy-Authorization as request header | h1-none | passou | 1 request(s), none with proxy headers |
| no CONNECT/Proxy-Authorization as request header | h1-direct | passou | 1 request(s), none with proxy headers |
| no CONNECT/Proxy-Authorization as request header | h1-relay | passou | 1 request(s), none with proxy headers |
| headers h2 vs no proxy | direct | passou | end-to-end order=same values=same proto=h2/h2; hop-by-hop headers rewritten by the proxy: none (excluded) |
| headers h2 vs no proxy | relay | passou | end-to-end order=same values=same proto=h2/h2; hop-by-hop headers rewritten by the proxy: none (excluded) |
| no CONNECT/Proxy-Authorization as request header | h2-none | passou | 1 request(s), none with proxy headers |
| no CONNECT/Proxy-Authorization as request header | h2-direct | passou | 1 request(s), none with proxy headers |
| no CONNECT/Proxy-Authorization as request header | h2-relay | passou | 1 request(s), none with proxy headers |

## Seguranca

| Criterion | Case | Result | Detail |
|---|---|---|---|
| password percent-encoded works | relay http auth | passou | 27 authenticated relayed connection(s) in the proxy evidence |
| allowlist refuses before the proxy | relay, controlled | passou | navigate refused (url_not_allowed); 0 proxy records and 0 origin records for site-b.test |
| untrusted HTTPS proxy certificate refused | relay | passou | error: the proxy https://127.0.0.1:18803 presented a certificate the system does not trust (invalid peer certificate: UnknownIssuer). Install the proxy CA in the system trust store, or check the host name |
| no password or Base64 in any output | all files, stdout, stderr, logs | passou | 0 hits in 3086 file(s) under the run folder |

## Exportacao

| Criterion | Case | Result | Detail |
|---|---|---|---|
| session records the proxy (no credentials) | relay h1 | passou | capture.proxy={"scheme": "http", "host": "127.0.0.1", "port": 18802, "authenticated": true, "route": "relay"} |
| sanitized export without host/port | relay h1 | passou | capture.proxy={"scheme": "http", "authenticated": true}; proxy port in output: [] |
| exported script warns it does not use the proxy | export-curl | passou | warning=yes; host/port/credential in script=no |
| exported script warns it does not use the proxy | export-python | passou | warning=yes; host/port/credential in script=no |
| export dialog shows the notice | App Export.tsx (source) | não executado | source has the notice element; the dialog itself was not driven (no window) |

## Regressao

| Criterion | Case | Result | Detail |
|---|---|---|---|
| sessions without proxy identical to f69e9dc | h1 | passou | identical (ignoring timestamps, ids, durations, paths, absent capture.proxy) |

## MCP

| Criterion | Case | Result | Detail |
|---|---|---|---|
| SCRAPELENS_PROXY_URL ignored without "env"; confirmation has no secret | mcp prepare | passou | cargo test mcp/tests/live.rs proxy_env_is_read_only: 1 passed |

## Egress

| Criterion | Case | Result | Detail |
|---|---|---|---|
| Chrome peers are loopback only (macOS, indirect) | relay | passou | 29 sample(s), 0 non-loopback peers |

## Fidelidade-NetLog

| Criterion | Case | Result | Detail |
|---|---|---|---|
| direct route: no false 'verified' from NetLog | h2 direct | passou | probe listed=True; request_without_url raised=False; verification: no proxy=partial, direct=partial |
| direct route: no false 'verified' from NetLog | h1 direct | passou | probe listed=True; request_without_url raised=False; verification: no proxy=verified, direct=verified |
