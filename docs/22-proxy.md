# 22. Capturing through a proxy

One proxy link per capture sends the browser's traffic through that proxy. It works in the desktop app (**Proxy** field) and in MCP (`start_capture.proxy`).

## Accepted links

| Form | Meaning |
| --- | --- |
| `http://[user:pass@]host[:port]` | HTTP proxy (default port 80) |
| `https://[user:pass@]host[:port]` | Proxy reached over TLS (default port 443) |
| `socks5://[user:pass@]host[:port]`, `socks5h://...` | SOCKS5 with remote DNS (default port 1080) |
| `[user:pass@]host:port` | No scheme: same as `http://` |
| `host:port:user:pass` | Common provider format: same as `http://user:pass@host:port` |

- Credentials are percent-decoded. IPv6 literals in brackets are accepted.
- Refused with a clear error: other schemes (including `socks4`), a path other than empty or `/`, a query, a fragment, control characters, port 0 or above 65535, an empty host.
- Out of scope: PAC files, per-request proxies, proxy lists and rotation.

## Credentials

The password exists only in the capture process memory and on the connection to the upstream proxy. It is never written to Chrome's command line, `session.json`, `cdp-events.jsonl`, `netlog.json`, `cdp-bodies.jsonl`, logs, errors, events, MCP output, preferences or exports.

- **App:** preferences keep only `scheme://host:port`. The password stays in memory until the app closes, then you type the link again.
- **MCP:** prefer `proxy: "env"`, which reads the link from the server's `SCRAPELENS_PROXY_URL` environment variable, so the password does not pass through the LLM. The variable is ignored unless `"env"` is requested. Confirmations and results show only `scheme://host:port` and whether credentials are set.

## Routes

| Case | Route | What Chrome uses |
| --- | --- | --- |
| No credentials and no allowlist | `direct` | `--proxy-server=scheme://host:port` |
| Credentials or an allowlist | `relay` | A local relay on `127.0.0.1` that speaks SOCKS5 to Chrome and adds authentication toward the upstream proxy |

Chrome does not accept credentials in `--proxy-server` and does not support SOCKS5 authentication, so the relay answers the upstream proxy. The relay does not parse or rewrite application bytes.

An `https://` proxy on the relay route uses TLS with the system trust store. Certificate checks are always on, and a certificate the system does not trust stops the capture with a clear error.

With an allowlist, the relay refuses any destination the allowlist does not permit, before contacting the upstream proxy.

## Keeping traffic on the proxy

Only the dedicated capture profile is changed, never system policy and never your own browser profile:

- DNS over HTTPS is off for the profile.
- WebRTC is limited with `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` and the matching profile preferences.
- Without an allowlist, `--host-resolver-rules` blocks local name resolution, except loopback and the proxy host. Anything that tries to leave directly fails instead of leaking.

Allowed exceptions: resolving the proxy's own host name, when the link uses a name, and loopback targets.

## Limits

- **No HTTP/3:** a proxied capture does not use QUIC. The session carries a note saying so.
- **Loopback targets skip the proxy:** this is Chrome's default in production.
- **Exported scripts do not use the proxy:** cURL, Python and priming scripts connect directly, so they can leave from a different IP than the capture.
- **Validation:** proxies were validated with local test proxies, not against commercial providers.

## Session record

Sessions record the proxy in an optional field, with no `schemaVersion` change:

```json
"capture": { "proxy": { "scheme": "http", "host": "proxy.example", "port": 8080, "authenticated": true, "route": "relay" } }
```

- **Sanitized export:** keeps only `scheme` and `authenticated`.
- **Full export:** also keeps `host`, `port` and `route`. Credentials appear in no export.
- **Direct route:** `netlog.json` holds the proxy address in raw form, and raw artifacts appear only in the full export.
- **Redaction:** the sanitizer always redacts `Proxy-Authorization`, `Proxy-Authenticate` and credentials embedded in URLs.

## Failures

These appear as actionable messages, with no credentials, on both routes:

- proxy unreachable, or DNS failure for the proxy host;
- authentication refused (HTTP 407 or SOCKS5 authentication failure);
- target refused by the proxy;
- invalid link.

Measurements and experiment scripts are in [`experiments/proxy/`](../experiments/proxy/). The session field is defined in [`core/CONTRACT-V1.md`](../core/CONTRACT-V1.md), and the MCP parameter in [`16-mcp-contract.md`](16-mcp-contract.md).
