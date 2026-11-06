# experiments/proxy/acceptance/ — proxy link acceptance (v0.1.2)

Automated acceptance of the proxy link, on the real capture paths and without any
window or MCP confirmation dialog. Test only: loopback origins, local test proxies
(`testserver/`), synthetic credentials, no paid proxy.

| Piece | What it is |
|---|---|
| `run_acceptance.py` | Starts the origin and the test proxies, runs the driver, scans every output, writes `results.json` |
| `driver/` | Small Rust crate (own workspace). Calls `scrapelens_capture::run` (App path) and `BrowserCapture` (controlled path behind MCP `start_capture`) |
| `RESULTS.md` | The table of the last run, without local paths |

## Requirements

- Google Chrome stable installed (the capture uses it with a dedicated profile per run).
- `testserver/` built: `cd testserver && cargo build`.
- The driver built: `cd driver && cargo build`.
- macOS or Linux with `lsof` and `pgrep`. Ports 18781–18808 and 18899 must be free.

## Run

```sh
cd experiments/proxy/acceptance
python3 run_acceptance.py --out <durable-folder>                   # everything
python3 run_acceptance.py --out <durable-folder> --only failures,fidelity
```

Sections: `failures`, `fidelity`, `security`, `export`, `regression`, `mcp`, `egress`; plus `netlog` (re-check only).
Keep `--out` outside the repository: it holds session folders, logs and the raw
evidence of the test proxies. Only the summary belongs in version control.

A full run refuses an existing `--out`. It first builds the driver and the core from one
committed revision (`git archive HEAD`, recorded in `<out>/pinned.json`), so the result does not
depend on the working tree. `--only netlog` re-checks an earlier run in place, without captures.
`summarize.py <out>/results.json > RESULTS.md` writes the repository-safe table.

## What each section checks

- **failures**: unreachable proxy, refused credentials, refused destination (direct and
  relay routes), and four invalid links. A pass needs a proxy-specific message in the
  error or in the notice; a generic Chrome error (`ERR_*`) does not pass.
- **fidelity**: the origin's view of the same probe URL with no proxy, with a direct
  route and with a relay route, for HTTP/1.1 and HTTP/2. Header names, order and values
  must match (hop-by-hop headers such as `Connection` are compared apart and reported). The origin must never see `CONNECT`, `Proxy-Authorization` or
  `Proxy-Connection` as request headers.
- **security**: percent-encoded password, allowlist refusal before the proxy is
  contacted, untrusted HTTPS proxy certificate, and a scan of every file, stdout and
  stderr for the password and its Base64 form.
- **export**: the sanitized export has no proxy `host` or `port`; the cURL and Python
  scripts say they do not use the proxy; the desktop dialog carries the notice (checked in
  the source only, the window is not driven).
- **regression**: a session with no proxy, from this build and from `f69e9dc`, must match
  ignoring timestamps, ids, durations, paths and an absent `capture.proxy`.
- **mcp**: `SCRAPELENS_PROXY_URL` is ignored without `"env"`, and the confirmation text
  shows no credential (runs `mcp/tests/live.rs proxy_env_is_read_only`).
- **egress** (macOS, indirect): samples the TCP peers of the capture's Chrome processes
  while a relay capture runs; any non-loopback peer is reported. DNS and the proxy's own
  host name are outside this check.

## Limits

- The Docker packet observer (`experiments/proxy/docker/`) is not run by this harness.
  On macOS the egress evidence is the sampled peer list above, and the report says so.
- The desktop window and its preference file are not driven; the MCP confirmation dialog
  is not answered (the controlled path is called directly after the same checks).
- Proxies here are local test proxies. They are not verified against commercial providers.
