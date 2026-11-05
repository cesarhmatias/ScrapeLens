# experiments/ — capture fidelity proof

Question: **which sources and events preserve which header sequence in
HTTP/1.1, h2 and h3 in Chrome 156.0.8078.48?**

The consolidated result is in [`../docs/02-matriz-fidelidade.md`](../docs/02-matriz-fidelidade.md).
Everything here is synthetic, local (127.0.0.1) and temporary.

## What runs

| Part | File | Role |
|---|---|---|
| h1 server | `servers/h1_raw.py` | raw socket, no HTTP library: exact order and repetition |
| h2 server | `servers/h2_tls.py` | `h2`/HPACK: decoded list of pairs |
| h3 server | `servers/h3_quic.py` | `aioquic`/QPACK: decoded list of pairs |
| Launcher | `capture/launch_chrome.py` | temporary dedicated profile, debug only on 127.0.0.1, `--log-net-log` |
| CDP client | `capture/cdp_capture.mjs` | records raw Network.* events, without normalizing headers |
| Orchestrator | `run_experiment.py` | servers → Chrome → CDP → NetLog → analysis |
| Comparator | `compare.py` | three layers per request + `layers.json`/`report.md` |
| Derived HAR | `har_from_cdp.mjs` | HAR 1.2 from CDP (fixture; not the DevTools exporter) |
| Cross-check | `crosscheck_contract.py` | same pipeline against `testserver/` (Rust/httlib-hpack/quiche) |

Ports: **8781** h1, **8782** h2/TLS, **8783** h3/QUIC. Self-signed certificate
generated in `certs/` and waived in Chrome by `--ignore-certificate-errors-spki-list`
(nothing is installed on the system). h3 is forced with `--origin-to-force-quic-on`,
without disabling QUIC.

## Reproduce

```bash
cd experiments
python3 -m venv .venv
.venv/bin/pip install h2 aioquic
.venv/bin/python certs/gen_cert.py
.venv/bin/python run_experiment.py --all     # 15 experiments, ~5 min
.venv/bin/python compare.py                  # layers.json + report.md + matrix.json
node har_from_cdp.mjs results/h1-page
```

A single experiment:

```bash
.venv/bin/python run_experiment.py --exp h2-ordered
.venv/bin/python compare.py
```

Cross-check against the contract servers (read-only on
`testserver/` and `fixtures/`):

```bash
.venv/bin/python crosscheck_contract.py --proto all   # h1, h2 and h3
```

The `testserver/` binary is auto-detected (Rust `target/{release,debug}` or Go
`bin/`), so switching the language of the reference servers does not break this
script. To point at another build: `--bin PATH` or `SCRAPELENS_TESTSERVER_BIN`.

Result: h1 14/14 identical; h2 confirms the merged `cookie` in the log; **h3 fails
on the contract server** (`ERR_QUIC_PROTOCOL_ERROR` / `CERTIFICATE_VERIFY_FAILED`,
also reproduced with an `aioquic` client), so the h3 line comes from the mock.

`run_experiment.py --list` shows the names. Each run writes to
`results/<experiment>/`:

- `plan.json` — URLs, mode (`native`/`ordered`), injected headers;
- `cdp-events.jsonl` — every Network.* event in emission order;
- `fetch-decisions.jsonl` — header list delivered to `Fetch.continueRequest`;
- `chrome-netlog.json` — NetLog (`--net-log-capture-mode=Everything`);
- `server-h{1,2,3}.jsonl` — reference: decoded pairs + response headers;
- `layers.json` — the three layers compared per request;
- `report.md` — human-readable report; `run.json` — Chrome version and NetLog integrity.

## Experiments

| Name | What it exercises |
|---|---|
| `h1-plain` / `h2-plain` / `h3-plain` | simple GET navigation |
| `h1-page` / `h2-page` / `h3-page` | `/setcookie` (2× Set-Cookie) and `/page`: each document fires 2 GET, 1 POST and 1 fetch with `Headers` from the Fetch API, all with cookies |
| `h1-ordered` / `h2-ordered` / `h3-ordered` | order + duplicates imposed by `Fetch.continueRequest` |
| `h1/h2/h3-cookieprobe` | 3 long-value cookies via `document.cookie` |
| `h1/h2/h3-set3` | 3 cookies identical to the contract ones (`Set-Cookie` + `SameSite=Lax`) |

## Findings the matrix uses

1. `requestWillBeSentExtraInfo.headers` is an **ASCII-ordered map** and already comes
   without duplicates; `requestWillBeSent.headers` is only the Blink subset.
2. `responseReceivedExtraInfo.headersText` (h1) is the only place in CDP with the
   raw response order; the `headers` object merges repetitions with `\n`.
3. h1 send NetLog preserves order, case and duplicates; in h2/h3 the session event
   may swap `priority`/`cookie`, and `Cookie` appears as 1 field even when the wire
   carries N.
4. h2/h3 receive NetLog merges duplicates with `\x00`; the
   `HTTP_TRANSACTION_READ_RESPONSE_HEADERS` event keeps the repetitions separate.
5. A header supplied by API does not come out as it went in: `Fetch.continueRequest` with 6
   pairs (3 duplicated) arrives as 3 pairs (last value wins); the Fetch API `Headers`
   merges `append()` into `"a, b"`.

## Precautions applied

- Profile at `results/<exp>/chrome-profile` (deleted at the end); never the personal profile.
- `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`: no external traffic.
- Terminates only the process started by the launcher (`os.killpg` of the group created).
- NetLog in `Everything` mode contains cookies — all synthetic (`sl_a`, `sl_b`).
  The product must warn the user before using this mode.
- Invalid/truncated NetLog is recorded as `netlog_valid_json: false`, without
  discarding the partial session.
