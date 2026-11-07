# h3 calibration — optional, off by default

Purpose: calibrate the **order of the QPACK-decoded request headers** of an h3
capture against the independent list written by `testserver` (`h3.jsonl`).
This is an experiment only. It does not add a product option, does not change
`capture/` and does not update `docs/02-fidelity-matrix.md` unless a run
produces a real comparison.

## What the run does

1. starts `testserver serve --only h3` on `127.0.0.1:8783`;
2. starts Chrome with a dedicated temporary profile, `--headless=new`,
   `--origin-to-force-quic-on=127.0.0.1:8783` and
   `--ssl-key-log-file=<out>/keys.log`;
3. captures loopback UDP/8783 to `<out>/h3.pcap` with `tcpdump`;
4. decrypts/decodes the pcap with `tshark -o tls.keylog_file:<keys>`;
5. compares the QPACK field order with `testserver`'s `h3.jsonl`.

## Requirements

- **Chrome** (the App's stable Chrome path, or `CHROME`).
- **tshark** with the HTTP/3 dissector. Wireshark 4.x is recommended; older
  versions may not expose the decoded QPACK field list.
- **tcpdump** and packet-capture permission:
  - macOS: `tcpdump` needs BPF access. Run the capture with `sudo` or install
    Wireshark's ChmodBPF helper; a normal user without BPF permission gets
    `Permission denied` and the script stops.
  - Linux: `CAP_NET_RAW` (and normally `CAP_NET_ADMIN`) on `tcpdump`, e.g.
    `sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump`, or run the
    capture as root. Docker needs `--cap-add=NET_RAW --cap-add=NET_ADMIN`.
- Loopback UDP/8783 free.

`run.sh` refuses to start when `tshark` or `tcpdump` is missing, and prints the
limit instead of producing a half-calibration.

## Run

```sh
experiments/h3-calibration/run.sh /path/outside/the/repo/h3-cal
```

The output directory must be outside the repository or ignored: it contains a
TLS **key log** and a **pcap**, both sensitive. The script never copies them
into a session, an export or the repository. `*.pcap`, `*.keylog` and the default
output names are in `.gitignore`.

## Result (2026-11-07, Debian trixie container)

`Dockerfile.trixie` installs Chromium, tshark 4.4.19 and tcpdump. Running
`run.sh` as root with `--cap-add NET_RAW --cap-add NET_ADMIN` produced a pcap,
a key log and testserver's `h3.jsonl`; tshark exposed the decoded HTTP/3
headers and the comparison returned:

```
MATCH: 17 header fields in QPACK order
```

The request is `GET /echo-order?case=calibration`; duplicates were not
exercised in this run. The pcap/key log stayed outside the repository and were
not exported. On macOS `tshark` is still absent, so the same command there
records the limit instead. The matrix row for this run states exactly these two
limits.

## Interpretation

- The reference is `testserver`'s `h3.jsonl` (`headers`, `pseudoheaders`,
  `header_names`), which is quiche's `h3::Event::Headers` list in decode order.
- `tshark` must expose the HTTP/3 header list; if it only exposes undecoded
  QPACK bytes, the script reports that limit. It never guesses the order from
  the NetLog or from CDP.
- The matrix row for this run is backed by a saved pcap, key log (outside the
  repo), tshark PDML and the match above. A future run with duplicates must
  update the row instead of reusing this one.
