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

## Current limit (2026-11-06, macOS)

`tshark` is not installed on this machine (and Wireshark is not in
`/Applications`), so the comparison has **not** been run. `tcpdump` 4.99.1 is
available. The matrix was not updated: without a decoded QPACK order there is no
proof. Install Wireshark/tshark with HTTP/3 support and run the command above.

## Interpretation

- The reference is `testserver`'s `h3.jsonl` (`headers`, `pseudoheaders`,
  `header_names`), which is quiche's `h3::Event::Headers` list in decode order.
- `tshark` must expose the HTTP/3 header list; if it only exposes undecoded
  QPACK bytes, the script reports that limit. It never guesses the order from
  the NetLog or from CDP.
- Do not edit `docs/02-fidelity-matrix.md` until this comparison produces a
  saved pcap, key log (outside the repo), tshark output and a match/diff report.
