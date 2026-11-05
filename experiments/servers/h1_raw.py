#!/usr/bin/env python3
"""HTTP/1.1 observation server, without an HTTP library.

Reads raw bytes from a TCP socket and records the headers in the order and with the
repetitions in which they appeared on the decoding line. There is no normalization,
duplicate merging or dictionary: the list of pairs is the evidence.
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import Recorder, body_payload, response_headers  # noqa: E402

PAGE = b"""<!doctype html><link rel="icon" href="data:,"><meta charset=utf-8><title>sl</title>
<script>
window.__done = (async () => {
  const out = [];
  document.cookie = 'sl_c=3; path=/';
  await fetch('/echo-order?from=afterjs', {credentials: 'include'}).then(r => r.json());
  const r1 = await fetch('/echo-order?from=page', {credentials: 'include'});
  out.push(await r1.json());
  const r2 = await fetch('/echo-order?from=page2', {credentials: 'include'});
  out.push(await r2.json());
  out.push(await fetch('/echo', {method: 'POST', credentials: 'include', body: 'k=v&z=1'}).then(r => r.json()));
  // Fetch API headers: deliberate insertion order and a duplicate via append().
  const h = new Headers();
  h.set('x-zeta', '1');
  h.set('x-alpha', '2');
  h.set('x-mid', '3');
  h.append('x-dup', 'a');
  h.append('x-dup', 'b');
  const r3 = await fetch('/echo-order?from=jsheaders', {headers: h, credentials: 'include'});
  out.push(await r3.json());
  window.__result = out;
  return out.length;
})();
</script>
"""

LONGCOOKIE_PAGE = b"""<!doctype html><link rel="icon" href="data:,"><meta charset=utf-8><title>sl longcookie</title>
<script>
window.__done = (async () => {
  document.cookie = 'ck_alpha=alpha-value-long; path=/';
  document.cookie = 'ck_beta=beta-value-long; path=/';
  document.cookie = 'ck_gamma=gamma-value-long; path=/';
  await fetch('/echo-order?from=longcookies', {credentials: 'include'}).then(r => r.json());
  return 1;
})();
</script>
"""

SET3_PAGE = b"""<!doctype html><link rel="icon" href="data:,"><meta charset=utf-8><title>sl set3</title>
<script>
window.__done = (async () => {
  await fetch('/echo-order?from=set3', {credentials: 'include'}).then(r => r.json());
  return 1;
})();
</script>
"""


class H1Server:
    def __init__(self, host: str, port: int, recorder: Recorder) -> None:
        self.host = host
        self.port = port
        self.rec = recorder
        self.conn_seq = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.conn_seq += 1
        conn = f"h1c{self.conn_seq}"
        try:
            while True:
                try:
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                    return
                except asyncio.LimitOverrunError:
                    return
                raw_block = head.decode("latin-1")
                lines = raw_block.split("\r\n")
                request_line = lines[0]
                parts = request_line.split(" ")
                method = parts[0] if parts else ""
                target = parts[1] if len(parts) > 1 else ""
                pairs: list[tuple[str, str]] = []
                for line in lines[1:]:
                    if not line:
                        continue
                    name, _, value = line.partition(":")
                    pairs.append((name, value.lstrip(" ")))
                length = 0
                for name, value in pairs:
                    if name.lower() == "content-length":
                        try:
                            length = int(value.strip())
                        except ValueError:
                            length = 0
                body = b""
                if length:
                    body = await reader.readexactly(length)
                out_headers, out_body = self.build(method, target, pairs, body)
                self.rec.record(
                    method=method,
                    target=target,
                    headers=pairs,
                    body=body,
                    raw_header_block=raw_block,
                    conn=conn,
                    response_headers=[list(h) for h in out_headers],
                )
                await self.write(writer, out_headers, out_body)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def build(
        self, method: str, target: str, pairs: list[tuple[str, str]], body: bytes
    ) -> tuple[list[tuple[str, str]], bytes]:
        path = target.split("?", 1)[0]
        if path == "/set3":
            payload, ctype = SET3_PAGE, "text/html; charset=utf-8"
        elif path == "/page-longcookies":
            payload, ctype = LONGCOOKIE_PAGE, "text/html; charset=utf-8"
        elif path in ("/page", "/setcookie"):
            payload, ctype = PAGE, "text/html; charset=utf-8"
        elif path == "/echo" and method == "POST":
            payload, ctype = body_payload("h1", pairs, request_body=body), "application/json; charset=utf-8"
        else:
            payload, ctype = body_payload("h1", pairs, request_body=body), "application/json; charset=utf-8"
        headers = [("content-type", ctype)] + [h for h in response_headers(path, "h1") if h[0] != "content-type"]
        headers.append(("content-length", str(len(payload))))
        headers.append(("connection", "keep-alive"))
        return headers, payload

    async def write(
        self, writer: asyncio.StreamWriter, headers: list[tuple[str, str]], body: bytes
    ) -> None:
        chunk = ["HTTP/1.1 200 OK\r\n"]
        for name, value in headers:
            chunk.append(f"{name}: {value}\r\n")
        chunk.append("\r\n")
        writer.write("".join(chunk).encode("latin-1") + body)
        await writer.drain()


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8781)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rec = Recorder(args.out, "http/1.1")
    srv = H1Server(args.host, args.port, rec)
    server = await asyncio.start_server(srv.handle, args.host, args.port, limit=1 << 20)
    print(f"h1 listening on {args.host}:{args.port} -> {args.out}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
