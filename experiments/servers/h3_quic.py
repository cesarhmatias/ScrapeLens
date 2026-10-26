#!/usr/bin/env python3
"""Servidor HTTP/3 (QUIC + QPACK via aioquic) que registra headers decodificados.

O evento HeadersReceived traz a lista de pares já decodificada do QPACK, na
ordem recebida e com pseudoheaders. É a referência para o lado h3.
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import Recorder, body_payload, response_headers  # noqa: E402

PAGE = b"""<!doctype html><link rel="icon" href="data:,"><meta charset=utf-8><title>sl h3</title>
<script>
window.__done = (async () => {
  document.cookie = 'sl_c=3; path=/';
  await fetch('/echo-order?from=afterjs', {credentials: 'include'}).then(r => r.json());
  await fetch('/echo-order?from=page', {credentials: 'include'}).then(r => r.json());
  await fetch('/echo-order?from=page2', {credentials: 'include'}).then(r => r.json());
  await fetch('/echo', {method: 'POST', credentials: 'include', body: 'k=v&z=1'}).then(r => r.json());
  const h = new Headers();
  h.set('x-zeta', '1'); h.set('x-alpha', '2'); h.set('x-mid', '3');
  h.append('x-dup', 'a'); h.append('x-dup', 'b');
  await fetch('/echo-order?from=jsheaders', {headers: h, credentials: 'include'}).then(r => r.json());
  return 4;
})();
</script>
"""


class H3Server(QuicConnectionProtocol):
    def __init__(self, *args, recorder: Recorder, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        self._rec = recorder
        self._buf: dict[int, dict] = {}
        self.conn_id = recorder.protocol + "-" + str(id(self))

    def quic_event_received(self, event) -> None:  # type: ignore[no-untyped-def]
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self._http = H3Connection(self._quic)
        if isinstance(event, ConnectionTerminated):
            return
        if self._http is None:
            return
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                pairs = [(n.decode("latin-1"), v.decode("latin-1")) for n, v in http_event.headers]
                pseudo = [p for p in pairs if p[0].startswith(":")]
                regular = [p for p in pairs if not p[0].startswith(":")]
                st = {"pairs": pairs, "pseudo": pseudo, "regular": regular, "body": b""}
                self._buf[http_event.stream_id] = st
                tls = {
                    "alpn": self._quic._network_paths[0].addr if False else "h3",
                    "tls_version": "TLSv1.3",
                }
                st["meta"] = (dict(pseudo).get(":method", ""), dict(pseudo).get(":path", ""), regular, pseudo, tls)
                if http_event.stream_ended:
                    self._respond(http_event.stream_id, st)
            elif isinstance(http_event, DataReceived):
                st = self._buf.get(http_event.stream_id)
                if st is not None:
                    st["body"] += http_event.data
                if http_event.stream_ended and st is not None:
                    self._respond(http_event.stream_id, st)

    def _respond(self, stream_id: int, st: dict) -> None:
        assert self._http is not None
        path = dict(st["pseudo"]).get(":path", "/").split("?", 1)[0]
        if path in ("/page", "/setcookie"):
            body, ctype = PAGE, "text/html; charset=utf-8"
        else:
            body = body_payload("h3", st["regular"], st["pseudo"])
            ctype = "application/json; charset=utf-8"
        meta = st.get("meta")
        headers = [(b":status", b"200")]
        for name, value in response_headers(path, "h3"):
            if name == "content-type":
                value = ctype
            headers.append((name.encode(), value.encode()))
        headers.append((b"content-length", str(len(body)).encode()))
        if meta:
            m, t, regular, pseudo, tls = meta
            self._rec.record(
                method=m,
                target=t,
                headers=regular,
                pseudoheaders=pseudo,
                body=st["body"],
                conn=self.conn_id,
                tls=tls,
                response_headers=[[n.decode(), v.decode()] for n, v in headers],
            )
        self._http.send_headers(stream_id, headers)
        self._http.send_data(stream_id, body, end_stream=True)
        self.transmit()


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8783)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    rec = Recorder(args.out, "h3")
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(args.cert, args.key)
    await serve(
        args.host,
        args.port,
        configuration=config,
        create_protocol=lambda *a, **kw: H3Server(*a, recorder=rec, **kw),
    )
    print(f"h3 listening on {args.host}:{args.port} -> {args.out}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
