#!/usr/bin/env python3
"""Servidor HTTP/2 (TLS/ALPN) que registra a lista de headers decodificada.

Usa a biblioteca `h2`, cujo evento RequestReceived entrega `headers` como
lista ordenada de pares — resultado direto da decodificação HPACK, antes de
qualquer conversão para dicionário. Duplicatas aparecem como pares repetidos.
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import ssl
import sys

import h2.config
import h2.connection
import h2.events

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import Recorder, body_payload, response_headers  # noqa: E402

PAGE = b"""<!doctype html><meta charset=utf-8><title>sl h2</title>
<script>
window.__done = (async () => {
  await fetch('/echo-order?from=page', {credentials: 'include'}).then(r => r.json());
  await fetch('/echo-order?from=page2', {credentials: 'include'}).then(r => r.json());
  return 2;
})();
</script>
"""


class H2Server:
    def __init__(self, recorder: Recorder) -> None:
        self.rec = recorder
        self.conn_seq = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.conn_seq += 1
        conn_id = f"h2c{self.conn_seq}"
        tls = {}
        try:
            tls = {
                "alpn": (writer.get_extra_info("ssl_object").selected_alpn_protocol() or ""),
                "tls_version": writer.get_extra_info("ssl_object").version() or "",
            }
        except Exception:
            pass
        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        streams: dict[int, dict] = {}
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=60)
                if not data:
                    return
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        pairs = [(str(n), str(v)) for n, v in event.headers]
                        pseudo = [(n, v) for n, v in pairs if n.startswith(":")]
                        regular = [(n, v) for n, v in pairs if not n.startswith(":")]
                        streams[event.stream_id] = {"pairs": pairs, "pseudo": pseudo, "regular": regular, "body": b""}
                        self.rec.record(
                            method=dict(pseudo).get(":method", ""),
                            target=dict(pseudo).get(":path", ""),
                            headers=regular,
                            pseudoheaders=pseudo,
                            conn=conn_id,
                            tls=tls,
                        )
                    elif isinstance(event, h2.events.DataReceived):
                        st = streams.get(event.stream_id)
                        if st is not None:
                            st["body"] += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        st = streams.get(event.stream_id)
                        if st is not None:
                            self.respond(conn, event.stream_id, st)
                            writer.write(conn.data_to_send())
                            await writer.drain()
                    elif isinstance(event, h2.events.StreamReset):
                        streams.pop(event.stream_id, None)
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError):
            return
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def respond(self, conn: h2.connection.H2Connection, stream_id: int, st: dict) -> None:
        path = dict(st["pseudo"]).get(":path", "/").split("?", 1)[0]
        method = dict(st["pseudo"]).get(":method", "GET")
        if path == "/page":
            body, ctype = PAGE, "text/html; charset=utf-8"
        else:
            body = body_payload("h2", st["regular"], st["pseudo"])
            ctype = "application/json; charset=utf-8"
        headers = [(b":status", b"200")]
        for name, value in response_headers(path, "h2"):
            if name == "content-type":
                value = ctype
            headers.append((name.encode(), value.encode()))
        headers.append((b"content-length", str(len(body)).encode()))
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, body, end_stream=True)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8782)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    rec = Recorder(args.out, "h2")
    srv = H2Server(rec)
    server = await asyncio.start_server(srv.handle, args.host, args.port, ssl=ctx, limit=1 << 20)
    print(f"h2 listening on {args.host}:{args.port} -> {args.out}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
