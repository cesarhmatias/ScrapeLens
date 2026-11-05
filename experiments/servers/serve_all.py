#!/usr/bin/env python3
"""Starts the three observation servers in one process (h1, h2, h3).

Usage: serve_all.py --outdir results/<exp> [--certs certs/] [--port-base 8781]
Writes: server-h1.jsonl, server-h2.jsonl, server-h3.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import h1_raw  # noqa: E402
import h2_tls  # noqa: E402
from common import Recorder  # noqa: E402
import ssl  # noqa: E402


async def run(args: argparse.Namespace) -> None:
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    base = args.port_base
    h1 = h1_raw.H1Server(args.host, base, Recorder(outdir / "server-h1.jsonl", "http/1.1"))
    srv1 = await asyncio.start_server(h1.handle, args.host, base, limit=1 << 20)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    h2 = h2_tls.H2Server(Recorder(outdir / "server-h2.jsonl", "h2"))
    srv2 = await asyncio.start_server(h2.handle, args.host, base + 1, ssl=ctx, limit=1 << 20)

    print(f"READY h1={base} h2={base+1} h3={base+2}", flush=True)
    await asyncio.gather(srv1.serve_forever(), srv2.serve_forever())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port-base", type=int, default=8781)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
