"""Utilidades compartilhadas pelos servidores de observação.

A referência de ordem é SEMPRE a lista de pares (nome, valor) no ponto em que o
protocolo foi decodificado, antes de qualquer normalização para dicionário.
Cada requisição vira uma linha JSONL.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import threading
from typing import Any, Iterable, Sequence

_LOCK = threading.Lock()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


class Recorder:
    """Append-only JSONL: uma linha por requisição observada."""

    def __init__(self, path: str | os.PathLike[str], protocol: str) -> None:
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.protocol = protocol
        self.path.write_text("")  # cada execução recomeça limpa

    def record(
        self,
        *,
        method: str,
        target: str,
        headers: Sequence[Sequence[str]],
        pseudoheaders: Sequence[Sequence[str]] = (),
        body: bytes = b"",
        raw_header_block: str | None = None,
        conn: str = "",
        note: str = "",
        tls: dict[str, Any] | None = None,
        response_headers: Sequence[Sequence[str]] = (),
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "source": "server",
            "protocol": self.protocol,
            "observed_at": _now(),
            "conn": conn,
            "method": method,
            "target": target,
            "headers": [[str(n), str(v)] for n, v in headers],
            "pseudoheaders": [[str(n), str(v)] for n, v in pseudoheaders],
            "header_names": [str(n) for n, _ in headers],
            "duplicate_names": sorted(
                {n for n, _ in headers if [x for x, _ in headers].count(n) > 1}
            ),
            "body_len": len(body),
            "body": body.decode("utf-8", "replace") if len(body) <= 4096 else "<truncated>",
        }
        if response_headers:
            row["response_headers"] = [[str(n), str(v)] for n, v in response_headers]
        if raw_header_block is not None:
            row["raw_header_block"] = raw_header_block
        if tls:
            row["tls"] = tls
        if note:
            row["note"] = note
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with _LOCK:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        return row


def body_payload(
    protocol: str,
    headers: Iterable[Sequence[str]],
    pseudo=(),
    request_body: bytes = b"",
) -> bytes:
    headers = list(headers)
    payload = {
        "protocol": protocol,
        "pseudoheaders": [[n, v] for n, v in pseudo],
        "headers": [[n, v] for n, v in headers],
        "header_names": [n for n, _ in headers],
        "duplicate_names": sorted(
            {n for n, _ in headers if [x for x, _ in headers].count(n) > 1}
        ),
        "request_id": os.urandom(4).hex(),
        "request_body": request_body.decode("utf-8", "replace"),
    }
    return json.dumps(payload, ensure_ascii=False).encode()


# Resposta comum: /setcookie devolve dois Set-Cookie e um header duplicado.
BASE_RESPONSE_HEADERS: list[tuple[str, str]] = [
    ("content-type", "application/json; charset=utf-8"),
    ("cache-control", "no-store"),
    ("x-resp-order", "1"),
    ("x-resp-order", "2"),
]


def response_headers(path: str, protocol: str) -> list[tuple[str, str]]:
    headers = list(BASE_RESPONSE_HEADERS)
    # Sem Alt-Svc: o experimento h3 usa --origin-to-force-quic-on para não
    # contaminar os resultados de h2 com tráfego migrado para h3.
    if path == "/set3":
        headers.append(("set-cookie", "sc_a=alpha; Path=/; SameSite=Lax"))
        headers.append(("set-cookie", "sc_b=beta; Path=/; SameSite=Lax"))
        headers.append(("set-cookie", "sc_dup=two; Path=/; SameSite=Lax"))
    if path.startswith("/setcookie"):
        headers.append(("set-cookie", "sl_a=1; Path=/"))
        headers.append(("set-cookie", "sl_b=2; Path=/"))
    return headers
