#!/usr/bin/env python3
"""Compare the QPACK-decoded order from tshark with testserver's h3.jsonl.

Both inputs are external evidence. No session is created and nothing is written.
Exit codes: 0 match, 1 order differs, 2 missing evidence, 3 tshark did not expose
the decoded HTTP/3 header list (the calibration limit).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


def server_order(path: pathlib.Path) -> list[str]:
    line = next((line for line in path.read_text().splitlines() if line.strip()), None)
    if line is None:
        raise SystemExit(f"LIMIT: {path} is empty")
    record = json.loads(line)
    pseudo = [pair[0] for pair in record.get("pseudoheaders") or []]
    names = record.get("header_names")
    if names is None:
        names = [pair[0] for pair in record.get("headers") or []]
    return [str(name) for name in pseudo + list(names)]


def walk(value, key_path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, f"{key_path}.{key}" if key_path else key)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item, key_path)
    elif isinstance(value, str):
        yield key_path, value


def field_order(path: pathlib.Path) -> list[str]:
    raw = path.read_text()
    if not raw.strip():
        raise SystemExit(f"LIMIT: {path} is empty; tshark produced no output")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise SystemExit(f"LIMIT: {path} is not tshark JSON")
    candidates: list[str] = []
    for key, text in walk(data):
        lower = key.lower()
        if "http3" in lower and "header" in lower:
            candidates.extend(part for part in re.split(r"(?:\\n|\n|,)+", text) if ":" in part)
    if not candidates:
        raise SystemExit(
            "LIMIT: tshark did not expose the decoded HTTP/3 header list "
            "(QPACK order not provable with this Wireshark build)"
        )
    names = []
    for line in candidates:
        if ": " in line:
            name = line.rsplit(": ", 1)[0]
        else:
            name = line.partition(":")[0]
        name = name.strip().strip('"')
        if name:
            names.append(name)
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=pathlib.Path)
    parser.add_argument("--tshark", required=True, type=pathlib.Path)
    args = parser.parse_args()
    expected = server_order(args.server)
    actual = field_order(args.tshark)
    if actual == expected:
        print(f"MATCH: {len(actual)} header fields in QPACK order")
        return 0
    print("DIFF: QPACK order differs from testserver")
    for index, (got, want) in enumerate(zip(actual, expected)):
        if got != want:
            print(f"  first difference at {index}: tshark={got!r} testserver={want!r}")
            break
    print(f"  tshark={len(actual)} fields, testserver={len(expected)} fields")
    print("  matrix unchanged until this is understood")
    return 1


if __name__ == "__main__":
    sys.exit(main())
