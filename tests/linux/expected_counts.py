#!/usr/bin/env python3
"""Prints the request count that a fixture file must produce, computed from the file itself.

  expected_counts.py har <file.har>      number of HAR entries
  expected_counts.py netlog <netlog.json> distinct URL_REQUEST sources in a Chrome NetLog

Used by tests/linux/acceptance.sh so no expected number is written in the script.
"""
import json
import sys


def har_count(path):
    return len(json.load(open(path, encoding="utf-8"))["log"]["entries"])


def netlog_count(path):
    doc = json.load(open(path, encoding="utf-8"))
    url_request = doc["constants"]["logSourceType"]["URL_REQUEST"]
    return len({e["source"]["id"] for e in doc["events"]
                if e.get("source", {}).get("type") == url_request})


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("har", "netlog"):
        sys.exit("usage: expected_counts.py har|netlog <file>")
    print(har_count(sys.argv[2]) if sys.argv[1] == "har" else netlog_count(sys.argv[2]))
