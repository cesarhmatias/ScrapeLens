#!/usr/bin/env python3
"""Generates the synthetic acceptance fixtures for ScrapeLens.

Everything here is invented: `.invalid` domains, documentation ports, fixed
timestamps. No fixture derives from a personal capture. The generated files are
committed to `fixtures/acceptance/` so the suite runs offline; the command
`run_acceptance.py --build-fixtures` regenerates them deterministically.

Usage:
  python3 tests/acceptance/fixtures.py            # generates fixtures/acceptance
  python3 tests/acceptance/fixtures.py --check    # fails if anything would change
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "target" / "release" / "scrapelens-core"
FIX = ROOT / "fixtures" / "acceptance"

FIXTURE_META = {
    "label": "synthetic-fixture",
    "origin": "synthetic",
    "note": "Invented data for the acceptance suite; no real traffic.",
}


def dump(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def meta(folder: pathlib.Path, purpose: str, extra: dict | None = None) -> None:
    payload = dict(FIXTURE_META)
    payload["purpose"] = purpose
    if extra:
        payload.update(extra)
    dump(folder / "fixture.json", payload)


# ---------------------------------------------------------------- HAR helper


def har_entry(index: int, url: str, *, status: int = 200,
              request_headers: list[tuple[str, str]] | None = None,
              response_headers: list[tuple[str, str]] | None = None,
              redirect: str = "", body: str | None = "{}", body_size: int | None = None,
              post_data: dict | None = None, encoding: str | None = None,
              mime: str = "application/json") -> dict:
    request: dict = {
        "method": "GET" if post_data is None else "POST",
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": [{"name": n, "value": v} for n, v in (request_headers or [])],
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": len((post_data or {}).get("text", "")) if post_data else 0,
    }
    if post_data:
        request["postData"] = post_data
    content: dict = {"mimeType": mime, "size": body_size if body_size is not None else (len(body) if body else 0)}
    if body is not None:
        content["text"] = body
    if encoding:
        content["encoding"] = encoding
    return {
        "startedDateTime": f"2026-10-26T20:00:{index:02d}.000Z",
        "time": 12.5 + index,
        "request": request,
        "response": {
            "status": status,
            "statusText": {200: "OK", 302: "Found"}.get(status, "OK"),
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": n, "value": v} for n, v in (response_headers or [])],
            "cookies": [],
            "content": content,
            "redirectURL": redirect,
            "headersSize": 120,
            "bodySize": content["size"],
        },
        "cache": {},
        "timings": {"send": 0, "wait": 10, "receive": 2},
    }


def har(entries: list[dict], creator: str = "scrapelens-aceite") -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "1"},
            "pages": [],
            "entries": entries,
        }
    }


# ------------------------------------------------------------- NetLog helper

# The NetLog `time` is in milliseconds of process ticks and `timeTickOffset`
# is the epoch (ms) at tick zero. A coherent capture satisfies, for the same
# event, `wallTime = timeTickOffset/1000 + timestamp` (in this project's real
# Chrome captures the difference is < 2 ms). Correlation fixtures declare
# CDP and NetLog by this same equation; without it the core calibrates the wrong unit.
TICK_OFFSET_MS = 1793046000000

NETLOG_TYPES = [
    "URL_REQUEST_START_JOB",
    "HTTP_TRANSACTION_SEND_REQUEST_HEADERS",
    "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
    "URL_REQUEST_REDIRECTED",
    "HTTP_STREAM_JOB_BOUND_TO_REQUEST",
    "HTTP2_SESSION_SEND_HEADERS",
    "HTTP2_SESSION_RECV_HEADERS",
    "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS",
    "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS",
]
NETLOG_IDS = {name: 1000 + i for i, name in enumerate(NETLOG_TYPES)}


def netlog_event(name: str, source_id: int, time_ms: int, *, phase: int = 0,
                 params: dict | None = None, source_type: int = 1) -> dict:
    return {
        "time": str(time_ms),
        "type": NETLOG_IDS[name],
        "source": {"id": source_id, "type": source_type, "start_time": str(time_ms - 5)},
        "phase": phase,
        "params": params or {},
    }


def netlog(events: list[dict], *, constants: bool = True) -> dict:
    if not constants:
        return {"events": events}
    return {
        "constants": {
            "logEventTypes": NETLOG_IDS,
            "timeTickOffset": TICK_OFFSET_MS,
            "logCaptureMode": "Everything",
            "logFormatVersion": 1,
        },
        "events": events,
        "polledData": {},
    }


H1_HEADERS = [
    "Host: 127.0.0.1:9999",
    "x-rep: a",
    "x-seq: 1",
    "X-Rep: b",
    "x-seq: 2",
    "x-mixed-Case: V",
    "x-rep: c",
    "cookie: sl_a=1; sl_b=2; sc_dup=one; sc_dup=two",
]
H1_RESPONSE = [
    "HTTP/1.1 200 OK",
    "content-type: application/json",
    "x-resp-order: 1",
    "x-resp-order: 2",
    "set-cookie: sc_a=1; Path=/; HttpOnly",
    "set-cookie: sc_b=2; Path=/; Secure; SameSite=Lax",
    "set-cookie: sc_dup=one; Path=/",
    "set-cookie: sc_dup=two; Path=/",
    "content-length: 2",
]


def h1_request_block(source_id: int, time_ms: int, url: str = "http://127.0.0.1:9999/dup?case=headers",
                     headers: list[str] | None = None, response: list[str] | None = None,
                     target: str = "/dup?case=headers") -> list[dict]:
    headers = headers or H1_HEADERS
    return [
        netlog_event("URL_REQUEST_START_JOB", source_id, time_ms, phase=1,
                     params={"url": url, "method": "GET", "request_type": "fetch"}),
        netlog_event("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", source_id, time_ms + 3,
                     params={"headers": headers, "line": f"GET {target} HTTP/1.1\r\n"}),
        netlog_event("HTTP_TRANSACTION_READ_RESPONSE_HEADERS", source_id, time_ms + 6,
                     params={"headers": response or H1_RESPONSE}),
        netlog_event("URL_REQUEST_START_JOB", source_id, time_ms + 10, phase=2,
                     params={"net_error": 0}),
    ]


def cdp_event(method: str, params: dict) -> dict:
    return {"method": method, "params": params}


# ------------------------------------------------------------------- builder


def run_core(*args: str, expect: int = 0) -> str:
    proc = subprocess.run([str(CORE), *args], capture_output=True, text=True)
    if proc.returncode != expect:
        raise SystemExit(
            f"core {args} rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc.stdout


def import_fixture(kind: str, source: pathlib.Path, target: pathlib.Path) -> pathlib.Path:
    if target.exists():
        shutil.rmtree(target)
    run_core(kind, str(source), "--out", str(target), "--label", "synthetic-fixture")
    return target


def patch_session(session_dir: pathlib.Path, mutate) -> None:
    path = session_dir / "session.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def shutil_copy_attachment(session_dir: pathlib.Path, name: str, data: bytes) -> None:
    target = session_dir / "attachments" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def build() -> None:
    if FIX.exists():
        shutil.rmtree(FIX)
    FIX.mkdir(parents=True)
    if not CORE.exists():
        raise SystemExit(f"core binary missing: {CORE}\nrun: cd core && cargo build --release")

    # ---------------------------------------------------------- A1 headers
    a1_dir = FIX / "headers-cookies"
    meta(a1_dir, "Repeated headers, original casing and cookies in HAR and h1 NetLog.")
    dump(a1_dir / "headers-cookies.har", har([
        har_entry(0, "https://fixture.invalid/dup?case=headers",
                  request_headers=[
                      ("x-rep", "a"), ("x-seq", "1"), ("X-Rep", "b"), ("x-seq", "2"),
                      ("x-mixed-Case", "V"), ("x-rep", "c"),
                      ("cookie", "sl_a=1; sl_b=2; sc_dup=one; sc_dup=two"),
                  ],
                  response_headers=[
                      ("content-type", "application/json"),
                      ("set-cookie", "sc_a=1; Path=/; HttpOnly"),
                      ("set-cookie", "sc_b=2; Path=/; Secure; SameSite=Lax"),
                      ("set-cookie", "sc_dup=one; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
                      ("set-cookie", "sc_dup=two; Path=/"),
                  ]),
    ]))
    dump(a1_dir / "headers-cookies.netlog.json", netlog(h1_request_block(201, 3_000_000)))

    # ---------------------------------------------------------- A2 parsers
    a2_dir = FIX / "parsers"
    meta(a2_dir, "Valid, incomplete, invalid and unknown-item HAR and NetLog files.")
    dump(a2_dir / "incomplete.har", har([
        {"startedDateTime": "2026-10-26T20:01:00.000Z", "time": 1,
         "request": {"method": "GET", "url": "https://fixture.invalid/missing-response",
                     "headers": [{"name": "x-a", "value": "1"}]}},
        har_entry(1, "https://fixture.invalid/ok",
                  request_headers=[("x-ok", "1")],
                  response_headers=[("content-type", "text/plain")], body="ok"),
    ]))
    dump(a2_dir / "invalid.har", {"log": {"version": "1.2", "creator": {"name": "x"}}})
    dump(a2_dir / "unknown-encoding.har", har([
        har_entry(0, "https://fixture.invalid/br",
                  request_headers=[("accept-encoding", "br")],
                  response_headers=[("content-encoding", "br"), ("content-type", "text/plain")],
                  body="bravo", encoding="br"),
    ]))

    unknown_events = h1_request_block(301, 3_100_000) + [
        {"time": "3100020", "type": 999_001, "source": {"id": 301, "type": 1},
         "phase": 0, "params": {"future_field": {"nested": True}}},
        {"time": "3100021", "type": 999_001, "source": {"id": 301, "type": 1},
         "phase": 0, "params": {}},
        {"time": "3100022", "type": 999_002, "source": {"id": 301, "type": 1},
         "phase": 0, "params": {}},
    ]
    dump(a2_dir / "unknown-events.netlog.json", netlog(unknown_events))
    dump(a2_dir / "no-constants.netlog.json",
         netlog(h1_request_block(302, 3_200_000), constants=False))
    dump(a2_dir / "bad-header-line.netlog.json", netlog(
        h1_request_block(303, 3_300_000, headers=[
            "Host: 127.0.0.1:9999",
            "x-ok: 1",
            "line without separator",
            "x-ok: 2",
        ])
    ))
    (a2_dir / "truncated.netlog.json").write_text('{"constants": {"logEventTypes": {}}, "events": [',
                                                   encoding="utf-8")

    # ---------------------------------------------------------- A3 ambiguous
    a3_dir = FIX / "ambiguous"
    meta(a3_dir, "Two identical simultaneous requests: correlation must be ambiguous with candidates.")
    dump(a3_dir / "netlog-ambiguous.json",
         netlog(h1_request_block(101, 2_000_000, url="http://127.0.0.1:9999/dup?case=ambiguous",
                                 target="/dup?case=ambiguous")
                + h1_request_block(102, 2_000_020, url="http://127.0.0.1:9999/dup?case=ambiguous",
                                   target="/dup?case=ambiguous")))
    lines = []
    for index, request_id in enumerate(("r1", "r2")):
        base = {
            "url": "http://127.0.0.1:9999/dup?case=ambiguous",
            "method": "GET",
            "headers": {"Accept": "*/*", "User-Agent": "ScrapelensAceite/1"},
        }
        timestamp = 2000.0 + index * 0.02
        # wallTime in the same NetLog equation (`timeTickOffset/1000 + timestamp`),
        # as in real captures: both clocks agree on epoch and monotonic time.
        lines.append(cdp_event("Network.requestWillBeSent", {
            "requestId": request_id, "loaderId": "L" + request_id, "frameId": "F1",
            "timestamp": timestamp, "wallTime": TICK_OFFSET_MS / 1000.0 + timestamp,
            "type": "Fetch", "request": base,
        }))
        lines.append(cdp_event("Network.responseReceived", {
            "requestId": request_id, "timestamp": timestamp + 0.03, "type": "Fetch",
            "response": {"url": base["url"], "status": 200, "statusText": "OK",
                         "headers": {"content-type": "text/plain"},
                         "mimeType": "text/plain", "connectionId": "7"},
        }))
        lines.append(cdp_event("Network.loadingFinished", {
            "requestId": request_id, "timestamp": timestamp + 0.05, "encodedDataLength": 2,
        }))
    (a3_dir / "cdp-ambiguous.jsonl").write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    # ---------------------------------------------------------- A4 redirects
    a4_dir = FIX / "redirects"
    meta(a4_dir, "Redirect chain and multiple attempts in HAR (3 hops) and NetLog (2 hops).")
    dump(a4_dir / "redirect-chain.har", har([
        har_entry(0, "https://fixture.invalid/a", status=302,
                  request_headers=[("x-step", "1")],
                  response_headers=[("location", "/b")], body=None, body_size=0,
                  redirect="https://fixture.invalid/b"),
        har_entry(1, "https://fixture.invalid/b", status=302,
                  request_headers=[("x-step", "2")],
                  response_headers=[("location", "/c")], body=None, body_size=0,
                  redirect="https://fixture.invalid/c"),
        har_entry(2, "https://fixture.invalid/c",
                  request_headers=[("x-step", "3")],
                  response_headers=[("content-type", "text/plain")], body="end"),
    ]))
    dump(a4_dir / "redirect-chain.netlog.json", netlog([
        netlog_event("URL_REQUEST_START_JOB", 202, 4_000_000, phase=1,
                     params={"url": "http://127.0.0.1:9999/a", "method": "GET",
                             "request_type": "main_frame"}),
        netlog_event("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", 202, 4_000_002,
                     params={"headers": ["Host: 127.0.0.1:9999", "x-step: 1"],
                             "line": "GET /a HTTP/1.1\r\n"}),
        netlog_event("HTTP_TRANSACTION_READ_RESPONSE_HEADERS", 202, 4_000_004,
                     params={"headers": ["HTTP/1.1 302 Found", "location: /b", "content-length: 0"]}),
        netlog_event("URL_REQUEST_REDIRECTED", 202, 4_000_005,
                     params={"location": "http://127.0.0.1:9999/b"}),
        netlog_event("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", 202, 4_000_008,
                     params={"headers": ["Host: 127.0.0.1:9999", "x-step: 2"],
                             "line": "GET /b HTTP/1.1\r\n"}),
        netlog_event("HTTP_TRANSACTION_READ_RESPONSE_HEADERS", 202, 4_000_010,
                     params={"headers": ["HTTP/1.1 200 OK", "content-type: text/plain",
                                         "content-length: 3"]}),
        netlog_event("URL_REQUEST_START_JOB", 202, 4_000_012, phase=2, params={"net_error": 0}),
    ]))

    # ---------------------------------------------------------- A5 bodies
    a5_dir = FIX / "bodies"
    meta(a5_dir, "Explicit body states: captured, empty, truncated, unavailable, discarded.")
    # Own session, with 3 requests and predictable attachments.
    dump(a5_dir / "bodies.har", har([
        har_entry(0, "https://fixture.invalid/discarded",
                  request_headers=[("x-case", "discarded")],
                  response_headers=[("content-type", "text/plain")], body="resposta"),
        har_entry(1, "https://fixture.invalid/truncated",
                  request_headers=[("x-case", "truncated")],
                  response_headers=[("content-type", "text/plain")], body="0123456789"),
        har_entry(2, "https://fixture.invalid/empty",
                  request_headers=[("x-case", "empty")],
                  response_headers=[("content-length", "0")], body=None, body_size=0),
    ]))
    import_fixture("import-har", a5_dir / "bodies.har", a5_dir / "session")

    def mutate_bodies(value: dict) -> None:
        requests = value["requests"]
        requests[0]["requestBody"] = {
            "state": "discarded",
            "note": "body discarded by the acceptance capture policy",
            "provenance": {"source": "manual", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        requests[0]["responseBody"] = {
            "state": "captured",
            "attachment": "har-entry-0000.response.bin",
            "bytes": 7,
            "contentType": "text/plain",
            "provenance": {"source": "manual", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        requests[1]["requestBody"] = {
            "state": "empty",
            "provenance": {"source": "har", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        requests[1]["responseBody"] = {
            "state": "truncated",
            "attachment": "har-entry-0001.response.bin",
            "bytes": 4,
            "truncatedAt": 4,
            "note": "4-byte limit of the fixture",
            "contentType": "text/plain",
            "provenance": {"source": "manual", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        requests[2]["requestBody"] = {
            "state": "unavailable",
            "note": "source does not provide a request body",
            "provenance": {"source": "har", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        requests[2]["responseBody"] = {
            "state": "empty",
            "bytes": 0,
            "provenance": {"source": "har", "method": "aceite.fixture",
                           "verification": "unverified"},
        }

    patch_session(a5_dir / "session", mutate_bodies)
    # The truncated attachment really keeps only the 4 captured bytes.
    (a5_dir / "session" / "attachments" / "har-entry-0001.response.bin").write_bytes(b"0123")

    # ---------------------------------------------------------- A6 diff
    a6_dir = FIX / "diff"
    meta(a6_dir, "Diff with duplicated headers, reordering and one new header.")
    dump(a6_dir / "diff.har", har([
        har_entry(0, "https://fixture.invalid/diff-a",
                  request_headers=[("x-seq", "1"), ("X-Rep", "a"), ("x-seq", "2"),
                                   ("x-rep", "b"), ("x-dup", "same"), ("x-dup", "same"),
                                   ("x-keep", "k")],
                  response_headers=[("content-type", "text/plain")], body="a"),
        har_entry(1, "https://fixture.invalid/diff-b",
                  request_headers=[("X-Rep", "a"), ("x-seq", "1"), ("x-seq", "2"),
                                   ("x-dup", "same"), ("x-dup", "same"), ("x-keep", "k"),
                                   ("x-new", "c")],
                  response_headers=[("content-type", "text/plain")], body="b"),
    ]))
    import_fixture("import-har", a6_dir / "diff.har", a6_dir / "session")

    # ---------------------------------------------------------- A7 export
    a7_dir = FIX / "export-special"
    meta(a7_dir, "URL, header and hostile-body escaping in cURL and Python.")
    hostile_url = ("https://fixture.invalid/p?q=o'relly&x=$HOME&y=`id`&z=a&b=100%"
                   "&u=%C3%A7%C3%A3o&pipe=|&semi=;")
    # Request body with quotes, $, backticks, backslash and binary content.
    request_body = b"a'b\"$HOME`id`\\\n"
    nul_body = b"bin\x00ario"
    dump(a7_dir / "special.har", har([
        har_entry(0, hostile_url,
                  request_headers=[
                      ("Host", "fixture.invalid"),
                      ("x-quote", "it's \"$HOME\" `id` \\ backslash"),
                      ("x-dup", "a"),
                      ("x-dup", "b"),
                      ("x-bad", "ok\r\nInjected: 1"),
                      ("content-length", str(len(request_body))),
                  ],
                  response_headers=[("content-type", "text/plain")], body="ok",
                  post_data={"mimeType": "text/plain", "text": request_body.decode("utf-8", "replace")}),
        har_entry(1, "https://fixture.invalid/nul",
                  request_headers=[("Host", "fixture.invalid"),
                                   ("content-length", str(len(nul_body)))],
                  response_headers=[("content-type", "text/plain")], body="ok",
                  post_data={"mimeType": "application/octet-stream", "text": "bin"}),
    ]))
    import_fixture("import-har", a7_dir / "special.har", a7_dir / "session")
    # Attachments with exact bytes (HAR postData.text does not preserve NUL).
    value = json.loads((a7_dir / "session" / "session.json").read_text())
    rid = value["requests"][0]["id"]
    rid_nul = value["requests"][1]["id"]
    shutil_copy_attachment(a7_dir / "session", f"{rid}.request.bin", request_body)
    shutil_copy_attachment(a7_dir / "session", f"{rid_nul}.request.bin", nul_body)

    def mutate_export(value: dict) -> None:
        request = value["requests"][0]
        request["requestBody"] = {
            "state": "captured",
            "attachment": f"{rid}.request.bin",
            "bytes": len(request_body),
            "contentType": "text/plain",
            "provenance": {"source": "manual", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        nul_request = value["requests"][1]
        nul_request["requestBody"] = {
            "state": "captured",
            "attachment": f"{rid_nul}.request.bin",
            "bytes": len(nul_body),
            "contentType": "application/octet-stream",
            "provenance": {"source": "manual", "method": "aceite.fixture",
                           "verification": "unverified"},
        }
        value["session"]["labels"] = sorted(set(value["session"].get("labels", []) + ["synthetic-fixture"]))

    patch_session(a7_dir / "session", mutate_export)
    meta(a7_dir, "URL, header and hostile-body escaping in cURL and Python.",
         {"requestIds": [rid, rid_nul]})

    # ---------------------------------------------------------- A8 sanitize
    a8_dir = FIX / "sanitize"
    meta(a8_dir, "Sanitization of credentials, cookies, token in URL, bodies and raw events.")
    dump(a8_dir / "secret.har", har([
        har_entry(0, "https://fixture.invalid/s?token=SECRET-URL-TOKEN#SECRET-FRAGMENT",
                  request_headers=[
                      ("Authorization", "Bearer SECRET-AUTH-TOKEN"),
                      ("Cookie", "sid=SECRET-COOKIE-VALUE; theme=dark"),
                      ("Content-Type", "application/json"),
                  ],
                  response_headers=[
                      ("content-type", "application/json"),
                      ("set-cookie", "session=SECRET-SET-COOKIE; Path=/; HttpOnly"),
                  ],
                  body=json.dumps({"access_token": "SECRET-JSON-TOKEN",
                                   "user": {"email": "pessoa@fixture.invalid"}}),
                  post_data={"mimeType": "application/json",
                             "text": json.dumps({"password": "SECRET-PASSWORD", "page": 2})}),
        har_entry(1, "https://fixture.invalid/form",
                  request_headers=[("Content-Type", "application/x-www-form-urlencoded")],
                  response_headers=[("content-type", "text/plain")],
                  body="SECRET-FREE-TEXT in the text body",
                  post_data={"mimeType": "application/x-www-form-urlencoded",
                             "text": "user=ana&password=SECRET-FORM-PASSWORD&page=2"}),
    ]))
    import_fixture("import-har", a8_dir / "secret.har", a8_dir / "session")
    raw_cdp = [
        {"method": "Network.requestWillBeSent", "params": {
            "requestId": "raw-1", "request": {
                "url": "https://fixture.invalid/s?token=SECRET-URL-TOKEN",
                "method": "GET",
                "headers": {"Authorization": "Bearer SECRET-AUTH-TOKEN",
                            "Cookie": "sid=SECRET-COOKIE-VALUE"},
            },
            "timestamp": 2000.0, "wallTime": 1793046000.0, "type": "Fetch",
        }},
        {"method": "Network.responseReceived", "params": {
            "requestId": "raw-1", "timestamp": 2000.1, "type": "Fetch",
            "response": {"url": "https://fixture.invalid/s", "status": 200,
                         "headers": {"set-cookie": "session=SECRET-SET-COOKIE"},
                         "mimeType": "application/json"},
        }},
    ]
    (a8_dir / "session" / "cdp-events.jsonl").write_text(
        "\n".join(json.dumps(line) for line in raw_cdp) + "\n", encoding="utf-8")
    dump(a8_dir / "session" / "netlog.json", netlog([
        netlog_event("URL_REQUEST_START_JOB", 401, 5_000_000, phase=1,
                     params={"url": "https://fixture.invalid/s?token=SECRET-URL-TOKEN",
                             "method": "GET", "request_type": "fetch"}),
        netlog_event("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", 401, 5_000_003,
                     params={"headers": ["Host: fixture.invalid",
                                         "authorization: Bearer SECRET-AUTH-TOKEN",
                                         "cookie: sid=SECRET-COOKIE-VALUE"],
                             "line": "GET /s HTTP/1.1\r\n"}),
    ]))
    # Unstructured HTML attachment: must be omitted with a warning.
    html_request = json.loads((a8_dir / "session" / "session.json").read_text())["requests"][0]
    html_name = "fixture-unstructured.response.bin"
    shutil_copy_attachment(a8_dir / "session", html_name,
                           b"<html><script>var token='SECRET-IN-HTML'</script></html>")
    html_request["responseBody"] = {
        "state": "captured",
        "attachment": html_name,
        "bytes": 56,
        "contentType": "text/html",
        "provenance": {"source": "manual", "method": "aceite.fixture",
                       "verification": "unverified"},
    }
    patch_session(a8_dir / "session", lambda value: value["requests"][0].update(
        responseBody=html_request["responseBody"]))
    (a8_dir / "session" / "notes.txt").write_text(
        "synthetic fixture; contains secrets only for the sanitization test\n", encoding="utf-8")

    # ---------------------------------------------------------- top README
    (FIX / "README.md").write_text(
        "# fixtures/acceptance — synthetic\n\n"
        "Generated by `tests/acceptance/fixtures.py`. All domains use `.invalid`, the\n"
        "timestamps are fixed and the data is invented. Each directory has `fixture.json`\n"
        "with `label: synthetic-fixture`.\n\n"
        "No fixture contains real traffic, a real cookie or a valid credential. The\n"
        "secrets in `sanitize/` are markers (`SECRET-*`) used to prove that the\n"
        "sanitization removes them.\n",
        encoding="utf-8",
    )
    print(f"fixtures generated in {FIX}")


def manifest() -> dict[str, str]:
    return {
        str(path.relative_to(FIX)): path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(FIX.rglob("*")) if path.is_file()
    }


if __name__ == "__main__":
    if "--check" in sys.argv:
        before = manifest() if FIX.exists() else {}
        build()
        after = manifest()
        if before != after:
            print("fixtures diverge from the builder; run without --check and commit", file=sys.stderr)
            sys.exit(1)
        print("fixtures up to date")
    else:
        build()
