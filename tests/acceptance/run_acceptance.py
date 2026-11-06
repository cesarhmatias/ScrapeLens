#!/usr/bin/env python3
"""Acceptance suite for the ScrapeLens MVP (the 10 criteria of the specification).

Drives the core CLI (`core/target/release/scrapelens-core`) and the synthetic
fixtures in `fixtures/acceptance/`. No step opens the network: the servers and the
Chrome of criterion 9 are local and orchestrated by `tests/capture/run-cycle.sh`.

Usage:
  python3 tests/acceptance/run_acceptance.py                       # items 1-8,10
  python3 tests/acceptance/run_acceptance.py --capture RUN_DIR     # + item 9
  python3 tests/acceptance/run_acceptance.py --only 1,3,6
  python3 tests/acceptance/run_acceptance.py --build-fixtures

Output: `tests/results/acceptance.json` and `tests/REPORT.md`.
Exit code 0 only if no selected item failed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "core" / "target" / "release" / "scrapelens-core"
FIX = ROOT / "fixtures" / "acceptance"
WORK = ROOT / "tests" / ".work"
RESULTS = ROOT / "tests" / "results"
REPORT = ROOT / "tests" / "REPORT.md"

# SHA-256 of the final bundle executable accepted in this round, documented in
# `src-tauri/PACKAGING.md`. A legitimate rebuild changes the hash: update both
# places together, so the suite never approves an undocumented artifact.
APP_EXECUTABLE = pathlib.Path(os.environ.get("SL_APP_EXECUTABLE") or (
    pathlib.Path(__file__).resolve().parents[2] / "src-tauri/target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens"))
EXPECTED_APP_SHA256 = "2691f1528a6b5b6009d8cc29c049f1e500093d6aab9f2163bcc4aad60df18156"

SECRETS = [
    "SECRET-AUTH-TOKEN",
    "SECRET-COOKIE-VALUE",
    "SECRET-SET-COOKIE",
    "SECRET-URL-TOKEN",
    "SECRET-FRAGMENT",
    "SECRET-JSON-TOKEN",
    "SECRET-PASSWORD",
    "SECRET-FORM-PASSWORD",
    "SECRET-FREE-TEXT",
    "SECRET-IN-HTML",
    "pessoa@fixture.invalid",
]


# --------------------------------------------------------------------- helpers


class Expect:
    """Accumulates assertions; an item fails if any row fails."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def ok(self, condition: bool, label: str) -> bool:
        self.rows.append({"ok": bool(condition), "label": label})
        return bool(condition)

    def eq(self, got, expected, label: str) -> bool:
        return self.ok(got == expected, f"{label}: expected {expected!r}, got {got!r}")

    def contains(self, haystack, needle, label: str) -> bool:
        present = needle in haystack
        return self.ok(present, f"{label}: {needle!r} "
                               + ("present" if present else "absent")
                               + f" in {short(haystack)}")

    @property
    def failures(self) -> list[dict]:
        return [row for row in self.rows if not row["ok"]]


def short(value, limit: int = 220) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False)
        except TypeError:
            text = repr(value)
    return text if len(text) <= limit else text[:limit] + "…"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fresh(path: pathlib.Path) -> pathlib.Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def core(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([str(CORE), *args], capture_output=True, text=True, timeout=timeout)


def core_ok(*args: str, timeout: int = 300) -> str:
    proc = core(*args, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"core {args} rc={proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def inspect(session: pathlib.Path) -> dict:
    """Returns the SessionV1 document (the `session` inside the `inspect` envelope)."""
    return json.loads(core_ok("inspect", str(session)))["session"]


SYNTHETIC_LABELS = ["capture-import", "synthetic-fixture"]  # import-capture
# Origin label per import type (core: har.rs, netlog.rs, session.rs).
ORIGIN_LABEL = {"import-har": "har-import", "import-netlog": "netlog-import", "import-capture": "capture-import"}


def import_to(kind: str, source: pathlib.Path, target: pathlib.Path) -> dict:
    fresh(target)
    core_ok(kind, str(source), "--out", str(target), "--label", "synthetic-fixture")
    session = inspect(target)
    expected = sorted([ORIGIN_LABEL[kind], "synthetic-fixture"])
    if sorted(session["session"].get("labels", [])) != expected:
        raise SystemExit(f"labels of the imported session {target.name}: {session['session'].get('labels')} != {expected}")
    return session


def view_verification(view: dict) -> str:
    """Weakest state among the occurrences of a HeaderView (contract: per information)."""
    order = {"unverified": 0, "partial": 1, "verified": 2}
    entries = list(view.get("headers", [])) + list(view.get("pseudoHeaders", []))
    if not entries:
        return "unverified"
    return min((entry.get("verification", "unverified") for entry in entries), key=order.get)


def fixture_meta(folder: pathlib.Path) -> dict:
    path = folder / "fixture.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def derive_name(base: pathlib.Path) -> str:
    return unicodedata.normalize("NFC", base.name)


# --------------------------------------------------------------- item checks


def item_1(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Repeated headers, casing and cookies preserved in the fixtures."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "headers-cookies"
    meta = fixture_meta(folder)
    exp.eq(meta.get("label"), "synthetic-fixture", "fixture identified as synthetic")
    exp.eq(meta.get("origin"), "synthetic", "synthetic origin declared")

    expected_names = ["x-rep", "x-seq", "X-Rep", "x-seq", "x-mixed-Case", "x-rep"]
    expected_pairs = list(zip(expected_names, ["a", "1", "b", "2", "V", "c"]))

    base = ctx["run"] / "item1"
    har_session = base / "har"
    nl_session = base / "netlog"
    imported_har = import_to("import-har", folder / "headers-cookies.har", har_session)
    imported_nl = import_to("import-netlog", folder / "headers-cookies.netlog.json", nl_session)
    evidence += [
        f"`scrapelens-core import-har fixtures/acceptance/headers-cookies/headers-cookies.har --out {rel(har_session)}`",
        f"`scrapelens-core import-netlog fixtures/acceptance/headers-cookies/headers-cookies.netlog.json --out {rel(nl_session)}`",
    ]

    for label, document in (("HAR", imported_har), ("NetLog h1", imported_nl)):
        request = document["requests"][0]
        headers = request["requestHeaders"]["headers"]
        pairs = [(entry["name"], entry["value"]) for entry in headers]
        without_cookie = [pair for pair in pairs
                          if pair[0].lower() not in {"cookie", "host"}]
        exp.eq(without_cookie, expected_pairs, f"{label}: order, casing and duplicates of the request")
        exp.eq(len([name for name, _ in without_cookie if name.lower() == "x-rep"]), 3,
               f"{label}: three occurrences of x-rep preserved")
        exp.eq(request["requestHeaders"]["orderState"], "sourceOrder",
               f"{label}: orderState=sourceOrder")

        cookie = request["cookie"]
        exp.eq(cookie.get("raw"),
               ["sl_a=1; sl_b=2; sc_dup=one; sc_dup=two"],
               f"{label}: raw Cookie field preserved")
        exp.eq([(pair["name"], pair["value"]) for pair in cookie.get("pairs", [])],
               [("sl_a", "1"), ("sl_b", "2"), ("sc_dup", "one"), ("sc_dup", "two")],
               f"{label}: internal Cookie pairs, with sc_dup duplicated")
        exp.ok(len([p for p in cookie.get("pairs", []) if p["name"] == "sc_dup"]) == 2,
               f"{label}: duplicate cookie name was not collapsed")

        set_cookies = request.get("setCookies", [])
        expected_set_cookies = ["sc_a=1; Path=/; HttpOnly",
                                "sc_b=2; Path=/; Secure; SameSite=Lax",
                                "sc_dup=one; Path=/",
                                "sc_dup=two; Path=/"]
        if label == "HAR":
            # The fixture HAR includes Expires on the third line; the raw line is preserved.
            expected_set_cookies[2] = "sc_dup=one; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
        exp.eq([record["raw"] for record in set_cookies], expected_set_cookies,
               f"{label}: Set-Cookie lines in source order")
        exp.eq([record.get("parsed", {}).get("name") for record in set_cookies],
               ["sc_a", "sc_b", "sc_dup", "sc_dup"],
               f"{label}: Set-Cookie parsed, repetition preserved")
        exp.ok(set_cookies[0].get("parsed", {}).get("httpOnly") is True,
               f"{label}: HttpOnly of sc_a parsed")
        exp.ok(set_cookies[1].get("parsed", {}).get("secure") is True,
               f"{label}: Secure of sc_b parsed")

        # Round trip: reopening the saved session does not change the sequence.
        reopened = inspect(har_session if label == "HAR" else nl_session)
        again = [(entry["name"], entry["value"])
                 for entry in reopened["requests"][0]["requestHeaders"]["headers"]]
        exp.eq([pair for pair in again if pair[0].lower() not in {"cookie", "host"}], expected_pairs,
               f"{label}: sequence preserved after saving and reading back")

    exp.eq(view_verification(imported_nl["requests"][0]["requestHeaders"]), "verified",
           "NetLog h1: request headers verified")
    exp.eq(view_verification(imported_nl["requests"][0]["responseHeaders"]), "verified",
           "NetLog h1: response headers verified")
    exp.eq(view_verification(imported_har["requests"][0]["requestHeaders"]), "unverified",
           "HAR: order remains unverified (no seal invented)")
    response_pairs = [(entry["name"], entry["value"])
                      for entry in imported_nl["requests"][0]["responseHeaders"]["headers"]]
    exp.ok(("x-resp-order", "1") in response_pairs and ("x-resp-order", "2") in response_pairs,
           "NetLog: duplicate response x-resp-order preserved in order")
    evidence.append("assertions: sequence/casing/duplicates, raw Cookie + pairs, raw + parsed Set-Cookie, verification by source")

    # Every acceptance fixture must declare itself synthetic.
    missing = [str(path.relative_to(ROOT)) for path in FIX.glob("*/fixture.json")
               if json.loads(path.read_text()).get("label") != "synthetic-fixture"]
    exp.eq(missing, [], "all acceptance fixtures labeled synthetic-fixture")
    return exp.rows, evidence, notes


def item_2(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Valid, incomplete, invalid and unknown-event HAR/NetLog inputs."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    parsers = FIX / "parsers"
    base = ctx["run"] / "item2"

    valid = import_to("import-har", FIX / "headers-cookies" / "headers-cookies.har", base / "valid-har")
    exp.eq(len(valid["requests"]), 1, "valid HAR: 1 request imported")

    incomplete = import_to("import-har", parsers / "incomplete.har", base / "incomplete-har")
    exp.eq(len(incomplete["requests"]), 2, "incomplete HAR: valid entries preserved")
    exp.eq(incomplete["session"]["completeness"]["state"], "partial",
           "incomplete HAR: completeness=partial")
    codes = {warning["code"] for warning in incomplete["warnings"]}
    exp.contains(codes, "har.missing_response", "incomplete HAR: explicit har.missing_response warning")
    har_counts = incomplete["session"]["completeness"]["counts"]
    exp.eq(har_counts.get("sourceEvents"), 2, "HAR: sourceEvents persisted (2 entries)")
    exp.eq(har_counts.get("sourceEventsUsed"), 2, "HAR: sourceEventsUsed persisted (2)")

    invalid_har = core("import-har", str(parsers / "invalid.har"), "--out", str(base / "invalid-har"))
    exp.ok(invalid_har.returncode != 0, "invalid HAR: explicit failure (not silent)")
    exp.contains(invalid_har.stderr, "error:", "invalid HAR: error message on stderr")

    unknown_encoding = import_to("import-har", parsers / "unknown-encoding.har", base / "encoding")
    codes = {warning["code"] for warning in unknown_encoding["warnings"]}
    exp.contains(codes, "har.unknown_encoding", "HAR with unknown encoding: warning")
    exp.eq(unknown_encoding["requests"][0]["responseBody"].get("bytes"), 5,
           "HAR with unknown encoding: body treated as text and measured")

    unknown = import_to("import-netlog", parsers / "unknown-events.netlog.json", base / "unknown")
    exp.eq(len(unknown["requests"]), 1, "NetLog with unknown events: request preserved")
    unknown_warning = next((warning for warning in unknown["warnings"]
                           if warning["code"] == "netlog.unknown_event_type"), None)
    exp.ok(unknown_warning is not None, "NetLog: warning persisted with the unknown count")
    if unknown_warning:
        match = re.search(r"(\d+) event", unknown_warning["message"])
        count = int(match.group(1)) if match else 0
        exp.ok(count >= 3, f"NetLog: {count} unknown events counted in the warning")
        exp.ok(bool((unknown_warning.get("detail") or {}).get("samples")),
               "NetLog: samples of unknown types preserved in the warning")
    codes = {warning["code"] for warning in unknown["warnings"]}
    exp.contains(codes, "netlog.unknown_event_type", "NetLog: netlog.unknown_event_type warning")
    exp.eq(unknown["session"]["completeness"]["state"], "partial",
           "NetLog with unknown items: completeness=partial")
    unknown_counts = unknown["session"]["completeness"]["counts"]
    exp.eq(unknown_counts.get("sourceEvents"), 7, "NetLog: sourceEvents persisted (7)")
    exp.eq(unknown_counts.get("sourceEventsUnknown"), 3, "NetLog: sourceEventsUnknown persisted (3)")

    no_constants = import_to("import-netlog", parsers / "no-constants.netlog.json", base / "no-constants")
    codes = {warning["code"]: warning for warning in no_constants["warnings"]}
    exp.contains(codes, "netlog.constants_missing", "NetLog without constants: explicit warning")
    exp.contains(codes, "netlog.no_requests", "NetLog without constants: zero-requests warning")
    exp.eq(no_constants["session"]["completeness"]["state"], "partial",
           "NetLog without constants: completeness=partial (never complete)")

    bad_line = import_to("import-netlog", parsers / "bad-header-line.netlog.json", base / "bad-line")
    exp.eq(len(bad_line["requests"]), 1, "NetLog with invalid header line: request preserved")
    codes = {warning["code"] for warning in bad_line["warnings"]}
    exp.contains(codes, "netlog.header_line_invalid", "NetLog: warning for a line without separator")
    names = [entry["name"] for entry in bad_line["requests"][0]["requestHeaders"]["headers"]]
    exp.eq(names.count("x-ok"), 2, "NetLog: valid headers around the invalid line kept")

    truncated = core("import-netlog", str(parsers / "truncated.netlog.json"), "--out", str(base / "truncated"))
    exp.ok(truncated.returncode != 0, "truncated NetLog: explicit failure")
    exp.contains(truncated.stderr, "error:", "truncated NetLog: error on stderr")

    evidence += [
        f"`scrapelens-core import-har fixtures/acceptance/parsers/incomplete.har --out {rel(base / 'incomplete-har')}`",
        f"`scrapelens-core import-netlog fixtures/acceptance/parsers/unknown-events.netlog.json --out {rel(base / 'unknown')}`",
        f"`scrapelens-core import-netlog fixtures/acceptance/parsers/no-constants.netlog.json --out {rel(base / 'no-constants')}`",
        "invalid cases: return code ≠ 0 with `error:` on stderr (HAR without entries, truncated NetLog)",
    ]
    notes.append("HAR does not prove order/duplicates: imported entries stay `unverified`, as in the contract.")
    notes.append("`completeness.counts.sourceEvents*` counts are now persisted and survive re-reading "
                 "(core fix in this wave); the warnings still carry samples of the unknown types.")
    return exp.rows, evidence, notes


def item_3(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Identical simultaneous requests: explicit ambiguity, no false choice."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "ambiguous"
    session_dir = ctx["run"] / "item3" / "capture"
    meta = fixture_meta(folder)
    exp.eq(meta.get("label"), "synthetic-fixture", "ambiguity fixture labeled synthetic")
    # The fixture must be consistent with real Chrome: the CDP `wallTime` is
    # `timeTickOffset/1000 + timestamp`. If this equation breaks, the core's unit
    # calibration (f6c6bdd) picks microseconds and the correlation drops to zero —
    # a fixture failure, not a core failure.
    cdp_events = [json.loads(line) for line in
                  (folder / "cdp-ambiguous.jsonl").read_text(encoding="utf-8").splitlines()
                  if line.strip()]
    offset_ms = json.loads((folder / "netlog-ambiguous.json").read_text(encoding="utf-8")
                           )["constants"]["timeTickOffset"]
    exp.ok(all(abs(event["params"]["wallTime"]
                   - (offset_ms / 1000.0 + event["params"]["timestamp"])) < 1e-6
               for event in cdp_events
               if event["method"] == "Network.requestWillBeSent"),
           "fixture clock consistent (wallTime = timeTickOffset/1000 + timestamp)")

    fresh(session_dir)
    core_ok("import-capture", str(folder / "cdp-ambiguous.jsonl"),
            str(folder / "netlog-ambiguous.json"), "--out", str(session_dir),
            "--label", "synthetic-fixture")
    session = inspect(session_dir)
    exp.eq(sorted(session["session"].get("labels", [])), SYNTHETIC_LABELS, "imported session labeled as synthetic fixture")
    evidence.append(
        "`scrapelens-core import-capture fixtures/acceptance/ambiguous/cdp-ambiguous.jsonl "
        "fixtures/acceptance/ambiguous/netlog-ambiguous.json --out "
        f"{rel(session_dir)}`"
    )

    requests = session["requests"]
    exp.eq(len(requests), 2, "two CDP requests imported")
    unit_warning = next((warning for warning in session["warnings"]
                         if warning["code"] == "netlog.time_unit_detected"), None)
    exp.ok(unit_warning is not None, "`time` unit calibrated by the CDP clock")
    exp.eq((unit_warning or {}).get("detail", {}).get("unit"), "milliseconds",
           "unit calibrated as milliseconds (the same as real Chrome)")
    ambiguous = [request for request in requests if request.get("match") == "ambiguous"]
    exp.eq(len(ambiguous), 2, "both marked match=ambiguous (no silent association)")
    for request in ambiguous:
        candidates = request.get("matchCandidates", [])
        exp.eq(len(candidates), 2, f"{request['id']}: two candidates exposed")
        exp.ok(all(candidate.get("score", 0) >= 55 for candidate in candidates),
               f"{request['id']}: candidates above the minimum score, for display only")
        exp.ok(all(candidate.get("entityId") for candidate in candidates),
               f"{request['id']}: candidates identifiable (entityId)")
        exp.eq(view_verification(request["requestHeaders"]), "unverified",
               f"{request['id']}: primary view was not promoted to verified under ambiguity")
    candidate_sets = sorted(tuple(sorted(c["entityId"] for c in request["matchCandidates"]))
                            for request in ambiguous)
    exp.eq(len(set(candidate_sets)), 1,
           "both requests see the same candidate set (no cross choice)")
    codes = [warning["code"] for warning in session["warnings"]]
    exp.eq(codes.count("correlate.ambiguous"), 2, "two correlate.ambiguous warnings persisted")

    netlog_only = import_to("import-netlog", folder / "netlog-ambiguous.json", ctx["run"] / "item3" / "netlog")
    exp.eq(len(netlog_only["requests"]), 2, "isolated NetLog keeps both attempts")
    exp.eq(netlog_only["session"]["completeness"]["state"], "partial",
           "NetLog alone without CDP: completeness=partial (coverage not proven)")

    notes.append("NetLog order/duplicates are preserved, but do not become the primary view while there is ambiguity.")
    notes.append("Leader's failure diagnosis: the fixture declared `wallTime` without the monotonic `timestamp` "
                 "(`1793046000.0`), and the core at `f6c6bdd` calibrated `time` as microseconds; the NetLog ran "
                 "2 s ahead and both requests became `unmatched`. Real Chrome satisfies "
                 "`wallTime = timeTickOffset/1000 + timestamp` (measured deviation < 1 ms), an equation now used in the "
                 "fixture. It was a fixture defect, not a core defect; the original failure is preserved in "
                 "`tests/results/acceptance-criterion3-leader-failure.json` and `REPORT-criterion3-leader-failure.md`.")
    notes.append("New assertions in this round: fixture clock consistency (CDP×NetLog) and calibrated unit "
                 "`milliseconds`. The ambiguity test stays strict: the two requests at 20 ms remain ambiguous, "
                 "each with the same 2 candidates and 2 `correlate.ambiguous` warnings.")
    return exp.rows, evidence, notes


def item_4(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Redirects and multiple attempts, without losing links."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "redirects"
    base = ctx["run"] / "item4"

    netlog = import_to("import-netlog", folder / "redirect-chain.netlog.json", base / "netlog")
    request = netlog["requests"][0]
    exp.eq(len(netlog["requests"]), 1, "NetLog: one LogicalRequest for the chain")
    exp.eq([attempt["status"] for attempt in request["attempts"]], [302, 200],
           "NetLog: status per attempt [302, 200]")
    exp.eq(len(request.get("redirects", [])), 1, "NetLog: one Redirect recorded")
    redirect = request["redirects"][0]
    exp.eq(redirect.get("fromUrl"), "http://127.0.0.1:9999/a", "NetLog: redirect fromUrl")
    exp.eq(redirect.get("toUrl"), "http://127.0.0.1:9999/b", "NetLog: redirect toUrl")
    exp.eq(redirect.get("status"), 302, "NetLog: redirect status")
    final_headers = [(entry["name"], entry["value"])
                     for entry in request["requestHeaders"]["headers"]]
    exp.eq(final_headers, [("Host", "127.0.0.1:9999"), ("x-step", "2")],
           "NetLog: final attempt headers in source order")
    exp.eq(view_verification(request["requestHeaders"]), "verified",
           "NetLog: final headers verified")

    har = import_to("import-har", folder / "redirect-chain.har", base / "har")
    har_request = har["requests"][0]
    exp.eq(len(har["requests"]), 1, "HAR: chain grouped into one LogicalRequest")
    exp.eq([attempt["status"] for attempt in har_request["attempts"]], [302, 302, 200],
           "HAR: three attempts in order")
    exp.eq(len(har_request.get("redirects", [])), 2, "HAR: two Redirects")
    exp.eq(har_request["responseBody"].get("state"), "captured",
           "HAR: final response body captured")

    evidence += [
        f"`scrapelens-core import-netlog fixtures/acceptance/redirects/redirect-chain.netlog.json --out {rel(base / 'netlog')}`",
        f"`scrapelens-core import-har fixtures/acceptance/redirects/redirect-chain.har --out {rel(base / 'har')}`",
    ]
    notes.append("The redirect is a link between attempts, not a separate request.")
    return exp.rows, evidence, notes


def item_5(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Missing/truncated/discarded/empty bodies with explicit state."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "bodies" / "session"
    session = inspect(session_path)
    evidence.append(f"`scrapelens-core inspect {rel(session_path)}`")

    requests = session["requests"]
    exp.eq(len(requests), 3, "three fixture requests")
    first, second, third = requests

    exp.eq(first["requestBody"].get("state"), "discarded", "req 1: body explicitly discarded")
    exp.contains(first["requestBody"].get("note") or "", "discarded",
                 "req 1: note explains the discard")
    exp.eq(first["responseBody"].get("state"), "captured", "req 1: response captured")
    attachment = first["responseBody"].get("attachment")
    exp.ok(bool(attachment), "req 1: attachment referenced")
    if attachment:
        path = session_path / "attachments" / attachment
        exp.ok(path.exists(), f"req 1: attachment {attachment} exists")
        if path.exists():
            exp.eq(path.read_bytes(), b"resposta", "req 1: attachment bytes match the HAR")

    exp.eq(second["requestBody"].get("state"), "empty", "req 2: request body empty (asserted)")
    exp.eq(second["responseBody"].get("state"), "truncated", "req 2: response explicitly truncated")
    exp.eq(second["responseBody"].get("truncatedAt"), 4, "req 2: truncatedAt recorded")
    exp.eq(second["responseBody"].get("bytes"), 4, "req 2: captured bytes recorded")
    truncated_attachment = second["responseBody"].get("attachment")
    if truncated_attachment:
        path = session_path / "attachments" / truncated_attachment
        exp.eq(path.read_bytes(), b"0123", "req 2: truncated attachment has exactly 4 bytes")

    exp.eq(third["requestBody"].get("state"), "unavailable",
           "req 3: request unavailable (not empty)")
    exp.contains(third["requestBody"].get("note") or "", "does not provide",
                 "req 3: note explains unavailability")
    exp.eq(third["responseBody"].get("state"), "empty", "req 3: response empty (0 bytes)")

    states = {request["requestBody"].get("state") for request in requests} | {
        request["responseBody"].get("state") for request in requests}
    exp.eq(states, {"discarded", "captured", "empty", "truncated", "unavailable"},
           "all five states appear in the fixture")
    notes.append("`empty` is only used when the source states zero bytes; absence becomes `unavailable` with a note.")
    return exp.rows, evidence, notes


def item_6(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Diff per occurrence: duplicates preserved and non-alphabetical order."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "diff" / "session"
    session = inspect(session_path)
    first, second = session["requests"]
    a_pairs = [(entry["name"], entry["value"]) for entry in first["requestHeaders"]["headers"]]
    b_pairs = [(entry["name"], entry["value"]) for entry in second["requestHeaders"]["headers"]]
    exp.eq(a_pairs.count(("x-dup", "same")), 2, "A: duplicate x-dup:same appears twice")
    exp.eq(b_pairs.count(("x-dup", "same")), 2, "B: duplicate x-dup:same appears twice")

    diff = json.loads(core_ok("diff", str(session_path), first["id"], second["id"]))
    evidence.append(f"`scrapelens-core diff {rel(session_path)} {first['id']} {second['id']}`")
    headers = diff["requestHeaders"]
    exp.eq([item["name"] for item in headers["added"]], ["x-new"],
           "diff: only x-new added")
    exp.eq([(item["name"], item["value"]) for item in headers["removed"]], [("x-rep", "b")],
           "diff: x-rep:b removed (value does not exist in B)")
    exp.eq(headers["changed"], [], "diff: no pair changed")
    exp.ok(any(move["name"] == "x-seq" for move in headers["reordered"]),
           "diff: x-seq reordering detected as reordered")
    exp.eq(headers["unchanged"], 6, "diff: six occurrences unchanged")
    touched = {item["name"] for item in headers["added"]} | {
        item["name"] for item in headers["removed"]} | {move["name"] for move in headers["reordered"]}
    exp.ok("x-dup" not in touched, "diff: the two x-dup occurrences were not collapsed")
    exp.eq(headers["added"][0].get("index"), 6, "diff: global index of the added occurrence")
    exp.ok(headers["reordered"][0]["a"]["index"] == 0 and headers["reordered"][0]["b"]["index"] == 1,
           "diff: reordering uses the original indices (0 → 1), not alphabetical order")
    exp.eq(diff["responseHeaders"]["added"] or [], [], "diff: response with no additions")
    exp.eq(diff["responseHeaders"]["removed"] or [], [], "diff: response with no removals")
    exp.eq(diff["cookies"]["unchanged"], 0, "diff: no cookies in this fixture")

    # The original order remains available in the session (the diff does not rewrite it).
    exp.eq(a_pairs[:4], [("x-seq", "1"), ("X-Rep", "a"), ("x-seq", "2"), ("x-rep", "b")],
           "A: original order intact after the diff")
    notes.append("The diff compares occurrences; `reordered` uses the original indices of A and B.")
    return exp.rows, evidence, notes


def item_7(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """cURL/Python export with hostile data and correct escaping."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "export-special" / "session"
    session = inspect(session_path)
    request = session["requests"][0]
    nul_request = session["requests"][1]
    # %C3%A7%C3%A3o is percent-encoded non-ASCII UTF-8 input, kept as is.
    expected_url = ("https://fixture.invalid/p?q=o'relly&x=$HOME&y=`id`&z=a&b=100%"
                    "&u=%C3%A7%C3%A3o&pipe=|&semi=;")
    expected_headers = [
        ("Host", "fixture.invalid"),
        ("x-quote", "it's \"$HOME\" `id` \\ backslash"),
        ("x-dup", "a"),
        ("x-dup", "b"),
        ("content-length", "15"),
    ]
    expected_body = b"a'b\"$HOME`id`\\\n"
    exp.eq(len(session["requests"]), 2, "two export requests")

    curl = core("export-curl", str(session_path), request["id"])
    exp.eq(curl.returncode, 0, "export-curl returns 0")
    exp.contains(curl.stderr, "export.header_injection",
                 "cURL: header with CR/LF discarded with a warning")
    script = ctx["run"] / "item7" / "export.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(curl.stdout, encoding="utf-8")
    syntax = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    exp.eq(syntax.returncode, 0, f"cURL: script passes `bash -n` ({syntax.stderr.strip()})")

    stub = ctx["run"] / "item7" / "stub.sh"
    stub.write_text(
        "curl() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' -- \"$@\"; }\n",
        encoding="utf-8")
    runner = ctx["run"] / "item7" / "run.sh"
    runner.write_text(f". {shlex_quote(str(stub))}\n. {shlex_quote(str(script))}\n", encoding="utf-8")
    executed = subprocess.run(["bash", str(runner)], capture_output=True, text=True)
    exp.eq(executed.returncode, 0, "cURL: execution with stub does not fail")
    argv: list[str] = []
    for line in executed.stdout.splitlines():
        line = line.strip()
        if line.startswith("["):
            argv = json.loads(line)
    exp.ok(bool(argv), "cURL: stub captured argv")
    if argv:
        url_index = argv.index("--url")
        exp.eq(argv[url_index + 1], expected_url,
               "cURL: hostile URL reaches the shell intact")
        got_headers = [argv[index + 1] for index, token in enumerate(argv) if token == "--header"]
        exp.eq([tuple(header.split(": ", 1)) for header in got_headers], expected_headers,
               "cURL: headers, order and duplicates arrive intact")
        exp.ok("--data-binary" in argv, "cURL: body included")
        if "--data-binary" in argv:
            exp.eq(argv[argv.index("--data-binary") + 1].encode(), expected_body,
                   "cURL: body bytes (quotes, $, backtick, backslash, \\n) intact")
        exp.ok(not any("x-bad" in value for value in got_headers),
               "cURL: header x-bad (CR/LF) is not replicated")

    nul_curl = core("export-curl", str(session_path), nul_request["id"])
    exp.eq(nul_curl.returncode, 0, "cURL: export with NUL body returns 0")
    exp.contains(nul_curl.stderr, "export.body_nul",
                 "cURL: NUL body omitted with a warning (not silently truncated)")
    exp.ok("--data-binary" not in nul_curl.stdout,
           "cURL: NUL body does not become a partial argument")

    python_export = core("export-python", str(session_path), request["id"])
    exp.eq(python_export.returncode, 0, "export-python returns 0")
    exp.contains(python_export.stderr, "export.header_injection",
                 "Python: header with CR/LF discarded with a warning")
    py_path = ctx["run"] / "item7" / "export.py"
    py_path.write_text(python_export.stdout, encoding="utf-8")
    compiled = subprocess.run([sys.executable, "-m", "py_compile", str(py_path)],
                              capture_output=True, text=True)
    exp.eq(compiled.returncode, 0, f"Python: valid syntax ({compiled.stderr.strip()})")
    method, target, sent_headers, sent_body = python_literals(py_path)
    exp.eq((method, target), ("POST", "/p?q=o'relly&x=$HOME&y=`id`&z=a&b=100%"
                              "&u=%C3%A7%C3%A3o&pipe=|&semi=;"),
           "Python: hostile method and target intact")
    exp.eq(sent_headers, expected_headers,
           "Python: putheader per occurrence, order and duplicates intact")
    exp.eq(sent_body, expected_body, "Python: body bytes intact")
    exp.ok(not any("x-bad" in name for name, _ in sent_headers),
           "Python: header x-bad is not replicated")

    nul_python = core("export-python", str(session_path), nul_request["id"])
    nul_path = ctx["run"] / "item7" / "nul.py"
    nul_path.write_text(nul_python.stdout, encoding="utf-8")
    nul_compiled = subprocess.run([sys.executable, "-m", "py_compile", str(nul_path)],
                                  capture_output=True, text=True)
    exp.eq(nul_compiled.returncode, 0, "Python: export with NUL compiles")
    _, _, _, nul_sent = python_literals(nul_path)
    exp.eq(nul_sent, b"bin\x00ario", "Python: NUL bytes preserved in the body")

    evidence += [
        f"`scrapelens-core export-curl {rel(session_path)} {request['id']}` → `bash -n` + execution with a stub that records argv",
        f"`scrapelens-core export-python {rel(session_path)} {request['id']}` → `python3 -m py_compile` + AST with literals",
        f"generated commands: {rel(script)}, {rel(py_path)}",
    ]
    notes.append("The exporters promise the HTTP request, not TLS/fingerprint (JA3/JA4, frames, HPACK).")
    return exp.rows, evidence, notes


def item_8(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Sanitization: credentials, cookies, token in URL, bodies and raw events."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    source = FIX / "sanitize" / "session"
    out = ctx["run"] / "item8" / "sanitized"
    if out.exists():
        shutil.rmtree(out)
    proc = core("sanitize", str(source), str(out))
    exp.eq(proc.returncode, 0, "sanitize returns 0")
    report = json.loads(proc.stdout) if proc.stdout.strip().startswith("{") else {}
    evidence.append(f"`scrapelens-core sanitize {rel(source)} {rel(out)}`")

    exp.ok(out.exists(), "sanitized directory created")
    if not out.exists():
        return exp.rows, evidence, notes
    exp.eq(stat.S_IMODE(out.stat().st_mode), 0o700, "sanitized directory with mode 0700")
    session_file = out / "session.json"
    exp.ok(session_file.exists(), "session.json present")
    exp.eq(stat.S_IMODE(session_file.stat().st_mode), 0o600, "session.json with mode 0600")
    for name in ("cdp-events.jsonl", "netlog.json"):
        exp.ok(not (out / name).exists(), f"raw event {name} not copied to the export")
    exp.contains(report.get("redactions", {}), "rawEvents", "report counts rawEvents")
    warning_codes = {warning["code"] for warning in report.get("warnings", [])}
    exp.contains(warning_codes, "sanitize.raw_events_removed",
                 "sanitize.raw_events_removed warning present")
    exp.contains(warning_codes, "sanitize.attachment_omitted",
                 "non-sanitizable attachment omitted with a warning")

    leaks: list[str] = []
    for path in out.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for secret in SECRETS:
                if secret.encode() in data:
                    leaks.append(f"{path.relative_to(out)}:{secret}")
    exp.eq(leaks, [], "no SECRET-* secret or e-mail remains in the sanitized tree")

    sanitized = json.loads(session_file.read_text(encoding="utf-8"))
    exp.contains(sanitized["session"].get("labels", []), "sanitized",
                 "session marked with label sanitized")
    urls = [request["url"] for request in sanitized["requests"]]
    exp.ok(all("SECRET" not in url for url in urls), "sanitized URLs without token")
    exp.ok(any("REDACTED" in url for url in urls), "[REDACTED] placeholder appears in the URL")
    exp.ok(all("SECRET" not in json.dumps(request.get("cookie", {}), ensure_ascii=False)
               for request in sanitized["requests"]), "Cookie sanitized")
    exp.ok(all("SECRET" not in json.dumps(request.get("setCookies", []), ensure_ascii=False)
               for request in sanitized["requests"]), "Set-Cookie sanitized")
    exp.contains(session_file.read_text(encoding="utf-8"), "[REDACTED]",
                 "values replaced by [REDACTED]")

    again = core("sanitize", str(source), str(out))
    exp.ok(again.returncode != 0, "sanitize refuses to overwrite an existing destination")
    exp.contains(again.stderr, "already contains", "refusal message is actionable")

    evidence += [
        f"modes: `{oct(stat.S_IMODE(out.stat().st_mode))}` on the directory and "
        f"`{oct(stat.S_IMODE(session_file.stat().st_mode))}` on session.json",
        "recursive scan for 10 SECRET-* markers + e-mail: no occurrences",
    ]
    notes.append("Sanitization does not promise to detect tokens in free-form path/HTML; those bodies are omitted with a warning.")
    return exp.rows, evidence, notes


def item_9(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Real capture cycle on macOS with a dedicated Chrome, no certificate."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    run_dir = ctx.get("capture")
    if not run_dir or not pathlib.Path(run_dir).exists():
        return [], [], ["not tested: no run of `tests/capture/run-cycle.sh` provided"]
    run_dir = pathlib.Path(run_dir)
    summary_path = run_dir / "run.json"
    exp.ok(summary_path.exists(), "capture run.json exists")
    if not summary_path.exists():
        return exp.rows, evidence, notes
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    evidence.append(f"real run: `{rel(run_dir)}` (generated by `tests/capture/run-cycle.sh`); "
                    "stable copy in `tests/results/capture-latest/run.json`")

    for leg in summary.get("captures", []):
        meta = leg.get("meta", {})
        flags = meta.get("chromeArgs", [])
        profile = meta.get("profile", "")
        exp.ok("--disable-quic" not in flags, f"{leg['name']}: QUIC was not disabled")
        exp.ok(any(flag.startswith("--enable-quic") for flag in flags),
               f"{leg['name']}: --enable-quic present")
        exp.ok(any(flag.startswith("--ignore-certificate-errors-spki-list=") for flag in flags),
               f"{leg['name']}: certificate waived by SPKI (nothing installed)")
        exp.ok("--ignore-certificate-errors" not in flags,
               f"{leg['name']}: does not use a global certificate bypass")
        exp.ok("--user-data-dir=" in " ".join(flags), f"{leg['name']}: explicit dedicated profile")
        exp.ok(bool(profile) and str(pathlib.Path(run_dir).resolve()) in str(pathlib.Path(profile).resolve()),
               f"{leg['name']}: dedicated profile inside the run directory")
        exp.ok("--remote-debugging-address=127.0.0.1" in flags,
               f"{leg['name']}: debug exposed only on loopback")
        exp.ok(meta.get("browser", {}).get("name") == "Chrome",
               f"{leg['name']}: Chrome browser identified")
        exp.contains(meta.get("browser", {}).get("version", ""), ".",
                     f"{leg['name']}: Chrome version recorded")

        session_dir = run_dir / leg["session"]
        exp.ok(session_dir.exists(), f"{leg['name']}: imported session exists")
        if not session_dir.exists():
            continue
        session = inspect(session_dir)
        state = session["session"]["completeness"]["state"]
        exp.eq(state, "complete", f"{leg['name']}: completeness=complete (flush finished)")
        requests = session["requests"]
        exp.ok(len(requests) >= 3, f"{leg['name']}: {len(requests)} real requests captured")
        protocols = {request["protocol"] for request in requests}
        exp.contains(protocols, leg.get("protocol"), f"{leg['name']}: protocol {leg.get('protocol')} present")
        exp.contains(protocols - {"unknown"}, leg.get("protocol"),
                     f"{leg['name']}: no divergent protocol")
        exp.ok(all(request.get("match") != "unmatched" for request in requests),
               f"{leg['name']}: all CDP requests correlated (matched/ambiguous)")
        verified = [request for request in requests
                    if view_verification(request["requestHeaders"]) == "verified"]
        if leg.get("protocol") == "h1":
            exp.ok(bool(verified), "h1: at least one request with verified headers (NetLog)")
        if "h2" in protocols:
            h2_views = {view_verification(request["requestHeaders"])
                        for request in requests if request["protocol"] == "h2"}
            exp.ok(h2_views and h2_views <= {"partial"},
                   f"h2: request headers remain partial (seen: {sorted(h2_views)})")
        exp.ok(any(request.get("status") for request in requests),
               f"{leg['name']}: real HTTP status present")
        states = [request["responseBody"].get("state") for request in requests]
        exp.ok(all(state in {"captured", "empty", "truncated", "unavailable", "discarded"}
                   for state in states),
               f"{leg['name']}: all bodies have explicit state {sorted(set(states))}")
        exp.ok(all(request["responseBody"].get("note")
                   for request in requests
                   if request["responseBody"].get("state") == "unavailable"),
               f"{leg['name']}: unavailable body always accompanied by a note")
        if leg.get("protocol") == "h3":
            exp.ok(any(request["protocol"] == "h3" for request in requests),
                   "h3: QUIC actually used (QUIC intact)")
            exp.ok(len(session.get("streamSessions", [])) > 0,
                   "h3: QUIC StreamSessions recorded")

    if summary.get("redirects", 0) >= 1:
        notes.append("The real page `/page` exercised redirects and POSTs.")
    else:
        exp.ok(False, "real capture exercised at least one redirect")
    har = summary.get("har")
    exp.ok(har is not None, "HAR rebuilt from the real CDP imported without failure")
    if har:
        exp.ok(har.get("requests", 0) > 0, f"real HAR: {har.get('requests')} requests imported")
        exp.ok(har.get("completeness") in {"complete", "partial"},
               f"real HAR: explicit completeness ({har.get('completeness')})")
    notes.append("The cycle's HAR is rebuilt from CDP (`experiments/har_from_cdp.mjs`), because Chrome 156 "
                 "does not expose `Network.getHAR`; the creator declares the origin and the order is not proven (unverified).")

    ambiguous = summary.get("ambiguous", 0)
    exp.ok(ambiguous >= 1,
           f"real capture: {ambiguous} ambiguous request(s) among the identical simultaneous ones")
    exp.ok(summary.get("certificateInstalled") is False,
           "no certificate was installed in the system")
    for common_name in ("ScrapeLens local test server", "ScrapeLens local test CA (synthetic)"):
        found = subprocess.run(["security", "find-certificate", "-c", common_name],
                               capture_output=True, text=True)
        exp.ok(found.returncode != 0,
               f"user keychain does not contain the certificate {common_name!r}")
    notes.append("The real cycle uses CDP, which does not fetch bodies: all bodies stay `unavailable` "
                 "with a note. Body capture (Network.getResponseBody) is not yet on the live path.")

    app_path = ctx.get("app")
    if app_path and pathlib.Path(app_path).exists():
        app = json.loads(pathlib.Path(app_path).read_text(encoding="utf-8"))
        bundle = app.get("bundle", {})
        live = app.get("capture", {})
        imports = app.get("imports", {})
        exp.ok(bundle.get("exists") is True, "app: .app bundle exists")
        exp.ok(bundle.get("arm64") is True, f"app: Mach-O arm64 ({bundle.get('machO', '')})")
        exp.ok(bundle.get("singleBinary") is True,
               f"app: single binary without sidecar ({bundle.get('binaries')})")
        exp.ok(bundle.get("signature") in ("adhoc", "local-identity"),
               f"app: ad-hoc signature or local identity 'ScrapeLens Local Signing' (no Apple certificate): {bundle.get('signature')}")
        exp.ok(bundle.get("codesignVerifyDeepStrict") is True,
               f"app: codesign --verify --deep --strict passed ({bundle.get('codesignVerifyOutput')})")
        # Recomputed on disk, independent of run.json.
        _cs = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(APP_EXECUTABLE.parents[2])],
                             capture_output=True, text=True)
        exp.ok(_cs.returncode == 0, f"app: codesign --verify --deep --strict recomputed on disk ({(_cs.stderr or _cs.stdout).strip()[-120:]})")
        exp.ok((bundle.get("sizeBytes") or 0) > 10 * 1024 * 1024,
               f"app: bundle with {((bundle.get('sizeBytes') or 0) / (1024 * 1024)):.2f} MiB")
        exp.eq(bundle.get("executableSha256"), EXPECTED_APP_SHA256,
               "app: executable is the documented final bundle (SHA-256)")
        # Recomputed on disk: run.json alone does not prove that the bundle exists.
        real_exe = APP_EXECUTABLE
        exp.ok(real_exe.is_file(), f"app: executable exists on disk ({real_exe})")
        if real_exe.is_file():
            disk = sha256(real_exe)
            exp.eq(disk, EXPECTED_APP_SHA256,
                   "app: SHA-256 of the executable on disk = EXPECTED_APP_SHA256")
            exp.eq(disk, bundle.get("executableSha256"),
                   "app: SHA-256 of the executable on disk = the one recorded in run.json")
        exp.ok((bundle.get("executableBytes") or 0) > 0,
               f"app: executable with {bundle.get('executableBytes')} bytes")

        exp.eq(live.get("mode"), "cdp+netlog", "app: live session in cdp+netlog mode")
        exp.eq(live.get("completeness"), "complete", "app: live session complete")
        exp.ok(live.get("requests", 0) >= 10, f"app: {live.get('requests')} real requests in the session")
        exp.ok("h1" in live.get("protocols", []), f"app: real protocols {live.get('protocols')}")
        exp.ok(live.get("verifiedHeaderEntries", 0) > 0,
               f"app: {live.get('verifiedHeaderEntries')} verified headers")
        exp.eq(live.get("verifiedSources"), ["netlog"],
               "app: verified headers come from NetLog (correct source)")
        exp.ok(all("HTTP_TRANSACTION_SEND_REQUEST_HEADERS" in event
                   for event in live.get("verifiedEvents", [])),
               "app: h1 verification anchored on HTTP_TRANSACTION_SEND_REQUEST_HEADERS")
        exp.ok(live.get("unmatched", 0) == 0,
               "app: no CDP request left without a match")
        ambiguous = live.get("ambiguous", [])
        exp.ok(len(ambiguous) >= 1, f"app: {len(ambiguous)} ambiguous requests")
        exp.ok(all(len(item.get("candidates", [])) >= 2 for item in ambiguous),
               "app: ambiguity always exposes >=2 candidates")
        exp.ok(all(item.get("candidates") and len(set(item["candidates"])) == len(item["candidates"])
                   for item in ambiguous), "app: distinct candidates, no silent choice")
        exp.eq(live.get("hasDemoLabel"), False, "app: real session without demo/synthetic label")
        exp.contains(live.get("cookieNames", []), "sc_dup", "app: cookie with duplicate name preserved")
        exp.ok(live.get("setCookieLines", 0) >= 4,
               f"app: {live.get('setCookieLines')} real Set-Cookie lines")
        exp.ok(live.get("redirects", 0) >= 1, f"app: {live.get('redirects')} real redirects")
        exp.ok(set(live.get("responseBodyStates", [])) <= {"captured", "empty", "truncated",
                                                          "unavailable", "discarded"},
               "app: valid body states in the real capture")
        exp.ok(live.get("unavailableWithNote") is True,
               "app: unavailable body always with a note (no invented body)")
        exp.eq(live.get("dirMode"), "0o700", "app: session directory 0700")
        for name in ("session.json", "cdp-events.jsonl", "netlog.json"):
            artifact = live.get("rawArtifacts", {}).get(name, {})
            exp.ok(artifact.get("exists") is True and artifact.get("bytes", 0) > 0,
                   f"app: raw artifact {name} present")
            exp.eq(artifact.get("mode"), "0o600", f"app: {name} with mode 0600")
        exp.contains(live.get("warnings", []), "correlate.ambiguous",
                     "app: correlate.ambiguous warning persisted")
        exp.ok(app.get("gui", {}).get("screenshotExists") is True,
               "app: screenshot of the real cycle captured")
        exp.ok(app.get("gui", {}).get("startUrl") == "http://127.0.0.1:8781/page",
               "app: cycle started on the local testserver page")
        server = app.get("testserver", {})
        exp.ok(server.get("h1Lines", 0) >= 10,
               f"app: testserver logged {server.get('h1Lines')} Chrome requests")

        har_import = imports.get("har") or {}
        exp.ok(bool(har_import), "app: real HAR session imported by the app")
        if har_import:
            exp.contains(har_import.get("labels", []), "har-import", "app: HAR with label har-import")
            exp.eq(har_import.get("mode"), "har-import", "app: HAR in har-import mode")
            exp.eq(har_import.get("completeness"), "complete", "app: HAR complete")
            exp.eq(har_import.get("requests"), 24,
                   "app: HAR imported via the UI has the 24 requests of the prepared file")
            exp.ok({"h1", "h2"} <= set(har_import.get("protocols", [])),
                   f"app: HAR covers h1 and h2 ({har_import.get('protocols')})")
            har_counts = har_import.get("counts") or {}
            exp.eq(har_counts.get("sourceEvents"), 24, "app: HAR with 24 sourceEvents persisted")
            exp.eq(har_counts.get("sourceEventsUsed"), 24, "app: HAR uses the 24 sourceEvents")
            exp.eq(har_counts.get("sourceEventsUnknown"), 0, "app: HAR without unknown source events")
            exp.ok((har_import.get("source") or {}).get("matchesSourceSequence") is True,
                   "app: saved HAR reproduces the method/URL sequence of har-derived.json")
            exp.eq(har_import.get("verifiedHeaderEntries"), 0,
                   "app: HAR does not claim verified order (0 verified headers)")
            exp.eq(har_import.get("headerSources"), ["har"],
                   "app: headers of the imported HAR have source har")
            exp.eq(har_import.get("hasDemoLabel"), False, "app: real HAR without demo label")
            exp.eq(har_import.get("dirMode"), "0o700", "app: imported HAR directory 0700")
            exp.eq((har_import.get("rawArtifacts", {}).get("session.json") or {}).get("mode"), "0o600",
                   "app: imported HAR session.json 0600")
            exp.ok((har_import.get("reload") or {}).get("unchangedAfterInspect") is True
                   and (har_import.get("reload") or {}).get("requestsFromInspect") == 24,
                   "app: imported HAR rereads from disk with 24 requests, without changing the file")
        netlog_import = imports.get("netlog") or {}
        exp.ok(bool(netlog_import), "app: real NetLog session imported by the app")
        if netlog_import:
            exp.contains(netlog_import.get("labels", []), "netlog-import",
                         "app: NetLog with label netlog-import")
            exp.eq(netlog_import.get("mode"), "netlog-import", "app: NetLog in netlog-import mode")
            exp.eq(netlog_import.get("completeness"), "partial",
                   "app: NetLog alone partial with a reason")
            exp.ok(bool(netlog_import.get("completenessReasons")),
                   "app: reason for partiality declared")
            exp.eq(netlog_import.get("requests"), 32,
                   "app: NetLog imported via the UI has the 32 requests of the prepared file")
            exp.ok({"h1", "h2", "h3"} <= set(netlog_import.get("protocols", [])),
                   f"app: NetLog covers h1/h2/h3 ({netlog_import.get('protocols')})")
            netlog_counts = netlog_import.get("counts") or {}
            exp.eq(netlog_counts.get("sourceEvents"), 5354,
                   "app: NetLog with 5354 sourceEvents persisted")
            exp.eq(netlog_counts.get("sourceEventsUsed"), 5354, "app: NetLog uses the 5354 sourceEvents")
            exp.eq(netlog_counts.get("sourceEventsUnknown"), 0,
                   "app: NetLog without unknown source events")
            exp.eq(netlog_import.get("streamSessions"), 15,
                   "app: 15 h3 StreamSessions persisted in the NetLog")
            exp.ok((netlog_import.get("source") or {}).get("matchesSourceBytes") is True,
                   "app: persisted netlog.json is byte-identical to the prepared h1h2h3.chrome-netlog.json")
            exp.ok(netlog_import.get("verifiedHeaderEntries", 0) > 0
                   and netlog_import.get("verifiedSources") == ["netlog"],
                   f"app: {netlog_import.get('verifiedHeaderEntries')} verified headers with netlog source")
            exp.eq(netlog_import.get("headerSources"), ["netlog"],
                   "app: headers of the imported NetLog have source netlog")
            exp.eq(netlog_import.get("hasDemoLabel"), False, "app: real NetLog without demo label")
            exp.eq(netlog_import.get("dirMode"), "0o700", "app: imported NetLog directory 0700")
            exp.eq((netlog_import.get("rawArtifacts", {}).get("session.json") or {}).get("mode"), "0o600",
                   "app: imported NetLog session.json 0600")
            exp.eq((netlog_import.get("rawArtifacts", {}).get("netlog.json") or {}).get("mode"), "0o600",
                   "app: netlog.json copied into the session with 0600")
            exp.ok((netlog_import.get("reload") or {}).get("unchangedAfterInspect") is True
                   and (netlog_import.get("reload") or {}).get("requestsFromInspect") == 32,
                   "app: imported NetLog rereads from disk with 32 requests, without changing the file")
        exp.ok(app.get("gui", {}).get("importsScreenshotExists") is True,
               "app: screenshot of the session imported via the UI captured")
        evidence.append(
            f"packaged app: `ScrapeLens.app` {((bundle.get('sizeBytes') or 0) / (1024 * 1024)):.2f} MiB, "
            f"arm64, signature {bundle.get('signature')}, single binary, executable `{bundle.get('executableSha256')}`; "
            f"live capture {live.get('id')} "
            f"({live.get('requests')} req, {live.get('verifiedHeaderEntries')} verified headers, "
            f"{len(ambiguous)} ambiguous); HAR import via the UI `{har_import.get('id')}` "
            f"({har_import.get('requests')} req, {har_import.get('protocols')}, "
            f"{har_import.get('counts', {}).get('sourceEvents')} sourceEvents); "
            f"NetLog import via the UI `{netlog_import.get('id')}` "
            f"({netlog_import.get('requests')} req, {netlog_import.get('protocols')}, "
            f"{netlog_import.get('streamSessions')} StreamSessions, "
            f"{netlog_import.get('counts', {}).get('sourceEvents')} sourceEvents).")
        evidence.append(f"real app sessions: `{rel(pathlib.Path(app.get('appSessionsDir', '')))}` "
                        f"· screenshots `{rel(pathlib.Path(app.get('gui', {}).get('screenshot') or ''))}` and "
                        f"`{rel(pathlib.Path(app.get('gui', {}).get('importsScreenshot') or ''))}`")
        notes.append("In this round the Start/Stop cycle was redone in the final bundle "
                     f"(`{EXPECTED_APP_SHA256[:12]}`, built at `c2d2b8f`, stable local signature, multi-target capture); the live session above is new, not reused.")
        notes.append("The HAR and NetLog imports were also redone in the final bundle "
                     f"(`{har_import.get('id')}` and `{netlog_import.get('id')}`), now via the UI: the harness "
                     "chose the files by mouse clicks in the native panel (the keyboard does not reach "
                     "the picker; in the final round 10 it was in the foreground). "
                     "Verification is independent of the user's confirmation: the saved HAR reproduces the "
                     "method/URL sequence of `har-derived.json` (24 entries) and the persisted `netlog.json` is "
                     "byte-identical to `h1h2h3.chrome-netlog.json` (SHA-256). Repeated imports of the same "
                     "files (suffixes `-N` on `har-3dbc391c02a985c5` and `netlog-1704043c442dcbd1`) have an identical `session.json`, with no effect on validation. The NetLog "
                     "alone warns `netlog.time_unit_assumed` because, without CDP, the NetLog clock unit "
                     "cannot be calibrated — the limitation is explicit in the session.")
    else:
        exp.ok(False, "app: cycle summary from the .app is missing (run tests/capture/app_validate.py)")
    evidence.append(
        f"CLI: Chrome {summary.get('chromeVersion', '?')}; {summary.get('requestCount', '?')} requests; "
        f"{summary.get('h3StreamSessions', 0)} StreamSessions h3; "
        f"{len(ambiguous) if isinstance(ambiguous, list) else ambiguous} ambiguous; "
        f"redirects={summary.get('redirects', 0)}")
    return exp.rows, evidence, notes


def item_10(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Large import: documented size, measured time and memory."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    large = WORK / "large"
    large.mkdir(parents=True, exist_ok=True)
    count = 20000

    def write_har(path: pathlib.Path, with_bodies: bool) -> None:
        marker = path.with_suffix(".mode")
        mode = "bodies" if with_bodies else "no-bodies"
        if path.exists() and marker.exists() and marker.read_text().strip() == mode:
            return
        entries = []
        for index in range(count):
            content = ({"mimeType": "application/json", "size": 20,
                        "text": json.dumps({"i": index, "pad": "xx"})}
                       if with_bodies else {"mimeType": "application/json", "size": 0})
            entries.append({
                "startedDateTime": f"2026-10-26T21:{index // 3600 % 60:02d}:{index // 60 % 60:02d}.{index % 1000:03d}Z",
                "time": 1.5,
                "request": {
                    "method": "GET",
                    "url": f"https://fixture.invalid/large/{index}?n={index}",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": name, "value": f"v{index}-{name}"} for name in
                                ("accept", "x-seq", "x-dup", "x-dup")],
                    "queryString": [{"name": "n", "value": str(index)}],
                    "cookies": [], "headersSize": -1, "bodySize": 0,
                },
                "response": {
                    "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "content-type", "value": "application/json"},
                                {"name": "x-resp", "value": f"r{index}"},
                                {"name": "content-length", "value": "0"}],
                    "cookies": [], "content": content,
                    "redirectURL": "", "headersSize": 120, "bodySize": content["size"],
                },
                "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0},
            })
        path.write_text(json.dumps({"log": {"version": "1.2",
                                             "creator": {"name": "scrapelens-aceite-large"},
                                             "entries": entries}}), encoding="utf-8")
        marker.write_text(mode + "\n", encoding="utf-8")

    har_path = large / "large.har"
    write_har(har_path, with_bodies=False)
    size_mb = har_path.stat().st_size / (1024 * 1024)
    exp.ok(size_mb > 5, f"large HAR generated ({size_mb:.1f} MiB)")
    notes.append(f"Main HAR: {count:,} requests, {size_mb:.1f} MiB, without bodies "
                 "(the pathological path with 20 thousand attachments is measured separately).")

    session_dir = large / "session"
    if session_dir.exists():
        shutil.rmtree(session_dir)
    elapsed, rss = measure(["import-har", str(har_path), "--out", str(session_dir), "--label", "synthetic-fixture"])
    session_mb = (session_dir / "session.json").stat().st_size / (1024 * 1024)
    evidence.append(
        f"`/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` "
        f"→ HAR {size_mb:.1f} MiB, {count:,} requests, {elapsed:.2f} s, peak {rss / (1024 * 1024):.0f} MiB RSS")
    evidence.append(f"saved session: session.json {session_mb:.1f} MiB")

    elapsed_inspect, rss_inspect = measure(["inspect", str(session_dir)])
    evidence.append(
        f"`/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` "
        f"→ {elapsed_inspect:.2f} s, peak {rss_inspect / (1024 * 1024):.0f} MiB RSS")

    session = inspect(session_dir)
    exp.eq(len(session["requests"]), count, f"all {count:,} requests imported")
    exp.eq(session["session"]["completeness"]["state"], "complete",
           "large import: completeness=complete")
    exp.ok(elapsed < 60, f"import-har under 60 s ({elapsed:.2f} s)")
    exp.ok(rss < 1536 * 1024 * 1024,
           f"import peak under 1.5 GiB ({rss / (1024 ** 2):.0f} MiB)")
    exp.ok(elapsed_inspect < 60, f"inspect under 60 s ({elapsed_inspect:.2f} s)")
    exp.ok(rss_inspect < 3584 * 1024 * 1024,
           f"inspect peak under 3.5 GiB ({rss_inspect / (1024 ** 2):.0f} MiB)")
    notes.append(f"`inspect` materializes the whole session as pretty JSON ({session_mb:.1f} MiB); "
                 f"the peak of {rss_inspect / (1024 ** 2):.0f} MiB comes from serialization, not from the parser.")

    # Supplementary measurement: the worst case of attachments (20 thousand bodies of 20 bytes).
    bodies_cache = RESULTS / "large-bodies.json"
    if ctx.get("large_bodies"):
        bodies_har = large / "large-bodies.har"
        write_har(bodies_har, with_bodies=True)
        bodies_session = large / "session-bodies"
        if bodies_session.exists():
            shutil.rmtree(bodies_session)
        bodies_elapsed, bodies_rss = measure(["import-har", str(bodies_har), "--out", str(bodies_session)])
        bodies_data = {"requests": count, "harMiB": round(bodies_har.stat().st_size / (1024 * 1024), 1),
                       "seconds": round(bodies_elapsed, 2),
                       "peakMiB": round(bodies_rss / (1024 * 1024)),
                       "sessionMiB": round((bodies_session / "session.json").stat().st_size / (1024 * 1024), 1),
                       "attachments": len(list((bodies_session / "attachments").iterdir()))}
        bodies_cache.write_text(json.dumps(bodies_data, indent=1) + "\n", encoding="utf-8")
        shutil.rmtree(bodies_session, ignore_errors=True)
        shutil.rmtree(bodies_har, ignore_errors=True)
    if bodies_cache.exists():
        bodies = json.loads(bodies_cache.read_text(encoding="utf-8"))
        evidence.append(
            f"supplementary, {bodies['requests']:,} attachments of 20 B: import {bodies['seconds']:.2f} s, "
            f"peak {bodies['peakMiB']} MiB, session {bodies['sessionMiB']} MiB")
        notes.append("Core fix confirmed: above 256 attachments, `fsync` is now batched per "
                     f"directory — {bodies['attachments']:,} attachments of 20 B import in {bodies['seconds']:.2f} s "
                     "(it was 128 s in the previous suite). Small sessions keep per-file `fsync`.")
    else:
        notes.append("Supplementary measurement with 20 thousand attachments not run in this round "
                     "(`--large-bodies`); the main path is measured above.")
    return exp.rows, evidence, notes


def python_literals(path: pathlib.Path) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Extracts method/target/headers/body literals from the generated Python script."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    method = target = ""
    headers: list[tuple[str, str]] = []
    body = b""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else ""
        if name == "putrequest" and len(node.args) >= 2:
            method = ast.literal_eval(node.args[0])
            target = ast.literal_eval(node.args[1])
        elif name == "putheader" and len(node.args) >= 2:
            headers.append((ast.literal_eval(node.args[0]), ast.literal_eval(node.args[1])))
        elif name == "send" and node.args:
            value = ast.literal_eval(node.args[0])
            body = value if isinstance(value, bytes) else str(value).encode()
    return method, target, headers, body


def measure(args: list[str]) -> tuple[float, int]:
    """Runs under /usr/bin/time -l and returns (seconds, peak RSS in bytes)."""
    import tempfile

    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as handle:
        stderr_path = pathlib.Path(handle.name)
    try:
        proc = subprocess.run(["/usr/bin/time", "-l", str(CORE), *args],
                              capture_output=True, text=True, timeout=600)
        text = proc.stderr
        if proc.returncode != 0:
            raise RuntimeError(f"core {args} failed: {text[-500:]}")
        real = re.search(r"([0-9.]+) real", text)
        rss = re.search(r"(\d+)\s+maximum resident set size", text)
        if not real or not rss:
            raise RuntimeError(f"unrecognized /usr/bin/time output: {text[-400:]}")
        return float(real.group(1)), int(rss.group(1))
    finally:
        stderr_path.unlink(missing_ok=True)


def shlex_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def rel(path: pathlib.Path) -> str:
    try:
        return str(pathlib.Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


# ------------------------------------------------------------------ execution

def item_11(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """MCP (round 11): crate tests, live tests and the full flow as a stdio client."""
    import re as _re
    rows: list[dict] = []
    evidence: list[str] = []
    notes: list[str] = []
    out_dir = RESULTS / "mcp"
    out_dir.mkdir(parents=True, exist_ok=True)
    commands: list[dict] = []

    def run_cmd(label: str, argv: list[str], cwd: pathlib.Path, timeout: int = 1500) -> dict:
        started = time.time()
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
        passed = sum(int(m.group(1)) for m in _re.finditer(r"(\d+) passed", output))
        failed = sum(int(m.group(1)) for m in _re.finditer(r"(\d+) failed", output))
        entry = {"label": label, "cmd": " ".join(argv), "cwd": rel(cwd), "rc": proc.returncode,
                 "passed": passed, "failed": failed, "seconds": round(time.time() - started, 2),
                 "tail": output[-800:]}
        commands.append(entry)
        rows.append({"ok": proc.returncode == 0,
                     "label": f"MCP {label}: rc={proc.returncode}, {passed} passed, {failed} failed"})
        return entry

    run_cmd("cargo test mcp", ["cargo", "test", "--offline"], ROOT / "mcp")
    run_cmd("cargo test capture", ["cargo", "test", "--offline"], ROOT / "capture")
    run_cmd("cargo test recon", ["cargo", "test", "--offline"], ROOT / "recon")
    run_cmd("live mcp e2e_live", ["cargo", "test", "--offline", "--test", "e2e_live", "--", "--ignored"],
            ROOT / "mcp")
    for live_name in ("live_pipe_opens_no_port_and_exposed_port_is_loopback_only",
                      "live_planted_symlinks_are_not_followed",
                      "live_port_gap_is_reported_on_all_paths",
                      "live_netlog_swap_race_does_not_write_through_a_symlink",
                      "live_inherited_fds_do_not_leak_into_chrome"):
        entry = run_cmd(f"live capture {live_name}",
                ["cargo", "test", "--offline", "--lib", f"browser::tests::{live_name}", "--", "--ignored", "--exact", "--test-threads=1"], ROOT / "capture")
        if entry["passed"] != 1 or entry["failed"] != 0:
            rows.append({"ok": False, "label": f"MCP live capture {live_name}: expected 1 test run, got {entry['passed']}"})
    run_cmd("live recon live_e2e.sh", ["sh", "scripts/live_e2e.sh"], ROOT / "recon")

    started = time.time()
    full = subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "acceptance" / "mcp_flow.py")],
                          cwd=ROOT, capture_output=True, text=True, timeout=900)
    try:
        flow_json = json.loads(full.stdout)
    except json.JSONDecodeError:
        flow_json = {"ok": False, "checks": [{"name": "flow output is JSON", "ok": False,
                                             "detail": (full.stdout + full.stderr)[-300:]}]}
    commands.append({"label": "stdio flow (independent client)", "cmd": "python3 -I tests/acceptance/mcp_flow.py",
                     "rc": full.returncode, "passed": flow_json.get("passed"), "failed": flow_json.get("failed"),
                     "seconds": round(time.time() - started, 2), "tail": full.stderr[-400:]})
    rows.append({"ok": full.returncode == 0 and bool(flow_json.get("ok")),
                 "label": f"MCP stdio flow: rc={full.returncode}, {flow_json.get('passed')} passed, "
                          f"{flow_json.get('failed')} failed"})
    for check_row in flow_json.get("checks", []):
        rows.append({"ok": bool(check_row.get("ok")),
                     "label": f"flow: {check_row.get('name')}"
                              + ("" if check_row.get("ok") else f" — {check_row.get('detail', '')}")})

    (out_dir / "flow.json").write_text(json.dumps(flow_json, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    run_json = {"generatedAt": now_iso(), "commands": commands,
                "flow": {"ok": flow_json.get("ok"), "passed": flow_json.get("passed"),
                         "failed": flow_json.get("failed"), "checks": flow_json.get("checks", [])}}
    (out_dir / "run.json").write_text(json.dumps(run_json, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    evidence.append(f"`{rel(out_dir / 'run.json')}` and `{rel(out_dir / 'flow.json')}` (command and flow outputs)")
    notes.append("Flow client: `tests/acceptance/mcp_flow.py`, JSON-RPC over stdio in Python, without the Rust harness; "
                 "local HTTP server on 127.0.0.1, real headless Chrome, nothing external.")
    return rows, evidence, notes


ITEMS = [
    (1, "Repeated headers and cookies preserved in the fixtures", item_1),
    (2, "Valid, incomplete and unknown-event HAR and NetLog", item_2),
    (3, "Identical simultaneous requests without false association", item_3),
    (4, "Redirects and multiple attempts", item_4),
    (5, "Explicit missing/truncated/discarded bodies", item_5),
    (6, "Diff without losing duplicates", item_6),
    (7, "cURL/Python export with special characters", item_7),
    (8, "Sanitization including raw events", item_8),
    (9, "Real capture cycle on macOS", item_9),
    (10, "Large import with documented size", item_10),
    (11, "MCP: crate tests, live tests and full stdio flow", item_11),
]


def run_item(number: int, title: str, fn, ctx: dict) -> dict:
    started = time.time()
    try:
        rows, evidence, notes = fn(ctx)
    except Exception as error:  # noqa: BLE001 - the report needs the real error
        rows, evidence, notes = [{"ok": False, "label": f"exception: {error}"}], [], []
    elapsed = time.time() - started
    if number == 9 and not rows:
        status = "not tested"
    else:
        status = "approved" if rows and all(row["ok"] for row in rows) else "failed"
    return {
        "item": number,
        "title": title,
        "status": status,
        "assertions": rows,
        "passed": sum(1 for row in rows if row["ok"]),
        "failed": sum(1 for row in rows if not row["ok"]),
        "evidence": evidence,
        "notes": notes,
        "seconds": round(elapsed, 2),
    }


def evidence_scope(capture: str | None, app_run: str | None) -> list[str]:
    """Separates what was produced in this round from historical evidence."""
    lines: list[str] = []
    if capture and pathlib.Path(capture).exists():
        summary = pathlib.Path(capture) / "run.json"
        stamp = ""
        if summary.exists():
            data = json.loads(summary.read_text(encoding="utf-8"))
            stamp = data.get("generatedAt") or data.get("startedAt") or ""
        lines.append(f"New in this round: CLI capture `{rel(pathlib.Path(capture))}`"
                     + (f" ({stamp})" if stamp else "")
                     + ", with both legs (h1h2 and h3) and the HAR derived from CDP.")
    if app_run and pathlib.Path(app_run).exists():
        app = json.loads(pathlib.Path(app_run).read_text(encoding="utf-8"))
        live = app.get("capture", {})
        imports = app.get("imports") or {}
        lines.append(f"New in this round: live session `{live.get('id')}` started and stopped "
                     f"by the final bundle (`{str(app.get('bundle', {}).get('executableSha256'))[:12]}`).")
        historical = [f"{name} `{data.get('id')}`" for name, data in imports.items() if data]
        if historical:
            lines.append("New in this round: HAR/NetLog imports via the UI of the final bundle ("
                         + ", ".join(historical)
                         + "), with manual selection by the user and verification by SHA-256/sequence against "
                           "the files prepared in `~/Projects/scrapelens-import-tmp`.")
    return lines


def render(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Acceptance report — ScrapeLens MVP")
    lines.append("")
    lines.append(f"Run: {report['generatedAt']} · core binary `{report['coreSha256'][:12]}` "
                 f"({report['coreBytes']} bytes) · commit `{report['gitCommit']}`")
    lines.append("")
    lines.append(f"Environment: macOS {report['macos']} · {report['machine']} · Python {report['python']}")
    lines.append("")
    lines.append("| # | Spec criterion | Status | Assertions |")
    lines.append("|---|---|---|---|")
    for entry in report["items"]:
        assertions = (f"{entry['passed']}/{entry['passed'] + entry['failed']}"
                      if entry["assertions"] else "—")
        lines.append(f"| {entry['item']} | {entry['title']} | **{entry['status']}** | {assertions} |")
    lines.append("")
    approved = sum(1 for entry in report["items"] if entry["status"] == "approved")
    passed = sum(entry["passed"] for entry in report["items"])
    failed = sum(entry["failed"] for entry in report["items"])
    lines.append(f"Summary: {approved}/{len(report['items'])} criteria approved; "
                 f"{passed}/{passed + failed} assertions passed.")
    lines.append("")
    lines.append("Requested criteria: (1) repeated headers/cookies, (2) valid/incomplete/unknown HAR/NetLog, "
                 "(3) identical simultaneous requests without false association, (4) redirects/attempts, (5) explicit bodies, "
                 "(6) diff with duplicates, (7) cURL/Python escaping, (8) sanitization with raw events, "
                 "(9) real macOS cycle, (10) large import measured.")
    lines.append("")
    if report.get("scope"):
        lines.append("Evidence scope:")
        lines.append("")
        for item in report["scope"]:
            lines.append(f"- {item}")
        lines.append("")
    for entry in report["items"]:
        lines.append(f"## {entry['item']}. {entry['title']} — {entry['status']}")
        lines.append("")
        if entry["evidence"]:
            lines.append("Evidence:")
            lines.append("")
            for evidence in entry["evidence"]:
                lines.append(f"- {evidence}")
            lines.append("")
        if entry["failed"]:
            lines.append("Failures:")
            lines.append("")
            for row in entry["assertions"]:
                if not row["ok"]:
                    lines.append(f"- {row['label']}")
            lines.append("")
        for note in entry["notes"]:
            lines.append(f"> {note}")
            lines.append("")
        lines.append(f"Assertions: {entry['passed']} passed, {entry['failed']} failed "
                     f"({entry['seconds']:.2f} s).")
        lines.append("")
    lines.append("## How to reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append('cd "$(git rev-parse --show-toplevel)"   # the repository root')
    lines.append("python3 tests/acceptance/run_acceptance.py --build-fixtures")
    lines.append("python3 tests/acceptance/run_acceptance.py")
    lines.append("tests/capture/run-cycle.sh")
    lines.append("python3 tests/acceptance/run_acceptance.py   # uses the last recorded capture")
    lines.append("```")
    lines.append("")
    lines.append("Everything offline: synthetic fixtures in `fixtures/acceptance/`, `.invalid` domains; "
                 "criterion 9 uses Chrome with a dedicated temporary profile and local servers. "
                 "Nothing is published and no telemetry is generated.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="list of items, e.g.: 1,3,6")
    parser.add_argument("--capture", help="real run directory of tests/capture/run-cycle.sh")
    parser.add_argument("--app-run", help="run.json of the cycle through the packaged app "
                                         "(default: tests/results/app-latest/run.json)")
    parser.add_argument("--build-fixtures", action="store_true", help="regenerates fixtures/acceptance before running")
    parser.add_argument("--large-bodies", action="store_true",
                        help="also measures the worst case of 20 thousand attachments (slow, ~100 s)")
    args = parser.parse_args()

    if args.build_fixtures:
        subprocess.run([sys.executable, str(ROOT / "tests" / "acceptance" / "fixtures.py")], check=True)

    if not CORE.exists():
        print(f"core binary missing: {CORE}\nrun: cd core && cargo build --release", file=sys.stderr)
        return 2

    last_capture = RESULTS / "last-capture.txt"
    capture = args.capture
    if capture is None and last_capture.exists():
        candidate = last_capture.read_text(encoding="utf-8").strip()
        if candidate and pathlib.Path(candidate).exists():
            capture = candidate
    if args.capture:
        RESULTS.mkdir(parents=True, exist_ok=True)
        last_capture.write_text(str(pathlib.Path(args.capture).resolve()) + "\n", encoding="utf-8")

    selected = {int(part) for part in args.only.split(",")} if args.only else {item[0] for item in ITEMS}
    run_root = fresh(WORK / "run")
    app_run = args.app_run
    if app_run is None and (RESULTS / "app-latest" / "run.json").exists():
        app_run = str(RESULTS / "app-latest" / "run.json")
    ctx = {"run": run_root, "capture": capture, "large_bodies": args.large_bodies, "app": app_run}

    results = [run_item(number, title, fn, ctx)
               for number, title, fn in ITEMS if number in selected]

    git = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True)
    report = {
        "generatedAt": now_iso(),
        "coreSha256": sha256(CORE),
        "coreBytes": CORE.stat().st_size,
        "gitCommit": git.stdout.strip() or "unknown",
        "macos": platform.mac_ver()[0] or platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "items": results,
    }
    report["scope"] = evidence_scope(capture, app_run)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "acceptance.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
    REPORT.write_text(render(report), encoding="utf-8")

    for entry in results:
        mark = "OK  " if entry["status"] == "approved" else ("SKIP" if entry["status"] == "not tested" else "FAIL")
        print(f"{mark} {entry['item']:>2}. {entry['title']} "
              f"({entry['passed']} passed, {entry['failed']} failed, {entry['seconds']:.2f}s)")
        for row in entry["assertions"]:
            if not row["ok"]:
                print(f"       - {row['label']}")
    print(f"\nreport: {rel(REPORT)}")
    return 0 if all(entry["status"] != "failed" for entry in results) else 1


if __name__ == "__main__":
    sys.exit(main())
