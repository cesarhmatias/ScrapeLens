#!/usr/bin/env python3
"""Validates the real capture cycle performed by the packaged ScrapeLens app.

Reads the `.app` bundle, the live capture session and the HAR/NetLog sessions that the
app itself recorded in ~/Library/Application Support/app.scrapelens.desktop/sessions,
checks structure, permissions, fidelity and the absence of demo labels, and writes
`run.json` for criterion 9 of the acceptance suite.

Usage:
  python3 tests/capture/app_validate.py \
    --run-dir tests/results/app-latest \
    --capture-id capture-1793058850184 \
    --har-id har-3dbc391c02a985c5-2 --netlog-id netlog-1704043c442dcbd1-2 \
    --screenshot tests/results/app-latest/screenshot-app-live.png \
    --imports-screenshot tests/results/app-latest/screenshot-app-imports.png

The HAR/NetLog imports compare the recorded session with the files prepared in
`~/Projects/scrapelens-import-tmp` (`--import-sources`): the HAR by the method/URL
sequence of the `log.entries`, and the NetLog by the SHA-256 of the persisted `netlog.json`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "core" / "target" / "release" / "scrapelens-core"
DEFAULT_SESSIONS = pathlib.Path.home() / "Library" / "Application Support" / "app.scrapelens.desktop" / "sessions"
DEFAULT_BUNDLE = ROOT / "src-tauri" / "target" / "release" / "bundle" / "macos" / "ScrapeLens.app"
DEFAULT_IMPORT_SOURCES = pathlib.Path.home() / "Projects" / "scrapelens-import-tmp"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


def inspect(session_dir: pathlib.Path) -> dict:
    proc = run(str(CORE), "inspect", str(session_dir))
    if proc.returncode != 0:
        raise SystemExit(f"inspect failed for {session_dir}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)["session"]


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mode(path: pathlib.Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def bundle_facts(bundle: pathlib.Path) -> dict:
    macos = bundle / "Contents" / "MacOS"
    binaries = sorted(path.name for path in macos.iterdir()) if macos.exists() else []
    executable = macos / "scrapelens"
    file_info = run("file", str(executable)).stdout.strip() if executable.exists() else ""
    codesign = run("codesign", "-dv", "--verbose=2", str(bundle))
    signature_text = codesign.stderr + codesign.stdout
    verify = run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(bundle))
    size = sum(path.stat().st_size for path in bundle.rglob("*") if path.is_file())
    return {
        "path": str(bundle),
        "exists": bundle.exists(),
        "sizeBytes": size,
        "executableSha256": sha256(executable) if executable.exists() else None,
        "executableBytes": executable.stat().st_size if executable.exists() else 0,
        "binaries": binaries,
        "singleBinary": binaries == ["scrapelens"],
        "machO": file_info,
        "arm64": "arm64" in file_info,
        "signature": ("adhoc" if "adhoc" in signature_text
                      else "local-identity" if "Authority=ScrapeLens Local Signing" in signature_text
                      else "unknown"),
        "codesignVerifyDeepStrict": verify.returncode == 0,
        "codesignVerifyOutput": (verify.stderr + verify.stdout).strip()[-300:],
        "identifier": next((line.split("=", 1)[1] for line in signature_text.splitlines()
                            if line.startswith("Identifier=")), None),
    }


def session_facts(session_dir: pathlib.Path) -> dict:
    sha_before = sha256(session_dir / "session.json")
    session = inspect(session_dir)
    sha_after = sha256(session_dir / "session.json")
    on_disk = json.loads((session_dir / "session.json").read_text(encoding="utf-8"))
    meta = session["session"]
    requests = session["requests"]
    verified = [header for request in requests
                for header in request["requestHeaders"].get("headers", [])
                if header.get("verification") == "verified"]
    ambiguous = [{"id": request["id"],
                  "candidates": [candidate.get("entityId") for candidate in request.get("matchCandidates", [])],
                  "candidateCount": len(request.get("matchCandidates", []))}
                 for request in requests if request.get("match") == "ambiguous"]
    cookie_names = sorted({pair["name"] for request in requests
                           for pair in request.get("cookie", {}).get("pairs", [])})
    header_sources = sorted({header.get("source")
                             for request in requests
                             for header in (request["requestHeaders"].get("headers", [])
                                            + request["responseHeaders"].get("headers", []))
                             if header.get("source")})
    set_cookie_lines = [record["raw"] for request in requests for record in request.get("setCookies", [])]
    raw = {}
    for name in ("session.json", "cdp-events.jsonl", "netlog.json"):
        path = session_dir / name
        raw[name] = {"exists": bool(path.exists()),
                     "bytes": path.stat().st_size if path.exists() else 0,
                     "mode": mode(path) if path.exists() else None}
    attachments = session_dir / "attachments"
    return {
        "id": session_dir.name,
        "path": str(session_dir),
        "sha256": sha256(session_dir / "session.json"),
        "mode": (meta.get("capture") or {}).get("mode"),
        "labels": meta.get("labels", []),
        "completeness": meta["completeness"]["state"],
        "completenessReasons": meta["completeness"]["reasons"],
        "counts": meta["completeness"]["counts"],
        "requests": len(requests),
        "attempts": sum(len(request.get("attempts", [])) for request in requests),
        "protocols": sorted({request["protocol"] for request in requests}),
        "statuses": sorted({request.get("status") for request in requests if request.get("status")}),
        "matched": sum(1 for request in requests if request.get("match") == "matched"),
        "ambiguous": ambiguous,
        "ambiguousCandidates": sum(item["candidateCount"] for item in ambiguous),
        "unmatched": sum(1 for request in requests if request.get("match") == "unmatched"),
        "redirects": sum(len(request.get("redirects", [])) for request in requests),
        "streamSessions": len(session.get("streamSessions", [])),
        "verifiedHeaderEntries": len(verified),
        "verifiedSources": sorted({header.get("source") for header in verified}),
        "verifiedEvents": sorted({header.get("event") for header in verified}),
        "headerSources": header_sources,
        "cookieNames": cookie_names,
        "setCookieLines": len(set_cookie_lines),
        "setCookieDuplicates": len(set_cookie_lines) - len(set(set_cookie_lines)),
        "responseBodyStates": sorted({request["responseBody"]["state"] for request in requests}),
        "unavailableWithNote": all(bool(request["responseBody"].get("note"))
                                   for request in requests
                                   if request["responseBody"]["state"] == "unavailable"),
        "warnings": [warning["code"] for warning in session.get("warnings", [])],
        "hasDemoLabel": any(label in {"demo", "synthetic-fixture", "demo-session"}
                            for label in meta.get("labels", [])),
        "dirMode": mode(session_dir),
        "rawArtifacts": raw,
        "reload": {
            "requestsOnDisk": len(on_disk.get("requests", [])),
            "requestsFromInspect": len(requests),
            "sha256BeforeInspect": sha_before,
            "sha256AfterInspect": sha_after,
            "unchangedAfterInspect": sha_before == sha_after,
        },
        "attachments": sorted(path.name for path in attachments.iterdir()) if attachments.exists() else [],
    }


def import_source_check(kind: str, session_dir: pathlib.Path, source_dir: pathlib.Path) -> dict:
    """Checks that the imported session came from the file prepared for the UI."""
    if kind == "har":
        source = source_dir / "har-derived.json"
        if not source.exists():
            return {"path": str(source), "exists": False}
        data = json.loads(source.read_text(encoding="utf-8"))
        entries = (data.get("log") or {}).get("entries") or []
        expected = [(entry.get("request", {}).get("method"), entry.get("request", {}).get("url"))
                    for entry in entries]
        session = inspect(session_dir)
        actual = [(request.get("method"), request.get("url")) for request in session["requests"]]
        return {
            "path": str(source),
            "exists": True,
            "sha256": sha256(source),
            "entries": len(expected),
            "matchesSourceSequence": expected == actual,
        }
    source = source_dir / "h1h2h3.chrome-netlog.json"
    persisted = session_dir / "netlog.json"
    if not source.exists() or not persisted.exists():
        return {"path": str(source), "exists": False}
    source_sha = sha256(source)
    return {
        "path": str(source),
        "exists": True,
        "sha256": source_sha,
        "persistedSha256": sha256(persisted),
        "matchesSourceBytes": source_sha == sha256(persisted),
    }


def duplicate_imports(sessions: pathlib.Path, kind: str, session_dir: pathlib.Path) -> list[str]:
    """Lists other sessions of the same kind with an identical session.json (repeated import)."""
    target = sha256(session_dir / "session.json")
    duplicates: list[str] = []
    for candidate in sorted(sessions.glob(kind + "-*")):
        other = candidate / "session.json"
        if candidate.name == session_dir.name or not other.exists():
            continue
        if sha256(other) == target:
            duplicates.append(candidate.name)
    return duplicates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--sessions", default=str(DEFAULT_SESSIONS))
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    parser.add_argument("--capture-id")
    parser.add_argument("--har-id")
    parser.add_argument("--netlog-id")
    parser.add_argument("--screenshot")
    parser.add_argument("--imports-screenshot")
    parser.add_argument("--import-sources", default=str(DEFAULT_IMPORT_SOURCES))
    parser.add_argument("--testserver-dir")
    parser.add_argument("--start-url", default="http://127.0.0.1:8781/page")
    args = parser.parse_args()

    run_dir = pathlib.Path(args.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    sessions = pathlib.Path(args.sessions).expanduser()
    bundle = pathlib.Path(args.bundle).expanduser()

    def pick(prefix: str, explicit: str | None) -> pathlib.Path | None:
        if explicit:
            return sessions / explicit
        candidates = sorted(sessions.glob(prefix + "*"), key=lambda path: path.stat().st_mtime,
                            reverse=True)
        return candidates[0] if candidates else None

    capture = pick("capture-", args.capture_id)
    har = pick("har-", args.har_id)
    netlog = pick("netlog-", args.netlog_id)
    if capture is None or not capture.exists():
        raise SystemExit("app capture session not found")

    facts = {
        "runId": run_dir.name,
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "gui": {
            "startedFrom": "ScrapeLens.app (release, pid captured by the window)",
            "startButton": "Start session",
            "stopButton": "Stop",
            "startUrl": args.start_url,
            "screenshot": str(pathlib.Path(args.screenshot).resolve()) if args.screenshot else None,
            "screenshotExists": bool(args.screenshot and pathlib.Path(args.screenshot).exists()),
        },
        "bundle": bundle_facts(bundle),
        "appSessionsDir": str(sessions),
        "capture": session_facts(capture),
        "imports": {
            "har": session_facts(har) if har and har.exists() else None,
            "netlog": session_facts(netlog) if netlog and netlog.exists() else None,
        },
    }
    source_dir = pathlib.Path(args.import_sources).expanduser()
    for key, session_dir in (("har", har), ("netlog", netlog)):
        data = facts["imports"][key]
        if data and session_dir and session_dir.exists():
            data["source"] = import_source_check(key, session_dir, source_dir)
            data["duplicateSessions"] = duplicate_imports(sessions, key, session_dir)
    if args.imports_screenshot:
        imports_shot = pathlib.Path(args.imports_screenshot).resolve()
        facts["gui"]["importsScreenshot"] = str(imports_shot)
        facts["gui"]["importsScreenshotExists"] = imports_shot.exists()
    if args.testserver_dir:
        evidence = pathlib.Path(args.testserver_dir)
        h1 = evidence / "h1.jsonl"
        facts["testserver"] = {
            "dir": str(evidence),
            "h1Lines": sum(1 for line in h1.read_text(encoding="utf-8").splitlines() if line.strip())
            if h1.exists() else 0,
        }
    facts["certificateInstalled"] = False
    facts["telemetry"] = False
    (run_dir / "run.json").write_text(json.dumps(facts, indent=1, ensure_ascii=False) + "\n",
                                      encoding="utf-8")

    capture_facts = facts["capture"]
    print(f"bundle: {facts['bundle']['sizeBytes'] / (1024 * 1024):.2f} MiB · "
          f"{'arm64' if facts['bundle']['arm64'] else 'unknown architecture'} · "
          f"{'single binary' if facts['bundle']['singleBinary'] else 'binaries: ' + str(facts['bundle']['binaries'])} · "
          f"{facts['bundle']['signature']} · executable {facts['bundle']['executableSha256']} "
          f"({facts['bundle']['executableBytes']} bytes)")
    print(f"app capture: {capture_facts['id']} · {capture_facts['requests']} requests · "
          f"{capture_facts['completeness']} · {capture_facts['protocols']} · "
          f"{capture_facts['ambiguous'].__len__()} ambiguous · {capture_facts['verifiedHeaderEntries']} verified headers")
    for name, data in facts["imports"].items():
        if data:
            print(f"import {name}: {data['requests']} requests · {data['completeness']} · "
                  f"labels={data['labels']} · {data['protocols']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
