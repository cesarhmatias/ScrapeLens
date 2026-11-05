#!/usr/bin/env python3
"""Compares the three evidence layers of each experiment.

(a) order as presented by the source: CDP object (requestWillBeSent.headers,
    requestWillBeSentExtraInfo.headers), response headersText, derived HAR.
(b) order handed to the encoder: *SEND_REQUEST_HEADERS / *_SEND_HEADERS
    events of the NetLog.
(c) order decoded on the wire: JSONL written by the observation server.

Output: results/<exp>/layers.json and results/<exp>/report.md + results/matrix.json
"""
from __future__ import annotations

import json
import pathlib
from collections import Counter, OrderedDict

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE / "results"

NETLOG_EVENTS = {
    "h1": ["HTTP_TRANSACTION_SEND_REQUEST_HEADERS"],
    "h2": ["HTTP2_SESSION_SEND_HEADERS", "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"],
    "h3": ["QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS", "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"],
}
# Event that represents the encoder entry point (HPACK/QPACK).
PREFERRED = {
    "h1": "HTTP_TRANSACTION_SEND_REQUEST_HEADERS",
    "h2": "HTTP2_SESSION_SEND_HEADERS",
    "h3": "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS",
}
PRE_SESSION = {
    "h2": "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS",
    "h3": "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS",
}
SERVER_FILE = {"h1": "server-h1.jsonl", "h2": "server-h2.jsonl", "h3": "server-h3.jsonl"}


def load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def split_netlog_header(raw: str) -> tuple[str, str]:
    # NetLog format: "Name: value" (h1) or ":pseudo: value" (h2/h3).
    name, _, value = raw.partition(": ")
    return name.strip(), value.strip()


def names(seq: list[list[str]] | list[tuple[str, str]]) -> list[str]:
    return [n for n, _ in seq]


def verdict(observed: list[str], reference: list[str]) -> str:
    """Classifies the relation between an observed order and the server reference."""
    if not observed:
        return "not observed"
    if observed == reference:
        return "identical (name and case)"
    if [n.lower() for n in observed] == [n.lower() for n in reference]:
        return "identical in order; case normalized"
    if Counter(n.lower() for n in observed) == Counter(n.lower() for n in reference):
        return "reordered (same multiset)"
    if set(n.lower() for n in observed) == set(n.lower() for n in reference):
        return "duplicates merged (same name set)"
    missing = sorted(set(n.lower() for n in reference) - set(n.lower() for n in observed))
    extra = sorted(set(n.lower() for n in observed) - set(n.lower() for n in reference))
    if missing and not extra:
        return f"subset ({len(missing)} names missing)"
    return "divergent"


def cdp_requests(events: list[dict]) -> list[dict]:
    """Rebuilds requests from CDP events, without normalizing headers."""
    by_id: OrderedDict[str, dict] = OrderedDict()
    for ev in events:
        m = ev["method"]
        p = ev["params"]
        if m == "Network.requestWillBeSent":
            rid = p["requestId"]
            rec = by_id.setdefault(rid, {"requestId": rid})
            rec["url"] = p["request"]["url"]
            rec["method"] = p["request"]["method"]
            rec["rws_headers"] = p["request"].get("headers", {})
            rec["rws_order"] = list(rec["rws_headers"].keys())
            if "redirectResponse" in p:
                rec["redirected_from"] = p["redirectResponse"].get("url")
        elif m == "Network.requestWillBeSentExtraInfo":
            rid = p.get("requestId")
            if rid is None:
                continue
            rec = by_id.setdefault(rid, {"requestId": rid})
            rec["extra_headers"] = p.get("headers", {})
            rec["extra_order"] = list(rec["extra_headers"].keys())
            rec["associated_cookies"] = p.get("associatedCookies", [])
        elif m == "Network.responseReceivedExtraInfo":
            rid = p.get("requestId")
            if rid is None:
                continue
            rec = by_id.setdefault(rid, {"requestId": rid})
            rec["resp_headers"] = p.get("headers", {})
            rec["resp_headers_text"] = p.get("headersText")
    return list(by_id.values())


def path_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def netlog_sends(netlog: dict, protocol: str) -> list[dict]:
    types = {v: k for k, v in netlog["constants"]["logEventTypes"].items()}
    out = []
    for ev in netlog.get("events", []):
        name = types.get(ev["type"], str(ev["type"]))
        if name not in NETLOG_EVENTS[protocol]:
            continue
        params = ev.get("params") or {}
        raw = params.get("headers")
        if not raw:
            continue
        pairs = [split_netlog_header(h) for h in raw]
        if protocol == "h1":
            line = (params.get("line") or "").strip()
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else ""
            method = parts[0] if parts else ""
        else:
            d = dict(pairs)
            path = d.get(":path", "")
            method = d.get(":method", "")
        out.append(
            {
                "event": name,
                "method": method,
                "path": path,
                "order": [n for n, _ in pairs],
                "pairs": pairs,
            }
        )
    return out


RECV_EVENTS = {
    "h1": ["HTTP_TRANSACTION_READ_RESPONSE_HEADERS"],
    "h2": ["HTTP2_SESSION_RECV_HEADERS", "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"],
    "h3": ["QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS", "HTTP_TRANSACTION_READ_RESPONSE_HEADERS"],
}
PREFERRED_RECV = {
    "h1": "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
    "h2": "HTTP2_SESSION_RECV_HEADERS",
    "h3": "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS",
}


def netlog_recvs(netlog: dict, protocol: str) -> list[dict]:
    types = {v: k for k, v in netlog["constants"]["logEventTypes"].items()}
    out = []
    for ev in netlog.get("events", []):
        name = types.get(ev["type"], str(ev["type"]))
        if name not in RECV_EVENTS[protocol]:
            continue
        raw = (ev.get("params") or {}).get("headers")
        if not raw:
            continue
        pairs: list[tuple[str, str]] = []
        nul = False
        for h in raw:
            n, v = split_netlog_header(h)
            if n.startswith("HTTP/"):
                pairs.append((":status", v))
                continue
            if "\x00" in v:
                nul = True
                for piece in v.split("\x00"):
                    pairs.append((n, piece))
            else:
                pairs.append((n, v))
        out.append({"event": name, "pairs": pairs, "nul_joined": nul})
    return out


def resp_key(pairs: list[tuple[str, str]]) -> tuple[str | None, bool]:
    length = None
    has_cookie = False
    for n, v in pairs:
        if n.lower() == "content-length":
            length = v
        elif n.lower() == "set-cookie":
            has_cookie = True
    return length, has_cookie


def drop_status(names: list[str]) -> list[str]:
    return [n for n in names if not n.startswith(":") and not n.startswith("HTTP/")]


def analyze_response(
    row: dict, protocol: str, recvs: list[dict], cdp_rec: dict | None, nth: int = 0
) -> dict:
    ref_pairs = [[n, v] for n, v in row.get("response_headers", [])]
    ref_names = drop_status([n for n, _ in ref_pairs])
    key = resp_key([(n, v) for n, v in ref_pairs])
    # identical requests produce identical responses: match by occurrence order
    cand = [r for r in recvs if resp_key(r["pairs"]) == key] if key[0] else []
    out: dict = {"server_order": ref_names, "nul_joined": False}

    preferred = [r for r in cand if r["event"] == PREFERRED_RECV[protocol]]
    pool = preferred or cand
    chosen = pool[nth] if nth < len(pool) else None
    if chosen:
        names = drop_status([n for n, _ in chosen["pairs"]])
        out["netlog_session"] = {
            "event": chosen["event"],
            "order": names,
            "verdict": verdict(names, ref_names),
            "nul_joined": chosen["nul_joined"],
            "candidates": len(cand),
        }
        other = [r for r in cand if r["event"] != chosen["event"]]
        if other:
            o = other[nth] if nth < len(other) else other[0]
            names2 = drop_status([n for n, _ in o["pairs"]])
            out["netlog_other"] = {
                "event": o["event"],
                "order": names2,
                "verdict": verdict(names2, ref_names),
                "nul_joined": o["nul_joined"],
            }
    else:
        out["netlog_session"] = {"event": None, "order": [], "verdict": "not observed", "nul_joined": False}

    if cdp_rec:
        text = cdp_rec.get("resp_headers_text")
        if text:
            lines = [ln for ln in text.split("\r\n") if ln]
            names = []
            for ln in lines[1:]:
                names.append(ln.split(":", 1)[0])
            out["cdp_headersText"] = {"order": names, "verdict": verdict(names, ref_names)}
        obj = cdp_rec.get("resp_headers") or {}
        out["cdp_object"] = {
            "order": list(obj.keys()),
            "sorted_ascii": list(obj.keys()) == sorted(obj.keys()),
            "joined_values": [[k, v] for k, v in obj.items() if isinstance(v, str) and "\n" in v],
            "verdict": verdict(drop_status(list(obj.keys())), ref_names),
        }
    return out


def analyze(exp_dir: pathlib.Path) -> dict:
    plan = json.loads((exp_dir / "plan.json").read_text())
    meta = json.loads((exp_dir / "cdp-meta.json").read_text()) if (exp_dir / "cdp-meta.json").exists() else {}
    netlog = json.loads((exp_dir / "chrome-netlog.json").read_text())
    events = load_jsonl(exp_dir / "cdp-events.jsonl")
    protocol = "h1"
    first = plan["urls"][0]
    if ":8782" in first:
        protocol = "h2"
    elif ":8783" in first:
        protocol = "h3"

    server_rows = load_jsonl(exp_dir / SERVER_FILE[protocol])
    sends = netlog_sends(netlog, protocol)
    recvs = netlog_recvs(netlog, protocol)
    cdps = cdp_requests(events)

    requests = []
    seen_send: dict[tuple[str, str], int] = {}
    seen_resp: dict[tuple, int] = {}
    for row in server_rows:
        target = row["target"]
        ref = names(row["pseudoheaders"]) + names(row["headers"])
        ref_full = [list(p) for p in row["pseudoheaders"]] + [list(p) for p in row["headers"]]

        key = (row["method"].upper(), target)
        nth = seen_send.get(key, 0)
        seen_send[key] = nth + 1
        cand = [s for s in sends if s["path"] == target and s["method"].upper() == row["method"].upper()]
        preferred = [s for s in cand if s["event"] == PREFERRED[protocol]]
        pre = [s for s in cand if s["event"] == PRE_SESSION.get(protocol)]
        pool = preferred or cand
        chosen = pool[nth] if nth < len(pool) else None
        if chosen:
            b = {
                "event": chosen["event"],
                "order": chosen["order"],
                "verdict": verdict(chosen["order"], ref),
                "candidates": len(cand),
                "ambiguous": len({(c["event"], c["path"]) for c in cand}) > 2 or len(pool) > 1,
            }
        else:
            b = {"event": None, "order": [], "verdict": "not observed", "candidates": 0, "ambiguous": False}
        b_pre = None
        mine_pre = pre[nth] if nth < len(pre) else None
        if mine_pre and mine_pre["event"] != b["event"]:
            b_pre = {
                "event": mine_pre["event"],
                "order": mine_pre["order"],
                "verdict": verdict(mine_pre["order"], ref),
            }

        cdps_same = [c for c in cdps if path_of(c.get("url") or "") == target and (c.get("method") or "").upper() == row["method"].upper()]
        cdp_rec = cdps_same[nth] if nth < len(cdps_same) else None
        a = {}
        if cdp_rec:
            a["requestId"] = cdp_rec["requestId"]
            a["rws"] = {
                "order": cdp_rec.get("rws_order", []),
                "n": len(cdp_rec.get("rws_order", [])),
                "verdict": verdict(cdp_rec.get("rws_order", []), ref),
            }
            a["extra"] = {
                "order": cdp_rec.get("extra_order", []),
                "n": len(cdp_rec.get("extra_order", [])),
                "verdict": verdict(cdp_rec.get("extra_order", []), ref),
                "sorted_ascii": cdp_rec.get("extra_order", []) == sorted(cdp_rec.get("extra_order", [])),
                "duplicates_in_reference": len(ref) - len({n.lower() for n in ref}),
                "cookies": [
                    c.get("cookie", {}).get("name") for c in cdp_rec.get("associated_cookies", [])
                ],
            }
            a["headersText"] = bool(cdp_rec.get("resp_headers_text"))
        else:
            a["rws"] = {"order": [], "n": 0, "verdict": "not observed"}
            a["extra"] = {"order": [], "n": 0, "verdict": "not observed", "sorted_ascii": None}
        rkey = resp_key([(n, v) for n, v in (row.get("response_headers") or [])])
        nth_resp = seen_resp.get(rkey, 0)
        seen_resp[rkey] = nth_resp + 1
        requests.append(
            {
                "target": target,
                "method": row["method"],
                "reference_server": ref_full,
                "reference_names": ref,
                "duplicates": row["duplicate_names"],
                "b_netlog": b,
                "b_netlog_pre_session": b_pre,
                "response": analyze_response(row, protocol, recvs, cdp_rec, nth=nth_resp),
                "a_cdp": a,
                "cdp_meta": meta,
            }
        )

    return {
        "experiment": exp_dir.name,
        "protocol": protocol,
        "browser": meta.get("browser") or (json.loads((exp_dir / "run.json").read_text())["chrome"] or {}).get("Browser"),
        "userAgent": meta.get("userAgent"),
        "plan": plan,
        "requests": requests,
    }


def report(layer: dict) -> str:
    lines = [
        f"# Experiment `{layer['experiment']}` — {layer['protocol']}",
        "",
        f"- Browser: `{layer['browser']}`",
        f"- User-Agent: `{layer['userAgent']}`",
        f"- Initial URL: `{layer['plan']['urls'][0]}`",
        "",
    ]
    for r in layer["requests"]:
        lines += [
            f"## `{r['method']} {r['target']}`",
            "",
            f"Server reference (decoded order): `{', '.join(r['reference_names'])}`",
            f"Observed duplicates: {r['duplicates'] or 'none'}",
            "",
            "| Layer | Source | Order | Verdict |",
            "|---|---|---|---|",
            f"| (c) decoded | server JSONL | `{', '.join(r['reference_names'])}` | reference |",
            f"| (b) encoder | NetLog `{r['b_netlog']['event'] or '-'}` | `{', '.join(r['b_netlog']['order']) or '-'}` | {r['b_netlog']['verdict']} |",
            *(
                [
                    f"| (b) pre-session | NetLog `{r['b_netlog_pre_session']['event']}` | `{', '.join(r['b_netlog_pre_session']['order'])}` | {r['b_netlog_pre_session']['verdict']} |"
                ]
                if r.get("b_netlog_pre_session")
                else []
            ),
            f"| (a) source | CDP `requestWillBeSent.headers` | `{', '.join(r['a_cdp']['rws']['order']) or '-'}` | {r['a_cdp']['rws']['verdict']} |",
            f"| (a) source | CDP `requestWillBeSentExtraInfo.headers` | `{', '.join(r['a_cdp']['extra']['order']) or '-'}` | {r['a_cdp']['extra']['verdict']} |",
            "",
            "Response (Set-Cookie / duplicates):",
            "",
            "| Layer | Source | Order | Verdict |",
            "|---|---|---|---|",
            f"| (c) written | server JSONL | `{', '.join(r['response']['server_order'])}` | reference |",
            f"| (a) read | NetLog `{r['response']['netlog_session']['event'] or '-'}` | `{', '.join(r['response']['netlog_session']['order']) or '-'}` | {r['response']['netlog_session']['verdict']} |",
        ]
        if r["response"]["netlog_session"].get("nul_joined"):
            lines.append("")
            lines.append("- NetLog at session level merged duplicate values with `\\x00`.")
        if r["response"].get("netlog_other"):
            o = r["response"]["netlog_other"]
            lines.append(f"- Alternative event `{o['event']}`: {o['verdict']} (duplicates {len(o['order']) - len({n.lower() for n in o['order']})}).")
        if r["response"].get("cdp_headersText"):
            lines.append(f"- CDP `headersText` (raw): {r['response']['cdp_headersText']['verdict']}.")
        if r["response"].get("cdp_object"):
            o = r["response"]["cdp_object"]
            lines.append(f"- CDP headers object: {o['verdict']}; ASCII-sorted={o['sorted_ascii']}; merged values={len(o['joined_values'])}.")
        if r["a_cdp"]["extra"].get("sorted_ascii"):
            lines.append("- `ExtraInfo.headers` is in ASCII/case-sensitive order, not in wire order.")
        if r["b_netlog"]["ambiguous"]:
            lines.append(f"- Ambiguity: {r['b_netlog']['candidates']} NetLog events matched this path.")
        if r["a_cdp"].get("headersText"):
            lines.append("- `responseReceivedExtraInfo.headersText` present (raw response order in h1).")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    # contract-* are the cross-check (crosscheck_contract.py) and have their own summary
    exps = sorted(
        p
        for p in RESULTS.iterdir()
        if p.is_dir() and (p / "plan.json").exists() and not p.name.startswith("contract-")
    )
    matrix = {}
    for exp in exps:
        layer = analyze(exp)
        (exp / "layers.json").write_text(json.dumps(layer, indent=2, ensure_ascii=False))
        (exp / "report.md").write_text(report(layer))
        matrix[exp.name] = {
            "protocol": layer["protocol"],
            "requests": [
                {
                    "target": r["target"],
                    "netlog": r["b_netlog"]["verdict"],
                    "cdp_rws": r["a_cdp"]["rws"]["verdict"],
                    "cdp_extra": r["a_cdp"]["extra"]["verdict"],
                    "cdp_extra_sorted": r["a_cdp"]["extra"].get("sorted_ascii"),
                    "response_netlog": r["response"]["netlog_session"]["verdict"],
                    "response_nul": r["response"]["netlog_session"].get("nul_joined"),
                }
                for r in layer["requests"]
            ],
        }
        print(f"{exp.name}: {len(layer['requests'])} requests")
    (RESULTS / "matrix.json").write_text(json.dumps(matrix, indent=2, ensure_ascii=False))
    agg: dict[str, Counter] = {}
    for name, m in matrix.items():
        for r in m["requests"]:
            agg.setdefault(f"{m['protocol']}|netlog", Counter())[r["netlog"]] += 1
            agg.setdefault(f"{m['protocol']}|cdp_rws", Counter())[r["cdp_rws"]] += 1
            agg.setdefault(f"{m['protocol']}|cdp_extra", Counter())[r["cdp_extra"]] += 1
    summary = {
        "total_requests": sum(len(m["requests"]) for m in matrix.values()),
        "by_protocol": {},
    }
    for name, m in matrix.items():
        bucket = summary["by_protocol"].setdefault(
            m["protocol"], {"requests": 0, "netlog": Counter(), "cdp_extra": Counter(), "response_netlog": Counter()}
        )
        for r in m["requests"]:
            bucket["requests"] += 1
            bucket["netlog"][r["netlog"]] += 1
            bucket["cdp_extra"][r["cdp_extra"]] += 1
            bucket["response_netlog"][r["response_netlog"]] += 1
    for proto, bucket in summary["by_protocol"].items():
        for key in ("netlog", "cdp_extra", "response_netlog"):
            bucket[key] = dict(bucket[key])
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
