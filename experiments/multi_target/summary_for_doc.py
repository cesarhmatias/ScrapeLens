#!/usr/bin/env python3
"""Gera trecho Markdown para docs/02-matriz-fidelidade.md a partir de analysis.json."""
from __future__ import annotations

import argparse
import json
import pathlib

KINDS = [
    ("popup", "Popup (`window.open`)"),
    ("target_blank", "Aba nova (`target=_blank`)"),
    ("oophif", "Iframe OOPIF (outra porta)"),
    ("dedicated_worker", "Worker dedicado"),
    ("service_worker", "Service worker (intercept + fetch próprio)"),
    ("page", "Documento principal"),
]


def agg(analysis: dict, key: str) -> dict[str, dict]:
    src = analysis[key]
    by_kind: dict[str, list] = {}
    for row in src.get("rows", []):
        by_kind.setdefault(row["target_kind"], []).append(row)
    out = {}
    for kind, _label in KINDS:
        rows = by_kind.get(kind, [])
        if not rows:
            out[kind] = {"server": "não verificado", "netlog": "não verificado", "cdp": "não verificado"}
            continue
        out[kind] = {
            "server": "sim" if any(r["server"] for r in rows) else "não",
            "netlog": "sim" if any(r["netlog"] for r in rows) else "não",
            "cdp": "sim" if any(r["cdp"] for r in rows) else "não",
            "extra_info": "sim" if any(r.get("headers_extra_info") == "sim" for r in rows) else "parcial",
            "bodies": "sim" if any(r.get("bodies_cdp") is True for r in rows) else "parcial",
            "sw_page": any(r.get("fromServiceWorker") for r in rows),
            "sw_source": next((r.get("serviceWorkerResponseSource") for r in rows if r.get("serviceWorkerResponseSource")), None),
        }
    out["_cost"] = {
        "sessions": src.get("sessionCount"),
        "events": src.get("eventCount"),
        "network_events": src.get("networkEventCount"),
        "elapsed_ms": src.get("elapsedMs"),
        "requestId_collisions": src.get("requestIdCollisionPairs"),
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("analysis", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path)
    args = ap.parse_args()
    data = json.loads(args.analysis.read_text())
    w = agg(data, "with_wait")
    n = agg(data, "without_wait") if "without_wait" in data else {}
    cmp_ = data.get("variant_compare", {})

    lines = [
        "## Captura multi-alvo (CDP auto-attach × NetLog)",
        "",
        "Contrato: `docs/14-captura-multi-alvo.md`. Harness: `experiments/multi_target/`.",
        "",
        "| Item | Valor |",
        "|---|---|",
        f"| Navegador | Chrome headless=new (ver `cdp-sessions.json`) |",
        f"| CDP | `Target.setDiscoverTargets` + `setAutoAttach` (flatten, `waitForDebuggerOnStart` true/false) |",
        f"| Evidência preliminar | `experiments/results/multi-target-smoke/` (smoke local; **repetir** com `testserver` `GET /multi/` quando a Testes publicar) |",
        "",
        "### Tabela por tipo de alvo (marcador `?m=`, variante **com** `waitForDebuggerOnStart`)",
        "",
        "| Tipo de alvo | Servidor (JSONL) | NetLog | CDP (sessão filha) | ExtraInfo (ordem) | Corpos CDP | SW `fromServiceWorker` |",
        "|---|---|---|---|---|---|---|",
    ]
    for kind, label in KINDS:
        c = w.get(kind, {})
        if kind.startswith("_"):
            continue
        lines.append(
            f"| {label} | {c.get('server', 'não verificado')} | {c.get('netlog', 'não verificado')} | "
            f"{c.get('cdp', 'não verificado')} | {c.get('extra_info', 'não verificado')} | "
            f"{c.get('bodies', 'não verificado')} | "
            f"{('sim' if c.get('sw_page') else '—') if c.get('cdp') != 'não verificado' else 'não verificado'} |"
        )

    lines.extend(
        [
            "",
            "### Variante **sem** `waitForDebuggerOnStart`",
            "",
            f"- Primeira requisição perdida no CDP (marcadores `popup-first` / `blank-first` / `oophif-first`): "
            f"{cmp_.get('first_request_lost_without_wait') or 'não verificado (smoke incompleto nesta execução)'}",
            f"- Sessões CDP: {n.get('_cost', {}).get('sessions', 'não verificado')}; "
            f"eventos Network: {n.get('_cost', {}).get('network_events', 'não verificado')}",
            "",
            "### Colisão de `requestId` entre sessões",
            "",
            f"Com wait: **{w.get('_cost', {}).get('requestId_collisions', '?')}** pares `(requestId)` vistos em mais de uma sessão "
            f"(correlação correta exige `(sessionId, requestId)`). Sem wait: "
            f"**{n.get('_cost', {}).get('requestId_collisions', 'não verificado')}**.",
            "",
            "### Custo (variante com wait, smoke)",
            "",
            f"| Sessões CDP | Eventos totais | Eventos Network.* | Tempo captura |",
            f"|---:|---:|---:|---:|",
            f"| {w.get('_cost', {}).get('sessions')} | {w.get('_cost', {}).get('events')} | "
            f"{w.get('_cost', {}).get('network_events')} | {w.get('_cost', {}).get('elapsed_ms')} ms |",
            "",
            "**Recomendação (1 linha):** usar auto-attach com `waitForDebuggerOnStart` e chave `(sessionId, requestId)`; "
            "alvos sem sessão CDP continuam só no NetLog; repetir medição oficial contra `testserver` `/multi/` antes de fixar o produto.",
            "",
        ]
    )
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
