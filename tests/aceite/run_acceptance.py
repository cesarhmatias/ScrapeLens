#!/usr/bin/env python3
"""Bateria de aceite do MVP ScrapeLens (10 critérios da especificação).

Consome o CLI do core (`core/target/release/scrapelens-core`) e as fixtures
sintéticas de `fixtures/aceite/`. Nenhuma etapa abre a rede: os servidores e o
Chrome do critério 9 são locais e orquestrados por `tests/capture/run-cycle.sh`.

Uso:
  python3 tests/aceite/run_acceptance.py                       # itens 1-8,10
  python3 tests/aceite/run_acceptance.py --capture RUN_DIR     # + item 9
  python3 tests/aceite/run_acceptance.py --only 1,3,6
  python3 tests/aceite/run_acceptance.py --build-fixtures

Saída: `tests/results/aceite.json` e `tests/RELATORIO.md`.
Código de saída 0 somente se nenhum item selecionado falhou.
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
FIX = ROOT / "fixtures" / "aceite"
WORK = ROOT / "tests" / ".work"
RESULTS = ROOT / "tests" / "results"
REPORT = ROOT / "tests" / "RELATORIO.md"

# SHA-256 do executável do bundle final aceito nesta rodada, documentado em
# `src-tauri/EMPACOTAMENTO.md`. Um rebuild legítimo muda o hash: atualize os dois
# lugares juntos, para que a bateria nunca aprove um artefato não documentado.
APP_EXECUTABLE = pathlib.Path(os.environ.get("SL_APP_EXECUTABLE") or (
    pathlib.Path(__file__).resolve().parents[2] / "src-tauri/target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens"))
EXPECTED_APP_SHA256 = "6c0092c3c73c779c2ded59d324c7cc739b462cf308c46069f3f06e47ec4759e9"

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
    """Acumula asserções; um item falha se qualquer linha falhar."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def ok(self, condition: bool, label: str) -> bool:
        self.rows.append({"ok": bool(condition), "label": label})
        return bool(condition)

    def eq(self, got, expected, label: str) -> bool:
        return self.ok(got == expected, f"{label}: esperado {expected!r}, obtido {got!r}")

    def contains(self, haystack, needle, label: str) -> bool:
        present = needle in haystack
        return self.ok(present, f"{label}: {needle!r} "
                               + ("presente" if present else "ausente")
                               + f" em {short(haystack)}")

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
    """Devolve o documento SessionV1 (o `session` de dentro do envelope `inspect`)."""
    return json.loads(core_ok("inspect", str(session)))["session"]


SYNTHETIC_LABELS = ["capture-import", "synthetic-fixture"]  # import-capture
# Rótulo de origem por tipo de importação (core: har.rs, netlog.rs, session.rs).
ORIGIN_LABEL = {"import-har": "har-import", "import-netlog": "netlog-import", "import-capture": "capture-import"}


def import_to(kind: str, source: pathlib.Path, target: pathlib.Path) -> dict:
    fresh(target)
    core_ok(kind, str(source), "--out", str(target), "--label", "synthetic-fixture")
    session = inspect(target)
    expected = sorted([ORIGIN_LABEL[kind], "synthetic-fixture"])
    if sorted(session["session"].get("labels", [])) != expected:
        raise SystemExit(f"rótulos da sessão importada {target.name}: {session['session'].get('labels')} != {expected}")
    return session


def view_verification(view: dict) -> str:
    """Estado mais fraco entre as ocorrências de um HeaderView (contrato: por informação)."""
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
    """Headers repetidos, caixa e cookies preservados nas fixtures."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "headers-cookies"
    meta = fixture_meta(folder)
    exp.eq(meta.get("label"), "synthetic-fixture", "fixture identificada como sintética")
    exp.eq(meta.get("origin"), "synthetic", "origem sintética declarada")

    expected_names = ["x-rep", "x-seq", "X-Rep", "x-seq", "x-mixed-Case", "x-rep"]
    expected_pairs = list(zip(expected_names, ["a", "1", "b", "2", "V", "c"]))

    base = ctx["run"] / "item1"
    har_session = base / "har"
    nl_session = base / "netlog"
    imported_har = import_to("import-har", folder / "headers-cookies.har", har_session)
    imported_nl = import_to("import-netlog", folder / "headers-cookies.netlog.json", nl_session)
    evidence += [
        f"`scrapelens-core import-har fixtures/aceite/headers-cookies/headers-cookies.har --out {rel(har_session)}`",
        f"`scrapelens-core import-netlog fixtures/aceite/headers-cookies/headers-cookies.netlog.json --out {rel(nl_session)}`",
    ]

    for label, document in (("HAR", imported_har), ("NetLog h1", imported_nl)):
        request = document["requests"][0]
        headers = request["requestHeaders"]["headers"]
        pairs = [(entry["name"], entry["value"]) for entry in headers]
        without_cookie = [pair for pair in pairs
                          if pair[0].lower() not in {"cookie", "host"}]
        exp.eq(without_cookie, expected_pairs, f"{label}: ordem, caixa e duplicatas da requisição")
        exp.eq(len([name for name, _ in without_cookie if name.lower() == "x-rep"]), 3,
               f"{label}: três ocorrências de x-rep preservadas")
        exp.eq(request["requestHeaders"]["orderState"], "sourceOrder",
               f"{label}: orderState=sourceOrder")

        cookie = request["cookie"]
        exp.eq(cookie.get("raw"),
               ["sl_a=1; sl_b=2; sc_dup=one; sc_dup=two"],
               f"{label}: campo Cookie bruto preservado")
        exp.eq([(pair["name"], pair["value"]) for pair in cookie.get("pairs", [])],
               [("sl_a", "1"), ("sl_b", "2"), ("sc_dup", "one"), ("sc_dup", "two")],
               f"{label}: pares internos do Cookie, com sc_dup duplicado")
        exp.ok(len([p for p in cookie.get("pairs", []) if p["name"] == "sc_dup"]) == 2,
               f"{label}: nome de cookie duplicado não foi colapsado")

        set_cookies = request.get("setCookies", [])
        expected_set_cookies = ["sc_a=1; Path=/; HttpOnly",
                                "sc_b=2; Path=/; Secure; SameSite=Lax",
                                "sc_dup=one; Path=/",
                                "sc_dup=two; Path=/"]
        if label == "HAR":
            # O HAR da fixture inclui Expires na terceira linha; a linha bruta é preservada.
            expected_set_cookies[2] = "sc_dup=one; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
        exp.eq([record["raw"] for record in set_cookies], expected_set_cookies,
               f"{label}: linhas Set-Cookie na ordem da fonte")
        exp.eq([record.get("parsed", {}).get("name") for record in set_cookies],
               ["sc_a", "sc_b", "sc_dup", "sc_dup"],
               f"{label}: Set-Cookie parseado, repetição preservada")
        exp.ok(set_cookies[0].get("parsed", {}).get("httpOnly") is True,
               f"{label}: HttpOnly de sc_a parseado")
        exp.ok(set_cookies[1].get("parsed", {}).get("secure") is True,
               f"{label}: Secure de sc_b parseado")

        # Roundtrip: reabrir a sessão gravada não altera a sequência.
        reopened = inspect(har_session if label == "HAR" else nl_session)
        again = [(entry["name"], entry["value"])
                 for entry in reopened["requests"][0]["requestHeaders"]["headers"]]
        exp.eq([pair for pair in again if pair[0].lower() not in {"cookie", "host"}], expected_pairs,
               f"{label}: sequência preservada após gravação e releitura")

    exp.eq(view_verification(imported_nl["requests"][0]["requestHeaders"]), "verified",
           "NetLog h1: headers de requisição verificados")
    exp.eq(view_verification(imported_nl["requests"][0]["responseHeaders"]), "verified",
           "NetLog h1: headers de resposta verificados")
    exp.eq(view_verification(imported_har["requests"][0]["requestHeaders"]), "unverified",
           "HAR: ordem permanece não verificada (não inventa selo)")
    response_pairs = [(entry["name"], entry["value"])
                      for entry in imported_nl["requests"][0]["responseHeaders"]["headers"]]
    exp.ok(("x-resp-order", "1") in response_pairs and ("x-resp-order", "2") in response_pairs,
           "NetLog: duplicata de resposta x-resp-order preservada na ordem")
    evidence.append("asserções: sequência/caixa/duplicatas, Cookie bruto+pares, Set-Cookie bruto+parseado, verificação por fonte")

    # Todas as fixtures de aceite precisam se declarar sintéticas.
    missing = [str(path.relative_to(ROOT)) for path in FIX.glob("*/fixture.json")
               if json.loads(path.read_text()).get("label") != "synthetic-fixture"]
    exp.eq(missing, [], "todas as fixtures de aceite rotuladas synthetic-fixture")
    return exp.rows, evidence, notes


def item_2(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """HAR/NetLog válidos, incompletos, inválidos e com eventos desconhecidos."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    parsers = FIX / "parsers"
    base = ctx["run"] / "item2"

    valid = import_to("import-har", FIX / "headers-cookies" / "headers-cookies.har", base / "valid-har")
    exp.eq(len(valid["requests"]), 1, "HAR válido: 1 requisição importada")

    incomplete = import_to("import-har", parsers / "incomplete.har", base / "incomplete-har")
    exp.eq(len(incomplete["requests"]), 2, "HAR incompleto: entradas válidas preservadas")
    exp.eq(incomplete["session"]["completeness"]["state"], "partial",
           "HAR incompleto: completeness=partial")
    codes = {warning["code"] for warning in incomplete["warnings"]}
    exp.contains(codes, "har.missing_response", "HAR incompleto: aviso explícito har.missing_response")
    har_counts = incomplete["session"]["completeness"]["counts"]
    exp.eq(har_counts.get("sourceEvents"), 2, "HAR: sourceEvents persistido (2 entradas)")
    exp.eq(har_counts.get("sourceEventsUsed"), 2, "HAR: sourceEventsUsed persistido (2)")

    invalid_har = core("import-har", str(parsers / "invalid.har"), "--out", str(base / "invalid-har"))
    exp.ok(invalid_har.returncode != 0, "HAR inválido: falha explícita (não silenciosa)")
    exp.contains(invalid_har.stderr, "erro:", "HAR inválido: mensagem de erro no stderr")

    unknown_encoding = import_to("import-har", parsers / "unknown-encoding.har", base / "encoding")
    codes = {warning["code"] for warning in unknown_encoding["warnings"]}
    exp.contains(codes, "har.unknown_encoding", "HAR com encoding desconhecido: aviso")
    exp.eq(unknown_encoding["requests"][0]["responseBody"].get("bytes"), 5,
           "HAR com encoding desconhecido: corpo tratado como texto e medido")

    unknown = import_to("import-netlog", parsers / "unknown-events.netlog.json", base / "unknown")
    exp.eq(len(unknown["requests"]), 1, "NetLog com eventos desconhecidos: requisição preservada")
    unknown_warning = next((warning for warning in unknown["warnings"]
                           if warning["code"] == "netlog.unknown_event_type"), None)
    exp.ok(unknown_warning is not None, "NetLog: aviso persistido com a contagem de desconhecidos")
    if unknown_warning:
        match = re.search(r"(\d+) evento", unknown_warning["message"])
        count = int(match.group(1)) if match else 0
        exp.ok(count >= 3, f"NetLog: {count} eventos desconhecidos contabilizados no aviso")
        exp.ok(bool((unknown_warning.get("detail") or {}).get("samples")),
               "NetLog: amostras dos tipos desconhecidos preservadas no aviso")
    codes = {warning["code"] for warning in unknown["warnings"]}
    exp.contains(codes, "netlog.unknown_event_type", "NetLog: aviso netlog.unknown_event_type")
    exp.eq(unknown["session"]["completeness"]["state"], "partial",
           "NetLog com itens desconhecidos: completeness=partial")
    unknown_counts = unknown["session"]["completeness"]["counts"]
    exp.eq(unknown_counts.get("sourceEvents"), 7, "NetLog: sourceEvents persistido (7)")
    exp.eq(unknown_counts.get("sourceEventsUnknown"), 3, "NetLog: sourceEventsUnknown persistido (3)")

    no_constants = import_to("import-netlog", parsers / "no-constants.netlog.json", base / "no-constants")
    codes = {warning["code"]: warning for warning in no_constants["warnings"]}
    exp.contains(codes, "netlog.constants_missing", "NetLog sem constants: aviso explícito")
    exp.contains(codes, "netlog.no_requests", "NetLog sem constants: aviso de zero requisições")
    exp.eq(no_constants["session"]["completeness"]["state"], "partial",
           "NetLog sem constants: completeness=partial (nunca complete)")

    bad_line = import_to("import-netlog", parsers / "bad-header-line.netlog.json", base / "bad-line")
    exp.eq(len(bad_line["requests"]), 1, "NetLog com linha de header inválida: requisição preservada")
    codes = {warning["code"] for warning in bad_line["warnings"]}
    exp.contains(codes, "netlog.header_line_invalid", "NetLog: aviso de linha sem separador")
    names = [entry["name"] for entry in bad_line["requests"][0]["requestHeaders"]["headers"]]
    exp.eq(names.count("x-ok"), 2, "NetLog: headers válidos ao redor da linha inválida mantidos")

    truncated = core("import-netlog", str(parsers / "truncated.netlog.json"), "--out", str(base / "truncated"))
    exp.ok(truncated.returncode != 0, "NetLog truncado: falha explícita")
    exp.contains(truncated.stderr, "erro:", "NetLog truncado: erro no stderr")

    evidence += [
        f"`scrapelens-core import-har fixtures/aceite/parsers/incomplete.har --out {rel(base / 'incomplete-har')}`",
        f"`scrapelens-core import-netlog fixtures/aceite/parsers/unknown-events.netlog.json --out {rel(base / 'unknown')}`",
        f"`scrapelens-core import-netlog fixtures/aceite/parsers/no-constants.netlog.json --out {rel(base / 'no-constants')}`",
        "casos inválidos: retorno ≠ 0 com `erro:` no stderr (HAR sem entries, NetLog truncado)",
    ]
    notes.append("HAR não comprova ordem/duplicatas: entradas importadas ficam `unverified`, como no contrato.")
    notes.append("Contagens `completeness.counts.sourceEvents*` agora são persistidas e sobrevivem à releitura "
                 "(correção do core nesta onda); os avisos continuam trazendo amostras dos tipos desconhecidos.")
    return exp.rows, evidence, notes


def item_3(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Requisições simultâneas idênticas: ambiguidade explícita, sem escolha falsa."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "ambiguous"
    session_dir = ctx["run"] / "item3" / "capture"
    meta = fixture_meta(folder)
    exp.eq(meta.get("label"), "synthetic-fixture", "fixture de ambiguidade rotulada sintética")
    # A fixture precisa ser coerente com o Chrome real: o `wallTime` do CDP é
    # `timeTickOffset/1000 + timestamp`. Se essa equação quebrar, a calibração de
    # unidade do core (f6c6bdd) escolhe microssegundos e a correlação zera —
    # falha da fixture, não do core.
    cdp_events = [json.loads(line) for line in
                  (folder / "cdp-ambiguous.jsonl").read_text(encoding="utf-8").splitlines()
                  if line.strip()]
    offset_ms = json.loads((folder / "netlog-ambiguous.json").read_text(encoding="utf-8")
                           )["constants"]["timeTickOffset"]
    exp.ok(all(abs(event["params"]["wallTime"]
                   - (offset_ms / 1000.0 + event["params"]["timestamp"])) < 1e-6
               for event in cdp_events
               if event["method"] == "Network.requestWillBeSent"),
           "relógio da fixture coerente (wallTime = timeTickOffset/1000 + timestamp)")

    fresh(session_dir)
    core_ok("import-capture", str(folder / "cdp-ambiguous.jsonl"),
            str(folder / "netlog-ambiguous.json"), "--out", str(session_dir),
            "--label", "synthetic-fixture")
    session = inspect(session_dir)
    exp.eq(sorted(session["session"].get("labels", [])), SYNTHETIC_LABELS, "sessão importada rotulada como fixture sintética")
    evidence.append(
        "`scrapelens-core import-capture fixtures/aceite/ambiguous/cdp-ambiguous.jsonl "
        "fixtures/aceite/ambiguous/netlog-ambiguous.json --out "
        f"{rel(session_dir)}`"
    )

    requests = session["requests"]
    exp.eq(len(requests), 2, "duas requisições CDP importadas")
    unit_warning = next((warning for warning in session["warnings"]
                         if warning["code"] == "netlog.time_unit_detected"), None)
    exp.ok(unit_warning is not None, "unidade de `time` calibrada pelo relógio do CDP")
    exp.eq((unit_warning or {}).get("detail", {}).get("unit"), "milliseconds",
           "unidade calibrada como milliseconds (a mesma do Chrome real)")
    ambiguous = [request for request in requests if request.get("match") == "ambiguous"]
    exp.eq(len(ambiguous), 2, "ambas marcadas match=ambiguous (nenhuma associação silenciosa)")
    for request in ambiguous:
        candidates = request.get("matchCandidates", [])
        exp.eq(len(candidates), 2, f"{request['id']}: dois candidatos expostos")
        exp.ok(all(candidate.get("score", 0) >= 55 for candidate in candidates),
               f"{request['id']}: candidatos acima do score mínimo, apenas para exibição")
        exp.ok(all(candidate.get("entityId") for candidate in candidates),
               f"{request['id']}: candidatos identificáveis (entityId)")
        exp.eq(view_verification(request["requestHeaders"]), "unverified",
               f"{request['id']}: visão primária não foi promovida a verified na ambiguidade")
    candidate_sets = sorted(tuple(sorted(c["entityId"] for c in request["matchCandidates"]))
                            for request in ambiguous)
    exp.eq(len(set(candidate_sets)), 1,
           "as duas requisições veem o mesmo conjunto de candidatos (não houve escolha cruzada)")
    codes = [warning["code"] for warning in session["warnings"]]
    exp.eq(codes.count("correlate.ambiguous"), 2, "dois avisos correlate.ambiguous persistidos")

    netlog_only = import_to("import-netlog", folder / "netlog-ambiguous.json", ctx["run"] / "item3" / "netlog")
    exp.eq(len(netlog_only["requests"]), 2, "NetLog isolado mantém as duas tentativas")
    exp.eq(netlog_only["session"]["completeness"]["state"], "partial",
           "NetLog isolado sem CDP: completeness=partial (cobertura não provada)")

    notes.append("A ordem/duplicata do NetLog é preservada, mas não vira visão primária enquanto há ambiguidade.")
    notes.append("Diagnóstico da falha do líder: a fixture declarava `wallTime` sem o `timestamp` monotônico "
                 "(`1793046000.0`), e o core de `f6c6bdd` calibrava `time` como microssegundos; o NetLog ficava "
                 "2 s à frente e as duas requisições viravam `unmatched`. O Chrome real satisfaz "
                 "`wallTime = timeTickOffset/1000 + timestamp` (desvio medido < 1 ms), equação agora usada na "
                 "fixture. Era defeito da fixture, não do core; a falha original está preservada em "
                 "`tests/results/aceite-criterio3-falha-lider.json` e `RELATORIO-criterio3-falha-lider.md`.")
    notes.append("Asserções novas nesta rodada: coerência do relógio da fixture (CDP×NetLog) e unidade "
                 "calibrada `milliseconds`. O teste de ambiguidade segue rigoroso: as duas requisições a 20 ms "
                 "continuam ambíguas, cada uma com os mesmos 2 candidatos e 2 avisos `correlate.ambiguous`.")
    return exp.rows, evidence, notes


def item_4(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Redirects e múltiplas tentativas, sem perder elos."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    folder = FIX / "redirects"
    base = ctx["run"] / "item4"

    netlog = import_to("import-netlog", folder / "redirect-chain.netlog.json", base / "netlog")
    request = netlog["requests"][0]
    exp.eq(len(netlog["requests"]), 1, "NetLog: um LogicalRequest para a cadeia")
    exp.eq([attempt["status"] for attempt in request["attempts"]], [302, 200],
           "NetLog: status por tentativa [302, 200]")
    exp.eq(len(request.get("redirects", [])), 1, "NetLog: um Redirect registrado")
    redirect = request["redirects"][0]
    exp.eq(redirect.get("fromUrl"), "http://127.0.0.1:9999/a", "NetLog: redirect fromUrl")
    exp.eq(redirect.get("toUrl"), "http://127.0.0.1:9999/b", "NetLog: redirect toUrl")
    exp.eq(redirect.get("status"), 302, "NetLog: status do redirect")
    final_headers = [(entry["name"], entry["value"])
                     for entry in request["requestHeaders"]["headers"]]
    exp.eq(final_headers, [("Host", "127.0.0.1:9999"), ("x-step", "2")],
           "NetLog: headers da tentativa final com ordem da fonte")
    exp.eq(view_verification(request["requestHeaders"]), "verified",
           "NetLog: headers finais verificados")

    har = import_to("import-har", folder / "redirect-chain.har", base / "har")
    har_request = har["requests"][0]
    exp.eq(len(har["requests"]), 1, "HAR: cadeia agrupada em um LogicalRequest")
    exp.eq([attempt["status"] for attempt in har_request["attempts"]], [302, 302, 200],
           "HAR: três tentativas na ordem")
    exp.eq(len(har_request.get("redirects", [])), 2, "HAR: dois Redirects")
    exp.eq(har_request["responseBody"].get("state"), "captured",
           "HAR: corpo da resposta final capturado")

    evidence += [
        f"`scrapelens-core import-netlog fixtures/aceite/redirects/redirect-chain.netlog.json --out {rel(base / 'netlog')}`",
        f"`scrapelens-core import-har fixtures/aceite/redirects/redirect-chain.har --out {rel(base / 'har')}`",
    ]
    notes.append("O redirect é um elo entre tentativas, não uma requisição separada.")
    return exp.rows, evidence, notes


def item_5(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Corpos ausentes/truncados/descartados/vazios com estado explícito."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "bodies" / "session"
    session = inspect(session_path)
    evidence.append(f"`scrapelens-core inspect {rel(session_path)}`")

    requests = session["requests"]
    exp.eq(len(requests), 3, "três requisições de fixture")
    first, second, third = requests

    exp.eq(first["requestBody"].get("state"), "discarded", "req 1: corpo descartado explícito")
    exp.contains(first["requestBody"].get("note") or "", "descartado",
                 "req 1: nota explica o descarte")
    exp.eq(first["responseBody"].get("state"), "captured", "req 1: resposta capturada")
    attachment = first["responseBody"].get("attachment")
    exp.ok(bool(attachment), "req 1: anexo referenciado")
    if attachment:
        path = session_path / "attachments" / attachment
        exp.ok(path.exists(), f"req 1: anexo {attachment} existe")
        if path.exists():
            exp.eq(path.read_bytes(), b"resposta", "req 1: bytes do anexo batem com o HAR")

    exp.eq(second["requestBody"].get("state"), "empty", "req 2: corpo de requisição vazio (afirmado)")
    exp.eq(second["responseBody"].get("state"), "truncated", "req 2: resposta truncada explícita")
    exp.eq(second["responseBody"].get("truncatedAt"), 4, "req 2: truncatedAt registrado")
    exp.eq(second["responseBody"].get("bytes"), 4, "req 2: bytes capturados registrados")
    truncated_attachment = second["responseBody"].get("attachment")
    if truncated_attachment:
        path = session_path / "attachments" / truncated_attachment
        exp.eq(path.read_bytes(), b"0123", "req 2: anexo truncado tem exatamente 4 bytes")

    exp.eq(third["requestBody"].get("state"), "unavailable",
           "req 3: requisição indisponível (não vazia)")
    exp.contains(third["requestBody"].get("note") or "", "não fornece",
                 "req 3: nota explica indisponibilidade")
    exp.eq(third["responseBody"].get("state"), "empty", "req 3: resposta vazia (0 bytes)")

    states = {request["requestBody"].get("state") for request in requests} | {
        request["responseBody"].get("state") for request in requests}
    exp.eq(states, {"discarded", "captured", "empty", "truncated", "unavailable"},
           "todos os cinco estados aparecem na fixture")
    notes.append("`empty` só é usado quando a fonte afirma zero bytes; ausência vira `unavailable` com nota.")
    return exp.rows, evidence, notes


def item_6(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Diff por ocorrência: duplicatas preservadas e ordem não alfabética."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "diff" / "session"
    session = inspect(session_path)
    first, second = session["requests"]
    a_pairs = [(entry["name"], entry["value"]) for entry in first["requestHeaders"]["headers"]]
    b_pairs = [(entry["name"], entry["value"]) for entry in second["requestHeaders"]["headers"]]
    exp.eq(a_pairs.count(("x-dup", "same")), 2, "A: duplicata x-dup:same aparece duas vezes")
    exp.eq(b_pairs.count(("x-dup", "same")), 2, "B: duplicata x-dup:same aparece duas vezes")

    diff = json.loads(core_ok("diff", str(session_path), first["id"], second["id"]))
    evidence.append(f"`scrapelens-core diff {rel(session_path)} {first['id']} {second['id']}`")
    headers = diff["requestHeaders"]
    exp.eq([item["name"] for item in headers["added"]], ["x-new"],
           "diff: apenas x-new adicionado")
    exp.eq([(item["name"], item["value"]) for item in headers["removed"]], [("x-rep", "b")],
           "diff: x-rep:b removido (valor não existe em B)")
    exp.eq(headers["changed"], [], "diff: nenhum par alterado")
    exp.ok(any(move["name"] == "x-seq" for move in headers["reordered"]),
           "diff: reordenação de x-seq detectada como reordered")
    exp.eq(headers["unchanged"], 6, "diff: seis ocorrências inalteradas")
    touched = {item["name"] for item in headers["added"]} | {
        item["name"] for item in headers["removed"]} | {move["name"] for move in headers["reordered"]}
    exp.ok("x-dup" not in touched, "diff: as duas ocorrências de x-dup não foram colapsadas")
    exp.eq(headers["added"][0].get("index"), 6, "diff: índice global da ocorrência adicionada")
    exp.ok(headers["reordered"][0]["a"]["index"] == 0 and headers["reordered"][0]["b"]["index"] == 1,
           "diff: reordenação usa índices originais (0 → 1), não ordem alfabética")
    exp.eq(diff["responseHeaders"]["added"] or [], [], "diff: resposta sem adições")
    exp.eq(diff["responseHeaders"]["removed"] or [], [], "diff: resposta sem remoções")
    exp.eq(diff["cookies"]["unchanged"], 0, "diff: sem cookies nesta fixture")

    # A ordem original continua disponível na sessão (o diff não a reescreve).
    exp.eq(a_pairs[:4], [("x-seq", "1"), ("X-Rep", "a"), ("x-seq", "2"), ("x-rep", "b")],
           "A: ordem original intacta após o diff")
    notes.append("O diff compara ocorrências; `reordered` usa os índices originais de A e B.")
    return exp.rows, evidence, notes


def item_7(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Exportação cURL/Python com dados hostis e escaping correto."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    session_path = FIX / "export-special" / "session"
    session = inspect(session_path)
    request = session["requests"][0]
    nul_request = session["requests"][1]
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
    exp.eq(len(session["requests"]), 2, "duas requisições de exportação")

    curl = core("export-curl", str(session_path), request["id"])
    exp.eq(curl.returncode, 0, "export-curl retorna 0")
    exp.contains(curl.stderr, "export.header_injection",
                 "cURL: header com CR/LF descartado com aviso")
    script = ctx["run"] / "item7" / "export.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(curl.stdout, encoding="utf-8")
    syntax = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    exp.eq(syntax.returncode, 0, f"cURL: script passa em `bash -n` ({syntax.stderr.strip()})")

    stub = ctx["run"] / "item7" / "stub.sh"
    stub.write_text(
        "curl() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' -- \"$@\"; }\n",
        encoding="utf-8")
    runner = ctx["run"] / "item7" / "run.sh"
    runner.write_text(f". {shlex_quote(str(stub))}\n. {shlex_quote(str(script))}\n", encoding="utf-8")
    executed = subprocess.run(["bash", str(runner)], capture_output=True, text=True)
    exp.eq(executed.returncode, 0, "cURL: execução com stub não falha")
    argv: list[str] = []
    for line in executed.stdout.splitlines():
        line = line.strip()
        if line.startswith("["):
            argv = json.loads(line)
    exp.ok(bool(argv), "cURL: stub capturou argv")
    if argv:
        url_index = argv.index("--url")
        exp.eq(argv[url_index + 1], expected_url,
               "cURL: URL hostil chega intacta ao shell")
        got_headers = [argv[index + 1] for index, token in enumerate(argv) if token == "--header"]
        exp.eq([tuple(header.split(": ", 1)) for header in got_headers], expected_headers,
               "cURL: headers, ordem e duplicatas chegam intactos")
        exp.ok("--data-binary" in argv, "cURL: corpo incluído")
        if "--data-binary" in argv:
            exp.eq(argv[argv.index("--data-binary") + 1].encode(), expected_body,
                   "cURL: bytes do corpo (aspas, $, crase, barra, \\n) intactos")
        exp.ok(not any("x-bad" in value for value in got_headers),
               "cURL: header x-bad (CR/LF) não é replicado")

    nul_curl = core("export-curl", str(session_path), nul_request["id"])
    exp.eq(nul_curl.returncode, 0, "cURL: exportação com corpo NUL retorna 0")
    exp.contains(nul_curl.stderr, "export.body_nul",
                 "cURL: corpo NUL omitido com aviso (não truncado em silêncio)")
    exp.ok("--data-binary" not in nul_curl.stdout,
           "cURL: corpo NUL não vira argumento parcial")

    python_export = core("export-python", str(session_path), request["id"])
    exp.eq(python_export.returncode, 0, "export-python retorna 0")
    exp.contains(python_export.stderr, "export.header_injection",
                 "Python: header com CR/LF descartado com aviso")
    py_path = ctx["run"] / "item7" / "export.py"
    py_path.write_text(python_export.stdout, encoding="utf-8")
    compiled = subprocess.run([sys.executable, "-m", "py_compile", str(py_path)],
                              capture_output=True, text=True)
    exp.eq(compiled.returncode, 0, f"Python: sintaxe válida ({compiled.stderr.strip()})")
    method, target, sent_headers, sent_body = python_literals(py_path)
    exp.eq((method, target), ("POST", "/p?q=o'relly&x=$HOME&y=`id`&z=a&b=100%"
                              "&u=%C3%A7%C3%A3o&pipe=|&semi=;"),
           "Python: método e target hostis intactos")
    exp.eq(sent_headers, expected_headers,
           "Python: putheader por ocorrência, ordem e duplicatas intactas")
    exp.eq(sent_body, expected_body, "Python: bytes do corpo intactos")
    exp.ok(not any("x-bad" in name for name, _ in sent_headers),
           "Python: header x-bad não é replicado")

    nul_python = core("export-python", str(session_path), nul_request["id"])
    nul_path = ctx["run"] / "item7" / "nul.py"
    nul_path.write_text(nul_python.stdout, encoding="utf-8")
    nul_compiled = subprocess.run([sys.executable, "-m", "py_compile", str(nul_path)],
                                  capture_output=True, text=True)
    exp.eq(nul_compiled.returncode, 0, "Python: exportação com NUL compila")
    _, _, _, nul_sent = python_literals(nul_path)
    exp.eq(nul_sent, b"bin\x00ario", "Python: bytes NUL preservados no corpo")

    evidence += [
        f"`scrapelens-core export-curl {rel(session_path)} {request['id']}` → `bash -n` + execução com stub que registra argv",
        f"`scrapelens-core export-python {rel(session_path)} {request['id']}` → `python3 -m py_compile` + AST com literais",
        f"comandos gerados: {rel(script)}, {rel(py_path)}",
    ]
    notes.append("Os exportadores prometem a requisição HTTP, não TLS/fingerprint (JA3/JA4, frames, HPACK).")
    return exp.rows, evidence, notes


def item_8(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Sanitização: credenciais, cookies, token em URL, corpos e eventos brutos."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    source = FIX / "sanitize" / "session"
    out = ctx["run"] / "item8" / "sanitized"
    if out.exists():
        shutil.rmtree(out)
    proc = core("sanitize", str(source), str(out))
    exp.eq(proc.returncode, 0, "sanitize retorna 0")
    report = json.loads(proc.stdout) if proc.stdout.strip().startswith("{") else {}
    evidence.append(f"`scrapelens-core sanitize {rel(source)} {rel(out)}`")

    exp.ok(out.exists(), "diretório sanitizado criado")
    if not out.exists():
        return exp.rows, evidence, notes
    exp.eq(stat.S_IMODE(out.stat().st_mode), 0o700, "diretório sanitizado com permissão 0700")
    session_file = out / "session.json"
    exp.ok(session_file.exists(), "session.json presente")
    exp.eq(stat.S_IMODE(session_file.stat().st_mode), 0o600, "session.json com permissão 0600")
    for name in ("cdp-events.jsonl", "netlog.json"):
        exp.ok(not (out / name).exists(), f"evento bruto {name} não copiado para a exportação")
    exp.contains(report.get("redactions", {}), "rawEvents", "relatório contabiliza rawEvents")
    warning_codes = {warning["code"] for warning in report.get("warnings", [])}
    exp.contains(warning_codes, "sanitize.raw_events_removed",
                 "aviso sanitize.raw_events_removed presente")
    exp.contains(warning_codes, "sanitize.attachment_omitted",
                 "anexo não sanitizável omitido com aviso")

    leaks: list[str] = []
    for path in out.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for secret in SECRETS:
                if secret.encode() in data:
                    leaks.append(f"{path.relative_to(out)}:{secret}")
    exp.eq(leaks, [], "nenhum segredo SECRET-* ou e-mail permanece na árvore sanitizada")

    sanitized = json.loads(session_file.read_text(encoding="utf-8"))
    exp.contains(sanitized["session"].get("labels", []), "sanitized",
                 "sessão marcada com label sanitized")
    urls = [request["url"] for request in sanitized["requests"]]
    exp.ok(all("SECRET" not in url for url in urls), "URLs sanitizadas sem token")
    exp.ok(any("REDACTED" in url for url in urls), "placeholder [REDACTED] aparece na URL")
    exp.ok(all("SECRET" not in json.dumps(request.get("cookie", {}), ensure_ascii=False)
               for request in sanitized["requests"]), "Cookie sanitizado")
    exp.ok(all("SECRET" not in json.dumps(request.get("setCookies", []), ensure_ascii=False)
               for request in sanitized["requests"]), "Set-Cookie sanitizado")
    exp.contains(session_file.read_text(encoding="utf-8"), "[REDACTED]",
                 "valores substituídos por [REDACTED]")

    again = core("sanitize", str(source), str(out))
    exp.ok(again.returncode != 0, "sanitize recusa sobrescrever destino já existente")
    exp.contains(again.stderr, "já contém", "mensagem de recusa é acionável")

    evidence += [
        f"permissões: `{oct(stat.S_IMODE(out.stat().st_mode))}` no diretório e "
        f"`{oct(stat.S_IMODE(session_file.stat().st_mode))}` no session.json",
        "varredura recursiva por 10 marcadores SECRET-* + e-mail: nenhuma ocorrência",
    ]
    notes.append("Sanitização não promete detectar tokens em path/HTML livre; esses corpos são omitidos com aviso.")
    return exp.rows, evidence, notes


def item_9(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Ciclo real de captura no macOS com Chrome dedicado, sem certificado."""
    exp = Expect()
    evidence: list[str] = []
    notes: list[str] = []
    run_dir = ctx.get("capture")
    if not run_dir or not pathlib.Path(run_dir).exists():
        return [], [], ["não testado: nenhuma execução de `tests/capture/run-cycle.sh` fornecida"]
    run_dir = pathlib.Path(run_dir)
    summary_path = run_dir / "run.json"
    exp.ok(summary_path.exists(), "run.json da captura existe")
    if not summary_path.exists():
        return exp.rows, evidence, notes
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    evidence.append(f"execução real: `{rel(run_dir)}` (gerada por `tests/capture/run-cycle.sh`); "
                    "cópia estável em `tests/results/capture-latest/run.json`")

    for leg in summary.get("captures", []):
        meta = leg.get("meta", {})
        flags = meta.get("chromeArgs", [])
        profile = meta.get("profile", "")
        exp.ok("--disable-quic" not in flags, f"{leg['name']}: QUIC não foi desabilitado")
        exp.ok(any(flag.startswith("--enable-quic") for flag in flags),
               f"{leg['name']}: --enable-quic presente")
        exp.ok(any(flag.startswith("--ignore-certificate-errors-spki-list=") for flag in flags),
               f"{leg['name']}: certificado dispensado por SPKI (nada instalado)")
        exp.ok("--ignore-certificate-errors" not in flags,
               f"{leg['name']}: não usa bypass global de certificado")
        exp.ok("--user-data-dir=" in " ".join(flags), f"{leg['name']}: perfil dedicado explícito")
        exp.ok(bool(profile) and str(pathlib.Path(run_dir).resolve()) in str(pathlib.Path(profile).resolve()),
               f"{leg['name']}: perfil dedicado dentro do diretório da execução")
        exp.ok("--remote-debugging-address=127.0.0.1" in flags,
               f"{leg['name']}: debug exposto apenas em loopback")
        exp.ok(meta.get("browser", {}).get("name") == "Chrome",
               f"{leg['name']}: navegador Chrome identificado")
        exp.contains(meta.get("browser", {}).get("version", ""), ".",
                     f"{leg['name']}: versão do Chrome registrada")

        session_dir = run_dir / leg["session"]
        exp.ok(session_dir.exists(), f"{leg['name']}: sessão importada existe")
        if not session_dir.exists():
            continue
        session = inspect(session_dir)
        state = session["session"]["completeness"]["state"]
        exp.eq(state, "complete", f"{leg['name']}: completeness=complete (flush encerrado)")
        requests = session["requests"]
        exp.ok(len(requests) >= 3, f"{leg['name']}: {len(requests)} requisições reais capturadas")
        protocols = {request["protocol"] for request in requests}
        exp.contains(protocols, leg.get("protocol"), f"{leg['name']}: protocolo {leg.get('protocol')} presente")
        exp.contains(protocols - {"unknown"}, leg.get("protocol"),
                     f"{leg['name']}: nenhum protocolo divergente")
        exp.ok(all(request.get("match") != "unmatched" for request in requests),
               f"{leg['name']}: todas as requisições CDP correlacionadas (matched/ambiguous)")
        verified = [request for request in requests
                    if view_verification(request["requestHeaders"]) == "verified"]
        if leg.get("protocol") == "h1":
            exp.ok(bool(verified), "h1: ao menos um request com headers verificados (NetLog)")
        if "h2" in protocols:
            h2_views = {view_verification(request["requestHeaders"])
                        for request in requests if request["protocol"] == "h2"}
            exp.ok(h2_views and h2_views <= {"partial"},
                   f"h2: headers de requisição permanecem partial (visto: {sorted(h2_views)})")
        exp.ok(any(request.get("status") for request in requests),
               f"{leg['name']}: status HTTP real presente")
        states = [request["responseBody"].get("state") for request in requests]
        exp.ok(all(state in {"captured", "empty", "truncated", "unavailable", "discarded"}
                   for state in states),
               f"{leg['name']}: todos os corpos têm estado explícito {sorted(set(states))}")
        exp.ok(all(request["responseBody"].get("note")
                   for request in requests
                   if request["responseBody"].get("state") == "unavailable"),
               f"{leg['name']}: corpo indisponível sempre acompanhado de nota")
        if leg.get("protocol") == "h3":
            exp.ok(any(request["protocol"] == "h3" for request in requests),
                   "h3: QUIC usado de fato (QUIC intacto)")
            exp.ok(len(session.get("streamSessions", [])) > 0,
                   "h3: StreamSessions QUIC registradas")

    if summary.get("redirects", 0) >= 1:
        notes.append("A página real `/page` exercitou redirects e POSTs.")
    else:
        exp.ok(False, "captura real exercitou ao menos um redirect")
    har = summary.get("har")
    exp.ok(har is not None, "HAR reconstruído do CDP real importado sem falha")
    if har:
        exp.ok(har.get("requests", 0) > 0, f"HAR real: {har.get('requests')} requisições importadas")
        exp.ok(har.get("completeness") in {"complete", "partial"},
               f"HAR real: completeness explícito ({har.get('completeness')})")
    notes.append("O HAR do ciclo é reconstruído do CDP (`experiments/har_from_cdp.mjs`), porque o Chrome 156 "
                 "não expõe `Network.getHAR`; o creator declara a origem e a ordem não é comprovada (unverified).")

    ambiguous = summary.get("ambiguous", 0)
    exp.ok(ambiguous >= 1,
           f"captura real: {ambiguous} requisição(ões) ambígua(s) nas simultâneas idênticas")
    exp.ok(summary.get("certificateInstalled") is False,
           "nenhum certificado foi instalado no sistema")
    for common_name in ("ScrapeLens local test server", "ScrapeLens local test CA (synthetic)"):
        found = subprocess.run(["security", "find-certificate", "-c", common_name],
                               capture_output=True, text=True)
        exp.ok(found.returncode != 0,
               f"chaveiro do usuário não contém o certificado {common_name!r}")
    notes.append("O ciclo real usa CDP, que não busca corpos: todos os corpos ficam `unavailable` "
                 "com nota. A captura de corpo (Network.getResponseBody) ainda não está no caminho ao vivo.")

    app_path = ctx.get("app")
    if app_path and pathlib.Path(app_path).exists():
        app = json.loads(pathlib.Path(app_path).read_text(encoding="utf-8"))
        bundle = app.get("bundle", {})
        live = app.get("capture", {})
        imports = app.get("imports", {})
        exp.ok(bundle.get("exists") is True, "app: bundle .app existe")
        exp.ok(bundle.get("arm64") is True, f"app: Mach-O arm64 ({bundle.get('machO', '')})")
        exp.ok(bundle.get("singleBinary") is True,
               f"app: binário único sem sidecar ({bundle.get('binaries')})")
        exp.ok(bundle.get("signature") in ("adhoc", "local-identity"),
               f"app: assinatura ad-hoc ou identidade local 'ScrapeLens Local Signing' (sem certificado Apple): {bundle.get('signature')}")
        exp.ok(bundle.get("codesignVerifyDeepStrict") is True,
               f"app: codesign --verify --deep --strict passou ({bundle.get('codesignVerifyOutput')})")
        # Recomputa em disco, independente do run.json.
        _cs = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(APP_EXECUTABLE.parents[2])],
                             capture_output=True, text=True)
        exp.ok(_cs.returncode == 0, f"app: codesign --verify --deep --strict recalculado em disco ({(_cs.stderr or _cs.stdout).strip()[-120:]})")
        exp.ok((bundle.get("sizeBytes") or 0) > 10 * 1024 * 1024,
               f"app: bundle com {((bundle.get('sizeBytes') or 0) / (1024 * 1024)):.2f} MiB")
        exp.eq(bundle.get("executableSha256"), EXPECTED_APP_SHA256,
               "app: executável é o bundle final documentado (SHA-256)")
        # Recomputa em disco: o run.json sozinho não prova que o bundle existe.
        real_exe = APP_EXECUTABLE
        exp.ok(real_exe.is_file(), f"app: executável existe em disco ({real_exe})")
        if real_exe.is_file():
            disk = sha256(real_exe)
            exp.eq(disk, EXPECTED_APP_SHA256,
                   "app: SHA-256 do executável em disco = EXPECTED_APP_SHA256")
            exp.eq(disk, bundle.get("executableSha256"),
                   "app: SHA-256 do executável em disco = o registrado no run.json")
        exp.ok((bundle.get("executableBytes") or 0) > 0,
               f"app: executável com {bundle.get('executableBytes')} bytes")

        exp.eq(live.get("mode"), "cdp+netlog", "app: sessão ao vivo em modo cdp+netlog")
        exp.eq(live.get("completeness"), "complete", "app: sessão ao vivo complete")
        exp.ok(live.get("requests", 0) >= 10, f"app: {live.get('requests')} requisições reais na sessão")
        exp.ok("h1" in live.get("protocols", []), f"app: protocolos reais {live.get('protocols')}")
        exp.ok(live.get("verifiedHeaderEntries", 0) > 0,
               f"app: {live.get('verifiedHeaderEntries')} headers verificados")
        exp.eq(live.get("verifiedSources"), ["netlog"],
               "app: headers verificados vêm do NetLog (fonte correta)")
        exp.ok(all("HTTP_TRANSACTION_SEND_REQUEST_HEADERS" in event
                   for event in live.get("verifiedEvents", [])),
               "app: verificação h1 ancorada em HTTP_TRANSACTION_SEND_REQUEST_HEADERS")
        exp.ok(live.get("unmatched", 0) == 0,
               "app: nenhuma requisição CDP ficou sem correspondência")
        ambiguous = live.get("ambiguous", [])
        exp.ok(len(ambiguous) >= 1, f"app: {len(ambiguous)} requisições ambíguas")
        exp.ok(all(len(item.get("candidates", [])) >= 2 for item in ambiguous),
               "app: ambiguidade sempre expõe >=2 candidatos")
        exp.ok(all(item.get("candidates") and len(set(item["candidates"])) == len(item["candidates"])
                   for item in ambiguous), "app: candidatos distintos, sem escolha silenciosa")
        exp.eq(live.get("hasDemoLabel"), False, "app: sessão real sem rótulo demo/sintético")
        exp.contains(live.get("cookieNames", []), "sc_dup", "app: cookie com nome duplicado preservado")
        exp.ok(live.get("setCookieLines", 0) >= 4,
               f"app: {live.get('setCookieLines')} linhas Set-Cookie reais")
        exp.ok(live.get("redirects", 0) >= 1, f"app: {live.get('redirects')} redirects reais")
        exp.ok(set(live.get("responseBodyStates", [])) <= {"captured", "empty", "truncated",
                                                          "unavailable", "discarded"},
               "app: estados de corpo válidos na captura real")
        exp.ok(live.get("unavailableWithNote") is True,
               "app: corpo unavailable sempre com nota (sem corpo inventado)")
        exp.eq(live.get("dirMode"), "0o700", "app: diretório da sessão 0700")
        for name in ("session.json", "cdp-events.jsonl", "netlog.json"):
            artifact = live.get("rawArtifacts", {}).get(name, {})
            exp.ok(artifact.get("exists") is True and artifact.get("bytes", 0) > 0,
                   f"app: artefato bruto {name} presente")
            exp.eq(artifact.get("mode"), "0o600", f"app: {name} com permissão 0600")
        exp.contains(live.get("warnings", []), "correlate.ambiguous",
                     "app: aviso correlate.ambiguous persistido")
        exp.ok(app.get("gui", {}).get("screenshotExists") is True,
               "app: print do ciclo real capturado")
        exp.ok(app.get("gui", {}).get("startUrl") == "http://127.0.0.1:8781/page",
               "app: ciclo iniciado na página local do testserver")
        server = app.get("testserver", {})
        exp.ok(server.get("h1Lines", 0) >= 10,
               f"app: testserver registrou {server.get('h1Lines')} requisições do Chrome")

        har_import = imports.get("har") or {}
        exp.ok(bool(har_import), "app: sessão HAR real importada pelo app")
        if har_import:
            exp.contains(har_import.get("labels", []), "har-import", "app: HAR com label har-import")
            exp.eq(har_import.get("mode"), "har-import", "app: HAR em modo har-import")
            exp.eq(har_import.get("completeness"), "complete", "app: HAR completo")
            exp.eq(har_import.get("requests"), 24,
                   "app: HAR importado pela UI tem as 24 requisições do arquivo preparado")
            exp.ok({"h1", "h2"} <= set(har_import.get("protocols", [])),
                   f"app: HAR cobre h1 e h2 ({har_import.get('protocols')})")
            har_counts = har_import.get("counts") or {}
            exp.eq(har_counts.get("sourceEvents"), 24, "app: HAR com 24 sourceEvents persistidos")
            exp.eq(har_counts.get("sourceEventsUsed"), 24, "app: HAR usa os 24 sourceEvents")
            exp.eq(har_counts.get("sourceEventsUnknown"), 0, "app: HAR sem eventos-fonte desconhecidos")
            exp.ok((har_import.get("source") or {}).get("matchesSourceSequence") is True,
                   "app: HAR gravado reproduz a sequência método/URL de har-derived.json")
            exp.eq(har_import.get("verifiedHeaderEntries"), 0,
                   "app: HAR não alega ordem verificada (0 headers verified)")
            exp.eq(har_import.get("headerSources"), ["har"],
                   "app: headers do HAR importado têm fonte har")
            exp.eq(har_import.get("hasDemoLabel"), False, "app: HAR real sem rótulo demo")
            exp.eq(har_import.get("dirMode"), "0o700", "app: diretório do HAR importado 0700")
            exp.eq((har_import.get("rawArtifacts", {}).get("session.json") or {}).get("mode"), "0o600",
                   "app: session.json do HAR importado 0600")
            exp.ok((har_import.get("reload") or {}).get("unchangedAfterInspect") is True
                   and (har_import.get("reload") or {}).get("requestsFromInspect") == 24,
                   "app: HAR importado relê do disco com 24 requisições, sem alterar o arquivo")
        netlog_import = imports.get("netlog") or {}
        exp.ok(bool(netlog_import), "app: sessão NetLog real importada pelo app")
        if netlog_import:
            exp.contains(netlog_import.get("labels", []), "netlog-import",
                         "app: NetLog com label netlog-import")
            exp.eq(netlog_import.get("mode"), "netlog-import", "app: NetLog em modo netlog-import")
            exp.eq(netlog_import.get("completeness"), "partial",
                   "app: NetLog isolado partial com motivo")
            exp.ok(bool(netlog_import.get("completenessReasons")),
                   "app: motivo da parcialidade declarado")
            exp.eq(netlog_import.get("requests"), 32,
                   "app: NetLog importado pela UI tem as 32 requisições do arquivo preparado")
            exp.ok({"h1", "h2", "h3"} <= set(netlog_import.get("protocols", [])),
                   f"app: NetLog cobre h1/h2/h3 ({netlog_import.get('protocols')})")
            netlog_counts = netlog_import.get("counts") or {}
            exp.eq(netlog_counts.get("sourceEvents"), 5354,
                   "app: NetLog com 5354 sourceEvents persistidos")
            exp.eq(netlog_counts.get("sourceEventsUsed"), 5354, "app: NetLog usa os 5354 sourceEvents")
            exp.eq(netlog_counts.get("sourceEventsUnknown"), 0,
                   "app: NetLog sem eventos-fonte desconhecidos")
            exp.eq(netlog_import.get("streamSessions"), 15,
                   "app: 15 StreamSessions h3 persistidas no NetLog")
            exp.ok((netlog_import.get("source") or {}).get("matchesSourceBytes") is True,
                   "app: netlog.json persistido é byte-idêntico ao h1h2h3.chrome-netlog.json preparado")
            exp.ok(netlog_import.get("verifiedHeaderEntries", 0) > 0
                   and netlog_import.get("verifiedSources") == ["netlog"],
                   f"app: {netlog_import.get('verifiedHeaderEntries')} headers verificados com fonte netlog")
            exp.eq(netlog_import.get("headerSources"), ["netlog"],
                   "app: headers do NetLog importado têm fonte netlog")
            exp.eq(netlog_import.get("hasDemoLabel"), False, "app: NetLog real sem rótulo demo")
            exp.eq(netlog_import.get("dirMode"), "0o700", "app: diretório do NetLog importado 0700")
            exp.eq((netlog_import.get("rawArtifacts", {}).get("session.json") or {}).get("mode"), "0o600",
                   "app: session.json do NetLog importado 0600")
            exp.eq((netlog_import.get("rawArtifacts", {}).get("netlog.json") or {}).get("mode"), "0o600",
                   "app: netlog.json copiado para a sessão com 0600")
            exp.ok((netlog_import.get("reload") or {}).get("unchangedAfterInspect") is True
                   and (netlog_import.get("reload") or {}).get("requestsFromInspect") == 32,
                   "app: NetLog importado relê do disco com 32 requisições, sem alterar o arquivo")
        exp.ok(app.get("gui", {}).get("importsScreenshotExists") is True,
               "app: print da sessão importada pela UI capturado")
        evidence.append(
            f"app empacotado: `ScrapeLens.app` {((bundle.get('sizeBytes') or 0) / (1024 * 1024)):.2f} MiB, "
            f"arm64, assinatura {bundle.get('signature')}, binário único, executável `{bundle.get('executableSha256')}`; "
            f"captura ao vivo {live.get('id')} "
            f"({live.get('requests')} req, {live.get('verifiedHeaderEntries')} headers verificados, "
            f"{len(ambiguous)} ambíguas); importação HAR pela UI `{har_import.get('id')}` "
            f"({har_import.get('requests')} req, {har_import.get('protocols')}, "
            f"{har_import.get('counts', {}).get('sourceEvents')} sourceEvents); "
            f"importação NetLog pela UI `{netlog_import.get('id')}` "
            f"({netlog_import.get('requests')} req, {netlog_import.get('protocols')}, "
            f"{netlog_import.get('streamSessions')} StreamSessions, "
            f"{netlog_import.get('counts', {}).get('sourceEvents')} sourceEvents).")
        evidence.append(f"sessões reais do app: `{rel(pathlib.Path(app.get('appSessionsDir', '')))}` "
                        f"· prints `{rel(pathlib.Path(app.get('gui', {}).get('screenshot') or ''))}` e "
                        f"`{rel(pathlib.Path(app.get('gui', {}).get('importsScreenshot') or ''))}`")
        notes.append("Nesta rodada o ciclo Iniciar/Encerrar foi refeito no bundle final "
                     f"(`{EXPECTED_APP_SHA256[:12]}`, compilado em `c2d2b8f`, assinatura local estável, captura multi-alvo); a sessão ao vivo acima é nova, não reaproveitada.")
        notes.append("As importações HAR e NetLog também foram refeitas no bundle final "
                     f"(`{har_import.get('id')}` e `{netlog_import.get('id')}`), agora pela UI: o harness "
                     "escolheu os arquivos por cliques do mouse no painel nativo (o teclado não chega "
                     "ao seletor; na rodada 10 final foi em primeiro plano). "
                     "A verificação é independente da confirmação do usuário: o HAR gravado reproduz a "
                     "sequência método/URL de `har-derived.json` (24 entradas) e o `netlog.json` persistido é "
                     "byte-idêntico ao `h1h2h3.chrome-netlog.json` (SHA-256). Importações repetidas dos mesmos "
                     "arquivos (sufixos `-N` em `har-3dbc391c02a985c5` e `netlog-1704043c442dcbd1`) têm `session.json` idêntico, sem efeito na validação. O NetLog "
                     "isolado avisa `netlog.time_unit_assumed` porque, sem CDP, a unidade do relógio do NetLog "
                     "não pode ser calibrada — a limitação fica explícita na sessão.")
    else:
        exp.ok(False, "app: resumo do ciclo pelo .app ausente (rode tests/capture/app_validate.py)")
    evidence.append(
        f"CLI: Chrome {summary.get('chromeVersion', '?')}; {summary.get('requestCount', '?')} requisições; "
        f"{summary.get('h3StreamSessions', 0)} StreamSessions h3; "
        f"{len(ambiguous) if isinstance(ambiguous, list) else ambiguous} ambíguas; "
        f"redirects={summary.get('redirects', 0)}")
    return exp.rows, evidence, notes


def item_10(ctx: dict) -> tuple[list[dict], list[str], list[str]]:
    """Importação grande: tamanho documentado, tempo e memória medidos."""
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
    exp.ok(size_mb > 5, f"HAR grande gerado ({size_mb:.1f} MiB)")
    notes.append(f"HAR principal: {count:,} requisições, {size_mb:.1f} MiB, sem corpos "
                 "(o caminho patológico com 20 mil anexos é medido à parte).")

    session_dir = large / "session"
    if session_dir.exists():
        shutil.rmtree(session_dir)
    elapsed, rss = measure(["import-har", str(har_path), "--out", str(session_dir), "--label", "synthetic-fixture"])
    session_mb = (session_dir / "session.json").stat().st_size / (1024 * 1024)
    evidence.append(
        f"`/usr/bin/time -l scrapelens-core import-har tests/.work/large/large.har --out tests/.work/large/session` "
        f"→ HAR {size_mb:.1f} MiB, {count:,} requisições, {elapsed:.2f} s, pico {rss / (1024 * 1024):.0f} MiB RSS")
    evidence.append(f"sessão gravada: session.json {session_mb:.1f} MiB")

    elapsed_inspect, rss_inspect = measure(["inspect", str(session_dir)])
    evidence.append(
        f"`/usr/bin/time -l scrapelens-core inspect tests/.work/large/session` "
        f"→ {elapsed_inspect:.2f} s, pico {rss_inspect / (1024 * 1024):.0f} MiB RSS")

    session = inspect(session_dir)
    exp.eq(len(session["requests"]), count, f"todas as {count:,} requisições importadas")
    exp.eq(session["session"]["completeness"]["state"], "complete",
           "importação grande: completeness=complete")
    exp.ok(elapsed < 60, f"import-har abaixo de 60 s ({elapsed:.2f} s)")
    exp.ok(rss < 1536 * 1024 * 1024,
           f"pico do import abaixo de 1,5 GiB ({rss / (1024 ** 2):.0f} MiB)")
    exp.ok(elapsed_inspect < 60, f"inspect abaixo de 60 s ({elapsed_inspect:.2f} s)")
    exp.ok(rss_inspect < 3584 * 1024 * 1024,
           f"inspect com pico abaixo de 3,5 GiB ({rss_inspect / (1024 ** 2):.0f} MiB)")
    notes.append(f"`inspect` materializa o JSON pretty da sessão inteira ({session_mb:.1f} MiB); "
                 f"o pico de {rss_inspect / (1024 ** 2):.0f} MiB vem da serialização, não do parser.")

    # Medição complementar: o pior caso de anexos (20 mil corpos de 20 bytes).
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
            f"complementar, {bodies['requests']:,} anexos de 20 B: import {bodies['seconds']:.2f} s, "
            f"pico {bodies['peakMiB']} MiB, sessão {bodies['sessionMiB']} MiB")
        notes.append("Correção do core confirmada: acima de 256 anexos o `fsync` passa a ser em lote por "
                     f"diretório — {bodies['attachments']:,} anexos de 20 B importam em {bodies['seconds']:.2f} s "
                     "(eram 128 s na bateria anterior). Sessões pequenas mantêm `fsync` por arquivo.")
    else:
        notes.append("Medição complementar com 20 mil anexos não executada nesta rodada "
                     "(`--large-bodies`); o caminho principal está medido acima.")
    return exp.rows, evidence, notes


def python_literals(path: pathlib.Path) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Extrai method/target/headers/body literais do script Python gerado."""
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
    """Executa sob /usr/bin/time -l e devolve (segundos, pico RSS em bytes)."""
    import tempfile

    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as handle:
        stderr_path = pathlib.Path(handle.name)
    try:
        proc = subprocess.run(["/usr/bin/time", "-l", str(CORE), *args],
                              capture_output=True, text=True, timeout=600)
        text = proc.stderr
        if proc.returncode != 0:
            raise RuntimeError(f"core {args} falhou: {text[-500:]}")
        real = re.search(r"([0-9.]+) real", text)
        rss = re.search(r"(\d+)\s+maximum resident set size", text)
        if not real or not rss:
            raise RuntimeError(f"saída de /usr/bin/time não reconhecida: {text[-400:]}")
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
    """MCP (rodada 11): testes dos crates, testes vivos e fluxo completo como cliente stdio."""
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
                     "label": f"MCP {label}: rc={proc.returncode}, {passed} passaram, {failed} falharam"})
        return entry

    run_cmd("cargo test mcp", ["cargo", "test", "--offline"], ROOT / "mcp")
    run_cmd("cargo test capture", ["cargo", "test", "--offline"], ROOT / "capture")
    run_cmd("cargo test recon", ["cargo", "test", "--offline"], ROOT / "recon")
    run_cmd("vivo mcp e2e_live", ["cargo", "test", "--offline", "--test", "e2e_live", "--", "--ignored"],
            ROOT / "mcp")
    for live_name in ("live_pipe_opens_no_port_and_exposed_port_is_loopback_only",
                      "live_planted_symlinks_are_not_followed",
                      "live_port_gap_is_reported_on_all_paths"):
        entry = run_cmd(f"vivo capture {live_name}",
                ["cargo", "test", "--offline", "--lib", f"browser::tests::{live_name}", "--", "--ignored", "--exact"], ROOT / "capture")
        if entry["passed"] != 1 or entry["failed"] != 0:
            rows.append({"ok": False, "label": f"MCP vivo capture {live_name}: esperado 1 teste executado, obtido {entry['passed']}"})
    run_cmd("vivo recon live_e2e.sh", ["sh", "scripts/live_e2e.sh"], ROOT / "recon")

    started = time.time()
    full = subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "aceite" / "mcp_flow.py")],
                          cwd=ROOT, capture_output=True, text=True, timeout=900)
    try:
        flow_json = json.loads(full.stdout)
    except json.JSONDecodeError:
        flow_json = {"ok": False, "checks": [{"name": "saída do fluxo é JSON", "ok": False,
                                             "detail": (full.stdout + full.stderr)[-300:]}]}
    commands.append({"label": "fluxo stdio (cliente independente)", "cmd": "python3 -I tests/aceite/mcp_flow.py",
                     "rc": full.returncode, "passed": flow_json.get("passed"), "failed": flow_json.get("failed"),
                     "seconds": round(time.time() - started, 2), "tail": full.stderr[-400:]})
    rows.append({"ok": full.returncode == 0 and bool(flow_json.get("ok")),
                 "label": f"MCP fluxo stdio: rc={full.returncode}, {flow_json.get('passed')} passaram, "
                          f"{flow_json.get('failed')} falharam"})
    for check_row in flow_json.get("checks", []):
        rows.append({"ok": bool(check_row.get("ok")),
                     "label": f"fluxo: {check_row.get('name')}"
                              + ("" if check_row.get("ok") else f" — {check_row.get('detail', '')}")})

    (out_dir / "flow.json").write_text(json.dumps(flow_json, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    run_json = {"generatedAt": now_iso(), "commands": commands,
                "flow": {"ok": flow_json.get("ok"), "passed": flow_json.get("passed"),
                         "failed": flow_json.get("failed"), "checks": flow_json.get("checks", [])}}
    (out_dir / "run.json").write_text(json.dumps(run_json, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    evidence.append(f"`{rel(out_dir / 'run.json')}` e `{rel(out_dir / 'flow.json')}` (saídas dos comandos e do fluxo)")
    notes.append("Cliente do fluxo: `tests/aceite/mcp_flow.py`, JSON-RPC por stdio em Python, sem o harness Rust; "
                 "servidor HTTP local em 127.0.0.1, Chrome real headless, nada externo.")
    return rows, evidence, notes


ITEMS = [
    (1, "Headers repetidos e cookies preservados nas fixtures", item_1),
    (2, "HAR e NetLog válidos, incompletos e com eventos desconhecidos", item_2),
    (3, "Requisições simultâneas idênticas sem associação falsa", item_3),
    (4, "Redirects e múltiplas tentativas", item_4),
    (5, "Corpos ausentes/truncados/descartados explícitos", item_5),
    (6, "Diff sem perder duplicatas", item_6),
    (7, "Exportação cURL/Python com caracteres especiais", item_7),
    (8, "Sanitização incluindo eventos brutos", item_8),
    (9, "Ciclo real de captura no macOS", item_9),
    (10, "Importação grande com tamanho documentado", item_10),
    (11, "MCP: testes dos crates, vivos e fluxo completo por stdio", item_11),
]


def run_item(number: int, title: str, fn, ctx: dict) -> dict:
    started = time.time()
    try:
        rows, evidence, notes = fn(ctx)
    except Exception as error:  # noqa: BLE001 - o relatório precisa do erro real
        rows, evidence, notes = [{"ok": False, "label": f"exceção: {error}"}], [], []
    elapsed = time.time() - started
    if number == 9 and not rows:
        status = "não testado"
    else:
        status = "aprovado" if rows and all(row["ok"] for row in rows) else "falhou"
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
    """Separa o que foi produzido nesta rodada do que é evidência histórica."""
    lines: list[str] = []
    if capture and pathlib.Path(capture).exists():
        summary = pathlib.Path(capture) / "run.json"
        stamp = ""
        if summary.exists():
            data = json.loads(summary.read_text(encoding="utf-8"))
            stamp = data.get("generatedAt") or data.get("startedAt") or ""
        lines.append(f"Novo nesta rodada: captura CLI `{rel(pathlib.Path(capture))}`"
                     + (f" ({stamp})" if stamp else "")
                     + ", com os dois legs (h1h2 e h3) e o HAR derivado do CDP.")
    if app_run and pathlib.Path(app_run).exists():
        app = json.loads(pathlib.Path(app_run).read_text(encoding="utf-8"))
        live = app.get("capture", {})
        imports = app.get("imports") or {}
        lines.append(f"Novo nesta rodada: sessão ao vivo `{live.get('id')}` iniciada e encerrada "
                     f"pelo bundle final (`{str(app.get('bundle', {}).get('executableSha256'))[:12]}`).")
        historical = [f"{name} `{data.get('id')}`" for name, data in imports.items() if data]
        if historical:
            lines.append("Novo nesta rodada: importações HAR/NetLog pela UI do bundle final ("
                         + ", ".join(historical)
                         + "), com seleção manual do usuário e verificação por SHA-256/sequência contra "
                           "os arquivos preparados em `~/Projects/scrapelens-import-tmp`.")
    return lines


def render(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Relatório de aceite — ScrapeLens MVP")
    lines.append("")
    lines.append(f"Execução: {report['generatedAt']} · binário do core `{report['coreSha256'][:12]}` "
                 f"({report['coreBytes']} bytes) · commit `{report['gitCommit']}`")
    lines.append("")
    lines.append(f"Ambiente: macOS {report['macos']} · {report['machine']} · Python {report['python']}")
    lines.append("")
    lines.append("| # | Critério da spec | Status | Asserções |")
    lines.append("|---|---|---|---|")
    for entry in report["items"]:
        assertions = (f"{entry['passed']}/{entry['passed'] + entry['failed']}"
                      if entry["assertions"] else "—")
        lines.append(f"| {entry['item']} | {entry['title']} | **{entry['status']}** | {assertions} |")
    lines.append("")
    approved = sum(1 for entry in report["items"] if entry["status"] == "aprovado")
    passed = sum(entry["passed"] for entry in report["items"])
    failed = sum(entry["failed"] for entry in report["items"])
    lines.append(f"Resumo: {approved}/{len(report['items'])} critérios aprovados; "
                 f"{passed}/{passed + failed} asserções passaram.")
    lines.append("")
    lines.append("Critérios do pedido: (1) headers repetidos/cookies, (2) HAR/NetLog válidos/incompletos/desconhecidos, "
                 "(3) simultâneas idênticas sem associação falsa, (4) redirects/tentativas, (5) corpos explícitos, "
                 "(6) diff com duplicatas, (7) escaping cURL/Python, (8) sanitização com eventos brutos, "
                 "(9) ciclo real macOS, (10) importação grande medida.")
    lines.append("")
    if report.get("scope"):
        lines.append("Escopo das evidências:")
        lines.append("")
        for item in report["scope"]:
            lines.append(f"- {item}")
        lines.append("")
    for entry in report["items"]:
        lines.append(f"## {entry['item']}. {entry['title']} — {entry['status']}")
        lines.append("")
        if entry["evidence"]:
            lines.append("Evidência:")
            lines.append("")
            for evidence in entry["evidence"]:
                lines.append(f"- {evidence}")
            lines.append("")
        if entry["failed"]:
            lines.append("Falhas:")
            lines.append("")
            for row in entry["assertions"]:
                if not row["ok"]:
                    lines.append(f"- {row['label']}")
            lines.append("")
        for note in entry["notes"]:
            lines.append(f"> {note}")
            lines.append("")
        lines.append(f"Asserções: {entry['passed']} passaram, {entry['failed']} falharam "
                     f"({entry['seconds']:.2f} s).")
        lines.append("")
    lines.append("## Como reproduzir")
    lines.append("")
    lines.append("```sh")
    lines.append("cd /Users/cesar/Projects/scrapelens")
    lines.append("python3 tests/aceite/run_acceptance.py --build-fixtures")
    lines.append("python3 tests/aceite/run_acceptance.py")
    lines.append("tests/capture/run-cycle.sh")
    lines.append("python3 tests/aceite/run_acceptance.py   # usa a última captura registrada")
    lines.append("```")
    lines.append("")
    lines.append("Tudo offline: fixtures sintéticas em `fixtures/aceite/`, domínios `.invalid`; "
                 "o critério 9 usa Chrome com perfil temporário dedicado e servidores locais. "
                 "Nada é publicado e nenhuma telemetria é gerada.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="lista de itens, ex.: 1,3,6")
    parser.add_argument("--capture", help="diretório de execução real de tests/capture/run-cycle.sh")
    parser.add_argument("--app-run", help="run.json do ciclo pelo app empacotado "
                                         "(padrão: tests/results/app-latest/run.json)")
    parser.add_argument("--build-fixtures", action="store_true", help="regenera fixtures/aceite antes de rodar")
    parser.add_argument("--large-bodies", action="store_true",
                        help="mede também o pior caso de 20 mil anexos (lento, ~100 s)")
    args = parser.parse_args()

    if args.build_fixtures:
        subprocess.run([sys.executable, str(ROOT / "tests" / "aceite" / "fixtures.py")], check=True)

    if not CORE.exists():
        print(f"binário do core ausente: {CORE}\nrode: cd core && cargo build --release", file=sys.stderr)
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
        "gitCommit": git.stdout.strip() or "desconhecido",
        "macos": platform.mac_ver()[0] or platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "items": results,
    }
    report["scope"] = evidence_scope(capture, app_run)
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "aceite.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
    REPORT.write_text(render(report), encoding="utf-8")

    for entry in results:
        mark = "OK  " if entry["status"] == "aprovado" else ("SKIP" if entry["status"] == "não testado" else "FAIL")
        print(f"{mark} {entry['item']:>2}. {entry['title']} "
              f"({entry['passed']} passaram, {entry['failed']} falharam, {entry['seconds']:.2f}s)")
        for row in entry["assertions"]:
            if not row["ok"]:
                print(f"       - {row['label']}")
    print(f"\nrelatório: {rel(REPORT)}")
    return 0 if all(entry["status"] != "falhou" for entry in results) else 1


if __name__ == "__main__":
    sys.exit(main())
