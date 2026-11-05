# detran-pb — reference-case fixture (real shape, synthetic values)

Acceptance case: reconstruction of the DETRAN-PB session described in
`docs/05-case-reference-detran.md`. This fixture exists for the tests of
**import, body search, grouping protection × application, dynamic fields and
CDP×NetLog correlation**.

**Label:** `sanitized-shape-real-case` — the *shape* of the flow came from the
real case; all values are synthetic and **no byte of the original HARs was
copied** into the repository.

## Files

| File | Contents |
|---|---|
| `detran-pb-sanitized.har` | 13 entries: entry → NatLogon → SIM1000X → on_interceptor → VES0009X → cmd_filtro → cmd_consultar_placa → cmd_nova → cmd_consultar_placa |
| `detran-pb-blocked.har` | 3 block entries: 200 without XML/STAMP, Connector without model, 403 |
| `detran-pb.cdp.jsonl` | 47 synthetic CDP events (`requestWillBeSent`, `requestWillBeSentExtraInfo` only on the POSTs, `responseReceived`, `loadingFinished`) |
| `detran-pb.netlog.json` | 52 NetLog events in the format of `fixtures/acceptance` (URL_REQUEST, headers sent/received, stream job) |
| `manifest.json` | expected flow, STAMP chain, search cases, ambiguity, dynamic/static field lists |
| `build_fixtures.py` | deterministic generator (fixed clock 2026-10-26T23:00Z) |
| `validate.py` | checks structure, flow, sizes, search, ambiguity and absence of real markers |

```sh
python3 fixtures/detran-pb/build_fixtures.py   # regenerates
python3 fixtures/detran-pb/validate.py         # OK: 13 HAR entries, 8 Connector posts...
```

## What the shape preserves

- Endpoints and pages: `/servlet/easynat-app?op=S37`, `/cisnatural/NatLogon.html`,
  `/UIC-SERVICOS/SIM1000X.html`, `/UIC-SERVICOS/VES0009X.html`,
  `POST /servlet/Connector`. Protection noise: `GET /TSPD/?type=18`.
- Form: `SESSIONID`, `PAGEINITPARAM`, `XML`, (`ERRORMESSAGE`), `STAMP` —
  `STAMP=INIT` at initialization and the last STAMP in the other calls.
- Textual protocol in the `XML` field (it is not XML): lengths in UTF-16 units,
  request opcodes `i/v/p/x` and response opcodes `l/p/q/z/w/b/c/s/k/x`.
  The initial `delta` is `inittini`; the responses carry a new delta at each step.
- Events: `on_interceptor` (S37 in item 1), `cmd_filtro`, `cmd_consultar_placa`,
  `cmd_nova`, `cmd_consultar_placa` (second plate).
- Full body × delta: the first query carries `v_situacao_atual`
  (`Veículo Apreendido`) and history; the second **omits** `v_situacao_atual`,
  keeps `vp_situacao_atual=true` and the `situacao_rows.items[...]` rows.
- Two queries with the **same URL and method**, told apart only by body/STAMP —
  an ambiguity case for correlation (do not associate by URL).
- HTTP 200 that is **not** application success (challenge/`request rejected`).

The Connector responses were checked against the case's reference decoder
(`decode_stream`): they decode in order, with the expected fields and delta.
The decoder is part of neither this fixture nor the MVP.

## Synthetic values

| Item | Value |
|---|---|
| `SESSIONID` | `CSAN00000_000000000001` (22 characters, same shape) |
| `m_currentProcessId` | `100000000001` |
| plates | `TST0T00`, `TST0T01` (Mercosul format, nonexistent by the `TST` convention) |
| STAMP | `INIT`, `2001`..`2008` |
| delta | `inittini`, `DLTA0001`..`DLTA0008` |
| cookies | `TS01a1b2c3=0189…f0` and `JSESSIONID=SYNTH…0001` |
| server IP | `198.51.100.10` (TEST-NET-2) |
| Natural model | `SA90001_CSAN00000`, `SA90002_…`, `SA90003_…` |

Absent by construction: real cookies/TS*, real SESSIONID, third-party plates,
real STAMP/delta tokens, original HTML, real IP, personal data, `Authorization`.
The generator refuses any value coming from the HARs; `validate.py` fails if a
real marker appears (`CASA`, `NUPP`, `082b79`, HAR names, etc.).

## How to use in tests

- **Body search**: `cmd_consultar_placa` must find entries 10 and 12;
  `cmd_nova` finds 11; `on_interceptor` finds 6. Search by URL is insufficient
  for the queries.
- **Protection × application**: `/TSPD/` is noise; the Connector is the
  application. A 200 response with `challenge` and without `XML`/`STAMP` is not success.
- **Dynamic fields**: `SESSIONID`, `STAMP`, `delta`, stream timestamps and
  `pageInitParam` change between sessions; endpoints, events and field names do not.
- **Correlation**: CDP `requestId` ≠ NetLog `source.id`; NetLog `time` is in
  **tick milliseconds** (Chrome 156 convention on this machine) and the wall
  clock is `timeTickOffset + time`. The two queries have the same URL, so the
  association needs body/time and must be able to declare ambiguity.
  `headersText` of `requestWillBeSentExtraInfo` preserves the header order; the
  CDP `headers` object does not.
- **Timeline**: `cmd_nova` between queries is visible as its own step.

## Limits

- Does not reproduce TSPD, CAPTCHA, real protection cookies, TLS/JA3 or the
  order of headers sent (the fidelity matrix covers that with `testserver/`).
- Paths and event names are those of the case; any resemblance in values is a
  coincidence of formats (plate, STAMP), not real data.
- Static fixture: do not run the endpoints or navigate to the real domain.

## CDP bodies (round 4, docs/08-bodies-search.md)

Marked as **sanitized from a real case** (real shape, synthetic values):

- `detran-pb.cdp-bodies.jsonl` (§1 format): the 8 form-urlencoded POST bodies,
  13 responses — 11 `captured` (one in binary `base64`: TSPD, entry 1),
  1 `truncated` (NatLogon, entry 2, `originalSize` 415) and 1 `unavailable`
  (entry 12, last query; it does not produce a value used later;
  "No resource with given identifier found"). `requestId` =
  `1001.1`…`1013.13` (index+1), `attemptIndex` 0 (no redirects in this flow).
- `detran-pb-edge.cdp.jsonl` + `detran-pb-edge.cdp-bodies.jsonl`: scenarios
  in the `testserver/` format (302 with attempt 0 `unavailable`, 307 with a body
  in both attempts, JSON, binary base64, already decoded gzip, 6 MiB `truncated`
  with `originalSize` 6291456, 204 `empty` with evidence).
- Expected search cases: `manifest.json` → `bodies_search_cases` and `bodies`.
  Automatic acceptance: `python3 tests/acceptance/check_bodies_search.py <session>`.

## Origin labels (Core d9aba1c)

Every import of these fixtures passes `--label synthetic-fixture`, so the app
does not show them as a real session. Expected labels in `session.labels`:
`import-capture` → `["capture-import","synthetic-fixture"]`; `import-har` →
`["har-import","synthetic-fixture"]`; `import-netlog` → `["netlog-import","synthetic-fixture"]`.
`tests/acceptance/check_bodies_search.py --import-fixture` and `run_acceptance.py`
assert this on every import.

## 2nd capture (B) and origin chain (round 5, docs/09-chain-comparison.md)

- `fixtures/detran-pb-b/` (`python3 fixtures/detran-pb/build_fixtures.py b`):
  same 13-step flow, same pages, models and constants; **they differ** in
  SESSIONID (`…0002`), processId, TS*/JSESSIONID cookies, STAMP (3001…3008),
  delta (`DLTB…`), time (+1 h) and plates `TST0T02`/`TST0T03`.
- Value chain (A and B, checked by `validate.py`): SESSIONID originates in the
  easynat-app HTML (`m_currentSessionId`); STAMP and delta come from the
  previous POST's response; the JSESSIONID comes from the easynat-app's
  Set-Cookie (the 1st request sends no cookie) and the TS* cookie only from the
  Set-Cookie of `/TSPD/` (protection). Fixture A was adjusted for this (before,
  all responses repeated both Set-Cookies and all requests sent a cookie);
  counts (13/8/47/52) and the core tests remain the same.
- Negative case §4.3: header `x-page-seq: 3` on the POSTs coincides by chance
  with `x-seq-hint: 3` from the `cmd_filtro` response (value <8, different
  name: it is not an origin).
- Expectations: `manifest.json` → `chain_compare` (origins §4.1, chain,
  comparison §4.2, sanitized §4.4). Acceptance:
  `python3 tests/acceptance/check_chain_compare.py` (fails until Core delivers
  `origins|chain|compare`; the JSON format adapter is tolerant and must be
  adjusted to the final contract).

## Round 5 review (timing, confidence and causality)

- **Sequential times**: each step starts 250 ms after the previous one and each
  response ends at start+100 ms (CDP `loadingFinished`, NetLog in ms and HAR
  consistent), so a producer always ends before the consumer. The NetLog
  previously had offsets inherited from microseconds (`+90000`); now they are
  `+1/+2/+90` ms.
- **Expectations by rule**: cookie-jar and same-field (STAMP) = `observed origin`/strong;
  SESSIONID and delta (value-match) = `possible origin (value-match)`/medium;
  in compare `get at runtime (origin: …)`; confidence of the chain
  step = strong if any reason is strong (r0001 strong via JSESSIONID).
  (These quoted labels are the ones in `manifest.json` and are kept as data.)
- **Causality regression** (`detran-pb-edge`, manifest `chain_compare.edge_regressions`):
  `2008.8` (slow producer, ends after the start of `2009.9`) → `slow_token` without
  origin; `2010.10`→`2011.11` (sequential) → strong same-field origin.
