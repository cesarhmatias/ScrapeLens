# 18. Memory when opening large sessions: where the peak is and how to reduce it

Round 12, wave 1. **Measurement only**: no code in `core/`, `mcp/` or `src-tauri/`
was changed. This document measures where the memory peak is when opening a very
large session (the open item "about 2.4 GB", `docs/06-entrega.md`) and proposes
reductions, each with the estimate and what was actually measured.

## 1. How it was measured

- **Synthetic session from a real loopback capture.** `capture/examples/capture_big.rs`
  starts an HTTP/1.1 server on `127.0.0.1` (std, keep-alive) that serves a page
  with `N` `fetch` calls to `/r/<i>` (JSON of ~1,5 KiB, one `Set-Cookie` every 50, varied
  headers). Stable Chrome is driven by `BrowserCapture` (CDP + NetLog
  `Everything`, allowlist only `localhost:<port>`, pipe). Synthetic data
  (`bigfixture-*`); no third-party site; no proxy; no CloakBrowser.
- **Per-stage harness.** `experiments/memoria-sessao/` (independent crate, read-only)
  runs **one stage per process** and prints the peak RSS (`getrusage`
  `ru_maxrss`) and the current RSS (`ps`) at each checkpoint, plus the time. Each stage
  imitates a real consumer:

  | Stage | Who does this today |
  |---|---|
  | `app-open`, `app-open-ipc` | App: `read_session_payload` (`src-tauri/src/commands.rs`): `read_to_string` + `serde_json::Value`, then the payload is serialized to the front end |
  | `lazy`, `lazy-search` | App: search (`cached_session` → `open_session_dir_lazy`) |
  | `import-eager`, `import-eager-pretty`, `import-eager-sanitize` | MCP: first masked call (`registry.rs` `Entry::masked`: `import_session_dir` + `sanitize_bundle`); CLI `inspect` (`import_session_dir` + `json!` + `to_string_pretty`) |
  | `netlog-only`, `cdp-only`, `capture-full`, `capture-write` | `stop_capture` / `import-capture`: CDP and NetLog parse + correlation (+ write) |
  | `validate-value` / `validate-ignored`, `eager-ignored`, `import-eager-stream` | Variants of the **proposal** (§4), measured separately |

- **Machine:** macOS arm64, 64 GiB, Chrome 156, `--release` binaries. The memory
  numbers are **RSS peaks** and repeatable (±1 %); the time numbers vary with the disk cache
  (±30 % on the short stages).
- **Reproduce:**
  ```
  cd capture && cargo build --release --example capture_big
  ./target/release/examples/capture_big /tmp/big20k 20000     # ~5 min
  cd ../experiments/memoria-sessao && cargo build --release
  ./target/release/memoria-sessao import-eager /tmp/big20k   # one stage at a time
  ```
  Note: the measurements were made on a clean snapshot of `HEAD` (`git archive`) because
  the core working tree was being edited by another agent.

## 2. Sizes of the measured sessions

| Requests | `session.json` | `netlog.json` | `cdp-events.jsonl` | `cdp-bodies.jsonl` | Attachments |
|---:|---:|---:|---:|---:|---:|
| 2.002 | 113 MiB | 31 MiB | 9,0 MiB | 2,7 MiB | 2.002 files |
| 5.002 | 283 MiB | 78 MiB | 22,5 MiB | 6,7 MiB | 5.002 files |
| 20.002 | **1.133 MiB** | 313 MiB | 90 MiB | 27 MiB | 20.002 files (18 MiB) |

A captured request weighs **~59 KiB in `session.json`** (pretty) and ~34 KiB in
compact JSON. The reference in `docs/06-entrega.md` (20.000 HAR requests,
`inspect` at 2.415 MiB) comes from a session that is much lighter per request; the same
`inspect` over 20.000 **captured** requests peaks at 9.305 MiB (3,9×), and
the 2.4 GB corresponds to only ~**5 thousand** captured requests (2.611 MiB in
`import-eager-pretty` with N = 5.002). The number of requests alone does not define the
risk: the session format (capture with NetLog and `headerEvidence` versus HAR) weighs
just as much.

Composition of one request (sample of 200, compact JSON, bytes):

| Field | Bytes | Note |
|---|---:|---|
| `attempts` (total) | 25.711 | inside it: `headerEvidence` **16.282**, `requestHeaders` 4.512, `responseHeaders` 1.272 |
| `requestHeaders` (request level) | 4.828 | **copy** of what is already in the attempt |
| `responseHeaders` (request level) | 1.291 | **copy** |
| `cookie`, `requestBody`, `responseBody`, `provenance`, `timings`, `cdp`, `target`, rest | ~2.100 | |
| **Total** | **~33.900** | `headerEvidence` = 48 %; header copies = 18 % |

## 3. Results: RSS peak per stage (MiB)

| Stage | N = 2.002 | N = 5.002 | N = 20.002 | MiB per 1.000 req. (5k→20k) |
|---|---:|---:|---:|---:|
| `lazy` (typed session + lazy attachments) | 121 | 293 | **1.154** | 57 |
| `app-open` (App: text + `Value`) | 648 | 1.615 | **6.453** | 322 |
| `app-open-ipc` (+ serialization to the front end) | 714 | 1.778 | **7.101** | 355 |
| `import-eager` (MCP mask / CLI) | 481 | 1.186 | **4.727** | 236 |
| `import-eager-sanitize` (+ masked copy) | 569 | 1.415 | **5.654** | 283 |
| `import-eager-pretty` (CLI `inspect`) | 1.057 | 2.611 | **9.305** | 606 |
| `capture-full` (parse + correlation) | 715 | 1.784 | **6.993** | 347 |
| `capture-write` (+ `write_session_dir`) | — | — | **9.189** | — |
| *Proposal:* `eager-ignored` | 163 | 399 | **1.576** | 78 |
| *Proposal:* `import-eager-stream` | — | 1.186 | **4.727** | — |

Time (ms): `import-eager` 1.154 / 2.890 / 17.795; `import-eager-sanitize` 1.960 /
6.964 / 25.764; **`capture-full` 2.767 / 20.512 / 248.911**.

The **memory** growth is linear in N. The **`capture-full` time** growth is not:
2.002 → 5.002 requests (×2,5) takes ×7,4 of the time; 5.002 → 20.002 (×4) takes ×12,1.

## 4. Where the peak is (per consumer)

### 4.1 Importing a whole session (`import_session_dir`): 4,7 GiB, of which ~3,1 GiB is a discarded DOM

`import_session_dir` reads the typed `session.json` (1,15 GiB), reads `cdp-events.jsonl` (90 MiB)
and `netlog.json` (313 MiB) in full and, **only to know whether the netlog is valid JSON**,
does `serde_json::from_slice::<Value>(&bytes)` (`core/src/parse/own.rs`, line 42):
a complete DOM that is discarded right afterwards. Measured in isolation on the same
`netlog.json`: **`validate-value` 3.464 MiB versus `validate-ignored` 315 MiB**
(just the bytes), in 2,5 s versus 0,36 s. The 4.727 MiB peak is exactly
1.154 (session) + 90 + 313 (bytes) + ~3.150 (DOM) + 18 (attachments).

### 4.2 CLI `inspect`: double, because of `json!` + `String`

`print_json(&json!({"session": ..., "report": ...}))` converts the typed session into a
DOM (`json!` calls `to_value`) and then serializes it into a 1,16 GiB `String`:
**9.305 MiB** (4.727 from the import + 4.578 from the DOM and the `String`). Serializing a typed
struct directly with `to_writer_pretty` into a stream **adds nothing**: the peak
stays at 4.727 MiB (`import-eager-stream`, measured).

### 4.3 Opening in the App: `Value` costs 5,6 times the typed session

`read_session_payload` does `read_to_string` (1.133 MiB) and `serde_json::from_str::<Value>`:
**6.453 MiB**, versus **1.154 MiB** for the same file typed (`lazy`). The payload
serialized to the front end is 649 MiB; the peak goes to **7.101 MiB** (the command moves the
`Value`, without cloning; a `json!` would clone it and push it to 10,9 GiB, which the real
code does not do). With 20 thousand captured requests the App would need ~7 GiB
just to open, and the webview would still receive 649 MiB of JSON.

### 4.4 Importing a capture (`stop_capture`, `import-capture`): 7,0 GiB and 4 minutes

Breakdown measured at 20.002 requests:

| Part | Peak | Time |
|---|---:|---:|
| NetLog parse (`import_netlog`) | 4.662 MiB | 4,6 s |
| CDP parse (`import_capture` without NetLog) | 1.966 MiB | 2,7 s |
| **CDP×NetLog correlation** (the rest of `capture-full`) | — | **~241 s** |
| Whole `capture-full` | 6.993 MiB | 248,9 s |
| + `write_session_dir` | 9.189 MiB | 263 s |

- **Time:** `find_candidates` (`core/src/correlate.rs`, line 220) walks **all**
  the pairs (CDP attempt × NetLog attempt) for each CDP attempt; for each pair it
  builds `format!("netlog-r{:04}-a{}")` and, in `score_candidate`, calls
  `canonical_url` twice. That is 20.002 × 20.029 ≈ **4,0 × 10⁸ pairs**; 248,9 s ÷
  4,0 × 10⁸ = **0,62 µs per pair** (with N = 5.002: 20,5 s ÷ 2,5 × 10⁷ = 0,8 µs): this is the
  quadratic cost. A 12 s `sample` with N = 5.002 confirms it: `attach_netlog` →
  `canonical_url` + `format!` + `malloc/free` dominate.
  This is also what `stop_capture` runs **inside the MCP server and the App** when
  ending a large capture: 4 minutes frozen and ~9 GiB.
- **Memory:** the 4,66 GiB NetLog peak is, as in 4.1, a DOM (`Value`) of
  3,1 GiB from the 313 MiB file, before it becomes the model.

### 4.4b First masked MCP call

`import-eager` (4.727) + `sanitize_bundle` over the reference (+927 MiB of masked
copy) = **5.654 MiB** peak, and the masked copy (~1,1 GiB) stays retained in the
cache for the session. The cost of `sanitize_bundle` is ~14 s with 20 thousand requests.

## 5. Reduction proposal, with estimate

Ordered by (gain ÷ effort). **Measured** = the numbers come from the harness; **estimated** =
extrapolation from the measured numbers, to be confirmed when the item is implemented.

| # | Change | Where | Gain | Effort | Risk |
|---|---|---|---|---|---|
| P1 | Validate `netlog.json` as a stream: `serde_json::from_slice::<serde::de::IgnoredAny>` instead of `Value` | `core/src/parse/own.rs:42` | `import-eager` **4.727 → 1.576 MiB (−67 %)**, 17,8 → 9,2 s. **Measured** (`eager-ignored`: same work without the DOM). Also applies to the masked MCP (5.654 → ~2.500 MiB, **estimated**: 1.576 + 927 of the copy) | 1 line + test | none: same validity verdict |
| P2 | `inspect` and other `print_json`: typed struct + `to_writer_pretty` as a stream instead of `json!` + `String` | `core/src/bin/scrapelens-core.rs` | `inspect` **9.305 → 4.727 MiB (−49 %)**; with P1 **1.576 MiB (−83 %)**. **Measured** (`import-eager-stream`) | small | none |
| P3 | Index the NetLog before correlating: `HashMap<(lowercase method, canonical_url), Vec<(request, attempt)>>`, with `canonical_url` and the id computed once per attempt. The candidate requires equal method and canonical URL (`score_candidate` returns `None` otherwise), so the set of candidates is **identical** | `core/src/correlate.rs` `find_candidates` | `capture-full` from **249 s to ~12 s** at 20 thousand requests (**estimated**: 7,4 s of measured parse + linear correlation at ~1 µs per attempt); `stop_capture` stops freezing for minutes. Memory barely changes | medium | low: the output must be equal (existing correlation tests + comparison of `session.json` before/after) |
| P4 | Streaming NetLog parse: a `Visitor` over the `events` array, keeping only the fields used, instead of `Value` | `core/src/parse/netlog.rs` | `import_netlog` peak **4.662 → ~1.500 MiB** (**estimated**: removes the 3.150 MiB DOM measured in `validate-value`); `capture-full` 6.993 → ~3.800 MiB. **Measured in round 16 (§8): `netlog-only` 4.759 → 1.615 MiB; `capture-full` 7.110 → 4.200 MiB** | large | medium (the parser is large; requires the corpus and `check_multi_target`) |
| P5 | App: do **not** build a `Value` or send the whole session to the front end. Typed parse (`SessionV1`, 1.154 MiB, 5,6× smaller) and a paginated/virtualized list: the command returns the per-request summary (~100 to 200 B) and the detail on demand | `src-tauri/src/commands.rs` + front end | opening **7.101 → ~1.200 MiB (−83 %)**, **estimated** (typed measured at 1.154 MiB; summaries for 20 thousand rows ≈ 4 MiB) and 649 MiB less over IPC | medium/large (changes the command contract) | medium |
| P6 | Write a compact `session.json` when it passes a limit (e.g. 50 MiB); keep pretty below | `core/src/store.rs` | file **1.133 → ~650 MiB (−43 %)** (**measured**: it is the `wireMiB` of 649); `app-open` and `read_to_string` drop in the same proportion as the text (−480 MiB at the `app-open` peak) | small | low (editor readability only for huge sessions) |
| P7 | `sanitize_bundle` consuming the bundle (or sanitizing in place) instead of copying | `core/src/export/sanitize.rs`, `mcp/src/registry.rs` | −927 MiB at the masked peak and in the memory retained per session (**measured** as the `import-eager-sanitize` delta) | medium | low |
| P8 | Schema: do not repeat `requestHeaders`/`responseHeaders` at the request level when there is a single attempt; store `headerEvidence` only as the difference between sources | `SessionV1` model (v2) | ~−65 % of the size per request (59 → ~20 KiB pretty), **estimated** from the composition in §2 (48 % + 18 %); typed and DOM drop together | large (schema version) | high (compatibility, all consumers) |

**Combined projection (20 thousand captured requests, estimated from the measurements):**

| Consumer | Today | P1+P2 (+P7) | + P3/P4 | + P5/P6 |
|---|---:|---:|---:|---:|
| `inspect` (CLI) | 9,3 GiB | **1,6 GiB** | — | — |
| MCP 1st masked call | 5,7 GiB | **~2,5 GiB** (P1) / ~1,6 (with P7) | — | — |
| `stop_capture` (imports the capture) | 7,0 GiB, 249 s | 7,0 GiB, 249 s | **~3,8 GiB, ~12 s** | — |
| Open in the App | 7,1 GiB | 7,1 GiB | 7,1 GiB | **~1,2 GiB** |

Recommendation: **P1, P2 and P3 first**. They are small, measured or with a clear
mechanism, and they solve the worst symptom for MCP users: `stop_capture` on a large
capture stops taking minutes (P3) and the masked open drops to a third
of the memory (P1). P5 is what fixes the App, but it changes the command contract and the
front end.

## 6. Limits of what was measured

- The load is synthetic and uniform (same body size, 1 host, HTTP/1.1, no
  redirects or WebSocket); real sessions have larger headers and less
  URL repetition (which lowers the cost of correlation without an index, but not
  the memory cost).
- `ru_maxrss` measures the peak of the whole process, including the allocator; the RSS
  retained after the peak is lower (and macOS returns pages gradually).
- The time of short stages depends on the disk cache; that of `capture-full` does not.
- Estimates for P3 to P8 were not implemented **in this round** (forbidden then); P1 and P2 have
  the variants measured in the harness, but using the current core API, not a patch. After that, P1,
  P2, P3, P4, P6 and P7 were implemented and measured (§7 and §8), and P5 was done by the App.
- The Chrome capture itself (the `capture_big` process) did not have its memory measured
  separately; `stop` runs the same import as `capture-write` (9,2 GiB peak).

## 7. Result after the fixes (round 13, wave 1)

Implemented in `core/` and `mcp/` (one commit per item): **P1** (`87bd164`: validation of
`netlog.json` and of the CDP lines as a stream, without a DOM, with the same verdict as `Value`, including the
recursion limit of 128 levels: `IgnoredAny` does not work because it skips it), **P2** (`752230e`:
`inspect` and `assess` write as a stream with a borrowed struct; output byte-for-byte equal), **P3**
(`4d82e36`: index by (lowercase method, canonical URL) and by NetLog source id; explicit
keys also indexed), **P6** (`2550041`: compact `session.json` when the indented JSON passes
50 MiB) and **P7** (`b438945`: `sanitize_bundle_owned` consumes the bundle and sanitizes in place; CLI
`sanitize` and the MCP registry use it). **P4** was left for round 16 and is measured in §8 (`ad4f5c1`);
**P5** was done by the App and is also measured (`docs/19-contrato-app.md`: 1.161 MiB when opening the
20 thousand session). **P8 was not done.**

**P3 requirement, identical output.** `core/tests/correlation_identity.rs` imports the 29 captures and
versioned fixtures (HTTP/1.1, h2, h3, contracts, multi-target, `src-tauri/evidence`, adapters) and
checks the indented `session.json` and the attachments, byte for byte (64-bit FNV-1a + size), against the
hashes recorded BEFORE the change (commit `aefacc9`); it passes equally after. One more unit test in
`correlate.rs` shows that the index never discards a pair that the scan of all pairs would accept,
and `tests/aceite/check_multi_target.py` (real multi-target capture) passed.

**Measured after** (same synthetic sessions as §2, same harness, `--release`, RSS peaks in MiB;
the new stage `import-eager-sanitize-owned` was added to the harness; `inspect` is the binary
`scrapelens-core inspect` measured with `/usr/bin/time -l`). N = 2.002 was not measured again.

| Stage | N = 5.002 before → after | N = 20.002 before → after | Time at 20.002 |
|---|---:|---:|---:|
| `import-eager` (MCP mask / CLI) — P1 | 1.186 → **400** | 4.727 → **1.580** (−67 %) | 17,8 s → 10,1 s |
| `inspect` (CLI) — P1+P2 | 2.611 → **419** | 9.305 → **1.656** (−82 %) | n/m → 11,5 s |
| MCP 1st masked call — P1+P7 (`import-eager-sanitize-owned`) | 1.415 → **415** | 5.654 → **1.649** (−71 %) | 25,8 s → 22,8 s |
| `capture-full` (parse + correlation) — P3 | 1.784 → 1.783 | 6.993 → 7.110 | **20,5 s → 2,2 s** (5k); **248,9 s → 9,3 s** (20k) |
| `capture-write` (+ `write_session_dir`) — P3+P6 | — → 1.903 | 9.189 → **7.580** | 263 s → **16,2 s** |
| `netlog-only` (NetLog parse; P4 pending in this round) | — → 1.194 | 4.662 → 4.759 | 4,6 s → 5,0 s |
| `session.json` written (5.002 req.) — P6 | 283 MiB → **162 MiB** (−43 %) | 1.133 MiB → ~650 MiB (estimated, same proportion) | — |

The `netlog-only`, `capture-full` and `capture-write` rows of this table are the state **before
P4**; the numbers with P4 are in §8.

Reading:

- The **time** to import a large capture dropped linearly: `capture-full` at 20 thousand requests
  from ~4 min to 9,3 s (27×); `stop_capture` in the MCP and the App stops freezing for minutes. The
  memory of `capture-full` did not change in that round (the NetLog DOM, P4, remained: 4,7 GiB for the
  parse alone); with P4, §8 shows 4,2 GiB and 8,1 s.
- The memory of `import-eager`, `inspect` and the MCP 1st masked call dropped to ~1,6 GiB (−67 to
  −82 %): it is the cost of the typed session (1,15 GiB) plus the CDP and NetLog bytes, without the DOM or the
  masked copy. The estimate in §5 (≈1,6 GiB) was confirmed; the one for the masked MCP (≈1,6 GiB with P7) too.
- `capture-write` dropped from 9,2 to 7,6 GiB and from 263 to 16 s; what remains is the NetLog parse
  (P4), resolved in round 16 (§8).
- Variation: ±1 % in memory; the short times vary with the disk cache (±30 %).
- Reproduce: `cd experiments/memoria-sessao && cargo build --release && ./target/release/memoria-sessao
  <stage> /tmp/big20k` (one stage per process); `inspect`: `/usr/bin/time -l
  core/target/release/scrapelens-core inspect /tmp/big20k > /dev/null`.

**After P4 and P5 (20 thousand captured requests, measured):**

| Consumer | Before (round 12) | P1–P3/P6 (round 13) | With P4/P5 |
|---|---:|---:|---:|
| `inspect` (CLI) | 9,3 GiB | **1,6 GiB** | 1,6 GiB (P4 does not apply to `inspect`) |
| MCP 1st masked call | 5,7 GiB | **1,6 GiB** | 1,6 GiB |
| `stop_capture` (imports the capture) | 7,0 GiB, 249 s | **7,1 GiB, 9,3 s** | **4,2 GiB, 8,1 s** (§8; with the write, 4,6 GiB, 17,1 s) |
| Open in the App (P5) | 7,1 GiB | 7,1 GiB | **1,16 GiB** (`docs/19-contrato-app.md`) |

## 8. Round 16: P4 measured (streaming NetLog parser)

P4 was implemented in `core/` in commit `ad4f5c1`: the NetLog `events` array is read by a
`Visitor` that keeps only the fields used, without building the `serde_json::Value` of the whole file.
The output is identical: `core/tests/correlation_identity.rs` still has the **29/29 hashes** equal
to those recorded before (reference `aefacc9`), and the NetLog corpus and the Core `check_multi_target`
passed.

Measurement redone in this round to check the Core's numbers: same sessions as §2
(`/tmp/big5k` and `/tmp/big20k`), same harness, `--release`, one stage per process, RSS peak
in MiB. The two runs agree within 1 %.

| Stage | N = 5.002 before → P4 | N = 20.002 before → P4 | Time at 20.002 |
|---|---:|---:|---:|
| `netlog-only` (NetLog parse) — **P4** | 1.194 → **407** (−66 %) | 4.759 → **1.615** (−66 %) | 5,0 s → **3,5 s** |
| `capture-full` (parse + correlation) — P3+P4 | 1.783 → **1.055** (−41 %) | 7.110 → **4.200** (−41 %) | 9,3 s → **8,1 s** |
| `capture-write` (+ `write_session_dir`) — P3+P4+P6 | 1.903 → **1.229** (−35 %) | 7.580 → **4.629** (−39 %) | 16,2 s → ~16 s |

Reading:

- **P4 removed the NetLog DOM.** `netlog-only` at 20 thousand dropped from 4.759 to 1.615 MiB (−66 %):
  the ~3,1 GiB DOM measured in §4.1/§4.4 no longer exists, and what remains is the typed model (~1,15
  GiB) plus the file text and the transient parse structures. The estimate in §5 (~1.500
  MiB) was 8 % below the measured value.
- **Against the round 12 baseline**, `capture-full` at 20 thousand went from 6.993 to 4.200 MiB
  (−40 %) and `capture-write` from 9.189 to 4.629 MiB (−50 %); `capture-full` at 5 thousand dropped 41 %, the
  same percentage as the large file — the gain scales with the NetLog, not with the number of requests.
- **Time:** the streaming parse is also faster (`netlog-only` 5,0 → 3,5 s; `capture-full`
  9,3 → 8,1 s). `capture-write` remains dominated by the write (14,7 s of the ~17 s), so the total
  time does not change noticeably (15,9 s in the Core run, 17,1 s in this one, within the
  ±30 % disk cache variation already recorded in §7).
- **P5 (App), measured:** opening the 20 thousand session in the App dropped from 7.108 to **1.161 MiB** (−84 %)
  with the typed path + paginated list, and what goes to the front end dropped from 681 MB to ~5,4 MB
  (`docs/19-contrato-app.md`, `src-tauri/examples/mem_open.rs`). It is the "Open in the App" row of the
  table in §7.
- **What is left:** the floor is now the typed session (~1,15 GiB at 20 thousand) and the ~650 MiB
  `session.json` written by P6. The next memory item is **P8** (schema, ~−65 % of the size per
  request), which requires a new schema version and was not done.

Reproduce (one stage per process):

```
cd experiments/memoria-sessao && cargo build --release
./target/release/memoria-sessao netlog-only   /tmp/big20k
./target/release/memoria-sessao capture-full  /tmp/big20k
./target/release/memoria-sessao capture-write /tmp/big20k
```
