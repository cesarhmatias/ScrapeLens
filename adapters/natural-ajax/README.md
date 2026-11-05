# scrapelens-natural-ajax

Adapter for the **Natural for Ajax** protocol (`XML` field of the Connector) for
ScrapeLens. It lives outside the core: it depends on `scrapelens-core` only through
the `ProtocolAdapter` trait.

- `grammar`: grammar independent of the trait (lengths in UTF-16 units,
  linear parsing, error instead of panic). Request: `i`/`v` + widths
  `2,2,2,2,2,3,5,1`, `p` (2/5) and `x` (2). Response: `l s p q z w b c k x`.
- `NaturalAjax`: implements the trait. Parts: `op` (raw structure), header
  `sid pid model page event` (value) and `empty dummy flag` (structure),
  `p.<name>` (value), `s.<key>` (name), `delta`. Length prefixes are never
  parts: `encode` recalculates them.
- `PYTHON_ENCODER` / `PYTHON_DECODER`: the encoder (and the decoder used to
  extract parts from responses) that the priming script includes, equivalent
  to the Rust code (tested side by side).
- `natural-core`: wrapper around the core CLI with the adapter registered
  (`export-priming`; the other subcommands go to `scrapelens-core`).
  The adapter only applies with `--adapter natural-ajax`; without the flag, the
  script takes the snippet path (control). **Strict** default for the adapter's parts: literal only for the Structure role,
  proven constant (≥ 2 requests in the session or static context),
  navigation or *UI constant* (booleans and numbers of up to 4 characters with
  sign/decimal: `true`, `-180`, `2.0`), or a command/resource name from the
  header (`event`, `page`, `model`, such as `cmd_filtro`) that does not look like
  an identifier nor PII; any other part without an origin becomes a
  required parameter, and a value whose origin is in another round is never a literal.
  `--lenient-parts` (intermediate): only a value that looks like an identifier,
  secret or timestamp (UUID, hex, ULID, base64, timestamp,
  mixed alphanumeric) becomes a parameter. `adapter-roundtrip <session>` prints
  `{"fields", "divergences", "divergenceKinds", ...}` (aggregates only).

Tests: `cargo test` (round-trip on the fixtures and, if they exist, on the 3 real
HARs, aggregates only), `python3 scripts/prove_strict.py` (detran-sim in `strict`
mode, 127.0.0.1 only).
