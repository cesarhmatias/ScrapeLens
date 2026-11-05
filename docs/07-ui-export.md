# Next round — export through the interface

## Authorized scope

Request of 2026-10-27: move on to the proposed next step, cURL/Python export
with preview/copy/save and export of a sanitized session. Reuse the existing
core. No CDP body capture, redesign or implementation of the DETRAN
requirements in this round. Do not publish or run exported code.

## Ownership

- App: app/, src-tauri/ and screenshot evidence of the feature.
- Tests: tests/ and fixtures/, after the implementation.
- Leader: docs/, README and review of the delivery.
- Core: no changes planned; if blocked, report before changing.

## Functional contract

1. Export action on the selected request of the open persisted session.
   cURL/Python generated in Rust from import_session_dir, requestId and
   the body attachment; call export::curl::to_curl and python::to_python with
   ExportOptions::default. Do not recreate an exporter in the frontend nor trust
   edited/normalized UI text as a source.
2. Text-only preview; cURL/Python toggle, copy via clipboard and save
   through a native dialog. Show warnings, skipped_headers, body_included/body_note
   returned by the core. An unavailable body state does not become an empty body
   presented as complete. Do not promise identical TLS/fingerprint/HTTP2/HTTP3.
3. Concise notice: the export may contain the session's cookies/credentials; never
   run code nor do replay/network. A demo without a persisted folder may be
   disabled with an explicit reason; do not produce a fictitious result.
4. Sanitize the whole session through its own action: sanitize_bundle with default options
   (keep_raw_events=false), preview of redaction counts, warnings and omitted
   attachments; save through a native destination choice into a new/empty, private folder.
   Preserve the origin and never reuse a folder with unsanitized data.
   Use SanitizedExport::write_to and the core's conservative policy.
5. The new destination must be distinct from the origin; refuse overwriting and symbolic
   links at the destinations of the new integration. Code saved with permission 0600;
   sanitized session 0700/0600. Cancellation neither writes nor alters the session.
   Heavy operations off the UI thread, with busy/actionable error.
6. The preview must match the copied/saved content; prevent silently exporting
   another request if the selection changes while generating/saving.
   The original session is never modified. No credentials in logs/reports.

## Validation of the round

Useful tests on the bridge: nonexistent request, missing folder, available body
vs unavailable, escaping, occupied destination/origin/symlink, cancellation and
preservation of the origin. Reuse the core's tests; do not duplicate the implementation.
Real flow on the bundle: open persisted session, select request, cURL/Python
preview, copy and compare with the saved file, sanitize/open the new session
with synthetic markers and verify absence in all files. New
ad-hoc signed bundle and specific hash. Record facts vs untested.

## Preserved base

Product base 7d25bc7, last acceptance 282/282 (77c32a7). There is a prior modification
in tests/results/app-latest/testserver/app-20261027/h1.jsonl at the start of this
round: preserve it, do not include it in an export commit without understanding its origin.
The outputs/ux-review proposal remains isolated. Conventional Commits for each
completed delivery, with no push/release/publication.

## Result of the round — 2026-10-27

Completed. arm64 ad-hoc bundle, SHA-256 of the executable
`9c04b98b30b3d6451ee53fa5eee589aaba0cd4e5d3185894e39facb0335bdbe5`
(source and signature in `src-tauri/PACKAGING.md`).

- Implementation (App): `eaf5471`…`2c6765e`; no changes to the core.
- Independent validation (Tests, `a83d985`/`ffc7fc1`): 14/16 on the first
  pass. F1/F2 failed: a destination that went through a symbolic link in an ancestor folder
  was accepted. Fixed in `16015a1`: any link in the destination
  chain is refused, except the system aliases `/var`, `/tmp` and `/etc`
  when they point to `/private/...`. Regressions: 16/16.
- The native proof revealed that minimal v1 sessions, accepted by the core, froze the
  UI (`s.attempts.map`). Fixed in `0d4dbab`: the adapter applies the same
  defaults as the core, with its own test.
- Native proof on bundle `9c04b98b…` (leader, at the user's request; native dialogs
  operated in the foreground), with file verification by Tests
  (`adc56ab`): open session, save cURL and Python (0600, identical to the preview),
  cancel without writing, copy identical to the preview, sanitize into a new folder
  0700/0600 with no raw events or markers, reopen the sanitized one with a redacted URL,
  origin byte-identical. Report: `tests/results/export/REPORT.md`;
  screenshot `docs/screenshots/24-export-sanitized-open.png`.

Open items and limitations: directory races not tested; sanitization remains
heuristic; export does not replicate TLS/JA3/JA4/HPACK; sessions labeled
`synthetic-fixture` show the demonstration title instead of the id (cosmetic).
Next rounds of the roadmap: CDP bodies and payload search, DETRAN case end to
end, distribution (licenses, notarization, Intel).
