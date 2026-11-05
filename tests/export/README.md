# Independent validation of UI export

`cargo test --manifest-path tests/export/Cargo.toml --offline` compiles the
module `src-tauri/src/export.rs` without editing it, in a separate test crate.
The module's nine internal tests are also run; seven new tests cover equivalence
with the core, body states, errors, sanitization and symlinks in ancestor
directories. No exported code is executed and there is no network.

In the initial validation commit, two tests **fail on purpose to record
reproduced bugs**; do not remove them or mark them ignored to approve the
feature. Report: `tests/results/export/REPORT.md`.

## Single manual script (after the fix and a new bundle)

Synthetic fixture without personal data: `python3 tests/export/prepare_manual.py`.
It already exists in `tests/.work/export-manual/source/`; the script refuses
to overwrite it. The credentials are fictitious markers, domain `.invalid`.

1. In the fixed bundle, **Open capture…** → select the folder
   `/Users/cesar/Projects/scrapelens/tests/.work/export-manual/source`.
   Select `captured` (POST `/echo`) and open **Export…**.
2. In cURL, **Copy** and **Save…** to the new path
   `/Users/cesar/Projects/scrapelens/tests/.work/export-manual/native.sh`.
   Repeat in Python in the same directory with the name `native.py`. Do not run anything.
   Cancel one save attempt and check that it does not report a saved file.
3. Close the export. **Export / Sanitize…** → **Save sanitized copy** →
   `/Users/cesar/Projects/scrapelens/tests/.work/export-manual/sanitized`.
   Click **Open sanitized session** and check that the session is labeled
   synthetic and the sensitive values are redacted.
4. Run `python3 tests/export/verify_manual.py` to check the files,
   permissions and SHA of the originals. The real copy must be checked separately,
   by reading the clipboard immediately after each click on Copy, without replacing
   the clipboard with a tool: the script does not prove that action.

The native selectors were left out of the automated proof, due to the block
already observed on NSSavePanel. No foreground attempt was repeated in this
validation. Screenshots of the App harness and its simulated clipboard are not
proof of the real dialog/clipboard.
