#!/usr/bin/env python3
"""Checks files saved manually from the app, without running them or opening the network."""
from pathlib import Path
import hashlib
import json
import stat

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'tests/.work/export-manual'
SOURCE=BASE/'source'
expected=json.loads((BASE/'source-manifest.json').read_text())
# The only ignored file: '.DS_Store' (Finder metadata created when browsing the folder;
# the app never writes to the source). Any other new/changed/missing file fails the check.
IGNORED_FINDER_METADATA = {'.DS_Store'}
actual={str(p.relative_to(SOURCE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.rglob('*') if p.is_file() and p.name not in IGNORED_FINDER_METADATA}
assert actual==expected, 'Source was modified'
for ext in ('sh','py'):
    file=BASE/f'native.{ext}'
    assert file.is_file(), f'Manual file missing: {file}'
    assert file.read_bytes()==(BASE/f'expected.{ext}').read_bytes(), f'Code differs from the preview/core: {file}'
    assert stat.S_IMODE(file.stat().st_mode)==0o600, f'Unexpected permission: {file}'
dest=BASE/'sanitized'
assert (dest/'session.json').is_file(), 'Manual sanitized session missing'
assert stat.S_IMODE(dest.stat().st_mode)==0o700
assert not (dest/'cdp-events.jsonl').exists()
assert not (dest/'netlog.json').exists()
for file in dest.rglob('*'):
    if file.is_file():
        assert stat.S_IMODE(file.stat().st_mode)==0o600
        assert b'ONLY_SYNTHETIC' not in file.read_bytes(), f'Marker not redacted: {file.name}'
print('PASSED: code identical, source intact, sanitization and permissions correct')
