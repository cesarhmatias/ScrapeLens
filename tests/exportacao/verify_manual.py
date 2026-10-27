#!/usr/bin/env python3
"""Confere arquivos salvos manualmente no app, sem executá-los ou abrir rede."""
from pathlib import Path
import hashlib
import json
import stat

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'tests/.work/exportacao-manual'
SOURCE=BASE/'source'
expected=json.loads((BASE/'source-manifest.json').read_text())
actual={str(p.relative_to(SOURCE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.rglob('*') if p.is_file()}
assert actual==expected, 'Origem foi alterada'
for ext in ('sh','py'):
    file=BASE/f'native.{ext}'
    assert file.is_file(), f'Arquivo manual ausente: {file}'
    assert file.read_bytes()==(BASE/f'expected.{ext}').read_bytes(), f'Código difere da prévia/core: {file}'
    assert stat.S_IMODE(file.stat().st_mode)==0o600, f'Permissão inesperada: {file}'
dest=BASE/'sanitized'
assert (dest/'session.json').is_file(), 'Sessão sanitizada manual ausente'
assert stat.S_IMODE(dest.stat().st_mode)==0o700
assert not (dest/'cdp-events.jsonl').exists()
assert not (dest/'netlog.json').exists()
for file in dest.rglob('*'):
    if file.is_file():
        assert stat.S_IMODE(file.stat().st_mode)==0o600
        assert b'ONLY_SYNTHETIC' not in file.read_bytes(), f'Marcador não redigido: {file.name}'
print('APROVADO: códigos idênticos, origem intacta, sanitização e permissões corretas')
