#!/usr/bin/env python3
"""Cria sessão SINTÉTICA privada e arquivos esperados; não executa exportações."""
import json
import hashlib
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'tests/.work/exportacao-manual'
SOURCE = BASE / 'source'

def main():
    if SOURCE.exists():
        raise SystemExit(f'Origem já existe; preserve-a: {SOURCE}')
    SOURCE.mkdir(parents=True, mode=0o700)
    (SOURCE / 'attachments').mkdir(mode=0o700)
    body = b'{"password":"MANUAL_BODY_ONLY_SYNTHETIC","public":"ok"}'
    def header(name, value):
        return dict(name=name, value=value, source='capture', method='synthetic-fixture', verification='unverified')
    session = {
        'schemaVersion': 1,
        'session': {'id':'synthetic-export-validation', 'startedAt':'2026-10-27T15:00:00Z', 'labels':['synthetic-fixture'], 'completeness':{'state':'complete','counts':{}}},
        'requests': [{
            'id':'captured','method':'POST','url':'https://fixture.invalid/echo?sid=MANUAL_URL_ONLY_SYNTHETIC','protocol':'h1','status':200,
            'requestHeaders':{'headers':[header('Authorization','Bearer MANUAL_AUTH_ONLY_SYNTHETIC'),header('Cookie','sid=MANUAL_COOKIE_ONLY_SYNTHETIC'),header('Content-Type','application/json')]},
            'requestBody':{'state':'captured','attachment':'request.json','contentType':'application/json','bytes':len(body)}
        }]
    }
    for path, data in [(SOURCE/'session.json',json.dumps(session,indent=2).encode()),(SOURCE/'attachments/request.json',body),(SOURCE/'cdp-events.jsonl',b'{"marker":"MANUAL_RAW_ONLY_SYNTHETIC"}\n')]:
        path.write_bytes(data)
        path.chmod(0o600)
    for fmt, suffix in [('export-curl','sh'),('export-python','py')]:
        output = subprocess.check_output([str(ROOT/'core/target/release/scrapelens-core'),fmt,str(SOURCE),'captured'])
        path=BASE/f'expected.{suffix}'
        path.write_bytes(output)
        path.chmod(0o600)
    manifest = {str(p.relative_to(SOURCE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.rglob('*') if p.is_file()}
    (BASE/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Origem sintética: {SOURCE}')
    print(f'Destinos novos para salvar manualmente: {BASE}/native.sh, {BASE}/native.py, {BASE}/sanitized')

if __name__ == '__main__':
    main()
