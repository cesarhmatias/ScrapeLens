#!/usr/bin/env python3
"""Regenera os payloads que o harness de UI usa como stub do Tauri.

O harness (`ui-harness.mjs`) precisa de duas respostas de `open_session`:
a sessão original e a sessão sanitizada. Elas são grandes e derivadas de
dados de sessão, então ficam fora do git; este script as recria a partir das
pastas reais.

Uso (na pasta `src-tauri/evidence/exportacao`):

    python3 prepare-payloads.py \
        "$HOME/Library/Application Support/app.scrapelens.desktop/sessions/har-3dbc391c02a985c5-2" \
        ./sanitized-har-synthetic

A sessão sanitizada pode ser recriada com:

    cd ../../ && cargo run --quiet --example export_dump -- \
        <sessão-original> har-0002 <esta-pasta>/sanitized-har-synthetic
"""

import json
import pathlib
import sys


def payload(directory: pathlib.Path, notice: str) -> str:
    session = json.loads((directory / "session.json").read_text(encoding="utf-8"))
    return json.dumps(
        {
            "session": session,
            "sessionDir": str(directory.resolve()),
            "synthetic": False,
            "notice": notice,
            "pending": False,
        },
        ensure_ascii=False,
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    original = pathlib.Path(sys.argv[1]).expanduser()
    sanitized = pathlib.Path(sys.argv[2]).expanduser()
    here = pathlib.Path(__file__).resolve().parent
    (here / "orig-payload.json").write_text(
        payload(original, "Sessão aberta: 24 requisições."), encoding="utf-8"
    )
    (here / "sanitized-payload.json").write_text(
        payload(sanitized, "Sessão sanitizada aberta: 24 requisições."), encoding="utf-8"
    )
    print("payloads gravados em", here)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
