#!/bin/bash
# Roteiro de aceitação Linux (rodada 14). Roda DENTRO de uma máquina OrbStack.
# Uso: acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]
# Só loopback. Não toca no macOS e não clica em janelas do usuário: tudo no Xvfb da máquina.
set -uo pipefail
ARCH_LABEL="$1"; APPIMAGE="$2"; DEB="${3:-}"
TESTSERVER="${4:-$HOME/scrapelens/testserver/target/release/scrapelens-testserver}"
PROBE="${5:-$HOME/scrapelens/tests/linux/probe_server.py}"
OUT="$HOME/sl-acceptance-$ARCH_LABEL-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"; FAILS=0
log(){ echo "$*" | tee -a "$OUT/summary.txt"; }
check(){ if [ "$1" = "0" ]; then log "OK   $2"; else log "FAIL $2"; FAILS=$((FAILS+1)); fi; }
DATA="$HOME/.local/share/app.scrapelens.desktop/sessions"

# 0. Desktop virtual na própria máquina.
export DISPLAY=:99
pgrep -x Xvfb >/dev/null || (Xvfb :99 -screen 0 1600x1000x24 >"$OUT/xvfb.log" 2>&1 &)
sleep 2
pgrep -x openbox >/dev/null || (openbox >"$OUT/openbox.log" 2>&1 &)
log "host: $(uname -m) · $(. /etc/os-release; echo "$PRETTY_NAME") · dpkg=$(dpkg --print-architecture)"
if [ "$(uname -m)" = x86_64 ]; then log "tipo de execução: ROSETTA (x86_64 sobre host arm64)"; else log "tipo de execução: NATIVA (aarch64)"; fi

# 1. Instalação do .deb (só amd64).
if [ -n "$DEB" ]; then
  sudo apt-get install -y "$DEB" >"$OUT/deb-install.log" 2>&1; check $? "instalar .deb ($DEB)"
fi

# 2. Testserver local (/page em 127.0.0.1:8781).
"$TESTSERVER" serve --only h1 --h1 127.0.0.1:8781 --evidence "$OUT/ts" --run-id lx-$ARCH_LABEL >"$OUT/testserver.log" 2>&1 &
TS=$!; sleep 2
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8781/page | grep -q 200; check $? "testserver responde /page"

# 3. Abrir o AppImage com as variáveis de teste.
chmod +x "$APPIMAGE"
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page SCRAPELENS_CAPTURE_NETWORK=loopback \
  "$APPIMAGE" >"$OUT/app.log" 2>&1 &
APP=$!; sleep 12
WID="$(xdotool search --name ScrapeLens 2>/dev/null | head -1)"
[ -n "$WID" ] && check 0 "janela ScrapeLens encontrada (wid=$WID)" || check 1 "janela ScrapeLens encontrada"
xdotool windowactivate --sync "$WID" 2>/dev/null; sleep 1

# 4. Iniciar (Ctrl+Shift+R); enquanto grava, ss -ltnp: nenhum LISTEN do Chrome da captura.
xdotool key --window "$WID" ctrl+shift+r; sleep 12
CHROME_PID="$(pgrep -f 'scrapelens-chrome' | head -1)"
ss -ltnp > "$OUT/ss-durante-captura.txt" 2>&1
if [ -n "$CHROME_PID" ]; then
  L="$(ss -ltnp | grep "pid=$CHROME_PID," || true)"
  [ -z "$L" ] && check 0 "nenhum LISTEN do Chrome da captura (pid $CHROME_PID)" || check 1 "nenhum LISTEN do Chrome da captura"
else
  check 1 "Chrome da captura encontrado (perfil scrapelens-chrome-*)"
fi
import -window root "$OUT/print-captura.png" 2>/dev/null; check $? "print da tela durante a captura"

# 5. Encerrar (Ctrl+.) e sessão no disco.
xdotool key --window "$WID" ctrl+period; sleep 15
SESS="$(ls -td "$DATA"/capture-* 2>/dev/null | head -1)"
[ -n "$SESS" ] && check 0 "sessão de captura no disco ($(basename "$SESS"))" || check 1 "sessão de captura no disco"
REQS="$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));s=d.get('session',d);print(s['completeness']['counts'].get('requests',0))" "$SESS/session.json" 2>/dev/null || echo 0)"
[ "${REQS:-0}" -ge 1 ] && check 0 "captura com requisições ($REQS)" || check 1 "captura com requisições"

# 6. Imports pela CLI de teste (fixtures em $HOME/fixtures-r14).
FIX="$HOME/fixtures-r14"
if [ -f "$FIX/har-derived.json" ] && [ -f "$FIX/h1h2h3.chrome-netlog.json" ]; then
  kill $APP 2>/dev/null; sleep 3
  SCRAPELENS_TEST_MODE=1 "$APPIMAGE" --import-har "$FIX/har-derived.json" >"$OUT/import-har.log" 2>&1 & sleep 12; kill $! 2>/dev/null
  SCRAPELENS_TEST_MODE=1 "$APPIMAGE" --import-netlog "$FIX/h1h2h3.chrome-netlog.json" >"$OUT/import-netlog.log" 2>&1 & sleep 12; kill $! 2>/dev/null
  check 0 "imports --import-har e --import-netlog executados"
else
  check 1 "fixtures presentes em $FIX"
fi

# 7. Contagens no disco: HAR complete 24, NetLog partial 32.
python3 - "$DATA" "$OUT/contagens.txt" <<'PY' || true
import json,glob,os,sys
root,out=sys.argv[1],sys.argv[2]; rows=[]
for d in sorted(glob.glob(os.path.join(root,'*'))):
    p=os.path.join(d,'session.json')
    if not os.path.isfile(p): continue
    j=json.load(open(p)); s=j.get('session',j)
    rows.append(f"{os.path.basename(d)} {s['completeness']['state']} {s['completeness']['counts'].get('requests')}")
open(out,'w').write("\n".join(rows)+"\n")
PY
grep -q "^har-.* complete 24$" "$OUT/contagens.txt" 2>/dev/null && check 0 "HAR complete com 24 requisições" || check 1 "HAR complete com 24 requisições"
grep -q "^netlog-.* partial 32$" "$OUT/contagens.txt" 2>/dev/null && check 0 "NetLog partial com 32 requisições" || check 1 "NetLog partial com 32 requisições"

# 8. navigator.webdriver: captura com a página-sonda (loopback), valor esperado false.
PROBE_LOG="$OUT/probe.jsonl"; : > "$PROBE_LOG"
python3 "$PROBE" 8791 "$PROBE_LOG" & PROBE_PID=$!; sleep 1
kill $APP 2>/dev/null; sleep 3
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8791/ SCRAPELENS_CAPTURE_NETWORK=loopback "$APPIMAGE" >"$OUT/app-probe.log" 2>&1 & APP2=$!; sleep 12
WID2="$(xdotool search --name ScrapeLens 2>/dev/null | head -1)"
[ -n "$WID2" ] && xdotool windowactivate --sync "$WID2" 2>/dev/null
[ -n "$WID2" ] && xdotool key --window "$WID2" ctrl+shift+r; sleep 10
[ -n "$WID2" ] && xdotool key --window "$WID2" ctrl+period; sleep 12
WD="$(python3 -c "import json,sys;v=[json.loads(l)['webdriver'] for l in open(sys.argv[1]) if l.strip()];print(v[-1] if v else 'ausente')" "$PROBE_LOG")"
[ "$WD" = "false" ] && check 0 "navigator.webdriver === false (valor: $WD)" || check 1 "navigator.webdriver === false (valor: $WD)"
kill $APP2 $PROBE_PID $TS 2>/dev/null
import -window root "$OUT/print-final.png" 2>/dev/null

log "FALHAS=$FAILS · saída em $OUT"
exit $FAILS
