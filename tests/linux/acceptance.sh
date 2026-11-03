#!/bin/bash
# Roteiro de aceitação Linux (rodada 14). Roda DENTRO de uma máquina OrbStack.
# Uso: acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]
# Só loopback. Não toca no macOS e não clica em janelas do usuário: tudo no Xvfb da própria máquina.
# Iniciar/Encerrar: cliques com xdotool na tela virtual (1600x1000), nos botões do app.
#   Iniciar sessão  -> (1044,178)   Encerrar -> (1138,178)
# Atalhos de teclado (ctrl+shift+r / ctrl+period) não chegam ao app no Linux: não usados.
set -uo pipefail
ARCH_LABEL="$1"; APPIMAGE="$2"; DEB="${3:-}"
TESTSERVER="${4:-$HOME/scrapelens/testserver/target/release/scrapelens-testserver}"
PROBE="${5:-$HOME/scrapelens/tests/linux/probe_server.py}"
OUT="$HOME/sl-acceptance-$ARCH_LABEL-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"; FAILS=0
export XDG_DATA_HOME="$OUT/xdg/data" XDG_CONFIG_HOME="$OUT/xdg/config" XDG_CACHE_HOME="$OUT/xdg/cache"
DATA="$XDG_DATA_HOME/app.scrapelens.desktop/sessions"
export DISPLAY=:99
log(){ echo "$*" | tee -a "$OUT/summary.txt"; }
check(){ if [ "$1" = "0" ]; then log "OK   $2"; else log "FAIL $2"; FAILS=$((FAILS+1)); fi; }
click(){ xdotool mousemove "$1" "$2" click 1; }
# Janela principal: a de maior largura entre as que têm o nome ScrapeLens (há um helper 10x10).
wid(){
  local best="" bw=0 w ww
  for w in $(xdotool search --name ScrapeLens 2>/dev/null); do
    ww="$(xwininfo -id "$w" 2>/dev/null | awk '/^  Width/{print $2}')"
    if [ -n "$ww" ] && [ "$ww" -gt "$bw" ]; then bw=$ww; best=$w; fi
  done
  echo "$best"
}
# Print: a tela virtual da máquina (1600x1000). No Xvfb só existem o openbox e a janela do ScrapeLens,
# e o X reporta a janela cliente como 10x10 (a moldura não tem geometria própria), então o recorte
# pela geometria da janela não é confiável; por isso o print é da tela virtual inteira.
shot_window(){
  local out="$2"
  timeout_import "$out" "1600x1000+0+0"
}
timeout_import(){ # tira a tela raiz e recorta; limite de 30 s para nunca travar o X
  local out="$1" geo="$2"
  (import -window root -crop "$geo" +repage "$out" >/dev/null 2>&1 & IP=$!; for i in $(seq 1 30); do kill -0 $IP 2>/dev/null || break; sleep 1; done; kill -9 $IP 2>/dev/null); [ -s "$out" ]
}
# Inicia a captura pelo botão e espera o Chrome da captura aparecer (uma nova tentativa de clique).
start_capture(){
  local i j w
  for i in 1 2 3; do
    w="$(wid)"; [ -n "$w" ] && xdotool windowactivate --sync "$w" 2>/dev/null; sleep 2
    click 1044 178
    for j in $(seq 1 30); do pgrep -f 'scrapelens-chrome' >/dev/null && return 0; sleep 1; done
  done
  return 1
}

# 0. Desktop virtual e limpeza de execuções anteriores (por nome exato de processo).
pgrep -x Xvfb >/dev/null || (Xvfb :99 -screen 0 1600x1000x24 >"$OUT/xvfb.log" 2>&1 &)
sleep 2
pgrep -x openbox >/dev/null || (openbox >"$OUT/openbox.log" 2>&1 &)
pkill -x scrapelens 2>/dev/null; pkill -x scrapelens-test 2>/dev/null; sleep 1
log "host: $(uname -m) · $(. /etc/os-release; echo "$PRETTY_NAME") · dpkg=$(dpkg --print-architecture)"
if [ "$(uname -m)" = x86_64 ]; then log "tipo de execução: ROSETTA (x86_64 sobre host arm64)"; else log "tipo de execução: NATIVA (aarch64)"; fi
log "navegador: $(google-chrome --version 2>/dev/null || chromium --version 2>/dev/null || echo ausente)"

# 1. Instalação do .deb (ambas as arquiteturas, arquitetura da máquina).
if [ -n "$DEB" ]; then
  sudo apt-get install -y "$DEB" >"$OUT/deb-install.log" 2>&1; check $? "instalar .deb ($(basename "$DEB"))"
  dpkg -s scrape-lens 2>/dev/null | grep -q "^Status: install ok installed" && check 0 "pacote scrape-lens instalado" || check 1 "pacote scrape-lens instalado"
fi

# 2. Testserver local (/page em 127.0.0.1:8781).
"$TESTSERVER" serve --only h1 --h1 127.0.0.1:8781 --evidence "$OUT/ts" --run-id lx-$ARCH_LABEL >"$OUT/testserver.log" 2>&1 &
TS=$!; sleep 2
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8781/page | grep -q 200; check $? "testserver responde /page"

# 3. Abrir o AppImage com as variáveis de teste.
chmod +x "$APPIMAGE"
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page SCRAPELENS_CAPTURE_NETWORK=loopback \
  "$APPIMAGE" >"$OUT/app.log" 2>&1 &
APP=$!; sleep 20
WID="$(wid)"
[ -n "$WID" ] && check 0 "janela ScrapeLens encontrada (wid=$WID)" || check 1 "janela ScrapeLens encontrada"
xdotool windowactivate --sync "$WID" 2>/dev/null; sleep 1

# 4. Iniciar (clique em Iniciar sessão); durante a captura: ss -ltnp e LISTEN do Chrome da captura.
start_capture; sleep 3
CHROME_PID="$(pgrep -f 'scrapelens-chrome' | head -1)"
ss -ltnp > "$OUT/ss-durante-captura.txt" 2>&1
if [ -n "$CHROME_PID" ]; then
  L="$(ss -ltnp | grep "pid=$CHROME_PID," || true)"
  [ -z "$L" ] && check 0 "nenhum LISTEN do Chrome da captura (pid $CHROME_PID)" || check 1 "nenhum LISTEN do Chrome da captura"
else
  check 1 "Chrome da captura encontrado (perfil scrapelens-chrome-*)"
fi
shot_window "$WID" "$OUT/print-captura.png"; check $? "print da janela durante a captura"

# 5. Encerrar (clique em Encerrar) e sessão no disco.
xdotool windowactivate --sync "$WID" 2>/dev/null; sleep 1
click 1138 178; sleep 15
SESS="$(ls -td "$DATA"/capture-* 2>/dev/null | head -1)"
[ -n "$SESS" ] && check 0 "sessão de captura no disco ($(basename "$SESS"))" || check 1 "sessão de captura no disco"
REQS="$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));s=d.get('session',d);print(s['completeness']['counts'].get('requests',0))" "$SESS/session.json" 2>/dev/null || echo 0)"
log "captura: requisições=$REQS"
[ "${REQS:-0}" -ge 1 ] && check 0 "captura com requisições ($REQS)" || check 1 "captura com requisições"

# 6. Imports pela CLI de teste (fixtures em $HOME/fixtures-r14); o app aberto é fechado antes.
FIX="$HOME/fixtures-r14"
kill $APP 2>/dev/null; sleep 3; pkill -x scrapelens 2>/dev/null; sleep 1
if [ -f "$FIX/har-derived.json" ] && [ -f "$FIX/h1h2h3.chrome-netlog.json" ]; then
  import_cli(){ # $1=flag $2=arquivo $3=prefixo da sessão; espera a sessão aparecer (até 60 s) e então encerra
    local before after
    before="$(ls "$DATA" 2>/dev/null | grep "^$3" | sort)"
    SCRAPELENS_TEST_MODE=1 "$APPIMAGE" "$1" "$2" >"$OUT/import-$3.log" 2>&1 & local ip=$!
    for i in $(seq 1 60); do
      after="$(ls "$DATA" 2>/dev/null | grep "^$3" | sort)"
      [ "$after" != "$before" ] && [ -n "$after" ] && break
      sleep 1
    done
    sleep 2; kill $ip 2>/dev/null; sleep 1; pkill -x scrapelens 2>/dev/null; sleep 1
    [ "$after" != "$before" ] && [ -n "$after" ]
  }
  import_cli --import-har "$FIX/har-derived.json" har; check $? "import --import-har (sessão har criada)"
  import_cli --import-netlog "$FIX/h1h2h3.chrome-netlog.json" netlog; check $? "import --import-netlog (sessão netlog criada)"
else
  check 1 "fixtures presentes em $FIX"
fi

# 7. Contagens no disco: HAR complete 24, NetLog partial 32 (somente as sessões deste run).
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

# 8. navigator.webdriver: nova captura com a página-sonda (loopback), valor esperado false.
PROBE_LOG="$OUT/probe.jsonl"; : > "$PROBE_LOG"
python3 "$PROBE" 8791 "$PROBE_LOG" >"$OUT/probe-server.log" 2>&1 & PROBE_PID=$!; sleep 1
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8791/ SCRAPELENS_CAPTURE_NETWORK=loopback \
  "$APPIMAGE" >"$OUT/app-probe.log" 2>&1 & APP2=$!; sleep 20
WID2="$(wid)"
if [ -n "$WID2" ]; then
  xdotool windowactivate --sync "$WID2" 2>/dev/null; sleep 1
  start_capture; sleep 8
  xdotool windowactivate --sync "$WID2" 2>/dev/null; sleep 1
  click 1138 178; sleep 12
fi
WD="$(python3 -c "import json,sys;v=[json.loads(l)['webdriver'] for l in open(sys.argv[1]) if l.strip()];print(v[-1] if v else 'ausente')" "$PROBE_LOG")"
log "navigator.webdriver (valor lido pela sonda): $WD"
[ "$WD" = "false" ] && check 0 "navigator.webdriver === false" || check 1 "navigator.webdriver === false (valor: $WD)"
[ -n "$WID2" ] && shot_window "$WID2" "$OUT/print-final.png"
kill $APP2 $PROBE_PID $TS 2>/dev/null

log "FALHAS=$FAILS · saída em $OUT"
exit $FAILS
