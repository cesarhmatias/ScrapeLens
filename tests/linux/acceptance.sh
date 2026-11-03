#!/bin/bash
# Roteiro de aceitação Linux (rodada 14). Roda DENTRO de uma máquina OrbStack.
# Nada é executado no macOS e nenhuma janela do usuário é tocada.
# Uso: acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]
#
# Iniciar/Encerrar usam os ATALHOS do app, enviados com xdotool key (XTEST) na tela virtual :99:
#   ctrl+shift+r -> Iniciar sessão
#   ctrl+period  -> Encerrar
# Os botões Iniciar (1044,178) e Encerrar (1138,178) NÃO são clicados em nenhum passo.
# Foco: windowactivate --sync na janela principal (sem clique). Se a tecla não chegar ao
# WebView, o roteiro tenta de novo com no máximo um clique neutro em (700,900) — área vazia,
# longe de qualquer controle — apenas para dar foco, e registra o caso em atalhos.txt.
set -uo pipefail
ARCH_LABEL="$1"; APPIMAGE="$2"; DEB="${3:-}"
TESTSERVER="${4:-$HOME/scrapelens/testserver/target/release/scrapelens-testserver}"
PROBE="${5:-$HOME/scrapelens/tests/linux/probe_server.py}"
OUT="$HOME/sl-acceptance-$ARCH_LABEL-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"; FAILS=0
export XDG_DATA_HOME="$OUT/xdg/data" XDG_CONFIG_HOME="$OUT/xdg/config" XDG_CACHE_HOME="$OUT/xdg/cache"
DATA="$XDG_DATA_HOME/app.scrapelens.desktop/sessions"
export DISPLAY=:99
NEUTRAL_X=700; NEUTRAL_Y=900      # área vazia da janela do app (sem controles)
CLICKS_BUTTON=0; NEUTRAL_CLICKS=0
START_MODE=""; STOP_MODE=""; START_MODE2=""; STOP_MODE2=""
log(){ echo "$*" | tee -a "$OUT/summary.txt"; }
check(){ if [ "$1" = "0" ]; then log "OK   $2"; else log "FAIL $2"; FAILS=$((FAILS+1)); fi; }
# Janela principal: maior área entre as que têm o nome ScrapeLens (o app cria um helper
# InputOnly 10x10 e uma janela real ~1440x920).
wid(){
  local best="" ba=0 w g ww wh
  for w in $(xdotool search --name ScrapeLens 2>/dev/null); do
    g="$(xwininfo -id "$w" 2>/dev/null)"
    ww="$(echo "$g" | awk '/^  Width:/{print $2}')"
    wh="$(echo "$g" | awk '/^  Height:/{print $2}')"
    if [ -z "$ww" ] || [ -z "$wh" ]; then continue; fi
    if [ $((ww*wh)) -gt "$ba" ]; then ba=$((ww*wh)); best=$w; fi
  done
  echo "$best"
}
wait_window(){ # janela real (largura > 100) já mapeada; até 60 s
  local i w
  for i in $(seq 1 60); do
    w="$(wid)"
    if [ -n "$w" ] && [ "$(xwininfo -id "$w" 2>/dev/null | awk '/^  Width:/{print $2}')" -gt 100 ]; then echo "$w"; return 0; fi
    sleep 1
  done
  return 1
}
# Foco sem clique: windowactivate e confirmação de que o foco X chegou na janela principal.
focus_app(){
  local w="$1" i
  [ -z "$w" ] && return 1
  for i in 1 2 3; do
    xdotool windowactivate --sync "$w" 2>/dev/null
    sleep 1
    [ "$(xdotool getwindowfocus 2>/dev/null)" = "$w" ] && return 0
    sleep 1
  done
  return 1
}
neutral_click(){ NEUTRAL_CLICKS=$((NEUTRAL_CLICKS+1)); xdotool mousemove $NEUTRAL_X $NEUTRAL_Y click 1; sleep 1; }
capture_chrome(){ pgrep -f -- '--user-data-dir=[^ ]*scrapelens-chrome' 2>/dev/null | head -1; }
key(){ xdotool key --clearmodifiers "$1"; }   # XTEST: vai para a janela com foco X
# Print: a tela virtual da máquina (1600x1000). A janela cliente do app é reportada como
# 10x10 no X, então o recorte por geometria não serve; a tela contém só openbox, o Chrome de
# teste e a janela do ScrapeLens.
shot_window(){ timeout_import "$2" "1600x1000+0+0"; }
timeout_import(){ # tira a tela raiz e recorta; limite de 30 s para nunca travar o X
  local out="$1" geo="$2"
  (import -window root -crop "$geo" +repage "$out" >/dev/null 2>&1 & IP=$!; for i in $(seq 1 30); do kill -0 $IP 2>/dev/null || break; sleep 1; done; kill -9 $IP 2>/dev/null); [ -s "$out" ]
}
# Iniciar pelo atalho ctrl+shift+r. 1ª tentativa = teclado puro (só windowactivate).
# Se não disparar, tenta de novo com um clique neutro de foco. O botão nunca é clicado.
start_capture(){
  local i t w
  for i in 1 2 3; do
    if [ -n "$(capture_chrome)" ]; then
      [ -z "$START_MODE" ] && START_MODE="já havia captura em andamento (tentativa $i)"
      return 0
    fi
    w="$(wid)"; focus_app "$w"
    if [ "$i" -ge 2 ]; then
      neutral_click
      log "iniciar: tentativa $i — tecla não disparou; clique neutro em ($NEUTRAL_X,$NEUTRAL_Y) só para foco"
    fi
    key ctrl+shift+r
    for t in $(seq 1 40); do
      if [ -n "$(capture_chrome)" ]; then
        [ -z "$START_MODE" ] && {
          if [ "$i" -eq 1 ]; then START_MODE="disparou com teclado puro (windowactivate + Ctrl+Shift+R, sem clique)";
          else START_MODE="disparou com clique neutro de foco em ($NEUTRAL_X,$NEUTRAL_Y), sem tocar no botão"; fi
        }
        return 0
      fi
      sleep 1
    done
  done
  return 1
}
# Encerrar pelo atalho ctrl+period. Mesmo esquema: teclado puro primeiro, clique neutro depois.
stop_capture(){
  local i t w
  for i in 1 2 3; do
    w="$(wid)"; focus_app "$w"
    if [ "$i" -ge 2 ]; then
      neutral_click
      log "encerrar: tentativa $i — tecla não disparou; clique neutro em ($NEUTRAL_X,$NEUTRAL_Y) só para foco"
    fi
    key ctrl+period
    for t in $(seq 1 40); do
      if [ -z "$(capture_chrome)" ]; then
        [ -z "$STOP_MODE" ] && {
          if [ "$i" -eq 1 ]; then STOP_MODE="disparou com teclado puro (windowactivate + Ctrl+., sem clique)";
          else STOP_MODE="disparou com clique neutro de foco em ($NEUTRAL_X,$NEUTRAL_Y), sem tocar no botão"; fi
        }
        return 0
      fi
      sleep 1
    done
  done
  return 1
}
wait_session(){ # espera session.json da sessão mais nova (import leva ~16 s)
  local t s
  for t in $(seq 1 60); do
    s="$(ls -td "$DATA"/capture-* 2>/dev/null | head -1)"
    [ -n "$s" ] && [ -f "$s/session.json" ] && { echo "$s"; return 0; }
    sleep 1
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
log "artefato: $(basename "$APPIMAGE") · sha256=$(sha256sum "$APPIMAGE" | cut -d' ' -f1)"

# 1. Instalação do .deb (arquitetura da máquina).
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
APP=$!
WID="$(wait_window)"; sleep 8
[ -n "$WID" ] && check 0 "janela ScrapeLens encontrada (wid=$WID)" || check 1 "janela ScrapeLens encontrada"
focus_app "$WID"

# 4. Iniciar pelo atalho Ctrl+Shift+R; durante a captura: ss -ltnp e LISTEN do Chrome da captura.
start_capture && check 0 "iniciar por atalho Ctrl+Shift+R (sem clique em botão)" || check 1 "iniciar por atalho Ctrl+Shift+R"
log "atalho iniciar: ${START_MODE:-não disparou}"
sleep 3
CHROME_PID="$(capture_chrome)"
ss -ltnp > "$OUT/ss-durante-captura.txt" 2>&1
if [ -n "$CHROME_PID" ]; then
  L="$(ss -ltnp | grep "pid=$CHROME_PID," || true)"
  [ -z "$L" ] && check 0 "nenhum LISTEN do Chrome da captura (pid $CHROME_PID)" || check 1 "nenhum LISTEN do Chrome da captura"
else
  check 1 "Chrome da captura encontrado (perfil scrapelens-chrome-*)"
fi
shot_window "$WID" "$OUT/print-captura.png"; check $? "print da janela durante a captura"

# 5. Encerrar pelo atalho Ctrl+. e sessão no disco.
stop_capture && check 0 "encerrar por atalho Ctrl+. (sem clique em botão)" || check 1 "encerrar por atalho Ctrl+."
log "atalho encerrar: ${STOP_MODE:-não disparou}"
SESS="$(wait_session)"
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
START_MODE=""; STOP_MODE=""
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8791/ SCRAPELENS_CAPTURE_NETWORK=loopback \
  "$APPIMAGE" >"$OUT/app-probe.log" 2>&1 & APP2=$!
WID2="$(wait_window)"; sleep 8
if [ -n "$WID2" ]; then
  focus_app "$WID2"; sleep 1
  start_capture; START_MODE2="$START_MODE"
  sleep 8
  stop_capture; STOP_MODE2="$STOP_MODE"
  log "2ª captura (sonda): iniciar=$START_MODE2 · encerrar=$STOP_MODE2"
fi
WD="$(python3 -c "import json,sys;v=[json.loads(l)['webdriver'] for l in open(sys.argv[1]) if l.strip()];print(v[-1] if v else 'ausente')" "$PROBE_LOG")"
log "navigator.webdriver (valor lido pela sonda): $WD"
[ "$WD" = "false" ] && check 0 "navigator.webdriver === false" || check 1 "navigator.webdriver === false (valor: $WD)"
[ -n "$WID2" ] && shot_window "$WID2" "$OUT/print-final.png"
kill $APP2 $PROBE_PID $TS 2>/dev/null

# 9. Atalhos: nenhum clique em coordenada de botão (Iniciar/Encerrar) em toda a bateria.
{
  echo "iniciar (Ctrl+Shift+R): ${START_MODE2:-$START_MODE}"
  echo "encerrar (Ctrl+.): ${STOP_MODE2:-$STOP_MODE}"
  echo "método: xdotool windowactivate --sync + xdotool key --clearmodifiers (XTEST, tela :99)"
  echo "cliques em coordenadas de botão Iniciar (1044,178) / Encerrar (1138,178): $CLICKS_BUTTON"
  echo "cliques neutros de foco em ($NEUTRAL_X,$NEUTRAL_Y): $NEUTRAL_CLICKS"
} > "$OUT/atalhos.txt"
[ "$CLICKS_BUTTON" -eq 0 ] && check 0 "nenhum clique nos botões Iniciar/Encerrar" || check 1 "nenhum clique nos botões Iniciar/Encerrar"
grep -q "^iniciar (Ctrl+Shift+R): disparou" "$OUT/atalhos.txt" && check 0 "iniciar disparou pelo atalho de teclado" || check 1 "iniciar disparou pelo atalho de teclado"
grep -q "^encerrar (Ctrl+.): disparou" "$OUT/atalhos.txt" && check 0 "encerrar disparou pelo atalho de teclado" || check 1 "encerrar disparou pelo atalho de teclado"

log "FALHAS=$FAILS · saída em $OUT"
exit $FAILS
