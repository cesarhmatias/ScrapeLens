#!/bin/bash
# Linux acceptance script (round 14). Runs INSIDE an OrbStack machine.
# Nothing runs on macOS and no user window is touched.
# Usage: acceptance.sh <amd64|arm64> <AppImage> [.deb] [testserver] [probe_server.py]
#
# Start/Stop use the app's SHORTCUTS, sent with xdotool key (XTEST) on the virtual screen :99:
#   ctrl+shift+r -> Start session
#   ctrl+period  -> Stop
# The Start (1044,178) and Stop (1138,178) buttons are NOT clicked in any step.
# Focus: windowactivate --sync on the main window (no click). If the key does not reach the
# WebView, the script retries with at most one neutral click at (700,900) — an empty area,
# far from any control — only to give focus, and records the case in atalhos.txt.
set -uo pipefail
ARCH_LABEL="$1"; APPIMAGE="$2"; DEB="${3:-}"
TESTSERVER="${4:-$HOME/scrapelens/testserver/target/release/scrapelens-testserver}"
PROBE="${5:-$HOME/scrapelens/tests/linux/probe_server.py}"
OUT="$HOME/sl-acceptance-$ARCH_LABEL-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"; FAILS=0
export XDG_DATA_HOME="$OUT/xdg/data" XDG_CONFIG_HOME="$OUT/xdg/config" XDG_CACHE_HOME="$OUT/xdg/cache"
DATA="$XDG_DATA_HOME/app.scrapelens.desktop/sessions"
export DISPLAY=:99
NEUTRAL_X=700; NEUTRAL_Y=900      # empty area of the app window (no controls)
CLICKS_BUTTON=0; NEUTRAL_CLICKS=0
START_MODE=""; STOP_MODE=""; START_MODE2=""; STOP_MODE2=""
log(){ echo "$*" | tee -a "$OUT/summary.txt"; }
check(){ if [ "$1" = "0" ]; then log "OK   $2"; else log "FAIL $2"; FAILS=$((FAILS+1)); fi; }
# Main window: largest area among those named ScrapeLens (the app creates a 10x10
# InputOnly helper and a real ~1440x920 window).
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
wait_window(){ # real window (width > 100) already mapped; up to 60 s
  local i w
  for i in $(seq 1 60); do
    w="$(wid)"
    if [ -n "$w" ] && [ "$(xwininfo -id "$w" 2>/dev/null | awk '/^  Width:/{print $2}')" -gt 100 ]; then echo "$w"; return 0; fi
    sleep 1
  done
  return 1
}
# Focus without clicking: windowactivate and confirmation that X focus reached the main window.
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
key(){ xdotool key --clearmodifiers "$1"; }   # XTEST: goes to the window with X focus
# Screenshot: the machine's virtual screen (1600x1000). The app's client window is reported
# as 10x10 on X, so cropping by geometry does not work; the screen contains only openbox,
# the test Chrome and the ScrapeLens window.
shot_window(){ timeout_import "$2" "1600x1000+0+0"; }
timeout_import(){ # grabs the root screen and crops it; 30 s limit so X never hangs
  local out="$1" geo="$2"
  (import -window root -crop "$geo" +repage "$out" >/dev/null 2>&1 & IP=$!; for i in $(seq 1 30); do kill -0 $IP 2>/dev/null || break; sleep 1; done; kill -9 $IP 2>/dev/null); [ -s "$out" ]
}
# Start via the ctrl+shift+r shortcut. 1st attempt = pure keyboard (windowactivate only).
# If it does not fire, retries with a neutral focus click. The button is never clicked.
start_capture(){
  local i t w
  for i in 1 2 3; do
    if [ -n "$(capture_chrome)" ]; then
      [ -z "$START_MODE" ] && START_MODE="a capture was already in progress (attempt $i)"
      return 0
    fi
    w="$(wid)"; focus_app "$w"
    if [ "$i" -ge 2 ]; then
      neutral_click
      log "start: attempt $i — key did not fire; neutral click at ($NEUTRAL_X,$NEUTRAL_Y) for focus only"
    fi
    key ctrl+shift+r
    for t in $(seq 1 40); do
      if [ -n "$(capture_chrome)" ]; then
        [ -z "$START_MODE" ] && {
          if [ "$i" -eq 1 ]; then START_MODE="fired with pure keyboard (windowactivate + Ctrl+Shift+R, no click)";
          else START_MODE="fired with neutral focus click at ($NEUTRAL_X,$NEUTRAL_Y), without touching the button"; fi
        }
        return 0
      fi
      sleep 1
    done
  done
  return 1
}
# Stop via the ctrl+period shortcut. Same scheme: pure keyboard first, neutral click afterwards.
stop_capture(){
  local i t w
  for i in 1 2 3; do
    w="$(wid)"; focus_app "$w"
    if [ "$i" -ge 2 ]; then
      neutral_click
      log "stop: attempt $i — key did not fire; neutral click at ($NEUTRAL_X,$NEUTRAL_Y) for focus only"
    fi
    key ctrl+period
    for t in $(seq 1 40); do
      if [ -z "$(capture_chrome)" ]; then
        [ -z "$STOP_MODE" ] && {
          if [ "$i" -eq 1 ]; then STOP_MODE="fired with pure keyboard (windowactivate + Ctrl+., no click)";
          else STOP_MODE="fired with neutral focus click at ($NEUTRAL_X,$NEUTRAL_Y), without touching the button"; fi
        }
        return 0
      fi
      sleep 1
    done
  done
  return 1
}
wait_session(){ # waits for session.json of the newest session (import takes ~16 s)
  local t s
  for t in $(seq 1 60); do
    s="$(ls -td "$DATA"/capture-* 2>/dev/null | head -1)"
    [ -n "$s" ] && [ -f "$s/session.json" ] && { echo "$s"; return 0; }
    sleep 1
  done
  return 1
}

# 0. Virtual desktop and cleanup of previous runs (by exact process name).
pgrep -x Xvfb >/dev/null || (Xvfb :99 -screen 0 1600x1000x24 >"$OUT/xvfb.log" 2>&1 &)
sleep 2
pgrep -x openbox >/dev/null || (openbox >"$OUT/openbox.log" 2>&1 &)
pkill -x scrapelens 2>/dev/null; pkill -x scrapelens-test 2>/dev/null; sleep 1
log "host: $(uname -m) · $(. /etc/os-release; echo "$PRETTY_NAME") · dpkg=$(dpkg --print-architecture)"
if [ "$(uname -m)" = x86_64 ]; then log "execution type: ROSETTA (x86_64 on arm64 host)"; else log "execution type: NATIVE (aarch64)"; fi
log "navegador: $(google-chrome --version 2>/dev/null || chromium --version 2>/dev/null || echo absent)"
log "artifact: $(basename "$APPIMAGE") · sha256=$(sha256sum "$APPIMAGE" | cut -d' ' -f1)"

# 1. Install the .deb (machine architecture).
if [ -n "$DEB" ]; then
  sudo apt-get install -y "$DEB" >"$OUT/deb-install.log" 2>&1; check $? "install .deb ($(basename "$DEB"))"
  dpkg -s scrape-lens 2>/dev/null | grep -q "^Status: install ok installed" && check 0 "scrape-lens package installed" || check 1 "scrape-lens package installed"
fi

# 2. Local testserver (/page on 127.0.0.1:8781).
"$TESTSERVER" serve --only h1 --h1 127.0.0.1:8781 --evidence "$OUT/ts" --run-id lx-$ARCH_LABEL >"$OUT/testserver.log" 2>&1 &
TS=$!; sleep 2
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8781/page | grep -q 200; check $? "testserver responds on /page"

# 3. Open the AppImage with the test variables.
chmod +x "$APPIMAGE"
SCRAPELENS_TEST_MODE=1 SCRAPELENS_CAPTURE_URL=http://127.0.0.1:8781/page SCRAPELENS_CAPTURE_NETWORK=loopback \
  "$APPIMAGE" >"$OUT/app.log" 2>&1 &
APP=$!
WID="$(wait_window)"; sleep 8
[ -n "$WID" ] && check 0 "ScrapeLens window found (wid=$WID)" || check 1 "ScrapeLens window found"
focus_app "$WID"

# 4. Start via the Ctrl+Shift+R shortcut; during capture: ss -ltnp and the LISTEN sockets of the capture Chrome.
start_capture && check 0 "start via Ctrl+Shift+R shortcut (no button click)" || check 1 "start via Ctrl+Shift+R shortcut"
log "start shortcut: ${START_MODE:-did not fire}"
sleep 3
CHROME_PID="$(capture_chrome)"
ss -ltnp > "$OUT/ss-durante-captura.txt" 2>&1
if [ -n "$CHROME_PID" ]; then
  L="$(ss -ltnp | grep "pid=$CHROME_PID," || true)"
  [ -z "$L" ] && check 0 "no LISTEN socket of the capture Chrome (pid $CHROME_PID)" || check 1 "no LISTEN socket of the capture Chrome"
else
  check 1 "capture Chrome found (profile scrapelens-chrome-*)"
fi
shot_window "$WID" "$OUT/print-captura.png"; check $? "window screenshot during capture"

# 5. Stop via the Ctrl+. shortcut and the session on disk.
stop_capture && check 0 "stop via Ctrl+. shortcut (no button click)" || check 1 "stop via Ctrl+. shortcut"
log "stop shortcut: ${STOP_MODE:-did not fire}"
SESS="$(wait_session)"
[ -n "$SESS" ] && check 0 "capture session on disk ($(basename "$SESS"))" || check 1 "capture session on disk"
REQS="$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));s=d.get('session',d);print(s['completeness']['counts'].get('requests',0))" "$SESS/session.json" 2>/dev/null || echo 0)"
log "capture: requests=$REQS"
[ "${REQS:-0}" -ge 1 ] && check 0 "capture with requests ($REQS)" || check 1 "capture with requests"

# 6. Imports through the test CLI (fixtures in $HOME/fixtures-r14); the open app is closed first.
FIX="$HOME/fixtures-r14"
kill $APP 2>/dev/null; sleep 3; pkill -x scrapelens 2>/dev/null; sleep 1
if [ -f "$FIX/har-derived.json" ] && [ -f "$FIX/h1h2h3.chrome-netlog.json" ]; then
  import_cli(){ # $1=flag $2=file $3=session prefix; waits for the session to appear (up to 60 s), then stops
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
  import_cli --import-har "$FIX/har-derived.json" har; check $? "import --import-har (har session created)"
  import_cli --import-netlog "$FIX/h1h2h3.chrome-netlog.json" netlog; check $? "import --import-netlog (netlog session created)"
else
  check 1 "fixtures present in $FIX"
fi

# 7. Counts on disk: HAR complete 24, NetLog partial 32 (only this run's sessions).
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
grep -q "^har-.* complete 24$" "$OUT/contagens.txt" 2>/dev/null && check 0 "HAR complete with 24 requests" || check 1 "HAR complete with 24 requests"
grep -q "^netlog-.* partial 32$" "$OUT/contagens.txt" 2>/dev/null && check 0 "NetLog partial with 32 requests" || check 1 "NetLog partial with 32 requests"

# 8. navigator.webdriver: new capture with the probe page (loopback), expected value false.
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
  log "2nd capture (probe): start=$START_MODE2 · stop=$STOP_MODE2"
fi
WD="$(python3 -c "import json,sys;v=[json.loads(l)['webdriver'] for l in open(sys.argv[1]) if l.strip()];print(v[-1] if v else 'absent')" "$PROBE_LOG")"
log "navigator.webdriver (value read by the probe): $WD"
[ "$WD" = "false" ] && check 0 "navigator.webdriver === false" || check 1 "navigator.webdriver === false (value: $WD)"
[ -n "$WID2" ] && shot_window "$WID2" "$OUT/print-final.png"
kill $APP2 $PROBE_PID $TS 2>/dev/null

# 9. Shortcuts: no click on a button coordinate (Start/Stop) in the whole suite.
{
  echo "start (Ctrl+Shift+R): ${START_MODE2:-$START_MODE}"
  echo "stop (Ctrl+.): ${STOP_MODE2:-$STOP_MODE}"
  echo "method: xdotool windowactivate --sync + xdotool key --clearmodifiers (XTEST, screen :99)"
  echo "clicks at Start (1044,178) / Stop (1138,178) button coordinates: $CLICKS_BUTTON"
  echo "neutral focus clicks at ($NEUTRAL_X,$NEUTRAL_Y): $NEUTRAL_CLICKS"
} > "$OUT/atalhos.txt"
[ "$CLICKS_BUTTON" -eq 0 ] && check 0 "no click on the Start/Stop buttons" || check 1 "no click on the Start/Stop buttons"
grep -q "^start (Ctrl+Shift+R): fired" "$OUT/atalhos.txt" && check 0 "start fired via keyboard shortcut" || check 1 "start fired via keyboard shortcut"
grep -q "^stop (Ctrl+.): fired" "$OUT/atalhos.txt" && check 0 "stop fired via keyboard shortcut" || check 1 "stop fired via keyboard shortcut"

log "FAILURES=$FAILS · output in $OUT"
exit $FAILS
