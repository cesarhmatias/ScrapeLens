#!/bin/sh
# End to end on a packaged App: real Chromium profile with a cookie (keyring), preferences
# that select it, the App started by its own shortcut, then the server log and the session.
# Usage: e2e-app.sh <launch command...>
export HOME=/home/tester/e2e
export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/.local/share XDG_CACHE_HOME=$HOME/.cache
export SCRAPELENS_TEST_MODE=0 APPIMAGE_EXTRACT_AND_RUN=1 NO_AT_BRIDGE=1 GDK_BACKEND=x11
rm -rf "$HOME"; mkdir -p "$XDG_CONFIG_HOME/app.scrapelens.desktop" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
cd /tmp && rm -f /tmp/srv.log
python3 /scripts/server.py /tmp/srv.log >/dev/null 2>&1 & sleep 1
cat > "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json" <<JSON
{"captureStartUrl": "http://127.0.0.1:8765/", "captureCookieSource": "chromium:Default"}
JSON
chmod 600 "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json"
dbus-run-session -- sh -c '
  echo | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  export XDG_CURRENT_DESKTOP=GNOME
  chromium --headless=new --no-sandbox --disable-gpu --user-data-dir=$HOME/.config/chromium http://127.0.0.1:8765/set >/tmp/c.log 2>&1 &
  C=$!; sleep 45; kill -TERM $C; sleep 6
  python3 /scripts/inspect.py $HOME/.config/chromium/Default/Cookies
  Xvfb :99 -screen 0 1440x920x24 >/tmp/xvfb.log 2>&1 &
  export DISPLAY=:99; sleep 2
  "$@" >/tmp/app.log 2>&1 &
  APP=$!
  for i in $(seq 1 90); do W=$(xdotool search --name "^ScrapeLens$" 2>/dev/null | head -1); [ -n "$W" ] && break; sleep 1; done
  echo "app-running: $(kill -0 $APP 2>/dev/null && echo yes || echo no) after ${i}s"
  echo "$W" > /tmp/win.txt
  sleep ${APP_READY_WAIT:-20}
  echo "window=$W"
  for w in $(xdotool search --name "ScrapeLens" 2>/dev/null); do echo "candidate $w $(xdotool getwindowname $w 2>/dev/null)"; done
  W=$(xdotool search --name "^ScrapeLens$" 2>/dev/null | tail -1); echo "main window=$W"
  xdotool mousemove --window "$W" 700 300 click 1 2>/dev/null; sleep 1
  xdotool key --clearmodifiers ctrl+shift+r; echo "start sent"
  sleep 12; xwd -root -silent 2>/dev/null | convert xwd:- /out/after-start.png 2>/dev/null; echo "== processes after start"; ps -eo pid,comm,args | grep -E "chromium|scrapelens" | grep -v grep | cut -c1-200 | head -8
  sleep 13
  xdotool mousemove 1271 150 click 1; echo "stop button clicked"
  sleep 15
  xwd -root -silent 2>/dev/null | convert xwd:- /out/end.png 2>/dev/null; echo "== server log"; cat /tmp/srv.log 2>/dev/null; echo "== app stdout"; tail -5 /tmp/app.log 2>/dev/null
  echo "== session"; S=$(find $XDG_DATA_HOME -name session.json -path "*sessions*" | head -1); echo "$S"
  if [ -n "$S" ]; then grep -o "cookiesImported[^}]*" "$(dirname "$S")/cdp-events.jsonl" 2>/dev/null | head -2; grep -o "imported from[^\"]*" "$S" | head -2; fi
  echo "== app log"; grep -i "cookie\|error\|capture transport" /tmp/app.log | head -10
  kill $APP 2>/dev/null; pkill -f scrapelens 2>/dev/null; sleep 2
' sh "$@" >/out/e2e-raw.txt 2>&1; grep -v "dbus-daemon\|WARN\|keyring-daemon\|GNOME_KEYRING" /out/e2e-raw.txt; cp /tmp/app.log /out/app.log 2>/dev/null; cp /tmp/srv.log /out/srv.log 2>/dev/null; cp /tmp/xvfb.log /out/xvfb.log 2>/dev/null
