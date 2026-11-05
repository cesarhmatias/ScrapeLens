#!/bin/sh
# End to end on a packaged App: a real browser profile with a cookie made by a real navigation
# (keyring for Chromium-family, plain file for Firefox), preferences that select it, the App
# started by its own shortcut, then the server log and the session.
# Usage: e2e-app.sh <launch command...>
# Env: BROWSER=chromium|chrome|edge|firefox (the browser that made the cookie; the image's browser)
#      KEYRING=unlocked|locked|absent (Chromium-family only: keyring state when the App starts)
set -u
BROWSER=${BROWSER:-chromium}; KEYRING=${KEYRING:-unlocked}
export HOME=/home/tester/e2e
export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/.local/share XDG_CACHE_HOME=$HOME/.cache
export SCRAPELENS_TEST_MODE=0 APPIMAGE_EXTRACT_AND_RUN=1 NO_AT_BRIDGE=1 GDK_BACKEND=x11
case "$BROWSER" in
  chromium) BIN=chromium;              PROFILE_ROOT=.config/chromium;      SRC=chromium:Default ;;
  chrome)   BIN=google-chrome-stable;  PROFILE_ROOT=.config/google-chrome; SRC=chrome:Default ;;
  edge)     BIN=microsoft-edge-stable; PROFILE_ROOT=.config/microsoft-edge; SRC=edge:Default ;;
  firefox)  BIN=firefox-esr;           PROFILE_ROOT=.mozilla/firefox/sl.e2e; SRC=firefox:sl.e2e ;;
  *) echo "unknown BROWSER: $BROWSER" >&2; exit 2 ;;
esac
export BROWSER BIN PROFILE_ROOT KEYRING
rm -rf "$HOME"; mkdir -p "$XDG_CONFIG_HOME/app.scrapelens.desktop" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
cd /tmp && rm -f /tmp/srv.log
python3 /scripts/server.py /tmp/srv.log >/dev/null 2>&1 & sleep 1
cat > "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json" <<JSON
{"captureStartUrl": "http://127.0.0.1:8765/", "captureCookieSource": "$SRC"}
JSON
chmod 600 "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json"
dbus-run-session -- sh -c '
  echo | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  export XDG_CURRENT_DESKTOP=GNOME
  if [ "$BROWSER" = firefox ]; then
    mkdir -p "$HOME/$PROFILE_ROOT"
    MOZ_HEADLESS=1 "$BIN" --headless --no-remote --profile "$HOME/$PROFILE_ROOT" http://127.0.0.1:8765/set >/tmp/c.log 2>&1 &
    C=$!; sleep 40; kill -TERM $C; sleep 8
  else
    "$BIN" --headless=new --no-sandbox --disable-gpu --user-data-dir="$HOME/$PROFILE_ROOT" http://127.0.0.1:8765/set >/tmp/c.log 2>&1 &
    C=$!; sleep 45; kill -TERM $C; sleep 6
  fi
  DB=$(find "$HOME/$PROFILE_ROOT" \( -name Cookies -o -name cookies.sqlite \) -type f | head -1)
  echo "cookie database: $DB"
  python3 /scripts/inspect.py "$DB"
  if [ "$KEYRING" = locked ]; then
    # The keyring is restarted without its password: the login collection stays locked.
    pkill -x gnome-keyring-d; sleep 2; echo "keyring: restarted locked"
  fi
  APP_WRAP=""; [ "$KEYRING" = absent ] && APP_WRAP="env -u DBUS_SESSION_BUS_ADDRESS"
  Xvfb :99 -screen 0 1440x920x24 >/tmp/xvfb.log 2>&1 &
  export DISPLAY=:99; sleep 2
  $APP_WRAP "$@" >/tmp/app.log 2>&1 &
  APP=$!
  for i in $(seq 1 90); do W=$(xdotool search --name "^ScrapeLens$" 2>/dev/null | head -1); [ -n "$W" ] && break; sleep 1; done
  echo "app-running: $(kill -0 $APP 2>/dev/null && echo yes || echo no) after ${i}s"
  echo "$W" > /tmp/win.txt
  sleep ${APP_READY_WAIT:-20}
  echo "window=$W"
  W=$(xdotool search --name "^ScrapeLens$" 2>/dev/null | tail -1); echo "main window=$W"
  xdotool mousemove --window "$W" 700 300 click 1 2>/dev/null; sleep 1
  xdotool key --clearmodifiers ctrl+shift+r; echo "start sent"
  sleep 12; xwd -root -silent 2>/dev/null | convert xwd:- /out/after-start.png 2>/dev/null; echo "== processes after start"; ps -eo pid,comm,args | grep -E "chromium|chrome|firefox|scrapelens" | grep -v grep | cut -c1-200 | head -8
  sleep 13
  xdotool mousemove 1271 150 click 1; echo "stop button clicked"
  sleep 15
  xwd -root -silent 2>/dev/null | convert xwd:- /out/end.png 2>/dev/null; echo "== server log"; cat /tmp/srv.log 2>/dev/null; echo "== app stdout"; tail -5 /tmp/app.log 2>/dev/null
  echo "== session"; S=$(find $XDG_DATA_HOME -name session.json -path "*sessions*" | head -1); echo "$S"
  if [ -n "$S" ]; then grep -o "cookiesImported[^}]*" "$(dirname "$S")/cdp-events.jsonl" 2>/dev/null | head -2; grep -o "imported from[^\"]*" "$S" | head -2; fi
  echo "== app log"; grep -i "cookie\|error\|capture transport\|keyring\|secret" /tmp/app.log | head -10
  kill $APP 2>/dev/null; pkill -f scrapelens 2>/dev/null; sleep 2
' sh "$@" >/out/e2e-raw.txt 2>&1; grep -v "dbus-daemon\|WARN\|keyring-daemon\|GNOME_KEYRING" /out/e2e-raw.txt; cp /tmp/app.log /out/app.log 2>/dev/null; cp /tmp/srv.log /out/srv.log 2>/dev/null; cp /tmp/xvfb.log /out/xvfb.log 2>/dev/null
