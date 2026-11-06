#!/bin/sh
# Inside the container: drives the packaged ScrapeLens under Xvfb (no user window).
# Env: PROXY_LINK (typed in the Proxy field), START_URL, coordinates PX PY (Proxy field),
# SX SY (Start session), TX TY (Stop), EX EY (Export / Sanitize…), OUT (folder for results).
# Usage: in-container.sh <launch command...>
set -u
export HOME=/home/tester/app
export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/.local/share XDG_CACHE_HOME=$HOME/.cache
export SCRAPELENS_TEST_MODE=0 APPIMAGE_EXTRACT_AND_RUN=1 NO_AT_BRIDGE=1 GDK_BACKEND=x11
rm -rf "$HOME"; mkdir -p "$XDG_CONFIG_HOME/app.scrapelens.desktop" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
cat > "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json" <<JSON
{"captureStartUrl": "$START_URL"}
JSON
chmod 600 "$XDG_CONFIG_HOME/app.scrapelens.desktop/preferences.json"
export PROXY_LINK START_URL OUT
dbus-run-session -- sh -c '
  echo | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  export XDG_CURRENT_DESKTOP=GNOME
  Xvfb :99 -screen 0 1440x920x24 >/tmp/xvfb.log 2>&1 &
  export DISPLAY=:99; sleep 2
  "$@" >/tmp/app.log 2>&1 &
  APP=$!
  for i in $(seq 1 90); do W=$(xdotool search --name "^ScrapeLens$" 2>/dev/null | tail -1); [ -n "$W" ] && break; sleep 1; done
  echo "app-running: $(kill -0 $APP 2>/dev/null && echo yes || echo no) window=$W"
  sleep 25
  xwd -root -silent 2>/dev/null | convert xwd:- "$OUT/01-launch.png" 2>/dev/null
  xdotool mousemove "$PX" "$PY" click 1; sleep 1
  xdotool type --delay 15 "$PROXY_LINK"; sleep 1; xdotool key Return; sleep 6
  xwd -root -silent 2>/dev/null | convert xwd:- "$OUT/02-proxy-set.png" 2>/dev/null
  xdotool mousemove "$SX" "$SY" click 1; echo "start clicked"; sleep 45
  xwd -root -silent 2>/dev/null | convert xwd:- "$OUT/03-started.png" 2>/dev/null
  xdotool mousemove "$TX" "$TY" click 1; echo "stop clicked"; sleep 20
  xwd -root -silent 2>/dev/null | convert xwd:- "$OUT/04-stopped.png" 2>/dev/null
  xdotool mousemove "$EX" "$EY" click 1; sleep 4
  xwd -root -silent 2>/dev/null | convert xwd:- "$OUT/05-export.png" 2>/dev/null
  kill $APP 2>/dev/null; pkill -x scrapelens 2>/dev/null; sleep 2
  cp -r "$XDG_DATA_HOME/app.scrapelens.desktop" "$OUT/app-data" 2>/dev/null
  cp -r "$XDG_CONFIG_HOME/app.scrapelens.desktop" "$OUT/app-config" 2>/dev/null
' sh "$@"
cp /tmp/app.log "$OUT/app.log" 2>/dev/null; cp /tmp/xvfb.log "$OUT/xvfb.log" 2>/dev/null
echo "in-container done"
