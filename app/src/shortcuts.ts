type Key = Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey" | "repeat">;
type State = { desktop: boolean; recording: boolean; busy: boolean; startUrlError: boolean };
/** GTK does not reliably dispatch native menu accelerators to the WebView. */
export function desktopShortcut(event: Key, isMac: boolean, state: State) {
  if (isMac || !event.ctrlKey || event.metaKey || event.altKey || event.repeat) return null;
  const key = event.key.toLowerCase();
  if (!event.shiftKey) return key === "." && state.recording && !state.busy ? "stop" : null;
  if (key === "c") return "copy";
  if (key === "d") return "demo";
  if (!state.desktop || state.recording || state.busy) return null;
  if (key === "r" && !state.startUrlError) return "start";
  if (key === "h") return "har";
  if (key === "n") return "netlog";
  return null;
}
