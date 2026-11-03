import assert from "node:assert/strict";
import { desktopShortcut } from "../src/shortcuts";
const ready = { desktop: true, recording: false, busy: false, startUrlError: false };
const event = { key: "R", ctrlKey: true, metaKey: false, altKey: false, shiftKey: true, repeat: false };
for (const [key, action] of [["R", "start"], ["H", "har"], ["N", "netlog"], ["D", "demo"], ["C", "copy"]]) {
  assert.equal(desktopShortcut({ ...event, key }, false, ready), action);
  assert.equal(desktopShortcut({ ...event, key }, true, ready), null);
}
for (const key of ["R", "H", "N"]) {
  for (const state of [{ ...ready, desktop: false }, { ...ready, recording: true }, { ...ready, busy: true }])
    assert.equal(desktopShortcut({ ...event, key }, false, state), null);
}
assert.equal(desktopShortcut(event, false, { ...ready, startUrlError: true }), null);
const stop = { ...event, key: ".", shiftKey: false };
assert.equal(desktopShortcut(stop, false, { ...ready, recording: true }), "stop");
assert.equal(desktopShortcut(stop, false, ready), null);
assert.equal(desktopShortcut(stop, false, { ...ready, recording: true, busy: true }), null);
for (const change of [{ ctrlKey: false }, { altKey: true }, { metaKey: true }, { repeat: true }, { shiftKey: false }])
  assert.equal(desktopShortcut({ ...event, ...change }, false, ready), null);
console.log("shortcuts: ok");
