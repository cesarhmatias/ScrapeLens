// Platform wording: a Linux desktop must not be told to look in /Applications or for a .app.
// Run: npm run test:platform-copy
import assert from "node:assert/strict";
import { chromeNotFoundCopy, chromePickerOptions } from "../src/listView";

const linuxCandidates = ["/opt/google/chrome/chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"];

// Linux: cites the real paths searched and the manual selection; no macOS wording.
const linux = chromeNotFoundCopy(linuxCandidates, false);
assert.equal(linux.title, "Chrome not found");
assert.doesNotMatch(linux.text, /\/Applications|\.app/);
assert.match(linux.text, /select the google-chrome or chromium executable manually/);
assert.equal(linux.detail, "Searched: /opt/google/chrome/chrome, /usr/bin/google-chrome, /usr/bin/chromium");
const linuxNone = chromeNotFoundCopy([], false);
assert.equal(linuxNone.detail, undefined, "no searched list is shown when there are no candidates");
assert.doesNotMatch(JSON.stringify(linuxNone), /\/Applications|\.app/);

// macOS: unchanged place and name.
const mac = chromeNotFoundCopy([], true);
assert.match(mac.text, /in \/Applications/);
assert.match(mac.text, /Google Chrome\.app/);
assert.equal(mac.detail, undefined);

// The picker: a folder or .app on macOS; an executable file on Linux.
const macPicker = chromePickerOptions(true);
assert.equal(macPicker.directory, true);
assert.match(macPicker.message, /Google Chrome\.app/);
const linuxPicker = chromePickerOptions(false);
assert.equal(linuxPicker.directory, false, "a Linux user picks the executable, not a folder");
assert.doesNotMatch(linuxPicker.message, /\.app|Contents\/MacOS/);
assert.match(linuxPicker.message, /google-chrome or chromium/);

console.log("platform-copy ok");
