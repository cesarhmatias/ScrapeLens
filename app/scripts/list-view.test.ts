// Demo list and recording badge (round 13). Run: npm run test:list-view
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { adaptSession, summaryOfRecord } from "../src/v1/adapter";
import type { SessionV1 } from "../src/v1/types";
import { activeFilterLabels, outcomeChipDisabled, sessionIsRecording } from "../src/listView";

const demo = JSON.parse(readFileSync(new URL("../src/demo/session.v1.json", import.meta.url), "utf8")) as SessionV1;
const { session } = adaptSession(demo);
// The demo is in memory (not paged): the list comes from the local summaries, all visible without a filter.
assert.equal(session.paged, false);
assert.equal(session.requests.map(summaryOfRecord).length, session.requestCount);
assert.equal(session.requestCount, 13);

// Verdict chips with 0 must not be switchable on (it was the "0 of 13" in the screenshot); active ones stay switchable.
assert.equal(outcomeChipDisabled(0, false), true);
assert.equal(outcomeChipDisabled(0, true), false);
assert.equal(outcomeChipDisabled(3, false), false);

const none = { query: "", typeFilter: "all", targetFilter: "all", protocol: "all", failFilter: false, blockFilter: false };
assert.deepEqual(activeFilterLabels(none), []);
assert.deepEqual(activeFilterLabels({ ...none, failFilter: true, blockFilter: true }), ["Application failures", "Possible blocks?"]);

// "Recording" badge: separate from the displayed session.
const rec = { sessionDir: "/x/sessions/capture-1" };
assert.equal(sessionIsRecording({ synthetic: true }, rec), false, "the demo never gets the badge");
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/other" }, rec), false);
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/capture-1/" }, rec), true);
assert.equal(sessionIsRecording({ sourcePath: "/x/sessions/capture-1" }, null), false);
console.log("list-view ok");

// Caveat (b): opening a session of 20,002 requests makes at most 2 list_requests calls up to the first screen.
import { PagedList, pagesFor } from "../src/listView";
assert.deepEqual(pagesFor(0, 30, undefined, 2000), [0]);
assert.deepEqual(pagesFor(0, 30, 20002, 2000), [0, 1]);
assert.deepEqual(pagesFor(0, 30, 13, 2000), [0]);
assert.deepEqual(pagesFor(0, 0, 0, 2000), []);
assert.deepEqual(pagesFor(19990, 20002, 20002, 2000), [9, 10]);

await (async () => {
  const total = 20002;
  const seen: number[] = [];
  let renders = 0;
  const list = new PagedList<number, { matched: number }>(
    async (offset, limit) => {
      seen.push(offset);
      const rows = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, i) => offset + i);
      return { meta: { matched: total }, rows };
    },
    2000,
    () => {
      renders++;
      list.ensure(0, 30); // each re-render asks again for the visible window
    },
  );
  // Mount: three consecutive renders (StrictMode/effects) must not multiply the calls.
  list.ensure(0, 30);
  list.ensure(0, 30);
  list.ensure(0, 30);
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  assert.ok(list.calls <= 2, `list_requests up to the first screen: ${list.calls}`);
  assert.deepEqual(seen, [0, 2000]);
  assert.equal(list.length, total);
  assert.equal(list.row(0), 0);
  assert.equal(list.row(2001), 2001);
  assert.ok(renders >= 1);
  // Scrolling to the end fetches only the window's pages (+ spare), not the intermediate ones.
  list.ensure(19990, 20002);
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(seen, [0, 2000, 18000, 20000]);
})();
console.log("paged-window ok");

// Round 14: shortcuts on Linux appear as Ctrl+/Shift+.
import { shortcutLabel } from "../src/listView";
assert.equal(shortcutLabel("⌘⇧R", true), "⌘⇧R");
assert.equal(shortcutLabel("⌘⇧R", false), "Ctrl+Shift+R");
assert.equal(shortcutLabel("⌘.", false), "Ctrl+.");
console.log("shortcut-label ok");
