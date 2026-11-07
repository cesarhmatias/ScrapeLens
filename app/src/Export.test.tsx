/// <reference types="node" />
import * as React from "react";
import assert from "node:assert/strict";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { SanitizeDialog } from "./Export";
import { bridge, type SanitizePreview } from "./bridge";
import type { SessionRecord } from "./types";

Object.assign(globalThis, { React, IS_REACT_ACT_ENVIRONMENT: true,
  window: { addEventListener() {}, removeEventListener() {} } });
const calls: unknown[][] = [];
bridge.previewSanitized = async (dir, sensitive = false) => {
  calls.push(["preview", dir, sensitive]);
  return { sessionId: "fixture", originalDir: dir, suggestedDestination: sensitive ? "/out/full" : "/out/sanitized",
    requests: 1, redactions: [], totalRedactions: 0, warnings: [], omittedAttachments: [],
    attachmentsKept: 0, rawArtifactsDropped: [], includeSensitive: sensitive,
    rawArtifactsKept: sensitive ? ["netlog.json"] : [] } satisfies SanitizePreview;
};
bridge.saveSanitized = async (dir, destination, sensitive) => {
  calls.push(["save", dir, destination, sensitive]);
  return null;
};
let renderer: ReactTestRenderer;
await act(async () => { renderer = create(<SanitizeDialog session={{ id: "fixture", sourcePath: "/capture", sourceToken: "tok-capture" } as SessionRecord}
  onClose={() => {}} onOpened={() => {}} />); });
const root = renderer!.root;
const checkbox = () => root.findByProps({ "data-testid": "sanitize-include-sensitive" });
const destination = () => root.findByProps({ "aria-label": "Export destination" });
assert.equal(checkbox().props.checked, false);
assert.deepEqual(calls[0], ["preview", "tok-capture", false]);
await act(async () => { checkbox().props.onChange({ target: { checked: true } }); });
assert.deepEqual(calls.at(-1), ["preview", "tok-capture", true]);
assert.equal(destination().props.value, "/out/full");
assert.equal(root.findByProps({ role: "alert" }).props.className, "export-warning");
const confirm = root.findAllByType("button").find(b => b.props.children === "Export full capture")!;
await act(async () => { await confirm.props.onClick(); });
assert.deepEqual(calls.at(-1), ["save", "tok-capture", "/out/full", true]);
await act(async () => { checkbox().props.onChange({ target: { checked: false } }); });
assert.equal(destination().props.value, "/out/sanitized");
await act(async () => { destination().props.onChange({ target: { value: "/custom/destination" } }); });
await act(async () => { checkbox().props.onChange({ target: { checked: true } }); });
assert.equal(destination().props.value, "/custom/destination");
await act(async () => { renderer!.unmount(); });
console.log("Export.test: checkbox, preview, save and destination preservation ok");
