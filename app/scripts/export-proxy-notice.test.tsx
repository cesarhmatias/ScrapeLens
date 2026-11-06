/// <reference types="node" />
// The Export / Sanitize dialog shows the proxy notice only for a session captured through a proxy.
// Run: npm run test:export-proxy-notice
import * as React from "react";
import assert from "node:assert/strict";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { SanitizeDialog } from "../src/Export";
import { bridge, type SanitizePreview } from "../src/bridge";
import type { SessionRecord } from "../src/types";

Object.assign(globalThis, { React, IS_REACT_ACT_ENVIRONMENT: true,
  window: { addEventListener() {}, removeEventListener() {} } });
bridge.previewSanitized = async (dir) => ({ sessionId: "fixture", originalDir: dir, suggestedDestination: "/out/sanitized",
  requests: 1, redactions: [], totalRedactions: 0, warnings: [], omittedAttachments: [],
  attachmentsKept: 0, rawArtifactsDropped: [], includeSensitive: false, rawArtifactsKept: [] } satisfies SanitizePreview);

function visibleText(node: { children: Array<string | ReactTestRenderer["root"]> }): string {
  return node.children.map((child) => (typeof child === "string" ? child : visibleText(child as never))).join("");
}

async function render(proxy: SessionRecord["capture"]["proxy"] | undefined): Promise<ReactTestRenderer> {
  let renderer!: ReactTestRenderer;
  const session = { id: "fixture", sourcePath: "/capture", capture: { cdpEvents: 0, status: "closed", proxy } } as unknown as SessionRecord;
  await act(async () => {
    renderer = create(<SanitizeDialog session={session} onClose={() => {}} onOpened={() => {}} />);
  });
  return renderer;
}

// Without a proxy: no notice at all (the dialog is unchanged).
{
  const renderer = await render(undefined);
  assert.equal(renderer.root.findAll((node) => node.props["data-testid"] === "export-proxy-notice").length, 0);
  await act(async () => renderer.unmount());
}

// With a proxy: a note, without host or credentials.
{
  const renderer = await render({ scheme: "http", host: "proxy.example", port: 8080, authenticated: true, route: "relay" });
  const notes = renderer.root.findAll((node) => node.props["data-testid"] === "export-proxy-notice");
  assert.equal(notes.length, 1);
  assert.equal(notes[0].props.role, "note");
  const text = visibleText(notes[0]);
  assert.match(text, /captured through a proxy/);
  assert.doesNotMatch(text, /proxy\.example|8080|@/);
  await act(async () => renderer.unmount());
}

console.log("export-proxy-notice ok");
