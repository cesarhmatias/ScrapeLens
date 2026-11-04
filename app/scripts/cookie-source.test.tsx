import * as React from "react";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CookieSourceSelect } from "../src/CookieSourceSelect";
const props = {
  sources: [{ id: "chrome:Default", browser: "Google Chrome", profile: "Default", label: "Google Chrome — Default", kind: "chromium" as const }],
  value: "chrome:Default", startUrl: "", disabled: false, onChange: () => {},
};
const blank = renderToStaticMarkup(<CookieSourceSelect {...props} />);
assert.match(blank, /aria-label="Import cookies from browser"/);
assert.match(blank, /No cookies \(clean session\)/);
assert.match(blank, /value="chrome:Default" selected=""/);
assert.match(blank, /Enter the start URL to import cookies/);
assert.match(blank, /With an empty URL, capture uses a clean session/);
const withUrl = renderToStaticMarkup(<CookieSourceSelect {...props} startUrl="https://example.org" disabled />);
assert.match(withUrl, /disabled=""/);
assert.doesNotMatch(withUrl, /id="cookie-source-hint"/);
const clean = renderToStaticMarkup(<CookieSourceSelect {...props} sources={[]} value="" />);
assert.doesNotMatch(clean, /cookie-source-hint/);
assert.match(clean, /value="" selected=""/);
console.log("cookie-source: ok");
