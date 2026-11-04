import * as React from "react";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CookieSourceSelect } from "../src/CookieSourceSelect";
const props = {
  sources: [{ id: "chrome:Default", browser: "Google Chrome", profile: "Default", label: "Google Chrome — Default", kind: "chromium" as const }],
  value: "chrome:Default", startUrl: "", disabled: false, onChange: () => {},
};
const blank = renderToStaticMarkup(<CookieSourceSelect {...props} />);
assert.match(blank, /aria-label="Importar cookies do navegador"/);
assert.match(blank, /Sem cookies \(sessão limpa\)/);
assert.match(blank, /value="chrome:Default" selected=""/);
assert.match(blank, /Informe a URL inicial para importar cookies/);
assert.match(blank, /Com URL vazia, a captura usa sessão limpa/);
const withUrl = renderToStaticMarkup(<CookieSourceSelect {...props} startUrl="https://example.org" disabled />);
assert.match(withUrl, /disabled=""/);
assert.doesNotMatch(withUrl, /id="cookie-source-hint"/);
const clean = renderToStaticMarkup(<CookieSourceSelect {...props} sources={[]} value="" />);
assert.doesNotMatch(clean, /cookie-source-hint/);
assert.match(clean, /value="" selected=""/);
console.log("cookie-source: ok");
