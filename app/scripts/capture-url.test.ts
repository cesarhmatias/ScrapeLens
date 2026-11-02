import assert from "node:assert/strict";
import { resolveCaptureStartUrl, validateHttpUrl } from "../src/captureUrl.ts";

assert.equal(resolveCaptureStartUrl("").ok && resolveCaptureStartUrl("").url, "about:blank");
assert.equal(resolveCaptureStartUrl("  ").ok && resolveCaptureStartUrl("  ").url, "about:blank");
assert.equal(resolveCaptureStartUrl("http://127.0.0.1:8781/page").ok, true);
assert.equal(validateHttpUrl("https://example.com/a").ok, true);
assert.equal(validateHttpUrl("about:blank").ok, false);
assert.equal(validateHttpUrl("file:///tmp/x").ok, false);
assert.equal(validateHttpUrl("http:// spaced").ok, false);
assert.equal(validateHttpUrl("http://").ok, false);

console.log("capture-url.test.ts: ok");
