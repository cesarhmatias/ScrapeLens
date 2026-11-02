import assert from "node:assert/strict";
import { MAX_URL_LEN, trimUrl, persistableUrl, resolveCaptureStartUrl, validateHttpUrl } from "../src/captureUrl.ts";

assert.equal(resolveCaptureStartUrl("").ok && resolveCaptureStartUrl("").url, "about:blank");
assert.equal(resolveCaptureStartUrl("  ").ok && resolveCaptureStartUrl("  ").url, "about:blank");
assert.equal(resolveCaptureStartUrl("http://127.0.0.1:8781/page").ok, true);
assert.equal(validateHttpUrl("https://example.com/a").ok, true);
assert.equal(validateHttpUrl("about:blank").ok, false);
assert.equal(validateHttpUrl("file:///tmp/x").ok, false);
assert.equal(validateHttpUrl("http:// spaced").ok, false);
assert.equal(validateHttpUrl("http://").ok, false);

for (const bad of [
  "http://user:pw@example.com/",
  "http://user@example.com",
  "http://@",
  "http:///",
  "http://:80/",
  "http://exa\u0000mple.com",
  "http://exa\u0007mple.com",
  "http://exa\u200Bmple.com",
  "http://\uFEFFexample.com",
  "http://example.com:99999/",
  "http://[::1/",
  `http://e.com/${"a".repeat(MAX_URL_LEN)}`,
]) {
  assert.equal(validateHttpUrl(bad).ok, false, `deveria recusar ${JSON.stringify(bad)}`);
}
assert.equal(validateHttpUrl("http://[::1]:8080/x").ok, true);
assert.equal(validateHttpUrl("https://example.com:443/a?b=1#c").ok, true);
const persisted = persistableUrl("https://example.com:8443/a/b?token=SECRET#frag");
assert.equal(persisted.ok && persisted.url, "https://example.com:8443/a/b");
const bare = persistableUrl("http://h?x=1");
assert.equal(bare.ok && bare.url, "http://h");

for (const raw of ["\u0085http://h/a", "http://h/a\u0085", "\uFEFFhttp://h/a", "http://h/a\uFEFF"]) {
  const r = resolveCaptureStartUrl(raw);
  assert.equal(r.ok && r.url, "http://h/a", JSON.stringify(raw));
  assert.equal(trimUrl(raw), "http://h/a");
}
assert.equal(validateHttpUrl("http://h\uFEFF/a").ok, false);

console.log("capture-url.test.ts: ok");
