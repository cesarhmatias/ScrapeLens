// Cookie import notice: undecryptable cookies and "no cookies for this domain" are shown
// differently; sessions without the report show nothing. Run: npm run test:cookie-import
import assert from "node:assert/strict";
import { cookieImportNotice, type CookieImportReport } from "../src/cookieImport";

const locked: CookieImportReport = {
  source: "Google Chrome — Default",
  domain: "example.test",
  importedCount: 1,
  skippedCount: 0,
  undecryptableCount: 1,
  undecryptableReason: "v11 cookie of Chromium: keyring is locked or has no entry for this browser: unlock it and try again (1)",
};

// Undecryptable cookies: a visible warning with the count, the reason and the action.
const warning = cookieImportNotice(locked);
assert.ok(warning);
assert.equal(warning.tone, "warning");
assert.match(warning.title, /1 cookie\(s\) from Google Chrome — Default could not be decrypted/);
assert.match(warning.detail, /1 imported\. v11 cookie of Chromium: keyring is locked/);
assert.match(warning.action ?? "", /Unlock the browser's keyring/);
assert.match(warning.action ?? "", /may be logged out/);

// Missing reason is still reported, without inventing one.
const noReason = cookieImportNotice({ ...locked, undecryptableReason: undefined });
assert.ok(noReason);
assert.match(noReason.detail, /The capture gave no reason\./);

// A browser was chosen and nothing was imported, with no error: say there are no cookies, not a failure.
const none = cookieImportNotice({
  source: "Brave — Default",
  domain: "example.test",
  importedCount: 0,
  skippedCount: 2,
  undecryptableCount: 0,
});
assert.ok(none);
assert.equal(none.tone, "info");
assert.equal(none.title, "No cookies for example.test in Brave — Default");
assert.match(none.detail, /not an error/);
assert.doesNotMatch(none.title, /fail|error/i);

// Given cookies (no browser): zero imported is not a message on its own.
assert.equal(
  cookieImportNotice({ source: "initialCookies", domain: "example.test", importedCount: 0, skippedCount: 0, undecryptableCount: 0 }),
  null,
);

// Normal import: nothing to say.
assert.equal(
  cookieImportNotice({ source: "Google Chrome — Default", domain: "example.test", importedCount: 3, skippedCount: 1, undecryptableCount: 0 }),
  null,
);

// Sessions from older captures: no report, no notice.
assert.equal(cookieImportNotice(undefined), null);
assert.equal(cookieImportNotice(null), null);

console.log("cookie-import ok");
