// Proxy field and session header rules. The UI never receives credentials: these tests use
// the same shapes the backend returns (server address and the authenticated flag only).
// Run: npm run test:proxy-field
import assert from "node:assert/strict";
import {
  PROXY_PLACEHOLDER,
  proxyFieldView,
  proxyHeaderView,
  proxyStartBlock,
  proxyStatusText,
  type ProxyInfo,
  type ProxyState,
} from "../src/proxyRules";

const active: ProxyInfo = { serverUrl: "http://proxy.example:8080", scheme: "http", host: "proxy.example", port: 8080, authenticated: true };
const empty: ProxyState = { saved: null, active: null, needsLink: false };

// Field states
assert.deepEqual(proxyFieldView(null), { kind: "empty" });
assert.deepEqual(proxyFieldView(empty), { kind: "empty" });
assert.deepEqual(proxyFieldView({ saved: null, active, needsLink: false }), {
  kind: "active",
  serverUrl: "http://proxy.example:8080",
  authenticated: true,
});
// Reopened app: the address is shown, the password must be typed again.
const reopened: ProxyState = { saved: "http://proxy.example:8080", active: null, needsLink: true };
assert.deepEqual(proxyFieldView(reopened), { kind: "needs-link", serverUrl: "http://proxy.example:8080" });
assert.match(proxyStartBlock(reopened, false) ?? "", /password is not kept between runs/);
assert.equal(proxyStartBlock(reopened, true), null, "while recording the start guard does not add a second message");
assert.equal(proxyStartBlock({ saved: active.serverUrl, active, needsLink: false }, false), null);
assert.equal(proxyStartBlock(empty, false), null, "no proxy: nothing changes");

// Status line: the active proxy is stated in full, with its credential fact and no secret.
const on = proxyStatusText({ saved: null, active, needsLink: false });
assert.equal(on.tone, "on");
assert.equal(on.text, "Using http://proxy.example:8080 · with credentials (kept in memory until the app closes)");
const onOpen = proxyStatusText({ saved: null, active: { ...active, authenticated: false, serverUrl: "http://proxy.example:3128", port: 3128 }, needsLink: false });
assert.equal(onOpen.text, "Using http://proxy.example:3128 · no credentials");
const warn = proxyStatusText(reopened);
assert.equal(warn.tone, "warn");
assert.match(warn.text, /^Saved http:\/\/proxy\.example:8080\. Enter the full link again/);
assert.equal(proxyStatusText(empty).text, "No proxy: the capture connects directly.");
for (const status of [on, onOpen, warn]) assert.doesNotMatch(status.text, /password=|user:|@/);

// The placeholder is an example, never a real host with credentials.
assert.match(PROXY_PLACEHOLDER, /^http:\/\/user:password@proxy\.example:8080$/);

// Session header: sessions without capture.proxy show nothing new.
assert.equal(proxyHeaderView(undefined), null);
assert.equal(proxyHeaderView(null), null);

// Full record (live capture): address, authentication flag and route, no credentials anywhere.
const full = proxyHeaderView({ scheme: "socks5", host: "10.0.0.5", port: 1080, authenticated: true, route: "relay" });
assert.ok(full);
assert.equal(full.address, "socks5://10.0.0.5:1080");
assert.equal(full.authenticated, true);
assert.match(full.routeText, /local relay/);
assert.match(full.http3Note, /HTTP\/3 is not used through a proxy/);

// Sanitized export: scheme and authentication only.
const sanitized = proxyHeaderView({ scheme: "http", authenticated: false });
assert.ok(sanitized);
assert.equal(sanitized.address, "http");
assert.equal(sanitized.authenticated, false);
assert.match(sanitized.routeText, /not recorded/);

// Direct route and IPv6 host.
const direct = proxyHeaderView({ scheme: "http", host: "::1", port: 3128, authenticated: false, route: "direct" });
assert.ok(direct);
assert.equal(direct.address, "http://[::1]:3128");
assert.match(direct.routeText, /direct to the proxy/);

console.log("proxy-field ok");
