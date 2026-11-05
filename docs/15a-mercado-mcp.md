# Round 11 — market research: MCP for capture and browser (2026-10-31)

Web research done by a research agent at the leader's request. Stars read on 31/10/2026; what is marked "not verified" had no primary source.

## Main findings
- No MCP examined documents preservation of header ORDER. That space belongs to ScrapeLens, through NetLog.
- Chrome DevTools MCP (Google, Apache-2.0): paginated `list_network_requests` and `get_network_request` with the body inline or in a file. Connects to an already-open Chrome. Not stealth.
- Playwright MCP (Microsoft, Apache-2.0): opt-in network (`--caps=network`), `--cdp-endpoint`, `--executable-path`, stdio or HTTP. Not stealth.
- browser-use and Stagehand: high-level agents, dependent on an LLM and the cloud, with no network tool. Avoid the model.
- Proxyman MCP (commercial): the best security design seen. Bind on 127.0.0.1, per-session token in a 0600 file, redaction on by default and read tools separate from write tools.
- mitmproxy-MCP, har-mcp, Burp and Charles: small or community-driven. Good patterns: redaction by default and write tools only with opt-in.
- Reference Puppeteer MCP: archived. Avoid.

## CloakBrowser (to be confirmed by Capture, phase A)
- It is a Python/JS wrapper (MIT) around a Chromium binary with C++ patches. The binary has its own license, with no redistribution.
- The free build for macOS is Chromium 145. From v148 on it requires a license key; the free one allows 1 session. The license is validated at cloakbrowser.dev, and there is an update check.
- Exposes CDP (`--remote-debugging-port`, cloakserve on port 9222). Whether it accepts `--log-net-log` and `Target.setAutoAttach`: not verified.
- The README admits that CDP commands leak detectable signals (reCAPTCHA). That conflicts with intercepting via CDP. NetLog is passive: it is the candidate for primary capture in stealth mode.
- Risks: open detection issues (#614, #598, #611, #602), crash on macOS arm64 (#575), ad-hoc signature (Gatekeeper blocks it). It cannot be embedded: ScrapeLens must locate a binary installed by the user.

## Design patterns to adopt
- List and detail by ID, with explicit handles (`session_id`, `request_id`) in every call.
- Own pagination (`cursor`/`has_more`, 25 to 50 items), `structuredContent` with `outputSchema`, and `resource_link` for large bodies.
- Resources for sessions and bodies (`scrapelens://session/{id}/request/{rid}/body`); tools for search, comparison and actions.
- Security:
  - redaction on by default, with opt-in for real values;
  - local bind with token;
  - `readOnlyHint` and `destructiveHint`, which the specification treats as untrusted;
  - confirmation (elicitation) for actions with side effects;
  - domain allowlist.
- Stdio transport by default; optional local HTTP. rmcp SDK (official Rust), which fits the Tauri backend.

## Proposed initial tools
1. list_sessions
2. import_capture(path, kind)
3. list_requests(session_id, filters, cursor, limit)
4. get_request(session_id, request_id, redact=true): headers in order, with the source of the order
5. get_body(request_id, part, range, decode)
6. search_bodies(session_id, query, regex, scope)
7. diff_requests(a, b, ignore[])
8. diff_sessions(a, b, match_by)
9. get_cookies_and_tokens(session_id, redact): origin of each cookie and token
10. browser_launch(engine=chrome|cloak, binary_path, proxy, capture=cdp|netlog|both): asks for confirmation
11. browser_navigate(browser_id, url): allowlist and confirmation
12. browser_act(browser_id, action, ref, value)
13. browser_stop(browser_id): finalizes the capture
14. generate_priming_script(session_id, target_request_id)
15. validate_run(session_id, script_ref): runs with confirmation

## Sources
- https://github.com/ChromeDevTools/chrome-devtools-mcp
- https://github.com/microsoft/playwright-mcp
- https://github.com/browser-use/browser-use
- https://github.com/browserbase/stagehand
- https://github.com/lups2000/mitmproxy-MCP
- https://github.com/tjamet/har-mcp
- https://github.com/PortSwigger/mcp-server
- https://proxyman.com/docs/mcp
- https://github.com/CloakHQ/CloakBrowser
- https://modelcontextprotocol.io/specification/latest/server/tools
- https://github.com/modelcontextprotocol/rust-sdk
