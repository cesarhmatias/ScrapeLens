<div align="center">

# 🔍 ScrapeLens

**Local high-fidelity HTTP session inspector and MCP server for reverse engineering web flows and scraping.**

[![Release](https://img.shields.io/github/v/release/cesarhmatias/ScrapeLens?style=flat-square&color=0066cc)](https://github.com/cesarhmatias/ScrapeLens/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20(arm64)%20%7C%20Linux%20(amd64%2C%20arm64)-lightgrey?style=flat-square)](src-tauri/PACKAGING.md)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange?style=flat-square&logo=rust)](core/Cargo.toml)
[![Tauri 2](https://img.shields.io/badge/Tauri-2.0-24c8db?style=flat-square&logo=tauri)](src-tauri/tauri.conf.json)
[![MCP](https://img.shields.io/badge/MCP-15%20Tools-8a2be2?style=flat-square)](docs/16-mcp-contract.md)

[Installation](#-installation-and-packages) •
[Highlights](#-key-features) •
[Desktop App](#-desktop-app-usage) •
[MCP Server](#-mcp-server-for-llm-agents) •
[Architecture](#-repository-architecture) •
[Development](#-development-and-build) •
[License](#-license)

</div>

---

**ScrapeLens** captures traffic from Chromium browsers (Chrome, Chromium, Brave, Arc, Edge) by combining **Chrome DevTools Protocol (CDP)** over a pipe with a streaming **NetLog**, or imports existing **HAR** and **NetLog** files. Unlike conventional tools that normalize headers into dictionaries, ScrapeLens preserves the **exact sequence reported by the source**, duplicate headers, original capitalization, HTTP/2 and HTTP/3 pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`), redirect chains, network attempts and **explicit per-field provenance**.

Built with **Tauri 2 + React/TypeScript + Rust**, it runs **100% locally**, with no external sidecars, no cloud and **no telemetry**.

![ScrapeLens main interface with a real capture from a local test server](docs/screenshots/live-capture-main.png)

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Protocol Fidelity & Provenance** | Preserves ordered header arrays with duplicates and original case. Visually distinguishes between order **verified on the wire** (`NetLog` / `headersText` HTTP/1.1) and **unverified** order (CDP/HAR objects). |
| **Multi-Target Capture over Pipe (`fd 3`/`fd 4`)** | Automatically attaches to pages, popups, cross-origin `iframes` (`OOPIF`), Service Workers and Shared Workers using the native DevTools pipe (`--remote-debugging-pipe`), without opening local TCP ports by default. |
| **Browser Cookie Import** | Optionally imports and decrypts in memory the cookies of an existing session (Chrome, Brave, Arc, Edge, Chromium, Firefox or Safari on macOS/Linux) before the first navigation, so the capture starts already authenticated. |
| **Origin Tracing and Priming** | Traces where each cookie, CSRF token, ViewState or dynamic parameter came from throughout the session and generates multi-step **priming** Python scripts (`requests.Session`) with no embedded secrets. |
| **Protocol Adapters (Natural for Ajax)** | Decodes, compares and re-encodes legacy protocols based on XML/dynamic forms (`adapters/natural-ajax` — e.g. `natparamext`, `F-STAMP`, `SUBPAGE`), with built-in execution validation. |
| **Sanitized or Full Export** | Generate `cURL` commands and Python scripts per request, or export the whole session: **sanitized by default** (redacting cookies, tokens, passwords and omitting raw events) or a **full capture with sensitive data** upon explicit confirmation (checkbox in the UI or `include_sensitive: true` in MCP). |
| **Native MCP Server (`scrapelens-mcp`)** | Exposes **15 MCP tools** over `stdio` so AI agents can inspect sessions, search bodies, trace tokens, compare requests, export captures and drive the browser with human confirmation (MCP elicitation). |
| **Scalability for Large Sessions** | Streaming NetLog parser (`O(HTTP requests)`), deduplicated attachment storage with safe writes (`0700`/`0600`, `O_NOFOLLOW`), backend pagination and a virtualized list in the front end. |

<details>
<summary><b>📸 See more screenshots</b></summary>
<br>

| Verified Detail (Headers in Source Order) | Side-by-Side Comparison (Diff) |
|---|---|
| ![Verified detail](docs/screenshots/live-request-detail-headers.png) | ![Comparison](docs/screenshots/live-compare-requests.png) |

| Application Timeline (Cookie Chain) | Export / Sanitize Dialog |
|---|---|
| ![Timeline](docs/screenshots/live-timeline.png) | ![Export](docs/screenshots/live-export-sanitize-dialog.png) |

These screenshots are real captures: headless Chrome 156 with a dedicated test profile, against the local ScrapeLens test server (`127.0.0.1:9781`, page `/page`). The top-bar screenshot was captured through a local test HTTP proxy (`127.0.0.1:9790`, no credentials) to show the **Proxy** field and the session header. The `/private/tmp/...` path in the export dialog is the temporary session folder of that run.

</details>

---

## 📦 Installation and Packages

Download the pre-built binaries from the [**Releases**](https://github.com/cesarhmatias/ScrapeLens/releases) tab:

- **macOS (Apple Silicon `arm64`)**: `ScrapeLens-0.1.3-macos-arm64.zip` (`ScrapeLens.app`)
- **Linux (`x86_64` / `amd64`)**: `ScrapeLens_0.1.3_amd64.deb` and `ScrapeLens_0.1.3_amd64.AppImage`
- **Linux (`aarch64` / `arm64`)**: `ScrapeLens_0.1.3_arm64.deb` and `ScrapeLens_0.1.3_aarch64.AppImage`

### Running on macOS

Unzip `ScrapeLens.app` (or use the bundle built at `src-tauri/target/release/bundle/macos/ScrapeLens.app`) and move it to `/Applications` or open it from the terminal:

```sh
open src-tauri/target/release/bundle/macos/ScrapeLens.app
```

> **Note on signing:** The package uses local signing (`ScrapeLens Local Signing` / ad-hoc), without Apple notarization. If Gatekeeper blocks the first launch, run `xattr -dr com.apple.quarantine /Applications/ScrapeLens.app` or open it via secondary click → **Open**. Details and `SHA-256` hashes in [`src-tauri/PACKAGING.md`](src-tauri/PACKAGING.md).

---

## 🖥️ Desktop App Usage

1. **Capture a live session**:
   - Optionally enter the **Start URL** and, if you want to start already logged in, select the source browser in the **Cookies** menu (or keep `No cookies (clean session)`).
   - Click **Start session**. ScrapeLens will open an isolated Chrome instance with a temporary profile (`0700`).
   - Run the desired flow in the browser and click **Stop** in ScrapeLens.
   - **macOS Keychain prompt:** the first time cookies are imported from a browser, macOS asks to allow access to that browser's *Safe Storage* key. Click **Allow**, not **Always Allow**: *Always Allow* gives the `security` tool permanent access, so any program that runs it can read the key. <!-- Remove this note when Keychain access moves into ScrapeLens itself (T09). -->
2. **Open or Import** (`⌘O`):
   - Open a native session folder (`session.json`) with **Open capture…**, or import **HAR** and **NetLog** files with the dedicated **HAR** and **NetLog** buttons in the top bar.
3. **Inspect and Search**:
   - Filter by text, method, status, protocol, MIME type or target (`target`).
   - Use the search field with the body scopes (**req. body**, **resp. body**) to locate JSON keys, form parameters, regex or values in headers/cookies/payloads.
   - Inspect **Raw headers**, **Cookies**, **Payload**, **Response**, **Redirects**, **Attempts**, **Origin** and **Timeline**.
4. **Compare and Trace**:
   - Click **Compare…** for a structural diff between two requests of the same session, or **Compare captures…** for different sessions.
5. **Export and Sanitize**:
   - On any request, click **Export…** to generate `cURL`, a `Python (requests)` script or a **Priming script** (with optional support for the `Natural for Ajax` wrapper), plus **Validate execution…** against the target.
   - In the top bar, click **Export / Sanitize…** to write a copy of the session to disk (`0700`/`0600`):
     - **Unchecked (default):** generates `<session>-sanitized` with conservative redaction of secrets and removal of raw events.
     - **Checked (`Include sensitive data`):** generates `<session>-full`, fully preserving cookies, tokens, bodies and the raw files (`cdp-events.jsonl`, `netlog.json`, `cdp-bodies.jsonl`).

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `⌘O` / `Ctrl+O` | Open session folder |
| `⌘F` / `Ctrl+F` | Focus request search |
| `⌘⇧C` / `Ctrl+Shift+C` | Copy the selected request's URL |
| `↑` / `↓` | Navigate the request list |
| `Esc` | Close modal / clear selection |

---

## 🌐 Proxy

Optional: one proxy link sends the whole capture through that proxy. Use the **Proxy** field next to *Start URL* and *Cookies*; its status line shows the server in use. In MCP, `start_capture` takes the same `proxy` value.

Accepted links:

| Form | Meaning |
|---|---|
| `http://[user:pass@]host[:port]` | HTTP proxy (default port 80) |
| `https://[user:pass@]host[:port]` | Proxy reached over TLS (default port 443) |
| `socks5://[user:pass@]host[:port]`, `socks5h://…` | SOCKS5, with remote DNS (default port 1080) |
| `[user:pass@]host:port` | No scheme: same as `http://` |
| `host:port:user:pass` | Common provider format: same as `http://user:pass@host:port` |

- **MCP:** prefer `proxy: "env"`, which reads the link from the server's `SCRAPELENS_PROXY_URL` variable, so the password never passes through the model. The variable is ignored unless `"env"` is requested.
- **App:** the password is kept in memory until the app closes. After a restart, the saved server is shown and the link must be typed again.
- **Limits:**
  - No HTTP/3 through a proxy; the session says so.
  - The password is never saved to disk, and never appears in the session files, exports, or logs.
  - Exported cURL, Python and priming scripts do not use the proxy, so they can leave from another IP.
  - Loopback targets are not sent through the proxy.
  - Validated with local test proxies, not against commercial providers.

Details: [`docs/22-proxy.md`](docs/22-proxy.md).

---

## 🤖 MCP Server for LLM Agents

The `scrapelens-mcp` binary implements the **Model Context Protocol (MCP)** over `stdio`, allowing AI assistants (Claude Desktop, Cursor, OpenCode, etc.) to analyze captures and run reverse-engineering sessions with protection against accidental leakage of secrets.

### Configuring an MCP client (no build needed)

The MCP server ships inside the ScrapeLens App, with the same version (0.1.3). Point the client at the App's own executable with the `mcp` subcommand; nothing has to be compiled.

| Package | Command the client runs |
|---|---|
| macOS `ScrapeLens.app` | `/Applications/ScrapeLens.app/Contents/MacOS/scrapelens mcp --sessions-dir <dir>` |
| Linux `.deb` | `/usr/bin/scrapelens mcp --sessions-dir <dir>` |
| Linux AppImage | `/path/to/ScrapeLens_0.1.3_amd64.AppImage mcp --sessions-dir <dir>` |

Example for macOS (`mcpServers`):

```json
{
  "mcpServers": {
    "scrapelens": {
      "command": "/Applications/ScrapeLens.app/Contents/MacOS/scrapelens",
      "args": [
        "mcp",
        "--sessions-dir",
        "/Users/you/Library/Application Support/app.scrapelens.desktop/sessions"
      ]
    }
  }
}
```

On Linux the sessions folder is `~/.local/share/app.scrapelens.desktop/sessions` (or `$XDG_DATA_HOME/app.scrapelens.desktop/sessions`). For the AppImage, when FUSE is not available, give the client the environment variable `APPIMAGE_EXTRACT_AND_RUN=1`.

- The server writes the protocol to stdout only; diagnostics go to stderr.
- `start_capture` asks the user to confirm in the client. A client that cannot ask is refused unless the server is started with `--allow-unconfirmed-capture`; use it only when you accept that a capture may start without confirmation.
- `start_capture` opens a visible Chrome unless the call sets `"headless": true`.

A developer build of the standalone server is still available with `cargo build --manifest-path mcp/Cargo.toml --release`; the packages do not need it.

### The 15 Tools of `scrapelens-mcp`

| Category | Tool | Description |
|---|---|---|
| **Sessions** | `list_sessions` | Lists sessions available in the working directory and extra directories (read-only). |
| | `import_session` | Imports a `.har` file, a `.json` (NetLog) file or a capture directory into the session vault. |
| | `export_session` | Exports a session to disk: sanitized by default (`include_sensitive: false`) or **full with sensitive data and raw artifacts** (`include_sensitive: true`). |
| | `site_profile` | Summarizes the session's hosts, protocols (`h1`/`h2`/`h3`), status, cookies, authentication and possible challenges/CAPTCHAs. |
| **Inspection & Search** | `list_requests` | Lists and filters requests by host, method, status, text, domain or pagination (`cursor`). |
| | `get_request` | Returns full request/response details, headers in original order, cookies and provenance. |
| | `get_body` | Reads the captured body (inline for small texts or written to `--out-dir` for large/binary payloads). |
| | `search_bodies` | Textual/structural search across URLs, headers, cookies and captured bodies. |
| **Analysis & Diff** | `trace_value` | Traces where a cookie, header or dynamic value first appeared (`firstSetter`) and where it was consumed. |
| | `diff_requests` | Compares two requests of the same session (URL, query, headers, cookies and body fields). |
| | `diff_sessions` | Pairs and compares equivalent requests across two distinct sessions. |
| **Live Capture** | `start_capture` | Starts a controlled capture in a Chromium-based browser with a host scope and user confirmation via MCP elicitation (supports `cookie_source` to import cookies). |
| | `navigate` | Navigates the monitored tab to a new URL within the authorized hosts. |
| | `capture_status` | Queries event, request and warning counts of the active capture. |
| | `stop_capture` | Ends the capture, persists the correlated session (`CDP + NetLog`) and returns the `sessionId`. |

> See the full contract in [`docs/16-mcp-contract.md`](docs/16-mcp-contract.md) and the browser/cookies guide in [`docs/16b-mcp-browser.md`](docs/16b-mcp-browser.md).

---

## 🏗️ Repository Architecture

```text
ScrapeLens/
├── app/                  # Desktop interface in React 18 + TypeScript + Vite
├── src-tauri/            # Native Tauri 2 shell (macOS & Linux), IPC commands, preferences and export
├── core/                 # Domain model, parsers (HAR, NetLog streaming, CDP), correlation, diff, priming, sanitization and CLI
├── capture/              # Live capture engine (CDP via pipe fd 3/4, NetLog, multi-target, cookie import)
├── mcp/                  # Model Context Protocol server (15 stdio tools + secret scrubbing + elicitation)
├── recon/                # Site surface diagnostics, WAF/CAPTCHA detection and profiling
├── adapters/
│   └── natural-ajax/     # Parser, diff and encoder for the Natural for Ajax protocol
├── testserver/           # Local test servers (HTTP/1.1, HTTP/2, HTTP/3 and DETRAN simulator)
├── fixtures/             # Synthetic fixtures and acceptance cases
├── tests/                # Automated acceptance and end-to-end integration suite
└── docs/                 # Architecture specifications, fidelity matrix, contracts and reports
```

---

## 🛠️ Development and Build

### Prerequisites

- **Rust** `1.88+` (`cargo`, `clippy`)
- **Node.js** `20+` e `npm`
- **Xcode Command Line Tools** (on macOS) or WebKitGTK/Tauri dependencies (on Linux — see [`docs/21-linux.md`](docs/21-linux.md))

### Main commands (from the root)

```sh
# 1. Install dependencies and validate the front end
npm --prefix app ci
npm --prefix app run typecheck
npm --prefix app test
npm --prefix app run build

# 2. Run the Rust test suites
cargo test --manifest-path core/Cargo.toml
cargo test --manifest-path capture/Cargo.toml
cargo test --manifest-path mcp/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path adapters/natural-ajax/Cargo.toml

# 3. Run in development mode
./app/node_modules/.bin/tauri dev

# 4. Build the macOS bundle (.app)
./app/node_modules/.bin/tauri build --bundles app
```

To use the development CLI of `core` directly:

```sh
cargo build --manifest-path core/Cargo.toml --release
./core/target/release/scrapelens-core inspect /path/to/session
./core/target/release/scrapelens-core export-curl /path/to/session cdp-r0001
./core/target/release/scrapelens-core export-python /path/to/session cdp-r0001
./core/target/release/scrapelens-core sanitize /path/to/session /path/to/sanitized-output
```

For contribution guidelines, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 📄 License

Distributed under the **MIT** license. See the [`LICENSE`](LICENSE) file for the full text.

Copyright © 2026 Cesar Matias.
